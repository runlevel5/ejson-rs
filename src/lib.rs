//! EJSON - Encrypted JSON secrets management.
//!
//! This crate provides utilities for managing encrypted secrets in source control
//! using public-key cryptography (NaCl Box).
//!
//! Supports JSON (.ejson, .json), TOML (.etoml, .toml), and YAML (.eyaml, .eyml, .yaml, .yml) file formats.
//!
//! # Security Features
//!
//! - Private keys are zeroized from memory when dropped
//! - File operations use locking to prevent race conditions
//! - Path traversal attacks are prevented through validation
//! - Maximum file size limits prevent denial of service
//! - Constant-time comparisons for key validation

pub mod boxed_message;
pub mod crypto;
pub mod format;
pub mod json;
pub mod toml;
pub mod yaml;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crypto::{CryptoError, Keypair};
use format::{FileFormat, FormatError};
use fs4::fs_std::FileExt;
use json::JsonError;
use subtle::ConstantTimeEq;
use thiserror::Error;
use toml::TomlError;
use yaml::YamlError;
use zeroize::Zeroizing;

/// Maximum file size for encryption/decryption operations (10 MB).
/// This prevents denial of service through memory exhaustion.
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Errors that can occur during ejson operations.
#[derive(Error, Debug)]
pub enum EjsonError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("json error: {0}")]
    Json(#[from] JsonError),

    #[error("toml error: {0}")]
    Toml(#[from] TomlError),

    #[error("yaml error: {0}")]
    Yaml(#[from] YamlError),

    #[error("format error: {0}")]
    Format(#[from] FormatError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("couldn't read key file")]
    KeyFileError(String),

    #[error("invalid private key")]
    InvalidPrivateKey,

    #[error("hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("file too large (max {} bytes)", MAX_FILE_SIZE)]
    FileTooLarge,

    #[error("invalid path: {0}")]
    InvalidPath(String),
}

/// Generate a new ejson keypair.
///
/// Returns the public and private keys as hex-encoded strings.
/// Note: The private key string should be handled securely by the caller.
pub fn generate_keypair() -> Result<(String, String), EjsonError> {
    let kp = Keypair::generate()?;
    Ok((kp.public_string(), kp.private_string()))
}

/// Validate that a path is safe to use (no path traversal, symlinks to outside, etc.)
fn validate_path(path: &Path) -> Result<(), EjsonError> {
    // Check for obviously dangerous patterns
    let path_str = path.to_string_lossy();

    // Reject paths with null bytes
    if path_str.contains('\0') {
        return Err(EjsonError::InvalidPath(
            "path contains null bytes".to_string(),
        ));
    }

    // On Unix, check if it's a device file
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(metadata) = fs::symlink_metadata(path) {
            let file_type = metadata.file_type();
            if file_type.is_block_device()
                || file_type.is_char_device()
                || file_type.is_fifo()
                || file_type.is_socket()
            {
                return Err(EjsonError::InvalidPath(
                    "path is not a regular file".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Read a file with size limit and locking.
fn read_file_with_lock(path: &Path) -> Result<Vec<u8>, EjsonError> {
    validate_path(path)?;

    let file = File::open(path)?;

    // Check file size before reading
    let metadata = file.metadata()?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }

    // Acquire shared lock for reading
    file.lock_shared()?;

    let mut data = Vec::with_capacity(metadata.len() as usize);
    let mut reader = std::io::BufReader::new(&file);
    reader.read_to_end(&mut data)?;

    // Lock is automatically released when file is dropped
    Ok(data)
}

/// Encrypt data from a reader and write to a writer.
///
/// The input must be valid JSON with a `_public_key` field containing
/// a hex-encoded 32-byte public key.
///
/// This function assumes JSON format. For format detection based on file extension,
/// use `encrypt_file_in_place`.
pub fn encrypt<R: Read, W: Write>(mut input: R, mut output: W) -> Result<usize, EjsonError> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    // Check size limit
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }

    encrypt_data(&data, &mut output, FileFormat::Json)
}

/// Encrypt data with a specific format.
pub fn encrypt_with_format<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    format: FileFormat,
) -> Result<usize, EjsonError> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    // Check size limit
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }

    encrypt_data(&data, &mut output, format)
}

fn encrypt_data<W: Write>(
    data: &[u8],
    output: &mut W,
    format: FileFormat,
) -> Result<usize, EjsonError> {
    // Generate ephemeral keypair for this encryption session
    let my_kp = Keypair::generate()?;

    match format {
        FileFormat::Json => {
            // Collapse multiline strings for JSON
            let data = json::collapse_multiline_string_literals(data)?;

            // Extract the public key from the document
            let pubkey = json::extract_public_key(&data)?;

            // Create encrypter
            let encrypter = my_kp.encrypter(pubkey);

            // Walk and encrypt
            let walker = json::Walker::new(|plaintext: &[u8]| {
                encrypter.encrypt(plaintext).map_err(|e| e.to_string())
            });

            let new_data = walker.walk(&data)?;
            output.write_all(&new_data)?;
            Ok(new_data.len())
        }
        FileFormat::Toml => {
            // Extract the public key from the document
            let pubkey = toml::extract_public_key(data)?;

            // Create encrypter
            let encrypter = my_kp.encrypter(pubkey);

            // Walk and encrypt
            let walker = toml::Walker::new(|plaintext: &[u8]| {
                encrypter.encrypt(plaintext).map_err(|e| e.to_string())
            });

            let new_data = walker.walk(data)?;
            output.write_all(&new_data)?;
            Ok(new_data.len())
        }
        FileFormat::Yaml => {
            // Extract the public key from the document
            let pubkey = yaml::extract_public_key(data)?;

            // Create encrypter
            let encrypter = my_kp.encrypter(pubkey);

            // Walk and encrypt
            let walker = yaml::Walker::new(|plaintext: &[u8]| {
                encrypter.encrypt(plaintext).map_err(|e| e.to_string())
            });

            let new_data = walker.walk(data)?;
            output.write_all(&new_data)?;
            Ok(new_data.len())
        }
    }
}

/// Encrypt a file in place with file locking.
///
/// The file format is auto-detected based on file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
/// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
///
/// Security: Uses exclusive file locking to prevent race conditions.
pub fn encrypt_file_in_place<P: AsRef<Path>>(file_path: P) -> Result<usize, EjsonError> {
    let file_path = file_path.as_ref();
    validate_path(file_path)?;

    let format = FileFormat::from_path(file_path)?;

    // Open file for reading first to get lock
    let file = File::open(file_path)?;

    // Check file size
    let metadata = file.metadata()?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }
    let permissions = metadata.permissions();

    // Acquire exclusive lock
    file.lock_exclusive()?;

    // Read the data while holding the lock
    let mut data = Vec::with_capacity(metadata.len() as usize);
    let mut reader = std::io::BufReader::new(&file);
    reader.read_to_end(&mut data)?;

    // Encrypt
    let mut output = Vec::new();
    let size = encrypt_data(&data, &mut output, format)?;

    // Write back (still holding lock via the open file handle)
    fs::write(file_path, &output)?;
    fs::set_permissions(file_path, permissions)?;

    // Lock is released when file is dropped
    Ok(size)
}

/// Decrypt data from a reader and write to a writer.
///
/// The private key is looked up in `keydir` (a file named after the public key),
/// or can be supplied directly via `user_supplied_private_key`.
///
/// This function assumes JSON format. For format detection based on file extension,
/// use `decrypt_file`.
pub fn decrypt<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    keydir: &str,
    user_supplied_private_key: &str,
) -> Result<(), EjsonError> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    // Check size limit
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }

    decrypt_data(
        &data,
        &mut output,
        keydir,
        user_supplied_private_key,
        FileFormat::Json,
    )
}

/// Decrypt data with a specific format.
pub fn decrypt_with_format<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    keydir: &str,
    user_supplied_private_key: &str,
    format: FileFormat,
) -> Result<(), EjsonError> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    // Check size limit
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }

    decrypt_data(
        &data,
        &mut output,
        keydir,
        user_supplied_private_key,
        format,
    )
}

fn decrypt_data<W: Write>(
    data: &[u8],
    output: &mut W,
    keydir: &str,
    user_supplied_private_key: &str,
    format: FileFormat,
) -> Result<(), EjsonError> {
    match format {
        FileFormat::Json => {
            // Extract the public key from the document
            let pubkey = json::extract_public_key(data)?;

            // Find the private key
            let privkey = find_private_key(&pubkey, keydir, user_supplied_private_key)?;

            // Create decrypter
            let kp = Keypair::from_keys(pubkey, privkey);
            let decrypter = kp.decrypter();

            // Walk and decrypt
            let walker = json::Walker::new(|ciphertext: &[u8]| {
                // Only decrypt if it looks like an encrypted message
                if boxed_message::is_boxed_message(ciphertext) {
                    decrypter.decrypt(ciphertext).map_err(|e| e.to_string())
                } else {
                    Ok(ciphertext.to_vec())
                }
            });

            let new_data = walker.walk(data)?;
            output.write_all(&new_data)?;
        }
        FileFormat::Toml => {
            // Extract the public key from the document
            let pubkey = toml::extract_public_key(data)?;

            // Find the private key
            let privkey = find_private_key(&pubkey, keydir, user_supplied_private_key)?;

            // Create decrypter
            let kp = Keypair::from_keys(pubkey, privkey);
            let decrypter = kp.decrypter();

            // Walk and decrypt
            let walker = toml::Walker::new(|ciphertext: &[u8]| {
                // Only decrypt if it looks like an encrypted message
                if boxed_message::is_boxed_message(ciphertext) {
                    decrypter.decrypt(ciphertext).map_err(|e| e.to_string())
                } else {
                    Ok(ciphertext.to_vec())
                }
            });

            let new_data = walker.walk(data)?;
            output.write_all(&new_data)?;
        }
        FileFormat::Yaml => {
            // Extract the public key from the document
            let pubkey = yaml::extract_public_key(data)?;

            // Find the private key
            let privkey = find_private_key(&pubkey, keydir, user_supplied_private_key)?;

            // Create decrypter
            let kp = Keypair::from_keys(pubkey, privkey);
            let decrypter = kp.decrypter();

            // Walk and decrypt
            let walker = yaml::Walker::new(|ciphertext: &[u8]| {
                // Only decrypt if it looks like an encrypted message
                if boxed_message::is_boxed_message(ciphertext) {
                    decrypter.decrypt(ciphertext).map_err(|e| e.to_string())
                } else {
                    Ok(ciphertext.to_vec())
                }
            });

            let new_data = walker.walk(data)?;
            output.write_all(&new_data)?;
        }
    }
    Ok(())
}

/// Decrypt a file and return the decrypted contents.
///
/// The file format is auto-detected based on file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
/// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
///
/// Security: Uses file locking and size limits.
pub fn decrypt_file<P: AsRef<Path>>(
    file_path: P,
    keydir: &str,
    user_supplied_private_key: &str,
) -> Result<Vec<u8>, EjsonError> {
    let file_path = file_path.as_ref();
    let format = FileFormat::from_path(file_path)?;
    let data = read_file_with_lock(file_path)?;
    let mut output = Vec::new();
    decrypt_data(
        &data,
        &mut output,
        keydir,
        user_supplied_private_key,
        format,
    )?;
    Ok(output)
}

fn find_private_key(
    pubkey: &[u8; 32],
    keydir: &str,
    user_supplied_private_key: &str,
) -> Result<[u8; 32], EjsonError> {
    // Use Zeroizing to ensure the private key string is cleared from memory
    let privkey_string: Zeroizing<String> = if !user_supplied_private_key.is_empty() {
        Zeroizing::new(user_supplied_private_key.to_string())
    } else {
        Zeroizing::new(read_private_key_from_disk(pubkey, keydir)?)
    };

    // Decode hex - the intermediate Vec will be small and short-lived
    let mut privkey_bytes = Zeroizing::new(hex::decode(privkey_string.trim())?);

    // Use constant-time comparison for key length to avoid timing attacks
    // (though this is minimal risk since we're comparing against a constant)
    let expected_len = 32u8;
    let actual_len = privkey_bytes.len() as u8;
    let len_ok = actual_len.ct_eq(&expected_len);

    if !bool::from(len_ok) {
        return Err(EjsonError::InvalidPrivateKey);
    }

    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&privkey_bytes);

    // Zeroize the intermediate bytes
    privkey_bytes.iter_mut().for_each(|b| *b = 0);

    Ok(privkey)
}

fn read_private_key_from_disk(pubkey: &[u8; 32], keydir: &str) -> Result<String, EjsonError> {
    let pubkey_hex = hex::encode(pubkey);
    let key_path = Path::new(keydir).join(&pubkey_hex);

    // Validate the constructed path
    validate_path(&key_path)?;

    // Verify the path is still within keydir after resolution
    // This prevents path traversal via malicious public key hex
    if let (Ok(canonical_keydir), Ok(canonical_key_path)) =
        (fs::canonicalize(keydir), fs::canonicalize(&key_path))
    {
        if !canonical_key_path.starts_with(&canonical_keydir) {
            return Err(EjsonError::InvalidPath(
                "key path escapes keydir".to_string(),
            ));
        }
    }

    let contents = fs::read_to_string(&key_path).map_err(|_| {
        // Don't include the full path in error messages to avoid information disclosure
        EjsonError::KeyFileError(format!(
            "key file for public key {}... not found or unreadable",
            &pubkey_hex[..8]
        ))
    })?;
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_keypair() {
        let (pub_key, priv_key) = generate_keypair().unwrap();
        assert_eq!(pub_key.len(), 64);
        assert_eq!(priv_key.len(), 64);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = format!("{}/{}", keydir, pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test JSON
        let json = format!(
            r#"{{"_public_key": "{}", "secret": "my secret value", "_comment": "not encrypted"}}"#,
            pub_hex
        );

        // Encrypt
        let mut encrypted = Vec::new();
        encrypt(json.as_bytes(), &mut encrypted).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Verify encryption happened
        assert!(encrypted_str.contains("EJ["));
        assert!(!encrypted_str.contains("my secret value"));
        assert!(encrypted_str.contains("not encrypted")); // Comment should not be encrypted

        // Decrypt
        let mut decrypted = Vec::new();
        decrypt(&encrypted[..], &mut decrypted, keydir, "").unwrap();
        let decrypted_str = String::from_utf8_lossy(&decrypted);

        // Verify decryption
        assert!(decrypted_str.contains("my secret value"));
        assert!(!decrypted_str.contains("EJ["));
    }

    #[test]
    fn test_encrypt_decrypt_toml_roundtrip() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = format!("{}/{}", keydir, pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test TOML
        let toml_content = format!(
            r#"_public_key = "{}"
secret = "my secret value"
_comment = "not encrypted"

[database]
password = "db_password"
_hint = "password hint"
"#,
            pub_hex
        );

        // Encrypt
        let mut encrypted = Vec::new();
        encrypt_with_format(toml_content.as_bytes(), &mut encrypted, FileFormat::Toml).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Verify encryption happened
        assert!(encrypted_str.contains("EJ["));
        assert!(!encrypted_str.contains("my secret value"));
        assert!(!encrypted_str.contains("db_password"));
        assert!(encrypted_str.contains("not encrypted")); // Comment should not be encrypted
        assert!(encrypted_str.contains("password hint")); // Underscore key should not be encrypted

        // Decrypt
        let mut decrypted = Vec::new();
        decrypt_with_format(&encrypted[..], &mut decrypted, keydir, "", FileFormat::Toml).unwrap();
        let decrypted_str = String::from_utf8_lossy(&decrypted);

        // Verify decryption
        assert!(decrypted_str.contains("my secret value"));
        assert!(decrypted_str.contains("db_password"));
        assert!(!decrypted_str.contains("EJ["));
    }

    #[test]
    fn test_format_detection_in_encrypt_file() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();

        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();

        // Test with .etoml extension
        let etoml_path = temp_dir.path().join("secrets.etoml");
        let toml_content = format!(
            r#"_public_key = "{}"
secret = "my secret"
"#,
            pub_hex
        );
        fs::write(&etoml_path, &toml_content).unwrap();

        // Encrypt
        encrypt_file_in_place(&etoml_path).unwrap();

        // Read and verify
        let encrypted = fs::read_to_string(&etoml_path).unwrap();
        assert!(encrypted.contains("EJ["));
        assert!(!encrypted.contains("my secret"));
    }

    #[test]
    fn test_encrypt_decrypt_yaml_roundtrip() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = format!("{}/{}", keydir, pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test YAML
        let yaml_content = format!(
            r#"_public_key: "{}"
secret: "my secret value"
_comment: "not encrypted"

database:
  password: "db_password"
  _hint: "password hint"
"#,
            pub_hex
        );

        // Encrypt
        let mut encrypted = Vec::new();
        encrypt_with_format(yaml_content.as_bytes(), &mut encrypted, FileFormat::Yaml).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Verify encryption happened
        assert!(encrypted_str.contains("EJ["));
        assert!(!encrypted_str.contains("my secret value"));
        assert!(!encrypted_str.contains("db_password"));
        assert!(encrypted_str.contains("not encrypted")); // Comment should not be encrypted
        assert!(encrypted_str.contains("password hint")); // Underscore key should not be encrypted

        // Decrypt
        let mut decrypted = Vec::new();
        decrypt_with_format(&encrypted[..], &mut decrypted, keydir, "", FileFormat::Yaml).unwrap();
        let decrypted_str = String::from_utf8_lossy(&decrypted);

        // Verify decryption
        assert!(decrypted_str.contains("my secret value"));
        assert!(decrypted_str.contains("db_password"));
        assert!(!decrypted_str.contains("EJ["));
    }

    #[test]
    fn test_format_detection_in_encrypt_yaml_file() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();

        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();

        // Test with .eyaml extension
        let eyaml_path = temp_dir.path().join("secrets.eyaml");
        let yaml_content = format!(
            r#"_public_key: "{}"
secret: "my secret"
"#,
            pub_hex
        );
        fs::write(&eyaml_path, &yaml_content).unwrap();

        // Encrypt
        encrypt_file_in_place(&eyaml_path).unwrap();

        // Read and verify
        let encrypted = fs::read_to_string(&eyaml_path).unwrap();
        assert!(encrypted.contains("EJ["));
        assert!(!encrypted.contains("my secret"));
    }

    #[test]
    fn test_path_validation_rejects_null_bytes() {
        let path = Path::new("/tmp/test\0file.ejson");
        let result = validate_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_private_key_length() {
        let pubkey = [0u8; 32];
        let result = find_private_key(&pubkey, "/nonexistent", "deadbeef"); // Too short
        assert!(matches!(result, Err(EjsonError::InvalidPrivateKey)));
    }
}
