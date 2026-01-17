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
pub mod typed;
pub mod yaml;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crypto::{CryptoError, Keypair};

// Re-export key type for public API
pub use crypto::KeyBytes;
// Re-export typed API
pub use format::FileFormat;
use format::FormatError;
use fs4::fs_std::FileExt;
use json::JsonError;
pub use typed::{DecryptedContent, DecryptedValue};

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

    // Helper closure to perform encryption
    let do_encrypt = |pubkey: KeyBytes, data: &[u8]| -> Result<Vec<u8>, EjsonError> {
        let encrypter = my_kp.encrypter(pubkey);
        let encrypt_fn = |plaintext: &[u8]| encrypter.encrypt(plaintext).map_err(|e| e.to_string());

        match format {
            FileFormat::Json => {
                let walker = json::Walker::new(encrypt_fn);
                Ok(walker.walk(data)?)
            }
            FileFormat::Toml => {
                let walker = toml::Walker::new(encrypt_fn);
                Ok(walker.walk(data)?)
            }
            FileFormat::Yaml => {
                let walker = yaml::Walker::new(encrypt_fn);
                Ok(walker.walk(data)?)
            }
        }
    };

    let new_data = match format {
        FileFormat::Json => {
            let data = json::collapse_multiline_string_literals(data)?;
            let pubkey = json::extract_public_key(&data)?;
            do_encrypt(pubkey, &data)?
        }
        FileFormat::Toml => {
            let pubkey = toml::extract_public_key(data)?;
            do_encrypt(pubkey, data)?
        }
        FileFormat::Yaml => {
            let pubkey = yaml::extract_public_key(data)?;
            do_encrypt(pubkey, data)?
        }
    };

    output.write_all(&new_data)?;
    Ok(new_data.len())
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
    // Extract public key based on format
    let pubkey = match format {
        FileFormat::Json => json::extract_public_key(data)?,
        FileFormat::Toml => toml::extract_public_key(data)?,
        FileFormat::Yaml => yaml::extract_public_key(data)?,
    };

    // Find the private key and create decrypter
    let privkey = find_private_key(&pubkey, keydir, user_supplied_private_key)?;
    let kp = Keypair::from_keys(pubkey, privkey);
    let decrypter = kp.decrypter();

    // Create decryption closure that conditionally decrypts
    let decrypt_fn = |ciphertext: &[u8]| {
        if boxed_message::is_boxed_message(ciphertext) {
            decrypter.decrypt(ciphertext).map_err(|e| e.to_string())
        } else {
            Ok(ciphertext.to_vec())
        }
    };

    // Walk and decrypt based on format
    let new_data = match format {
        FileFormat::Json => json::Walker::new(decrypt_fn).walk(data)?,
        FileFormat::Toml => toml::Walker::new(decrypt_fn).walk(data)?,
        FileFormat::Yaml => yaml::Walker::new(decrypt_fn).walk(data)?,
    };

    output.write_all(&new_data)?;
    Ok(())
}

/// Decrypt a file and return the decrypted contents.
///
/// The file format is auto-detected based on file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
/// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
///
/// If `trim_underscore_prefix` is true, the first leading underscore will be
/// stripped from all keys in the output.
///
/// Security: Uses file locking and size limits.
pub fn decrypt_file<P: AsRef<Path>>(
    file_path: P,
    keydir: &str,
    user_supplied_private_key: &str,
    trim_underscore_prefix: bool,
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

    if trim_underscore_prefix {
        output = trim_underscore_prefix_from_keys(&output, format)?;
    }

    Ok(output)
}

/// Decrypt bytes and return the decrypted contents as a typed value.
///
/// This function is similar to [`decrypt_with_format`], but instead of returning raw bytes,
/// it returns a [`DecryptedContent`] enum that provides format-agnostic access to
/// the decrypted data.
///
/// This is useful when you have the encrypted data already in memory (e.g., from an HTTP
/// response or embedded resource) and want to work with the typed API.
///
/// # Example
///
/// ```no_run
/// use ejson::{decrypt_bytes_typed, DecryptedContent, format::FileFormat};
///
/// let encrypted_data = b"{\"_public_key\": \"...\", \"secret\": \"EJ[...]\"}";
/// let content = decrypt_bytes_typed(encrypted_data, "/opt/ejson/keys", "", FileFormat::Json, false)?;
///
/// // Access values uniformly regardless of JSON/YAML/TOML format
/// if let Some(env) = content.get("environment") {
///     if let Some(map) = env.as_string_map() {
///         for (key, value) in map {
///             if let Some(v) = value.as_str() {
///                 println!("{}={}", key, v);
///             }
///         }
///     }
/// }
/// # Ok::<(), ejson::EjsonError>(())
/// ```
pub fn decrypt_bytes_typed(
    data: &[u8],
    keydir: &str,
    user_supplied_private_key: &str,
    format: FileFormat,
    trim_underscore_prefix: bool,
) -> Result<DecryptedContent, EjsonError> {
    // Check size limit
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }

    // Decrypt to bytes first
    let mut output = Vec::new();
    decrypt_data(data, &mut output, keydir, user_supplied_private_key, format)?;

    let decrypted_bytes = if trim_underscore_prefix {
        trim_underscore_prefix_from_keys(&output, format)?
    } else {
        output
    };

    // Parse based on format
    let content = match format {
        FileFormat::Json => {
            let value: serde_json::Value =
                serde_json::from_slice(&decrypted_bytes).map_err(|_| JsonError::InvalidJson)?;
            DecryptedContent::Json(value)
        }
        FileFormat::Yaml => {
            let value: serde_norway::Value = serde_norway::from_slice(&decrypted_bytes)
                .map_err(|e| YamlError::InvalidYaml(e.to_string()))?;
            DecryptedContent::Yaml(value)
        }
        FileFormat::Toml => {
            let s = std::str::from_utf8(&decrypted_bytes)
                .map_err(|e| TomlError::InvalidToml(e.to_string()))?;
            let value: ::toml::Value =
                ::toml::from_str(s).map_err(|e| TomlError::InvalidToml(e.to_string()))?;
            DecryptedContent::Toml(value)
        }
    };

    Ok(content)
}

/// Decrypt a file and return the decrypted contents as a typed value.
///
/// This function is similar to [`decrypt_file`], but instead of returning raw bytes,
/// it returns a [`DecryptedContent`] enum that provides format-agnostic access to
/// the decrypted data.
///
/// This is particularly useful for tools like `ejson2env` that need to extract
/// specific values from the decrypted content without knowing the file format.
///
/// # Example
///
/// ```no_run
/// use ejson::{decrypt_file_typed, DecryptedContent};
///
/// let content = decrypt_file_typed("secrets.ejson", "/opt/ejson/keys", "", false)?;
///
/// // Access values uniformly regardless of JSON/YAML/TOML format
/// if let Some(env) = content.get("environment") {
///     if let Some(map) = env.as_string_map() {
///         for (key, value) in map {
///             if let Some(v) = value.as_str() {
///                 println!("{}={}", key, v);
///             }
///         }
///     }
/// }
/// # Ok::<(), ejson::EjsonError>(())
/// ```
pub fn decrypt_file_typed<P: AsRef<Path>>(
    file_path: P,
    keydir: &str,
    user_supplied_private_key: &str,
    trim_underscore_prefix: bool,
) -> Result<DecryptedContent, EjsonError> {
    let file_path = file_path.as_ref();
    let format = FileFormat::from_path(file_path)?;

    // Decrypt to bytes first
    let decrypted_bytes = decrypt_file(
        file_path,
        keydir,
        user_supplied_private_key,
        trim_underscore_prefix,
    )?;

    // Parse based on format
    let content = match format {
        FileFormat::Json => {
            let value: serde_json::Value =
                serde_json::from_slice(&decrypted_bytes).map_err(|_| JsonError::InvalidJson)?;
            DecryptedContent::Json(value)
        }
        FileFormat::Yaml => {
            let value: serde_norway::Value = serde_norway::from_slice(&decrypted_bytes)
                .map_err(|e| YamlError::InvalidYaml(e.to_string()))?;
            DecryptedContent::Yaml(value)
        }
        FileFormat::Toml => {
            let s = std::str::from_utf8(&decrypted_bytes)
                .map_err(|e| TomlError::InvalidToml(e.to_string()))?;
            let value: ::toml::Value =
                ::toml::from_str(s).map_err(|e| TomlError::InvalidToml(e.to_string()))?;
            DecryptedContent::Toml(value)
        }
    };

    Ok(content)
}

/// Trim the first leading underscore from all keys in the data.
///
/// This is a post-processing step applied after decryption when the
/// `--trim-underscore-prefix` flag is used.
fn trim_underscore_prefix_from_keys(
    data: &[u8],
    format: FileFormat,
) -> Result<Vec<u8>, EjsonError> {
    match format {
        FileFormat::Json => Ok(json::trim_underscore_prefix_from_keys(data)?),
        FileFormat::Toml => Ok(toml::trim_underscore_prefix_from_keys(data)?),
        FileFormat::Yaml => Ok(yaml::trim_underscore_prefix_from_keys(data)?),
    }
}

fn find_private_key(
    pubkey: &KeyBytes,
    keydir: &str,
    user_supplied_private_key: &str,
) -> Result<KeyBytes, EjsonError> {
    // Use Zeroizing to ensure the private key string is cleared from memory
    let privkey_string: Zeroizing<String> = if user_supplied_private_key.is_empty() {
        Zeroizing::new(read_private_key_from_disk(pubkey, keydir)?)
    } else {
        Zeroizing::new(user_supplied_private_key.to_string())
    };

    // Decode hex - the intermediate Vec will be small and short-lived
    let mut privkey_bytes = Zeroizing::new(hex::decode(privkey_string.trim())?);

    if privkey_bytes.len() != 32 {
        return Err(EjsonError::InvalidPrivateKey);
    }

    let privkey: KeyBytes = privkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| EjsonError::InvalidPrivateKey)?;

    // Zeroize the intermediate bytes
    privkey_bytes.iter_mut().for_each(|b| *b = 0);

    Ok(privkey)
}

fn read_private_key_from_disk(pubkey: &KeyBytes, keydir: &str) -> Result<String, EjsonError> {
    let pubkey_hex = hex::encode(pubkey);
    let keydir_path = Path::new(keydir);
    let key_path = keydir_path.join(&pubkey_hex);

    // Validate the constructed path
    validate_path(&key_path)?;

    // Verify the path is still within keydir after resolution
    // This prevents path traversal via malicious public key hex
    if let (Ok(canonical_keydir), Ok(canonical_key_path)) =
        (fs::canonicalize(keydir_path), fs::canonicalize(&key_path))
    {
        if !canonical_key_path.starts_with(&canonical_keydir) {
            return Err(EjsonError::InvalidPath(
                "key path escapes keydir".to_string(),
            ));
        }
    }

    fs::read_to_string(&key_path).map_err(|_| {
        // Don't include the full path in error messages to avoid information disclosure
        EjsonError::KeyFileError(format!(
            "key file for public key {}... not found or unreadable",
            &pubkey_hex[..8]
        ))
    })
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
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test JSON
        let json = format!(
            r#"{{"_public_key": "{pub_hex}", "secret": "my secret value", "_comment": "not encrypted"}}"#
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
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test TOML
        let toml_content = format!(
            r#"_public_key = "{pub_hex}"
secret = "my secret value"
_comment = "not encrypted"

[database]
password = "db_password"
_hint = "password hint"
"#
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
            r#"_public_key = "{pub_hex}"
secret = "my secret"
"#
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
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test YAML
        let yaml_content = format!(
            r#"_public_key: "{pub_hex}"
secret: "my secret value"
_comment: "not encrypted"

database:
  password: "db_password"
  _hint: "password hint"
"#
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
            r#"_public_key: "{pub_hex}"
secret: "my secret"
"#
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

    #[test]
    fn test_decrypt_file_typed_json() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create and encrypt test JSON file
        let json_path = temp_dir.path().join("secrets.ejson");
        let json_content = format!(
            r#"{{"_public_key": "{pub_hex}", "environment": {{"FOO": "bar", "BAZ": "qux"}}, "secret": "value"}}"#
        );
        fs::write(&json_path, &json_content).unwrap();
        encrypt_file_in_place(&json_path).unwrap();

        // Decrypt with typed API
        let content = decrypt_file_typed(&json_path, keydir, "", false).unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_file_typed_toml() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create and encrypt test TOML file
        let toml_path = temp_dir.path().join("secrets.etoml");
        let toml_content = format!(
            r#"_public_key = "{pub_hex}"
secret = "value"

[environment]
FOO = "bar"
BAZ = "qux"
"#
        );
        fs::write(&toml_path, &toml_content).unwrap();
        encrypt_file_in_place(&toml_path).unwrap();

        // Decrypt with typed API
        let content = decrypt_file_typed(&toml_path, keydir, "", false).unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_file_typed_yaml() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create and encrypt test YAML file
        let yaml_path = temp_dir.path().join("secrets.eyaml");
        let yaml_content = format!(
            r#"_public_key: "{pub_hex}"
secret: "value"

environment:
  FOO: "bar"
  BAZ: "qux"
"#
        );
        fs::write(&yaml_path, &yaml_content).unwrap();
        encrypt_file_in_place(&yaml_path).unwrap();

        // Decrypt with typed API
        let content = decrypt_file_typed(&yaml_path, keydir, "", false).unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_file_typed_ejson2env_pattern() {
        // This test demonstrates the simplified ejson2env pattern
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Test with JSON
        let json_path = temp_dir.path().join("secrets.ejson");
        let json_content = format!(
            r#"{{"_public_key": "{pub_hex}", "environment": {{"DATABASE_URL": "postgres://localhost", "API_KEY": "secret123"}}}}"#
        );
        fs::write(&json_path, &json_content).unwrap();
        encrypt_file_in_place(&json_path).unwrap();

        // Simulate ejson2env extraction
        let content = decrypt_file_typed(&json_path, keydir, "", false).unwrap();

        // The pattern that ejson2env would use
        let env_secrets: std::collections::HashMap<String, String> = content
            .get("environment")
            .and_then(|env| env.as_string_map())
            .map(|map| {
                map.filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        assert_eq!(env_secrets.len(), 2);
        assert_eq!(
            env_secrets.get("DATABASE_URL"),
            Some(&"postgres://localhost".to_string())
        );
        assert_eq!(env_secrets.get("API_KEY"), Some(&"secret123".to_string()));
    }

    #[test]
    fn test_decrypt_bytes_typed_json() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test JSON and encrypt it
        let json_content = format!(
            r#"{{"_public_key": "{pub_hex}", "environment": {{"FOO": "bar", "BAZ": "qux"}}, "secret": "value"}}"#
        );
        let mut encrypted = Vec::new();
        encrypt(json_content.as_bytes(), &mut encrypted).unwrap();

        // Decrypt bytes with typed API
        let content = decrypt_bytes_typed(&encrypted, keydir, "", FileFormat::Json, false).unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_bytes_typed_toml() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test TOML and encrypt it
        let toml_content = format!(
            r#"_public_key = "{pub_hex}"
secret = "value"

[environment]
FOO = "bar"
BAZ = "qux"
"#
        );
        let mut encrypted = Vec::new();
        encrypt_with_format(toml_content.as_bytes(), &mut encrypted, FileFormat::Toml).unwrap();

        // Decrypt bytes with typed API
        let content = decrypt_bytes_typed(&encrypted, keydir, "", FileFormat::Toml, false).unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));
    }

    #[test]
    fn test_decrypt_bytes_typed_yaml() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test YAML and encrypt it
        let yaml_content = format!(
            r#"_public_key: "{pub_hex}"
secret: "value"

environment:
  FOO: "bar"
  BAZ: "qux"
"#
        );
        let mut encrypted = Vec::new();
        encrypt_with_format(yaml_content.as_bytes(), &mut encrypted, FileFormat::Yaml).unwrap();

        // Decrypt bytes with typed API
        let content = decrypt_bytes_typed(&encrypted, keydir, "", FileFormat::Yaml, false).unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));
    }

    #[test]
    fn test_decrypt_bytes_typed_with_trim_underscore() {
        // Generate a keypair
        let kp = Keypair::generate().unwrap();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test JSON with underscore-prefixed keys
        let json_content =
            format!(r#"{{"_public_key": "{pub_hex}", "_environment": {{"_FOO": "bar"}}}}"#);
        let mut encrypted = Vec::new();
        encrypt(json_content.as_bytes(), &mut encrypted).unwrap();

        // Decrypt bytes with typed API and trim underscore prefix
        let content = decrypt_bytes_typed(&encrypted, keydir, "", FileFormat::Json, true).unwrap();

        // Keys should have underscore prefix removed
        let env = content
            .get("environment")
            .expect("should have environment (trimmed)");
        let foo = env.get("FOO").expect("should have FOO (trimmed)");
        assert_eq!(foo.as_str(), Some("bar"));
    }
}
