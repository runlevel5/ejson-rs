//! EJSON - Encrypted JSON secrets management.
//!
//! This crate provides utilities for managing encrypted secrets in source control
//! using public-key cryptography (NaCl Box).
//!
//! Supports JSON (.ejson, .json), TOML (.etoml, .toml), and YAML (.eyaml, .yaml, .yml) file formats.

pub mod boxed_message;
pub mod crypto;
pub mod format;
pub mod json;
pub mod toml;
pub mod yaml;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crypto::{CryptoError, Keypair};
use format::FileFormat;
use json::JsonError;
use thiserror::Error;
use toml::TomlError;
use yaml::YamlError;

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

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("couldn't read key file: {0}")]
    KeyFileError(String),

    #[error("invalid private key")]
    InvalidPrivateKey,

    #[error("hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
}

/// Generate a new ejson keypair.
///
/// Returns the public and private keys as hex-encoded strings.
pub fn generate_keypair() -> Result<(String, String), EjsonError> {
    let kp = Keypair::generate()?;
    Ok((kp.public_string(), kp.private_string()))
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

/// Encrypt a file in place.
///
/// The file format is auto-detected based on file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
pub fn encrypt_file_in_place<P: AsRef<Path>>(file_path: P) -> Result<usize, EjsonError> {
    let file_path = file_path.as_ref();
    let format = FileFormat::from_path(file_path);
    let metadata = fs::metadata(file_path)?;
    let permissions = metadata.permissions();

    let data = fs::read(file_path)?;
    let mut output = Vec::new();
    let size = encrypt_data(&data, &mut output, format)?;

    fs::write(file_path, &output)?;
    fs::set_permissions(file_path, permissions)?;

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
pub fn decrypt_file<P: AsRef<Path>>(
    file_path: P,
    keydir: &str,
    user_supplied_private_key: &str,
) -> Result<Vec<u8>, EjsonError> {
    let file_path = file_path.as_ref();
    let format = FileFormat::from_path(file_path);
    let data = fs::read(file_path)?;
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
    let privkey_string = if !user_supplied_private_key.is_empty() {
        user_supplied_private_key.to_string()
    } else {
        read_private_key_from_disk(pubkey, keydir)?
    };

    let privkey_bytes = hex::decode(privkey_string.trim())?;

    if privkey_bytes.len() != 32 {
        return Err(EjsonError::InvalidPrivateKey);
    }

    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&privkey_bytes);
    Ok(privkey)
}

fn read_private_key_from_disk(pubkey: &[u8; 32], keydir: &str) -> Result<String, EjsonError> {
    let key_file = format!("{}/{}", keydir, hex::encode(pubkey));
    let contents = fs::read_to_string(&key_file)
        .map_err(|e| EjsonError::KeyFileError(format!("{}: {}", key_file, e)))?;
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
}
