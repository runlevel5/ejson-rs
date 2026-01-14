//! EJSON - Encrypted JSON secrets management.
//!
//! This crate provides utilities for managing encrypted secrets in source control
//! using public-key cryptography (NaCl Box).

pub mod boxed_message;
pub mod crypto;
pub mod json;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crypto::{CryptoError, Keypair};
use json::{extract_public_key, JsonError, Walker};
use thiserror::Error;

/// Errors that can occur during ejson operations.
#[derive(Error, Debug)]
pub enum EjsonError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("json error: {0}")]
    Json(#[from] JsonError),

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
pub fn encrypt<R: Read, W: Write>(mut input: R, mut output: W) -> Result<usize, EjsonError> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    // Generate ephemeral keypair for this encryption session
    let my_kp = Keypair::generate()?;

    // Collapse multiline strings
    let data = json::collapse_multiline_string_literals(&data)?;

    // Extract the public key from the document
    let pubkey = extract_public_key(&data)?;

    // Create encrypter
    let encrypter = my_kp.encrypter(pubkey);

    // Walk and encrypt
    let walker =
        Walker::new(|plaintext: &[u8]| encrypter.encrypt(plaintext).map_err(|e| e.to_string()));

    let new_data = walker.walk(&data)?;
    output.write_all(&new_data)?;
    Ok(new_data.len())
}

/// Encrypt a file in place.
pub fn encrypt_file_in_place<P: AsRef<Path>>(file_path: P) -> Result<usize, EjsonError> {
    let file_path = file_path.as_ref();
    let metadata = fs::metadata(file_path)?;
    let permissions = metadata.permissions();

    let data = fs::read(file_path)?;
    let mut output = Vec::new();
    let written = encrypt(&data[..], &mut output)?;

    fs::write(file_path, &output)?;
    fs::set_permissions(file_path, permissions)?;

    Ok(written)
}

/// Decrypt data from a reader and write to a writer.
///
/// The private key is looked up in `keydir` (a file named after the public key),
/// or can be supplied directly via `user_supplied_private_key`.
pub fn decrypt<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    keydir: &str,
    user_supplied_private_key: &str,
) -> Result<(), EjsonError> {
    let mut data = Vec::new();
    input.read_to_end(&mut data)?;

    // Extract the public key from the document
    let pubkey = extract_public_key(&data)?;

    // Find the private key
    let privkey = find_private_key(&pubkey, keydir, user_supplied_private_key)?;

    // Create decrypter
    let kp = Keypair::from_keys(pubkey, privkey);
    let decrypter = kp.decrypter();

    // Walk and decrypt
    let walker = Walker::new(|ciphertext: &[u8]| {
        // Only decrypt if it looks like an encrypted message
        if boxed_message::is_boxed_message(ciphertext) {
            decrypter.decrypt(ciphertext).map_err(|e| e.to_string())
        } else {
            Ok(ciphertext.to_vec())
        }
    });

    let new_data = walker.walk(&data)?;
    output.write_all(&new_data)?;
    Ok(())
}

/// Decrypt a file and return the decrypted contents.
pub fn decrypt_file<P: AsRef<Path>>(
    file_path: P,
    keydir: &str,
    user_supplied_private_key: &str,
) -> Result<Vec<u8>, EjsonError> {
    let data = fs::read(file_path)?;
    let mut output = Vec::new();
    decrypt(&data[..], &mut output, keydir, user_supplied_private_key)?;
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
}
