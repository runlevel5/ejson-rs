//! Cryptographic operations for ejson using NaCl Box (Curve25519 + XSalsa20 + Poly1305).
//!
//! This module provides a simple convenience wrapper around crypto_box.
//! It models a situation where you don't care about authenticating the encryptor,
//! so the nonce and encryption public key are prepended to the encrypted message.

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::boxed_message::{is_boxed_message, BoxedMessage};

/// Size of a public or private key in bytes.
pub const KEY_SIZE: usize = 32;

/// Type alias for a 32-byte key array.
pub type KeyBytes = [u8; KEY_SIZE];

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("couldn't decrypt message")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("failed to generate random bytes")]
    RandomGenerationFailed,

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("invalid message format")]
    InvalidMessageFormat,
}

/// A Curve25519 keypair for encryption/decryption operations.
///
/// Security: Private key material is automatically zeroized when the struct is dropped.
/// Clone is intentionally not implemented to prevent uncontrolled duplication of key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    #[zeroize(skip)] // Public key doesn't need zeroizing
    pub public: KeyBytes,
    pub private: KeyBytes,
}

// Custom Debug implementation that redacts the private key
impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &hex::encode(self.public))
            .field("private", &"[REDACTED]")
            .finish()
    }
}

impl Keypair {
    /// Generate a new random Curve25519 keypair.
    pub fn generate() -> Result<Self, CryptoError> {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = secret_key.public_key();

        Ok(Self {
            public: *public_key.as_bytes(),
            private: secret_key.to_bytes(),
        })
    }

    /// Create a keypair from existing public and private keys.
    pub fn from_keys(public: KeyBytes, private: KeyBytes) -> Self {
        Self { public, private }
    }

    /// Returns the public key as a hex-encoded string.
    pub fn public_string(&self) -> String {
        hex::encode(self.public)
    }

    /// Returns the private key as a hex-encoded string.
    ///
    /// Security: The returned string should be wrapped in `Zeroizing<String>` by the caller
    /// if it will be stored.
    pub fn private_string(&self) -> String {
        hex::encode(self.private)
    }

    /// Create an Encrypter for encrypting messages to a peer's public key.
    ///
    /// This consumes the keypair to prevent multiple copies of key material.
    pub fn into_encrypter(self, peer_public: KeyBytes) -> Encrypter {
        Encrypter::new(self, peer_public)
    }

    /// Create a Decrypter for decrypting messages.
    ///
    /// This consumes the keypair to prevent multiple copies of key material.
    pub fn into_decrypter(self) -> Decrypter {
        Decrypter::new(self)
    }

    /// Create an Encrypter while keeping the keypair (for cases where both encrypt and decrypt are needed).
    ///
    /// Security: This copies the private key material. Use sparingly.
    pub fn encrypter(&self, peer_public: KeyBytes) -> Encrypter {
        let kp = Self::from_keys(self.public, self.private);
        Encrypter::new(kp, peer_public)
    }

    /// Create a Decrypter while keeping the keypair (for cases where both encrypt and decrypt are needed).
    ///
    /// Security: This copies the private key material. Use sparingly.
    pub fn decrypter(&self) -> Decrypter {
        let kp = Self::from_keys(self.public, self.private);
        Decrypter::new(kp)
    }
}

/// Encrypter encrypts messages using NaCl Box.
///
/// Typically created from an ephemeral keypair for a single encryption session.
/// Security: Key material is automatically zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encrypter {
    keypair: Keypair,
    #[zeroize(skip)]
    peer_public: KeyBytes,
    #[zeroize(skip)] // SalsaBox handles its own cleanup
    salsa_box: SalsaBox,
}

// Custom Debug implementation that redacts sensitive data
impl fmt::Debug for Encrypter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypter")
            .field("keypair", &"[REDACTED]")
            .field("peer_public", &hex::encode(self.peer_public))
            .finish()
    }
}

impl Encrypter {
    /// Create a new Encrypter with precomputed shared key.
    pub fn new(keypair: Keypair, peer_public: KeyBytes) -> Self {
        let secret_key = SecretKey::from(keypair.private);
        let public_key = PublicKey::from(peer_public);
        let salsa_box = SalsaBox::new(&public_key, &secret_key);

        Self {
            keypair,
            peer_public,
            salsa_box,
        }
    }

    /// Encrypt a message, returning the encrypted bytes in boxed message format.
    ///
    /// If the message is already encrypted (starts with "EJ["), it is returned unchanged.
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // If already encrypted, return as-is
        if is_boxed_message(message) {
            return Ok(message.to_vec());
        }

        let boxed = self.encrypt_raw(message)?;
        Ok(boxed.dump())
    }

    fn encrypt_raw(&self, message: &[u8]) -> Result<BoxedMessage, CryptoError> {
        let nonce = SalsaBox::generate_nonce(&mut OsRng);

        let ciphertext = self
            .salsa_box
            .encrypt(&nonce, message)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(BoxedMessage {
            schema_version: 1,
            encrypter_public: self.keypair.public,
            nonce: nonce.into(),
            box_data: ciphertext,
        })
    }
}

/// Decrypter decrypts messages using NaCl Box.
///
/// This implementation caches the precomputed shared key (SalsaBox) for each
/// unique encrypter public key, significantly improving performance when
/// decrypting multiple messages from the same encrypter (which is the common
/// case in ejson files where all values are encrypted with the same ephemeral key).
///
/// Security: Key material is automatically zeroized when dropped.
pub struct Decrypter {
    keypair: Keypair,
    /// Cache of SalsaBox instances keyed by encrypter public key.
    /// Uses RefCell for interior mutability since decrypt takes &self.
    cache: RefCell<HashMap<KeyBytes, SalsaBox>>,
}

// Manual Zeroize implementation since we can't derive it with RefCell
impl Drop for Decrypter {
    fn drop(&mut self) {
        self.keypair.private.zeroize();
    }
}

// Custom Debug implementation that redacts sensitive data
impl fmt::Debug for Decrypter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decrypter")
            .field("keypair", &"[REDACTED]")
            .field("cached_keys", &self.cache.borrow().len())
            .finish()
    }
}

impl Decrypter {
    /// Create a new Decrypter from a keypair.
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// Decrypt a message in boxed message format.
    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let boxed = BoxedMessage::load(message).map_err(|_| CryptoError::InvalidMessageFormat)?;
        self.decrypt_boxed(&boxed)
    }

    fn decrypt_boxed(&self, boxed: &BoxedMessage) -> Result<Vec<u8>, CryptoError> {
        let nonce = boxed.nonce.into();

        // Check if we have a cached SalsaBox for this encrypter
        let mut cache = self.cache.borrow_mut();

        let salsa_box = cache.entry(boxed.encrypter_public).or_insert_with(|| {
            let secret_key = SecretKey::from(self.keypair.private);
            let peer_public = PublicKey::from(boxed.encrypter_public);
            SalsaBox::new(&peer_public, &secret_key)
        });

        salsa_box
            .decrypt(&nonce, boxed.box_data.as_slice())
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = Keypair::generate().unwrap();
        assert_eq!(kp.public.len(), 32);
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public_string().len(), 64);
        assert_eq!(kp.private_string().len(), 64);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender_kp = Keypair::generate().unwrap();
        let receiver_kp = Keypair::generate().unwrap();
        let receiver_public = receiver_kp.public;

        let encrypter = sender_kp.into_encrypter(receiver_public);
        let decrypter = receiver_kp.into_decrypter();

        let plaintext = b"Hello, World!";
        let encrypted = encrypter.encrypt(plaintext).unwrap();
        let decrypted = decrypter.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_already_encrypted_passthrough() {
        let kp = Keypair::generate().unwrap();
        let encrypter = kp.encrypter(kp.public);

        // First encryption
        let plaintext = b"secret";
        let encrypted = encrypter.encrypt(plaintext).unwrap();

        // Second encryption should return same bytes
        let double_encrypted = encrypter.encrypt(&encrypted).unwrap();
        assert_eq!(encrypted, double_encrypted);
    }

    #[test]
    fn test_keypair_debug_redacts_private_key() {
        let kp = Keypair::generate().unwrap();
        let debug_output = format!("{:?}", kp);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(&kp.private_string()));
    }
}
