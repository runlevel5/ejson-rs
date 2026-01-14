//! Cryptographic operations for ejson using NaCl Box (Curve25519 + XSalsa20 + Poly1305).
//!
//! This module provides a simple convenience wrapper around crypto_box.
//! It models a situation where you don't care about authenticating the encryptor,
//! so the nonce and encryption public key are prepended to the encrypted message.

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use thiserror::Error;

use crate::boxed_message::{is_boxed_message, BoxedMessage};

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
#[derive(Clone)]
pub struct Keypair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl Keypair {
    /// Generate a new random Curve25519 keypair.
    pub fn generate() -> Result<Self, CryptoError> {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = secret_key.public_key();

        Ok(Self {
            public: public_key.as_bytes().to_owned(),
            private: secret_key.to_bytes(),
        })
    }

    /// Create a keypair from existing public and private keys.
    pub fn from_keys(public: [u8; 32], private: [u8; 32]) -> Self {
        Self { public, private }
    }

    /// Returns the public key as a hex-encoded string.
    pub fn public_string(&self) -> String {
        hex::encode(self.public)
    }

    /// Returns the private key as a hex-encoded string.
    pub fn private_string(&self) -> String {
        hex::encode(self.private)
    }

    /// Create an Encrypter for encrypting messages to a peer's public key.
    pub fn encrypter(&self, peer_public: [u8; 32]) -> Encrypter {
        Encrypter::new(self.clone(), peer_public)
    }

    /// Create a Decrypter for decrypting messages.
    pub fn decrypter(&self) -> Decrypter {
        Decrypter::new(self.clone())
    }
}

/// Encrypter encrypts messages using NaCl Box.
///
/// Typically created from an ephemeral keypair for a single encryption session.
pub struct Encrypter {
    keypair: Keypair,
    #[allow(dead_code)]
    peer_public: [u8; 32],
    salsa_box: SalsaBox,
}

impl Encrypter {
    /// Create a new Encrypter with precomputed shared key.
    pub fn new(keypair: Keypair, peer_public: [u8; 32]) -> Self {
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
pub struct Decrypter {
    keypair: Keypair,
}

impl Decrypter {
    /// Create a new Decrypter from a keypair.
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Decrypt a message in boxed message format.
    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let boxed = BoxedMessage::load(message).map_err(|_| CryptoError::InvalidMessageFormat)?;
        self.decrypt_boxed(&boxed)
    }

    fn decrypt_boxed(&self, boxed: &BoxedMessage) -> Result<Vec<u8>, CryptoError> {
        let secret_key = SecretKey::from(self.keypair.private);
        let peer_public = PublicKey::from(boxed.encrypter_public);
        let salsa_box = SalsaBox::new(&peer_public, &secret_key);

        let nonce = boxed.nonce.into();
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

        let encrypter = sender_kp.encrypter(receiver_kp.public);
        let decrypter = receiver_kp.decrypter();

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
}
