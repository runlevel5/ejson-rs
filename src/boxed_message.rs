//! Wire format for encrypted messages.
//!
//! The schema is:
//! ```text
//! EJ[<version>:<encrypterPublic>:<nonce>:<ciphertext>]
//! ```
//! Where:
//! - version: Schema version (currently "1")
//! - encrypterPublic: Base64-encoded 32-byte public key
//! - nonce: Base64-encoded 24-byte nonce
//! - ciphertext: Base64-encoded encrypted data

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use regex::Regex;
use std::fmt;
use std::sync::LazyLock;
use thiserror::Error;

/// Size of the nonce in bytes.
pub const NONCE_SIZE: usize = 24;

/// Size of the public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Regex pattern for parsing boxed messages.
static MESSAGE_PARSER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^EJ\[(\d):([A-Za-z0-9+=/]{44}):([A-Za-z0-9+=/]{32}):(.+)\]$").unwrap()
});

/// Errors that can occur when parsing boxed messages.
#[derive(Error, Debug)]
pub enum BoxedMessageError {
    #[error("invalid message format")]
    InvalidFormat,

    #[error("invalid base64 encoding")]
    InvalidBase64,

    #[error("public key invalid")]
    InvalidPublicKey,

    #[error("nonce invalid")]
    InvalidNonce,

    #[error("invalid schema version")]
    InvalidSchemaVersion,
}

/// A boxed message containing the encrypted data along with metadata needed for decryption.
///
/// Security: Debug output redacts sensitive cryptographic material.
#[derive(Clone)]
pub struct BoxedMessage {
    pub schema_version: u8,
    pub encrypter_public: [u8; PUBLIC_KEY_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub box_data: Vec<u8>,
}

// Custom Debug implementation that redacts sensitive cryptographic material
impl fmt::Debug for BoxedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxedMessage")
            .field("schema_version", &self.schema_version)
            .field("encrypter_public", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("box_data", &format!("[{} bytes]", self.box_data.len()))
            .finish()
    }
}

impl BoxedMessage {
    /// Estimate the serialized size of a boxed message.
    /// Useful for pre-allocating buffers.
    pub fn estimate_size(plaintext_len: usize) -> usize {
        // EJ[1: + base64(32) + : + base64(24) + : + base64(ciphertext) + ]
        // ciphertext = plaintext + 16 bytes (Poly1305 tag)
        // base64 size = (n + 2) / 3 * 4
        let ciphertext_len = plaintext_len + 16;
        let box_b64_len = ciphertext_len.div_ceil(3) * 4;
        4 + 44 + 1 + 32 + 1 + box_b64_len + 1 // EJ[1: + pub + : + nonce + : + box + ]
    }

    /// Serialize the boxed message to wire format.
    pub fn dump(&self) -> Vec<u8> {
        // Pre-allocate with estimated size
        let estimated_size = Self::estimate_size(self.box_data.len());
        let mut result = Vec::with_capacity(estimated_size);

        result.extend_from_slice(b"EJ[");
        result.extend_from_slice(self.schema_version.to_string().as_bytes());
        result.push(b':');
        result.extend_from_slice(BASE64.encode(self.encrypter_public).as_bytes());
        result.push(b':');
        result.extend_from_slice(BASE64.encode(self.nonce).as_bytes());
        result.push(b':');
        result.extend_from_slice(BASE64.encode(&self.box_data).as_bytes());
        result.push(b']');

        result
    }

    /// Parse a boxed message from wire format.
    pub fn load(data: &[u8]) -> Result<Self, BoxedMessageError> {
        let s = std::str::from_utf8(data).map_err(|_| BoxedMessageError::InvalidFormat)?;

        let captures = MESSAGE_PARSER
            .captures(s)
            .ok_or(BoxedMessageError::InvalidFormat)?;

        // Parse schema version
        let schema_version: u8 = captures
            .get(1)
            .ok_or(BoxedMessageError::InvalidFormat)?
            .as_str()
            .parse()
            .map_err(|_| BoxedMessageError::InvalidSchemaVersion)?;

        // Decode public key
        let pub_b64 = captures
            .get(2)
            .ok_or(BoxedMessageError::InvalidFormat)?
            .as_str();
        let pub_bytes = BASE64
            .decode(pub_b64)
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        let encrypter_public: [u8; PUBLIC_KEY_SIZE] = pub_bytes
            .try_into()
            .map_err(|_| BoxedMessageError::InvalidPublicKey)?;

        // Decode nonce
        let nonce_b64 = captures
            .get(3)
            .ok_or(BoxedMessageError::InvalidFormat)?
            .as_str();
        let nonce_bytes = BASE64
            .decode(nonce_b64)
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        let nonce: [u8; NONCE_SIZE] = nonce_bytes
            .try_into()
            .map_err(|_| BoxedMessageError::InvalidNonce)?;

        // Decode ciphertext
        let box_b64 = captures
            .get(4)
            .ok_or(BoxedMessageError::InvalidFormat)?
            .as_str();
        let box_data = BASE64
            .decode(box_b64)
            .map_err(|_| BoxedMessageError::InvalidBase64)?;

        Ok(Self {
            schema_version,
            encrypter_public,
            nonce,
            box_data,
        })
    }
}

/// Check if data is in boxed message format.
/// Uses a fast prefix check instead of full regex matching.
pub fn is_boxed_message(data: &[u8]) -> bool {
    // Fast path: check prefix first
    if !data.starts_with(b"EJ[") {
        return false;
    }
    // Only run full regex validation if prefix matches
    if let Ok(s) = std::str::from_utf8(data) {
        MESSAGE_PARSER.is_match(s)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boxed_message_roundtrip() {
        let msg = BoxedMessage {
            schema_version: 1,
            encrypter_public: [1u8; 32],
            nonce: [2u8; 24],
            box_data: vec![3, 4, 5, 6, 7, 8, 9, 10],
        };

        let serialized = msg.dump();
        let parsed = BoxedMessage::load(&serialized).unwrap();

        assert_eq!(parsed.schema_version, msg.schema_version);
        assert_eq!(parsed.encrypter_public, msg.encrypter_public);
        assert_eq!(parsed.nonce, msg.nonce);
        assert_eq!(parsed.box_data, msg.box_data);
    }

    #[test]
    fn test_is_boxed_message() {
        // Valid format
        let valid = b"EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:AwQFBgcICQo=]";
        assert!(is_boxed_message(valid));

        // Invalid formats
        assert!(!is_boxed_message(b"not encrypted"));
        assert!(!is_boxed_message(b"EJ[invalid"));
        assert!(!is_boxed_message(b""));
    }
}
