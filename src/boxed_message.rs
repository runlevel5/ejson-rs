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

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use regex::Regex;
use std::fmt;
use std::sync::LazyLock;
use thiserror::Error;

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
    pub encrypter_public: [u8; 32],
    pub nonce: [u8; 24],
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
    /// Serialize the boxed message to wire format.
    pub fn dump(&self) -> Vec<u8> {
        let pub_b64 = BASE64.encode(self.encrypter_public);
        let nonce_b64 = BASE64.encode(self.nonce);
        let box_b64 = BASE64.encode(&self.box_data);

        format!(
            "EJ[{}:{}:{}:{}]",
            self.schema_version, pub_b64, nonce_b64, box_b64
        )
        .into_bytes()
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
        if pub_bytes.len() != 32 {
            return Err(BoxedMessageError::InvalidPublicKey);
        }
        let mut encrypter_public = [0u8; 32];
        encrypter_public.copy_from_slice(&pub_bytes);

        // Decode nonce
        let nonce_b64 = captures
            .get(3)
            .ok_or(BoxedMessageError::InvalidFormat)?
            .as_str();
        let nonce_bytes = BASE64
            .decode(nonce_b64)
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        if nonce_bytes.len() != 24 {
            return Err(BoxedMessageError::InvalidNonce);
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

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
pub fn is_boxed_message(data: &[u8]) -> bool {
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
