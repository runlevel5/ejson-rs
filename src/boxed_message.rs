//! Wire format for encrypted messages.
//!
//! Two schema versions are supported:
//!
//! ```text
//! EJ[1:<encrypterPublic>:<nonce>:<ciphertext>]                    (legacy NaCl box)
//! EJ[2:<ephemeralX25519Public>:<mlkemCiphertext>:<nonce>:<box>]   (hybrid post-quantum)
//! ```
//!
//! The v1 fields are:
//! - encrypterPublic: Base64-encoded 32-byte public key
//! - nonce: Base64-encoded 24-byte nonce
//! - ciphertext: Base64-encoded encrypted data
//!
//! The v2 fields are handled in [`crate::hybrid`]; this module provides the shared
//! envelope parser ([`parse_boxed_envelope`]) and the version-aware
//! [`is_boxed_message`] check.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::fmt;
use thiserror::Error;

/// Size of the nonce in bytes.
pub const NONCE_SIZE: usize = 24;

/// Size of the public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Schema version for the legacy NaCl-box format.
pub const SCHEMA_VERSION_LEGACY: u8 = 1;

/// Schema version for the hybrid post-quantum format.
pub const SCHEMA_VERSION_HYBRID: u8 = 2;

/// Parse the `EJ[<version>:<field>:...]` envelope common to all schema versions.
///
/// Returns the numeric version and the colon-separated fields that follow it, borrowed
/// from `data` (no copies — the fields can be several kilobytes for v2 messages). The
/// fields themselves are NOT decoded or validated here; callers validate the field count
/// and contents for their specific schema version.
pub fn parse_boxed_envelope(data: &[u8]) -> Result<(u8, Vec<&str>), BoxedMessageError> {
    let s = std::str::from_utf8(data).map_err(|_| BoxedMessageError::InvalidFormat)?;
    let body = s
        .strip_prefix("EJ[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(BoxedMessageError::InvalidFormat)?;

    let (version_str, rest) = body
        .split_once(':')
        .ok_or(BoxedMessageError::InvalidFormat)?;
    if version_str.is_empty() || rest.is_empty() {
        return Err(BoxedMessageError::InvalidFormat);
    }

    let version: u8 = version_str
        .parse()
        .map_err(|_| BoxedMessageError::InvalidSchemaVersion)?;

    let fields = rest.split(':').collect();
    Ok((version, fields))
}

/// Returns true if `s` decodes as standard base64 to exactly `n` bytes.
fn is_base64_len(s: &str, n: usize) -> bool {
    BASE64.decode(s).map(|b| b.len() == n).unwrap_or(false)
}

/// Returns true if `s` is non-empty and decodes as standard base64 to a non-empty value.
fn is_base64_nonempty(s: &str) -> bool {
    !s.is_empty() && BASE64.decode(s).map(|b| !b.is_empty()).unwrap_or(false)
}

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

    /// Parse a v1 boxed message from wire format.
    pub fn load(data: &[u8]) -> Result<Self, BoxedMessageError> {
        let (version, fields) = parse_boxed_envelope(data)?;
        if version != SCHEMA_VERSION_LEGACY || fields.len() != 3 {
            return Err(BoxedMessageError::InvalidFormat);
        }

        // Decode public key
        let pub_bytes = BASE64
            .decode(fields[0])
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        let encrypter_public: [u8; PUBLIC_KEY_SIZE] = pub_bytes
            .try_into()
            .map_err(|_| BoxedMessageError::InvalidPublicKey)?;

        // Decode nonce
        let nonce_bytes = BASE64
            .decode(fields[1])
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        let nonce: [u8; NONCE_SIZE] = nonce_bytes
            .try_into()
            .map_err(|_| BoxedMessageError::InvalidNonce)?;

        // Decode ciphertext
        let box_data = BASE64
            .decode(fields[2])
            .map_err(|_| BoxedMessageError::InvalidBase64)?;

        Ok(Self {
            schema_version: version,
            encrypter_public,
            nonce,
            box_data,
        })
    }
}

/// Check if data is in a supported boxed message format (v1 or v2).
///
/// Used to decide whether a string value requires encryption or is already encrypted.
/// Validates the field count and that each fixed-size field is valid base64 decoding to
/// exactly its expected byte length (and that the ciphertext field is non-empty base64).
/// This full validation matters: a value only misclassified as "already boxed" during
/// `encrypt` would be written out in cleartext, so we do not rely on length alone.
pub fn is_boxed_message(data: &[u8]) -> bool {
    // Fast path: check prefix first
    if !data.starts_with(b"EJ[") {
        return false;
    }

    let Ok((version, fields)) = parse_boxed_envelope(data) else {
        return false;
    };

    match version {
        SCHEMA_VERSION_LEGACY => {
            // EJ[1:<pub(32)>:<nonce(24)>:<box>]
            fields.len() == 3
                && is_base64_len(fields[0], PUBLIC_KEY_SIZE)
                && is_base64_len(fields[1], NONCE_SIZE)
                && is_base64_nonempty(fields[2])
        }
        SCHEMA_VERSION_HYBRID => {
            // EJ[2:<ephemeralX25519(32)>:<mlkemCt(1088)>:<nonce(24)>:<box>]
            fields.len() == 4
                && is_base64_len(fields[0], crate::hybrid::HYBRID_X25519_KEY_SIZE)
                && is_base64_len(fields[1], crate::hybrid::HYBRID_MLKEM_CIPHERTEXT_SIZE)
                && is_base64_len(fields[2], NONCE_SIZE)
                && is_base64_nonempty(fields[3])
        }
        _ => false,
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

    #[test]
    fn test_is_boxed_message_rejects_non_base64_fields() {
        // Correct field *lengths* but the fixed fields contain characters outside the
        // base64 alphabet ('*', '#'). This must NOT be classified as boxed, otherwise a
        // plaintext value of this shape would be left in cleartext on encrypt.
        let bad_pub = format!(
            "EJ[1:{}:{}:{}]",
            "*".repeat(44),
            "AgICAgICAgICAgICAgICAgICAgICAgIC",
            "AwQFBgcICQo="
        );
        assert!(!is_boxed_message(bad_pub.as_bytes()));

        let bad_nonce = format!(
            "EJ[1:{}:{}:{}]",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "#".repeat(32),
            "AwQFBgcICQo="
        );
        assert!(!is_boxed_message(bad_nonce.as_bytes()));

        // Empty ciphertext field is rejected.
        let empty_box =
            b"EJ[1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AgICAgICAgICAgICAgICAgICAgICAgIC:]";
        assert!(!is_boxed_message(empty_box));

        // Wrong decoded length for the public key field (43 'A's decodes to != 32 bytes).
        let wrong_len = format!(
            "EJ[1:{}:{}:{}]",
            "A".repeat(44),
            "AgICAgICAgICAgICAgICAgICAgICAgIC",
            "AwQFBgcICQo="
        );
        // 44 base64 chars of 'A' decode to 33 bytes, not 32.
        assert!(!is_boxed_message(wrong_len.as_bytes()));
    }
}
