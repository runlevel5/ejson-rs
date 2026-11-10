//! Format handler trait for unified file format support.
//!
//! This module provides a trait-based abstraction for handling different
//! encrypted file formats (JSON, YAML, TOML). Implementing this trait
//! makes it easy to add support for new formats.

use thiserror::Error;

use crate::crypto::CryptoError;

/// The standard key name at which the public key is stored in encrypted documents.
pub const PUBLIC_KEY_FIELD: &str = "_public_key";

/// Size of the public key in bytes.
pub const KEY_SIZE: usize = 32;

/// Decode a legacy (`v1`) public key: exactly 64 hex characters.
pub(crate) fn decode_legacy_public_key(key: &str) -> Option<[u8; KEY_SIZE]> {
    let mut bytes = [0u8; KEY_SIZE];
    hex::decode_to_slice(key, &mut bytes).ok()?;
    Some(bytes)
}

/// Type alias for the action function used in walk operations.
///
/// This function takes a byte slice (the value to encrypt/decrypt) and returns
/// either the transformed bytes or the [`CryptoError`] that stopped it.
pub type WalkAction<'a> = &'a (dyn Fn(&[u8]) -> Result<Vec<u8>, CryptoError> + 'a);

/// What can go wrong while reading or rewriting a document, in any format.
///
/// Messages never quote the document, which may contain secrets.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FormatError {
    /// The document has no top-level `_public_key`.
    #[error("public key not present in file")]
    PublicKeyMissing,

    /// `_public_key` is present but is not a single string.
    #[error("public key has invalid format")]
    PublicKeyInvalid,

    /// The document is not valid JSON, YAML or TOML. `message` says what is
    /// wrong and, where known, the line and column.
    #[error("invalid {format}: {message}")]
    InvalidSyntax {
        /// `"JSON"`, `"YAML"` or `"TOML"`.
        format: &'static str,
        message: String,
    },

    /// Objects and arrays are nested more than `max` levels deep.
    #[error("invalid {format}: nested more than {max} levels deep")]
    NestingTooDeep {
        /// `"JSON"`, `"YAML"` or `"TOML"`.
        format: &'static str,
        max: usize,
    },

    /// Encrypting or decrypting a value failed. The message is the cause's.
    #[error(transparent)]
    ActionFailed(#[from] CryptoError),
}

/// A trait for handling encrypted file formats.
///
/// Implementors of this trait provide format-specific logic for:
/// - Extracting public keys from documents
/// - Walking the document tree and applying encrypt/decrypt actions to values
/// - Transforming keys (e.g., trimming underscore prefixes)
///
/// # Example: Adding a new format
///
/// ```
/// use ejson::handler::{FormatHandler, FormatError, WalkAction};
///
/// pub struct XmlHandler;
///
/// impl FormatHandler for XmlHandler {
///     fn format_name(&self) -> &'static str {
///         "XML"
///     }
///
///     fn extract_public_key_string(&self, data: &[u8]) -> Result<String, FormatError> {
///         // Parse XML and return the _public_key attribute/element as written
///         todo!()
///     }
///
///     fn walk(&self, data: &[u8], action: WalkAction<'_>) -> Result<Vec<u8>, FormatError> {
///         // Walk XML tree, apply action to encryptable string values
///         todo!()
///     }
///
///     fn trim_underscore_prefix_from_keys(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
///         // Transform XML keys/attributes
///         todo!()
///     }
/// }
/// ```
pub trait FormatHandler: Send + Sync {
    /// Returns the human-readable name of this format (e.g., "JSON", "YAML", "TOML").
    fn format_name(&self) -> &'static str;

    /// Extract the document's `_public_key` value as written, without
    /// interpreting it.
    ///
    /// The scheme is detected from this string by [`crate::keys::PublicKey::parse`]:
    /// a `v1` key is 64 hex characters, a `v2` key begins with `v2:`.
    fn extract_public_key_string(&self, data: &[u8]) -> Result<String, FormatError>;

    /// Walk the document tree and apply an action to encryptable string values.
    ///
    /// A value is encryptable if:
    /// - It's a string value (not a key/field name)
    /// - Its parent key does NOT begin with an underscore
    ///
    /// Note: The underscore prefix does NOT propagate to nested values.
    /// For example, in `{"_comment": {"inner": "value"}}`, the "value" string
    /// SHOULD be encrypted because underscore doesn't propagate to nested mappings.
    fn walk(&self, data: &[u8], action: WalkAction<'_>) -> Result<Vec<u8>, FormatError>;

    /// Trim the first leading underscore from all keys in the document.
    ///
    /// The `_public_key` field should be excluded from trimming.
    fn trim_underscore_prefix_from_keys(&self, data: &[u8]) -> Result<Vec<u8>, FormatError>;

    /// Optional preprocessing step before walking (e.g., collapse multiline strings).
    ///
    /// Default implementation returns the data unchanged.
    fn preprocess(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal test handler for unit testing
    struct TestHandler;

    impl FormatHandler for TestHandler {
        fn format_name(&self) -> &'static str {
            "TEST"
        }

        fn extract_public_key_string(&self, _data: &[u8]) -> Result<String, FormatError> {
            Err(FormatError::PublicKeyMissing)
        }

        fn walk(&self, data: &[u8], _action: WalkAction<'_>) -> Result<Vec<u8>, FormatError> {
            Ok(data.to_vec())
        }

        fn trim_underscore_prefix_from_keys(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
            Ok(data.to_vec())
        }
    }

    #[test]
    fn test_format_handler_trait() {
        let handler = TestHandler;
        assert_eq!(handler.format_name(), "TEST");
        assert!(matches!(
            handler.extract_public_key_string(b"test"),
            Err(FormatError::PublicKeyMissing)
        ));
    }

    #[test]
    fn test_decode_legacy_public_key() {
        let hex = "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f";
        let key = decode_legacy_public_key(hex).unwrap();
        assert_eq!(hex::encode(key), hex);
        assert_eq!(decode_legacy_public_key(&hex.to_uppercase()), Some(key));

        assert_eq!(decode_legacy_public_key(""), None);
        assert_eq!(decode_legacy_public_key(&hex[..63]), None);
        assert_eq!(decode_legacy_public_key(&format!("{hex}0")), None);
        assert_eq!(decode_legacy_public_key(&format!("{hex}00")), None);
        assert_eq!(decode_legacy_public_key(&hex.replace('6', "g")), None);
        assert_eq!(decode_legacy_public_key(&format!(" {}", &hex[1..])), None);
    }

    #[test]
    fn test_default_preprocess() {
        let handler = TestHandler;
        let data = b"unchanged data";
        let result = handler.preprocess(data).unwrap();
        assert_eq!(result, data);
    }
}
