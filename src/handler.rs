//! Format handler trait for unified file format support.
//!
//! This module provides a trait-based abstraction for handling different
//! encrypted file formats (JSON, YAML, TOML). Implementing this trait
//! makes it easy to add support for new formats.

use thiserror::Error;

/// The standard key name at which the public key is stored in encrypted documents.
pub const PUBLIC_KEY_FIELD: &str = "_public_key";

/// Size of the public key in bytes.
pub const KEY_SIZE: usize = 32;

/// Type alias for the action function used in walk operations.
///
/// This function takes a byte slice (the value to encrypt/decrypt) and returns
/// either the transformed bytes or an error message.
pub type WalkAction<'a> = &'a (dyn Fn(&[u8]) -> Result<Vec<u8>, String> + 'a);

/// Common errors that can occur during format processing.
///
/// Format-specific handlers can define their own error types that implement
/// `Into<FormatError>` for integration with the unified error handling.
#[derive(Error, Debug)]
pub enum FormatError {
    #[error("public key not present in file")]
    PublicKeyMissing,

    #[error("public key has invalid format")]
    PublicKeyInvalid,

    #[error("invalid {format} syntax: {message}")]
    InvalidSyntax {
        format: &'static str,
        message: String,
    },

    #[error("action failed: {0}")]
    ActionFailed(String),
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
/// ```ignore
/// use ejson::handler::{FormatHandler, FormatError, KEY_SIZE, WalkAction};
///
/// pub struct XmlHandler;
///
/// impl FormatHandler for XmlHandler {
///     fn format_name(&self) -> &'static str {
///         "XML"
///     }
///
///     fn extract_public_key(&self, data: &[u8]) -> Result<[u8; KEY_SIZE], FormatError> {
///         // Parse XML and extract _public_key attribute/element
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

    /// Extract the public key from the document.
    ///
    /// The public key should be stored in a field named `_public_key` as a
    /// hex-encoded 32-byte string.
    fn extract_public_key(&self, data: &[u8]) -> Result<[u8; KEY_SIZE], FormatError>;

    /// Extract the raw `_public_key` value as a string, without interpreting it.
    ///
    /// This is used for scheme detection: a legacy `v1` key is a 64-character hex
    /// string, while a hybrid `v2` key begins with `v2:`. The default implementation
    /// delegates to [`FormatHandler::extract_public_key`] and hex-encodes the result,
    /// so existing handlers keep working (legacy-only). Handlers that want to support
    /// the `v2` scheme should override this to return the raw field value.
    fn extract_public_key_string(&self, data: &[u8]) -> Result<String, FormatError> {
        Ok(hex::encode(self.extract_public_key(data)?))
    }

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

/// Extension trait for working with boxed format handlers.
///
/// This allows using `Box<dyn FormatHandler>` with the same ergonomics
/// as concrete handler types.
impl FormatHandler for Box<dyn FormatHandler> {
    fn format_name(&self) -> &'static str {
        (**self).format_name()
    }

    fn extract_public_key(&self, data: &[u8]) -> Result<[u8; KEY_SIZE], FormatError> {
        (**self).extract_public_key(data)
    }

    fn extract_public_key_string(&self, data: &[u8]) -> Result<String, FormatError> {
        (**self).extract_public_key_string(data)
    }

    fn walk(&self, data: &[u8], action: WalkAction<'_>) -> Result<Vec<u8>, FormatError> {
        (**self).walk(data, action)
    }

    fn trim_underscore_prefix_from_keys(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        (**self).trim_underscore_prefix_from_keys(data)
    }

    fn preprocess(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        (**self).preprocess(data)
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

        fn extract_public_key(&self, _data: &[u8]) -> Result<[u8; KEY_SIZE], FormatError> {
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
            handler.extract_public_key(b"test"),
            Err(FormatError::PublicKeyMissing)
        ));
    }

    #[test]
    fn test_default_preprocess() {
        let handler = TestHandler;
        let data = b"unchanged data";
        let result = handler.preprocess(data).unwrap();
        assert_eq!(result, data);
    }
}
