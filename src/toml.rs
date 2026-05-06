//! TOML processing for etoml files.
//!
//! This module provides functions to:
//! - Extract the public key from an etoml document
//! - Walk the TOML tree and selectively encrypt/decrypt string values
//!
//! The walker uses `toml_edit` to preserve formatting and comments.

use crate::handler::{FormatError, FormatHandler, KEY_SIZE, PUBLIC_KEY_FIELD, WalkAction};
use thiserror::Error;
use toml_edit::{DocumentMut, Item, Value};

/// Errors that can occur during TOML processing.
#[derive(Error, Debug)]
pub enum TomlError {
    #[error("public key not present in ETOML file")]
    PublicKeyMissing,

    #[error("public key has invalid format")]
    PublicKeyInvalid,

    #[error("invalid toml: {0}")]
    InvalidToml(String),

    #[error("action failed: {0}")]
    ActionFailed(String),
}

/// Extract the _public_key value from an ETOML document.
pub fn extract_public_key(data: &[u8]) -> Result<[u8; KEY_SIZE], TomlError> {
    let s = String::from_utf8_lossy(data);
    let doc: toml::Value = toml::from_str(&s).map_err(|e| TomlError::InvalidToml(e.to_string()))?;

    let key_value = doc
        .get(PUBLIC_KEY_FIELD)
        .ok_or(TomlError::PublicKeyMissing)?;

    let key_str = key_value.as_str().ok_or(TomlError::PublicKeyInvalid)?;

    if key_str.len() != KEY_SIZE * 2 {
        return Err(TomlError::PublicKeyInvalid);
    }

    let key_bytes = hex::decode(key_str).map_err(|_| TomlError::PublicKeyInvalid)?;

    key_bytes
        .try_into()
        .map_err(|_| TomlError::PublicKeyInvalid)
}

/// Walker walks a TOML structure, applying an action to encryptable string values.
///
/// A value is encryptable if:
/// - It's a string value (not a key)
/// - Its referencing key does NOT begin with an underscore
///
/// Note: The underscore prefix does NOT propagate to nested values.
pub struct Walker<F>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, String>,
{
    action: F,
}

impl<F> Walker<F>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, String>,
{
    pub fn new(action: F) -> Self {
        Self { action }
    }

    /// Walk the TOML data and apply the action to encryptable values.
    pub fn walk(&self, data: &[u8]) -> Result<Vec<u8>, TomlError> {
        let s = String::from_utf8_lossy(data);
        let mut doc: DocumentMut = s
            .parse()
            .map_err(|e: toml_edit::TomlError| TomlError::InvalidToml(e.to_string()))?;

        // Process all items in the document
        self.walk_table(doc.as_table_mut())?;

        Ok(doc.to_string().into_bytes())
    }

    fn walk_table(&self, table: &mut toml_edit::Table) -> Result<(), TomlError> {
        // Collect keys first to avoid borrow issues
        let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();

        for key in keys {
            let is_comment = key.starts_with('_');

            if let Some(item) = table.get_mut(&key) {
                self.walk_item(item, is_comment)?;
            }
        }

        Ok(())
    }

    fn walk_item(&self, item: &mut Item, is_comment: bool) -> Result<(), TomlError> {
        match item {
            Item::Value(value) => self.walk_value(value, is_comment)?,
            Item::Table(table) => {
                // For tables, underscore doesn't propagate to nested values
                self.walk_table(table)?;
            }
            Item::ArrayOfTables(array) => {
                for table in array.iter_mut() {
                    self.walk_table(table)?;
                }
            }
            Item::None => {}
        }
        Ok(())
    }

    fn walk_value(&self, value: &mut Value, is_comment: bool) -> Result<(), TomlError> {
        match value {
            Value::String(s) if !is_comment => {
                let plaintext = s.value();
                let result =
                    (self.action)(plaintext.as_bytes()).map_err(TomlError::ActionFailed)?;
                let result_str = String::from_utf8_lossy(&result).to_string();
                *s = toml_edit::Formatted::new(result_str);
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.walk_value(item, is_comment)?;
                }
            }
            Value::InlineTable(table) => {
                // For inline tables, process each key-value pair
                let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
                for key in keys {
                    let inner_is_comment = key.starts_with('_');
                    if let Some(inner_value) = table.get_mut(&key) {
                        self.walk_value(inner_value, inner_is_comment)?;
                    }
                }
            }
            // Non-string values (integers, floats, booleans, datetimes) are not encrypted
            _ => {}
        }
        Ok(())
    }
}

/// Trim the first leading underscore from all keys in a TOML document.
/// The `_public_key` field is excluded from trimming.
pub fn trim_underscore_prefix_from_keys(data: &[u8]) -> Result<Vec<u8>, TomlError> {
    let s = String::from_utf8_lossy(data);
    let mut doc: DocumentMut = s
        .parse()
        .map_err(|e: toml_edit::TomlError| TomlError::InvalidToml(e.to_string()))?;

    transform_toml_table_keys(doc.as_table_mut());

    Ok(doc.to_string().into_bytes())
}

fn transform_toml_table_keys(table: &mut toml_edit::Table) {
    // Collect keys that need to be renamed (exclude _public_key)
    let keys_to_rename: Vec<(String, String)> = table
        .iter()
        .filter_map(|(k, _)| {
            if k.starts_with('_') && k != "_public_key" {
                Some((k.to_string(), k[1..].to_string()))
            } else {
                None
            }
        })
        .collect();

    // Rename keys by removing and re-inserting with new key
    for (old_key, new_key) in keys_to_rename {
        if let Some(item) = table.remove(&old_key) {
            table.insert(&new_key, item);
        }
    }

    // Recursively process nested tables
    let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
    for key in keys {
        if let Some(item) = table.get_mut(&key) {
            transform_toml_item_keys(item);
        }
    }
}

fn transform_toml_item_keys(item: &mut Item) {
    match item {
        Item::Table(table) => {
            transform_toml_table_keys(table);
        }
        Item::ArrayOfTables(array) => {
            for table in array.iter_mut() {
                transform_toml_table_keys(table);
            }
        }
        Item::Value(value) => {
            transform_toml_value_keys(value);
        }
        Item::None => {}
    }
}

fn transform_toml_value_keys(value: &mut Value) {
    match value {
        Value::InlineTable(table) => {
            // Collect keys that need to be renamed (exclude _public_key)
            let keys_to_rename: Vec<(String, String)> = table
                .iter()
                .filter_map(|(k, _)| {
                    if k.starts_with('_') && k != "_public_key" {
                        Some((k.to_string(), k[1..].to_string()))
                    } else {
                        None
                    }
                })
                .collect();

            // Rename keys
            for (old_key, new_key) in keys_to_rename {
                if let Some(val) = table.remove(&old_key) {
                    table.insert(&new_key, val);
                }
            }

            // Recursively process nested values
            let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
            for key in keys {
                if let Some(inner_value) = table.get_mut(&key) {
                    transform_toml_value_keys(inner_value);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                transform_toml_value_keys(item);
            }
        }
        _ => {}
    }
}

// ============================================================================
// FormatHandler trait implementation
// ============================================================================

/// Convert TomlError to the unified FormatError.
impl From<TomlError> for FormatError {
    fn from(err: TomlError) -> Self {
        match err {
            TomlError::PublicKeyMissing => FormatError::PublicKeyMissing,
            TomlError::PublicKeyInvalid => FormatError::PublicKeyInvalid,
            TomlError::InvalidToml(msg) => FormatError::InvalidSyntax {
                format: "TOML",
                message: msg,
            },
            TomlError::ActionFailed(msg) => FormatError::ActionFailed(msg),
        }
    }
}

/// TOML format handler implementing the FormatHandler trait.
///
/// This handler uses `toml_edit` to preserve formatting and comments.
#[derive(Debug, Clone, Copy, Default)]
pub struct TomlHandler;

impl TomlHandler {
    /// Create a new TOML format handler.
    pub fn new() -> Self {
        Self
    }
}

impl FormatHandler for TomlHandler {
    fn format_name(&self) -> &'static str {
        "TOML"
    }

    fn extract_public_key(&self, data: &[u8]) -> Result<[u8; KEY_SIZE], FormatError> {
        extract_public_key(data).map_err(Into::into)
    }

    fn walk(&self, data: &[u8], action: WalkAction<'_>) -> Result<Vec<u8>, FormatError> {
        Walker::new(action).walk(data).map_err(Into::into)
    }

    fn trim_underscore_prefix_from_keys(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        trim_underscore_prefix_from_keys(data).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_public_key() {
        let toml =
            br#"_public_key = "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f"
secret = "value"
"#;
        let key = extract_public_key(toml).unwrap();
        assert_eq!(
            hex::encode(key),
            "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f"
        );
    }

    #[test]
    fn test_extract_public_key_missing() {
        let toml = br#"secret = "value""#;
        assert!(matches!(
            extract_public_key(toml),
            Err(TomlError::PublicKeyMissing)
        ));
    }

    #[test]
    fn test_walker_with_comment_key() {
        let toml = br#"_comment = "not encrypted"
secret = "encrypted"
"#;
        let walker = Walker::new(|data| {
            Ok(format!("ENCRYPTED:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#"_comment = "not encrypted""#));
        assert!(result_str.contains(r#"secret = "ENCRYPTED:encrypted""#));
    }

    #[test]
    fn test_walker_nested_table() {
        let toml = br#"[outer]
inner = "value"
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#"inner = "E:value""#));
    }

    #[test]
    fn test_walker_underscore_does_not_propagate() {
        // Underscore prefix should NOT propagate to nested values
        let toml = br#"[_outer]
inner = "should_encrypt"
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // The inner value SHOULD be encrypted (underscore doesn't propagate)
        assert!(result_str.contains(r#"inner = "E:should_encrypt""#));
    }

    #[test]
    fn test_walker_array() {
        let toml = br#"secrets = ["secret1", "secret2"]
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""E:secret1""#));
        assert!(result_str.contains(r#""E:secret2""#));
    }

    #[test]
    fn test_walker_inline_table() {
        let toml = br#"credentials = { username = "admin", password = "secret123" }
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""E:admin""#));
        assert!(result_str.contains(r#""E:secret123""#));
    }

    #[test]
    fn test_walker_non_string_values() {
        let toml = br#"port = 8080
enabled = true
ratio = 1.5
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Non-string values should NOT be encrypted
        assert!(result_str.contains("port = 8080"));
        assert!(result_str.contains("enabled = true"));
        assert!(result_str.contains("ratio = 1.5"));
    }

    #[test]
    fn test_trim_underscore_prefix_from_keys() {
        let toml = br#"_public_key = "abc123"
_secret = "value"
normal = "data"
"#;
        let result = trim_underscore_prefix_from_keys(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // _public_key should NOT be trimmed
        assert!(result_str.contains("_public_key = "));
        // Other underscore keys should have it removed
        assert!(result_str.contains("secret = "));
        assert!(result_str.contains("normal = "));
        // Should not have underscore prefix on _secret
        assert!(!result_str.contains("_secret"));
    }

    #[test]
    fn test_trim_underscore_prefix_nested_table() {
        let toml = br#"[_outer]
_inner = "value"
normal = "data"
"#;
        let result = trim_underscore_prefix_from_keys(toml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Both nested keys should have underscore removed
        assert!(result_str.contains("[outer]"));
        assert!(result_str.contains("inner = "));
        assert!(!result_str.contains("_outer"));
        assert!(!result_str.contains("_inner"));
    }
}
