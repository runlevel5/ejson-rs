//! YAML processing for eyaml files.
//!
//! This module provides functions to:
//! - Extract the public key from an eyaml document
//! - Walk the YAML tree and selectively encrypt/decrypt string values
//!
//! The walker uses `serde_yml` for parsing and serialization.

use serde_yml::{Mapping, Value};
use thiserror::Error;

/// The key name at which the public key should be stored in an EYAML document.
pub const PUBLIC_KEY_FIELD: &str = "_public_key";

/// Size of the public key in bytes.
const KEY_SIZE: usize = 32;

/// Errors that can occur during YAML processing.
#[derive(Error, Debug)]
pub enum YamlError {
    #[error("public key not present in EYAML file")]
    PublicKeyMissing,

    #[error("public key has invalid format")]
    PublicKeyInvalid,

    #[error("invalid yaml: {0}")]
    InvalidYaml(String),

    #[error("action failed: {0}")]
    ActionFailed(String),
}

/// Extract the _public_key value from an EYAML document.
pub fn extract_public_key(data: &[u8]) -> Result<[u8; KEY_SIZE], YamlError> {
    let s = String::from_utf8_lossy(data);
    let doc: Value = serde_yml::from_str(&s).map_err(|e| YamlError::InvalidYaml(e.to_string()))?;

    let key_value = doc
        .get(PUBLIC_KEY_FIELD)
        .ok_or(YamlError::PublicKeyMissing)?;

    let key_str = key_value.as_str().ok_or(YamlError::PublicKeyInvalid)?;

    if key_str.len() != KEY_SIZE * 2 {
        return Err(YamlError::PublicKeyInvalid);
    }

    let key_bytes = hex::decode(key_str).map_err(|_| YamlError::PublicKeyInvalid)?;

    key_bytes
        .try_into()
        .map_err(|_| YamlError::PublicKeyInvalid)
}

/// Walker walks a YAML structure, applying an action to encryptable string values.
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

    /// Walk the YAML data and apply the action to encryptable values.
    pub fn walk(&self, data: &[u8]) -> Result<Vec<u8>, YamlError> {
        let s = String::from_utf8_lossy(data);
        let mut doc: Value =
            serde_yml::from_str(&s).map_err(|e| YamlError::InvalidYaml(e.to_string()))?;

        // Process the document
        self.walk_value(&mut doc, false)?;

        let output =
            serde_yml::to_string(&doc).map_err(|e| YamlError::InvalidYaml(e.to_string()))?;
        Ok(output.into_bytes())
    }

    fn walk_value(&self, value: &mut Value, is_comment: bool) -> Result<(), YamlError> {
        match value {
            Value::String(s) => {
                if !is_comment {
                    let result = (self.action)(s.as_bytes()).map_err(YamlError::ActionFailed)?;
                    *s = String::from_utf8_lossy(&result).to_string();
                }
            }
            Value::Mapping(map) => {
                self.walk_mapping(map)?;
            }
            Value::Sequence(seq) => {
                for item in seq.iter_mut() {
                    self.walk_value(item, is_comment)?;
                }
            }
            // Non-string values (numbers, booleans, null) are not encrypted
            _ => {}
        }
        Ok(())
    }

    fn walk_mapping(&self, map: &mut Mapping) -> Result<(), YamlError> {
        // Collect keys first to avoid borrow issues
        let keys: Vec<Value> = map.keys().cloned().collect();

        for key in keys {
            let is_comment = key.as_str().map(|s| s.starts_with('_')).unwrap_or(false);

            if let Some(value) = map.get_mut(&key) {
                match value {
                    Value::Mapping(_) => {
                        // For nested mappings, underscore doesn't propagate to nested values
                        self.walk_value(value, false)?;
                    }
                    _ => {
                        self.walk_value(value, is_comment)?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Trim the first leading underscore from all keys in a YAML document.
/// The `_public_key` field is excluded from trimming.
pub fn trim_underscore_prefix_from_keys(data: &[u8]) -> Result<Vec<u8>, YamlError> {
    let s = String::from_utf8_lossy(data);
    let doc: Value = serde_yml::from_str(&s).map_err(|e| YamlError::InvalidYaml(e.to_string()))?;

    let transformed = transform_yaml_keys(doc);

    let output =
        serde_yml::to_string(&transformed).map_err(|e| YamlError::InvalidYaml(e.to_string()))?;
    Ok(output.into_bytes())
}

fn transform_yaml_keys(value: Value) -> Value {
    match value {
        Value::Mapping(map) => {
            let new_map: Mapping = map
                .into_iter()
                .map(|(key, val)| {
                    let new_key = if let Some(key_str) = key.as_str() {
                        if key_str.starts_with('_') && key_str != "_public_key" {
                            Value::String(key_str[1..].to_string())
                        } else {
                            key
                        }
                    } else {
                        key
                    };
                    (new_key, transform_yaml_keys(val))
                })
                .collect();
            Value::Mapping(new_map)
        }
        Value::Sequence(seq) => Value::Sequence(seq.into_iter().map(transform_yaml_keys).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_public_key() {
        let yaml =
            br#"_public_key: "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f"
secret: "value"
"#;
        let key = extract_public_key(yaml).unwrap();
        assert_eq!(
            hex::encode(key),
            "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f"
        );
    }

    #[test]
    fn test_extract_public_key_missing() {
        let yaml = br#"secret: "value""#;
        assert!(matches!(
            extract_public_key(yaml),
            Err(YamlError::PublicKeyMissing)
        ));
    }

    #[test]
    fn test_walker_with_comment_key() {
        let yaml = br#"_comment: "not encrypted"
secret: "encrypted"
"#;
        let walker = Walker::new(|data| {
            Ok(format!("ENCRYPTED:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("_comment: not encrypted"));
        assert!(
            result_str.contains("secret: 'ENCRYPTED:encrypted'")
                || result_str.contains("secret: ENCRYPTED:encrypted")
        );
    }

    #[test]
    fn test_walker_nested_mapping() {
        let yaml = br#"outer:
  inner: "value"
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("E:value"));
    }

    #[test]
    fn test_walker_underscore_does_not_propagate() {
        // Underscore prefix should NOT propagate to nested values
        let yaml = br#"_outer:
  inner: "should_encrypt"
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // The inner value SHOULD be encrypted (underscore doesn't propagate)
        assert!(result_str.contains("E:should_encrypt"));
    }

    #[test]
    fn test_walker_sequence() {
        let yaml = br#"secrets:
  - "secret1"
  - "secret2"
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("E:secret1"));
        assert!(result_str.contains("E:secret2"));
    }

    #[test]
    fn test_walker_inline_mapping() {
        let yaml = br#"credentials: { username: "admin", password: "secret123" }
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("E:admin"));
        assert!(result_str.contains("E:secret123"));
    }

    #[test]
    fn test_walker_non_string_values() {
        let yaml = br#"port: 8080
enabled: true
ratio: 1.5
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Non-string values should NOT be encrypted
        assert!(result_str.contains("port: 8080"));
        assert!(result_str.contains("enabled: true"));
        assert!(result_str.contains("ratio: 1.5"));
    }

    #[test]
    fn test_trim_underscore_prefix_from_keys() {
        let yaml = br#"_public_key: "abc123"
_secret: "value"
normal: "data"
"#;
        let result = trim_underscore_prefix_from_keys(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // _public_key should NOT be trimmed
        assert!(result_str.contains("_public_key:"));
        // Other underscore keys should have it removed
        assert!(result_str.contains("secret:"));
        assert!(result_str.contains("normal:"));
        // Should not have underscore prefix on _secret
        assert!(!result_str.contains("_secret"));
    }

    #[test]
    fn test_trim_underscore_prefix_nested_mapping() {
        let yaml = br#"_outer:
  _inner: "value"
  normal: "data"
"#;
        let result = trim_underscore_prefix_from_keys(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Both nested keys should have underscore removed
        assert!(result_str.contains("outer:"));
        assert!(result_str.contains("inner:"));
        assert!(!result_str.contains("_outer"));
        assert!(!result_str.contains("_inner"));
    }
}
