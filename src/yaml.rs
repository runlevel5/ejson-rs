//! YAML processing for eyaml files.
//!
//! This module provides functions to:
//! - Extract the public key from an eyaml document
//! - Walk the YAML tree and selectively encrypt/decrypt string values
//!
//! The walker uses `serde_norway` for parsing and serialization.

use crate::handler::{FormatError, FormatHandler, KEY_SIZE, PUBLIC_KEY_FIELD, WalkAction};
use serde_norway::{Mapping, Value};
use thiserror::Error;

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

/// Build an `InvalidYaml` error that never quotes document values.
///
/// Parser errors from `serde_norway` only give a location, but deserialisation
/// errors echo the offending value (`invalid value: string "hunter2", ...`),
/// which in an EYAML file is often a plaintext secret. Quoted fragments are
/// redacted; the rest of the message and the location are kept.
pub(crate) fn invalid_yaml(err: serde_norway::Error) -> YamlError {
    YamlError::InvalidYaml(redact_quoted(&err.to_string()))
}

/// Replace the contents of `"..."` and `` `...` `` fragments with `...`.
fn redact_quoted(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut open: Option<char> = None;
    for c in msg.chars() {
        match open {
            Some(q) if c == q => {
                out.push_str("...");
                out.push(c);
                open = None;
            }
            Some(_) => {}
            None => {
                out.push(c);
                if c == '"' || c == '`' {
                    open = Some(c);
                }
            }
        }
    }
    if open.is_some() {
        out.push_str("...");
    }
    out
}

/// Extract the raw `_public_key` string value from an EYAML document.
pub fn extract_public_key_string(data: &[u8]) -> Result<String, YamlError> {
    let s = String::from_utf8_lossy(data);
    let doc: Value = serde_norway::from_str(&s).map_err(invalid_yaml)?;

    let key_value = doc
        .get(PUBLIC_KEY_FIELD)
        .ok_or(YamlError::PublicKeyMissing)?;

    key_value
        .as_str()
        .map(str::to_string)
        .ok_or(YamlError::PublicKeyInvalid)
}

/// Extract the _public_key value from an EYAML document as a legacy 32-byte key.
pub fn extract_public_key(data: &[u8]) -> Result<[u8; KEY_SIZE], YamlError> {
    let key_str = extract_public_key_string(data)?;

    if key_str.len() != KEY_SIZE * 2 {
        return Err(YamlError::PublicKeyInvalid);
    }

    let key_bytes = hex::decode(&key_str).map_err(|_| YamlError::PublicKeyInvalid)?;

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
        let mut doc: Value = serde_norway::from_str(&s).map_err(invalid_yaml)?;

        // Process the document
        self.walk_value(&mut doc, false)?;

        let output = serde_norway::to_string(&doc).map_err(invalid_yaml)?;
        Ok(output.into_bytes())
    }

    fn walk_value(&self, value: &mut Value, is_comment: bool) -> Result<(), YamlError> {
        match value {
            Value::String(s) if !is_comment => {
                let result = (self.action)(s.as_bytes()).map_err(YamlError::ActionFailed)?;
                *s = String::from_utf8_lossy(&result).to_string();
            }
            Value::Mapping(map) => {
                self.walk_mapping(map)?;
            }
            Value::Sequence(seq) => {
                for item in seq.iter_mut() {
                    self.walk_value(item, is_comment)?;
                }
            }
            // A tag (e.g. `!secret value`) doesn't change whether the value is
            // encryptable; skipping it here would leave the value in plaintext.
            Value::Tagged(tagged) => {
                self.walk_value(&mut tagged.value, is_comment)?;
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

/// List the values that `encrypt` leaves in plaintext only because YAML
/// parses them as numbers or booleans.
///
/// ejson only encrypts strings, but in YAML an unquoted `pin: 123456` or
/// `enabled: true` is a number or a bool, so a value that looks like any other
/// secret silently stays readable. (`yes`/`no` are strings in YAML 1.2, so
/// they are encrypted and not reported.) Returns the dotted path of each such value
/// (e.g. `db.port`, `pins[0]`) in a position that would otherwise be
/// encrypted, i.e. not under an `_`-prefixed key.
pub fn plaintext_scalar_paths(data: &[u8]) -> Result<Vec<String>, YamlError> {
    let s = String::from_utf8_lossy(data);
    let doc: Value = serde_norway::from_str(&s).map_err(invalid_yaml)?;
    let mut paths = Vec::new();
    collect_plaintext_scalars(&doc, String::new(), false, &mut paths);
    Ok(paths)
}

/// Mirrors [`Walker::walk_value`]'s rules for which values are encryptable.
fn collect_plaintext_scalars(value: &Value, path: String, is_comment: bool, out: &mut Vec<String>) {
    match value {
        Value::Number(_) | Value::Bool(_) if !is_comment => out.push(path),
        Value::Mapping(map) => {
            for (key, val) in map {
                let name = key.as_str().map_or_else(|| "?".to_string(), str::to_string);
                let child = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                let key_is_comment = name.starts_with('_');
                collect_plaintext_scalars(val, child, key_is_comment, out);
            }
        }
        Value::Sequence(seq) => {
            for (i, item) in seq.iter().enumerate() {
                collect_plaintext_scalars(item, format!("{path}[{i}]"), is_comment, out);
            }
        }
        Value::Tagged(tagged) => collect_plaintext_scalars(&tagged.value, path, is_comment, out),
        _ => {}
    }
}

/// Trim the first leading underscore from all keys in a YAML document.
/// The `_public_key` field is excluded from trimming.
pub fn trim_underscore_prefix_from_keys(data: &[u8]) -> Result<Vec<u8>, YamlError> {
    let s = String::from_utf8_lossy(data);
    let doc: Value = serde_norway::from_str(&s).map_err(invalid_yaml)?;

    let transformed = transform_yaml_keys(doc);

    let output = serde_norway::to_string(&transformed).map_err(invalid_yaml)?;
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
        Value::Tagged(mut tagged) => {
            tagged.value = transform_yaml_keys(tagged.value);
            Value::Tagged(tagged)
        }
        other => other,
    }
}

// ============================================================================
// FormatHandler trait implementation
// ============================================================================

/// Convert YamlError to the unified FormatError.
impl From<YamlError> for FormatError {
    fn from(err: YamlError) -> Self {
        match err {
            YamlError::PublicKeyMissing => FormatError::PublicKeyMissing,
            YamlError::PublicKeyInvalid => FormatError::PublicKeyInvalid,
            YamlError::InvalidYaml(msg) => FormatError::InvalidSyntax {
                format: "YAML",
                message: msg,
            },
            YamlError::ActionFailed(msg) => FormatError::ActionFailed(msg),
        }
    }
}

/// YAML format handler implementing the FormatHandler trait.
///
/// This handler uses `serde_norway` for parsing and serialization.
#[derive(Debug, Clone, Copy, Default)]
pub struct YamlHandler;

impl YamlHandler {
    /// Create a new YAML format handler.
    pub fn new() -> Self {
        Self
    }
}

impl FormatHandler for YamlHandler {
    fn format_name(&self) -> &'static str {
        "YAML"
    }

    fn extract_public_key(&self, data: &[u8]) -> Result<[u8; KEY_SIZE], FormatError> {
        extract_public_key(data).map_err(Into::into)
    }

    fn extract_public_key_string(&self, data: &[u8]) -> Result<String, FormatError> {
        extract_public_key_string(data).map_err(Into::into)
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
    fn test_walker_tagged_values() {
        let yaml = br#"scalar: !secret hunter2
mapping: !creds
  password: hunter3
sequence: !list
  - hunter4
_comment: !note leave me
"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Tagged values must be encrypted, and the tags preserved
        assert!(result_str.contains("!secret E:hunter2"));
        assert!(result_str.contains("!creds"));
        assert!(result_str.contains("password: E:hunter3"));
        assert!(result_str.contains("!list"));
        assert!(result_str.contains("E:hunter4"));
        // The underscore rule still applies to tagged values
        assert!(result_str.contains("_comment: !note leave me"));
    }

    #[test]
    fn test_trim_underscore_prefix_tagged_mapping() {
        let yaml = br#"outer: !tag
  _inner: "value"
"#;
        let result = trim_underscore_prefix_from_keys(yaml).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("inner:"));
        assert!(!result_str.contains("_inner"));
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

    #[test]
    fn test_parse_errors_do_not_quote_values() {
        let yaml = b"_public_key: abc\npin: !!int hunter2-supersecret\n";

        let errors = [
            extract_public_key_string(yaml).unwrap_err(),
            Walker::new(|d| Ok(d.to_vec())).walk(yaml).unwrap_err(),
            trim_underscore_prefix_from_keys(yaml).unwrap_err(),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.contains("hunter2"), "error leaked the secret: {msg}");
            assert!(msg.contains("line 2"), "error lost its location: {msg}");
        }
    }

    #[test]
    fn test_redact_quoted() {
        assert_eq!(
            redact_quoted(r#"invalid value: string "s3cr3t", expected an integer at line 2"#),
            r#"invalid value: string "...", expected an integer at line 2"#
        );
        assert_eq!(redact_quoted("integer `1234` here"), "integer `...` here");
        assert_eq!(
            redact_quoted(r#"unterminated "abc"#),
            r#"unterminated "..."#
        );
        assert_eq!(redact_quoted("no quotes"), "no quotes");
    }

    #[test]
    fn test_plaintext_scalar_paths() {
        let yaml = br#"_public_key: abc
password: hunter2
pin: 123456
enabled: true
legacy_yes: yes
ratio: 1.5
quoted_pin: "123456"
empty:
_comment_pin: 42
db:
  port: 5432
  _note: 1
pins:
  - 1111
  - "2222"
tagged: !x 7
"#;
        assert_eq!(
            plaintext_scalar_paths(yaml).unwrap(),
            vec!["pin", "enabled", "ratio", "db.port", "pins[0]", "tagged"]
        );
    }
}
