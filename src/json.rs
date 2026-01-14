//! JSON processing for ejson files.
//!
//! This module provides functions to:
//! - Extract the public key from an ejson document
//! - Walk the JSON tree and selectively encrypt/decrypt string values
//!
//! The walker uses a scanner-based approach instead of parsing and re-serializing
//! to preserve key ordering and make diffs meaningful over time.

use serde_json::Value;
use thiserror::Error;

/// The key name at which the public key should be stored in an EJSON document.
pub const PUBLIC_KEY_FIELD: &str = "_public_key";

/// Errors that can occur during JSON processing.
#[derive(Error, Debug)]
pub enum JsonError {
    #[error("public key not present in EJSON file")]
    PublicKeyMissing,

    #[error("public key has invalid format")]
    PublicKeyInvalid,

    #[error("invalid json")]
    InvalidJson,

    #[error("action failed: {0}")]
    ActionFailed(String),
}

/// Extract the _public_key value from an EJSON document.
pub fn extract_public_key(data: &[u8]) -> Result<[u8; 32], JsonError> {
    let obj: Value = serde_json::from_slice(data).map_err(|_| JsonError::InvalidJson)?;

    let key_value = obj
        .get(PUBLIC_KEY_FIELD)
        .ok_or(JsonError::PublicKeyMissing)?;

    let key_str = key_value.as_str().ok_or(JsonError::PublicKeyInvalid)?;

    if key_str.len() != 64 {
        return Err(JsonError::PublicKeyInvalid);
    }

    let key_bytes = hex::decode(key_str).map_err(|_| JsonError::PublicKeyInvalid)?;

    if key_bytes.len() != 32 {
        return Err(JsonError::PublicKeyInvalid);
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Walker walks a JSON structure, applying an action to encryptable string values.
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

    /// Walk the JSON data and apply the action to encryptable values.
    pub fn walk(&self, data: &[u8]) -> Result<Vec<u8>, JsonError> {
        // First, collapse multiline string literals
        let data = collapse_multiline_string_literals(data)?;

        // Use a character-by-character scanner to preserve formatting
        let mut output = Vec::with_capacity(data.len());
        let chars: Vec<char> = String::from_utf8_lossy(&data).chars().collect();
        let mut i = 0;

        self.walk_value(&chars, &mut i, &mut output, false)?;

        // Append any trailing whitespace/content
        while i < chars.len() {
            output.push(chars[i] as u8);
            i += 1;
        }

        Ok(output)
    }

    fn walk_value(
        &self,
        chars: &[char],
        i: &mut usize,
        output: &mut Vec<u8>,
        is_comment: bool,
    ) -> Result<(), JsonError> {
        self.skip_whitespace(chars, i, output);

        if *i >= chars.len() {
            return Ok(());
        }

        match chars[*i] {
            '{' => self.walk_object(chars, i, output)?,
            '[' => self.walk_array(chars, i, output, is_comment)?,
            '"' => self.walk_string(chars, i, output, is_comment)?,
            _ => self.walk_literal(chars, i, output)?,
        }

        Ok(())
    }

    fn walk_object(
        &self,
        chars: &[char],
        i: &mut usize,
        output: &mut Vec<u8>,
    ) -> Result<(), JsonError> {
        // Output '{'
        output.push(chars[*i] as u8);
        *i += 1;

        self.skip_whitespace(chars, i, output);

        // Empty object
        if *i < chars.len() && chars[*i] == '}' {
            output.push(chars[*i] as u8);
            *i += 1;
            return Ok(());
        }

        loop {
            self.skip_whitespace(chars, i, output);

            if *i >= chars.len() {
                return Err(JsonError::InvalidJson);
            }

            // Parse key (must be a string)
            if chars[*i] != '"' {
                return Err(JsonError::InvalidJson);
            }

            let key = self.read_string_raw(chars, i)?;
            let is_comment = key.starts_with('_');

            // Output the key as-is
            output.push('"' as u8);
            for c in key.chars() {
                if c == '"' {
                    output.extend_from_slice(b"\\\"");
                } else if c == '\\' {
                    output.extend_from_slice(b"\\\\");
                } else if c == '\n' {
                    output.extend_from_slice(b"\\n");
                } else if c == '\r' {
                    output.extend_from_slice(b"\\r");
                } else if c == '\t' {
                    output.extend_from_slice(b"\\t");
                } else {
                    let mut buf = [0u8; 4];
                    output.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
            output.push('"' as u8);

            self.skip_whitespace(chars, i, output);

            // Expect ':'
            if *i >= chars.len() || chars[*i] != ':' {
                return Err(JsonError::InvalidJson);
            }
            output.push(chars[*i] as u8);
            *i += 1;

            // Parse value
            self.walk_value(chars, i, output, is_comment)?;

            self.skip_whitespace(chars, i, output);

            if *i >= chars.len() {
                return Err(JsonError::InvalidJson);
            }

            if chars[*i] == '}' {
                output.push(chars[*i] as u8);
                *i += 1;
                return Ok(());
            } else if chars[*i] == ',' {
                output.push(chars[*i] as u8);
                *i += 1;
            } else {
                return Err(JsonError::InvalidJson);
            }
        }
    }

    fn walk_array(
        &self,
        chars: &[char],
        i: &mut usize,
        output: &mut Vec<u8>,
        is_comment: bool,
    ) -> Result<(), JsonError> {
        // Output '['
        output.push(chars[*i] as u8);
        *i += 1;

        self.skip_whitespace(chars, i, output);

        // Empty array
        if *i < chars.len() && chars[*i] == ']' {
            output.push(chars[*i] as u8);
            *i += 1;
            return Ok(());
        }

        loop {
            self.walk_value(chars, i, output, is_comment)?;

            self.skip_whitespace(chars, i, output);

            if *i >= chars.len() {
                return Err(JsonError::InvalidJson);
            }

            if chars[*i] == ']' {
                output.push(chars[*i] as u8);
                *i += 1;
                return Ok(());
            } else if chars[*i] == ',' {
                output.push(chars[*i] as u8);
                *i += 1;
            } else {
                return Err(JsonError::InvalidJson);
            }
        }
    }

    fn walk_string(
        &self,
        chars: &[char],
        i: &mut usize,
        output: &mut Vec<u8>,
        is_comment: bool,
    ) -> Result<(), JsonError> {
        let string_content = self.read_string_raw(chars, i)?;

        if is_comment {
            // Don't encrypt, output as-is
            output.push('"' as u8);
            // Re-escape the string properly
            let escaped = escape_json_string(&string_content);
            output.extend_from_slice(escaped.as_bytes());
            output.push('"' as u8);
        } else {
            // Apply the action (encrypt/decrypt)
            let result =
                (self.action)(string_content.as_bytes()).map_err(|e| JsonError::ActionFailed(e))?;

            // Output the result as a JSON string
            let result_str = String::from_utf8_lossy(&result);
            output.push('"' as u8);
            let escaped = escape_json_string(&result_str);
            output.extend_from_slice(escaped.as_bytes());
            output.push('"' as u8);
        }

        Ok(())
    }

    fn walk_literal(
        &self,
        chars: &[char],
        i: &mut usize,
        output: &mut Vec<u8>,
    ) -> Result<(), JsonError> {
        // Read numbers, booleans, null
        while *i < chars.len() {
            let c = chars[*i];
            if c.is_alphanumeric() || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
                output.push(c as u8);
                *i += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Read a JSON string and return its unescaped content.
    fn read_string_raw(&self, chars: &[char], i: &mut usize) -> Result<String, JsonError> {
        if *i >= chars.len() || chars[*i] != '"' {
            return Err(JsonError::InvalidJson);
        }
        *i += 1; // Skip opening quote

        let mut result = String::new();
        let mut escaped = false;

        while *i < chars.len() {
            let c = chars[*i];
            *i += 1;

            if escaped {
                match c {
                    '"' => result.push('"'),
                    '\\' => result.push('\\'),
                    '/' => result.push('/'),
                    'b' => result.push('\x08'),
                    'f' => result.push('\x0C'),
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    'u' => {
                        // Unicode escape
                        if *i + 4 > chars.len() {
                            return Err(JsonError::InvalidJson);
                        }
                        let hex: String = chars[*i..*i + 4].iter().collect();
                        *i += 4;
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                result.push(ch);
                            }
                        }
                    }
                    _ => {
                        result.push('\\');
                        result.push(c);
                    }
                }
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                return Ok(result);
            } else {
                result.push(c);
            }
        }

        Err(JsonError::InvalidJson)
    }

    fn skip_whitespace(&self, chars: &[char], i: &mut usize, output: &mut Vec<u8>) {
        while *i < chars.len() && chars[*i].is_whitespace() {
            output.push(chars[*i] as u8);
            *i += 1;
        }
    }
}

/// Escape a string for JSON output.
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Collapse multiline string literals by replacing embedded newlines with \n.
///
/// JSON doesn't handle multiline literals, so we convert embedded newlines
/// in string literals to escape sequences.
pub fn collapse_multiline_string_literals(data: &[u8]) -> Result<Vec<u8>, JsonError> {
    let s = String::from_utf8_lossy(data);
    let mut result = Vec::with_capacity(data.len());
    let mut in_string = false;
    let mut escaped = false;
    let chars: Vec<char> = s.chars().collect();

    for c in chars {
        if in_string {
            if c == '\n' {
                result.extend_from_slice(b"\\n");
                continue;
            } else if c == '\r' {
                result.extend_from_slice(b"\\r");
                continue;
            }
        }

        // Append the character
        let mut buf = [0u8; 4];
        result.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());

        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            escaped = false;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_public_key() {
        let json = br#"{"_public_key": "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f", "secret": "value"}"#;
        let key = extract_public_key(json).unwrap();
        assert_eq!(
            hex::encode(key),
            "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f"
        );
    }

    #[test]
    fn test_extract_public_key_missing() {
        let json = br#"{"secret": "value"}"#;
        assert!(matches!(
            extract_public_key(json),
            Err(JsonError::PublicKeyMissing)
        ));
    }

    #[test]
    fn test_walker_with_comment_key() {
        let json = br#"{"_comment": "not encrypted", "secret": "encrypted"}"#;
        let walker = Walker::new(|data| {
            Ok(format!("ENCRYPTED:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""_comment": "not encrypted""#));
        assert!(result_str.contains(r#""secret": "ENCRYPTED:encrypted""#));
    }

    #[test]
    fn test_walker_nested() {
        let json = br#"{"outer": {"inner": "value"}}"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""inner": "E:value""#));
    }

    #[test]
    fn test_walker_underscore_does_not_propagate() {
        // Underscore prefix should NOT propagate to nested values
        let json = br#"{"_outer": {"inner": "should_encrypt"}}"#;
        let walker =
            Walker::new(|data| Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes()));

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // The inner value SHOULD be encrypted (underscore doesn't propagate)
        assert!(result_str.contains(r#""inner": "E:should_encrypt""#));
    }

    #[test]
    fn test_collapse_multiline() {
        let json = b"{\"key\": \"line1\nline2\"}";
        let result = collapse_multiline_string_literals(json).unwrap();
        assert_eq!(result, b"{\"key\": \"line1\\nline2\"}");
    }
}
