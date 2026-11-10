//! JSON processing for ejson files.
//!
//! This module provides functions to:
//! - Extract the public key from an ejson document
//! - Walk the JSON tree and selectively encrypt/decrypt string values
//!
//! The walker uses a scanner-based approach instead of parsing and re-serializing
//! to preserve key ordering and make diffs meaningful over time.

use std::fmt;

use crate::handler::{
    FormatError, FormatHandler, KEY_SIZE, PUBLIC_KEY_FIELD, WalkAction, decode_legacy_public_key,
};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

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

/// Extract the raw `_public_key` string value from an EJSON document.
///
/// The value is returned uninterpreted; scheme detection happens in [`crate::keys`].
///
/// A document that defines `_public_key` more than once at the top level is
/// rejected with [`JsonError::PublicKeyInvalid`].
pub fn extract_public_key_string(data: &[u8]) -> Result<String, JsonError> {
    let obj: Value = serde_json::from_slice(data).map_err(|_| JsonError::InvalidJson)?;

    if has_duplicate_public_key(data) {
        return Err(JsonError::PublicKeyInvalid);
    }

    let key_value = obj
        .get(PUBLIC_KEY_FIELD)
        .ok_or(JsonError::PublicKeyMissing)?;

    key_value
        .as_str()
        .map(str::to_string)
        .ok_or(JsonError::PublicKeyInvalid)
}

/// Returns true if the top-level object defines `_public_key` more than once.
///
/// `serde_json` keeps the last of a set of duplicate keys. For `_public_key`
/// that means a reviewer can see one key at the top of a file while a second
/// one further down is the key secrets actually get encrypted to.
pub fn has_duplicate_public_key(data: &[u8]) -> bool {
    struct CountPublicKeys;

    impl<'de> Visitor<'de> for CountPublicKeys {
        type Value = usize;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<usize, A::Error> {
            let mut count = 0;
            while let Some(key) = map.next_key::<String>()? {
                if key == PUBLIC_KEY_FIELD {
                    count += 1;
                }
                map.next_value::<IgnoredAny>()?;
            }
            Ok(count)
        }
    }

    struct PublicKeyCount(usize);

    impl<'de> Deserialize<'de> for PublicKeyCount {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_map(CountPublicKeys).map(PublicKeyCount)
        }
    }

    // Not an object (or not JSON): there is nothing to duplicate.
    serde_json::from_slice::<PublicKeyCount>(data).is_ok_and(|c| c.0 > 1)
}

/// Extract the _public_key value from an EJSON document as a legacy 32-byte key.
pub fn extract_public_key(data: &[u8]) -> Result<[u8; KEY_SIZE], JsonError> {
    let key_str = extract_public_key_string(data)?;
    decode_legacy_public_key(&key_str).ok_or(JsonError::PublicKeyInvalid)
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

// The action is a closure, which has no useful `Debug` output.
impl<F> fmt::Debug for Walker<F>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, String>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Walker").finish_non_exhaustive()
    }
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
        // First, collapse multiline string literals. The copy, made only if
        // there are any, holds plaintext when encrypting, so it is wiped.
        let collapsed = collapse_multiline(data).map(Zeroizing::new);
        let data = collapsed.as_ref().map_or(data, |v| v.as_slice());

        // Pre-allocate with ~2.5x input size (encrypted output is typically 2-3x larger)
        let mut output = Vec::with_capacity(data.len() * 5 / 2);
        let mut i = 0;

        self.walk_value(data, &mut i, &mut output, false)?;

        // Append any trailing whitespace/content
        while i < data.len() {
            output.push(data[i]);
            i += 1;
        }

        Ok(output)
    }

    fn walk_value(
        &self,
        data: &[u8],
        i: &mut usize,
        output: &mut Vec<u8>,
        is_comment: bool,
    ) -> Result<(), JsonError> {
        self.skip_whitespace(data, i, output);

        if *i >= data.len() {
            return Ok(());
        }

        match data[*i] {
            b'{' => self.walk_object(data, i, output)?,
            b'[' => self.walk_array(data, i, output, is_comment)?,
            b'"' => self.walk_string(data, i, output, is_comment)?,
            _ => self.walk_literal(data, i, output)?,
        }

        Ok(())
    }

    fn walk_object(
        &self,
        data: &[u8],
        i: &mut usize,
        output: &mut Vec<u8>,
    ) -> Result<(), JsonError> {
        // Output '{'
        output.push(data[*i]);
        *i += 1;

        self.skip_whitespace(data, i, output);

        // Empty object
        if *i < data.len() && data[*i] == b'}' {
            output.push(data[*i]);
            *i += 1;
            return Ok(());
        }

        loop {
            self.skip_whitespace(data, i, output);

            if *i >= data.len() {
                return Err(JsonError::InvalidJson);
            }

            // Parse key (must be a string)
            if data[*i] != b'"' {
                return Err(JsonError::InvalidJson);
            }

            let key = self.read_string_raw(data, i)?;
            let is_comment = key.starts_with(b"_");

            // Output the key as-is (re-escaped)
            output.push(b'"');
            escape_json_bytes_to(&key, output);
            output.push(b'"');

            self.skip_whitespace(data, i, output);

            // Expect ':'
            if *i >= data.len() || data[*i] != b':' {
                return Err(JsonError::InvalidJson);
            }
            output.push(data[*i]);
            *i += 1;

            // Parse value
            self.walk_value(data, i, output, is_comment)?;

            self.skip_whitespace(data, i, output);

            if *i >= data.len() {
                return Err(JsonError::InvalidJson);
            }

            if data[*i] == b'}' {
                output.push(data[*i]);
                *i += 1;
                return Ok(());
            } else if data[*i] == b',' {
                output.push(data[*i]);
                *i += 1;
            } else {
                return Err(JsonError::InvalidJson);
            }
        }
    }

    fn walk_array(
        &self,
        data: &[u8],
        i: &mut usize,
        output: &mut Vec<u8>,
        is_comment: bool,
    ) -> Result<(), JsonError> {
        // Output '['
        output.push(data[*i]);
        *i += 1;

        self.skip_whitespace(data, i, output);

        // Empty array
        if *i < data.len() && data[*i] == b']' {
            output.push(data[*i]);
            *i += 1;
            return Ok(());
        }

        loop {
            self.walk_value(data, i, output, is_comment)?;

            self.skip_whitespace(data, i, output);

            if *i >= data.len() {
                return Err(JsonError::InvalidJson);
            }

            if data[*i] == b']' {
                output.push(data[*i]);
                *i += 1;
                return Ok(());
            } else if data[*i] == b',' {
                output.push(data[*i]);
                *i += 1;
            } else {
                return Err(JsonError::InvalidJson);
            }
        }
    }

    fn walk_string(
        &self,
        data: &[u8],
        i: &mut usize,
        output: &mut Vec<u8>,
        is_comment: bool,
    ) -> Result<(), JsonError> {
        // Either side of the action may be plaintext (input when encrypting,
        // result when decrypting), so both are wiped once copied to `output`.
        let string_content = Zeroizing::new(self.read_string_raw(data, i)?);

        if is_comment {
            // Don't encrypt, output as-is
            output.push(b'"');
            escape_json_bytes_to(&string_content, output);
            output.push(b'"');
        } else {
            // Apply the action (encrypt/decrypt)
            let result =
                Zeroizing::new((self.action)(&string_content).map_err(JsonError::ActionFailed)?);

            // Output the result as a JSON string
            output.push(b'"');
            escape_json_bytes_to(&result, output);
            output.push(b'"');
        }

        Ok(())
    }

    fn walk_literal(
        &self,
        data: &[u8],
        i: &mut usize,
        output: &mut Vec<u8>,
    ) -> Result<(), JsonError> {
        // Read numbers, booleans, null
        while *i < data.len() {
            let c = data[*i];
            if c.is_ascii_alphanumeric() || c == b'-' || c == b'+' || c == b'.' {
                output.push(c);
                *i += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Read a JSON string and return its unescaped content as bytes.
    fn read_string_raw(&self, data: &[u8], i: &mut usize) -> Result<Vec<u8>, JsonError> {
        read_string_raw(data, i)
    }

    #[inline]
    fn skip_whitespace(&self, data: &[u8], i: &mut usize, output: &mut Vec<u8>) {
        while *i < data.len() && data[*i].is_ascii_whitespace() {
            output.push(data[*i]);
            *i += 1;
        }
    }
}

/// Escape bytes for JSON output, appending to output buffer.
#[inline]
fn escape_json_bytes_to(s: &[u8], output: &mut Vec<u8>) {
    for &c in s {
        match c {
            b'"' => output.extend_from_slice(b"\\\""),
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'\n' => output.extend_from_slice(b"\\n"),
            b'\r' => output.extend_from_slice(b"\\r"),
            b'\t' => output.extend_from_slice(b"\\t"),
            c if c < 0x20 => {
                // Control characters
                output.extend_from_slice(format!("\\u{c:04x}").as_bytes());
            }
            c => output.push(c),
        }
    }
}

/// Read a JSON string starting at the opening quote and return its unescaped
/// content as UTF-8 bytes.
///
/// `\uXXXX` escapes are decoded per RFC 8259, including UTF-16 surrogate
/// pairs for characters outside the Basic Multilingual Plane. Malformed
/// escapes are an error rather than being dropped: silently changing a value
/// here would corrupt the secret that gets encrypted.
fn read_string_raw(data: &[u8], i: &mut usize) -> Result<Vec<u8>, JsonError> {
    if *i >= data.len() || data[*i] != b'"' {
        return Err(JsonError::InvalidJson);
    }
    *i += 1; // Skip opening quote

    let mut result = Vec::with_capacity(64);
    let mut escaped = false;

    while *i < data.len() {
        let c = data[*i];
        *i += 1;

        if escaped {
            match c {
                b'"' => result.push(b'"'),
                b'\\' => result.push(b'\\'),
                b'/' => result.push(b'/'),
                b'b' => result.push(0x08),
                b'f' => result.push(0x0C),
                b'n' => result.push(b'\n'),
                b'r' => result.push(b'\r'),
                b't' => result.push(b'\t'),
                b'u' => {
                    let ch = read_unicode_escape(data, i)?;
                    let mut buf = [0u8; 4];
                    result.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => {
                    result.push(b'\\');
                    result.push(c);
                }
            }
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if c == b'"' {
            return Ok(result);
        } else {
            result.push(c);
        }
    }

    Err(JsonError::InvalidJson)
}

/// Decode the code point of a `\uXXXX` escape whose `\u` has already been
/// consumed, consuming a trailing `\uXXXX` low surrogate when the first one is
/// a high surrogate.
fn read_unicode_escape(data: &[u8], i: &mut usize) -> Result<char, JsonError> {
    let first = read_hex4(data, i)?;
    let code = match first {
        0xD800..=0xDBFF => {
            if data.get(*i..*i + 2) != Some(b"\\u") {
                return Err(JsonError::InvalidJson);
            }
            *i += 2;
            let second = read_hex4(data, i)?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(JsonError::InvalidJson);
            }
            0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        }
        0xDC00..=0xDFFF => return Err(JsonError::InvalidJson),
        _ => first,
    };
    char::from_u32(code).ok_or(JsonError::InvalidJson)
}

/// Read exactly four hex digits.
fn read_hex4(data: &[u8], i: &mut usize) -> Result<u32, JsonError> {
    let hex = data.get(*i..*i + 4).ok_or(JsonError::InvalidJson)?;
    if !hex.iter().all(u8::is_ascii_hexdigit) {
        return Err(JsonError::InvalidJson);
    }
    *i += 4;
    // All four bytes are ASCII hex digits, so this is valid UTF-8 and parses.
    let hex = std::str::from_utf8(hex).map_err(|_| JsonError::InvalidJson)?;
    u32::from_str_radix(hex, 16).map_err(|_| JsonError::InvalidJson)
}

/// Trim the first leading underscore from all keys in a JSON document.
/// The `_public_key` field is excluded from trimming.
///
/// This uses serde_json to parse and rebuild the JSON, which means formatting
/// may change slightly (though keys order is preserved).
pub fn trim_underscore_prefix_from_keys(data: &[u8]) -> Result<Vec<u8>, JsonError> {
    let value: Value = serde_json::from_slice(data).map_err(|_| JsonError::InvalidJson)?;
    let transformed = transform_json_keys(value);
    serde_json::to_vec_pretty(&transformed).map_err(|_| JsonError::InvalidJson)
}

fn transform_json_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let new_map: serde_json::Map<String, Value> = map
                .into_iter()
                .map(|(key, val)| {
                    let new_key = if key.starts_with('_') && key != "_public_key" {
                        key[1..].to_string()
                    } else {
                        key
                    };
                    (new_key, transform_json_keys(val))
                })
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(transform_json_keys).collect()),
        other => other,
    }
}

/// Collapse multiline string literals by replacing embedded newlines with \n.
///
/// JSON doesn't handle multiline literals, so we convert embedded newlines
/// in string literals to escape sequences.
pub fn collapse_multiline_string_literals(data: &[u8]) -> Result<Vec<u8>, JsonError> {
    Ok(collapse_multiline(data).unwrap_or_else(|| data.to_vec()))
}

/// Like [`collapse_multiline_string_literals`], but returns `None` when no
/// string contains a raw newline, so callers needn't copy a document that is
/// already valid (the common case, and always true after `preprocess`).
fn collapse_multiline(data: &[u8]) -> Option<Vec<u8>> {
    // Allocated on the first newline found inside a string.
    let mut result: Option<Vec<u8>> = None;
    let mut in_string = false;
    let mut escaped = false;

    for (i, &c) in data.iter().enumerate() {
        if in_string && (c == b'\n' || c == b'\r') {
            let out = result.get_or_insert_with(|| {
                let mut out = Vec::with_capacity(data.len() + 16);
                out.extend_from_slice(&data[..i]);
                out
            });
            out.extend_from_slice(if c == b'\n' { b"\\n" } else { b"\\r" });
            continue;
        }

        if let Some(out) = result.as_mut() {
            out.push(c);
        }

        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
            escaped = false;
        }
    }

    result
}

// ============================================================================
// FormatHandler trait implementation
// ============================================================================

/// Convert JsonError to the unified FormatError.
impl From<JsonError> for FormatError {
    fn from(err: JsonError) -> Self {
        match err {
            JsonError::PublicKeyMissing => FormatError::PublicKeyMissing,
            JsonError::PublicKeyInvalid => FormatError::PublicKeyInvalid,
            JsonError::InvalidJson => FormatError::InvalidSyntax {
                format: "JSON",
                message: "invalid JSON syntax".to_string(),
            },
            JsonError::ActionFailed(msg) => FormatError::ActionFailed(msg),
        }
    }
}

/// JSON format handler implementing the FormatHandler trait.
///
/// This handler uses a scanner-based approach to preserve formatting
/// and key ordering in the output.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonHandler;

impl JsonHandler {
    /// Create a new JSON format handler.
    pub fn new() -> Self {
        Self
    }
}

impl FormatHandler for JsonHandler {
    fn format_name(&self) -> &'static str {
        "JSON"
    }

    fn extract_public_key(&self, data: &[u8]) -> Result<[u8; KEY_SIZE], FormatError> {
        extract_public_key(data).map_err(Into::into)
    }

    fn extract_public_key_string(&self, data: &[u8]) -> Result<String, FormatError> {
        if has_duplicate_public_key(data) {
            return Err(FormatError::InvalidSyntax {
                format: "JSON",
                message: format!("`{PUBLIC_KEY_FIELD}` is defined more than once"),
            });
        }
        extract_public_key_string(data).map_err(Into::into)
    }

    fn walk(&self, data: &[u8], action: WalkAction<'_>) -> Result<Vec<u8>, FormatError> {
        Walker::new(action).walk(data).map_err(Into::into)
    }

    fn trim_underscore_prefix_from_keys(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        trim_underscore_prefix_from_keys(data).map_err(Into::into)
    }

    fn preprocess(&self, data: &[u8]) -> Result<Vec<u8>, FormatError> {
        collapse_multiline_string_literals(data).map_err(Into::into)
    }
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
    fn test_duplicate_public_key_is_rejected() {
        let json = br#"{"_public_key": "aaaa", "a": "s", "_public_key": "bbbb"}"#;
        assert!(has_duplicate_public_key(json));
        assert!(matches!(
            extract_public_key_string(json),
            Err(JsonError::PublicKeyInvalid)
        ));
        assert!(matches!(
            JsonHandler.extract_public_key_string(json),
            Err(FormatError::InvalidSyntax { .. })
        ));

        // An escaped spelling of the same key is still the same key
        let escaped = br#"{"_public_key": "aaaa", "_public\u005fkey": "bbbb"}"#;
        assert!(has_duplicate_public_key(escaped));
    }

    #[test]
    fn test_single_or_nested_public_key_is_not_a_duplicate() {
        assert!(!has_duplicate_public_key(br#"{"_public_key": "aaaa"}"#));
        assert!(!has_duplicate_public_key(
            br#"{"_public_key": "aaaa", "nested": {"_public_key": "bbbb"}}"#
        ));
        assert!(!has_duplicate_public_key(
            br#"["_public_key", "_public_key"]"#
        ));
        assert!(!has_duplicate_public_key(b"not json"));
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
    fn test_walker_decodes_unicode_escapes() {
        // BMP escape, surrogate pair (U+1F600), and raw UTF-8 must all reach
        // the action as the same UTF-8 bytes serde_json would produce.
        let json = r#"{"a": "x\u00e9y", "b": "pre\ud83d\ude00post", "c": "pre😀post"}"#.as_bytes();
        let walker = Walker::new(|data| Ok(data.to_vec()));

        let result = walker.walk(json).unwrap();
        let parsed: Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(parsed["a"], "xéy");
        assert_eq!(parsed["b"], "pre😀post");
        assert_eq!(parsed["c"], "pre😀post");
    }

    #[test]
    fn test_walker_rejects_malformed_unicode_escapes() {
        let walker = Walker::new(|data| Ok(data.to_vec()));
        for bad in [
            br#"{"a": "\ud83d"}"#.as_slice(),       // lone high surrogate
            br#"{"a": "\ud83dx"}"#.as_slice(),      // high surrogate, no escape after
            br#"{"a": "\ud83d\u0041"}"#.as_slice(), // high surrogate + non-low
            br#"{"a": "\ude00"}"#.as_slice(),       // lone low surrogate
            br#"{"a": "\u00zz"}"#.as_slice(),       // invalid hex
            br#"{"a": "\u00"}"#.as_slice(),         // truncated
        ] {
            assert!(
                matches!(walker.walk(bad), Err(JsonError::InvalidJson)),
                "expected InvalidJson for {}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// The straightforward always-copy implementation `collapse_multiline`
    /// replaced; kept as the reference for its behaviour.
    fn collapse_reference(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let (mut in_string, mut escaped) = (false, false);
        for &c in data {
            if in_string && c == b'\n' {
                result.extend_from_slice(b"\\n");
                continue;
            }
            if in_string && c == b'\r' {
                result.extend_from_slice(b"\\r");
                continue;
            }
            result.push(c);
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == b'\\' {
                    escaped = true;
                } else if c == b'"' {
                    in_string = false;
                }
            } else if c == b'"' {
                in_string = true;
                escaped = false;
            }
        }
        result
    }

    #[test]
    fn test_collapse_multiline_only_copies_when_needed() {
        // Newlines between tokens, escaped quotes and escaped newlines need no change.
        for unchanged in [
            "{\n  \"a\": \"b\",\r\n  \"c\": \"d\"\n}\n",
            r#"{"a": "quote \" and \\", "b": "x\ny"}"#,
            "",
            "\"unterminated",
        ] {
            assert_eq!(
                collapse_multiline(unchanged.as_bytes()),
                None,
                "{unchanged:?}"
            );
        }

        for changed in [
            "{\"a\": \"line1\nline2\"}",
            "{\"a\": \"crlf\r\nend\", \"b\": \"x\"}\n",
            "{\n \"a\": \"esc \\\" still in\nstring\",\n \"b\": \"\n\"}",
            "\"unterminated\n",
        ] {
            assert_eq!(
                collapse_multiline(changed.as_bytes()),
                Some(collapse_reference(changed.as_bytes())),
                "{changed:?}"
            );
            assert_eq!(
                collapse_multiline_string_literals(changed.as_bytes()).unwrap(),
                collapse_reference(changed.as_bytes())
            );
        }
    }

    #[test]
    fn test_collapse_multiline() {
        let json = b"{\"key\": \"line1\nline2\"}";
        let result = collapse_multiline_string_literals(json).unwrap();
        assert_eq!(result, b"{\"key\": \"line1\\nline2\"}");
    }

    #[test]
    fn test_trim_underscore_prefix_from_keys() {
        let json = br#"{"_public_key": "abc123", "_secret": "value", "normal": "data"}"#;
        let result = trim_underscore_prefix_from_keys(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // _public_key should NOT be trimmed
        assert!(result_str.contains(r#""_public_key""#));
        // Other underscore keys should have it removed
        assert!(result_str.contains(r#""secret""#));
        assert!(result_str.contains(r#""normal""#));
        // Should not have underscore prefix on _secret
        assert!(!result_str.contains(r#""_secret""#));
    }

    #[test]
    fn test_trim_underscore_prefix_nested() {
        let json = br#"{"_outer": {"_inner": "value", "normal": "data"}}"#;
        let result = trim_underscore_prefix_from_keys(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Both nested keys should have underscore removed
        assert!(result_str.contains(r#""outer""#));
        assert!(result_str.contains(r#""inner""#));
        assert!(!result_str.contains(r#""_outer""#));
        assert!(!result_str.contains(r#""_inner""#));
    }

    #[test]
    fn test_trim_underscore_prefix_no_underscore() {
        let json = br#"{"normal": "value", "key": "data"}"#;
        let result = trim_underscore_prefix_from_keys(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Keys without underscore should remain unchanged
        assert!(result_str.contains(r#""normal""#));
        assert!(result_str.contains(r#""key""#));
    }
}
