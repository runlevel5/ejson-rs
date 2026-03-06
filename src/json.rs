//! JSON processing for ejson files.
//!
//! This module provides functions to:
//! - Extract the public key from an ejson document
//! - Walk the JSON tree and selectively encrypt/decrypt string values
//!
//! The walker uses a scanner-based approach instead of parsing and re-serializing
//! to preserve key ordering and make diffs meaningful over time.

use crate::handler::{FormatError, FormatHandler, KEY_SIZE, PUBLIC_KEY_FIELD, WalkAction};
use serde_json::Value;
use thiserror::Error;

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
pub fn extract_public_key(data: &[u8]) -> Result<[u8; KEY_SIZE], JsonError> {
    let obj: Value = serde_json::from_slice(data).map_err(|_| JsonError::InvalidJson)?;

    let key_value = obj
        .get(PUBLIC_KEY_FIELD)
        .ok_or(JsonError::PublicKeyMissing)?;

    let key_str = key_value.as_str().ok_or(JsonError::PublicKeyInvalid)?;

    if key_str.len() != KEY_SIZE * 2 {
        return Err(JsonError::PublicKeyInvalid);
    }

    let key_bytes = hex::decode(key_str).map_err(|_| JsonError::PublicKeyInvalid)?;

    key_bytes
        .try_into()
        .map_err(|_| JsonError::PublicKeyInvalid)
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

        // Pre-allocate with ~2.5x input size (encrypted output is typically 2-3x larger)
        let mut output = Vec::with_capacity(data.len() * 5 / 2);
        let mut i = 0;

        self.walk_value(&data, &mut i, &mut output, false)?;

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
        let string_content = self.read_string_raw(data, i)?;

        if is_comment {
            // Don't encrypt, output as-is
            output.push(b'"');
            escape_json_bytes_to(&string_content, output);
            output.push(b'"');
        } else {
            // Apply the action (encrypt/decrypt)
            let result = (self.action)(&string_content).map_err(JsonError::ActionFailed)?;

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
                        // Unicode escape
                        if *i + 4 > data.len() {
                            return Err(JsonError::InvalidJson);
                        }
                        let hex = std::str::from_utf8(&data[*i..*i + 4])
                            .map_err(|_| JsonError::InvalidJson)?;
                        *i += 4;
                        if let Ok(code) = u32::from_str_radix(hex, 16)
                            && let Some(ch) = char::from_u32(code)
                        {
                            let mut buf = [0u8; 4];
                            let encoded = ch.encode_utf8(&mut buf);
                            result.extend_from_slice(encoded.as_bytes());
                        }
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
                output.extend_from_slice(format!("\\u{:04x}", c).as_bytes());
            }
            c => output.push(c),
        }
    }
}

// Parallel encryption support
#[cfg(feature = "parallel")]
pub mod parallel {
    use super::*;
    use rayon::prelude::*;

    /// Collected string value for parallel processing
    struct StringValue {
        content: Vec<u8>,
        is_comment: bool,
    }

    /// Parallel walker that collects strings, encrypts in parallel, then reconstructs.
    pub struct ParallelWalker<F>
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, String> + Sync,
    {
        action: F,
    }

    impl<F> ParallelWalker<F>
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, String> + Sync,
    {
        pub fn new(action: F) -> Self {
            Self { action }
        }

        /// Walk the JSON data and apply the action to encryptable values in parallel.
        pub fn walk(&self, data: &[u8]) -> Result<Vec<u8>, JsonError> {
            // First, collapse multiline string literals
            let data = collapse_multiline_string_literals(data)?;

            // Phase 1: Collect all strings
            let mut strings = Vec::new();
            let mut i = 0;
            self.collect_strings(&data, &mut i, &mut strings, false)?;

            // Phase 2: Encrypt in parallel
            let encrypted: Result<Vec<_>, _> = strings
                .par_iter()
                .map(|sv| {
                    if sv.is_comment {
                        Ok(sv.content.clone())
                    } else {
                        (self.action)(&sv.content).map_err(JsonError::ActionFailed)
                    }
                })
                .collect();
            let encrypted = encrypted?;

            // Phase 3: Reconstruct output
            let mut output = Vec::with_capacity(data.len() * 5 / 2);
            let mut string_idx = 0;
            let mut i = 0;
            self.reconstruct(
                &data,
                &mut i,
                &mut output,
                &encrypted,
                &mut string_idx,
                false,
            )?;

            // Append any trailing content
            while i < data.len() {
                output.push(data[i]);
                i += 1;
            }

            Ok(output)
        }

        fn collect_strings(
            &self,
            data: &[u8],
            i: &mut usize,
            strings: &mut Vec<StringValue>,
            is_comment: bool,
        ) -> Result<(), JsonError> {
            skip_whitespace_no_output(data, i);

            if *i >= data.len() {
                return Ok(());
            }

            match data[*i] {
                b'{' => self.collect_object(data, i, strings)?,
                b'[' => self.collect_array(data, i, strings, is_comment)?,
                b'"' => {
                    let content = read_string_raw_static(data, i)?;
                    strings.push(StringValue {
                        content,
                        is_comment,
                    });
                }
                _ => {
                    // Skip literals
                    while *i < data.len() {
                        let c = data[*i];
                        if c.is_ascii_alphanumeric() || c == b'-' || c == b'+' || c == b'.' {
                            *i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }

            Ok(())
        }

        fn collect_object(
            &self,
            data: &[u8],
            i: &mut usize,
            strings: &mut Vec<StringValue>,
        ) -> Result<(), JsonError> {
            *i += 1; // Skip '{'
            skip_whitespace_no_output(data, i);

            if *i < data.len() && data[*i] == b'}' {
                *i += 1;
                return Ok(());
            }

            loop {
                skip_whitespace_no_output(data, i);

                if *i >= data.len() || data[*i] != b'"' {
                    return Err(JsonError::InvalidJson);
                }

                let key = read_string_raw_static(data, i)?;
                let is_comment = key.starts_with(b"_");

                skip_whitespace_no_output(data, i);

                if *i >= data.len() || data[*i] != b':' {
                    return Err(JsonError::InvalidJson);
                }
                *i += 1;

                self.collect_strings(data, i, strings, is_comment)?;

                skip_whitespace_no_output(data, i);

                if *i >= data.len() {
                    return Err(JsonError::InvalidJson);
                }

                if data[*i] == b'}' {
                    *i += 1;
                    return Ok(());
                } else if data[*i] == b',' {
                    *i += 1;
                } else {
                    return Err(JsonError::InvalidJson);
                }
            }
        }

        fn collect_array(
            &self,
            data: &[u8],
            i: &mut usize,
            strings: &mut Vec<StringValue>,
            is_comment: bool,
        ) -> Result<(), JsonError> {
            *i += 1; // Skip '['
            skip_whitespace_no_output(data, i);

            if *i < data.len() && data[*i] == b']' {
                *i += 1;
                return Ok(());
            }

            loop {
                self.collect_strings(data, i, strings, is_comment)?;

                skip_whitespace_no_output(data, i);

                if *i >= data.len() {
                    return Err(JsonError::InvalidJson);
                }

                if data[*i] == b']' {
                    *i += 1;
                    return Ok(());
                } else if data[*i] == b',' {
                    *i += 1;
                } else {
                    return Err(JsonError::InvalidJson);
                }
            }
        }

        fn reconstruct(
            &self,
            data: &[u8],
            i: &mut usize,
            output: &mut Vec<u8>,
            encrypted: &[Vec<u8>],
            string_idx: &mut usize,
            is_comment: bool,
        ) -> Result<(), JsonError> {
            skip_whitespace_with_output(data, i, output);

            if *i >= data.len() {
                return Ok(());
            }

            match data[*i] {
                b'{' => self.reconstruct_object(data, i, output, encrypted, string_idx)?,
                b'[' => {
                    self.reconstruct_array(data, i, output, encrypted, string_idx, is_comment)?
                }
                b'"' => {
                    // Skip original string
                    let _ = read_string_raw_static(data, i)?;
                    // Output encrypted value
                    output.push(b'"');
                    escape_json_bytes_to(&encrypted[*string_idx], output);
                    output.push(b'"');
                    *string_idx += 1;
                }
                _ => {
                    // Copy literals
                    while *i < data.len() {
                        let c = data[*i];
                        if c.is_ascii_alphanumeric() || c == b'-' || c == b'+' || c == b'.' {
                            output.push(c);
                            *i += 1;
                        } else {
                            break;
                        }
                    }
                }
            }

            Ok(())
        }

        fn reconstruct_object(
            &self,
            data: &[u8],
            i: &mut usize,
            output: &mut Vec<u8>,
            encrypted: &[Vec<u8>],
            string_idx: &mut usize,
        ) -> Result<(), JsonError> {
            output.push(data[*i]);
            *i += 1;

            skip_whitespace_with_output(data, i, output);

            if *i < data.len() && data[*i] == b'}' {
                output.push(data[*i]);
                *i += 1;
                return Ok(());
            }

            loop {
                skip_whitespace_with_output(data, i, output);

                if *i >= data.len() || data[*i] != b'"' {
                    return Err(JsonError::InvalidJson);
                }

                let key = read_string_raw_static(data, i)?;
                let is_comment = key.starts_with(b"_");

                output.push(b'"');
                escape_json_bytes_to(&key, output);
                output.push(b'"');

                skip_whitespace_with_output(data, i, output);

                if *i >= data.len() || data[*i] != b':' {
                    return Err(JsonError::InvalidJson);
                }
                output.push(data[*i]);
                *i += 1;

                self.reconstruct(data, i, output, encrypted, string_idx, is_comment)?;

                skip_whitespace_with_output(data, i, output);

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

        fn reconstruct_array(
            &self,
            data: &[u8],
            i: &mut usize,
            output: &mut Vec<u8>,
            encrypted: &[Vec<u8>],
            string_idx: &mut usize,
            is_comment: bool,
        ) -> Result<(), JsonError> {
            output.push(data[*i]);
            *i += 1;

            skip_whitespace_with_output(data, i, output);

            if *i < data.len() && data[*i] == b']' {
                output.push(data[*i]);
                *i += 1;
                return Ok(());
            }

            loop {
                self.reconstruct(data, i, output, encrypted, string_idx, is_comment)?;

                skip_whitespace_with_output(data, i, output);

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
    }

    #[inline]
    fn skip_whitespace_no_output(data: &[u8], i: &mut usize) {
        while *i < data.len() && data[*i].is_ascii_whitespace() {
            *i += 1;
        }
    }

    #[inline]
    fn skip_whitespace_with_output(data: &[u8], i: &mut usize, output: &mut Vec<u8>) {
        while *i < data.len() && data[*i].is_ascii_whitespace() {
            output.push(data[*i]);
            *i += 1;
        }
    }

    fn read_string_raw_static(data: &[u8], i: &mut usize) -> Result<Vec<u8>, JsonError> {
        if *i >= data.len() || data[*i] != b'"' {
            return Err(JsonError::InvalidJson);
        }
        *i += 1;

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
                        if *i + 4 > data.len() {
                            return Err(JsonError::InvalidJson);
                        }
                        let hex = std::str::from_utf8(&data[*i..*i + 4])
                            .map_err(|_| JsonError::InvalidJson)?;
                        *i += 4;
                        if let Ok(code) = u32::from_str_radix(hex, 16)
                            && let Some(ch) = char::from_u32(code)
                        {
                            let mut buf = [0u8; 4];
                            let encoded = ch.encode_utf8(&mut buf);
                            result.extend_from_slice(encoded.as_bytes());
                        }
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
    let mut result = Vec::with_capacity(data.len());
    let mut in_string = false;
    let mut escaped = false;

    for &c in data {
        if in_string {
            if c == b'\n' {
                result.extend_from_slice(b"\\n");
                continue;
            } else if c == b'\r' {
                result.extend_from_slice(b"\\r");
                continue;
            }
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

    Ok(result)
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

#[cfg(all(test, feature = "parallel"))]
mod parallel_tests {
    use super::parallel::ParallelWalker;

    #[test]
    fn test_parallel_walker_basic() {
        let json = br#"{"key": "value", "another": "data"}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""key": "E:value""#));
        assert!(result_str.contains(r#""another": "E:data""#));
    }

    #[test]
    fn test_parallel_walker_with_comment_key() {
        let json = br#"{"_comment": "not encrypted", "secret": "encrypted"}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("ENCRYPTED:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Comment keys should not be encrypted
        assert!(result_str.contains(r#""_comment": "not encrypted""#));
        assert!(result_str.contains(r#""secret": "ENCRYPTED:encrypted""#));
    }

    #[test]
    fn test_parallel_walker_nested() {
        let json = br#"{"outer": {"inner": "value"}}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""inner": "E:value""#));
    }

    #[test]
    fn test_parallel_walker_underscore_does_not_propagate() {
        // Underscore prefix should NOT propagate to nested values
        let json = br#"{"_outer": {"inner": "should_encrypt"}}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // The inner value SHOULD be encrypted (underscore doesn't propagate)
        assert!(result_str.contains(r#""inner": "E:should_encrypt""#));
    }

    #[test]
    fn test_parallel_walker_array() {
        let json = br#"{"items": ["a", "b", "c"]}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""E:a""#));
        assert!(result_str.contains(r#""E:b""#));
        assert!(result_str.contains(r#""E:c""#));
    }

    #[test]
    fn test_parallel_walker_array_with_comment_key() {
        let json = br#"{"_items": ["a", "b"], "secrets": ["x", "y"]}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Items in _items should NOT be encrypted
        assert!(result_str.contains(r#""_items": ["a", "b"]"#));
        // Items in secrets SHOULD be encrypted
        assert!(result_str.contains(r#""E:x""#));
        assert!(result_str.contains(r#""E:y""#));
    }

    #[test]
    fn test_parallel_walker_mixed_types() {
        let json = br#"{"str": "value", "num": 42, "bool": true, "null": null}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains(r#""str": "E:value""#));
        assert!(result_str.contains(r#""num": 42"#));
        assert!(result_str.contains(r#""bool": true"#));
        assert!(result_str.contains(r#""null": null"#));
    }

    #[test]
    fn test_parallel_walker_empty_object() {
        let json = br#"{}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        assert_eq!(result, b"{}");
    }

    #[test]
    fn test_parallel_walker_empty_array() {
        let json = br#"{"arr": []}"#;
        let walker = ParallelWalker::new(|data| {
            Ok(format!("E:{}", String::from_utf8_lossy(data)).into_bytes())
        });

        let result = walker.walk(json).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains(r#""arr": []"#));
    }

    #[test]
    fn test_parallel_walker_matches_sequential() {
        // Ensure parallel and sequential walkers produce the same output
        use super::Walker;

        let json = br#"{
            "_public_key": "abc123",
            "secret": "mysecret",
            "_comment": "should not encrypt",
            "nested": {
                "inner": "value",
                "_skip": "not this"
            },
            "array": ["one", "two"]
        }"#;

        let action =
            |data: &[u8]| Ok(format!("ENC:{}", String::from_utf8_lossy(data)).into_bytes());

        let sequential = Walker::new(&action);
        let parallel = ParallelWalker::new(&action);

        let seq_result = sequential.walk(json).unwrap();
        let par_result = parallel.walk(json).unwrap();

        assert_eq!(seq_result, par_result);
    }
}
