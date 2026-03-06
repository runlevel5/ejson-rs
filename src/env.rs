//! Environment variable export utilities for EJSON/EYAML/ETOML files.
//!
//! This module provides functionality to decrypt EJSON/EYAML/ETOML files and export
//! the secrets from the `environment` key as shell environment variables.
//!
//! Supported file formats:
//! - `.ejson`, `.json` - JSON format
//! - `.eyaml`, `.eyml`, `.yaml`, `.yml` - YAML format
//! - `.etoml`, `.toml` - TOML format

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use crate::EjsonError;
use crate::typed::DecryptedContent;
use thiserror::Error;
use zeroize::Zeroize;

/// A map of environment variable names to their secret values.
///
/// Security: This struct automatically zeroizes all secret values when dropped,
/// preventing sensitive data from lingering in memory. Each key and value string
/// is individually zeroized before the map is cleared.
pub struct SecretEnvMap {
    /// The underlying map of environment variable names to values.
    /// Both keys (env var names) and values (secrets) are zeroized on drop.
    inner: BTreeMap<String, String>,
}

impl SecretEnvMap {
    /// Creates a new empty SecretEnvMap.
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    /// Inserts a key-value pair into the map.
    pub fn insert(&mut self, key: String, value: String) {
        self.inner.insert(key, value);
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.inner.get(key)
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns an iterator over the key-value pairs.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, String> {
        self.inner.iter()
    }
}

impl Default for SecretEnvMap {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for SecretEnvMap {
    fn zeroize(&mut self) {
        // Zeroize each key and value individually before clearing the map
        // We need to take ownership to zeroize, so we drain and zeroize each entry
        for (mut key, mut value) in std::mem::take(&mut self.inner) {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl Drop for SecretEnvMap {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for SecretEnvMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEnvMap")
            .field("len", &self.inner.len())
            .field("keys", &self.inner.keys().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

impl<'a> IntoIterator for &'a SecretEnvMap {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::btree_map::Iter<'a, String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

/// Validates that a string is a valid environment variable identifier.
/// Must start with letter or underscore, followed by letters, digits, or underscores.
#[inline]
fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Errors that can occur during env export operations.
#[derive(Error, Debug)]
pub enum EnvError {
    #[error("environment is not set in ejson/eyaml/etoml")]
    NoEnv,

    #[error("environment is not a map[string]interface{{}}")]
    EnvNotMap,

    #[error("invalid identifier as key in environment: {0:?}")]
    InvalidIdentifier(String),

    #[error("could not load ejson/eyaml/etoml file: {0}")]
    LoadError(String),

    #[error("could not load environment from file: {0}")]
    EnvLoadError(String),

    #[error("ejson error: {0}")]
    Ejson(#[from] EjsonError),
}

/// Type alias for export functions.
pub type ExportFunction = fn(&mut dyn Write, &SecretEnvMap) -> Result<(), EnvError>;

/// Returns true if the error is due to the environment being missing or invalid.
pub fn is_env_error(err: &EnvError) -> bool {
    matches!(err, EnvError::NoEnv | EnvError::EnvNotMap)
}

/// Extracts environment values from decrypted content (JSON, YAML, or TOML).
///
/// Returns a SecretEnvMap of environment variable names to their values.
/// Only string values are exported; non-string values are silently ignored.
///
/// Security: The returned SecretEnvMap will automatically zeroize all values when dropped.
pub fn extract_env(content: &DecryptedContent) -> Result<SecretEnvMap, EnvError> {
    let raw_env = content.get("environment").ok_or(EnvError::NoEnv)?;

    let env_map = raw_env.as_string_map().ok_or(EnvError::EnvNotMap)?;

    let mut env_secrets = SecretEnvMap::new();

    for (key, raw_value) in env_map {
        // Reject keys that would be invalid environment variable identifiers
        if !is_valid_identifier(key) {
            return Err(EnvError::InvalidIdentifier(key.to_string()));
        }

        // Only export values that are strings
        if let Some(value) = raw_value.as_str() {
            env_secrets.insert(key.to_string(), value.to_string());
        }
    }

    Ok(env_secrets)
}

/// Reads secrets from file and extracts environment variables.
///
/// Security: The returned SecretEnvMap will automatically zeroize all values when dropped.
pub fn read_and_extract_env<P: AsRef<Path>>(
    file_path: P,
    keydir: &str,
    private_key: &str,
    trim_underscore_prefix: bool,
) -> Result<SecretEnvMap, EnvError> {
    let content =
        crate::decrypt_file_typed(file_path, keydir, private_key, trim_underscore_prefix)?;

    extract_env(&content)
}

/// Reads, extracts, and exports environment variables.
///
/// If the environment key is missing or invalid, it's not considered a fatal error
/// and an empty export will be produced.
///
/// Security: All secret values are automatically zeroized when dropped.
pub fn read_and_export_env<P: AsRef<Path>, W: Write>(
    file_path: P,
    keydir: &str,
    private_key: &str,
    trim_underscore_prefix: bool,
    export_func: ExportFunction,
    output: &mut W,
) -> Result<(), EnvError> {
    let env_values =
        match read_and_extract_env(&file_path, keydir, private_key, trim_underscore_prefix) {
            Ok(values) => values,
            Err(e) if is_env_error(&e) => SecretEnvMap::new(),
            Err(e) => return Err(EnvError::EnvLoadError(e.to_string())),
        };

    export_func(output, &env_values)
}

/// Filters control characters from a value, preserving newlines.
fn filtered_value(v: &str) -> (String, bool) {
    let mut had_control_chars = false;
    let filtered: String = v
        .chars()
        .filter(|&c| {
            if c.is_control() && c != '\n' {
                had_control_chars = true;
                false
            } else {
                true
            }
        })
        .collect();
    (filtered, had_control_chars)
}

/// Shell-escapes a value for safe use in shell commands.
/// This mimics Go's shellescape.Quote behavior which always uses single quotes
/// and escapes single quotes by ending the quoted string, adding an escaped
/// single quote, then starting a new quoted string.
fn shell_quote(s: &str) -> String {
    // Go's shellescape.Quote behavior:
    // - Always wraps in single quotes
    // - Escapes single quotes as: 'text'"'"'more'
    //   which means: end single quote, add escaped single quote, start new single quote
    let mut result = String::with_capacity(s.len() + 2);
    result.push('\'');
    for c in s.chars() {
        if c == '\'' {
            // End the current single-quoted string, add an escaped single quote,
            // then start a new single-quoted string
            result.push_str("'\"'\"'");
        } else {
            result.push(c);
        }
    }
    result.push('\'');
    result
}

/// Internal export function that writes environment variables with a prefix.
fn export(w: &mut dyn Write, prefix: &str, values: &SecretEnvMap) -> Result<(), EnvError> {
    // SecretEnvMap uses BTreeMap internally, so iteration is sorted by key
    for (k, v) in values {
        // Validate key is a valid shell identifier
        if !is_valid_identifier(k) {
            return Err(EnvError::InvalidIdentifier(k.to_string()));
        }

        let (filtered, had_control_chars) = filtered_value(v);
        if had_control_chars {
            eprintln!("ejson env trimmed control characters from value");
        }

        let quoted = shell_quote(&filtered);
        let _ = writeln!(w, "{}{}={}", prefix, k, quoted);
    }
    Ok(())
}

/// Exports environment variables with "export " prefix.
///
/// Output format: `export KEY='value'`
///
/// Returns an error if any key is not a valid shell identifier.
pub fn export_env(w: &mut dyn Write, values: &SecretEnvMap) -> Result<(), EnvError> {
    export(w, "export ", values)
}

/// Exports environment variables without "export " prefix.
///
/// Output format: `KEY='value'`
///
/// Returns an error if any key is not a valid shell identifier.
pub fn export_quiet(w: &mut dyn Write, values: &SecretEnvMap) -> Result<(), EnvError> {
    export(w, "", values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecryptedContent;

    #[test]
    fn test_is_valid_identifier() {
        // Should match
        assert!(is_valid_identifier("ALL_CAPS123"));
        assert!(is_valid_identifier("lowercase"));
        assert!(is_valid_identifier("a"));
        assert!(is_valid_identifier("_leading_underscore"));

        // Should not match
        assert!(!is_valid_identifier("1_leading_digit"));
        assert!(!is_valid_identifier("contains whitespace"));
        assert!(!is_valid_identifier("contains-dash"));
        assert!(!is_valid_identifier("contains_special_character;"));
        assert!(!is_valid_identifier("")); // Empty key
        assert!(!is_valid_identifier("key\nnewline"));
    }

    #[test]
    fn test_filtered_value() {
        let (filtered, had_control) = filtered_value("normal value");
        assert_eq!(filtered, "normal value");
        assert!(!had_control);

        let (filtered, had_control) = filtered_value("value\nwith\nnewlines");
        assert_eq!(filtered, "value\nwith\nnewlines");
        assert!(!had_control);

        let (filtered, had_control) = filtered_value("\x08value with control");
        assert_eq!(filtered, "value with control");
        assert!(had_control);
    }

    #[test]
    fn test_extract_env_json_no_env() {
        let json_value = serde_json::json!({
            "_public_key": "abc123"
        });
        let content = DecryptedContent::Json(json_value);
        let result = extract_env(&content);
        assert!(matches!(result, Err(EnvError::NoEnv)));
    }

    #[test]
    fn test_extract_env_json_not_map() {
        let json_value = serde_json::json!({
            "_public_key": "abc123",
            "environment": "not a map"
        });
        let content = DecryptedContent::Json(json_value);
        let result = extract_env(&content);
        assert!(matches!(result, Err(EnvError::EnvNotMap)));
    }

    #[test]
    fn test_extract_env_json_invalid_key() {
        let json_value = serde_json::json!({
            "_public_key": "abc123",
            "environment": {
                "invalid key": "value"
            }
        });
        let content = DecryptedContent::Json(json_value);
        let result = extract_env(&content);
        assert!(matches!(result, Err(EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_extract_env_json_valid() {
        let json_value = serde_json::json!({
            "_public_key": "abc123",
            "environment": {
                "test_key": "test_value",
                "_underscore_key": "underscore_value"
            }
        });
        let content = DecryptedContent::Json(json_value);
        let result = extract_env(&content).unwrap();
        assert_eq!(result.get("test_key"), Some(&"test_value".to_string()));
        assert_eq!(
            result.get("_underscore_key"),
            Some(&"underscore_value".to_string())
        );
    }

    #[test]
    fn test_export_env() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value".to_string());

        export_env(&mut output, &values).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "export key='value'\n");
    }

    #[test]
    fn test_export_quiet() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value".to_string());

        export_quiet(&mut output, &values).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "key='value'\n");
    }

    #[test]
    fn test_export_escaping() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert(
            "test".to_string(),
            "test value'; echo dangerous; echo 'done".to_string(),
        );

        export_env(&mut output, &values).unwrap();
        let result = String::from_utf8(output).unwrap();
        // The value should be properly escaped
        // The expected output should match Go's shellescape.Quote behavior
        let expected = "export test='test value'\"'\"'; echo dangerous; echo '\"'\"'done'\n";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_command_injection_in_key() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key; touch pwned.txt".to_string(), "value".to_string());

        let result = export_env(&mut output, &values);
        // Invalid key should return an error
        assert!(matches!(result, Err(EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_empty_key_returns_error() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("".to_string(), "value".to_string());

        let result = export_env(&mut output, &values);
        // Empty key should return an error
        assert!(matches!(result, Err(EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_dash_in_key_returns_error() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key-with-dash".to_string(), "value".to_string());

        let result = export_env(&mut output, &values);
        // Key with dash should return an error (not valid for POSIX shell variables)
        assert!(matches!(result, Err(EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_newline_in_value() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value\nnewline".to_string());

        export_env(&mut output, &values).unwrap();
        let result = String::from_utf8(output).unwrap();
        // Newlines in values should be preserved and properly escaped
        assert!(result.contains("newline"));
    }

    #[test]
    fn test_is_env_error() {
        assert!(is_env_error(&EnvError::NoEnv));
        assert!(is_env_error(&EnvError::EnvNotMap));
        assert!(!is_env_error(&EnvError::InvalidIdentifier(
            "test".to_string()
        )));
    }

    #[test]
    fn test_secret_env_map_debug_redacts_values() {
        let mut secrets = SecretEnvMap::new();
        secrets.insert("API_KEY".to_string(), "super_secret_key_123".to_string());
        secrets.insert("DB_PASSWORD".to_string(), "password123".to_string());

        let debug_output = format!("{:?}", secrets);

        // Should show keys but not values
        assert!(debug_output.contains("API_KEY"));
        assert!(debug_output.contains("DB_PASSWORD"));
        assert!(debug_output.contains("[REDACTED]"));
        // Should NOT contain the actual secret values
        assert!(!debug_output.contains("super_secret_key_123"));
        assert!(!debug_output.contains("password123"));
    }

    #[test]
    fn test_secret_env_map_zeroize() {
        let mut secrets = SecretEnvMap::new();
        secrets.insert("KEY".to_string(), "secret_value".to_string());

        // Verify the map has content before zeroize
        assert_eq!(secrets.len(), 1);
        assert!(secrets.get("KEY").is_some());

        // Zeroize the map
        secrets.zeroize();

        // After zeroize, the map should be empty
        assert!(secrets.is_empty());
        assert_eq!(secrets.len(), 0);
    }

    #[test]
    fn test_secret_env_map_into_iterator() {
        let mut secrets = SecretEnvMap::new();
        secrets.insert("ZEBRA".to_string(), "value_z".to_string());
        secrets.insert("ALPHA".to_string(), "value_a".to_string());
        secrets.insert("MIKE".to_string(), "value_m".to_string());

        // Test that we can iterate using for-in syntax (IntoIterator trait)
        let collected: Vec<_> = (&secrets).into_iter().collect();
        assert_eq!(collected.len(), 3);

        // Verify iteration order is sorted by key (BTreeMap behavior)
        let keys: Vec<_> = collected.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["ALPHA", "MIKE", "ZEBRA"]);

        // Verify values are correctly associated
        let pairs: Vec<_> = collected
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("ALPHA", "value_a"),
                ("MIKE", "value_m"),
                ("ZEBRA", "value_z")
            ]
        );

        // Test idiomatic for-in loop
        let mut count = 0;
        for (k, v) in &secrets {
            assert!(!k.is_empty());
            assert!(!v.is_empty());
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_shell_quote_backticks() {
        // Backticks could cause command substitution in some contexts
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "`whoami`".to_string());

        export_env(&mut output, &values).unwrap();
        let result = String::from_utf8(output).unwrap();
        // Single quotes prevent backtick expansion
        assert_eq!(result, "export key='`whoami`'\n");
    }

    #[test]
    fn test_shell_quote_dollar_expansion() {
        // Dollar signs could cause variable expansion
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "$HOME".to_string());

        export_env(&mut output, &values).unwrap();
        let result = String::from_utf8(output).unwrap();
        // Single quotes prevent dollar expansion
        assert_eq!(result, "export key='$HOME'\n");
    }

    #[test]
    fn test_shell_quote_subshell() {
        // $(command) could cause command substitution
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "$(cat /etc/passwd)".to_string());

        export_env(&mut output, &values).unwrap();
        let result = String::from_utf8(output).unwrap();
        // Single quotes prevent subshell expansion
        assert_eq!(result, "export key='$(cat /etc/passwd)'\n");
    }

    #[test]
    fn test_key_with_equals_returns_error() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key=value".to_string(), "test".to_string());

        let result = export_env(&mut output, &values);
        // Key with equals should return an error
        assert!(matches!(result, Err(EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_key_with_backtick_returns_error() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key`whoami`".to_string(), "test".to_string());

        let result = export_env(&mut output, &values);
        // Key with backtick should return an error
        assert!(matches!(result, Err(EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_key_with_dollar_returns_error() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("$KEY".to_string(), "test".to_string());

        let result = export_env(&mut output, &values);
        // Key starting with dollar should return an error
        assert!(matches!(result, Err(EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_value_with_null_byte() {
        // Null bytes are control characters and should be filtered
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "before\x00after".to_string());

        export_env(&mut output, &values).unwrap();
        let result = String::from_utf8(output).unwrap();
        // Null byte should be removed
        assert_eq!(result, "export key='beforeafter'\n");
    }
}
