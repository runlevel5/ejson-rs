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

use crate::typed::DecryptedContent;
use crate::{EjsonError, KeySource, UnderscorePrefix};
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

    /// Returns the value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.inner.get(key).map(String::as_str)
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns an iterator over the `(name, value)` pairs, sorted by name.
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.inner.iter())
    }
}

/// Iterator over the `(name, value)` pairs of a [`SecretEnvMap`], sorted by name.
///
/// Its `Debug` output does not print the values.
pub struct Iter<'a>(std::collections::btree_map::Iter<'a, String, String>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl std::fmt::Debug for Iter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Iter")
            .field("remaining", &self.0.len())
            .finish_non_exhaustive()
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
    type Item = (&'a str, &'a str);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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
#[non_exhaustive]
pub enum EnvError {
    #[error("environment is not set in ejson/eyaml/etoml")]
    NoEnv,

    #[error("environment is not a map[string]interface{{}}")]
    EnvNotMap,

    #[error("invalid identifier as key in environment: {0:?}")]
    InvalidIdentifier(String),

    /// Reading or decrypting the file failed. The message is the cause's.
    #[error(transparent)]
    Ejson(#[from] EjsonError),

    #[error("could not write environment: {0}")]
    Write(#[source] std::io::Error),
}

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
    key: KeySource<'_>,
    underscore_prefix: UnderscorePrefix,
) -> Result<SecretEnvMap, EnvError> {
    let content = crate::decrypt_file_typed(file_path, key, underscore_prefix)?;

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
    key: KeySource<'_>,
    underscore_prefix: UnderscorePrefix,
    shell: Shell,
    style: ExportStyle,
    output: &mut W,
) -> Result<(), EnvError> {
    let env_values = match read_and_extract_env(&file_path, key, underscore_prefix) {
        Ok(values) => values,
        Err(e) if is_env_error(&e) => SecretEnvMap::new(),
        Err(e) => return Err(e),
    };

    export(output, &env_values, shell, style)
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

/// Identifies the shell syntax to use when exporting environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// POSIX-compatible shells (bash, zsh, sh, dash, ...): `export KEY='value'`
    Posix,
    /// Fish shell: `set -gx KEY 'value'`
    Fish,
}

impl Shell {
    /// Detects the current shell from the environment.
    ///
    /// Returns [`Shell::Fish`] when `$FISH_VERSION` is in the environment, and
    /// [`Shell::Posix`] otherwise. Note that fish itself does *not* export
    /// `$FISH_VERSION` (as of fish 4), so under fish this usually returns
    /// `Posix`. That is safe: values are quoted so they read the same in both
    /// shells, and fish understands `export KEY=value`.
    pub fn detect() -> Self {
        if std::env::var_os("FISH_VERSION").is_some() {
            Shell::Fish
        } else {
            Shell::Posix
        }
    }
}

/// Whether the variables are exported to child processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportStyle {
    /// `export KEY='value'` (POSIX) or `set -gx KEY 'value'` (fish).
    #[default]
    Exported,
    /// `KEY='value'` (POSIX, also valid in a `.env` file) or
    /// `set -g KEY 'value'` (fish).
    Unexported,
}

/// Quotes a value so it reads back identically in POSIX shells *and* fish.
///
/// The value is wrapped in single quotes. The only two characters that single
/// quotes treat differently between the shells, `'` and `\`, are written as
/// double-quoted `"'"` and `"\\"` instead, which both shells read the same
/// way:
///
/// ```text
/// it's      ->  'it'"'"'s'
/// back\    ->  'back'"\\"''
/// ```
///
/// Using one form for both matters because the shell is often guessed wrong:
/// fish does not export `$FISH_VERSION`, so `--shell auto` emits POSIX output
/// under fish. With POSIX-only quoting, a value ending in a backslash
/// (`'x\'`) left fish's string open and the *next* value was run as a
/// command.
///
/// For values without a backslash this is byte-for-byte the same as Go's
/// `shellescape.Quote`, used by the original `ejson2env`.
fn shell_quote(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('\'');
    for c in s.chars() {
        match c {
            '\'' => result.push_str("'\"'\"'"),
            '\\' => result.push_str("'\"\\\\\"'"),
            c => result.push(c),
        }
    }
    result.push('\'');
    result
}

/// Writes `values` as shell assignments, one per line, sorted by name.
///
/// ```
/// use ejson::env::{ExportStyle, SecretEnvMap, Shell, export};
///
/// let mut values = SecretEnvMap::new();
/// values.insert("API_KEY".to_string(), "it's secret".to_string());
///
/// let mut out = Vec::new();
/// export(&mut out, &values, Shell::Posix, ExportStyle::Exported)?;
/// assert_eq!(out, b"export API_KEY='it'\"'\"'s secret'\n");
///
/// let mut out = Vec::new();
/// export(&mut out, &values, Shell::Fish, ExportStyle::Unexported)?;
/// assert_eq!(out, b"set -g API_KEY 'it'\"'\"'s secret'\n");
/// # Ok::<(), ejson::env::EnvError>(())
/// ```
///
/// Values are quoted so that POSIX shells and fish read them identically, and
/// control characters other than newlines are dropped (reported through
/// [`log`]). Returns [`EnvError::InvalidIdentifier`] if a name is not a valid
/// shell identifier, before writing that line.
pub fn export<W: Write>(
    mut w: W,
    values: &SecretEnvMap,
    shell: Shell,
    style: ExportStyle,
) -> Result<(), EnvError> {
    let exported = style == ExportStyle::Exported;

    // SecretEnvMap iterates sorted by name
    for (k, v) in values {
        // Validate key is a valid shell identifier
        if !is_valid_identifier(k) {
            return Err(EnvError::InvalidIdentifier(k.to_string()));
        }

        let (filtered, had_control_chars) = filtered_value(v);
        if had_control_chars {
            log::warn!("trimmed control characters from the value of {k}");
        }

        let quoted = shell_quote(&filtered);
        match shell {
            Shell::Posix => {
                let prefix = if exported { "export " } else { "" };
                writeln!(w, "{prefix}{k}={quoted}")
            }
            Shell::Fish => {
                let flag = if exported { "-gx" } else { "-g" };
                writeln!(w, "set {flag} {k} {quoted}")
            }
        }
        .map_err(EnvError::Write)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Short names for the combinations the tests below use.
    fn export_env(w: &mut dyn Write, values: &SecretEnvMap) -> Result<(), EnvError> {
        export(w, values, Shell::Posix, ExportStyle::Exported)
    }
    fn export_quiet(w: &mut dyn Write, values: &SecretEnvMap) -> Result<(), EnvError> {
        export(w, values, Shell::Posix, ExportStyle::Unexported)
    }
    fn export_env_fish(w: &mut dyn Write, values: &SecretEnvMap) -> Result<(), EnvError> {
        export(w, values, Shell::Fish, ExportStyle::Exported)
    }
    fn export_quiet_fish(w: &mut dyn Write, values: &SecretEnvMap) -> Result<(), EnvError> {
        export(w, values, Shell::Fish, ExportStyle::Unexported)
    }
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
        assert_eq!(result.get("test_key"), Some("test_value"));
        assert_eq!(result.get("_underscore_key"), Some("underscore_value"));
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
    fn test_export_env_fish() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value".to_string());

        export_env_fish(&mut output, &values).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "set -gx key 'value'\n");
    }

    #[test]
    fn test_export_quiet_fish() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value".to_string());

        export_quiet_fish(&mut output, &values).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "set -g key 'value'\n");
    }

    #[test]
    fn test_fish_quote_single_quote() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "it's a value".to_string());

        export_env_fish(&mut output, &values).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "set -gx key 'it'\"'\"'s a value'\n"
        );
    }

    #[test]
    fn test_fish_quote_backslash() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "back\\slash".to_string());

        export_env_fish(&mut output, &values).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "set -gx key 'back'\"\\\\\"'slash'\n"
        );
    }

    #[test]
    fn test_fish_quote_dollar_and_backtick_untouched() {
        // Unlike POSIX, these need no special handling inside fish single quotes.
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "$HOME `whoami`".to_string());

        export_env_fish(&mut output, &values).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "set -gx key '$HOME `whoami`'\n"
        );
    }

    #[test]
    fn test_export_style_default_is_exported() {
        assert_eq!(ExportStyle::default(), ExportStyle::Exported);
    }

    #[test]
    #[allow(unsafe_code)]
    fn test_detect_shell() {
        // SAFETY: env vars are process-global; this test owns FISH_VERSION
        // for its duration and restores it afterwards. It doesn't run
        // alongside other tests that touch this variable.
        let previous = std::env::var_os("FISH_VERSION");

        unsafe { std::env::remove_var("FISH_VERSION") };
        assert_eq!(Shell::detect(), Shell::Posix);

        unsafe { std::env::set_var("FISH_VERSION", "3.7.0") };
        assert_eq!(Shell::detect(), Shell::Fish);

        match previous {
            Some(v) => unsafe { std::env::set_var("FISH_VERSION", v) },
            None => unsafe { std::env::remove_var("FISH_VERSION") },
        }
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
    fn test_read_and_export_env_returns_the_underlying_error() {
        let mut output = Vec::new();
        let err = read_and_export_env(
            "does-not-exist.ejson",
            KeySource::keydir("/nonexistent"),
            UnderscorePrefix::Keep,
            Shell::Posix,
            ExportStyle::Exported,
            &mut output,
        )
        .unwrap_err();

        // The cause is kept as a typed error, not flattened into a string.
        assert!(matches!(err, EnvError::Ejson(EjsonError::Io(_))), "{err:?}");
        assert!(output.is_empty());
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

        let debug_output = format!("{secrets:?}");

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
    fn test_secret_env_map_yields_string_slices() {
        let mut secrets = SecretEnvMap::new();
        secrets.insert("B".to_string(), "two".to_string());
        secrets.insert("A".to_string(), "one".to_string());

        let value: Option<&str> = secrets.get("A");
        assert_eq!(value, Some("one"));
        assert_eq!(secrets.get("MISSING"), None);

        let iter = secrets.iter();
        assert_eq!(iter.len(), 2);
        // The iterator's Debug output must not print the secrets.
        assert_eq!(format!("{iter:?}"), "Iter { remaining: 2, .. }");
        let pairs: Vec<(&str, &str)> = iter.collect();
        assert_eq!(pairs, [("A", "one"), ("B", "two")]);
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
        let keys: Vec<&str> = collected.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec!["ALPHA", "MIKE", "ZEBRA"]);

        // Verify values are correctly associated
        assert_eq!(
            collected,
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
    fn test_posix_backslash_is_safe_for_fish_too() {
        // A trailing backslash used to leave fish's string open, so the next
        // value was run as a command when fish evaluated POSIX output.
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("A".to_string(), "x\\".to_string());
        values.insert("B".to_string(), "; echo PWNED #".to_string());

        export_env(&mut output, &values).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "export A='x'\"\\\\\"''\nexport B='; echo PWNED #'\n"
        );
    }

    #[test]
    fn test_posix_and_fish_quote_values_identically() {
        for value in [
            "plain",
            "it's",
            "back\\slash",
            "x\\",
            "\\'\\'",
            "$HOME `id`",
        ] {
            let mut values = SecretEnvMap::new();
            values.insert("K".to_string(), value.to_string());

            let mut posix = Vec::new();
            export_env(&mut posix, &values).unwrap();
            let mut fish = Vec::new();
            export_env_fish(&mut fish, &values).unwrap();

            let posix = String::from_utf8(posix).unwrap();
            let fish = String::from_utf8(fish).unwrap();
            assert_eq!(
                posix.strip_prefix("export K="),
                fish.strip_prefix("set -gx K "),
                "{value:?}"
            );
        }
    }

    #[test]
    fn test_write_errors_are_reported() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut values = SecretEnvMap::new();
        values.insert("K".to_string(), "v".to_string());
        assert!(matches!(
            export_env(&mut FailingWriter, &values),
            Err(EnvError::Write(_))
        ));
    }

    #[test]
    fn test_trimmed_control_characters_are_reported_through_log() {
        crate::test_log::install();

        let mut values = SecretEnvMap::new();
        values.insert("CTRL_CHAR_PROBE".to_string(), "se\x07cret".to_string());
        values.insert("CLEAN_PROBE".to_string(), "secret".to_string());
        let mut output = Vec::new();
        export_env(&mut output, &values).unwrap();

        let warnings = crate::test_log::messages_containing("CTRL_CHAR_PROBE");
        assert_eq!(
            warnings,
            ["WARN: trimmed control characters from the value of CTRL_CHAR_PROBE"]
        );
        // The message names the variable, never its value.
        assert!(crate::test_log::messages_containing("secret").is_empty());
        assert!(crate::test_log::messages_containing("CLEAN_PROBE").is_empty());
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
