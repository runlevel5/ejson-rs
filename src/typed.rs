//! Typed API for working with decrypted content.
//!
//! This module provides a unified interface for accessing decrypted values
//! across different file formats (JSON, YAML, TOML) without requiring
//! format-specific handling in consuming code.
//!
//! # Example
//!
//! ```no_run
//! use ejson::DecryptedContent;
//!
//! fn extract_env(content: &DecryptedContent) -> Vec<(String, String)> {
//!     let mut env = Vec::new();
//!     if let Some(env_value) = content.get("environment") {
//!         if let Some(map) = env_value.as_string_map() {
//!             for (key, value) in map {
//!                 if let Some(v) = value.as_str() {
//!                     env.push((key.to_string(), v.to_string()));
//!                 }
//!             }
//!         }
//!     }
//!     env
//! }
//! ```

use std::fmt;

use crate::format::FileFormat;
use crate::handler::FormatError;

/// A borrowed value inside a [`DecryptedContent`]: a string, number, boolean,
/// list or map, whichever format it came from.
///
/// Security: `Debug` output shows only the format, never the value, so
/// decrypted secrets don't end up in logs via `{:?}` or `dbg!`.
#[derive(Clone)]
pub struct DecryptedValue<'a>(ValueRef<'a>);

/// The format-specific value behind a [`DecryptedValue`]. Private, so the
/// parser crates are not part of ejson's public API.
#[derive(Clone, Copy)]
enum ValueRef<'a> {
    Json(&'a serde_json::Value),
    Yaml(&'a serde_norway::Value),
    Toml(&'a ::toml::Value),
}

impl fmt::Debug for DecryptedValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self.0 {
            ValueRef::Json(_) => "Json",
            ValueRef::Yaml(_) => "Yaml",
            ValueRef::Toml(_) => "Toml",
        };
        write!(f, "DecryptedValue::{variant}([REDACTED])")
    }
}

impl<'a> DecryptedValue<'a> {
    fn json(value: &'a serde_json::Value) -> Self {
        Self(ValueRef::Json(value))
    }

    fn yaml(value: &'a serde_norway::Value) -> Self {
        Self(ValueRef::Yaml(value))
    }

    fn toml(value: &'a ::toml::Value) -> Self {
        Self(ValueRef::Toml(value))
    }

    /// Returns the value as a string slice if it is a string.
    ///
    /// Returns `None` for non-string values.
    pub fn as_str(&self) -> Option<&'a str> {
        match self.0 {
            ValueRef::Json(v) => v.as_str(),
            ValueRef::Yaml(v) => v.as_str(),
            ValueRef::Toml(v) => v.as_str(),
        }
    }

    /// Returns an iterator over key-value pairs if this value is a map
    /// (a JSON object, YAML mapping or TOML table).
    ///
    /// Returns `None` for non-map values. YAML entries whose key is not a
    /// string are skipped.
    pub fn as_string_map(
        &self,
    ) -> Option<Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>> {
        match self.0 {
            ValueRef::Json(v) => v.as_object().map(|obj| {
                Box::new(
                    obj.iter()
                        .map(|(k, v)| (k.as_str(), DecryptedValue::json(v))),
                ) as Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>
            }),
            ValueRef::Yaml(v) => v.as_mapping().map(|mapping| {
                Box::new(
                    mapping
                        .iter()
                        .filter_map(|(k, v)| k.as_str().map(|key| (key, DecryptedValue::yaml(v)))),
                ) as Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>
            }),
            ValueRef::Toml(v) => v.as_table().map(|table| {
                Box::new(
                    table
                        .iter()
                        .map(|(k, v)| (k.as_str(), DecryptedValue::toml(v))),
                ) as Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>
            }),
        }
    }

    /// Returns the value as an i64 if it is an integer type.
    pub fn as_i64(&self) -> Option<i64> {
        match self.0 {
            ValueRef::Json(v) => v.as_i64(),
            ValueRef::Yaml(v) => v.as_i64(),
            ValueRef::Toml(v) => v.as_integer(),
        }
    }

    /// Returns the value as an f64 if it is a floating-point type.
    pub fn as_f64(&self) -> Option<f64> {
        match self.0 {
            ValueRef::Json(v) => v.as_f64(),
            ValueRef::Yaml(v) => v.as_f64(),
            ValueRef::Toml(v) => v.as_float(),
        }
    }

    /// Returns the value as a bool if it is a boolean type.
    pub fn as_bool(&self) -> Option<bool> {
        match self.0 {
            ValueRef::Json(v) => v.as_bool(),
            ValueRef::Yaml(v) => v.as_bool(),
            ValueRef::Toml(v) => v.as_bool(),
        }
    }

    /// Returns true if this value is null/none.
    pub fn is_null(&self) -> bool {
        match self.0 {
            ValueRef::Json(v) => v.is_null(),
            ValueRef::Yaml(v) => v.is_null(),
            ValueRef::Toml(_) => false, // TOML doesn't have null
        }
    }

    /// Returns an iterator over array elements if this value is an array.
    pub fn as_array(&self) -> Option<Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>> {
        match self.0 {
            ValueRef::Json(v) => v.as_array().map(|arr| {
                Box::new(arr.iter().map(DecryptedValue::json))
                    as Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>
            }),
            ValueRef::Yaml(v) => v.as_sequence().map(|seq| {
                Box::new(seq.iter().map(DecryptedValue::yaml))
                    as Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>
            }),
            ValueRef::Toml(v) => v.as_array().map(|arr| {
                Box::new(arr.iter().map(DecryptedValue::toml))
                    as Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>
            }),
        }
    }

    /// Gets a nested value by key if this value is a map/object/table.
    pub fn get(&self, key: &str) -> Option<DecryptedValue<'a>> {
        match self.0 {
            ValueRef::Json(v) => v.get(key).map(DecryptedValue::json),
            ValueRef::Yaml(v) => v.get(key).map(DecryptedValue::yaml),
            ValueRef::Toml(v) => v.get(key).map(DecryptedValue::toml),
        }
    }
}

/// A decrypted document, parsed, with the same accessors whichever format it
/// was written in.
///
/// It is opaque: which parser crate holds the data is an implementation
/// detail. To work with the document through a specific parser, decrypt to
/// bytes with [`decrypt_file`](crate::decrypt_file) or
/// [`decrypt`](crate::decrypt) and parse those.
///
/// Security: `Debug` output shows only the format, never the contents, so
/// decrypted secrets don't end up in logs via `{:?}` or `dbg!`.
///
/// ```compile_fail
/// // The representation is private: there are no variants to construct or match.
/// let content = ejson::DecryptedContent::Json(Default::default());
/// ```
#[derive(Clone)]
pub struct DecryptedContent(Content);

/// The format-specific document behind a [`DecryptedContent`]. Private, so
/// the parser crates are not part of ejson's public API.
#[derive(Clone)]
enum Content {
    Json(serde_json::Value),
    Yaml(serde_norway::Value),
    Toml(::toml::Value),
}

impl fmt::Debug for DecryptedContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self.0 {
            Content::Json(_) => "Json",
            Content::Yaml(_) => "Yaml",
            Content::Toml(_) => "Toml",
        };
        write!(f, "DecryptedContent::{variant}([REDACTED])")
    }
}

impl DecryptedContent {
    /// Parse an already-decrypted document.
    ///
    /// The decrypt functions return a `DecryptedContent` directly; this is for
    /// building one from plaintext, for example in tests of code that consumes
    /// it.
    ///
    /// ```
    /// use ejson::{DecryptedContent, FileFormat};
    ///
    /// let yaml = b"environment:\n  API_KEY: s3cr3t\n";
    /// let content = DecryptedContent::parse(yaml, FileFormat::Yaml)?;
    ///
    /// let env = content.get("environment").unwrap();
    /// assert_eq!(env.get("API_KEY").unwrap().as_str(), Some("s3cr3t"));
    /// assert_eq!(content.format(), FileFormat::Yaml);
    /// # Ok::<(), ejson::FormatError>(())
    /// ```
    pub fn parse(data: &[u8], format: FileFormat) -> Result<Self, FormatError> {
        Ok(Self(match format {
            FileFormat::Json => Content::Json(
                serde_json::from_slice(data).map_err(|e| crate::json::json_syntax_error(&e))?,
            ),
            FileFormat::Yaml => {
                Content::Yaml(serde_norway::from_slice(data).map_err(crate::yaml::invalid_yaml)?)
            }
            FileFormat::Toml => {
                let text = std::str::from_utf8(data).map_err(|e| FormatError::InvalidSyntax {
                    format: "TOML",
                    message: e.to_string(),
                })?;
                Content::Toml(crate::toml::parse_value(text)?)
            }
        }))
    }

    #[cfg(test)]
    pub(crate) fn from_json(value: serde_json::Value) -> Self {
        Self(Content::Json(value))
    }

    #[cfg(test)]
    pub(crate) fn from_yaml(value: serde_norway::Value) -> Self {
        Self(Content::Yaml(value))
    }

    #[cfg(test)]
    pub(crate) fn from_toml(value: ::toml::Value) -> Self {
        Self(Content::Toml(value))
    }

    /// The format the document was written in.
    pub fn format(&self) -> FileFormat {
        match self.0 {
            Content::Json(_) => FileFormat::Json,
            Content::Yaml(_) => FileFormat::Yaml,
            Content::Toml(_) => FileFormat::Toml,
        }
    }

    /// Gets a top-level value by key.
    ///
    /// Returns a [`DecryptedValue`] reference that can be used to access
    /// the value in a format-agnostic way.
    pub fn get(&self, key: &str) -> Option<DecryptedValue<'_>> {
        self.as_value().get(key)
    }

    /// Returns a [`DecryptedValue`] reference to the root value.
    pub fn as_value(&self) -> DecryptedValue<'_> {
        match &self.0 {
            Content::Json(v) => DecryptedValue::json(v),
            Content::Yaml(v) => DecryptedValue::yaml(v),
            Content::Toml(v) => DecryptedValue::toml(v),
        }
    }

    /// Returns an iterator over top-level key-value pairs if the root is a map/object/table.
    pub fn as_string_map(
        &self,
    ) -> Option<Box<dyn Iterator<Item = (&str, DecryptedValue<'_>)> + '_>> {
        self.as_value().as_string_map()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypted_value_json_as_str() {
        let json = serde_json::json!({"key": "value"});
        let value = DecryptedValue::json(&json["key"]);
        assert_eq!(value.as_str(), Some("value"));
    }

    #[test]
    fn test_decrypted_value_json_as_string_map() {
        let json = serde_json::json!({"a": "1", "b": "2"});
        let value = DecryptedValue::json(&json);
        let map: Vec<_> = value.as_string_map().unwrap().collect();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_decrypted_content_get() {
        let json = serde_json::json!({"environment": {"FOO": "bar"}});
        let content = DecryptedContent::from_json(json);

        let env = content.get("environment").unwrap();
        let foo = env.get("FOO").unwrap();
        assert_eq!(foo.as_str(), Some("bar"));
    }

    #[test]
    fn test_decrypted_value_yaml_as_str() {
        let yaml: serde_norway::Value = serde_norway::from_str("key: value").unwrap();
        let value = DecryptedValue::yaml(&yaml["key"]);
        assert_eq!(value.as_str(), Some("value"));
    }

    #[test]
    fn test_decrypted_value_toml_as_str() {
        let toml: ::toml::Value = ::toml::from_str("key = \"value\"").unwrap();
        let value = DecryptedValue::toml(toml.get("key").unwrap());
        assert_eq!(value.as_str(), Some("value"));
    }

    #[test]
    fn test_nested_access() {
        let json = serde_json::json!({
            "environment": {
                "DATABASE_URL": "postgres://localhost",
                "API_KEY": "secret123"
            }
        });
        let content = DecryptedContent::from_json(json);

        let env = content.get("environment").unwrap();
        let db_url = env.get("DATABASE_URL").unwrap();
        assert_eq!(db_url.as_str(), Some("postgres://localhost"));
    }

    #[test]
    fn test_string_map_iteration() {
        let json = serde_json::json!({
            "environment": {
                "FOO": "bar",
                "BAZ": "qux"
            }
        });
        let content = DecryptedContent::from_json(json);

        let env = content.get("environment").unwrap();
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();

        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_debug_output_redacts_secrets() {
        let contents = [
            DecryptedContent::from_json(serde_json::json!({"password": "hunter2-secret"})),
            DecryptedContent::from_yaml(serde_norway::from_str("password: hunter2-secret").unwrap()),
            DecryptedContent::from_toml(::toml::from_str("password = \"hunter2-secret\"").unwrap()),
        ];

        for content in &contents {
            let value = content.get("password").unwrap();
            assert_eq!(value.as_str(), Some("hunter2-secret"));

            for debug in [
                format!("{content:?}"),
                format!("{content:#?}"),
                format!("{value:?}"),
                format!("{:?}", content.as_value()),
                // Common ways a value ends up in a log line
                format!("{:?}", Some(content)),
                format!("{:?}", Ok::<_, ()>(content)),
            ] {
                assert!(!debug.contains("hunter2"), "leaked: {debug}");
                assert!(!debug.contains("password"), "leaked a key: {debug}");
                assert!(debug.contains("[REDACTED]"), "{debug}");
            }
        }

        assert_eq!(
            format!("{:?}", contents[0]),
            "DecryptedContent::Json([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", contents[1].as_value()),
            "DecryptedValue::Yaml([REDACTED])"
        );
    }

    #[test]
    fn test_parse_reports_format_and_rejects_bad_input() {
        let documents = [
            (FileFormat::Json, r#"{"a": {"b": "c"}, "n": 1}"#),
            (FileFormat::Yaml, "a:\n  b: c\nn: 1\n"),
            (FileFormat::Toml, "n = 1\n[a]\nb = \"c\"\n"),
        ];
        for (format, text) in documents {
            let content = DecryptedContent::parse(text.as_bytes(), format).unwrap();
            assert_eq!(content.format(), format);
            let b = content.get("a").and_then(|a| a.get("b")).unwrap();
            assert_eq!(b.as_str(), Some("c"), "{format}");
            assert_eq!(content.get("n").unwrap().as_i64(), Some(1), "{format}");
        }

        // Errors carry a location but never the document's text.
        let err = DecryptedContent::parse(b"{\"password\": \"hunter2\" oops}", FileFormat::Json)
            .unwrap_err();
        assert!(matches!(err, FormatError::InvalidSyntax { format: "JSON", .. }));
        assert!(!err.to_string().contains("hunter2"));

        let err = DecryptedContent::parse(&[0xff, 0xfe], FileFormat::Toml).unwrap_err();
        assert!(matches!(err, FormatError::InvalidSyntax { format: "TOML", .. }));
    }
}
