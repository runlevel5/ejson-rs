//! Typed API for working with decrypted content.
//!
//! This module provides a unified interface for accessing decrypted values
//! across different file formats (JSON, YAML, TOML) without requiring
//! format-specific handling in consuming code.
//!
//! # Example
//!
//! ```no_run
//! use ejson::typed::DecryptedContent;
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

/// A reference type for uniformly accessing values across JSON, YAML, and TOML formats.
///
/// This enum wraps references to the underlying format-specific value types,
/// providing a common interface for value access.
#[derive(Debug, Clone)]
pub enum DecryptedValue<'a> {
    /// A JSON value reference
    Json(&'a serde_json::Value),
    /// A YAML value reference
    Yaml(&'a serde_norway::Value),
    /// A TOML value reference
    Toml(&'a ::toml::Value),
}

impl<'a> DecryptedValue<'a> {
    /// Returns the value as a string slice if it is a string type.
    ///
    /// Works with:
    /// - JSON strings
    /// - YAML strings
    /// - TOML strings
    ///
    /// Returns `None` for non-string values.
    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            DecryptedValue::Json(v) => v.as_str(),
            DecryptedValue::Yaml(v) => v.as_str(),
            DecryptedValue::Toml(v) => v.as_str(),
        }
    }

    /// Returns an iterator over key-value pairs if this value is a map/object/table.
    ///
    /// Works with:
    /// - JSON objects
    /// - YAML mappings (with string keys)
    /// - TOML tables
    ///
    /// Returns `None` for non-map values or YAML mappings with non-string keys.
    pub fn as_string_map(
        &self,
    ) -> Option<Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>> {
        match self {
            DecryptedValue::Json(v) => v.as_object().map(|obj| {
                Box::new(
                    obj.iter()
                        .map(|(k, v)| (k.as_str(), DecryptedValue::Json(v))),
                ) as Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>
            }),
            DecryptedValue::Yaml(v) => v.as_mapping().map(|mapping| {
                Box::new(
                    mapping
                        .iter()
                        .filter_map(|(k, v)| k.as_str().map(|key| (key, DecryptedValue::Yaml(v)))),
                ) as Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>
            }),
            DecryptedValue::Toml(v) => v.as_table().map(|table| {
                Box::new(
                    table
                        .iter()
                        .map(|(k, v)| (k.as_str(), DecryptedValue::Toml(v))),
                ) as Box<dyn Iterator<Item = (&'a str, DecryptedValue<'a>)> + 'a>
            }),
        }
    }

    /// Returns the value as an i64 if it is an integer type.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            DecryptedValue::Json(v) => v.as_i64(),
            DecryptedValue::Yaml(v) => v.as_i64(),
            DecryptedValue::Toml(v) => v.as_integer(),
        }
    }

    /// Returns the value as an f64 if it is a floating-point type.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            DecryptedValue::Json(v) => v.as_f64(),
            DecryptedValue::Yaml(v) => v.as_f64(),
            DecryptedValue::Toml(v) => v.as_float(),
        }
    }

    /// Returns the value as a bool if it is a boolean type.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            DecryptedValue::Json(v) => v.as_bool(),
            DecryptedValue::Yaml(v) => v.as_bool(),
            DecryptedValue::Toml(v) => v.as_bool(),
        }
    }

    /// Returns true if this value is null/none.
    pub fn is_null(&self) -> bool {
        match self {
            DecryptedValue::Json(v) => v.is_null(),
            DecryptedValue::Yaml(v) => v.is_null(),
            DecryptedValue::Toml(_) => false, // TOML doesn't have null
        }
    }

    /// Returns an iterator over array elements if this value is an array.
    pub fn as_array(&self) -> Option<Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>> {
        match self {
            DecryptedValue::Json(v) => v.as_array().map(|arr| {
                Box::new(arr.iter().map(DecryptedValue::Json))
                    as Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>
            }),
            DecryptedValue::Yaml(v) => v.as_sequence().map(|seq| {
                Box::new(seq.iter().map(DecryptedValue::Yaml))
                    as Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>
            }),
            DecryptedValue::Toml(v) => v.as_array().map(|arr| {
                Box::new(arr.iter().map(DecryptedValue::Toml))
                    as Box<dyn Iterator<Item = DecryptedValue<'a>> + 'a>
            }),
        }
    }

    /// Gets a nested value by key if this value is a map/object/table.
    pub fn get(&self, key: &str) -> Option<DecryptedValue<'a>> {
        match self {
            DecryptedValue::Json(v) => v.get(key).map(DecryptedValue::Json),
            DecryptedValue::Yaml(v) => v.get(key).map(DecryptedValue::Yaml),
            DecryptedValue::Toml(v) => v.get(key).map(DecryptedValue::Toml),
        }
    }
}

/// A typed wrapper that holds the parsed decrypted content.
///
/// This enum contains the actual parsed value (not just bytes) after decryption,
/// allowing format-agnostic access to the decrypted data.
#[derive(Debug, Clone)]
pub enum DecryptedContent {
    /// Decrypted and parsed JSON content
    Json(serde_json::Value),
    /// Decrypted and parsed YAML content
    Yaml(serde_norway::Value),
    /// Decrypted and parsed TOML content
    Toml(::toml::Value),
}

impl DecryptedContent {
    /// Gets a top-level value by key.
    ///
    /// Returns a [`DecryptedValue`] reference that can be used to access
    /// the value in a format-agnostic way.
    pub fn get(&self, key: &str) -> Option<DecryptedValue<'_>> {
        match self {
            DecryptedContent::Json(v) => v.get(key).map(DecryptedValue::Json),
            DecryptedContent::Yaml(v) => v.get(key).map(DecryptedValue::Yaml),
            DecryptedContent::Toml(v) => v.get(key).map(DecryptedValue::Toml),
        }
    }

    /// Returns a [`DecryptedValue`] reference to the root value.
    pub fn as_value(&self) -> DecryptedValue<'_> {
        match self {
            DecryptedContent::Json(v) => DecryptedValue::Json(v),
            DecryptedContent::Yaml(v) => DecryptedValue::Yaml(v),
            DecryptedContent::Toml(v) => DecryptedValue::Toml(v),
        }
    }

    /// Returns an iterator over top-level key-value pairs if the root is a map/object/table.
    pub fn as_string_map(
        &self,
    ) -> Option<Box<dyn Iterator<Item = (&str, DecryptedValue<'_>)> + '_>> {
        self.as_value().as_string_map()
    }

    /// Returns the underlying JSON value if this is JSON content.
    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            DecryptedContent::Json(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the underlying YAML value if this is YAML content.
    pub fn as_yaml(&self) -> Option<&serde_norway::Value> {
        match self {
            DecryptedContent::Yaml(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the underlying TOML value if this is TOML content.
    pub fn as_toml(&self) -> Option<&::toml::Value> {
        match self {
            DecryptedContent::Toml(v) => Some(v),
            _ => None,
        }
    }

    /// Consumes the content and returns the underlying JSON value.
    pub fn into_json(self) -> Option<serde_json::Value> {
        match self {
            DecryptedContent::Json(v) => Some(v),
            _ => None,
        }
    }

    /// Consumes the content and returns the underlying YAML value.
    pub fn into_yaml(self) -> Option<serde_norway::Value> {
        match self {
            DecryptedContent::Yaml(v) => Some(v),
            _ => None,
        }
    }

    /// Consumes the content and returns the underlying TOML value.
    pub fn into_toml(self) -> Option<::toml::Value> {
        match self {
            DecryptedContent::Toml(v) => Some(v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypted_value_json_as_str() {
        let json = serde_json::json!({"key": "value"});
        let value = DecryptedValue::Json(&json["key"]);
        assert_eq!(value.as_str(), Some("value"));
    }

    #[test]
    fn test_decrypted_value_json_as_string_map() {
        let json = serde_json::json!({"a": "1", "b": "2"});
        let value = DecryptedValue::Json(&json);
        let map: Vec<_> = value.as_string_map().unwrap().collect();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_decrypted_content_get() {
        let json = serde_json::json!({"environment": {"FOO": "bar"}});
        let content = DecryptedContent::Json(json);

        let env = content.get("environment").unwrap();
        let foo = env.get("FOO").unwrap();
        assert_eq!(foo.as_str(), Some("bar"));
    }

    #[test]
    fn test_decrypted_value_yaml_as_str() {
        let yaml: serde_norway::Value = serde_norway::from_str("key: value").unwrap();
        let value = DecryptedValue::Yaml(&yaml["key"]);
        assert_eq!(value.as_str(), Some("value"));
    }

    #[test]
    fn test_decrypted_value_toml_as_str() {
        let toml: ::toml::Value = ::toml::from_str("key = \"value\"").unwrap();
        let value = DecryptedValue::Toml(toml.get("key").unwrap());
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
        let content = DecryptedContent::Json(json);

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
        let content = DecryptedContent::Json(json);

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
}
