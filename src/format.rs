//! File format detection for ejson files.
//!
//! This module provides functionality to detect whether a file is in JSON, TOML, or YAML format
//! based on file extension, and to get the appropriate handler for a format.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use thiserror::Error;

use crate::handler::FormatHandler;
use crate::json::JsonHandler;
use crate::toml::TomlHandler;
use crate::yaml::YamlHandler;

/// Errors that can occur during file format detection.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FileFormatError {
    #[error("unsupported file extension: {0}")]
    UnsupportedFileExtension(String),
}

/// Supported file formats for ejson.
///
/// More formats may be added in a minor release, so a `match` on a
/// `FileFormat` needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FileFormat {
    /// JSON format (.ejson, .json)
    #[default]
    Json,
    /// YAML format (.eyaml, .eyml, .yaml, .yml)
    Yaml,
    /// TOML format (.etoml, .toml)
    Toml,
}

impl fmt::Display for FileFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "JSON"),
            Self::Yaml => write!(f, "YAML"),
            Self::Toml => write!(f, "TOML"),
        }
    }
}

impl FileFormat {
    /// Detect the file format from a file path based on extension.
    ///
    /// The extension is matched case-insensitively (`secrets.JSON` is JSON).
    /// Returns an error if the extension is not recognized or missing.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, FileFormatError> {
        let Some(ext) = path.as_ref().extension().and_then(OsStr::to_str) else {
            return Err(FileFormatError::UnsupportedFileExtension(
                "(none)".to_string(),
            ));
        };
        match ext.to_ascii_lowercase().as_str() {
            "eyaml" | "eyml" | "yaml" | "yml" => Ok(FileFormat::Yaml),
            "ejson" | "json" => Ok(FileFormat::Json),
            "etoml" | "toml" => Ok(FileFormat::Toml),
            _ => Err(FileFormatError::UnsupportedFileExtension(ext.to_string())),
        }
    }

    /// Get the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            FileFormat::Json => "ejson",
            FileFormat::Yaml => "eyaml",
            FileFormat::Toml => "etoml",
        }
    }

    /// Get the format handler for this format.
    ///
    /// The handlers are stateless, so this is a shared static reference.
    pub(crate) fn handler(self) -> &'static dyn FormatHandler {
        match self {
            FileFormat::Json => &JsonHandler,
            FileFormat::Yaml => &YamlHandler,
            FileFormat::Toml => &TomlHandler,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_path_json_extensions() {
        assert_eq!(
            FileFormat::from_path("file.json").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("file.ejson").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.json").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.ejson").unwrap(),
            FileFormat::Json
        );
    }

    #[test]
    fn test_from_path_yaml_extensions() {
        assert_eq!(
            FileFormat::from_path("file.yaml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(FileFormat::from_path("file.yml").unwrap(), FileFormat::Yaml);
        assert_eq!(
            FileFormat::from_path("file.eyaml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("file.eyml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.eyaml").unwrap(),
            FileFormat::Yaml
        );
    }

    #[test]
    fn test_from_path_toml_extensions() {
        assert_eq!(
            FileFormat::from_path("file.toml").unwrap(),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("file.etoml").unwrap(),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.toml").unwrap(),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("path/to/file.etoml").unwrap(),
            FileFormat::Toml
        );
    }

    #[test]
    fn test_from_path_unsupported_extension() {
        let err = FileFormat::from_path("file.txt").unwrap_err();
        assert!(matches!(err, FileFormatError::UnsupportedFileExtension(ext) if ext == "txt"));

        let err = FileFormat::from_path("file.xml").unwrap_err();
        assert!(matches!(err, FileFormatError::UnsupportedFileExtension(ext) if ext == "xml"));
    }

    #[test]
    fn test_from_path_is_case_insensitive() {
        for (path, format) in [
            ("secrets.JSON", FileFormat::Json),
            ("secrets.Ejson", FileFormat::Json),
            ("secrets.YAML", FileFormat::Yaml),
            ("secrets.eYml", FileFormat::Yaml),
            ("dir/secrets.EToml", FileFormat::Toml),
            ("secrets.TOML", FileFormat::Toml),
        ] {
            assert_eq!(FileFormat::from_path(path).unwrap(), format, "{path}");
        }
    }

    #[test]
    fn test_from_path_unsupported_extension_keeps_original_case() {
        let err = FileFormat::from_path("secrets.TXT").unwrap_err();
        assert!(matches!(err, FileFormatError::UnsupportedFileExtension(ext) if ext == "TXT"));
    }

    #[test]
    fn test_from_path_no_extension() {
        let err = FileFormat::from_path("file").unwrap_err();
        assert!(matches!(err, FileFormatError::UnsupportedFileExtension(ext) if ext == "(none)"));

        let err = FileFormat::from_path("path/to/file").unwrap_err();
        assert!(matches!(err, FileFormatError::UnsupportedFileExtension(ext) if ext == "(none)"));
    }

    #[test]
    fn test_handler_matches_the_format() {
        // Each format's handler reads `_public_key` from a document in that
        // format, and rejects one in another format.
        let documents = [
            (FileFormat::Json, r#"{"_public_key": "abc"}"#),
            (FileFormat::Yaml, "_public_key: abc\nlist:\n  - x\n"),
            (FileFormat::Toml, "_public_key = \"abc\"\n[table]\n"),
        ];
        for (format, document) in documents {
            let key = format.handler().extract_public_key_string(document.as_bytes());
            assert_eq!(key.unwrap(), "abc", "{format}");
        }
        assert!(
            FileFormat::Json
                .handler()
                .extract_public_key_string(documents[2].1.as_bytes())
                .is_err()
        );
        assert!(
            FileFormat::Toml
                .handler()
                .extract_public_key_string(documents[0].1.as_bytes())
                .is_err()
        );
    }

    #[test]
    fn test_file_format_extension() {
        assert_eq!(FileFormat::Json.extension(), "ejson");
        assert_eq!(FileFormat::Yaml.extension(), "eyaml");
        assert_eq!(FileFormat::Toml.extension(), "etoml");
    }

    #[test]
    fn test_file_format_default() {
        assert_eq!(FileFormat::default(), FileFormat::Json);
    }

    #[test]
    fn test_file_format_display() {
        assert_eq!(format!("{}", FileFormat::Json), "JSON");
        assert_eq!(format!("{}", FileFormat::Yaml), "YAML");
        assert_eq!(format!("{}", FileFormat::Toml), "TOML");
    }
}
