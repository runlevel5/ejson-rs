//! File format detection for ejson files.
//!
//! This module provides functionality to detect whether a file is in JSON, TOML, or YAML format
//! based on file extension.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during file format detection.
#[derive(Error, Debug)]
pub enum FormatError {
    #[error("unsupported file extension: {0}")]
    UnsupportedFileExtension(String),
}

/// Supported file formats for ejson.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// Returns an error if the extension is not recognized or missing.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, FormatError> {
        match path.as_ref().extension().and_then(OsStr::to_str) {
            Some("eyaml") | Some("eyml") | Some("yaml") | Some("yml") => Ok(FileFormat::Yaml),
            Some("ejson") | Some("json") => Ok(FileFormat::Json),
            Some("etoml") | Some("toml") => Ok(FileFormat::Toml),
            Some(ext) => Err(FormatError::UnsupportedFileExtension(ext.to_string())),
            None => Err(FormatError::UnsupportedFileExtension("(none)".to_string())),
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
        assert!(matches!(err, FormatError::UnsupportedFileExtension(ext) if ext == "txt"));

        let err = FileFormat::from_path("file.xml").unwrap_err();
        assert!(matches!(err, FormatError::UnsupportedFileExtension(ext) if ext == "xml"));
    }

    #[test]
    fn test_from_path_no_extension() {
        let err = FileFormat::from_path("file").unwrap_err();
        assert!(matches!(err, FormatError::UnsupportedFileExtension(ext) if ext == "(none)"));

        let err = FileFormat::from_path("path/to/file").unwrap_err();
        assert!(matches!(err, FormatError::UnsupportedFileExtension(ext) if ext == "(none)"));
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
