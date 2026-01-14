//! File format detection for ejson files.
//!
//! This module provides functionality to detect whether a file is in JSON or TOML format
//! based on file extension.

use std::path::Path;

/// Supported file formats for ejson.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// JSON format (.ejson, .json)
    Json,
    /// TOML format (.etoml, .toml)
    Toml,
}

impl FileFormat {
    /// Detect the file format based on the file extension.
    ///
    /// Returns `Json` as the default if the extension is not recognized.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();

        if let Some(ext) = path.extension() {
            match ext.to_str() {
                Some("etoml") | Some("toml") => FileFormat::Toml,
                Some("ejson") | Some("json") => FileFormat::Json,
                _ => FileFormat::Json, // Default to JSON
            }
        } else {
            FileFormat::Json // Default to JSON
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_ejson() {
        assert_eq!(FileFormat::from_path("secrets.ejson"), FileFormat::Json);
    }

    #[test]
    fn test_format_detection_json() {
        assert_eq!(FileFormat::from_path("config.json"), FileFormat::Json);
    }

    #[test]
    fn test_format_detection_etoml() {
        assert_eq!(FileFormat::from_path("secrets.etoml"), FileFormat::Toml);
    }

    #[test]
    fn test_format_detection_toml() {
        assert_eq!(FileFormat::from_path("config.toml"), FileFormat::Toml);
    }

    #[test]
    fn test_format_detection_unknown() {
        assert_eq!(FileFormat::from_path("file.txt"), FileFormat::Json);
    }

    #[test]
    fn test_format_detection_no_extension() {
        assert_eq!(FileFormat::from_path("secrets"), FileFormat::Json);
    }

    #[test]
    fn test_format_detection_with_path() {
        assert_eq!(
            FileFormat::from_path("/path/to/secrets.etoml"),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("/path/to/secrets.ejson"),
            FileFormat::Json
        );
    }
}
