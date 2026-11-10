//! The YAML and TOML walkers must never panic, and with an identity action
//! must not change the parsed document.
#![no_main]

use ejson::{toml as etoml, yaml as eyaml};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let identity = |v: &[u8]| Ok(v.to_vec());

    if let Ok(walked) = eyaml::Walker::new(identity).walk(data) {
        let before = serde_norway::from_slice::<serde_norway::Value>(data);
        let after = serde_norway::from_slice::<serde_norway::Value>(&walked);
        if let (Ok(before), Ok(after)) = (before, after) {
            assert_eq!(before, after, "YAML walker changed the document");
        }
    }
    let _ = eyaml::trim_underscore_prefix_from_keys(data);

    if let Ok(walked) = etoml::Walker::new(identity).walk(data) {
        let before = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.parse::<toml::Table>().ok());
        let after = std::str::from_utf8(&walked)
            .ok()
            .and_then(|s| s.parse::<toml::Table>().ok());
        if let (Some(before), Some(after)) = (before, after) {
            assert_eq!(before, after, "TOML walker changed the document");
        }
    }
    let _ = etoml::trim_underscore_prefix_from_keys(data);
});
