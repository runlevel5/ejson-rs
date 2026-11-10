//! The hand-written JSON scanner must never panic, and with an identity
//! action it must reproduce exactly the document `serde_json` sees: anything
//! else means the value that gets encrypted differs from the one in the file.
#![no_main]

use ejson::json::Walker;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let walker = Walker::new(|v: &[u8]| Ok(v.to_vec()));
    let walked = walker.walk(data);

    // Only compare documents serde_json accepts; ejson parses those first
    // (to read `_public_key`) and rejects everything else before walking.
    let Ok(expected) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let walked = walked.expect("walker rejected JSON that serde_json accepts");
    let actual: Value = serde_json::from_slice(&walked).expect("walker produced invalid JSON");
    assert_eq!(actual, expected, "walker changed the document");
});
