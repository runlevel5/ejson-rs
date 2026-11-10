//! Private key parsing must never panic, whatever is in the keydir file or
//! piped to `--key-from-stdin`.
#![no_main]

use std::sync::OnceLock;

use ejson::keys::{PrivateKey, PublicKey, generate_keypair_for_scheme};
use libfuzzer_sys::fuzz_target;

fn public_keys() -> &'static [PublicKey; 2] {
    static KEYS: OnceLock<[PublicKey; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        ["v1", "v2"].map(|scheme| {
            let (public, _, _) = generate_keypair_for_scheme(scheme).unwrap();
            PublicKey::parse(&public).unwrap()
        })
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for public in public_keys() {
        let _ = PrivateKey::parse_for_public(public, text);
    }
    let _ = PublicKey::parse(text);
});
