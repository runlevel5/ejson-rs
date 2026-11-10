//! Decrypting an arbitrary document with a real key must never panic, for
//! every format and both schemes. Inputs are attacker-controlled: anyone with
//! the public key can write a secrets file.
#![no_main]

use std::sync::OnceLock;

use ejson::format::FileFormat;
use ejson::{Scheme, decrypt_bytes_typed, generate_keypair};
use libfuzzer_sys::fuzz_target;

struct Key {
    public: String,
    private: String,
}

fn keys() -> &'static [Key; 2] {
    static KEYS: OnceLock<[Key; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [Scheme::V1, Scheme::V2].map(|scheme| {
            let kp = generate_keypair(scheme);
            Key {
                public: kp.public_key,
                private: kp.private_key.to_string(),
            }
        })
    })
}

fuzz_target!(|input: (u8, &[u8])| {
    let (selector, body) = input;
    let key = &keys()[usize::from(selector & 1)];
    let format = match (selector >> 1) % 3 {
        0 => FileFormat::Json,
        1 => FileFormat::Yaml,
        _ => FileFormat::Toml,
    };

    // Splice the real public key in so inputs reach the decrypt path instead
    // of failing on key lookup.
    let Ok(body) = std::str::from_utf8(body) else {
        return;
    };
    let doc = body.replace("PUBKEY", &key.public);

    let _ = decrypt_bytes_typed(doc.as_bytes(), "/nonexistent", &key.private, format, false);
    let _ = decrypt_bytes_typed(doc.as_bytes(), "/nonexistent", &key.private, format, true);
});
