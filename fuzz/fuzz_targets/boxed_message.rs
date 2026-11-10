//! The `EJ[...]` envelope parsers must never panic, must agree with
//! `is_boxed_message`, and must round-trip what they accept.
#![no_main]

use ejson::boxed_message::{BoxedMessage, is_boxed_message};
use ejson::hybrid::HybridBoxedMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let boxed = is_boxed_message(data);
    let v1 = BoxedMessage::load(data);
    let v2 = HybridBoxedMessage::load(data);

    // `encrypt` passes a value through unchanged when `is_boxed_message` says
    // it is already encrypted, so a value that neither parser accepts must not
    // be classified as boxed (it would be written out in plaintext).
    if boxed {
        assert!(
            v1.is_ok() || v2.is_ok(),
            "is_boxed_message accepted an unparsable value"
        );
    }

    if let Ok(msg) = v1 {
        let again = BoxedMessage::load(&msg.dump()).expect("v1 dump must reload");
        assert_eq!(again.encrypter_public, msg.encrypter_public);
        assert_eq!(again.nonce, msg.nonce);
        assert_eq!(again.box_data, msg.box_data);
    }
    if let Ok(msg) = v2 {
        let again = HybridBoxedMessage::load(&msg.dump()).expect("v2 dump must reload");
        assert_eq!(again.ephemeral_x25519_public, msg.ephemeral_x25519_public);
        assert_eq!(again.mlkem_ciphertext, msg.mlkem_ciphertext);
        assert_eq!(again.nonce, msg.nonce);
        assert_eq!(again.box_data, msg.box_data);
    }
});
