//! Schema-aware key handling and encrypt/decrypt dispatch.
//!
//! ejson supports two encryption schemes:
//! - `v1` — legacy NaCl box (Curve25519 + XSalsa20 + Poly1305), see [`crate::crypto`].
//! - `v2` — hybrid post-quantum (X25519 + ML-KEM-768), see [`crate::hybrid`].
//!
//! This module provides scheme-tagged [`PublicKey`]/[`PrivateKey`] types and the
//! [`AnyEncrypter`]/[`AnyDecrypter`] dispatchers used by the top-level encrypt/decrypt
//! flows, so the rest of the crate stays scheme-agnostic.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::{CryptoError, Decrypter, Encrypter, KeyBytes, Keypair};
use crate::hybrid::{
    self, HYBRID_PUBLIC_KEY_PREFIX, HybridDecrypter, HybridEncrypter, HybridPrivateKey,
    HybridPublicKey,
};

/// Canonical scheme identifiers.
pub const SCHEME_LEGACY: &str = "v1";
pub const SCHEME_HYBRID: &str = "v2";

/// Schema version numbers as they appear in the `EJ[<n>:...]` wire format.
pub const VERSION_LEGACY: u8 = 1;
pub const VERSION_HYBRID: u8 = 2;

/// Normalize a user-supplied scheme string to a canonical `v1`/`v2`, accepting a range of
/// aliases. Unknown values are returned lowercased so the caller can produce a helpful
/// error.
pub fn normalize_scheme(scheme: &str) -> String {
    match scheme.trim().to_lowercase().as_str() {
        "" | "1" | "v1" | "legacy" | "classic" | "nacl" | "box" => SCHEME_LEGACY.to_string(),
        "2" | "v2" | "hybrid" | "pqc" | "post-quantum" | "postquantum" | "mlkem" | "ml-kem" => {
            SCHEME_HYBRID.to_string()
        }
        other => other.to_string(),
    }
}

/// A schema-aware public key.
///
/// The hybrid variant is boxed because its ML-KEM material makes it ~1.2 KB, far larger
/// than the 32-byte legacy variant.
pub enum PublicKey {
    Legacy(KeyBytes),
    Hybrid(Box<HybridPublicKey>),
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self {
            PublicKey::Legacy(_) => SCHEME_LEGACY,
            PublicKey::Hybrid(_) => SCHEME_HYBRID,
        };
        f.debug_struct("PublicKey")
            .field("scheme", &scheme)
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl PublicKey {
    /// The schema version number.
    pub fn version(&self) -> u8 {
        match self {
            PublicKey::Legacy(_) => VERSION_LEGACY,
            PublicKey::Hybrid(_) => VERSION_HYBRID,
        }
    }

    /// Parse a public key as it appears in a document's `_public_key` field.
    ///
    /// A `v2:` prefix selects the hybrid scheme; otherwise it is parsed as a legacy
    /// 64-character hex key.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        let s = s.trim();
        if s.starts_with(HYBRID_PUBLIC_KEY_PREFIX) {
            Ok(PublicKey::Hybrid(Box::new(
                HybridPublicKey::parse_document_string(s)?,
            )))
        } else {
            Ok(PublicKey::Legacy(parse_legacy_public_key(s)?))
        }
    }

    /// The document form of this public key (hex for legacy, `v2:<base64>` for hybrid).
    pub fn to_document_string(&self) -> String {
        match self {
            PublicKey::Legacy(k) => hex::encode(k),
            PublicKey::Hybrid(h) => h.to_document_string(),
        }
    }

    /// The keydir filename for this key. Legacy keys use the 64-char hex public key
    /// (unchanged from before); hybrid keys use a 32-char derived key ID.
    pub fn key_id(&self) -> String {
        match self {
            PublicKey::Legacy(k) => hex::encode(k),
            PublicKey::Hybrid(h) => h.key_id(),
        }
    }
}

/// A schema-aware private key.
///
/// Opaque: the key material can't be read or pattern-matched out of it. It
/// is wiped from memory on drop, and its `Debug` output is redacted.
///
/// ```compile_fail,E0616
/// # fn demo(key: ejson::keys::PrivateKey) {
/// let _inner = key.0; // private field
/// # }
/// ```
pub struct PrivateKey(PrivateKeyInner);

enum PrivateKeyInner {
    Legacy(Zeroizing<KeyBytes>),
    // Boxed for the same size reason as [`PublicKey::Hybrid`].
    Hybrid(Box<HybridPrivateKey>),
}

// Never prints key material.
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("scheme", &self.scheme())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl PrivateKey {
    /// Parse private key material for the given public key, verifying the scheme matches.
    pub fn parse_for_public(public: &PublicKey, data: &str) -> Result<Self, CryptoError> {
        Ok(Self(match public {
            PublicKey::Legacy(_) => PrivateKeyInner::Legacy(parse_legacy_private_key(data)?),
            PublicKey::Hybrid(h) => {
                PrivateKeyInner::Hybrid(Box::new(HybridPrivateKey::parse_for_public(h, data)?))
            }
        }))
    }

    /// The scheme this key belongs to: `"v1"` or `"v2"`.
    pub fn scheme(&self) -> &'static str {
        match self.0 {
            PrivateKeyInner::Legacy(_) => SCHEME_LEGACY,
            PrivateKeyInner::Hybrid(_) => SCHEME_HYBRID,
        }
    }
}

/// Scheme-tagged encrypter.
#[derive(Debug)]
pub enum AnyEncrypter {
    Legacy(Encrypter),
    Hybrid(Box<HybridEncrypter>),
}

impl AnyEncrypter {
    /// Build an encrypter targeting the given recipient public key.
    ///
    /// For the legacy scheme this generates a fresh ephemeral keypair (reused for all
    /// values in the file, as before). For the hybrid scheme, ephemeral material is
    /// generated per value inside [`HybridEncrypter::encrypt`].
    pub fn for_public_key(public: &PublicKey) -> Result<Self, CryptoError> {
        match public {
            PublicKey::Legacy(peer) => {
                let kp = Keypair::generate();
                Ok(AnyEncrypter::Legacy(kp.into_encrypter(*peer)))
            }
            PublicKey::Hybrid(h) => Ok(AnyEncrypter::Hybrid(Box::new(HybridEncrypter::new(
                (**h).clone(),
            )?))),
        }
    }

    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            AnyEncrypter::Legacy(e) => e.encrypt(message),
            AnyEncrypter::Hybrid(e) => e.encrypt(message),
        }
    }
}

/// Scheme-tagged decrypter.
#[derive(Debug)]
pub enum AnyDecrypter {
    Legacy(Decrypter),
    Hybrid(Box<HybridDecrypter>),
}

impl AnyDecrypter {
    /// Build a decrypter from a matching public/private key pair.
    pub fn new(public: &PublicKey, private: PrivateKey) -> Result<Self, CryptoError> {
        match (public, private.0) {
            (PublicKey::Legacy(pubk), PrivateKeyInner::Legacy(privk)) => {
                // `privk` wipes its copy when it goes out of scope; the
                // keypair wipes the one it now owns on drop.
                let kp = Keypair::from_keys(*pubk, *privk);
                Ok(AnyDecrypter::Legacy(kp.into_decrypter()))
            }
            (PublicKey::Hybrid(_), PrivateKeyInner::Hybrid(privk)) => {
                Ok(AnyDecrypter::Hybrid(Box::new(HybridDecrypter::new(*privk))))
            }
            _ => Err(CryptoError::KeyMismatch),
        }
    }

    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            AnyDecrypter::Legacy(d) => d.decrypt(message),
            AnyDecrypter::Hybrid(d) => d.decrypt(message),
        }
    }
}

/// Generate a keypair for the named scheme.
///
/// Returns `(public_key_document_string, private_key_file_string, key_id)`. The private
/// key should be written to `keydir/<key_id>`.
pub fn generate_keypair_for_scheme(
    scheme: &str,
) -> Result<(String, Zeroizing<String>, String), CryptoError> {
    match normalize_scheme(scheme).as_str() {
        SCHEME_LEGACY => {
            let kp = Keypair::generate();
            let public = kp.public_string();
            let private = kp.private_hex();
            let key_id = public.clone();
            Ok((public, private, key_id))
        }
        SCHEME_HYBRID => {
            let (public, private) = hybrid::generate_hybrid_keypair();
            let key_id = public.key_id();
            Ok((
                public.to_document_string(),
                private.to_file_string(),
                key_id,
            ))
        }
        other => Err(CryptoError::UnsupportedScheme(other.to_string())),
    }
}

fn parse_legacy_public_key(s: &str) -> Result<KeyBytes, CryptoError> {
    crate::handler::decode_legacy_public_key(s).ok_or(CryptoError::InvalidPublicKey)
}

fn parse_legacy_private_key(data: &str) -> Result<Zeroizing<KeyBytes>, CryptoError> {
    // Decoded straight into a buffer that is wiped on drop, including when
    // decoding fails part-way.
    let mut key = Zeroizing::new([0u8; crate::crypto::KEY_SIZE]);
    hex::decode_to_slice(data.trim(), key.as_mut_slice())
        .map_err(|_| CryptoError::InvalidPrivateKey)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_scheme() {
        for s in ["", "v1", "1", "legacy", "nacl", "BOX"] {
            assert_eq!(normalize_scheme(s), SCHEME_LEGACY);
        }
        for s in ["v2", "2", "pqc", "hybrid", "ML-KEM", "post-quantum"] {
            assert_eq!(normalize_scheme(s), SCHEME_HYBRID);
        }
        assert_eq!(normalize_scheme("bogus"), "bogus");
    }

    #[test]
    fn test_legacy_parse_and_ids() {
        let (public, private, key_id) = generate_keypair_for_scheme("v1").unwrap();
        assert_eq!(public.len(), 64);
        assert_eq!(key_id, public);
        let pk = PublicKey::parse(&public).unwrap();
        assert_eq!(pk.version(), VERSION_LEGACY);
        assert_eq!(pk.key_id(), public);
        PrivateKey::parse_for_public(&pk, &private).unwrap();
    }

    #[test]
    fn test_hybrid_parse_and_ids() {
        let (public, private, key_id) = generate_keypair_for_scheme("v2").unwrap();
        assert!(public.starts_with("v2:"));
        assert!(private.starts_with("ejson-key v2\n"));
        assert_eq!(key_id.len(), 32);
        let pk = PublicKey::parse(&public).unwrap();
        assert_eq!(pk.version(), VERSION_HYBRID);
        assert_eq!(pk.key_id(), key_id);
        PrivateKey::parse_for_public(&pk, &private).unwrap();
    }

    #[test]
    fn test_debug_output_never_contains_private_keys() {
        for scheme in ["v1", "v2"] {
            let (public, private, key_id) = generate_keypair_for_scheme(scheme).unwrap();
            let pk = PublicKey::parse(&public).unwrap();
            let privk = PrivateKey::parse_for_public(&pk, &private).unwrap();

            // Every hex or base64 run of the private key file that is long
            // enough to be key material, and isn't part of the public key.
            let secrets: Vec<&str> = private
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/')
                .filter(|part| part.len() >= 32 && !public.contains(part) && *part != key_id)
                .collect();
            assert!(!secrets.is_empty());

            let private_debug = format!("{privk:?}");
            let decrypter = AnyDecrypter::new(&pk, privk).unwrap();
            let encrypter = AnyEncrypter::for_public_key(&pk).unwrap();
            let outputs = [
                private_debug,
                format!("{decrypter:?}"),
                format!("{encrypter:?}"),
                format!("{pk:?}"),
            ];

            for output in &outputs {
                for secret in &secrets {
                    assert!(!output.contains(secret), "{scheme}: leaked in {output}");
                }
            }
            assert!(outputs[0].contains("[REDACTED]"));
            assert!(outputs[1].contains("[REDACTED]"));
            assert!(outputs[3].contains(&key_id));
        }
    }

    #[test]
    fn test_key_errors_say_what_is_wrong() {
        // Malformed public keys
        for bad in ["", "abc", "zz", "v2:", "v2:not-base64!", "v2:AAAA"] {
            assert!(
                matches!(PublicKey::parse(bad), Err(CryptoError::InvalidPublicKey)),
                "{bad:?}"
            );
        }

        for scheme in ["v1", "v2"] {
            let (public, private, _) = generate_keypair_for_scheme(scheme).unwrap();
            let pk = PublicKey::parse(&public).unwrap();

            // Malformed private keys
            for bad in ["", "not-a-key", "abcd", "ejson-key v2\nkeyid: x\n"] {
                assert!(
                    matches!(
                        PrivateKey::parse_for_public(&pk, bad),
                        Err(CryptoError::InvalidPrivateKey)
                    ),
                    "{scheme}: {bad:?}"
                );
            }

            // A valid private key of the other scheme is malformed for this one.
            let other_scheme = if scheme == "v1" { "v2" } else { "v1" };
            let (other_public, other_private, _) =
                generate_keypair_for_scheme(other_scheme).unwrap();
            assert!(matches!(
                PrivateKey::parse_for_public(&pk, &other_private),
                Err(CryptoError::InvalidPrivateKey)
            ));

            // Handing a decrypter keys of two different schemes is a mismatch.
            let other_pk = PublicKey::parse(&other_public).unwrap();
            let privk = PrivateKey::parse_for_public(&pk, &private).unwrap();
            assert!(matches!(
                AnyDecrypter::new(&other_pk, privk),
                Err(CryptoError::KeyMismatch)
            ));
        }

        // A well-formed v2 key for a different v2 public key is a mismatch,
        // detected when the key is loaded.
        let (public, _, _) = generate_keypair_for_scheme("v2").unwrap();
        let (_, other_private, _) = generate_keypair_for_scheme("v2").unwrap();
        let pk = PublicKey::parse(&public).unwrap();
        assert!(matches!(
            PrivateKey::parse_for_public(&pk, &other_private),
            Err(CryptoError::KeyMismatch)
        ));
    }

    #[test]
    fn test_unsupported_scheme() {
        assert!(matches!(
            generate_keypair_for_scheme("v9"),
            Err(CryptoError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn test_roundtrip_both_schemes() {
        for scheme in ["v1", "v2"] {
            let (public, private, _id) = generate_keypair_for_scheme(scheme).unwrap();
            let pk = PublicKey::parse(&public).unwrap();
            let enc = AnyEncrypter::for_public_key(&pk).unwrap();
            let ct = enc.encrypt(b"hello world").unwrap();
            let privk = PrivateKey::parse_for_public(&pk, &private).unwrap();
            let dec = AnyDecrypter::new(&pk, privk).unwrap();
            assert_eq!(dec.decrypt(&ct).unwrap(), b"hello world");
        }
    }
}
