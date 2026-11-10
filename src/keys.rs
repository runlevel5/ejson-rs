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
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::crypto::{CryptoError, Decrypter, Encrypter, KeyBytes, Keypair};
use crate::hybrid::{
    self, HYBRID_PUBLIC_KEY_PREFIX, HybridDecrypter, HybridEncrypter, HybridPrivateKey,
    HybridPublicKey,
};

/// An encryption scheme.
///
/// Parses from its canonical name (`"v1"`, `"v2"`) and a few aliases, and
/// displays as the canonical name:
///
/// ```
/// use ejson::Scheme;
///
/// assert_eq!("pqc".parse::<Scheme>()?, Scheme::V2);
/// assert_eq!(Scheme::V2.to_string(), "v2");
/// assert!("v9".parse::<Scheme>().is_err());
/// # Ok::<(), ejson::CryptoError>(())
/// ```
///
/// More schemes may be added in a minor release, so a `match` on a `Scheme`
/// needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Scheme {
    /// Legacy NaCl box (Curve25519 + XSalsa20 + Poly1305).
    #[default]
    V1,
    /// Hybrid post-quantum (X25519 + ML-KEM-768, HKDF-SHA256, XChaCha20-Poly1305).
    V2,
}

impl Scheme {
    /// The canonical name: `"v1"` or `"v2"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::V1 => "v1",
            Scheme::V2 => "v2",
        }
    }

    /// The schema version number as it appears in the `EJ[<n>:...]` wire format.
    pub const fn version(self) -> u8 {
        match self {
            Scheme::V1 => 1,
            Scheme::V2 => 2,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scheme {
    type Err = CryptoError;

    /// Accepts the canonical names and aliases, ignoring case and surrounding
    /// whitespace. Anything else is [`CryptoError::UnsupportedScheme`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "1" | "v1" | "legacy" | "classic" | "nacl" | "box" => Ok(Scheme::V1),
            "2" | "v2" | "hybrid" | "pqc" | "post-quantum" | "postquantum" | "mlkem" | "ml-kem" => {
                Ok(Scheme::V2)
            }
            other => Err(CryptoError::UnsupportedScheme(other.to_string())),
        }
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
        f.debug_struct("PublicKey")
            .field("scheme", &self.scheme())
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl PublicKey {
    /// The scheme this key belongs to.
    pub fn scheme(&self) -> Scheme {
        match self {
            PublicKey::Legacy(_) => Scheme::V1,
            PublicKey::Hybrid(_) => Scheme::V2,
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

    /// The scheme this key belongs to.
    pub fn scheme(&self) -> Scheme {
        match self.0 {
            PrivateKeyInner::Legacy(_) => Scheme::V1,
            PrivateKeyInner::Hybrid(_) => Scheme::V2,
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

/// A freshly generated keypair, in the forms ejson stores them.
///
/// `Debug` output redacts the private key, which is wiped from memory on drop.
///
/// Fields may be added in a minor release, so this can't be built with a
/// struct literal; get one from [`generate_keypair`].
#[non_exhaustive]
pub struct GeneratedKeypair {
    /// The scheme the keypair was generated for.
    pub scheme: Scheme,
    /// Goes in a document's `_public_key` field: 64 hex characters for `v1`,
    /// `v2:<base64>` for `v2`.
    pub public_key: String,
    /// The contents of the private key file. For `v2` this is a multi-line
    /// `ejson-key v2` file.
    pub private_key: Zeroizing<String>,
    /// The name of the private key file in the keydir: the hex public key for
    /// `v1`, a 32-character derived ID for `v2`.
    pub key_id: String,
}

impl fmt::Debug for GeneratedKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedKeypair")
            .field("scheme", &self.scheme)
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Generate a new keypair for `scheme`.
pub fn generate_keypair(scheme: Scheme) -> GeneratedKeypair {
    match scheme {
        Scheme::V1 => {
            let kp = Keypair::generate();
            let public_key = kp.public_string();
            GeneratedKeypair {
                scheme,
                key_id: public_key.clone(),
                private_key: kp.private_hex(),
                public_key,
            }
        }
        Scheme::V2 => {
            let (public, private) = hybrid::generate_hybrid_keypair();
            GeneratedKeypair {
                scheme,
                public_key: public.to_document_string(),
                private_key: private.to_file_string(),
                key_id: public.key_id(),
            }
        }
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

    /// `(public_key, private_key, key_id)` of a new keypair.
    fn generate(scheme: Scheme) -> (String, Zeroizing<String>, String) {
        let kp = generate_keypair(scheme);
        assert_eq!(kp.scheme, scheme);
        (kp.public_key, kp.private_key, kp.key_id)
    }

    const SCHEMES: [Scheme; 2] = [Scheme::V1, Scheme::V2];

    #[test]
    fn test_scheme_parsing_and_display() {
        for s in ["v1", "1", "legacy", "classic", "nacl", "BOX", " V1 "] {
            assert_eq!(s.parse::<Scheme>().unwrap(), Scheme::V1, "{s:?}");
        }
        for s in [
            "v2",
            "2",
            "pqc",
            "hybrid",
            "ML-KEM",
            "mlkem",
            "post-quantum",
            "postquantum",
        ] {
            assert_eq!(s.parse::<Scheme>().unwrap(), Scheme::V2, "{s:?}");
        }
        for s in ["", "bogus", "v9", "3"] {
            assert!(
                matches!(s.parse::<Scheme>(), Err(CryptoError::UnsupportedScheme(_))),
                "{s:?}"
            );
        }

        for scheme in SCHEMES {
            // The canonical name round-trips.
            assert_eq!(scheme.to_string().parse::<Scheme>().unwrap(), scheme);
            assert_eq!(scheme.as_str(), scheme.to_string());
        }
        assert_eq!((Scheme::V1.version(), Scheme::V2.version()), (1, 2));
        assert_eq!(Scheme::default(), Scheme::V1);
    }

    #[test]
    fn test_generated_keypair_debug_redacts_the_private_key() {
        for scheme in SCHEMES {
            let kp = generate_keypair(scheme);
            let debug = format!("{kp:?}");
            assert!(debug.contains("[REDACTED]"));
            assert!(debug.contains(&kp.key_id));
            for line in kp
                .private_key
                .lines()
                .filter(|l| l.contains("priv") || l.len() == 64)
            {
                let secret = line.rsplit(' ').next().unwrap();
                assert!(!debug.contains(secret), "{scheme}: leaked");
            }
        }
    }

    #[test]
    fn test_legacy_parse_and_ids() {
        let (public, private, key_id) = generate(Scheme::V1);
        assert_eq!(public.len(), 64);
        assert_eq!(key_id, public);
        let pk = PublicKey::parse(&public).unwrap();
        assert_eq!(pk.scheme(), Scheme::V1);
        assert_eq!(pk.key_id(), public);
        PrivateKey::parse_for_public(&pk, &private).unwrap();
    }

    #[test]
    fn test_hybrid_parse_and_ids() {
        let (public, private, key_id) = generate(Scheme::V2);
        assert!(public.starts_with("v2:"));
        assert!(private.starts_with("ejson-key v2\n"));
        assert_eq!(key_id.len(), 32);
        let pk = PublicKey::parse(&public).unwrap();
        assert_eq!(pk.scheme(), Scheme::V2);
        assert_eq!(pk.key_id(), key_id);
        PrivateKey::parse_for_public(&pk, &private).unwrap();
    }

    #[test]
    fn test_debug_output_never_contains_private_keys() {
        for scheme in SCHEMES {
            let (public, private, key_id) = generate(scheme);
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

        for scheme in SCHEMES {
            let (public, private, _) = generate(scheme);
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
            let other_scheme = if scheme == Scheme::V1 {
                Scheme::V2
            } else {
                Scheme::V1
            };
            let (other_public, other_private, _) = generate(other_scheme);
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
        let (public, _, _) = generate(Scheme::V2);
        let (_, other_private, _) = generate(Scheme::V2);
        let pk = PublicKey::parse(&public).unwrap();
        assert!(matches!(
            PrivateKey::parse_for_public(&pk, &other_private),
            Err(CryptoError::KeyMismatch)
        ));
    }

    #[test]
    fn test_roundtrip_both_schemes() {
        for scheme in SCHEMES {
            let (public, private, _id) = generate(scheme);
            let pk = PublicKey::parse(&public).unwrap();
            let enc = AnyEncrypter::for_public_key(&pk).unwrap();
            let ct = enc.encrypt(b"hello world").unwrap();
            let privk = PrivateKey::parse_for_public(&pk, &private).unwrap();
            let dec = AnyDecrypter::new(&pk, privk).unwrap();
            assert_eq!(dec.decrypt(&ct).unwrap(), b"hello world");
        }
    }
}
