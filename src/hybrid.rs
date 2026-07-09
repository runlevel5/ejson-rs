//! Hybrid post-quantum encryption (schema `v2`).
//!
//! The `v2` scheme combines classical X25519 ECDH with the NIST-standardized
//! ML-KEM-768 key-encapsulation mechanism (FIPS 203). The two shared secrets are
//! concatenated and run through HKDF-SHA256 to derive a key for XChaCha20-Poly1305,
//! which encrypts the individual JSON string values. This provides confidentiality
//! against both classical and quantum ("harvest-now-decrypt-later") adversaries: an
//! attacker must break *both* X25519 and ML-KEM to recover a secret.
//!
//! Wire format:
//! ```text
//! EJ[2:<b64 ephemeral X25519 public>:<b64 ML-KEM ciphertext>:<b64 nonce>:<b64 box>]
//! ```
//!
//! This is the `v2` scheme — the first scheme after the legacy `v1` NaCl box. See the
//! project README for details.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, kem::Kem as _};
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

use crate::boxed_message::{
    BoxedMessageError, NONCE_SIZE, SCHEMA_VERSION_HYBRID, is_boxed_message, parse_boxed_envelope,
};
use crate::crypto::CryptoError;

/// Size of an X25519 public/private key in bytes.
pub const HYBRID_X25519_KEY_SIZE: usize = 32;

/// Size of the ML-KEM-768 decapsulation key seed in bytes.
pub const HYBRID_MLKEM_SEED_SIZE: usize = 64;

/// Size of the ML-KEM-768 encapsulation key (public) in bytes.
pub const HYBRID_MLKEM_PUBLIC_KEY_SIZE: usize = 1184;

/// Size of an ML-KEM-768 ciphertext in bytes.
pub const HYBRID_MLKEM_CIPHERTEXT_SIZE: usize = 1088;

/// Combined size of the raw public key payload (X25519 public ‖ ML-KEM encapsulation key).
pub const HYBRID_PUBLIC_KEY_PAYLOAD_SIZE: usize =
    HYBRID_X25519_KEY_SIZE + HYBRID_MLKEM_PUBLIC_KEY_SIZE;

/// Prefix that marks a hybrid public key in a document's `_public_key` field.
pub const HYBRID_PUBLIC_KEY_PREFIX: &str = "v2:";

/// Header line at the top of a hybrid private key file.
pub const HYBRID_KEY_FILE_HEADER: &str = "ejson-key v2";

/// Domain separator for deriving the hybrid key ID.
const HYBRID_KEY_ID_DOMAIN: &[u8] = b"ejson/v2/pubkey";

/// HKDF salt for the hybrid KDF.
const HYBRID_KDF_SALT: &[u8] = b"ejson/v2/x25519-mlkem768/hkdf-sha256";

/// AEAD domain separator, prepended to the transcript used as HKDF info and AEAD AAD.
const HYBRID_AAD_DOMAIN: &[u8] = b"ejson/v2/x25519-mlkem768/xchacha20poly1305";

/// A hybrid `v2` public key: an X25519 public key plus an ML-KEM-768 encapsulation key.
#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519_public: [u8; HYBRID_X25519_KEY_SIZE],
    pub mlkem_ek: [u8; HYBRID_MLKEM_PUBLIC_KEY_SIZE],
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl HybridPublicKey {
    /// Raw public key payload: `x25519_public ‖ mlkem_ek`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PUBLIC_KEY_PAYLOAD_SIZE);
        out.extend_from_slice(&self.x25519_public);
        out.extend_from_slice(&self.mlkem_ek);
        out
    }

    /// Document form: `v2:<base64 payload>`.
    pub fn to_document_string(&self) -> String {
        format!(
            "{HYBRID_PUBLIC_KEY_PREFIX}{}",
            BASE64.encode(self.to_bytes())
        )
    }

    /// The keydir filename for this key: `hex(sha256(domain ‖ x25519 ‖ mlkem_ek)[..16])`.
    pub fn key_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(HYBRID_KEY_ID_DOMAIN);
        h.update(self.x25519_public);
        h.update(self.mlkem_ek);
        hex::encode(&h.finalize()[..16])
    }

    /// Validate and construct a hybrid public key from raw `x25519 ‖ mlkem_ek` bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, CryptoError> {
        if payload.len() != HYBRID_PUBLIC_KEY_PAYLOAD_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        let (x_bytes, ek_bytes) = payload.split_at(HYBRID_X25519_KEY_SIZE);

        // Validate the ML-KEM encapsulation key parses.
        let ek_arr: Array<u8, _> =
            Array::try_from(ek_bytes).map_err(|_| CryptoError::InvalidKeyLength)?;
        EncapsulationKey::<MlKem768>::new(&ek_arr).map_err(|_| CryptoError::InvalidKeyLength)?;

        let mut key = Self {
            x25519_public: [0u8; HYBRID_X25519_KEY_SIZE],
            mlkem_ek: [0u8; HYBRID_MLKEM_PUBLIC_KEY_SIZE],
        };
        key.x25519_public.copy_from_slice(x_bytes);
        key.mlkem_ek.copy_from_slice(ek_bytes);
        Ok(key)
    }

    /// Parse a `v2:<base64>` document public key string.
    pub fn parse_document_string(s: &str) -> Result<Self, CryptoError> {
        let s = s.trim();
        let payload = s
            .strip_prefix(HYBRID_PUBLIC_KEY_PREFIX)
            .ok_or(CryptoError::InvalidKeyLength)?;
        let bytes = BASE64
            .decode(payload)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Self::from_payload(&bytes)
    }

    fn encapsulation_key(&self) -> Result<EncapsulationKey<MlKem768>, CryptoError> {
        let ek_arr: Array<u8, _> =
            Array::try_from(&self.mlkem_ek[..]).map_err(|_| CryptoError::InvalidKeyLength)?;
        EncapsulationKey::<MlKem768>::new(&ek_arr).map_err(|_| CryptoError::InvalidKeyLength)
    }

    fn x25519(&self) -> X25519Public {
        X25519Public::from(self.x25519_public)
    }
}

/// A hybrid `v2` private key: X25519 private scalar plus the ML-KEM-768 seed, along with
/// the corresponding public key.
pub struct HybridPrivateKey {
    pub public: HybridPublicKey,
    pub x25519_private: [u8; HYBRID_X25519_KEY_SIZE],
    pub mlkem_seed: [u8; HYBRID_MLKEM_SEED_SIZE],
}

impl fmt::Debug for HybridPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPrivateKey")
            .field("key_id", &self.public.key_id())
            .field("x25519_private", &"[REDACTED]")
            .field("mlkem_seed", &"[REDACTED]")
            .finish()
    }
}

impl Drop for HybridPrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.x25519_private.zeroize();
        self.mlkem_seed.zeroize();
    }
}

impl HybridPrivateKey {
    /// Serialize into the `ejson-key v2` private key file body.
    pub fn to_file_string(&self) -> Zeroizing<String> {
        // Hex-encode the secret components into Zeroizing temporaries so their heap
        // allocations are wiped on drop; build the output by pushing (never `format!`,
        // which would create unzeroized intermediate strings holding the secrets).
        let priv_x_hex = Zeroizing::new(hex::encode(self.x25519_private));
        let seed_hex = Zeroizing::new(hex::encode(self.mlkem_seed));

        let mut out = Zeroizing::new(String::new());
        out.push_str(HYBRID_KEY_FILE_HEADER);
        out.push_str("\nkeyid: ");
        out.push_str(&self.public.key_id());
        out.push_str("\npub-x25519: ");
        out.push_str(&hex::encode(self.public.x25519_public));
        out.push_str("\npub-mlkem768: ");
        out.push_str(&BASE64.encode(self.public.mlkem_ek));
        out.push_str("\npriv-x25519: ");
        out.push_str(&priv_x_hex);
        out.push_str("\npriv-mlkem768-seed: ");
        out.push_str(&seed_hex);
        out
    }

    /// Parse an `ejson-key v2` private key file body and verify it matches `expected`.
    pub fn parse_for_public(expected: &HybridPublicKey, data: &str) -> Result<Self, CryptoError> {
        let fields = parse_key_file_fields(data)?;

        // Reconstruct and validate the embedded public key.
        let pub_x_bytes =
            hex::decode(&fields.pub_x25519).map_err(|_| CryptoError::InvalidKeyLength)?;
        let pub_mlkem_bytes = BASE64
            .decode(&fields.pub_mlkem768)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        if pub_x_bytes.len() != HYBRID_X25519_KEY_SIZE
            || pub_mlkem_bytes.len() != HYBRID_MLKEM_PUBLIC_KEY_SIZE
        {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut payload = Vec::with_capacity(HYBRID_PUBLIC_KEY_PAYLOAD_SIZE);
        payload.extend_from_slice(&pub_x_bytes);
        payload.extend_from_slice(&pub_mlkem_bytes);
        let public = HybridPublicKey::from_payload(&payload)?;

        if fields.keyid != public.key_id()
            || public.to_document_string() != expected.to_document_string()
        {
            return Err(CryptoError::DecryptionFailed);
        }

        // Private X25519: must correspond to the public X25519.
        let priv_x_bytes = Zeroizing::new(
            hex::decode(fields.priv_x25519.as_str()).map_err(|_| CryptoError::InvalidKeyLength)?,
        );
        if priv_x_bytes.len() != HYBRID_X25519_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut x25519_private = [0u8; HYBRID_X25519_KEY_SIZE];
        x25519_private.copy_from_slice(&priv_x_bytes);
        let derived_x_public = X25519Public::from(&StaticSecret::from(x25519_private));
        if derived_x_public.as_bytes() != &public.x25519_public {
            return Err(CryptoError::DecryptionFailed);
        }

        // ML-KEM seed: must regenerate the public encapsulation key.
        let seed_bytes = Zeroizing::new(
            hex::decode(fields.priv_mlkem768_seed.as_str())
                .map_err(|_| CryptoError::InvalidKeyLength)?,
        );
        if seed_bytes.len() != HYBRID_MLKEM_SEED_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut mlkem_seed = [0u8; HYBRID_MLKEM_SEED_SIZE];
        mlkem_seed.copy_from_slice(&seed_bytes);
        let dk = DecapsulationKey::<MlKem768>::from_seed(Array::from(mlkem_seed));
        if dk.encapsulation_key().to_bytes().as_slice() != public.mlkem_ek.as_slice() {
            return Err(CryptoError::DecryptionFailed);
        }

        Ok(Self {
            public,
            x25519_private,
            mlkem_seed,
        })
    }

    /// The ML-KEM decapsulation key, expanded from the stored seed.
    ///
    /// Infallible: the seed is a fixed-size array and ML-KEM key expansion from a seed
    /// always succeeds.
    fn decapsulation_key(&self) -> DecapsulationKey<MlKem768> {
        DecapsulationKey::<MlKem768>::from_seed(Array::from(self.mlkem_seed))
    }
}

/// Generate a fresh hybrid `v2` keypair.
pub fn generate_hybrid_keypair() -> Result<(HybridPublicKey, HybridPrivateKey), CryptoError> {
    let x_priv = StaticSecret::random();
    let x_pub = X25519Public::from(&x_priv);

    let (dk, ek) = MlKem768::generate_keypair();
    let ek_bytes = ek.to_bytes();
    let mut seed = dk.to_bytes();

    let mut public = HybridPublicKey {
        x25519_public: *x_pub.as_bytes(),
        mlkem_ek: [0u8; HYBRID_MLKEM_PUBLIC_KEY_SIZE],
    };
    public.mlkem_ek.copy_from_slice(ek_bytes.as_slice());

    let mut private = HybridPrivateKey {
        public: public.clone(),
        x25519_private: x_priv.to_bytes(),
        mlkem_seed: [0u8; HYBRID_MLKEM_SEED_SIZE],
    };
    private.mlkem_seed.copy_from_slice(seed.as_slice());
    // Wipe the local copy of the seed now that it lives in the private key struct.
    seed.iter_mut().for_each(|b| *b = 0);

    Ok((public, private))
}

/// Encrypts individual values to a hybrid `v2` recipient.
///
/// The parsed recipient keys are cached so encrypting a document with many values does
/// not re-parse the 1184-byte ML-KEM encapsulation key per value.
pub struct HybridEncrypter {
    peer: HybridPublicKey,
    peer_x25519: X25519Public,
    peer_mlkem_ek: EncapsulationKey<MlKem768>,
}

impl HybridEncrypter {
    pub fn new(peer: HybridPublicKey) -> Result<Self, CryptoError> {
        // Parse (and validate) the peer key material once, up front.
        let peer_mlkem_ek = peer.encapsulation_key()?;
        let peer_x25519 = peer.x25519();
        Ok(Self {
            peer,
            peer_x25519,
            peer_mlkem_ek,
        })
    }

    /// Encrypt a value. If the value is already boxed, it is returned unchanged (ejson's
    /// no-reencrypt behavior).
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if is_boxed_message(message) {
            return Ok(message.to_vec());
        }

        // Fresh ephemeral X25519 key per value.
        let eph = EphemeralSecret::random();
        let eph_public = X25519Public::from(&eph);
        let x_shared = eph.diffie_hellman(&self.peer_x25519);

        // Fresh ML-KEM encapsulation per value.
        let (mlkem_ct, mlkem_shared) = self.peer_mlkem_ek.encapsulate();

        // The transcript is both the HKDF info and the AEAD AAD; build it once.
        let aad = transcript(&self.peer, eph_public.as_bytes(), mlkem_ct.as_slice());
        let key = derive_key(&aad, x_shared.as_bytes(), mlkem_shared.as_slice());

        let aead = XChaCha20Poly1305::new((&*key).into());
        let nonce: XNonce = Array::generate();
        let box_data = aead
            .encrypt(
                &nonce,
                Payload {
                    msg: message,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut mlkem_ct_arr = [0u8; HYBRID_MLKEM_CIPHERTEXT_SIZE];
        mlkem_ct_arr.copy_from_slice(mlkem_ct.as_slice());
        let mut nonce_arr = [0u8; NONCE_SIZE];
        nonce_arr.copy_from_slice(nonce.as_slice());

        Ok(HybridBoxedMessage {
            ephemeral_x25519_public: *eph_public.as_bytes(),
            mlkem_ciphertext: mlkem_ct_arr,
            nonce: nonce_arr,
            box_data,
        }
        .dump())
    }
}

/// Decrypts hybrid `v2` boxed messages.
///
/// The recipient's X25519 secret and ML-KEM decapsulation key are derived once at
/// construction (the raw private key material is dropped/zeroized afterwards) so
/// decrypting a document with many values does not re-expand the ML-KEM key per value.
pub struct HybridDecrypter {
    public: HybridPublicKey,
    x25519_private: StaticSecret,
    mlkem_dk: DecapsulationKey<MlKem768>,
}

impl HybridDecrypter {
    pub fn new(private: HybridPrivateKey) -> Self {
        let x25519_private = StaticSecret::from(private.x25519_private);
        let mlkem_dk = private.decapsulation_key();
        Self {
            public: private.public.clone(),
            x25519_private,
            mlkem_dk,
        }
    }

    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let bm =
            HybridBoxedMessage::load(message).map_err(|_| CryptoError::InvalidMessageFormat)?;

        let eph_public = X25519Public::from(bm.ephemeral_x25519_public);
        let x_shared = self.x25519_private.diffie_hellman(&eph_public);

        let ct_arr: Ciphertext<MlKem768> =
            Array::try_from(&bm.mlkem_ciphertext[..]).map_err(|_| CryptoError::DecryptionFailed)?;
        let mlkem_shared = self.mlkem_dk.decapsulate(&ct_arr);

        // The transcript is both the HKDF info and the AEAD AAD; build it once.
        let aad = transcript(
            &self.public,
            &bm.ephemeral_x25519_public,
            &bm.mlkem_ciphertext,
        );
        let key = derive_key(&aad, x_shared.as_bytes(), mlkem_shared.as_slice());

        let aead = XChaCha20Poly1305::new((&*key).into());
        let nonce = XNonce::from(bm.nonce);
        aead.decrypt(
            &nonce,
            Payload {
                msg: &bm.box_data,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// The parsed `v2` wire message.
pub struct HybridBoxedMessage {
    pub ephemeral_x25519_public: [u8; HYBRID_X25519_KEY_SIZE],
    pub mlkem_ciphertext: [u8; HYBRID_MLKEM_CIPHERTEXT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub box_data: Vec<u8>,
}

impl HybridBoxedMessage {
    /// Serialize to the `v2` wire format.
    pub fn dump(&self) -> Vec<u8> {
        format!(
            "EJ[{}:{}:{}:{}:{}]",
            SCHEMA_VERSION_HYBRID,
            BASE64.encode(self.ephemeral_x25519_public),
            BASE64.encode(self.mlkem_ciphertext),
            BASE64.encode(self.nonce),
            BASE64.encode(&self.box_data),
        )
        .into_bytes()
    }

    /// Parse from the `v2` wire format.
    pub fn load(data: &[u8]) -> Result<Self, BoxedMessageError> {
        let (version, fields) = parse_boxed_envelope(data)?;
        if version != SCHEMA_VERSION_HYBRID || fields.len() != 4 {
            return Err(BoxedMessageError::InvalidFormat);
        }

        let ephemeral = BASE64
            .decode(fields[0])
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        let ephemeral_x25519_public: [u8; HYBRID_X25519_KEY_SIZE] = ephemeral
            .try_into()
            .map_err(|_| BoxedMessageError::InvalidPublicKey)?;

        let ct = BASE64
            .decode(fields[1])
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        let mlkem_ciphertext: [u8; HYBRID_MLKEM_CIPHERTEXT_SIZE] = ct
            .try_into()
            .map_err(|_| BoxedMessageError::InvalidFormat)?;

        let nonce_bytes = BASE64
            .decode(fields[2])
            .map_err(|_| BoxedMessageError::InvalidBase64)?;
        let nonce: [u8; NONCE_SIZE] = nonce_bytes
            .try_into()
            .map_err(|_| BoxedMessageError::InvalidNonce)?;

        let box_data = BASE64
            .decode(fields[3])
            .map_err(|_| BoxedMessageError::InvalidBase64)?;

        Ok(Self {
            ephemeral_x25519_public,
            mlkem_ciphertext,
            nonce,
            box_data,
        })
    }
}

/// Build the transcript bound as HKDF info and AEAD AAD.
fn transcript(
    recipient: &HybridPublicKey,
    ephemeral_x25519_public: &[u8],
    mlkem_ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HYBRID_AAD_DOMAIN.len()
            + 1
            + ephemeral_x25519_public.len()
            + recipient.x25519_public.len()
            + recipient.mlkem_ek.len()
            + mlkem_ciphertext.len(),
    );
    out.extend_from_slice(HYBRID_AAD_DOMAIN);
    out.push(0);
    out.extend_from_slice(ephemeral_x25519_public);
    out.extend_from_slice(&recipient.x25519_public);
    out.extend_from_slice(&recipient.mlkem_ek);
    out.extend_from_slice(mlkem_ciphertext);
    out
}

/// Derive the 32-byte AEAD key: `HKDF-SHA256(salt, ikm = x25519 ‖ mlkem, info = transcript)`.
///
/// `info` is the transcript (also used as the AEAD AAD); the caller builds it once and
/// passes it here to avoid recomputing it.
fn derive_key(info: &[u8], x25519_shared: &[u8], mlkem_shared: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(x25519_shared.len() + mlkem_shared.len()));
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(mlkem_shared);

    let hk = Hkdf::<Sha256>::new(Some(HYBRID_KDF_SALT), &ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    // expand only fails for absurd output lengths; 32 bytes always succeeds.
    hk.expand(info, key.as_mut_slice())
        .expect("HKDF expand of 32 bytes is infallible");
    key
}

/// Fields parsed from a hybrid private key file.
///
/// The private components are held in `Zeroizing` buffers so their heap allocations are
/// wiped when the parsed fields are dropped.
struct KeyFileFields {
    keyid: String,
    pub_x25519: String,
    pub_mlkem768: String,
    priv_x25519: Zeroizing<String>,
    priv_mlkem768_seed: Zeroizing<String>,
}

/// Parse `key: value` lines from a hybrid private key file (after the header line).
fn parse_key_file_fields(data: &str) -> Result<KeyFileFields, CryptoError> {
    let mut lines = data.trim().lines();
    match lines.next() {
        Some(header) if header.trim() == HYBRID_KEY_FILE_HEADER => {}
        _ => return Err(CryptoError::InvalidKeyLength),
    }

    let mut keyid = String::new();
    let mut pub_x25519 = String::new();
    let mut pub_mlkem768 = String::new();
    let mut priv_x25519 = Zeroizing::new(String::new());
    let mut priv_mlkem768_seed = Zeroizing::new(String::new());

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(CryptoError::InvalidKeyLength)?;
        let value = value.trim();
        // Private values are assigned as whole `Zeroizing`s so a duplicated field wipes
        // the value it replaces. Unknown fields are ignored for forward compatibility.
        match name.trim() {
            "keyid" => keyid = value.to_string(),
            "pub-x25519" => pub_x25519 = value.to_string(),
            "pub-mlkem768" => pub_mlkem768 = value.to_string(),
            "priv-x25519" => priv_x25519 = Zeroizing::new(value.to_string()),
            "priv-mlkem768-seed" => priv_mlkem768_seed = Zeroizing::new(value.to_string()),
            _ => {}
        }
    }

    if keyid.is_empty()
        || pub_x25519.is_empty()
        || pub_mlkem768.is_empty()
        || priv_x25519.is_empty()
        || priv_mlkem768_seed.is_empty()
    {
        return Err(CryptoError::InvalidKeyLength);
    }

    Ok(KeyFileFields {
        keyid,
        pub_x25519,
        pub_mlkem768,
        priv_x25519,
        priv_mlkem768_seed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (HybridPublicKey, HybridPrivateKey) {
        generate_hybrid_keypair().unwrap()
    }

    #[test]
    fn test_keypair_generation_and_parsing() {
        let (pubk, privk) = keypair();
        assert!(pubk.to_document_string().starts_with("v2:"));
        assert_eq!(pubk.key_id().len(), 32);

        let parsed_pub =
            HybridPublicKey::parse_document_string(&pubk.to_document_string()).unwrap();
        assert_eq!(parsed_pub.to_document_string(), pubk.to_document_string());

        let parsed_priv =
            HybridPrivateKey::parse_for_public(&parsed_pub, &privk.to_file_string()).unwrap();

        let enc = HybridEncrypter::new(parsed_pub).unwrap();
        let dec = HybridDecrypter::new(parsed_priv);
        let ct = enc.encrypt(b"secret").unwrap();
        assert_eq!(dec.decrypt(&ct).unwrap(), b"secret");
    }

    #[test]
    fn test_roundtrip_and_no_reencrypt() {
        let (pubk, privk) = keypair();
        let enc = HybridEncrypter::new(pubk).unwrap();
        let dec = HybridDecrypter::new(privk);

        let messages: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"This is a test of the post-quantum emergency broadcast system.".to_vec(),
            b"0123456789abcdef".repeat(640),
        ];
        for message in messages {
            let ct = enc.encrypt(&message).unwrap();
            assert!(ct.starts_with(b"EJ[2:"), "ciphertext should be v2");
            assert!(is_boxed_message(&ct));

            // Re-encrypting an already-boxed message returns it unchanged.
            let ct2 = enc.encrypt(&ct).unwrap();
            assert_eq!(ct2, ct);

            assert_eq!(dec.decrypt(&ct).unwrap(), message);
        }
    }

    #[test]
    fn test_rejects_wrong_key() {
        let (pubk, privk) = keypair();
        let (_wrong_pub, wrong_priv) = keypair();
        let enc = HybridEncrypter::new(pubk).unwrap();
        let wrong_dec = HybridDecrypter::new(wrong_priv);
        let _ = privk;

        let ct = enc.encrypt(b"swordfish").unwrap();
        assert!(wrong_dec.decrypt(&ct).is_err());
    }

    #[test]
    fn test_rejects_tampering() {
        let (pubk, privk) = keypair();
        let enc = HybridEncrypter::new(pubk).unwrap();
        let dec = HybridDecrypter::new(privk);
        let ct = enc.encrypt(b"swordfish").unwrap();

        let mutators: Vec<fn(&mut HybridBoxedMessage)> = vec![
            |bm| bm.ephemeral_x25519_public[0] ^= 0x80,
            |bm| bm.mlkem_ciphertext[0] ^= 0x80,
            |bm| bm.nonce[0] ^= 0x80,
            |bm| bm.box_data[0] ^= 0x80,
        ];
        for mutate in mutators {
            let mut bm = HybridBoxedMessage::load(&ct).unwrap();
            mutate(&mut bm);
            assert!(dec.decrypt(&bm.dump()).is_err());
        }
    }

    #[test]
    fn test_rejects_mlkem_ciphertext_splice() {
        let (pubk, privk) = keypair();
        let enc = HybridEncrypter::new(pubk).unwrap();
        let dec = HybridDecrypter::new(privk);

        let ct1 = enc.encrypt(b"first secret").unwrap();
        let ct2 = enc.encrypt(b"second secret").unwrap();

        let mut bm1 = HybridBoxedMessage::load(&ct1).unwrap();
        let bm2 = HybridBoxedMessage::load(&ct2).unwrap();
        bm1.mlkem_ciphertext = bm2.mlkem_ciphertext;

        assert!(dec.decrypt(&bm1.dump()).is_err());
    }

    #[test]
    fn test_private_key_rejects_mismatched_public_key() {
        let (pubk, _privk) = keypair();
        let (_other_pub, other_priv) = keypair();
        assert!(HybridPrivateKey::parse_for_public(&pubk, &other_priv.to_file_string()).is_err());
    }

    #[test]
    fn test_public_key_rejects_invalid_inputs() {
        assert!(HybridPublicKey::parse_document_string("v2:not base64").is_err());
        assert!(HybridPublicKey::parse_document_string(&format!("v2:{}", "A".repeat(16))).is_err());
        assert!(HybridPublicKey::parse_document_string("deadbeef").is_err());
    }
}
