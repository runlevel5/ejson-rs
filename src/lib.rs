// No `unsafe` in the library. Tests may opt in locally (environment variable
// mutation is `unsafe` in edition 2024), so they get `deny` instead of `forbid`.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

//! EJSON - Encrypted JSON secrets management.
//!
//! This crate provides utilities for managing encrypted secrets in source control
//! using public-key cryptography: NaCl box (`v1`) or hybrid X25519 + ML-KEM-768
//! (`v2`).
//!
//! Supports JSON (.ejson, .json), TOML (.etoml, .toml), and YAML (.eyaml, .eyml, .yaml, .yml) file formats.
//!
//! # Security Features
//!
//! - Private key material is zeroized from memory when dropped (best effort;
//!   see the individual types)
//! - Files are locked while being read or encrypted, and encrypted files are
//!   replaced atomically
//! - Only regular files are read: devices, FIFOs and sockets are rejected,
//!   including through symlinks
//! - Private keys are looked up by a filename derived from the public key and
//!   must resolve to a file inside the keydir
//! - Input files are limited to [`MAX_FILE_SIZE`] and keys to
//!   [`MAX_KEY_FILE_SIZE`], enforced while reading
//!
//! # Warnings
//!
//! The library never writes to stdout or stderr. Non-fatal problems, such as
//! a private key file that other users can read, are reported through the
//! [`log`] crate at `warn` level; install a logger to see them. The `ejson`
//! command-line tool prints them to stderr.
//!
//! Ciphertext authentication (Poly1305) is verified by the RustCrypto
//! implementations, which compare tags in constant time. ejson itself does no
//! other secret-dependent comparisons.

// Compile the "2.0" examples in the upgrade guide as doctests, so the guide
// can't drift from the API.
#[cfg(doctest)]
#[doc = include_str!("../UPGRADING.md")]
struct UpgradingGuide;

/// Declares implementation modules: private, unless the `unstable-internals`
/// feature is on, which makes them `pub` for the fuzz targets.
macro_rules! internal_modules {
    ($($name:ident),* $(,)?) => {
        $(
            #[cfg(feature = "unstable-internals")]
            pub mod $name;
            #[cfg(not(feature = "unstable-internals"))]
            mod $name;
        )*
    };
}

/// The implementation modules are not part of the public API.
///
/// ```compile_fail
/// use ejson::crypto::Keypair;
/// ```
///
/// ```compile_fail
/// use ejson::keys::PrivateKey;
/// ```
///
/// ```compile_fail
/// use ejson::json::Walker;
/// ```
#[cfg(all(doctest, not(feature = "unstable-internals")))]
struct InternalModulesArePrivate;

/// Even with `unstable-internals`, private key material can't be read out
/// of the key types.
///
/// ```compile_fail
/// let keypair = ejson::crypto::Keypair::generate();
/// let _key = keypair.private; // private field
/// ```
///
/// ```compile_fail
/// let (_public, private) = ejson::hybrid::generate_hybrid_keypair();
/// let _seed = private.mlkem_seed; // private field
/// ```
///
/// ```compile_fail
/// # fn demo(key: ejson::keys::PrivateKey) {
/// let _inner = key.0; // private field
/// # }
/// ```
///
/// The same code without the private access does compile:
///
/// ```
/// let keypair = ejson::crypto::Keypair::generate();
/// let _hex = keypair.private_hex();
/// let (_public, private) = ejson::hybrid::generate_hybrid_keypair();
/// let _file = private.to_file_string();
/// # fn demo(key: ejson::keys::PrivateKey) {
/// let _scheme = key.scheme();
/// # }
/// ```
#[cfg(all(doctest, feature = "unstable-internals"))]
struct SecretFieldsArePrivate;

/// The public enums that may gain variants, and `GeneratedKeypair`, are
/// `#[non_exhaustive]`: code outside the crate must allow for additions.
///
/// A `match` without a wildcard arm does not compile:
///
/// ```compile_fail
/// fn name(scheme: ejson::Scheme) -> &'static str {
///     match scheme {
///         ejson::Scheme::V1 => "v1",
///         ejson::Scheme::V2 => "v2",
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn extension(format: ejson::FileFormat) -> &'static str {
///     match format {
///         ejson::FileFormat::Json => "ejson",
///         ejson::FileFormat::Yaml => "eyaml",
///         ejson::FileFormat::Toml => "etoml",
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn is_fish(shell: ejson::env::Shell) -> bool {
///     match shell {
///         ejson::env::Shell::Posix => false,
///         ejson::env::Shell::Fish => true,
///     }
/// }
/// ```
///
/// ```compile_fail
/// fn uses_keydir(key: ejson::KeySource<'_>) -> bool {
///     match key {
///         ejson::KeySource::Keydir(_) => true,
///         ejson::KeySource::PrivateKey(_) => false,
///     }
/// }
/// ```
///
/// Nor does building a `GeneratedKeypair` by hand:
///
/// ```compile_fail
/// let generated = ejson::generate_keypair(ejson::Scheme::V1);
/// let _copy = ejson::GeneratedKeypair {
///     scheme: generated.scheme,
///     public_key: generated.public_key,
///     private_key: generated.private_key,
///     key_id: generated.key_id,
/// };
/// ```
///
/// With a wildcard arm, and reading fields instead of building the struct,
/// the same code compiles:
///
/// ```
/// fn name(scheme: ejson::Scheme) -> &'static str {
///     match scheme {
///         ejson::Scheme::V1 => "v1",
///         ejson::Scheme::V2 => "v2",
///         _ => "newer",
///     }
/// }
/// fn extension(format: ejson::FileFormat) -> &'static str {
///     match format {
///         ejson::FileFormat::Json => "ejson",
///         ejson::FileFormat::Yaml => "eyaml",
///         ejson::FileFormat::Toml => "etoml",
///         _ => "other",
///     }
/// }
/// fn is_fish(shell: ejson::env::Shell) -> bool {
///     match shell {
///         ejson::env::Shell::Posix => false,
///         ejson::env::Shell::Fish => true,
///         _ => false,
///     }
/// }
/// fn uses_keydir(key: ejson::KeySource<'_>) -> bool {
///     match key {
///         ejson::KeySource::Keydir(_) => true,
///         ejson::KeySource::PrivateKey(_) => false,
///         _ => false,
///     }
/// }
///
/// let generated = ejson::generate_keypair(ejson::Scheme::V1);
/// let ejson::GeneratedKeypair { scheme, public_key, .. } = generated;
/// assert_eq!(name(scheme), "v1");
/// assert_eq!(public_key.len(), 64);
/// assert_eq!(extension(ejson::FileFormat::Toml), "etoml");
/// assert!(is_fish(ejson::env::Shell::Fish));
/// assert!(uses_keydir(ejson::KeySource::keydir("/opt/ejson/keys")));
/// ```
#[cfg(doctest)]
struct PublicTypesCanGrow;

pub mod env;

internal_modules!(
    boxed_message,
    crypto,
    format,
    handler,
    hybrid,
    json,
    keys,
    toml,
    typed,
    yaml,
);

use std::fs::{self, File};
use std::io::{Read, Write};
use std::mem::DropGuard;
use std::path::Path;

use boxed_message::ValueKind;

pub use crypto::CryptoError;
pub use format::{FileFormat, FileFormatError};
pub use handler::{FormatError, PUBLIC_KEY_FIELD};
pub use keys::{GeneratedKeypair, Scheme, generate_keypair};
pub use typed::{DecryptedContent, DecryptedValue};

use thiserror::Error;
use zeroize::Zeroizing;

/// Where the private key for a document comes from.
///
/// ```no_run
/// use ejson::{KeySource, UnderscorePrefix};
///
/// // Look the key up in a keydir, in the file named after the document's public key:
/// let plaintext = ejson::decrypt_file("secrets.ejson", KeySource::keydir("/opt/ejson/keys"), UnderscorePrefix::Keep)?;
///
/// // Or supply the private key directly (e.g. fetched from a secrets manager):
/// let private_key = std::env::var("EJSON_PRIVATE_KEY").unwrap();
/// let plaintext = ejson::decrypt_file("secrets.ejson", KeySource::PrivateKey(&private_key), UnderscorePrefix::Keep)?;
/// # Ok::<(), ejson::EjsonError>(())
/// ```
///
/// More sources may be added in a minor release, so a `match` on a
/// `KeySource` needs a wildcard arm.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum KeySource<'a> {
    /// Read the key from this directory, from the file named after the
    /// document's public key (its key ID).
    Keydir(&'a Path),
    /// Use this private key: 64 hex characters for `v1`, or the contents of an
    /// `ejson-key v2` file for `v2`.
    PrivateKey(&'a str),
}

impl<'a> KeySource<'a> {
    /// A [`KeySource::Keydir`] from anything path-like.
    pub fn keydir<P: AsRef<Path> + ?Sized>(keydir: &'a P) -> Self {
        Self::Keydir(keydir.as_ref())
    }
}

// Never prints a private key.
impl std::fmt::Debug for KeySource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keydir(keydir) => f.debug_tuple("Keydir").field(keydir).finish(),
            Self::PrivateKey(_) => f.debug_tuple("PrivateKey").field(&"[REDACTED]").finish(),
        }
    }
}

/// Whether key names keep their leading underscore in decrypted output.
///
/// In a secrets file, a key that starts with `_` (such as `_comment`) is left
/// unencrypted. `Trim` removes that first underscore from every key name in
/// the output, except `_public_key`: `_comment` becomes `comment`, `__x`
/// becomes `_x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnderscorePrefix {
    /// Leave key names as written.
    #[default]
    Keep,
    /// Remove the first leading underscore from key names.
    Trim,
}

/// Maximum file size for encryption/decryption operations (10 MB).
/// This prevents denial of service through memory exhaustion.
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum size of a private key, whether read from the keydir or stdin (64 KiB).
/// A `v2` key file is about 2 KB; anything far larger is not a key.
pub const MAX_KEY_FILE_SIZE: u64 = 64 * 1024;

/// Errors that can occur during ejson operations.
///
/// The wrapping variants are transparent: their message is the inner error's
/// message, with no extra prefix.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum EjsonError {
    /// A key is malformed or doesn't match, or a value couldn't be encrypted
    /// or decrypted outside of walking a document (see [`FormatError::ActionFailed`]).
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// The document is malformed, lacks a public key, or one of its values
    /// couldn't be encrypted or decrypted.
    #[error(transparent)]
    Format(#[from] FormatError),

    /// The file extension doesn't name a supported format.
    #[error(transparent)]
    FileFormat(#[from] FileFormatError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The private key file couldn't be read.
    ///
    /// The message names the key by the first characters of its ID, never by
    /// the path of the keydir.
    #[error("couldn't read key file for public key {}...: {reason}", key_id_prefix(.key_id))]
    KeyFile {
        /// The key ID, which is the file's name in the keydir: the hex public
        /// key for `v1`, a 32-character derived ID for `v2`.
        key_id: String,
        reason: KeyFileReason,
    },

    /// The decrypted output couldn't be written (see [`decrypt_file_to`]).
    #[error("couldn't write output file: {0}")]
    Output(#[source] std::io::Error),

    #[error("file too large (max {} bytes)", MAX_FILE_SIZE)]
    FileTooLarge,

    #[error("invalid path: {0}")]
    InvalidPath(InvalidPathReason),
}

/// The first eight characters of a key ID, enough to recognise the key.
fn key_id_prefix(key_id: &str) -> &str {
    key_id
        .char_indices()
        .nth(8)
        .map_or(key_id, |(end, _)| &key_id[..end])
}

/// Why a private key file couldn't be read. See [`EjsonError::KeyFile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyFileReason {
    /// There is no file for this key in the keydir (or no such keydir).
    NotFound,
    /// The file is not UTF-8 text, so it can't be a key.
    NotUtf8,
    /// The file exists but couldn't be read. Only the kind of failure is
    /// kept: the operating system's message can include the path.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for KeyFileReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found in keydir"),
            Self::NotUtf8 => f.write_str("not valid UTF-8 text"),
            Self::Io(kind) => write!(f, "{kind}"),
        }
    }
}

/// Why a path can't be used. See [`EjsonError::InvalidPath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum InvalidPathReason {
    #[error("path contains null bytes")]
    NullByte,

    /// The path is a directory, device, FIFO or socket (possibly through a
    /// symlink).
    #[error("path is not a regular file")]
    NotRegularFile,

    /// The key file resolves to somewhere outside the keydir.
    #[error("key path escapes keydir")]
    EscapesKeydir,

    #[error("path has no file name")]
    NoFileName,
}

/// Reject paths that can't be a usable input file: paths containing NUL
/// bytes, and (on Unix) devices, FIFOs and sockets, following symlinks.
///
/// This is an early check, before `open` (opening a FIFO blocks);
/// [`open_regular_file`] re-checks the opened handle. It does not restrict
/// *where* a path points: input paths come from the user.
fn validate_path(path: &Path) -> Result<(), EjsonError> {
    // Check for obviously dangerous patterns
    let path_str = path.to_string_lossy();

    // Reject paths with null bytes
    if path_str.contains('\0') {
        return Err(EjsonError::InvalidPath(InvalidPathReason::NullByte));
    }

    // Reject anything that isn't a regular file. This follows symlinks, so a
    // link to a device is caught too, and runs before `open` because opening a
    // FIFO blocks. `open_regular_file` re-checks the opened handle.
    if let Ok(metadata) = fs::metadata(path) {
        // Checked here as well as after opening: on Windows a directory can't
        // be opened as a file, which would otherwise surface as a confusing
        // "permission denied".
        let is_special = metadata.is_dir() || is_device_fifo_or_socket(&metadata);

        if is_special {
            return Err(EjsonError::InvalidPath(InvalidPathReason::NotRegularFile));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn is_device_fifo_or_socket(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    let file_type = metadata.file_type();
    file_type.is_block_device()
        || file_type.is_char_device()
        || file_type.is_fifo()
        || file_type.is_socket()
}

#[cfg(not(unix))]
fn is_device_fifo_or_socket(_metadata: &fs::Metadata) -> bool {
    false
}

/// Open `path` and check that the opened handle is a regular file within the
/// size limit.
///
/// The check is made on the handle, not the path, so the path can't be swapped
/// for something else (e.g. a symlink to `/dev/zero`) between check and use.
fn open_regular_file(path: &Path, max_size: u64) -> Result<(File, fs::Metadata), EjsonError> {
    validate_path(path)?;

    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(EjsonError::InvalidPath(InvalidPathReason::NotRegularFile));
    }
    if metadata.len() > max_size {
        return Err(EjsonError::FileTooLarge);
    }
    Ok((file, metadata))
}

/// Read to the end of `reader`, failing with `FileTooLarge` once more than
/// `max_size` bytes have been read instead of buffering without bound.
fn read_to_end_limited<R: Read>(
    reader: R,
    max_size: u64,
    capacity: u64,
) -> Result<Vec<u8>, EjsonError> {
    // Only a capacity hint: fall back to growing on demand if it doesn't fit
    // in `usize`.
    let capacity = usize::try_from(capacity.min(max_size)).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    reader.take(max_size + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max_size {
        return Err(EjsonError::FileTooLarge);
    }
    Ok(data)
}

/// Read a file with size limit and locking.
fn read_file_with_lock(path: &Path) -> Result<Vec<u8>, EjsonError> {
    let (file, metadata) = open_regular_file(path, MAX_FILE_SIZE)?;

    // Acquire shared lock for reading
    file.lock_shared()?;

    // The size limit is enforced while reading too: the file may have grown
    // since `metadata` was taken.
    let reader = std::io::BufReader::new(&file);
    let data = read_to_end_limited(reader, MAX_FILE_SIZE, metadata.len())?;

    // Lock is automatically released when file is dropped
    Ok(data)
}

/// Encrypt a document read from `input` and write the result to `output`.
///
/// The document must be in `format` and have a top-level `_public_key`. Returns
/// the number of bytes written. To encrypt a file, detecting the format from
/// its extension, use [`encrypt_file_in_place`].
pub fn encrypt<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    format: FileFormat,
) -> Result<usize, EjsonError> {
    // The input is plaintext: wipe it once it has been encrypted.
    let data = Zeroizing::new(read_to_end_limited(&mut input, MAX_FILE_SIZE, 0)?);

    encrypt_data(&data, &mut output, format, None)
}

fn encrypt_data<W: Write>(
    data: &[u8],
    output: &mut W,
    format: FileFormat,
    source: Option<&Path>,
) -> Result<usize, EjsonError> {
    // Get the appropriate handler for this format
    let handler = format.handler();

    // Preprocess the data (e.g., collapse multiline strings for JSON). This is
    // another copy of the plaintext, so it is wiped when dropped.
    let data = Zeroizing::new(handler.preprocess(data)?);

    // Extract the public key and select the encryption scheme from it.
    let pubkey_string = handler.extract_public_key_string(&data)?;
    let pubkey = keys::PublicKey::parse(&pubkey_string)?;
    let encrypter = keys::AnyEncrypter::for_public_key(&pubkey)?;

    // Encrypt plaintext values and leave already-encrypted ones alone. A value
    // that looks encrypted but isn't well-formed is refused: encrypting it
    // again would bury a damaged secret (or one from a newer ejson) inside a
    // valid-looking one.
    let encrypt_fn = |value: &[u8]| match boxed_message::classify_value(value) {
        ValueKind::Damaged => Err(CryptoError::DamagedMessage),
        ValueKind::Plaintext | ValueKind::Boxed => encrypter.encrypt(value),
    };

    // Walk and encrypt
    let new_data = handler.walk(&data, &encrypt_fn)?;

    if format == FileFormat::Yaml {
        warn_unencrypted_yaml_scalars(&new_data, source);
    }

    output.write_all(&new_data)?;
    Ok(new_data.len())
}

/// Warn (through `log`) about YAML values that stayed in plaintext only
/// because YAML parsed them as numbers or booleans, such as an unquoted
/// `pin: 123456`. `source` is the file being encrypted, if there is one.
fn warn_unencrypted_yaml_scalars(encrypted: &[u8], source: Option<&Path>) {
    let Ok(paths) = yaml::plaintext_scalar_paths(encrypted) else {
        return;
    };
    if paths.is_empty() {
        return;
    }
    let file = source.map_or_else(String::new, |path| format!("{}: ", path.display()));
    log::warn!(
        "{file}these values are numbers or booleans in YAML, so they were left \
         unencrypted: {}. Quote them (e.g. pin: \"123456\") to have them encrypted",
        paths.join(", ")
    );
}

/// Encrypt a file in place with file locking.
///
/// The file format is auto-detected based on file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
/// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
///
/// Security: Uses exclusive file locking to prevent race conditions, and
/// replaces the file atomically (write to a temporary file, then rename), so a
/// crash or full disk can never leave it truncated or half-written.
pub fn encrypt_file_in_place<P: AsRef<Path>>(file_path: P) -> Result<usize, EjsonError> {
    let file_path = file_path.as_ref();
    let format = FileFormat::from_path(file_path)?;

    // Replace the symlink's target, not the symlink itself.
    let file_path = &fs::canonicalize(file_path)?;

    // The file contents are (at least partly) plaintext: wipe our copy once
    // it has been encrypted.
    let (file, metadata, data) = lock_and_read_for_update(file_path)?;
    let data = Zeroizing::new(data);

    // Encrypt
    let mut output = Vec::new();
    let size = encrypt_data(&data, &mut output, format, Some(file_path))?;

    // Nothing new to encrypt: leave the file untouched.
    if output != *data {
        replace_file_atomically(file_path, &output, &metadata)?;
    }

    // Lock is released when file is dropped
    drop(file);
    Ok(size)
}

/// Open `path`, take an exclusive lock and read it.
///
/// Because [`replace_file_atomically`] swaps in a new inode, a process that
/// was waiting for the lock may end up holding a lock on the old, replaced
/// file. In that case the path is opened again, so every writer sees the
/// latest contents.
fn lock_and_read_for_update(path: &Path) -> Result<(File, fs::Metadata, Vec<u8>), EjsonError> {
    const MAX_ATTEMPTS: usize = 8;

    for _ in 0..MAX_ATTEMPTS {
        let (file, _) = open_regular_file(path, MAX_FILE_SIZE)?;
        file.lock()?;

        // The file we locked may have been replaced while we waited.
        if !is_same_file(&file, path)? {
            continue;
        }

        // Re-read metadata under the lock; size or mode may have changed.
        let metadata = file.metadata()?;

        let reader = std::io::BufReader::new(&file);
        let data = read_to_end_limited(reader, MAX_FILE_SIZE, metadata.len())?;
        return Ok((file, metadata, data));
    }

    Err(EjsonError::Io(std::io::Error::other(
        "file kept being replaced while waiting for its lock",
    )))
}

/// Whether the open `file` is still the file that `path` names.
#[cfg(unix)]
fn is_same_file(file: &File, path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let (open, named) = (file.metadata()?, fs::metadata(path)?);
    Ok(open.dev() == named.dev() && open.ino() == named.ino())
}

/// Whether the open `file` is still the file that `path` names.
///
/// std has no stable way to read a file's identity on Windows, so this uses
/// `same-file` (volume serial number plus file index).
#[cfg(windows)]
fn is_same_file(file: &File, path: &Path) -> std::io::Result<bool> {
    let open = same_file::Handle::from_file(file.try_clone()?)?;
    Ok(open == same_file::Handle::from_path(path)?)
}

/// No way to tell on this platform: assume the file was not replaced.
#[cfg(not(any(unix, windows)))]
fn is_same_file(_file: &File, _path: &Path) -> std::io::Result<bool> {
    Ok(true)
}

/// Replace `path` with `data` by writing a temporary file in the same
/// directory and renaming it over `path`.
///
/// The temporary file gets `original`'s permissions (and, on Unix, its owner
/// and group where allowed) before the rename, so the replacement is never
/// more exposed than the file it replaces.
fn replace_file_atomically(
    path: &Path,
    data: &[u8],
    original: &fs::Metadata,
) -> Result<(), EjsonError> {
    write_via_temp_file(path, data, |temp| {
        temp.set_permissions(original.permissions())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Only root can give a file away; otherwise keep our own ownership.
            let _ = std::os::unix::fs::fchown(temp, Some(original.uid()), Some(original.gid()));
        }
        Ok(())
    })
}

/// Write `data` to `path` so that it is readable only by its owner, creating
/// or atomically replacing the file.
///
/// The data goes to a new owner-only (`0600` on Unix) temporary file in the
/// same directory, which is synced and then renamed over `path`, so `path` is
/// never left half-written and never briefly has looser permissions. If
/// anything fails, the temporary file is removed so no partial copy of `data`
/// is left on disk.
///
/// On non-Unix platforms the file gets the directory's default permissions.
fn write_private_file_atomically(path: &Path, data: &[u8]) -> Result<(), EjsonError> {
    write_via_temp_file(path, data, |_| Ok(()))
}

/// Write `data` to an owner-only temporary file next to `path`, call
/// `prepare` on it, sync it and rename it over `path`. The temporary file is
/// removed on any failure.
fn write_via_temp_file(
    path: &Path,
    data: &[u8],
    prepare: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<(), EjsonError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or(EjsonError::InvalidPath(InvalidPathReason::NoFileName))?
        .to_string_lossy();

    let (temp_path, temp) = create_temp_file(parent, &name)?;

    // Remove the temporary file unless the rename succeeds, on an error and
    // on a panic alike.
    let temp_path = DropGuard::new(temp_path, |temp_path| {
        let _ = fs::remove_file(temp_path);
    });
    // Declared after the guard so that the file is closed before the guard
    // removes it: Windows may refuse to delete a file that is still open.
    let mut temp = temp;

    temp.write_all(data)?;
    prepare(&temp)?;
    temp.sync_all()?;
    drop(temp);
    fs::rename(&*temp_path, path)?;
    DropGuard::dismiss(temp_path);

    // Persist the rename itself. Best effort: not every platform can open or
    // sync a directory.
    #[cfg(unix)]
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Create a new, owner-only temporary file next to the file being written.
fn create_temp_file(dir: &Path, name: &str) -> Result<(std::path::PathBuf, File), EjsonError> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    loop {
        let unique = format!(
            ".{name}.ejson-{}-{}.tmp",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let temp_path = dir.join(unique);

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Decrypt a document read from `input` and write the plaintext to `output`.
///
/// The document must be in `format`. `key` says where the private key comes
/// from: a keydir or the key itself (see [`KeySource`]). To decrypt a file,
/// detecting the format from its extension, use [`decrypt_file`].
pub fn decrypt<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    key: KeySource<'_>,
    format: FileFormat,
) -> Result<(), EjsonError> {
    let data = read_to_end_limited(&mut input, MAX_FILE_SIZE, 0)?;

    decrypt_data(&data, &mut output, key, format)
}

fn decrypt_data<W: Write>(
    data: &[u8],
    output: &mut W,
    key: KeySource<'_>,
    format: FileFormat,
) -> Result<(), EjsonError> {
    // Get the appropriate handler for this format
    let handler = format.handler();

    // Extract public key using the handler and select the scheme from it.
    let pubkey_string = handler.extract_public_key_string(data)?;
    let pubkey = keys::PublicKey::parse(&pubkey_string)?;

    // Find the matching private key and create a scheme-aware decrypter.
    let privkey = find_private_key(&pubkey, key)?;
    let decrypter = keys::AnyDecrypter::new(&pubkey, privkey)?;

    // Decrypt encrypted values and pass plaintext ones through (a secret that
    // was added but not encrypted yet). A value that looks encrypted but isn't
    // well-formed is an error: printing it unchanged would hide the damage.
    let decrypt_fn = |value: &[u8]| match boxed_message::classify_value(value) {
        ValueKind::Boxed => decrypter.decrypt(value),
        ValueKind::Plaintext => Ok(value.to_vec()),
        ValueKind::Damaged => Err(CryptoError::DamagedMessage),
    };

    // Walk and decrypt using the handler
    let new_data = handler.walk(data, &decrypt_fn)?;

    output.write_all(&new_data)?;
    Ok(())
}

/// Decrypt a file and return the decrypted contents.
///
/// The file format is auto-detected based on file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
/// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
///
/// `underscore_prefix` says whether key names keep their leading underscore
/// in the output (see [`UnderscorePrefix`]).
///
/// Security: Uses file locking and size limits. The plaintext is returned in a
/// buffer that is wiped from memory when dropped.
pub fn decrypt_file<P: AsRef<Path>>(
    file_path: P,
    key: KeySource<'_>,
    underscore_prefix: UnderscorePrefix,
) -> Result<Zeroizing<Vec<u8>>, EjsonError> {
    let file_path = file_path.as_ref();
    let format = FileFormat::from_path(file_path)?;
    let data = read_file_with_lock(file_path)?;
    let mut output = Zeroizing::new(Vec::new());
    decrypt_data(&data, &mut *output, key, format)?;

    if underscore_prefix == UnderscorePrefix::Trim {
        // The untrimmed copy is wiped when `output` is replaced.
        output = Zeroizing::new(trim_underscore_prefix_from_keys(&output, format)?);
    }

    Ok(output)
}

/// Decrypt a file and write the plaintext to `output_path`.
///
/// This is [`decrypt_file`] followed by a careful write: the output is
/// readable only by its owner (`0600` on Unix), and it is written to a
/// temporary file in the same directory and renamed into place, so
/// `output_path` is never left half-written and an existing file there is
/// replaced atomically. If anything fails, no partial copy of the plaintext
/// is left on disk.
///
/// A failure to write is reported as [`EjsonError::Output`], which tells it
/// apart from a failure to read or decrypt the input.
///
/// ```no_run
/// use ejson::{KeySource, UnderscorePrefix};
///
/// ejson::decrypt_file_to(
///     "secrets.ejson",
///     "/run/app/secrets.json",
///     KeySource::keydir("/opt/ejson/keys"),
///     UnderscorePrefix::Keep,
/// )?;
/// # Ok::<(), ejson::EjsonError>(())
/// ```
///
/// On non-Unix platforms the output gets the directory's default permissions.
pub fn decrypt_file_to<P: AsRef<Path>, Q: AsRef<Path>>(
    file_path: P,
    output_path: Q,
    key: KeySource<'_>,
    underscore_prefix: UnderscorePrefix,
) -> Result<(), EjsonError> {
    let plaintext = decrypt_file(file_path, key, underscore_prefix)?;

    write_private_file_atomically(output_path.as_ref(), &plaintext).map_err(|e| match e {
        EjsonError::Io(source) => EjsonError::Output(source),
        other => other,
    })
}

/// Decrypt bytes and return the decrypted contents as a typed value.
///
/// This function is similar to [`decrypt`], but instead of returning raw bytes,
/// it returns a [`DecryptedContent`] enum that provides format-agnostic access to
/// the decrypted data.
///
/// This is useful when you have the encrypted data already in memory (e.g., from an HTTP
/// response or embedded resource) and want to work with the typed API.
///
/// # Example
///
/// ```no_run
/// use ejson::{decrypt_bytes_typed, DecryptedContent, FileFormat, KeySource, UnderscorePrefix};
///
/// let encrypted_data = b"{\"_public_key\": \"...\", \"secret\": \"EJ[...]\"}";
/// let key = KeySource::keydir("/opt/ejson/keys");
/// let content = decrypt_bytes_typed(encrypted_data, key, FileFormat::Json, UnderscorePrefix::Keep)?;
///
/// // Access values uniformly regardless of JSON/YAML/TOML format
/// if let Some(env) = content.get("environment") {
///     if let Some(map) = env.as_string_map() {
///         for (key, value) in map {
///             if let Some(v) = value.as_str() {
///                 println!("{}={}", key, v);
///             }
///         }
///     }
/// }
/// # Ok::<(), ejson::EjsonError>(())
/// ```
pub fn decrypt_bytes_typed(
    data: &[u8],
    key: KeySource<'_>,
    format: FileFormat,
    underscore_prefix: UnderscorePrefix,
) -> Result<DecryptedContent, EjsonError> {
    // Check size limit
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(EjsonError::FileTooLarge);
    }

    // Decrypt to bytes first. Both intermediate buffers hold plaintext and
    // are wiped once the typed value has been parsed from them.
    let mut output = Zeroizing::new(Vec::new());
    decrypt_data(data, &mut *output, key, format)?;

    let decrypted_bytes = if underscore_prefix == UnderscorePrefix::Trim {
        Zeroizing::new(trim_underscore_prefix_from_keys(&output, format)?)
    } else {
        output
    };

    Ok(DecryptedContent::parse(&decrypted_bytes, format)?)
}

/// Decrypt a file and return the decrypted contents as a typed value.
///
/// This function is similar to [`decrypt_file`], but instead of returning raw bytes,
/// it returns a [`DecryptedContent`] enum that provides format-agnostic access to
/// the decrypted data.
///
/// This is particularly useful for tools like `ejson2env` that need to extract
/// specific values from the decrypted content without knowing the file format.
///
/// # Example
///
/// ```no_run
/// use ejson::{decrypt_file_typed, DecryptedContent, KeySource, UnderscorePrefix};
///
/// let key = KeySource::keydir("/opt/ejson/keys");
/// let content = decrypt_file_typed("secrets.ejson", key, UnderscorePrefix::Keep)?;
///
/// // Access values uniformly regardless of JSON/YAML/TOML format
/// if let Some(env) = content.get("environment") {
///     if let Some(map) = env.as_string_map() {
///         for (key, value) in map {
///             if let Some(v) = value.as_str() {
///                 println!("{}={}", key, v);
///             }
///         }
///     }
/// }
/// # Ok::<(), ejson::EjsonError>(())
/// ```
pub fn decrypt_file_typed<P: AsRef<Path>>(
    file_path: P,
    key: KeySource<'_>,
    underscore_prefix: UnderscorePrefix,
) -> Result<DecryptedContent, EjsonError> {
    let file_path = file_path.as_ref();
    let format = FileFormat::from_path(file_path)?;

    // Decrypt to bytes first; wiped once the typed value has been parsed.
    let decrypted_bytes = decrypt_file(file_path, key, underscore_prefix)?;

    Ok(DecryptedContent::parse(&decrypted_bytes, format)?)
}

/// Trim the first leading underscore from all keys in the data.
///
/// This is a post-processing step applied after decryption when the
/// `--trim-underscore-prefix` flag is used.
fn trim_underscore_prefix_from_keys(
    data: &[u8],
    format: FileFormat,
) -> Result<Vec<u8>, EjsonError> {
    let handler = format.handler();
    Ok(handler.trim_underscore_prefix_from_keys(data)?)
}

fn find_private_key(
    pubkey: &keys::PublicKey,
    key: KeySource<'_>,
) -> Result<keys::PrivateKey, EjsonError> {
    // A key read from disk is owned here and wiped on return; a key supplied
    // by the caller is borrowed, not copied.
    let from_disk: Zeroizing<String>;
    let privkey_string: &str = match key {
        KeySource::Keydir(keydir) => {
            from_disk = read_private_key_from_disk(pubkey, keydir)?;
            &from_disk
        }
        KeySource::PrivateKey(private_key) => private_key,
    };

    Ok(keys::PrivateKey::parse_for_public(pubkey, privkey_string)?)
}

/// Read the private key for `pubkey` from `keydir`.
///
/// The key, and the raw bytes it is decoded from, are wiped when dropped.
fn read_private_key_from_disk(
    pubkey: &keys::PublicKey,
    keydir: &Path,
) -> Result<Zeroizing<String>, EjsonError> {
    // The keydir filename is the key ID: for legacy keys this is the 64-char hex public
    // key (unchanged); for hybrid keys it is a 32-char derived ID.
    let key_id = pubkey.key_id();
    let key_path = keydir.join(&key_id);

    // Verify the path is still within keydir after resolution
    // This prevents path traversal via a malicious key ID
    if let (Ok(canonical_keydir), Ok(canonical_key_path)) =
        (fs::canonicalize(keydir), fs::canonicalize(&key_path))
        && !canonical_key_path.starts_with(&canonical_keydir)
    {
        return Err(EjsonError::InvalidPath(InvalidPathReason::EscapesKeydir));
    }

    // The error (and the warning below) name the key, never the keydir path.
    let key_file_error = |reason: KeyFileReason| EjsonError::KeyFile {
        key_id: key_id.clone(),
        reason,
    };

    let (file, metadata) = match open_regular_file(&key_path, MAX_KEY_FILE_SIZE) {
        Ok(opened) => opened,
        Err(e @ (EjsonError::InvalidPath(_) | EjsonError::FileTooLarge)) => return Err(e),
        Err(EjsonError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(key_file_error(KeyFileReason::NotFound));
        }
        // Report the kind of failure (e.g. "permission denied") but not the
        // OS error text, which can include the path.
        Err(EjsonError::Io(e)) => return Err(key_file_error(KeyFileReason::Io(e.kind()))),
        Err(_) => return Err(key_file_error(KeyFileReason::Io(std::io::ErrorKind::Other))),
    };
    let data = Zeroizing::new(read_to_end_limited(
        file,
        MAX_KEY_FILE_SIZE,
        metadata.len(),
    )?);
    let contents = Zeroizing::new(
        std::str::from_utf8(&data)
            .map_err(|_| key_file_error(KeyFileReason::NotUtf8))?
            .to_owned(),
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(problem) = key_file_mode_problem(metadata.permissions().mode()) {
            log::warn!(
                "key file for public key {}... is {problem}; \
                 restrict it with `chmod 440` (or `chmod 400`)",
                key_id_prefix(&key_id)
            );
        }
    }

    Ok(contents)
}

/// Describe what is wrong with a private key file's permission bits, if anything.
///
/// Group *read* access is allowed, since `ejson keygen -w` creates keys `0440`
/// so a service group can read them. Access for other users, or write access
/// for anyone but the owner, is reported.
#[cfg(unix)]
fn key_file_mode_problem(mode: u32) -> Option<&'static str> {
    if mode & 0o007 != 0 {
        Some("accessible by other users")
    } else if mode & 0o020 != 0 {
        Some("writable by its group")
    } else {
        None
    }
}

/// Captures `log` records so tests can assert on the library's warnings.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod test_log {
    use std::sync::{Mutex, Once};

    static MESSAGES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    struct Capture;

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            let message = format!("{}: {}", record.level(), record.args());
            MESSAGES.lock().unwrap().push(message);
        }

        fn flush(&self) {}
    }

    /// Install the capturing logger (once per test process).
    pub(crate) fn install() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&Capture).expect("no other logger in tests");
            log::set_max_level(log::LevelFilter::Trace);
        });
    }

    /// Captured messages containing `needle`. Tests run in parallel and share
    /// the log, so each test filters on something unique to it.
    pub(crate) fn messages_containing(needle: &str) -> Vec<String> {
        MESSAGES
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.contains(needle))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use tempfile::TempDir;

    #[test]
    fn test_unencrypted_yaml_scalars_are_reported_through_log() {
        test_log::install();

        let temp_dir = TempDir::new().unwrap();
        let kp = generate_keypair(Scheme::V1);
        let path = temp_dir.path().join("yaml-scalar-probe.eyaml");
        fs::write(
            &path,
            format!(
                "_public_key: {}\npassword: hunter2\npin: 987654\ndb:\n  port: 5432\n_skip: 1\n",
                kp.public_key
            ),
        )
        .unwrap();
        encrypt_file_in_place(&path).unwrap();

        let warnings = test_log::messages_containing("yaml-scalar-probe.eyaml");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with("WARN: "));
        assert!(warnings[0].contains("left unencrypted: pin, db.port. Quote them"));
        // Names only: neither the values nor the string secret are logged.
        assert!(!warnings[0].contains("987654"));
        assert!(!warnings[0].contains("hunter2"));

        // A file with nothing to report produces no warning, and neither
        // does a JSON file with numbers (which are unambiguous there).
        let clean = temp_dir.path().join("yaml-clean-probe.eyaml");
        fs::write(
            &clean,
            format!("_public_key: {}\npassword: x\n", kp.public_key),
        )
        .unwrap();
        encrypt_file_in_place(&clean).unwrap();
        assert!(test_log::messages_containing("yaml-clean-probe").is_empty());

        let json = temp_dir.path().join("json-number-probe.ejson");
        fs::write(
            &json,
            format!(r#"{{"_public_key": "{}", "pin": 123456}}"#, kp.public_key),
        )
        .unwrap();
        encrypt_file_in_place(&json).unwrap();
        assert!(test_log::messages_containing("json-number-probe").is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_exposed_key_file_is_reported_through_log() {
        use std::os::unix::fs::PermissionsExt;
        test_log::install();

        let keydir = TempDir::new().unwrap();
        let exposed = keys::PublicKey::Legacy([0xcd; 32]);
        let restricted = keys::PublicKey::Legacy([0xce; 32]);
        for (key, mode) in [(&exposed, 0o644), (&restricted, 0o440)] {
            let path = keydir.path().join(key.key_id());
            fs::write(&path, "00").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            read_private_key_from_disk(key, keydir.path()).unwrap();
        }

        let warnings = test_log::messages_containing("cdcdcdcd");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with("WARN: key file for public key cdcdcdcd..."));
        assert!(warnings[0].contains("accessible by other users"));

        // A correctly restricted key produces no warning.
        assert!(test_log::messages_containing("cececece").is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_key_file_mode_problem() {
        // What keygen creates, and stricter, is fine
        assert_eq!(key_file_mode_problem(0o100440), None);
        assert_eq!(key_file_mode_problem(0o100400), None);
        assert_eq!(key_file_mode_problem(0o100600), None);
        assert_eq!(key_file_mode_problem(0o100640), None);
        // Anything for "other", or group write, is flagged
        assert!(key_file_mode_problem(0o100644).is_some());
        assert!(key_file_mode_problem(0o100604).is_some());
        assert!(key_file_mode_problem(0o100401).is_some());
        assert!(key_file_mode_problem(0o100460).is_some());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test JSON
        let json = format!(
            r#"{{"_public_key": "{pub_hex}", "secret": "my secret value", "_comment": "not encrypted"}}"#
        );

        // Encrypt
        let mut encrypted = Vec::new();
        encrypt(json.as_bytes(), &mut encrypted, FileFormat::Json).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Verify encryption happened
        assert!(encrypted_str.contains("EJ["));
        assert!(!encrypted_str.contains("my secret value"));
        assert!(encrypted_str.contains("not encrypted")); // Comment should not be encrypted

        // Decrypt
        let mut decrypted = Vec::new();
        decrypt(
            &encrypted[..],
            &mut decrypted,
            KeySource::keydir(keydir),
            FileFormat::Json,
        )
        .unwrap();
        let decrypted_str = String::from_utf8_lossy(&decrypted);

        // Verify decryption
        assert!(decrypted_str.contains("my secret value"));
        assert!(!decrypted_str.contains("EJ["));
    }

    #[test]
    fn test_encrypt_decrypt_toml_roundtrip() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test TOML
        let toml_content = format!(
            r#"_public_key = "{pub_hex}"
secret = "my secret value"
_comment = "not encrypted"

[database]
password = "db_password"
_hint = "password hint"
"#
        );

        // Encrypt
        let mut encrypted = Vec::new();
        encrypt(toml_content.as_bytes(), &mut encrypted, FileFormat::Toml).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Verify encryption happened
        assert!(encrypted_str.contains("EJ["));
        assert!(!encrypted_str.contains("my secret value"));
        assert!(!encrypted_str.contains("db_password"));
        assert!(encrypted_str.contains("not encrypted")); // Comment should not be encrypted
        assert!(encrypted_str.contains("password hint")); // Underscore key should not be encrypted

        // Decrypt
        let mut decrypted = Vec::new();
        decrypt(
            &encrypted[..],
            &mut decrypted,
            KeySource::keydir(keydir),
            FileFormat::Toml,
        )
        .unwrap();
        let decrypted_str = String::from_utf8_lossy(&decrypted);

        // Verify decryption
        assert!(decrypted_str.contains("my secret value"));
        assert!(decrypted_str.contains("db_password"));
        assert!(!decrypted_str.contains("EJ["));
    }

    #[test]
    fn test_format_detection_in_encrypt_file() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();

        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();

        // Test with .etoml extension
        let etoml_path = temp_dir.path().join("secrets.etoml");
        let toml_content = format!(
            r#"_public_key = "{pub_hex}"
secret = "my secret"
"#
        );
        fs::write(&etoml_path, &toml_content).unwrap();

        // Encrypt
        encrypt_file_in_place(&etoml_path).unwrap();

        // Read and verify
        let encrypted = fs::read_to_string(&etoml_path).unwrap();
        assert!(encrypted.contains("EJ["));
        assert!(!encrypted.contains("my secret"));
    }

    #[test]
    fn test_encrypt_decrypt_yaml_roundtrip() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test YAML
        let yaml_content = format!(
            r#"_public_key: "{pub_hex}"
secret: "my secret value"
_comment: "not encrypted"

database:
  password: "db_password"
  _hint: "password hint"
"#
        );

        // Encrypt
        let mut encrypted = Vec::new();
        encrypt(yaml_content.as_bytes(), &mut encrypted, FileFormat::Yaml).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Verify encryption happened
        assert!(encrypted_str.contains("EJ["));
        assert!(!encrypted_str.contains("my secret value"));
        assert!(!encrypted_str.contains("db_password"));
        assert!(encrypted_str.contains("not encrypted")); // Comment should not be encrypted
        assert!(encrypted_str.contains("password hint")); // Underscore key should not be encrypted

        // Decrypt
        let mut decrypted = Vec::new();
        decrypt(
            &encrypted[..],
            &mut decrypted,
            KeySource::keydir(keydir),
            FileFormat::Yaml,
        )
        .unwrap();
        let decrypted_str = String::from_utf8_lossy(&decrypted);

        // Verify decryption
        assert!(decrypted_str.contains("my secret value"));
        assert!(decrypted_str.contains("db_password"));
        assert!(!decrypted_str.contains("EJ["));
    }

    #[test]
    fn test_format_detection_in_encrypt_yaml_file() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();

        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();

        // Test with .eyaml extension
        let eyaml_path = temp_dir.path().join("secrets.eyaml");
        let yaml_content = format!(
            r#"_public_key: "{pub_hex}"
secret: "my secret"
"#
        );
        fs::write(&eyaml_path, &yaml_content).unwrap();

        // Encrypt
        encrypt_file_in_place(&eyaml_path).unwrap();

        // Read and verify
        let encrypted = fs::read_to_string(&eyaml_path).unwrap();
        assert!(encrypted.contains("EJ["));
        assert!(!encrypted.contains("my secret"));
    }

    fn write_ejson_fixture(dir: &Path) -> (std::path::PathBuf, String) {
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        fs::write(dir.join(&pub_hex), kp.private_hex()).unwrap();
        let path = dir.join("secrets.ejson");
        fs::write(
            &path,
            format!(r#"{{"_public_key": "{pub_hex}", "secret": "my secret"}}"#),
        )
        .unwrap();
        (path, pub_hex)
    }

    #[test]
    #[cfg(unix)]
    fn test_write_private_file_atomically() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("out.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file_atomically(&path, b"secret").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"secret");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got 0o{mode:o}");
        assert_eq!(fs::read_dir(temp_dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn test_write_private_file_atomically_cleans_up_on_failure() {
        // Renaming a file over a non-empty directory fails after the data
        // has been written; the temporary copy must not be left behind.
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("out.json");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), "x").unwrap();

        assert!(write_private_file_atomically(&target, b"secret").is_err());

        let names: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("out.json")]);
    }

    #[test]
    fn test_encrypt_in_place_leaves_no_temp_files() {
        let temp_dir = TempDir::new().unwrap();
        let (path, _) = write_ejson_fixture(temp_dir.path());

        encrypt_file_in_place(&path).unwrap();

        let leftovers: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
        assert!(!fs::read_to_string(&path).unwrap().contains("my secret"));
    }

    #[test]
    fn test_encrypt_in_place_failure_keeps_original() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("secrets.ejson");
        let original = r#"{"_public_key": "not-a-key", "secret": "my secret"}"#;
        fs::write(&path, original).unwrap();

        assert!(encrypt_file_in_place(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn test_encrypt_in_place_skips_write_when_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let (path, _) = write_ejson_fixture(temp_dir.path());

        encrypt_file_in_place(&path).unwrap();
        let first = fs::read(&path).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();

        encrypt_file_in_place(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), first);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    }

    #[test]
    #[cfg(unix)]
    fn test_encrypt_in_place_preserves_mode_and_symlink() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let (path, _) = write_ejson_fixture(temp_dir.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let link = temp_dir.path().join("link.ejson");
        std::os::unix::fs::symlink(&path, &link).unwrap();

        encrypt_file_in_place(&link).unwrap();

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert!(!fs::read_to_string(&path).unwrap().contains("my secret"));
    }

    #[test]
    fn test_concurrent_encrypt_in_place() {
        // Writers that waited on the lock of a since-replaced inode must
        // re-open the path; every run must leave a valid, fully encrypted file.
        let temp_dir = TempDir::new().unwrap();
        let (path, pub_hex) = write_ejson_fixture(temp_dir.path());

        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| encrypt_file_in_place(&path).unwrap());
            }
        });

        let out = decrypt_file(
            &path,
            KeySource::Keydir(temp_dir.path()),
            UnderscorePrefix::Keep,
        )
        .unwrap();
        let out = String::from_utf8(out.to_vec()).unwrap();
        assert!(out.contains("my secret"));
        assert!(out.contains(&pub_hex));
    }

    #[test]
    fn test_missing_key_file_error_names_the_key() {
        let keydir = TempDir::new().unwrap();
        let pubkey = keys::PublicKey::Legacy([0xab; 32]);

        let err = read_private_key_from_disk(&pubkey, keydir.path()).unwrap_err();
        assert!(matches!(
            &err,
            EjsonError::KeyFile { key_id, reason: KeyFileReason::NotFound }
                if *key_id == "ab".repeat(32)
        ));

        let msg = err.to_string();
        assert_eq!(
            msg,
            "couldn't read key file for public key abababab...: not found in keydir"
        );
        // The keydir path must not leak into the message.
        assert!(!msg.contains(keydir.path().to_str().unwrap()));
    }

    #[test]
    #[cfg(unix)]
    fn test_unreadable_key_file_error_gives_the_reason() {
        use std::os::unix::fs::PermissionsExt;

        let keydir = TempDir::new().unwrap();
        let pubkey = keys::PublicKey::Legacy([0xab; 32]);
        let key_path = keydir.path().join(pubkey.key_id());
        fs::write(&key_path, "00").unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o000)).unwrap();

        // Root ignores file permissions, so there is nothing to observe.
        if File::open(&key_path).is_ok() {
            return;
        }

        let err = read_private_key_from_disk(&pubkey, keydir.path()).unwrap_err();
        assert!(matches!(
            err,
            EjsonError::KeyFile {
                reason: KeyFileReason::Io(std::io::ErrorKind::PermissionDenied),
                ..
            }
        ));
        assert_eq!(
            err.to_string(),
            "couldn't read key file for public key abababab...: permission denied"
        );
    }

    #[test]
    fn test_non_utf8_key_file_error_gives_the_reason() {
        let keydir = TempDir::new().unwrap();
        let pubkey = keys::PublicKey::Legacy([0xab; 32]);
        fs::write(keydir.path().join(pubkey.key_id()), [0xff, 0xfe]).unwrap();

        let err = read_private_key_from_disk(&pubkey, keydir.path()).unwrap_err();
        assert!(matches!(
            err,
            EjsonError::KeyFile {
                reason: KeyFileReason::NotUtf8,
                ..
            }
        ));
        assert_eq!(
            err.to_string(),
            "couldn't read key file for public key abababab...: not valid UTF-8 text"
        );
    }

    #[test]
    fn test_decrypt_file_underscore_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let kp = generate_keypair(Scheme::V1);
        let key = KeySource::PrivateKey(&kp.private_key);
        let path = temp_dir.path().join("s.ejson");
        fs::write(
            &path,
            format!(
                r#"{{"_public_key": "{}", "_note": "plain", "__x": "y", "a": "secret"}}"#,
                kp.public_key
            ),
        )
        .unwrap();
        encrypt_file_in_place(&path).unwrap();

        assert_eq!(UnderscorePrefix::default(), UnderscorePrefix::Keep);

        // The plaintext comes back in a buffer that wipes itself on drop.
        let kept: Zeroizing<Vec<u8>> = decrypt_file(&path, key, UnderscorePrefix::Keep).unwrap();
        let kept = String::from_utf8(kept.to_vec()).unwrap();
        assert!(kept.contains(r#""_note": "plain""#));
        assert!(kept.contains(r#""__x": "y""#));

        let trimmed = decrypt_file(&path, key, UnderscorePrefix::Trim).unwrap();
        let trimmed: serde_json::Value = serde_json::from_slice(&trimmed).unwrap();
        assert_eq!(trimmed["note"], "plain");
        assert_eq!(trimmed["_x"], "y");
        assert_eq!(trimmed["a"], "secret");
        // `_public_key` keeps its underscore.
        assert_eq!(trimmed["_public_key"], kp.public_key);
        assert!(trimmed.get("_note").is_none());
    }

    #[test]
    fn test_key_source_debug_redacts_the_private_key() {
        let keydir = KeySource::keydir("/opt/ejson/keys");
        assert_eq!(format!("{keydir:?}"), r#"Keydir("/opt/ejson/keys")"#);

        let key = KeySource::PrivateKey("0123456789abcdef-secret");
        assert_eq!(format!("{key:?}"), r#"PrivateKey("[REDACTED]")"#);
    }

    #[test]
    fn test_empty_private_key_is_an_error_not_a_keydir_lookup() {
        let temp_dir = TempDir::new().unwrap();
        let (path, _) = write_ejson_fixture(temp_dir.path());
        encrypt_file_in_place(&path).unwrap();

        // The matching key is sitting in what used to be the fallback keydir.
        assert!(
            decrypt_file(
                &path,
                KeySource::Keydir(temp_dir.path()),
                UnderscorePrefix::Keep
            )
            .is_ok()
        );
        assert!(matches!(
            decrypt_file(&path, KeySource::PrivateKey(""), UnderscorePrefix::Keep),
            Err(EjsonError::Crypto(CryptoError::InvalidPrivateKey))
        ));
    }

    /// Whether `result` failed with `CryptoError::DamagedMessage`.
    fn is_damaged_message_error<T>(result: &Result<T, EjsonError>) -> bool {
        matches!(
            result,
            Err(EjsonError::Format(FormatError::ActionFailed(
                CryptoError::DamagedMessage
            )))
        )
    }

    #[test]
    fn test_damaged_encrypted_values_are_rejected() {
        for (name, doc) in [
            ("s.ejson", r#"{"_public_key": "PUB", "a": "secret"}"#),
            ("s.eyaml", "_public_key: PUB\na: secret\n"),
            ("s.etoml", "_public_key = \"PUB\"\na = \"secret\"\n"),
        ] {
            let temp_dir = TempDir::new().unwrap();
            let kp = generate_keypair(Scheme::V1);
            let key = KeySource::PrivateKey(&kp.private_key);
            let path = temp_dir.path().join(name);
            fs::write(&path, doc.replace("PUB", &kp.public_key)).unwrap();
            encrypt_file_in_place(&path).unwrap();
            let encrypted = fs::read_to_string(&path).unwrap();
            assert!(decrypt_file(&path, key, UnderscorePrefix::Keep).is_ok());

            for damaged in [
                // one extra character in the encrypter's public key
                encrypted.replacen("EJ[1:", "EJ[1:A", 1),
                // a schema version this build doesn't know
                encrypted.replacen("EJ[1:", "EJ[3:", 1),
            ] {
                fs::write(&path, &damaged).unwrap();

                // Decrypt fails instead of printing the value unchanged...
                assert!(
                    is_damaged_message_error(&decrypt_file(&path, key, UnderscorePrefix::Keep)),
                    "{name}"
                );
                // ...and encrypt refuses to wrap it in a second layer,
                // leaving the file as it was.
                assert!(
                    is_damaged_message_error(&encrypt_file_in_place(&path)),
                    "{name}"
                );
                assert_eq!(fs::read_to_string(&path).unwrap(), damaged, "{name}");
            }
        }
    }

    #[test]
    fn test_unencrypted_values_still_pass_through_on_decrypt() {
        // A secret added to an encrypted file but not encrypted yet.
        let temp_dir = TempDir::new().unwrap();
        let kp = generate_keypair(Scheme::V1);
        let path = temp_dir.path().join("s.ejson");
        fs::write(
            &path,
            format!(r#"{{"_public_key": "{}", "a": "secret"}}"#, kp.public_key),
        )
        .unwrap();
        encrypt_file_in_place(&path).unwrap();
        let with_new_value =
            fs::read_to_string(&path)
                .unwrap()
                .replacen('}', r#", "new": "not encrypted yet"}"#, 1);
        fs::write(&path, with_new_value).unwrap();

        let out = decrypt_file(
            &path,
            KeySource::PrivateKey(&kp.private_key),
            UnderscorePrefix::Keep,
        )
        .unwrap();
        let out = String::from_utf8(out.to_vec()).unwrap();
        assert!(out.contains(r#""a": "secret""#));
        assert!(out.contains(r#""new": "not encrypted yet""#));
    }

    #[test]
    fn test_decrypt_failure_keeps_the_typed_cause() {
        use std::error::Error as _;

        // Encrypt each format to one key, then decrypt with another.
        let other = generate_keypair(Scheme::V1);
        for (name, doc) in [
            ("s.ejson", r#"{"_public_key": "PUB", "a": "secret"}"#),
            ("s.eyaml", "_public_key: PUB\na: secret\n"),
            ("s.etoml", "_public_key = \"PUB\"\na = \"secret\"\n"),
        ] {
            let temp_dir = TempDir::new().unwrap();
            let kp = generate_keypair(Scheme::V1);
            let path = temp_dir.path().join(name);
            fs::write(&path, doc.replace("PUB", &kp.public_key)).unwrap();
            encrypt_file_in_place(&path).unwrap();

            let err = decrypt_file(
                &path,
                KeySource::PrivateKey(&other.private_key),
                UnderscorePrefix::Keep,
            )
            .unwrap_err();

            // The cause can be matched on, not just read as text...
            assert!(
                matches!(
                    err,
                    EjsonError::Format(FormatError::ActionFailed(CryptoError::DecryptionFailed))
                ),
                "{name}: {err:?}"
            );
            // ...and the message is the cause's, with no wrapper prefixes.
            assert_eq!(err.to_string(), "couldn't decrypt message");
            assert!(err.source().is_none());
        }
    }

    #[test]
    fn test_is_same_file_detects_a_replaced_file() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("secrets.ejson");
        fs::write(&path, "original").unwrap();
        let open = File::open(&path).unwrap();
        assert!(is_same_file(&open, &path).unwrap());

        // Rewriting in place keeps the same file...
        fs::write(&path, "rewritten in place").unwrap();
        assert!(is_same_file(&open, &path).unwrap());

        // ...but replacing it by rename, as `encrypt` does, does not.
        let replacement = temp_dir.path().join("replacement");
        fs::write(&replacement, "replaced").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(!is_same_file(&open, &path).unwrap());

        // A fresh handle sees the new file.
        let reopened = File::open(&path).unwrap();
        assert!(is_same_file(&reopened, &path).unwrap());
    }

    #[test]
    fn test_decrypt_file_to() {
        let temp_dir = TempDir::new().unwrap();
        let (path, _) = write_ejson_fixture(temp_dir.path());
        let original = fs::read_to_string(&path).unwrap();
        encrypt_file_in_place(&path).unwrap();
        let key = KeySource::Keydir(temp_dir.path());
        let output = temp_dir.path().join("plain.json");

        // Replaces an existing file, whatever its permissions were.
        fs::write(&output, "old contents").unwrap();
        decrypt_file_to(&path, &output, key, UnderscorePrefix::Keep).unwrap();
        assert_eq!(fs::read_to_string(&output).unwrap(), original);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&output).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "got 0o{mode:o}");
        }

        let temp_files = || {
            fs::read_dir(temp_dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
                .count()
        };
        assert_eq!(temp_files(), 0);

        // If decryption fails, nothing is written.
        let untouched = temp_dir.path().join("untouched.json");
        let wrong_key = generate_keypair(Scheme::V1);
        let result = decrypt_file_to(
            &path,
            &untouched,
            KeySource::PrivateKey(&wrong_key.private_key),
            UnderscorePrefix::Keep,
        );
        assert!(matches!(result, Err(EjsonError::Format(_))));
        assert!(!untouched.exists());

        // A failure to write is told apart from a failure to decrypt, and
        // leaves no partial plaintext behind.
        let blocked = temp_dir.path().join("blocked.json");
        fs::create_dir(&blocked).unwrap();
        fs::write(blocked.join("keep"), "x").unwrap();
        let result = decrypt_file_to(&path, &blocked, key, UnderscorePrefix::Keep);
        assert!(matches!(result, Err(EjsonError::Output(_))), "{result:?}");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("couldn't write output file: ")
        );
        assert_eq!(temp_files(), 0);
    }

    #[test]
    fn test_structured_error_reasons_and_messages() {
        // Messages are unchanged from when these carried pre-formatted text.
        for (reason, message) in [
            (
                InvalidPathReason::NullByte,
                "invalid path: path contains null bytes",
            ),
            (
                InvalidPathReason::NotRegularFile,
                "invalid path: path is not a regular file",
            ),
            (
                InvalidPathReason::EscapesKeydir,
                "invalid path: key path escapes keydir",
            ),
            (
                InvalidPathReason::NoFileName,
                "invalid path: path has no file name",
            ),
        ] {
            assert_eq!(EjsonError::InvalidPath(reason).to_string(), message);
        }

        let key_file = |key_id: &str, reason| EjsonError::KeyFile {
            key_id: key_id.to_string(),
            reason,
        };
        assert_eq!(
            key_file("0123456789abcdef", KeyFileReason::NotFound).to_string(),
            "couldn't read key file for public key 01234567...: not found in keydir"
        );
        // A short or non-ASCII key ID doesn't panic when shortened.
        assert_eq!(
            key_file("abc", KeyFileReason::NotUtf8).to_string(),
            "couldn't read key file for public key abc...: not valid UTF-8 text"
        );
        assert_eq!(key_id_prefix("ééééééééé-tail"), "éééééééé");

        // The reasons can be matched on.
        let temp_dir = TempDir::new().unwrap();
        assert!(matches!(
            open_regular_file(temp_dir.path(), MAX_FILE_SIZE),
            Err(EjsonError::InvalidPath(InvalidPathReason::NotRegularFile))
        ));
        assert!(matches!(
            validate_path(Path::new("/tmp/nul\0byte.ejson")),
            Err(EjsonError::InvalidPath(InvalidPathReason::NullByte))
        ));
        assert!(matches!(
            write_private_file_atomically(Path::new("/"), b"x"),
            Err(EjsonError::InvalidPath(InvalidPathReason::NoFileName))
        ));
    }

    #[test]
    fn test_read_to_end_limited() {
        assert_eq!(read_to_end_limited(&b"abc"[..], 3, 0).unwrap(), b"abc");
        assert!(matches!(
            read_to_end_limited(&b"abcd"[..], 3, 0),
            Err(EjsonError::FileTooLarge)
        ));
        // An endless reader stops at the limit instead of exhausting memory
        assert!(matches!(
            read_to_end_limited(std::io::repeat(0), 1024, 0),
            Err(EjsonError::FileTooLarge)
        ));
    }

    #[test]
    fn test_open_regular_file_rejects_directories() {
        let temp_dir = TempDir::new().unwrap();
        assert!(matches!(
            open_regular_file(temp_dir.path(), MAX_FILE_SIZE),
            Err(EjsonError::InvalidPath(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_to_device_is_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let link = temp_dir.path().join("secrets.ejson");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();

        assert!(matches!(
            decrypt_file(
                &link,
                KeySource::keydir("/nonexistent"),
                UnderscorePrefix::Keep
            ),
            Err(EjsonError::InvalidPath(_))
        ));
        assert!(matches!(
            encrypt_file_in_place(&link),
            Err(EjsonError::InvalidPath(_))
        ));
    }

    #[test]
    fn test_key_file_must_be_regular_file() {
        // Only the check on the opened handle catches this: the path is inside
        // the keydir and is not a device.
        let keydir = TempDir::new().unwrap();
        let pubkey = keys::PublicKey::Legacy([7u8; 32]);
        fs::create_dir(keydir.path().join(pubkey.key_id())).unwrap();

        assert!(matches!(
            read_private_key_from_disk(&pubkey, keydir.path()),
            Err(EjsonError::InvalidPath(_))
        ));
    }

    #[test]
    fn test_oversized_key_file_is_rejected() {
        let keydir = TempDir::new().unwrap();
        let pubkey = keys::PublicKey::Legacy([7u8; 32]);
        let big = vec![b'a'; usize::try_from(MAX_KEY_FILE_SIZE).unwrap() + 1];
        fs::write(keydir.path().join(pubkey.key_id()), big).unwrap();

        assert!(matches!(
            read_private_key_from_disk(&pubkey, keydir.path()),
            Err(EjsonError::FileTooLarge)
        ));
    }

    #[test]
    fn test_path_validation_rejects_null_bytes() {
        let path = Path::new("/tmp/test\0file.ejson");
        let result = validate_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_private_key_length() {
        let pubkey = keys::PublicKey::Legacy([0u8; 32]);
        let result = find_private_key(&pubkey, KeySource::PrivateKey("deadbeef")); // Too short
        assert!(matches!(
            result,
            Err(EjsonError::Crypto(CryptoError::InvalidPrivateKey))
        ));
    }

    #[test]
    fn test_decrypt_file_typed_json() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create and encrypt test JSON file
        let json_path = temp_dir.path().join("secrets.ejson");
        let json_content = format!(
            r#"{{"_public_key": "{pub_hex}", "environment": {{"FOO": "bar", "BAZ": "qux"}}, "secret": "value"}}"#
        );
        fs::write(&json_path, &json_content).unwrap();
        encrypt_file_in_place(&json_path).unwrap();

        // Decrypt with typed API
        let content = decrypt_file_typed(
            &json_path,
            KeySource::keydir(keydir),
            UnderscorePrefix::Keep,
        )
        .unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_file_typed_toml() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create and encrypt test TOML file
        let toml_path = temp_dir.path().join("secrets.etoml");
        let toml_content = format!(
            r#"_public_key = "{pub_hex}"
secret = "value"

[environment]
FOO = "bar"
BAZ = "qux"
"#
        );
        fs::write(&toml_path, &toml_content).unwrap();
        encrypt_file_in_place(&toml_path).unwrap();

        // Decrypt with typed API
        let content = decrypt_file_typed(
            &toml_path,
            KeySource::keydir(keydir),
            UnderscorePrefix::Keep,
        )
        .unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_file_typed_yaml() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create and encrypt test YAML file
        let yaml_path = temp_dir.path().join("secrets.eyaml");
        let yaml_content = format!(
            r#"_public_key: "{pub_hex}"
secret: "value"

environment:
  FOO: "bar"
  BAZ: "qux"
"#
        );
        fs::write(&yaml_path, &yaml_content).unwrap();
        encrypt_file_in_place(&yaml_path).unwrap();

        // Decrypt with typed API
        let content = decrypt_file_typed(
            &yaml_path,
            KeySource::keydir(keydir),
            UnderscorePrefix::Keep,
        )
        .unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_file_typed_ejson2env_pattern() {
        // This test demonstrates the simplified ejson2env pattern
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Test with JSON
        let json_path = temp_dir.path().join("secrets.ejson");
        let json_content = format!(
            r#"{{"_public_key": "{pub_hex}", "environment": {{"DATABASE_URL": "postgres://localhost", "API_KEY": "secret123"}}}}"#
        );
        fs::write(&json_path, &json_content).unwrap();
        encrypt_file_in_place(&json_path).unwrap();

        // Simulate ejson2env extraction
        let content = decrypt_file_typed(
            &json_path,
            KeySource::keydir(keydir),
            UnderscorePrefix::Keep,
        )
        .unwrap();

        // The pattern that ejson2env would use
        let env_secrets: std::collections::HashMap<String, String> = content
            .get("environment")
            .and_then(|env| env.as_string_map())
            .map(|map| {
                map.filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        assert_eq!(env_secrets.len(), 2);
        assert_eq!(
            env_secrets.get("DATABASE_URL"),
            Some(&"postgres://localhost".to_string())
        );
        assert_eq!(env_secrets.get("API_KEY"), Some(&"secret123".to_string()));
    }

    #[test]
    fn test_decrypt_bytes_typed_json() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test JSON and encrypt it
        let json_content = format!(
            r#"{{"_public_key": "{pub_hex}", "environment": {{"FOO": "bar", "BAZ": "qux"}}, "secret": "value"}}"#
        );
        let mut encrypted = Vec::new();
        encrypt(json_content.as_bytes(), &mut encrypted, FileFormat::Json).unwrap();

        // Decrypt bytes with typed API
        let content = decrypt_bytes_typed(
            &encrypted,
            KeySource::keydir(keydir),
            FileFormat::Json,
            UnderscorePrefix::Keep,
        )
        .unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));

        // Iterate over environment map
        let pairs: Vec<_> = env
            .as_string_map()
            .unwrap()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
            .collect();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.contains(&("FOO".to_string(), "bar".to_string())));
        assert!(pairs.contains(&("BAZ".to_string(), "qux".to_string())));
    }

    #[test]
    fn test_decrypt_bytes_typed_toml() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test TOML and encrypt it
        let toml_content = format!(
            r#"_public_key = "{pub_hex}"
secret = "value"

[environment]
FOO = "bar"
BAZ = "qux"
"#
        );
        let mut encrypted = Vec::new();
        encrypt(toml_content.as_bytes(), &mut encrypted, FileFormat::Toml).unwrap();

        // Decrypt bytes with typed API
        let content = decrypt_bytes_typed(
            &encrypted,
            KeySource::keydir(keydir),
            FileFormat::Toml,
            UnderscorePrefix::Keep,
        )
        .unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));
    }

    #[test]
    fn test_decrypt_bytes_typed_yaml() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test YAML and encrypt it
        let yaml_content = format!(
            r#"_public_key: "{pub_hex}"
secret: "value"

environment:
  FOO: "bar"
  BAZ: "qux"
"#
        );
        let mut encrypted = Vec::new();
        encrypt(yaml_content.as_bytes(), &mut encrypted, FileFormat::Yaml).unwrap();

        // Decrypt bytes with typed API
        let content = decrypt_bytes_typed(
            &encrypted,
            KeySource::keydir(keydir),
            FileFormat::Yaml,
            UnderscorePrefix::Keep,
        )
        .unwrap();

        // Access using unified API
        let env = content.get("environment").expect("should have environment");
        let foo = env.get("FOO").expect("should have FOO");
        assert_eq!(foo.as_str(), Some("bar"));
    }

    #[test]
    fn test_decrypt_bytes_typed_with_trim_underscore() {
        // Generate a keypair
        let kp = Keypair::generate();
        let pub_hex = kp.public_string();
        let priv_hex = kp.private_hex().to_string();

        // Create a temporary keydir
        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Write the private key to the keydir
        let key_file = temp_dir.path().join(&pub_hex);
        fs::write(&key_file, &priv_hex).unwrap();

        // Create test JSON with underscore-prefixed keys
        let json_content =
            format!(r#"{{"_public_key": "{pub_hex}", "_environment": {{"_FOO": "bar"}}}}"#);
        let mut encrypted = Vec::new();
        encrypt(json_content.as_bytes(), &mut encrypted, FileFormat::Json).unwrap();

        // Decrypt bytes with typed API and trim underscore prefix
        let content = decrypt_bytes_typed(
            &encrypted,
            KeySource::keydir(keydir),
            FileFormat::Json,
            UnderscorePrefix::Trim,
        )
        .unwrap();

        // Keys should have underscore prefix removed
        let env = content
            .get("environment")
            .expect("should have environment (trimmed)");
        let foo = env.get("FOO").expect("should have FOO (trimmed)");
        assert_eq!(foo.as_str(), Some("bar"));
    }

    #[test]
    fn test_hybrid_encrypt_decrypt_file() {
        // Generate a v2 hybrid keypair and store the private key under its key id.
        let GeneratedKeypair {
            public_key: pub_key,
            private_key: priv_key,
            key_id,
            ..
        } = generate_keypair(Scheme::V2);
        assert!(pub_key.starts_with("v2:"));

        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();
        fs::write(temp_dir.path().join(&key_id), priv_key.as_bytes()).unwrap();

        // Write a document with a nested secret and a plaintext (underscore) comment.
        let ejson_path = temp_dir.path().join("secrets.ejson");
        let original = format!(
            r#"{{"_public_key": "{pub_key}", "a": "b", "nested": {{"secret": "value"}}, "_comment": "plaintext"}}"#
        );
        fs::write(&ejson_path, &original).unwrap();

        // Encrypt in place: encryptable values become v2 boxes, comment stays plaintext.
        encrypt_file_in_place(&ejson_path).unwrap();
        let ciphertext = fs::read_to_string(&ejson_path).unwrap();
        assert!(ciphertext.contains(r#""a": "EJ[2:"#));
        assert!(ciphertext.contains(r#""secret": "EJ[2:"#));
        assert!(ciphertext.contains(r#""_comment": "plaintext""#));

        // Decrypt via the keydir.
        let out = decrypt_file(
            &ejson_path,
            KeySource::keydir(keydir),
            UnderscorePrefix::Keep,
        )
        .unwrap();
        assert_eq!(String::from_utf8(out.to_vec()).unwrap(), original);

        // Decrypt via a user-supplied (multi-line) private key, ignoring the keydir.
        let out = decrypt_file(
            &ejson_path,
            KeySource::PrivateKey(&priv_key),
            UnderscorePrefix::Keep,
        )
        .unwrap();
        assert_eq!(String::from_utf8(out.to_vec()).unwrap(), original);
    }
}
