# Upgrading to ejson 2.0

ejson 2.0 keeps the file formats, the key formats and the wire format of 1.x.
Files encrypted with 1.x decrypt with 2.0 and the other way round, and existing
key files work unchanged.

What changes is the Rust library API, plus a few behaviours of the
command-line tool.

## Command-line tool

| Situation | 1.x | 2.0 |
| --- | --- | --- |
| a value that starts with `EJ[` but is not a valid encrypted message | `decrypt` printed it unchanged; `encrypt` encrypted it again | both fail and say so; `encrypt` leaves the file unchanged |
| `--key-from-stdin` with nothing on stdin | silently fell back to the keydir | fails with `invalid private key` |
| `ejson keygen --scheme <unknown>` | exit code 1, `Key generation failed: …` | exit code 2 (usage error), reported while parsing arguments |
| a `v2` private key that belongs to a different public key | `couldn't decrypt message` | `private key does not match the public key` |

The first row catches truncated or hand-edited ciphertexts, and values written
by a newer ejson with a schema this version doesn't know. A file containing one
now fails where it used to appear to work: fix or re-create that value. Values
that don't start with `EJ[` still pass through `decrypt` unchanged, so a secret
you added but haven't encrypted yet behaves as before.

### Error messages

Messages no longer carry the internal prefixes `format error:`,
`crypto error:`, `file format error:`, `io error:` and `action failed:`. If a
script matches on error text, check it against the new wording:

| 1.x | 2.0 |
| --- | --- |
| `Decryption failed: format error: action failed: couldn't decrypt message` | `Decryption failed: couldn't decrypt message` |
| `Encryption failed: format error: invalid JSON syntax: invalid JSON syntax` | `Encryption failed: invalid JSON: syntax error at line 3, column 7` |
| `Encryption failed: file format error: unsupported file extension: txt` | `Encryption failed: unsupported file extension: txt` |
| `Encryption failed: crypto error: invalid key length` | `Encryption failed: invalid public key` |

`ejson env` errors no longer start with `could not load environment from
file:`. When `decrypt -o` can't write its output, the message is now
`Decryption failed: couldn't write output file: …` (it was `Failed to write
output file: …`). The warning about unquoted YAML numbers is now a single line that
starts with `ejson: warning:`. Exit codes are unchanged apart from the
`--scheme` case above.

## Library

The examples marked "2.0" below are compiled as part of the test suite.

### A smaller public API

In 1.x every module was public. In 2.0 the public API is the crate root and
the `env` module; the modules `boxed_message`, `crypto`, `format`, `handler`,
`hybrid`, `json`, `keys`, `toml`, `typed` and `yaml` are private.

| 1.x | 2.0 |
| --- | --- |
| `ejson::crypto::CryptoError` | `ejson::CryptoError` |
| `ejson::format::FileFormat`, `format::FileFormatError` | `ejson::FileFormat`, `ejson::FileFormatError` |
| `ejson::typed::{DecryptedContent, DecryptedValue}` | `ejson::{DecryptedContent, DecryptedValue}` |
| `ejson::handler::FormatError` | `ejson::FormatError` |
| `ejson::KeyBytes`, `ejson::KEY_SIZE`, `ejson::FormatHandler` | removed |
| `Keypair`, `Encrypter`, `Decrypter`, the `hybrid` and `boxed_message` types, the `Walker` types, `PublicKey`, `PrivateKey` | not public; use the functions below |

If you relied on something that is now private, please open an issue: making
an item public again is not a breaking change.

### Encrypting and decrypting

`encrypt` and `decrypt` now take the format; the `_with_format` variants are
gone. Every decrypt function takes one `KeySource` instead of a keydir string
and a private key string (where an empty key meant "look in the keydir"), and
an `UnderscorePrefix` instead of a `bool`. `decrypt_file` returns its plaintext
in a buffer that is wiped from memory when dropped.

1.x:

```text
ejson::encrypt(input, output)?;                                  // JSON only
ejson::encrypt_with_format(input, output, FileFormat::Yaml)?;
ejson::decrypt_with_format(input, output, "/opt/ejson/keys", "", FileFormat::Yaml)?;
let plaintext: Vec<u8> = ejson::decrypt_file("secrets.ejson", "/opt/ejson/keys", "", false)?;
let plaintext: Vec<u8> = ejson::decrypt_file("secrets.ejson", "", &private_key, true)?;
```

2.0:

```rust,no_run
use ejson::{FileFormat, KeySource, UnderscorePrefix};

# let (input, mut output) = (std::io::empty(), Vec::new());
# let private_key = String::new();
ejson::encrypt(input, &mut output, FileFormat::Yaml)?;

# let input = std::io::empty();
let keydir = KeySource::keydir("/opt/ejson/keys");
ejson::decrypt(input, &mut output, keydir, FileFormat::Yaml)?;

// The plaintext is a `Zeroizing<Vec<u8>>`; it derefs to `&[u8]`.
let plaintext = ejson::decrypt_file("secrets.ejson", keydir, UnderscorePrefix::Keep)?;
let _: &[u8] = &plaintext;

// With the private key in hand instead of a keydir:
let key = KeySource::PrivateKey(&private_key);
let trimmed = ejson::decrypt_file("secrets.ejson", key, UnderscorePrefix::Trim)?;
# let _ = trimmed;
# Ok::<(), ejson::EjsonError>(())
```

`KeySource` and `UnderscorePrefix` replace the same arguments in
`decrypt_file_typed`, `decrypt_bytes_typed`, `env::read_and_extract_env` and
`env::read_and_export_env`. An empty private key is now an error.

`write_private_file_atomically` is no longer public. To decrypt a file to
another file, with the output readable only by its owner and written
atomically, use `decrypt_file_to`:

```rust,no_run
use ejson::{KeySource, UnderscorePrefix};

ejson::decrypt_file_to(
    "secrets.ejson",
    "/run/app/secrets.json",
    KeySource::keydir("/opt/ejson/keys"),
    UnderscorePrefix::Keep,
)?;
# Ok::<(), ejson::EjsonError>(())
```

### Types that can grow

`Scheme`, `FileFormat`, `KeySource`, `env::Shell` and `GeneratedKeypair` are
`#[non_exhaustive]`, so that a new scheme, format, key source or shell can be
added without another major version.

| 1.x | 2.0 |
| --- | --- |
| `match format { FileFormat::Json => …, FileFormat::Yaml => …, FileFormat::Toml => … }` | add a `_ => …` arm (same for `Scheme`, `KeySource`, `Shell`) |
| `GeneratedKeypair { scheme, public_key, private_key, key_id }` as a pattern | add `..` |

```rust
fn extension(format: ejson::FileFormat) -> &'static str {
    match format {
        ejson::FileFormat::Json => "ejson",
        ejson::FileFormat::Yaml => "eyaml",
        ejson::FileFormat::Toml => "etoml",
        _ => "unknown",
    }
}
assert_eq!(extension(ejson::FileFormat::Yaml), "eyaml");
```

### Generating keys

1.x:

```text
let (public_key, private_key) = ejson::generate_keypair()?;
let (public_key, private_key, key_id) = ejson::generate_keypair_for_scheme("v2")?;
```

2.0:

```rust
use ejson::Scheme;

let keypair = ejson::generate_keypair(Scheme::V2);
let _ = (&keypair.public_key, &keypair.private_key, &keypair.key_id);

// A scheme name from user input (canonical names and aliases such as "pqc"):
let scheme: Scheme = "v1".parse()?;
assert_eq!(scheme.as_str(), "v1");
# Ok::<(), ejson::CryptoError>(())
```

Key generation can no longer fail, so there is no `Result`.

### Errors

All error enums are `#[non_exhaustive]`: a `match` on one needs a `_ =>` arm.
`JsonError`, `YamlError` and `TomlError` are merged into `FormatError`.

| 1.x | 2.0 |
| --- | --- |
| `EjsonError::Json(e)`, `::Yaml(e)`, `::Toml(e)` | `EjsonError::Format(e)` |
| `JsonError::InvalidJson`, `YamlError::InvalidYaml(m)`, `TomlError::InvalidToml(m)` | `FormatError::InvalidSyntax { format, message }` |
| `ActionFailed(String)` | `FormatError::ActionFailed(CryptoError)` |
| `EjsonError::InvalidPrivateKey` | `EjsonError::Crypto(CryptoError::InvalidPrivateKey)` |
| `CryptoError::InvalidKeyLength` | `CryptoError::InvalidPublicKey` or `CryptoError::InvalidPrivateKey` |
| `CryptoError::DecryptionFailed` when loading a mismatched key | `CryptoError::KeyMismatch` |
| `EjsonError::KeyFileError(message)` | `EjsonError::KeyFile { key_id, reason }`, with `KeyFileReason::{NotFound, NotUtf8, Io(kind)}` |
| `EjsonError::InvalidPath(message)` | `EjsonError::InvalidPath(reason)`, with `InvalidPathReason::{NullByte, NotRegularFile, EscapesKeydir, NoFileName}` |
| `EnvError::EnvLoadError(message)` | `EnvError::Ejson(error)` |
| `EjsonError::HexError`, `CryptoError::RandomGenerationFailed`, `EnvError::LoadError` | removed (they were never returned) |

New variants you may want to handle: `CryptoError::DamagedMessage` (a value
starts with `EJ[` but is not a valid encrypted message),
`FormatError::NestingTooDeep` (JSON nested more than 127 levels deep) and
`EjsonError::Output` (the output of `decrypt_file_to` couldn't be written).

A decryption failure can now be matched on:

```rust,no_run
use ejson::{CryptoError, EjsonError, FormatError, KeySource, UnderscorePrefix};

let key = KeySource::keydir("/opt/ejson/keys");
match ejson::decrypt_file("secrets.ejson", key, UnderscorePrefix::Keep) {
    Ok(_plaintext) => {}
    Err(EjsonError::Format(FormatError::ActionFailed(CryptoError::DecryptionFailed))) => {
        // wrong key, or a value was tampered with
    }
    Err(_other) => {}
}
```

### Typed access to decrypted documents

`DecryptedContent` and `DecryptedValue` are opaque: they no longer expose the
`serde_json`, `serde_norway` and `toml` value types, and have no variants to
match on. The format-neutral accessors (`get`, `as_str`, `as_string_map`,
`as_array`, …) are unchanged.

| 1.x | 2.0 |
| --- | --- |
| matching on `DecryptedContent::Json(..)` to learn the format | `content.format()` |
| `content.as_json()`, `into_yaml()`, … | decrypt to bytes with `decrypt_file` or `decrypt` and parse them yourself |
| `DecryptedContent::Json(value)` to build one | `DecryptedContent::parse(bytes, FileFormat::Json)?` |

```rust
use ejson::{DecryptedContent, FileFormat};

let content = DecryptedContent::parse(br#"{"environment": {"API_KEY": "s3cr3t"}}"#, FileFormat::Json)?;
assert_eq!(content.format(), FileFormat::Json);

let env = content.get("environment").unwrap();
assert_eq!(env.get("API_KEY").unwrap().as_str(), Some("s3cr3t"));
# Ok::<(), ejson::FormatError>(())
```

### Environment export

The eight `export_*` functions and the `ExportFunction` type are replaced by
one `export` function. `detect_shell()` is now `Shell::detect()`.

| 1.x | 2.0 |
| --- | --- |
| `export_env(w, values)` | `export(w, values, Shell::Posix, ExportStyle::Exported)` |
| `export_quiet(w, values)` | `export(w, values, Shell::Posix, ExportStyle::Unexported)` |
| `export_env_fish`, `export_quiet_fish` | `Shell::Fish` with the same two styles |
| `export_env_auto`, `export_quiet_auto` | `Shell::detect()` with the same two styles |
| `read_and_export_env(path, keydir, key, trim, export_fn, out)` | `read_and_export_env(path, key_source, underscore_prefix, shell, style, out)` |
| `is_env_error(&err)` | `err.is_missing_environment()` |

`SecretEnvMap::get` returns `Option<&str>` instead of `Option<&String>`, and
iterating a map yields `(&str, &str)`.

```rust
use ejson::env::{ExportStyle, SecretEnvMap, Shell, export};

let mut env = SecretEnvMap::new();
env.insert("API_KEY".to_string(), "s3cr3t".to_string());

let value: Option<&str> = env.get("API_KEY");
assert_eq!(value, Some("s3cr3t"));

let mut out = Vec::new();
export(&mut out, &env, Shell::Posix, ExportStyle::Exported)?;
assert_eq!(out, b"export API_KEY='s3cr3t'\n");
# Ok::<(), ejson::env::EnvError>(())
```

### Removed in 1.1.0

The `parallel` cargo feature and `ejson::json::parallel::ParallelWalker` were
removed in 1.1.0.
