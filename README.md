# ejson-rs

A Rust implementation of [Shopify/ejson](https://github.com/Shopify/ejson) — a utility for managing secrets in source control using public-key cryptography.

This is a drop-in replacement for the original Go implementation, with added support for **YAML** and **TOML** file formats and strong focus on performance and security.
Additionally it also integrate `ejson2env` into `ejson env` command for convenience.

![demo](./ejson-demo.gif)

See [ejsonkms](https://github.com/runlevel5/ejsonkms-rs) to manage secrets with the help of AWS KMS.

## Why ejson?

- **Safe version control** — Secrets can be safely stored in git
- **Auditable changes** — Track secret changes line-by-line with `git blame`
- **Easy access control** — Anyone with commit access can write secrets; decryption can be restricted to production servers
- **Synchronized deployments** — Secrets change with application source, not separately via config management
- **Battle-tested** — Simple, well-tested, easily-auditable source

## Why another port?

I am fully aware that of other Rust port like [rejson](https://github.com/pseudomuto/rejson) has a similar goal, but I wanted to create a more performant and secure implementation. Additionally I want to be fully in control of the codebase and have the ability to make changes that are specific to my needs.

## How It Works

Secrets are encrypted using public-key cryptography. Public keys are embedded in the secrets file, while private keys are stored separately on the filesystem. Two schemes are supported:

- **`v1` (default)** — legacy [NaCl](http://nacl.cr.yp.to/) [Box](http://nacl.cr.yp.to/box.html): [Curve25519](http://en.wikipedia.org/wiki/Curve25519) + XSalsa20 + Poly1305. Encrypted values look like `EJ[1:...]`.
- **`v2` (hybrid post-quantum)** — X25519 combined with [ML-KEM-768](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203); the two shared secrets are run through HKDF-SHA256 and values are encrypted with XChaCha20-Poly1305. Encrypted values look like `EJ[2:...]`. This protects against "harvest-now-decrypt-later" quantum attacks: an adversary must break *both* X25519 and ML-KEM. Generate `v2` keys with `ejson keygen --pqc`.

Both schemes interoperate within the same tool — existing `v1` keys and documents keep working unchanged, and `ejson decrypt`/`ejson encrypt` auto-detect the scheme from the document's `_public_key`.

## Installation

### Pre-built Binaries

Download compiled binaries from [Releases](https://github.com/runlevel5/ejson-rs/releases).

### Homebrew (macOS & Linux)

```bash
brew tap runlevel5/ejson-rs https://github.com/runlevel5/ejson-rs
brew install ejson
```

This installs the same prebuilt binary published to [Releases](https://github.com/runlevel5/ejson-rs/releases) — no compiler needed.

### Build from Source

```bash
git clone https://github.com/runlevel5/ejson-rs.git
cd ejson-rs
cargo build --release
cp ./target/release/ejson ~/.local/bin/
```

> **Note:** As of July 2026, there is no Deb package yet. A Fedora RPM spec lives in `build/rpm/`. Contributions welcome!

## Quick Start

### 1. Create the Key Directory

```bash
mkdir -p /opt/ejson/keys
```

> **macOS users:** You may need to grant write permissions:
> ```bash
> sudo chown -R $(whoami) /opt/ejson
> ```

You can customize the key location with `EJSON_KEYDIR` or the `--keydir` option.

### 2. Generate a Keypair

```bash
# Print keys to stdout
$ ejson keygen
Public Key:
63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f
Private Key:
75b80b4a693156eb435f4ed2fe397e583f461f09fd99ec2bd1bdef0a56cf6e64

# Write keys to keydir (recommended)
$ ejson keygen -w
53393332c6c7c474af603c078f5696c8fe16677a09a711bba299a6c1c1676a59
```

By default `keygen` generates a legacy `v1` keypair. To generate a hybrid
post-quantum `v2` keypair, use `--pqc` (or `--scheme v2`):

```bash
$ ejson keygen --pqc -w
v2:<base64 X25519 public key + ML-KEM-768 encapsulation key>
$ ls /opt/ejson/keys
<32-character key id>
```

Hybrid public keys are intentionally much longer than legacy keys because the full
ML-KEM encapsulation key is embedded in the document. This preserves the workflow where
anyone who can edit the document can add new secrets without access to the private
keydir. The `v2` private key is stored in an `ejson-key v2` file named by a 32-character
key ID (rather than the public key itself).

### 3. Create a Secrets File

Create `secrets.ejson` (or `.etoml` / `.eyaml`):

```json
{
  "_public_key": "<your-public-key>",
  "_database_username": "admin",
  "database_password": "supersecret123"
}
```

### 4. Encrypt

```bash
$ ejson encrypt secrets.ejson
```

Result:
```json
{
  "_public_key": "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f",
  "_database_username": "admin",
  "database_password": "EJ[1:WGj2t4znULHT1IRveMEdvvNXqZzNBNMsJ5iZVy6Dvxs=:kA6ekF8ViYR5ZLeSmMXWsdLfWr7wn9qS:fcHQtdt6nqcNOXa97/M278RX6w==]"
}
```

### 5. Decrypt

```bash
$ ejson decrypt secrets.ejson
```

The private key must be in the keydir. For `v1` keys the filename is the 64-character
hex public key; for `v2` keys it is the 32-character key ID. If you used
`ejson keygen -w` (or `keygen --pqc -w`), this is already set up.

#### Trimming Underscore Prefixes

When decrypting, you can strip the leading underscore from keys (except `_public_key`) using the `--trim-underscore-prefix` flag:

```bash
$ ejson decrypt --trim-underscore-prefix secrets.ejson
```

This transforms keys like `_database_username` to `database_username` in the output, which is useful when consuming decrypted secrets in systems that don't expect underscore-prefixed keys.

### 6. Export Environment Variables

The `ejson env` command extracts variables from the `environment` key and outputs them as shell export statements:

```bash
# Output export statements
$ ejson env secrets.ejson
export API_KEY='secret123'
export DATABASE_URL='postgres://localhost'

# Load into current shell
$ eval $(ejson env secrets.ejson)

# Output without "export" prefix (useful for .env files)
$ ejson env -q secrets.ejson > .env

# Strip leading underscores from variable names
$ ejson env --trim-underscore-prefix secrets.ejson

# In fish, this is auto-detected - no flag needed:
$ eval (ejson env secrets.ejson)
set -gx API_KEY 'secret123'
set -gx DATABASE_URL 'postgres://localhost'

# Force a specific shell's syntax instead of auto-detecting
$ ejson env --shell fish secrets.ejson
$ ejson env --shell posix secrets.ejson
```

**Input file example** (`secrets.ejson`):
```json
{
  "_public_key": "<public key>",
  "environment": {
    "DATABASE_URL": "<encrypted>",
    "API_KEY": "<encrypted>",
    "_ENVIRONMENT": "production"
  }
}
```

**Output**:
```bash
export API_KEY='decrypted-api-key'
export DATABASE_URL='decrypted-database-url'
export _ENVIRONMENT='production'
```

> **Underscore Prefix:** Keys prefixed with `_` (e.g., `_ENVIRONMENT`) are left **unencrypted** in the secrets file. This is useful for non-sensitive configuration values that you want to keep readable. Use `--trim-underscore-prefix` to strip the first leading underscore from variable names in the output (e.g., `_ENVIRONMENT` becomes `ENVIRONMENT`, but `__DOUBLE` becomes `_DOUBLE`).

> **Shell Compatibility:** By default, `ejson env` auto-detects the running shell (via `$FISH_VERSION`) and emits `export KEY='value'` for POSIX-compatible shells (**bash**, **zsh**, **sh**, **ksh**) or `set -gx KEY 'value'` for **fish**. Use `--shell posix` or `--shell fish` to force a specific syntax instead of auto-detecting. Other shells with different syntax (e.g. csh, tcsh) are not supported.

## Supported Formats

Format detection is automatic based on file extension:

| Format | Extensions |
|--------|------------|
| JSON   | `.ejson`, `.json` |
| TOML   | `.etoml`, `.toml` |
| YAML   | `.eyaml`, `.eyml`, `.yaml`, `.yml` |

### Encryption Rules

These rules apply to all formats:

1. **Public key required** — Must have a top-level `_public_key` field. For `v1` it is a 64-character hex key; for `v2` it begins with `v2:` followed by a base64-encoded X25519 public key plus ML-KEM-768 encapsulation key.
2. **Strings are encrypted** — All string values are encrypted by default
3. **Other types are not encrypted** — Numbers, booleans, nulls, dates remain plaintext
4. **Underscore prefix skips encryption** — Keys starting with `_` protect their immediate value
5. **Underscores don't propagate** — Nested values under `_key` are still encrypted unless they also have underscore prefixes
6. **Arrays work element-by-element** — String arrays have each element encrypted individually
7. **Encrypted values are schema-tagged** — legacy values are `EJ[1:<ephemeral public>:<nonce>:<ciphertext>]`; hybrid values are `EJ[2:<ephemeral X25519 public>:<ML-KEM ciphertext>:<nonce>:<ciphertext>]`. Existing `EJ[1:...]` values remain decryptable.

### Example: TOML

```toml
_public_key = "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f"

_database_username = "admin"           # Not encrypted (underscore prefix)
database_password = "supersecret123"   # Encrypted

[api]
secret_key = "api-secret-key"          # Encrypted
_endpoint = "https://api.example.com"  # Not encrypted
```

### Example: YAML

```yaml
_public_key: "63ccf05a9492e68e12eeb1c705888aebdcc0080af7e594fc402beb24cce9d14f"

_database_username: "admin"            # Not encrypted
database_password: "supersecret123"    # Encrypted

api:
  secret_key: "api-secret-key"         # Encrypted
  _endpoint: "https://api.example.com" # Not encrypted

allowed_hosts:                         # Each element encrypted
  - "host1.example.com"
  - "host2.example.com"
```

## Security

### File Permissions (Unix)

ejson-rs automatically applies restrictive file permissions to protect sensitive data:

| File Type | Permissions | Description |
|-----------|-------------|-------------|
| Private key files (`ejson keygen -w`) | `0o440` | Owner and group read-only |
| Decrypted output files (`ejson decrypt -o`) | `0o600` | Owner read/write only |

This ensures that:
- Private keys cannot be accidentally modified
- Decrypted secrets are not world-readable

> **Note:** On non-Unix platforms (e.g., Windows), these permission settings are not applied. Take care to manually secure sensitive files on these systems.

### Best Practices

- Store private keys only on systems that need to decrypt secrets
- Use `ejson keygen -w` to automatically save keys with proper permissions
- Avoid passing private keys via command-line arguments; use `--key-from-stdin` instead
- Add `*.ejson`, `*.etoml`, `*.eyaml` patterns to your deployment scripts to ensure secrets are decrypted at runtime

## Benchmarking

Comparing `ejson-rs` with the original Go `Shopify/ejson` and `Shopify/ejson2env` implementations:

| Metric     | Speed                             | Memory                                |
|------------|-----------------------------------|---------------------------------------|
| Keygen     | Rust is 1.03-1.35x faster than Go | Rust uses ~2.3x less RAM than Go      |
| Encryption | Rust is 1.02-1.53x faster than Go | Rust uses 1.58-4.33x less RAM than Go |
| Decryption | Rust is 1.3-1.6x faster than Go   | Rust uses 1.37-2.86x less RAM than Go |
| Env        | Rust is 1.3-4x faster than Go     | Rust uses 1.07-2.1x less RAM than Go  |

The Rust codes are 100% memory safe and all without the overhead of a runtime garbage collector like that of Go.
In conclusion, you can expect a smaller footprint and more secure/performant version of ejson.

## pre-commit hook

A [pre-commit](https://pre-commit.com/) hook is also supported to automatically run `ejson encrypt` on all `.ejson`, `.eyaml`, `.eyml`, `.etoml`, and `.toml` files in a repository.

To use, add the following to a `.pre-commit-config.yaml` file in your repository:

```yaml
repos:
  - repo: https://github.com/runlevel5/ejson-rs
    hooks:
      - id: run-ejson-encrypt
```

## manpage installation

Copy the man pages to your system's manpage directories:

```sh
sudo cp man/*.1 /usr/local/share/man/man1/
sudo cp man/*.5 /usr/local/share/man/man5/
sudo mandb
man ejson          # Command overview
man ejson.5        # File format specification
man ejson-keygen
man ejson-encrypt
man ejson-decrypt
man ejson-env
```

## See Also

- [Original ejson documentation](https://shopify.github.io/ejson)
- [rejson](https://github.com/pseudomuto/rejson) - yet another Rust port
