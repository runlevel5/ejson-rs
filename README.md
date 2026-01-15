# ejson-rs

A Rust implementation of [Shopify/ejson](https://github.com/Shopify/ejson) — a utility for managing secrets in source control using public-key cryptography.

This is a drop-in replacement for the original Go implementation, with added support for **YAML** and **TOML** file formats.

![demo](http://burkelibbey.s3.amazonaws.com/ejson-demo.gif)

See [ejson2env-rs](https://github.com/runlevel5/ejson2env-rs) for a useful tool to help with exporting a portion of secrets as environment variables for environments/tools that require this pattern.

## Why ejson?

- **Safe version control** — Secrets can be safely stored in git
- **Auditable changes** — Track secret changes line-by-line with `git blame`
- **Easy access control** — Anyone with commit access can write secrets; decryption can be restricted to production servers
- **Synchronized deployments** — Secrets change with application source, not separately via config management
- **Battle-tested** — Simple, well-tested, easily-auditable source

## How It Works

Secrets are encrypted using public-key, elliptic curve cryptography ([NaCl](http://nacl.cr.yp.to/) [Box](http://nacl.cr.yp.to/box.html): [Curve25519](http://en.wikipedia.org/wiki/Curve25519) + [Salsa20](http://en.wikipedia.org/wiki/Salsa20) + [Poly1305-AES](http://en.wikipedia.org/wiki/Poly1305-AES)). Public keys are embedded in the secrets file, while private keys are stored separately on the filesystem.

## Installation

### Pre-built Binaries

Download compiled binaries from [Releases](https://github.com/runlevel5/ejson-rs/releases).

### Build from Source

```bash
git clone https://github.com/runlevel5/ejson-rs.git
cd ejson-rs
cargo build --release
cp ./target/release/ejson ~/.local/bin/
```

> **Note:** As of January 2026, there are no Homebrew, Deb, or RPM packages. Contributions welcome!

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

The private key must be in the keydir, named after the public key. If you used `ejson keygen -w`, this is already set up.

## Supported Formats

Format detection is automatic based on file extension:

| Format | Extensions |
|--------|------------|
| JSON   | `.ejson`, `.json` |
| TOML   | `.etoml`, `.toml` |
| YAML   | `.eyaml`, `.yaml`, `.yml` |

### Encryption Rules

These rules apply to all formats:

1. **Public key required** — Must have a top-level `_public_key` field
2. **Strings are encrypted** — All string values are encrypted by default
3. **Other types are not encrypted** — Numbers, booleans, nulls, dates remain plaintext
4. **Underscore prefix skips encryption** — Keys starting with `_` protect their immediate value
5. **Underscores don't propagate** — Nested values under `_key` are still encrypted unless they also have underscore prefixes
6. **Arrays work element-by-element** — String arrays have each element encrypted individually

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

## See Also

- [Original ejson documentation](https://shopify.github.io/ejson)
- Use with [pre-commit](https://pre-commit.com/) to automatically encrypt secrets on commit
