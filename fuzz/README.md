# Fuzzing

Fuzz targets for the parsers that read untrusted input. Anyone with a
document's public key can write a secrets file, so every byte of a document,
and of an `EJ[...]` value in it, is attacker-controlled.

| Target           | Checks                                                                                                    |
| ---------------- | --------------------------------------------------------------------------------------------------------- |
| `boxed_message`  | `EJ[1:…]`/`EJ[2:…]` parsing never panics, round-trips, and `is_boxed_message` never accepts a value neither parser can load (it would be left in plaintext on encrypt) |
| `json_walk`      | The hand-written JSON walker never panics and, with an identity action, yields exactly the document `serde_json` parses |
| `yaml_toml_walk` | The YAML and TOML walkers and key-trimming never panic, and an identity walk doesn't change the document |
| `key_file`       | Parsing keydir / `--key-from-stdin` key material for `v1` and `v2` never panics                           |
| `decrypt`        | Decrypting an arbitrary JSON/YAML/TOML document with a real `v1` or `v2` key never panics                  |

## Running

Requires nightly Rust and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz run json_walk fuzz/corpus/json_walk fuzz/seeds/json_walk -- \
    -max_total_time=300 -dict=fuzz/json.dict
```

`fuzz/seeds/<target>` holds small hand-made starting inputs (encrypted with
throwaway keys whose private halves were never committed; the `key_file` seeds
are synthetic all-zero keys). New interesting inputs are written to
`fuzz/corpus/<target>` and crashes to `fuzz/artifacts/<target>`; both are
git-ignored.

To reproduce a crash, including one uploaded by the `Fuzz` workflow:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

The `decrypt` target's first input byte picks the key (bit 0: `v1`/`v2`) and
format (JSON/YAML/TOML); the string `PUBKEY` in the rest is replaced with the
real public key.
