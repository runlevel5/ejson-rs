//! End-to-end tests that run the compiled `ejson` binary.
//!
//! The unit tests call the action functions directly; these check what a user
//! actually gets: exit codes, what goes to stdout versus stderr, flags,
//! aliases and environment variables.

// Test helpers panic on failure by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

/// A command for the binary under test, isolated from the caller's environment.
fn ejson() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ejson"));
    cmd.env_remove("EJSON_KEYDIR").env_remove("FISH_VERSION");
    cmd
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("failed to run ejson")
}

fn run_with_stdin(cmd: &mut Command, input: &str) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run ejson");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[track_caller]
fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success, got {:?}\nstdout: {}\nstderr: {}",
        output.status,
        stdout(output),
        stderr(output)
    );
}

#[track_caller]
fn assert_fails_with(output: &Output, expected_stderr: &str) {
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(output));
    assert!(
        stderr(output).contains(expected_stderr),
        "stderr {:?} does not contain {expected_stderr:?}",
        stderr(output)
    );
}

/// A scratch directory with a keydir holding one freshly generated key.
struct Fixture {
    dir: TempDir,
    public_key: String,
}

impl Fixture {
    fn new(scheme: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let output = run(ejson()
            .args(["keygen", "-w", "--scheme", scheme, "-k"])
            .arg(dir.path().join("keys")));
        assert_success(&output);
        Self {
            public_key: stdout(&output).trim().to_string(),
            dir,
        }
    }

    fn keydir(&self) -> PathBuf {
        self.dir.path().join("keys")
    }

    fn private_key(&self) -> String {
        let entry = fs::read_dir(self.keydir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        fs::read_to_string(entry.path()).unwrap()
    }

    /// Write `contents` (with `PUBKEY` replaced by the public key) to `name`.
    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, contents.replace("PUBKEY", &self.public_key)).unwrap();
        path
    }

    /// Write a file and encrypt it in place.
    fn write_encrypted(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.write(name, contents);
        assert_success(&run(ejson().arg("encrypt").arg(&path)));
        path
    }

    fn decrypt(&self, path: &Path) -> Command {
        let mut cmd = ejson();
        cmd.arg("decrypt").arg("-k").arg(self.keydir()).arg(path);
        cmd
    }

    fn env(&self, path: &Path) -> Command {
        let mut cmd = ejson();
        cmd.arg("env").arg("-k").arg(self.keydir()).arg(path);
        cmd
    }
}

const JSON_DOC: &str = r#"{
  "_public_key": "PUBKEY",
  "_comment": "left alone",
  "password": "hunter2",
  "port": 5432,
  "nested": {"token": "abc123"}
}
"#;

// ---------------------------------------------------------------------------
// General
// ---------------------------------------------------------------------------

#[test]
fn version_and_help() {
    let version = run(ejson().arg("--version"));
    assert_success(&version);
    assert_eq!(
        stdout(&version).trim(),
        format!("ejson {}", env!("CARGO_PKG_VERSION"))
    );

    for args in [
        vec!["--help"],
        vec!["keygen", "--help"],
        vec!["encrypt", "--help"],
        vec!["decrypt", "--help"],
        vec!["env", "--help"],
    ] {
        assert_success(&run(ejson().args(&args)));
    }
}

#[test]
fn no_arguments_is_a_usage_error() {
    let output = run(&mut ejson());
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("Usage"));
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

#[test]
fn keygen_prints_both_keys_and_warns_on_stderr() {
    let output = run(ejson().arg("keygen"));
    assert_success(&output);

    let out = stdout(&output);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "Public Key:");
    assert_eq!(lines[1].len(), 64);
    assert_eq!(lines[2], "Private Key:");
    assert_eq!(lines[3].len(), 64);
    // The warning must not pollute stdout, which scripts parse.
    assert!(!out.contains("WARNING"));
    assert!(stderr(&output).contains("WARNING"));
}

#[test]
fn keygen_write_prints_only_the_public_key() {
    let fx = Fixture::new("v1");
    assert_eq!(fx.public_key.len(), 64);

    let key_file = fx.keydir().join(&fx.public_key);
    let private = fs::read_to_string(&key_file).unwrap();
    assert_eq!(private.trim().len(), 64);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o440);
    }
}

#[test]
fn keygen_pqc_and_alias_generate_a_v2_key() {
    let dir = TempDir::new().unwrap();
    let output = run(ejson().args(["g", "--pqc", "-w", "-k"]).arg(dir.path()));
    assert_success(&output);
    assert!(stdout(&output).starts_with("v2:"));

    let key_file = fs::read_dir(dir.path()).unwrap().next().unwrap().unwrap();
    assert!(
        fs::read_to_string(key_file.path())
            .unwrap()
            .starts_with("ejson-key v2\n")
    );
}

#[test]
fn keygen_rejects_an_unknown_scheme() {
    let output = run(ejson().args(["keygen", "--scheme", "v9"]));
    assert_fails_with(&output, "unsupported key scheme: v9");
}

#[test]
fn keydir_can_come_from_the_environment() {
    let dir = TempDir::new().unwrap();
    let output = run(ejson()
        .args(["keygen", "-w"])
        .env("EJSON_KEYDIR", dir.path()));
    assert_success(&output);
    assert!(dir.path().join(stdout(&output).trim()).exists());
}

// ---------------------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------------------

#[test]
fn encrypt_replaces_strings_and_leaves_the_rest() {
    let fx = Fixture::new("v1");
    let path = fx.write("secrets.ejson", JSON_DOC);

    let output = run(ejson().arg("encrypt").arg(&path));
    assert_success(&output);
    assert!(stdout(&output).starts_with("Wrote "));
    assert!(stdout(&output).contains("secrets.ejson"));

    let encrypted = fs::read_to_string(&path).unwrap();
    assert!(!encrypted.contains("hunter2"));
    assert!(!encrypted.contains("abc123"));
    assert!(encrypted.contains(r#""password": "EJ[1:"#));
    assert!(encrypted.contains(r#""token": "EJ[1:"#));
    assert!(encrypted.contains(r#""_comment": "left alone""#));
    assert!(encrypted.contains(r#""port": 5432"#));
    assert!(encrypted.contains(&fx.public_key));
}

#[test]
fn encrypt_is_idempotent() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", JSON_DOC);
    let first = fs::read(&path).unwrap();

    assert_success(&run(ejson().arg("e").arg(&path)));
    assert_eq!(fs::read(&path).unwrap(), first);
}

#[test]
fn encrypt_accepts_several_files_and_formats() {
    let fx = Fixture::new("v1");
    let json = fx.write("a.ejson", JSON_DOC);
    let yaml = fx.write("b.eyaml", "_public_key: PUBKEY\npassword: hunter2\n");
    let toml = fx.write(
        "c.ETOML",
        "_public_key = \"PUBKEY\"\npassword = \"hunter2\"\n",
    );

    let output = run(ejson().arg("encrypt").args([&json, &yaml, &toml]));
    assert_success(&output);
    assert_eq!(stdout(&output).lines().count(), 3);

    for path in [&json, &yaml, &toml] {
        let contents = fs::read_to_string(path).unwrap();
        assert!(!contents.contains("hunter2"), "{}", path.display());
        assert!(contents.contains("EJ[1:"), "{}", path.display());
    }
}

#[test]
fn encrypt_errors() {
    let fx = Fixture::new("v1");

    let missing = fx.dir.path().join("missing.ejson");
    assert_fails_with(
        &run(ejson().arg("encrypt").arg(&missing)),
        "Encryption failed",
    );

    let wrong_ext = fx.write("secrets.txt", JSON_DOC);
    assert_fails_with(
        &run(ejson().arg("encrypt").arg(&wrong_ext)),
        "unsupported file extension: txt",
    );

    let no_key = fx.write("nokey.ejson", r#"{"password": "hunter2"}"#);
    assert_fails_with(
        &run(ejson().arg("encrypt").arg(&no_key)),
        "public key not present",
    );
    // A failed encrypt must not touch the file.
    assert_eq!(
        fs::read_to_string(&no_key).unwrap(),
        r#"{"password": "hunter2"}"#
    );

    let duplicate = fx.write(
        "dup.ejson",
        r#"{"_public_key": "PUBKEY", "a": "b", "_public_key": "PUBKEY"}"#,
    );
    assert_fails_with(
        &run(ejson().arg("encrypt").arg(&duplicate)),
        "`_public_key` is defined more than once",
    );
}

#[test]
fn syntax_errors_do_not_print_the_secret() {
    let fx = Fixture::new("v1");
    let bad_toml = fx.write(
        "bad.etoml",
        "_public_key = \"PUBKEY\"\npassword = \"hunter2-supersecret\" oops\n",
    );
    let bad_yaml = fx.write(
        "bad.eyaml",
        "_public_key: PUBKEY\npin: !!int hunter2-supersecret\n",
    );

    for path in [bad_toml, bad_yaml] {
        let output = run(ejson().arg("encrypt").arg(&path));
        assert_fails_with(&output, "line 2");
        assert!(!stderr(&output).contains("hunter2"), "{}", stderr(&output));
        assert!(!stdout(&output).contains("hunter2"));
    }
}

// ---------------------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------------------

#[test]
fn decrypt_restores_the_original_json_exactly() {
    for scheme in ["v1", "v2"] {
        let fx = Fixture::new(scheme);
        let path = fx.write_encrypted("secrets.ejson", JSON_DOC);

        let output = run(&mut fx.decrypt(&path));
        assert_success(&output);
        assert_eq!(
            stdout(&output),
            JSON_DOC.replace("PUBKEY", &fx.public_key),
            "{scheme}"
        );
        assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    }
}

#[test]
fn decrypt_yaml_and_toml() {
    let fx = Fixture::new("v1");
    let yaml = fx.write_encrypted(
        "s.eyaml",
        "_public_key: PUBKEY\npassword: hunter2\ntagged: !secret hunter3\n",
    );
    let toml = fx.write_encrypted(
        "s.etoml",
        "_public_key = \"PUBKEY\"\npassword = \"hunter2\"\n",
    );

    let output = run(&mut fx.decrypt(&yaml));
    assert_success(&output);
    assert!(stdout(&output).contains("password: hunter2"));
    assert!(stdout(&output).contains("tagged: !secret hunter3"));

    let output = run(fx.decrypt(&toml).arg("--trim-underscore-prefix"));
    assert_success(&output);
    assert!(stdout(&output).contains("password = \"hunter2\""));
    // `_public_key` keeps its underscore.
    assert!(stdout(&output).contains("_public_key = "));
}

#[test]
fn decrypt_to_a_file_writes_nothing_to_stdout() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", JSON_DOC);
    let out_path = fx.dir.path().join("plain.json");
    fs::write(&out_path, "old contents").unwrap();

    let output = run(fx.decrypt(&path).arg("-o").arg(&out_path));
    assert_success(&output);
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read_to_string(&out_path).unwrap(),
        JSON_DOC.replace("PUBKEY", &fx.public_key)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // No temporary files are left next to the output.
    let leftovers: Vec<_> = fs::read_dir(fx.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn decrypt_with_key_from_stdin() {
    for scheme in ["v1", "v2"] {
        let fx = Fixture::new(scheme);
        let path = fx.write_encrypted("secrets.ejson", JSON_DOC);
        let private_key = fx.private_key();

        // Point the keydir somewhere empty: only stdin can supply the key.
        let empty = TempDir::new().unwrap();
        let output = run_with_stdin(
            ejson()
                .args(["d", "--key-from-stdin", "-k"])
                .arg(empty.path())
                .arg(&path),
            &private_key,
        );
        assert_success(&output);
        assert!(
            stdout(&output).contains(r#""password": "hunter2""#),
            "{scheme}"
        );
    }
}

#[test]
fn decrypt_trim_underscore_prefix() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", JSON_DOC);

    let output = run(fx.decrypt(&path).arg("--trim-underscore-prefix"));
    assert_success(&output);
    let out = stdout(&output);
    assert!(out.contains(r#""comment": "left alone""#));
    assert!(!out.contains("_comment"));
    assert!(out.contains("_public_key"));
}

#[test]
fn decrypt_errors() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", JSON_DOC);
    let prefix = &fx.public_key[..8];

    // No key in the keydir: names the key, not the path.
    let empty = TempDir::new().unwrap();
    let output = run(ejson().args(["decrypt", "-k"]).arg(empty.path()).arg(&path));
    assert_fails_with(
        &output,
        &format!("couldn't read key file for public key {prefix}...: not found in keydir"),
    );
    assert!(!stderr(&output).contains(empty.path().to_str().unwrap()));
    assert!(output.stdout.is_empty());

    // Wrong key on stdin.
    let other = Fixture::new("v1");
    let output = run_with_stdin(
        fx.decrypt(&path).arg("--key-from-stdin"),
        &other.private_key(),
    );
    assert_fails_with(&output, "couldn't decrypt message");
    assert!(output.stdout.is_empty());

    // Malformed key on stdin.
    let output = run_with_stdin(fx.decrypt(&path).arg("--key-from-stdin"), "not-a-key");
    assert_fails_with(&output, "invalid private key");

    // Tampered ciphertext: change one character of the first value's
    // encrypted payload, keeping it well-formed base64.
    let mut tampered = fs::read_to_string(&path).unwrap();
    let value_start = tampered.find("EJ[1:").unwrap();
    let value_end = value_start + tampered[value_start..].find(']').unwrap();
    let payload = value_start + tampered[value_start..value_end].rfind(':').unwrap() + 1;
    let replacement = if tampered.as_bytes()[payload] == b'A' {
        "B"
    } else {
        "A"
    };
    tampered.replace_range(payload..=payload, replacement);
    let tampered_path = fx.dir.path().join("tampered.ejson");
    fs::write(&tampered_path, tampered).unwrap();
    let output = run(&mut fx.decrypt(&tampered_path));
    assert_fails_with(&output, "couldn't decrypt message");
    assert!(output.stdout.is_empty());
}

#[test]
#[cfg(unix)]
fn decrypt_rejects_a_symlink_to_a_device() {
    let fx = Fixture::new("v1");
    let link = fx.dir.path().join("zero.ejson");
    std::os::unix::fs::symlink("/dev/zero", &link).unwrap();

    assert_fails_with(&run(&mut fx.decrypt(&link)), "not a regular file");
    assert_fails_with(
        &run(ejson().arg("encrypt").arg(&link)),
        "not a regular file",
    );
}

#[test]
#[cfg(unix)]
fn decrypt_warns_about_an_exposed_key_file() {
    use std::os::unix::fs::PermissionsExt;

    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", JSON_DOC);
    let key_file = fx.keydir().join(&fx.public_key);
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();

    let output = run(&mut fx.decrypt(&path));
    assert_success(&output);
    assert!(stderr(&output).contains("ejson: warning: key file for public key"));
    assert!(stderr(&output).contains("accessible by other users"));
    // The warning goes to stderr only; stdout is still exactly the document.
    assert_eq!(stdout(&output), JSON_DOC.replace("PUBKEY", &fx.public_key));
}

// ---------------------------------------------------------------------------
// env
// ---------------------------------------------------------------------------

const ENV_DOC: &str = r#"{
  "_public_key": "PUBKEY",
  "environment": {
    "API_KEY": "s3cr3t",
    "QUOTED": "it's",
    "_PLAIN": "visible",
    "NUMBER": 5
  },
  "other": "ignored"
}"#;

#[test]
fn env_exports_string_values_sorted() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", ENV_DOC);

    let output = run(fx.env(&path).args(["--shell", "posix"]));
    assert_success(&output);
    assert_eq!(
        stdout(&output),
        "export API_KEY='s3cr3t'\nexport QUOTED='it'\"'\"'s'\nexport _PLAIN='visible'\n"
    );
}

#[test]
fn env_quiet_fish_and_trim_flags() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", ENV_DOC);

    let quiet = run(fx.env(&path).args(["--shell", "posix", "-q"]));
    assert_success(&quiet);
    assert!(stdout(&quiet).starts_with("API_KEY='s3cr3t'\n"));
    assert!(!stdout(&quiet).contains("export"));

    let fish = run(fx.env(&path).args(["--shell", "fish"]));
    assert_success(&fish);
    assert!(stdout(&fish).starts_with("set -gx API_KEY 's3cr3t'\n"));

    let fish_quiet = run(fx.env(&path).args(["--shell", "fish", "--quiet"]));
    assert!(stdout(&fish_quiet).starts_with("set -g API_KEY 's3cr3t'\n"));

    let trimmed = run(fx
        .env(&path)
        .args(["--shell", "posix", "--trim-underscore-prefix"]));
    assert_success(&trimmed);
    assert!(stdout(&trimmed).contains("export PLAIN='visible'\n"));
    assert!(!stdout(&trimmed).contains("_PLAIN"));
}

#[test]
fn env_auto_follows_fish_version() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", ENV_DOC);

    let posix = run(&mut fx.env(&path));
    assert!(stdout(&posix).starts_with("export API_KEY="));

    let fish = run(fx.env(&path).env("FISH_VERSION", "4.0.0"));
    assert!(stdout(&fish).starts_with("set -gx API_KEY "));
}

#[test]
fn env_without_an_environment_key_prints_nothing() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", JSON_DOC);

    let output = run(&mut fx.env(&path));
    assert_success(&output);
    assert!(output.stdout.is_empty());
}

#[test]
fn env_rejects_names_that_are_not_identifiers() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted(
        "secrets.ejson",
        r#"{"_public_key": "PUBKEY", "environment": {"BAD; touch pwned": "x"}}"#,
    );

    let output = run(&mut fx.env(&path));
    assert_fails_with(&output, "invalid identifier");
    assert!(output.stdout.is_empty());
}

#[test]
fn env_with_key_from_stdin() {
    let fx = Fixture::new("v1");
    let path = fx.write_encrypted("secrets.ejson", ENV_DOC);
    let empty = TempDir::new().unwrap();

    let output = run_with_stdin(
        ejson()
            .args(["env", "--shell", "posix", "--key-from-stdin", "-k"])
            .arg(empty.path())
            .arg(&path),
        &fx.private_key(),
    );
    assert_success(&output);
    assert!(stdout(&output).contains("export API_KEY='s3cr3t'"));
}
