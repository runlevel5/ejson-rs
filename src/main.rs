//! EJSON CLI - Manage encrypted secrets using public key encryption.
//!
//! Supports JSON (.ejson, .json), TOML (.etoml, .toml), and YAML (.eyaml, .eyml, .yaml, .yml) file formats.

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use ejson::env::{
    ExportFunction, export_env, export_env_auto, export_env_fish, export_quiet, export_quiet_auto,
    export_quiet_fish, read_and_export_env,
};
use zeroize::Zeroizing;

/// Which shell syntax to emit environment variable assignments in.
#[derive(ValueEnum, Clone, Copy, Debug, Default)]
enum ShellArg {
    /// Fish syntax if `$FISH_VERSION` is set, otherwise POSIX. Fish doesn't
    /// export it, so under fish this is usually POSIX, which fish also accepts.
    #[default]
    Auto,
    /// POSIX-compatible shells (bash, zsh, sh, ...): `export KEY='value'`
    Posix,
    /// Fish shell: `set -gx KEY 'value'`
    Fish,
}

/// Manage encrypted secrets using public key encryption.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new EJSON keypair
    #[command(alias = "g")]
    Keygen {
        /// Directory containing EJSON keys
        #[arg(
            short = 'k',
            long = "keydir",
            default_value = "/opt/ejson/keys",
            env = "EJSON_KEYDIR"
        )]
        keydir: String,

        /// Write private key to keydir, print only public key
        #[arg(short = 'w', long = "write")]
        write: bool,

        /// Key scheme to generate: v1 (legacy NaCl box) or v2 (hybrid post-quantum)
        #[arg(long = "scheme", default_value = "v1")]
        scheme: String,

        /// Generate a v2 hybrid X25519 + ML-KEM-768 keypair (alias for --scheme v2)
        #[arg(long = "pqc")]
        pqc: bool,
    },

    /// (Re-)encrypt one or more EJSON/ETOML/EYAML files
    #[command(alias = "e")]
    Encrypt {
        /// Files to encrypt (format detected by extension: .ejson/.json, .etoml/.toml, or .eyaml/.eyml/.yaml/.yml)
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },

    /// Decrypt an EJSON/ETOML/EYAML file
    #[command(alias = "d")]
    Decrypt {
        /// Directory containing EJSON keys
        #[arg(
            short = 'k',
            long = "keydir",
            default_value = "/opt/ejson/keys",
            env = "EJSON_KEYDIR"
        )]
        keydir: String,

        /// File to decrypt (format detected by extension: .ejson/.json, .etoml/.toml, or .eyaml/.eyml/.yaml/.yml)
        file: PathBuf,

        /// Print output to the provided file, rather than stdout
        #[arg(short = 'o')]
        output: Option<PathBuf>,

        /// Read the private key from STDIN
        #[arg(long = "key-from-stdin")]
        key_from_stdin: bool,

        /// Strip the first leading underscore from keys in the output
        #[arg(long = "trim-underscore-prefix")]
        trim_underscore_prefix: bool,
    },

    /// Export environment variables from the 'environment' key in an EJSON/ETOML/EYAML file
    Env {
        /// Directory containing EJSON keys
        #[arg(
            short = 'k',
            long = "keydir",
            default_value = "/opt/ejson/keys",
            env = "EJSON_KEYDIR"
        )]
        keydir: String,

        /// File to read (format detected by extension: .ejson/.json, .etoml/.toml, or .eyaml/.eyml/.yaml/.yml)
        file: PathBuf,

        /// Read the private key from STDIN
        #[arg(long = "key-from-stdin")]
        key_from_stdin: bool,

        /// Suppress export statement (output: KEY='value' instead of export KEY='value')
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,

        /// Shell syntax to emit. Defaults to auto-detecting fish via $FISH_VERSION,
        /// otherwise POSIX.
        #[arg(long = "shell", value_enum, default_value_t = ShellArg::Auto)]
        shell: ShellArg,

        /// Strip the first leading underscore from variable names
        /// (e.g., _ENVIRONMENT becomes ENVIRONMENT, __KEY becomes _KEY)
        #[arg(long = "trim-underscore-prefix")]
        trim_underscore_prefix: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    // Every command except `encrypt` handles private keys or plaintext.
    if !matches!(cli.command, Commands::Encrypt { .. }) {
        disable_core_dumps();
    }

    let result = match cli.command {
        Commands::Keygen {
            keydir,
            write,
            scheme,
            pqc,
        } => {
            let scheme = if pqc { "v2".to_string() } else { scheme };
            keygen_action(&keydir, write, &scheme)
        }
        Commands::Encrypt { files } => encrypt_action(&files),
        Commands::Decrypt {
            keydir,
            file,
            output,
            key_from_stdin,
            trim_underscore_prefix,
        } => decrypt_action(
            &file,
            &keydir,
            output.as_deref(),
            key_from_stdin,
            trim_underscore_prefix,
        ),
        Commands::Env {
            keydir,
            file,
            key_from_stdin,
            quiet,
            shell,
            trim_underscore_prefix,
        } => env_action(
            &file,
            &keydir,
            key_from_stdin,
            quiet,
            shell,
            trim_underscore_prefix,
        ),
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        process::exit(1);
    }
}

/// Keep private keys and decrypted secrets out of core dumps.
///
/// Zeroizing only wipes the final copy of a buffer, so a crash dump could
/// still contain key material or plaintext. Best effort: failures are
/// ignored, since none of this is needed for correctness.
fn disable_core_dumps() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let _ = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        );
    }

    // Not dumpable also stops other processes of the same user from
    // attaching with ptrace or reading /proc/<pid>/mem.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    }
}

fn keygen_action(keydir: &str, write_flag: bool, scheme: &str) -> Result<(), String> {
    let (pub_key, priv_key, key_id) = ejson::generate_keypair_for_scheme(scheme)
        .map_err(|e| format!("Key generation failed: {e}"))?;

    if write_flag {
        let keydir_path = Path::new(keydir);
        // The keydir filename is the key ID (the hex public key for v1, a short id for v2).
        let key_file = keydir_path.join(&key_id);

        // Ensure keydir exists. Directories we create are not world-accessible;
        // the group keeps access to match the 0o440 key files.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(keydir_path)
            .map_err(|e| format!("Failed to create keydir: {e}"))?;

        // Write private key with restrictive permissions
        // Use create_new(true) to ensure atomic creation with correct permissions
        // and to prevent accidentally overwriting an existing key
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o440)
            .open(&key_file)
            .map_err(|e| format!("Failed to write key file: {e}"))?;

        // Ensure the file ends with exactly one trailing newline (v2 bodies are
        // multi-line). Build the buffer inside Zeroizing so this copy of the private
        // key is wiped from memory on drop.
        let mut contents = Zeroizing::new(String::with_capacity(priv_key.len() + 1));
        contents.push_str(&priv_key);
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("Failed to write key: {e}"))?;

        println!("{pub_key}");
    } else {
        // Print warning to stderr before displaying the private key
        eprintln!("WARNING: The private key will be displayed below.");
        eprintln!("         This key should be kept secret and stored securely.");
        eprintln!("         Consider using 'ejson keygen -w' to write directly to keydir.");
        eprintln!("         Terminal scrollback may retain this key.");
        eprintln!();
        println!("Public Key:\n{pub_key}\nPrivate Key:\n{}", *priv_key);
    }

    Ok(())
}

fn encrypt_action(files: &[PathBuf]) -> Result<(), String> {
    for file_path in files {
        let n = ejson::encrypt_file_in_place(file_path)
            .map_err(|e| format!("Encryption failed: {e}"))?;

        println!("Wrote {n} bytes to {}.", file_path.display());
        warn_plaintext_yaml_scalars(file_path);
    }
    Ok(())
}

/// Warn about YAML values that stayed in plaintext only because YAML parsed
/// them as numbers or booleans (e.g. an unquoted `pin: 123456`).
fn warn_plaintext_yaml_scalars(file_path: &Path) {
    if !matches!(
        ejson::FileFormat::from_path(file_path),
        Ok(ejson::FileFormat::Yaml)
    ) {
        return;
    }
    let Ok(data) = fs::read(file_path) else {
        return;
    };
    let Ok(paths) = ejson::yaml::plaintext_scalar_paths(&data) else {
        return;
    };
    if paths.is_empty() {
        return;
    }

    eprintln!(
        "warning: {}: these values are numbers or booleans in YAML, so they were \
         left unencrypted: {}",
        file_path.display(),
        paths.join(", ")
    );
    eprintln!("         Quote them (e.g. pin: \"123456\") to have them encrypted.");
}

fn decrypt_action(
    file: &Path,
    keydir: &str,
    output: Option<&Path>,
    key_from_stdin: bool,
    trim_underscore_prefix: bool,
) -> Result<(), String> {
    // Use Zeroizing wrapper for private key to ensure it's cleared from memory
    let user_supplied_private_key: Zeroizing<String> = if key_from_stdin {
        read_key_from_stdin()?
    } else {
        Zeroizing::new(String::new())
    };

    let decrypted = Zeroizing::new(
        ejson::decrypt_file(
            file,
            keydir,
            &user_supplied_private_key,
            trim_underscore_prefix,
        )
        .map_err(|e| format!("Decryption failed: {e}"))?,
    );

    if let Some(out_path) = output {
        // Write decrypted output with restrictive permissions
        // Use atomic write pattern: write to temp file, then rename
        // This prevents race conditions and ensures correct permissions

        let parent = out_path.parent().unwrap_or(Path::new("."));

        // Create a temporary file in the same directory for atomic rename
        let temp_path = parent.join(format!(".ejson_decrypt_{}.tmp", std::process::id()));

        // Write to temp file with restrictive permissions
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp_path)
                .map_err(|e| format!("Failed to create temporary file: {e}"))?;
            file.write_all(&decrypted)
                .map_err(|e| format!("Failed to write temporary file: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("Failed to sync temporary file: {e}"))?;
        }

        // Atomic rename to final destination
        fs::rename(&temp_path, out_path).map_err(|e| {
            // Clean up temp file on error
            let _ = fs::remove_file(&temp_path);
            format!("Failed to rename temporary file to output: {e}")
        })?;
    } else {
        io::stdout()
            .write_all(&decrypted)
            .map_err(|e| format!("Failed to write to stdout: {e}"))?;
    }

    Ok(())
}

/// Read a private key from stdin, refusing input larger than any real key.
fn read_key_from_stdin() -> Result<Zeroizing<String>, String> {
    let mut stdin_content = Zeroizing::new(String::new());
    io::stdin()
        .take(ejson::MAX_KEY_FILE_SIZE + 1)
        .read_to_string(&mut stdin_content)
        .map_err(|e| format!("Failed to read from stdin: {e}"))?;
    if stdin_content.len() as u64 > ejson::MAX_KEY_FILE_SIZE {
        return Err(format!(
            "Private key on stdin is larger than {} bytes",
            ejson::MAX_KEY_FILE_SIZE
        ));
    }
    Ok(Zeroizing::new(stdin_content.trim().to_string()))
}

fn env_action(
    file: &Path,
    keydir: &str,
    key_from_stdin: bool,
    quiet: bool,
    shell: ShellArg,
    trim_underscore_prefix: bool,
) -> Result<(), String> {
    // Use Zeroizing wrapper for private key to ensure it's cleared from memory
    let user_supplied_private_key: Zeroizing<String> = if key_from_stdin {
        read_key_from_stdin()?
    } else {
        Zeroizing::new(String::new())
    };

    // Select the export function based on flags
    let export_func: ExportFunction = match (shell, quiet) {
        (ShellArg::Auto, true) => export_quiet_auto,
        (ShellArg::Auto, false) => export_env_auto,
        (ShellArg::Posix, true) => export_quiet,
        (ShellArg::Posix, false) => export_env,
        (ShellArg::Fish, true) => export_quiet_fish,
        (ShellArg::Fish, false) => export_env_fish,
    };

    // Get stdout handle with buffering for better performance
    let mut stdout = BufWriter::new(io::stdout());

    // Execute with the trim flag passed to the library
    read_and_export_env(
        file,
        keydir,
        &user_supplied_private_key,
        trim_underscore_prefix,
        export_func,
        &mut stdout,
    )
    .map_err(|e| format!("Failed to export environment: {e}"))?;

    // Ensure all buffered output is flushed
    stdout
        .flush()
        .map_err(|e| format!("Failed to flush output: {e}"))?;

    Ok(())
}

// Unix-specific extensions for file and directory permissions
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

#[cfg(not(unix))]
trait OpenOptionsExt {
    fn mode(&mut self, _mode: u32) -> &mut Self;
}

#[cfg(not(unix))]
impl OpenOptionsExt for fs::OpenOptions {
    fn mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

#[cfg(not(unix))]
trait DirBuilderExt {
    fn mode(&mut self, _mode: u32) -> &mut Self;
}

#[cfg(not(unix))]
impl DirBuilderExt for fs::DirBuilder {
    fn mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper to set up a test environment with keypair and encrypted file
    fn setup_test_env() -> (TempDir, TempDir, PathBuf, String) {
        // Generate a keypair
        let (pub_key, priv_key, _) = ejson::generate_keypair_for_scheme("v1").unwrap();

        // Create a temporary keydir and write the private key
        let keydir = TempDir::new().unwrap();
        let key_file = keydir.path().join(&pub_key);
        fs::write(&key_file, priv_key.as_bytes()).unwrap();

        // Create a temporary directory for test files
        let temp_dir = TempDir::new().unwrap();

        // Create an encrypted ejson file
        let ejson_path = temp_dir.path().join("secrets.ejson");
        let json_content =
            format!(r#"{{"_public_key": "{pub_key}", "secret": "my secret value"}}"#);
        fs::write(&ejson_path, &json_content).unwrap();

        // Encrypt the file
        ejson::encrypt_file_in_place(&ejson_path).unwrap();

        (keydir, temp_dir, ejson_path, pub_key)
    }

    #[test]
    #[cfg(unix)]
    fn test_decrypt_output_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (keydir, temp_dir, ejson_path, _) = setup_test_env();

        // Define output path for decrypted file
        let output_path = temp_dir.path().join("decrypted.json");

        // Run decrypt_action with output file
        decrypt_action(
            &ejson_path,
            keydir.path().to_str().unwrap(),
            Some(output_path.as_path()),
            false,
            false,
        )
        .unwrap();

        // Verify the output file exists
        assert!(output_path.exists());

        // Verify the output file has restrictive permissions (0o600)
        let metadata = fs::metadata(&output_path).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777; // Mask to get only permission bits

        assert_eq!(
            mode, 0o600,
            "Decrypted output file should have 0o600 permissions, got 0o{:o}",
            mode
        );

        // Verify the content was actually decrypted
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("my secret value"));
    }

    #[test]
    #[cfg(unix)]
    fn test_keygen_key_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        // Run keygen with write flag
        keygen_action(keydir, true, "v1").unwrap();

        // Find the key file (should be the only file in keydir)
        let entries: Vec<_> = fs::read_dir(keydir).unwrap().collect();
        assert_eq!(entries.len(), 1, "Expected exactly one key file");

        let key_file = entries[0].as_ref().unwrap().path();

        // Verify the key file has restrictive permissions (0o440)
        let metadata = fs::metadata(&key_file).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode() & 0o777;

        assert_eq!(
            mode, 0o440,
            "Key file should have 0o440 permissions, got 0o{:o}",
            mode
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_keygen_creates_keydir_without_world_access() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().join("a").join("keys");

        keygen_action(keydir.to_str().unwrap(), true, "v1").unwrap();

        for dir in [keydir.parent().unwrap(), keydir.as_path()] {
            let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode & 0o007, 0, "{} is 0o{mode:o}", dir.display());
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_keygen_hybrid_writes_keyid_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let keydir = temp_dir.path().to_str().unwrap();

        keygen_action(keydir, true, "v2").unwrap();

        let entries: Vec<_> = fs::read_dir(keydir).unwrap().collect();
        assert_eq!(entries.len(), 1, "Expected exactly one key file");
        let key_file = entries[0].as_ref().unwrap().path();

        // The keydir filename for a hybrid key is a 32-char key ID.
        assert_eq!(
            key_file.file_name().unwrap().to_str().unwrap().len(),
            32,
            "Hybrid key file should be named by a 32-char key id"
        );

        // The file body is the multi-line `ejson-key v2` private key.
        let contents = fs::read_to_string(&key_file).unwrap();
        assert!(contents.starts_with("ejson-key v2\n"));

        let mode = fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o440, "got 0o{mode:o}");
    }

    #[test]
    fn test_decrypt_action_writes_correct_content() {
        let (keydir, temp_dir, ejson_path, _) = setup_test_env();

        let output_path = temp_dir.path().join("decrypted.json");

        decrypt_action(
            &ejson_path,
            keydir.path().to_str().unwrap(),
            Some(output_path.as_path()),
            false,
            false,
        )
        .unwrap();

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("my secret value"));
        assert!(!content.contains("EJ["));
    }

    #[test]
    fn test_decrypt_atomic_write_overwrites_existing() {
        let (keydir, temp_dir, ejson_path, _) = setup_test_env();

        let output_path = temp_dir.path().join("decrypted.json");

        // Create an existing file
        fs::write(&output_path, "old content").unwrap();

        // Decrypt should overwrite atomically
        decrypt_action(
            &ejson_path,
            keydir.path().to_str().unwrap(),
            Some(output_path.as_path()),
            false,
            false,
        )
        .unwrap();

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("my secret value"));
        assert!(!content.contains("old content"));
    }
}
