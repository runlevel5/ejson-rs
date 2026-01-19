//! EJSON CLI - Manage encrypted secrets using public key encryption.
//!
//! Supports JSON (.ejson, .json), TOML (.etoml, .toml), and YAML (.eyaml, .eyml, .yaml, .yml) file formats.

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand};
use ejson::env::{export_env, export_quiet, read_and_export_env, ExportFunction};
use zeroize::Zeroizing;

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

        /// Strip the first leading underscore from variable names
        /// (e.g., _ENVIRONMENT becomes ENVIRONMENT, __KEY becomes _KEY)
        #[arg(long = "trim-underscore-prefix")]
        trim_underscore_prefix: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Keygen { keydir, write } => keygen_action(&keydir, write),
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
            trim_underscore_prefix,
        } => env_action(
            &file,
            &keydir,
            key_from_stdin,
            quiet,
            trim_underscore_prefix,
        ),
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn keygen_action(keydir: &str, write_flag: bool) -> Result<(), String> {
    let (pub_key, priv_key) =
        ejson::generate_keypair().map_err(|e| format!("Key generation failed: {e}"))?;

    // Wrap private key in Zeroizing for automatic cleanup
    let priv_key = Zeroizing::new(priv_key);

    if write_flag {
        let keydir_path = Path::new(keydir);
        let key_file = keydir_path.join(&pub_key);

        // Ensure keydir exists
        fs::create_dir_all(keydir_path).map_err(|e| format!("Failed to create keydir: {e}"))?;

        // Write private key with restrictive permissions
        // Use create_new(true) to ensure atomic creation with correct permissions
        // and to prevent accidentally overwriting an existing key
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o440)
            .open(&key_file)
            .map_err(|e| format!("Failed to write key file: {e}"))?;

        writeln!(file, "{}", *priv_key).map_err(|e| format!("Failed to write key: {e}"))?;

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
    }
    Ok(())
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
        let mut stdin_content = Zeroizing::new(String::new());
        io::stdin()
            .read_to_string(&mut stdin_content)
            .map_err(|e| format!("Failed to read from stdin: {e}"))?;
        Zeroizing::new(stdin_content.trim().to_string())
    } else {
        Zeroizing::new(String::new())
    };

    let decrypted = ejson::decrypt_file(
        file,
        keydir,
        &user_supplied_private_key,
        trim_underscore_prefix,
    )
    .map_err(|e| format!("Decryption failed: {e}"))?;

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

fn env_action(
    file: &Path,
    keydir: &str,
    key_from_stdin: bool,
    quiet: bool,
    trim_underscore_prefix: bool,
) -> Result<(), String> {
    // Use Zeroizing wrapper for private key to ensure it's cleared from memory
    let user_supplied_private_key: Zeroizing<String> = if key_from_stdin {
        let mut stdin_content = Zeroizing::new(String::new());
        io::stdin()
            .read_to_string(&mut stdin_content)
            .map_err(|e| format!("Failed to read from stdin: {e}"))?;
        Zeroizing::new(stdin_content.trim().to_string())
    } else {
        Zeroizing::new(String::new())
    };

    // Select the export function based on flags
    let export_func: ExportFunction = if quiet { export_quiet } else { export_env };

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

// Unix-specific extension for file permissions
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper to set up a test environment with keypair and encrypted file
    fn setup_test_env() -> (TempDir, TempDir, PathBuf, String) {
        // Generate a keypair
        let (pub_key, priv_key) = ejson::generate_keypair().unwrap();

        // Create a temporary keydir and write the private key
        let keydir = TempDir::new().unwrap();
        let key_file = keydir.path().join(&pub_key);
        fs::write(&key_file, &priv_key).unwrap();

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
        keygen_action(keydir, true).unwrap();

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
