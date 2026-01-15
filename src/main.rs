//! EJSON CLI - Manage encrypted secrets using public key encryption.
//!
//! Supports JSON (.ejson, .json), TOML (.etoml, .toml), and YAML (.eyaml, .yaml, .yml) file formats.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

/// Manage encrypted secrets using public key encryption.
#[derive(Parser)]
#[command(name = "ejson")]
#[command(version, author, about)]
struct Cli {
    /// Directory containing EJSON keys
    #[arg(
        short = 'k',
        long = "keydir",
        default_value = "/opt/ejson/keys",
        env = "EJSON_KEYDIR",
        global = true
    )]
    keydir: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new EJSON keypair
    #[command(alias = "g")]
    Keygen {
        /// Write private key to keydir, print only public key
        #[arg(short = 'w', long = "write")]
        write: bool,
    },

    /// (Re-)encrypt one or more EJSON/ETOML/EYAML files
    #[command(alias = "e")]
    Encrypt {
        /// Files to encrypt (format detected by extension: .ejson/.json, .etoml/.toml, or .eyaml/.yaml/.yml)
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },

    /// Decrypt an EJSON/ETOML/EYAML file
    #[command(alias = "d")]
    Decrypt {
        /// File to decrypt (format detected by extension: .ejson/.json, .etoml/.toml, or .eyaml/.yaml/.yml)
        file: PathBuf,

        /// Print output to the provided file, rather than stdout
        #[arg(short = 'o')]
        output: Option<PathBuf>,

        /// Read the private key from STDIN
        #[arg(long = "key-from-stdin")]
        key_from_stdin: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Keygen { write } => keygen_action(&cli.keydir, write),
        Commands::Encrypt { files } => encrypt_action(&files),
        Commands::Decrypt {
            file,
            output,
            key_from_stdin,
        } => decrypt_action(&file, &cli.keydir, output.as_deref(), key_from_stdin),
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn keygen_action(keydir: &str, write_flag: bool) -> Result<(), String> {
    let (pub_key, priv_key) =
        ejson::generate_keypair().map_err(|e| format!("Key generation failed: {}", e))?;

    if write_flag {
        let key_file = format!("{}/{}", keydir, pub_key);

        // Ensure keydir exists
        fs::create_dir_all(keydir).map_err(|e| format!("Failed to create keydir: {}", e))?;

        // Write private key with restrictive permissions
        // Use create_new(true) to ensure atomic creation with correct permissions
        // and to prevent accidentally overwriting an existing key
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o440)
            .open(&key_file)
            .map_err(|e| format!("Failed to write key file: {}", e))?;

        writeln!(file, "{}", priv_key).map_err(|e| format!("Failed to write key: {}", e))?;

        println!("{}", pub_key);
    } else {
        println!("Public Key:\n{}\nPrivate Key:\n{}", pub_key, priv_key);
    }

    Ok(())
}

fn encrypt_action(files: &[PathBuf]) -> Result<(), String> {
    for file_path in files {
        let n = ejson::encrypt_file_in_place(file_path)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        println!("Wrote {} bytes to {}.", n, file_path.display());
    }
    Ok(())
}

fn decrypt_action(
    file: &PathBuf,
    keydir: &str,
    output: Option<&std::path::Path>,
    key_from_stdin: bool,
) -> Result<(), String> {
    let user_supplied_private_key = if key_from_stdin {
        let mut stdin_content = String::new();
        io::stdin()
            .read_to_string(&mut stdin_content)
            .map_err(|e| format!("Failed to read from stdin: {}", e))?;
        stdin_content.trim().to_string()
    } else {
        String::new()
    };

    let decrypted = ejson::decrypt_file(file, keydir, &user_supplied_private_key)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    if let Some(out_path) = output {
        // Write decrypted output with restrictive permissions (owner read/write only)
        // Use create_new(true) to atomically create with correct permissions,
        // preventing a window where the file has incorrect permissions.
        // If file exists, remove it first and create fresh to ensure correct permissions.
        if out_path.exists() {
            fs::remove_file(out_path)
                .map_err(|e| format!("Failed to remove existing output file: {}", e))?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out_path)
            .map_err(|e| format!("Failed to create output file: {}", e))?;
        file.write_all(&decrypted)
            .map_err(|e| format!("Failed to write output file: {}", e))?;
    } else {
        io::stdout()
            .write_all(&decrypted)
            .map_err(|e| format!("Failed to write to stdout: {}", e))?;
    }

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
        let json_content = format!(
            r#"{{"_public_key": "{}", "secret": "my secret value"}}"#,
            pub_key
        );
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
        )
        .unwrap();

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("my secret value"));
        assert!(!content.contains("EJ["));
    }
}
