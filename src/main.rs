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
#[command(version = "0.0.3")]
#[command(author = "Trung Lê <8@tle.id.au>")]
#[command(about = "Manage encrypted secrets using public key encryption")]
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
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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
        fs::write(out_path, &decrypted)
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
