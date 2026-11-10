//! Benchmarks for encryption performance with large files.

use std::fs;
use std::time::Instant;
use tempfile::TempDir;

fn generate_large_json(num_entries: usize, pub_key: &str) -> String {
    let mut json = format!(r#"{{"_public_key": "{pub_key}""#);

    for i in 0..num_entries {
        json.push_str(&format!(
            r#", "secret_{i}": "This is a secret value number {i} with some additional text to make it longer""#
        ));
    }
    json.push('}');
    json
}

fn generate_large_toml(num_entries: usize, pub_key: &str) -> String {
    let mut toml = format!(r#"_public_key = "{pub_key}""#);
    toml.push('\n');

    for i in 0..num_entries {
        toml.push_str(&format!(
            r#"secret_{i} = "This is a secret value number {i} with some additional text to make it longer""#
        ));
        toml.push('\n');
    }
    toml
}

fn generate_large_yaml(num_entries: usize, pub_key: &str) -> String {
    let mut yaml = format!(r#"_public_key: "{pub_key}""#);
    yaml.push('\n');

    for i in 0..num_entries {
        yaml.push_str(&format!(
            r#"secret_{i}: "This is a secret value number {i} with some additional text to make it longer""#
        ));
        yaml.push('\n');
    }
    yaml
}

fn benchmark_format(format_name: &str, content: &str, extension: &str, iterations: usize) -> f64 {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join(format!("test.{extension}"));
    let file_size = content.len();

    let mut total_duration = std::time::Duration::ZERO;

    for _ in 0..iterations {
        // Write the file fresh each time
        fs::write(&file_path, content).unwrap();

        // Benchmark encryption
        let start = Instant::now();
        let _ = ejson::encrypt_file_in_place(&file_path).unwrap();
        total_duration += start.elapsed();
    }

    let avg_ms = total_duration.as_secs_f64() * 1000.0 / iterations as f64;
    let throughput_mb_s = (file_size as f64 / 1_000_000.0) / (avg_ms / 1000.0);

    println!(
        "{format_name:5}: {file_size:>8} bytes, avg {avg_ms:>8.2} ms, {throughput_mb_s:>6.2} MB/s"
    );

    avg_ms
}

fn main() {
    // Generate keypair
    let (pub_key, _priv_key, _) = ejson::generate_keypair_for_scheme("v1").unwrap();

    println!("=== Encryption Benchmark (avg of 5 runs) ===\n");

    for &num_entries in &[100, 500, 1000, 2000, 5000, 10000] {
        println!("--- {num_entries} entries ---");

        // JSON
        let json_content = generate_large_json(num_entries, &pub_key);
        benchmark_format("JSON", &json_content, "ejson", 5);

        // TOML
        let toml_content = generate_large_toml(num_entries, &pub_key);
        benchmark_format("TOML", &toml_content, "etoml", 5);

        // YAML
        let yaml_content = generate_large_yaml(num_entries, &pub_key);
        benchmark_format("YAML", &yaml_content, "eyaml", 5);

        println!();
    }

    // Test with very large entry count
    println!("=== Large Scale Test ===\n");
    for &num_entries in &[20000, 50000] {
        println!("--- {num_entries} entries ---");
        let json_content = generate_large_json(num_entries, &pub_key);
        benchmark_format("JSON", &json_content, "ejson", 3);

        let toml_content = generate_large_toml(num_entries, &pub_key);
        benchmark_format("TOML", &toml_content, "etoml", 3);

        let yaml_content = generate_large_yaml(num_entries, &pub_key);
        benchmark_format("YAML", &yaml_content, "eyaml", 3);
        println!();
    }
}
