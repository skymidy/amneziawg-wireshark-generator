use anyhow::{bail, Context, Result};
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// List available network interfaces using tshark -D
pub fn list_interfaces() -> Result<Vec<String>> {
    let output = Command::new("tshark")
        .arg("-D")
        .output()
        .context("Failed to run tshark. Is Wireshark installed and tshark in PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("tshark -D failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interfaces: Vec<String> = stdout
        .lines()
        .map(|line| line.to_string())
        .collect();

    Ok(interfaces)
}

/// Capture TLS ClientHello signatures matching the domain pattern
pub fn capture_signatures(
    interface: &str,
    domain_pattern: &str,
    count: usize,
    timeout_secs: u64,
    verbose: bool,
) -> Result<Vec<String>> {
    let domain_regex = Regex::new(domain_pattern)
        .context("Invalid domain regex pattern")?;

    // Build tshark command
    // We capture TLS ClientHello packets and extract SNI + TCP payload
    // Use -a duration: for reliable timeout (tshark exits after N seconds)
    let duration_arg = format!("duration:{}", timeout_secs);
    let mut child = Command::new("tshark")
        .args([
            "-i", interface,
            "-a", &duration_arg,
            "-f", "tcp port 443",
            "-Y", "tls.handshake.type == 1",
            "-T", "fields",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "tcp.payload",
            "-E", "separator=|",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn tshark process")?;

    let stdout = child.stdout.take().context("Failed to get stdout")?;
    let reader = BufReader::new(stdout);

    let mut signatures = Vec::new();

    // tshark will exit after timeout_secs via -a duration flag
    // The loop ends when tshark closes stdout
    for line in reader.lines() {
        // Check if we have enough signatures
        if signatures.len() >= count {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(e) => {
                if verbose {
                    eprintln!("Error reading line: {}", e);
                }
                continue;
            }
        };

        if line.is_empty() {
            continue;
        }

        // Parse the output: SNI|payload_hex
        let parts: Vec<&str> = line.splitn(2, '|').collect();
        if parts.len() < 2 {
            if verbose {
                eprintln!("Malformed line: {}", line);
            }
            continue;
        }

        let sni = parts[0];
        let payload_hex = parts[1];

        // Check if SNI matches domain pattern
        if !domain_regex.is_match(sni) {
            if verbose {
                println!("Skipping non-matching domain: {}", sni);
            }
            continue;
        }

        if payload_hex.is_empty() {
            if verbose {
                eprintln!("Empty payload for: {}", sni);
            }
            continue;
        }

        // Clean up the hex payload (remove colons if present)
        let clean_hex: String = payload_hex
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();

        if clean_hex.is_empty() {
            continue;
        }

        // Validate TLS record: must start with 16 03 (handshake + TLS version)
        // 0x16 = handshake record type, 0x03 = TLS major version
        let clean_hex_lower = clean_hex.to_lowercase();
        if !clean_hex_lower.starts_with("1603") {
            if verbose {
                eprintln!("Skipping invalid TLS record (doesn't start with 16 03): {}", sni);
            }
            continue;
        }

        // Format as AmneziaWG signature
        let signature = format!("<b 0x{}>", clean_hex_lower);

        println!("[{}] Captured from: {}", signatures.len() + 1, sni);
        if verbose {
            // Show first 64 chars of signature
            let preview = if signature.len() > 64 {
                format!("{}...", &signature[..64])
            } else {
                signature.clone()
            };
            println!("    {}", preview);
        }

        signatures.push(signature);
    }

    // Kill the tshark process and wait for it to exit (prevents zombie processes)
    let _ = child.kill();
    let _ = child.wait();

    Ok(signatures)
}
