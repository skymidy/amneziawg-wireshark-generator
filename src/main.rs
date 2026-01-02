mod output;
mod tshark;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "awg-sig-gen")]
#[command(about = "Capture TLS ClientHello packet signatures for AmneziaWG junk packets")]
#[command(version)]
struct Args {
    /// Network interface to capture on
    #[arg(short, long)]
    interface: Option<String>,

    /// Number of signatures to capture
    #[arg(short, long, default_value = "5")]
    count: usize,

    /// Output file path
    #[arg(short, long, default_value = "signatures.txt")]
    output: PathBuf,

    /// Domain filter regex (e.g., "\.ru$" for .ru domains)
    #[arg(short, long, default_value = r"\.ru$")]
    domain: String,

    /// Capture timeout in seconds
    #[arg(short, long, default_value = "60")]
    timeout: u64,

    /// List available network interfaces
    #[arg(short, long)]
    list_interfaces: bool,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_interfaces {
        return list_interfaces();
    }

    let interface = args
        .interface
        .context("Interface is required. Use -l to list available interfaces.")?;

    println!("Starting capture on interface: {}", interface);
    println!("Looking for TLS ClientHello to domains matching: {}", args.domain);
    println!("Will capture {} signatures (timeout: {}s)", args.count, args.timeout);

    let signatures = tshark::capture_signatures(
        &interface,
        &args.domain,
        args.count,
        args.timeout,
        args.verbose,
    )?;

    if signatures.is_empty() {
        println!("No matching packets captured.");
        return Ok(());
    }

    output::write_signatures(&args.output, &signatures)?;

    println!(
        "Captured {} signature(s) to {}",
        signatures.len(),
        args.output.display()
    );

    Ok(())
}

fn list_interfaces() -> Result<()> {
    println!("Available network interfaces:");
    let interfaces = tshark::list_interfaces()?;
    for iface in interfaces {
        println!("  {}", iface);
    }
    Ok(())
}
