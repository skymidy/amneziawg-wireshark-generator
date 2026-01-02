use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Write signatures to output file
pub fn write_signatures(path: &Path, signatures: &[String]) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create output file: {}", path.display()))?;

    let mut writer = BufWriter::new(file);

    for signature in signatures {
        writeln!(writer, "{}", signature)
            .with_context(|| "Failed to write signature")?;
    }

    writer.flush().context("Failed to flush output file")?;

    Ok(())
}
