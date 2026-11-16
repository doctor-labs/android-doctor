//! Binary hex patch: find a byte pattern and replace it, writing the result to a NEW file.
//! Magiskboot-style `hexpatch`: `from` and `to` are hex strings of the same byte length.
//! The input is never changed.

use crate::detect::refuse_blocking_file;
use crate::extract::create_part;
use anyhow::{Context, Result, bail, ensure};
use std::io::Write;
use std::path::Path;

/// Decode a hex string (upper or lower case, no separators) to bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    ensure!(!s.is_empty(), "hex pattern is empty");
    ensure!(
        s.len() % 2 == 0,
        "hex pattern has an odd number of digits ({})",
        s.len()
    );
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .with_context(|| format!("invalid hex byte {:?}", &s[i..i + 2]))
        })
        .collect()
}

/// Replace every occurrence of `from` with `to` in `data`. `from` and `to` must be the same length.
pub fn patch_bytes(mut data: Vec<u8>, from: &[u8], to: &[u8]) -> Result<(Vec<u8>, usize)> {
    ensure!(!from.is_empty(), "search pattern is empty");
    ensure!(
        from.len() == to.len(),
        "pattern length ({}) and replacement length ({}) differ; hexpatch needs equal lengths",
        from.len(),
        to.len()
    );
    let mut count = 0usize;
    let mut i = 0usize;
    while i + from.len() <= data.len() {
        if &data[i..i + from.len()] == from {
            data[i..i + to.len()].copy_from_slice(to);
            count += 1;
            i += from.len();
        } else {
            i += 1;
        }
    }
    Ok((data, count))
}

/// Read `input`, replace `from_hex` with `to_hex`, and write to `output` (a new file).
/// Refuses to overwrite unless `force`. Returns the number of replacements made.
pub fn run(
    input: &Path,
    from_hex: &str,
    to_hex: &str,
    output: &Path,
    force: bool,
) -> Result<usize> {
    refuse_blocking_file(input)?;
    ensure!(
        output.symlink_metadata().is_err() || force,
        "{} already exists; pass --force to overwrite",
        output.display()
    );
    if let (Ok(a), Ok(b)) = (input.canonicalize(), output.canonicalize()) {
        ensure!(a != b, "the output is the input; choose a new file");
    }
    let from = decode_hex(from_hex)?;
    let to = decode_hex(to_hex)?;
    let data = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let (patched, count) = patch_bytes(data, &from, &to)?;
    ensure!(
        count > 0,
        "pattern not found in {} (no changes made)",
        input.display()
    );

    let mut part = output.as_os_str().to_owned();
    part.push(".part");
    let part = std::path::PathBuf::from(part);
    let mut out = create_part(&part)?;
    out.write_all(&patched)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(&part, output)
        .with_context(|| format!("renaming {} into place", part.display()))?;
    Ok(count)
}