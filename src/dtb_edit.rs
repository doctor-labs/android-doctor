//! Device tree (DTB/FDT) edits, written to a NEW file. The input is never changed.
//!
//! Magiskboot-style `dtb patch`: zero out verity/encryption markers in fstab-like property
//! values inside an FDT blob so the bootloader does not enforce dm-verity or forced encryption.
//! This rewrites property values in place (same byte length) and leaves the rest of the blob
//! unchanged, then writes it to a new path.

use crate::detect::refuse_blocking_file;
use crate::dt;
use crate::extract::create_part;
use anyhow::{Context, Result, ensure};
use std::io::Write;
use std::path::Path;

/// Markers in fstab mount options/property values that enable verity or forced encryption.
/// Replacing their bytes with spaces of the same length disables them without changing offsets.
const VERITY_MARKERS: &[&[u8]] = &[
    b",verify",
    b"verify,",
    b"verify",
    b",avb_keys=",
    b",avb",
    b"avb,",
    b",support_scfs",
    b"support_scfs,",
];

const ENCRYPT_MARKERS: &[&[u8]] = &[
    b"forceencrypt=",
    b"forcefdeorfbe=",
    b"fileencryption=",
    b"encryptable=",
    b",quota",
    b"quota,",
    b",wrappedkey",
    b"wrappedkey,",
];

/// Replace marker bytes with spaces inside `buf`, keeping length the same. Returns count.
fn blank_markers(buf: &mut [u8], markers: &[&[u8]]) -> usize {
    let mut count = 0usize;
    for &m in markers {
        if m.is_empty() || m.len() > buf.len() {
            continue;
        }
        let mut i = 0usize;
        while i + m.len() <= buf.len() {
            if &buf[i..i + m.len()] == m {
                for b in &mut buf[i..i + m.len()] {
                    *b = b' ';
                }
                count += 1;
                i += m.len();
            } else {
                i += 1;
            }
        }
    }
    count
}

/// Read one DTB/FDT blob from `input` (raw .dtb or a boot image's dtb section is not handled
/// here; pass a DTB file). Returns the full blob bytes.
fn read_dtb_file(input: &Path) -> Result<Vec<u8>> {
    refuse_blocking_file(input)?;
    let data = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    // Validate it is an FDT so we don't patch random files silently.
    ensure!(
        data.starts_with(&[0xd0, 0x0d, 0xfe, 0xed]),
        "{} is not a device tree blob (DTB/FDT)",
        input.display()
    );
    // Parse to ensure it's structurally sane before editing.
    dt::parse_fdt(&data).with_context(|| format!("parsing {}", input.display()))?;
    Ok(data)
}

/// Patch verity/encryption markers in `data` (an FDT blob). Returns (patched, changes).
pub fn patch_fstab(mut data: Vec<u8>, verity: bool, encryption: bool) -> Result<(Vec<u8>, usize)> {
    ensure!(verity || encryption, "nothing to patch");
    // We blank markers anywhere in the blob's property/string data. This is a conservative
    // byte-level edit that preserves size/offsets. Only operate on blobs that parsed as FDT.
    dt::parse_fdt(&data)?;
    let mut changes = 0usize;
    if verity {
        changes += blank_markers(&mut data, VERITY_MARKERS);
    }
    if encryption {
        changes += blank_markers(&mut data, ENCRYPT_MARKERS);
    }
    Ok((data, changes))
}

/// `dtb patch <input> -o <output>`: remove verity and/or encryption markers from an FDT blob.
pub fn run_patch(
    input: &Path,
    output: &Path,
    verity: bool,
    encryption: bool,
    force: bool,
) -> Result<usize> {
    ensure!(
        output.symlink_metadata().is_err() || force,
        "{} already exists; pass --force to overwrite",
        output.display()
    );
    if let (Ok(a), Ok(b)) = (input.canonicalize(), output.canonicalize()) {
        ensure!(a != b, "the output is the input; choose a new file");
    }
    let data = read_dtb_file(input)?;
    let (patched, changes) = patch_fstab(data, verity, encryption)?;
    ensure!(
        changes > 0,
        "no verity/encryption markers found in {} (no changes made)",
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
    Ok(changes)
}

/// Dump a human-readable description of a DTB (like magiskboot dtb print, for session use).
pub fn print_dtb(input: &Path) -> Result<String> {
    refuse_blocking_file(input)?;
    Ok(dt::describe_file(input)?)
}
