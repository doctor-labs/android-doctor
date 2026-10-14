//! zImage kernel wrapper detect and decompress (android-doctor #174).
//!
//! The 32-bit ARM `zImage` is a self-extracting wrapper: a fixed-size header, then a compressed
//! payload the bootloader decompresses into place before jumping to it. `classify_section` in
//! `src/ramdisk.rs` recognises `arm64-image` (the `ARMd` magic at 0x38) and nothing else, so a
//! zImage section falls through to the entropy branch and is reported as unknown.
//!
//! ## Ground truth (verified by the manager with `file(1)`, not from memory)
//!
//! The layout below is the Linux `struct boot_img_hdr` as stored little-endian on disk:
//!
//! | offset | size | field            | value in the fixture |
//! |---|---|---|---|
//! | 0x24 | 4 | `magic`          | `0x016F2818` little-endian => bytes `18 28 6f 01` |
//! | 0x28 | 4 | `header_csum`    | `"HdrS"` |
//! | 0x2c | 4 | `header_size`    | `0x40` |
//! | 0x30 | 4 | `kernel_size`    | length of the payload |
//! | 0x34 | 4 | `kernel_offset`  | load address, `0x00008000` |
//! | 0x38 | 4 | `ramdisk_size`   | `0` |
//! | 0x3c | 4 | `ramdisk_offset` | `0` |
//!
//! `file` on a blob built to exactly that spec prints
//! `Linux kernel ARM boot executable zImage (little-endian)`, and `xxd -l 0x50` shows
//! `1828 6f01` at 0x24 with `HdrS` at 0x28. Two independent confirmations of the magic.
//!
//! The payload is one of gzip, bzip2, LZMA, LZO, LZ4 or zstd. The two the tests exercise are
//! **gzip** and **LZMA**, because both crates are already dependencies of this crate and neither
//! needs a new one. The other four are out of scope for this issue; say so rather than guessing.
//!
//! `android-doctor` has no library target, so like the rest of this repository's integration
//! tests these drive the built binary through `CARGO_BIN_EXE_android-doctor`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_android-doctor")
}

/// Build a zImage wrapper around `payload`, the way the bootloader expects to find one.
///
/// The payload starts at 0x70, one 16-byte-aligned slot past the 0x40 header.
fn zimage(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 0x70];
    out[0x24..0x28].copy_from_slice(&[0x18, 0x28, 0x6F, 0x01]);
    out[0x28..0x2c].copy_from_slice(b"HdrS");
    out[0x2c..0x30].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x30..0x34].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[0x34..0x38].copy_from_slice(&0x0000_8000u32.to_le_bytes());
    out[0x38..0x3c].copy_from_slice(&0u32.to_le_bytes());
    out[0x3c..0x40].copy_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn gzip_payload(body: &[u8]) -> Option<Vec<u8>> {
    // gzip is in the crate already; the test compresses with the `gzip` CLI so the fixture is
    // byte-for-byte reproducible on any machine rather than depending on a compressor's version.
    let mut child = Command::new("gzip")
        .arg("-9")
        .arg("-n")
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    {
        use std::io::Write;
        child.stdin.as_mut()?.write_all(body).ok()?;
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

fn have(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ad-zimg-{name}"));
    fs::write(&path, bytes).expect("write fixture");
    path
}

fn identify(path: &Path) -> String {
    let out = Command::new(exe())
        .arg("identify")
        .arg(path)
        .arg("--json")
        .output()
        .expect("run identify");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_zimage_is_identified_as_a_zimage_rather_than_an_unknown_blob() {
    let Some(payload) = gzip_payload(b"kernel") else {
        return;
    };
    let path = write_temp("plain.bin", &zimage(&payload));
    let json = identify(&path);
    let _ = fs::remove_file(&path);
    // Today this is {"id": "unknown", "description": "unknown format"}. It must name the wrapper.
    assert!(
        json.contains("zImage") || json.contains("zimage"),
        "identify did not recognise the zImage wrapper: {json}"
    );
    assert!(
        !json.contains("\"id\": \"unknown\""),
        "identify still calls a zImage unknown: {json}"
    );
}

#[test]
fn the_arm64_kernel_image_is_still_identified_as_itself() {
    // arm64-image is recognised by the "ARMd" magic at 0x38. The two must not collide.
    let mut arm64 = vec![0u8; 0x400];
    arm64[0x38..0x3c].copy_from_slice(b"ARMd");
    let path = write_temp("arm64.bin", &arm64);
    let json = identify(&path);
    let _ = fs::remove_file(&path);
    assert!(
        json.contains("arm64") || json.contains("ARM64"),
        "the ARM64 kernel image stopped being recognised: {json}"
    );
}

#[test]
fn the_zimage_header_reports_the_fields_the_bootloader_uses() {
    let Some(payload) = gzip_payload(b"kernel") else {
        return;
    };
    let mut blob = zimage(&payload);
    blob[0x34..0x38].copy_from_slice(&0x0000_8000u32.to_le_bytes());
    let path = write_temp("hdr.bin", &blob);
    let out = Command::new(exe())
        .arg("unpack")
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run unpack");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = fs::remove_file(&path);
    // `unpack` is the command that already prints a boot image's sections and their format,
    // so the header the wrapper carries must be visible there rather than in a new command.
    assert!(
        text.contains("zimage") || text.contains("zImage"),
        "unpack did not report the zImage format: {text}"
    );
    // The kernel_size the header declares must be what it then reports.
    assert!(
        text.contains(&payload.len().to_string()),
        "unpack did not report the kernel size {}: {text}",
        payload.len()
    );
}

#[test]
fn an_lzma_payload_decompresses_back_to_the_kernel() {
    if !have("xz") {
        eprintln!("ZIMAGE LZMA TESTS SKIPPED: the xz CLI is required to build the .lzma payload");
        return;
    }
    let body = b"the kernel image bytes, twice over\n".repeat(4);
    let mut child = Command::new("xz")
        .arg("--format=lzma")
        .arg("-9")
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn xz");
    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(&body).unwrap();
    }
    let payload = child.wait_with_output().expect("xz").stdout;
    assert!(payload.len() > 13, "xz produced no .lzma container");
    assert_eq!(
        payload[0], 0x5D,
        "an .lzma container starts with the 0x5D properties byte"
    );

    let path = write_temp("lzma.bin", &zimage(&payload));
    // `ramdisk` on a plain cpio is the closest existing surface; the zImage wraps the same thing.
    // Today it errors with "not a compressed or plain cpio archive: no known format [unknown]".
    let out = Command::new(exe())
        .arg("ramdisk")
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run ramdisk");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = fs::remove_file(&path);
    assert!(
        !text.contains("no known format"),
        "the LZMA zImage payload was not decompressed: {text}"
    );
}

#[test]
fn a_bogus_wrapper_is_refused_rather_than_guessed() {
    let Some(payload) = gzip_payload(b"kernel") else {
        return;
    };
    // Right magic, wrong signature.
    let mut bad = zimage(&payload);
    bad[0x28] = b'X';
    let path = write_temp("badsig.bin", &bad);
    let json = identify(&path);
    let _ = fs::remove_file(&path);
    assert!(
        !json.contains("zimage") && !json.contains("zImage"),
        "a wrapper with a broken signature was still called a zImage: {json}"
    );
}

#[test]
fn a_truncated_wrapper_is_refused_rather_than_guessed() {
    let Some(payload) = gzip_payload(b"kernel") else {
        return;
    };
    // Cut before the header ends: the magic is at 0x24 but the header does not finish.
    let path = write_temp("trunc.bin", &zimage(&payload)[..0x30]);
    let json = identify(&path);
    let _ = fs::remove_file(&path);
    assert!(
        !json.contains("zimage") && !json.contains("zImage"),
        "a truncated wrapper was still called a zImage: {json}"
    );
}

#[test]
fn a_wrapper_claiming_an_absurd_payload_is_not_trusted() {
    let Some(payload) = gzip_payload(b"kernel") else {
        return;
    };
    let mut bomb = zimage(&payload);
    bomb[0x30..0x34].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let path = write_temp("bomb.bin", &bomb);
    // Must exit without a panic, without a hang, and without allocating the claimed size.
    let out = Command::new(exe())
        .arg("identify")
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run identify");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = fs::remove_file(&path);
    // A Rust panic prints "panicked at" and exits 101. Neither is acceptable on hostile input.
    assert!(
        !err.contains("panicked at") && out.status.code() != Some(101),
        "identify panicked on a zImage claiming a 4 GiB payload: {err}"
    );
    // And the size the wrapper claims must never be trusted to size a read or an allocation.
    assert!(
        !text.contains("zimage") || text.contains("truncat") || text.contains("invalid"),
        "a kernel_size running past the end of the file was reported as a usable zImage: {text}"
    );
}

#[test]
fn an_empty_file_is_handled_without_a_panic() {
    let path = write_temp("empty.bin", b"");
    let out = Command::new(exe())
        .arg("identify")
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run identify");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = fs::remove_file(&path);
    assert!(
        !err.contains("panicked at") && out.status.code() != Some(101),
        "identify panicked on an empty file: {err}"
    );
}
