//! `android-doctor vbmeta` on a partition image with an AVB footer (AD-01). A clean unsigned
//! footer exits 0; a changed data byte is caught by the footer's own hash descriptor, exits 1
//! and shows in the output (no --images needed). A signed top-level vbmeta is unchanged.

use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SALT: &str = "00112233445566778899aabbccddeeff";

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("vbmeta-footer-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .output()
        .unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn vbmeta(image: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["vbmeta", s(image)];
    args.extend_from_slice(extra);
    run(&args)
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).expect("vbmeta --json prints JSON")
}

/// A 1 MiB boot partition: 8 KiB of data, then vbmeta and a 64-byte footer (algorithm NONE).
fn footer_image(dir: &Path) -> PathBuf {
    let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let raw = dir.join("boot-raw.img");
    let out = dir.join("boot.img");
    std::fs::write(&raw, &data).unwrap();
    let o = run(&[
        "avbfooter",
        s(&raw),
        "-o",
        s(&out),
        "--partition-name",
        "boot",
        "--partition-size",
        "1048576",
        "--salt",
        SALT,
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    out
}

#[test]
fn a_clean_unsigned_footer_exits_0_and_its_hash_is_checked() {
    let dir = scratch("clean");
    let img = footer_image(&dir);
    let o = vbmeta(&img, &[]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("check boot: ok"), "{text}");
    let j = json(&vbmeta(&img, &["--json"]));
    assert_eq!(j["partition_checks"][0]["partition"], "boot");
    assert_eq!(j["partition_checks"][0]["result"], "ok");
}

#[test]
fn a_flipped_data_byte_exits_1_and_changes_the_output() {
    let dir = scratch("flipped");
    let clean = footer_image(&dir);
    let bad = dir.join("boot-bad.img");
    let mut b = std::fs::read(&clean).unwrap();
    b[100] ^= 0xff;
    std::fs::write(&bad, &b).unwrap();

    let good_out = vbmeta(&clean, &[]);
    let o = vbmeta(&bad, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert_ne!(
        o.stdout, good_out.stdout,
        "the mismatch must show in the output"
    );
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("check boot: MISMATCH"), "{text}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("boot"),
        "the exit message names the partition: {err}"
    );

    let j = json(&vbmeta(&bad, &["--json"]));
    assert_eq!(j["partition_checks"][0]["result"], "MISMATCH");
}

#[test]
fn a_signed_vbmeta_still_verifies_and_a_corrupt_signature_still_exits_1() {
    let dir = scratch("signed");
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let priv_pem = dir.join("priv.pem");
    std::fs::write(
        &priv_pem,
        key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let vb = dir.join("vbmeta.img");
    let o = run(&[
        "avbmake",
        "-o",
        s(&vb),
        "--algorithm",
        "SHA256_RSA2048",
        "--key",
        s(&priv_pem),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let good = vbmeta(&vb, &[]);
    assert_eq!(good.status.code(), Some(0));

    // one bit inside the RSA signature (auth block starts at 256, signature at +32)
    let mut b = std::fs::read(&vb).unwrap();
    b[256 + 32 + 10] ^= 0x01;
    let bad = dir.join("vbmeta-bad.img");
    std::fs::write(&bad, &b).unwrap();
    let o = vbmeta(&bad, &[]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("signature"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}
