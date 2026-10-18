//! `verify-ota` exit codes and `ok`: an OTA is ok only when a signature actually verified.
//! Unsigned and truncated inputs must never pass as verified.

use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::process::{Command, Output};

const OTA: &[u8] = include_bytes!("fixtures/ota/ota-signed.zip");

fn write_input(tag: &str, bytes: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("verify-ota-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("ota.zip");
    std::fs::write(&p, bytes).unwrap();
    p
}

/// A plain zip with no whole-file signature footer.
fn unsigned_zip() -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("payload.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"not signed").unwrap();
    w.finish().unwrap().into_inner()
}

fn verify_ota(input: &PathBuf, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .arg("verify-ota")
        .arg(input)
        .args(extra)
        .output()
        .unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("verify-ota --json prints JSON")
}

#[test]
fn signed_ota_verifies_and_exits_zero() {
    let p = write_input("signed", OTA);
    let out = verify_ota(&p, &["--json"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let j = json(&out);
    assert_eq!(j["ok"], true, "{j}");
    assert!(
        j["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["verdict"] == "verified"),
        "{j}"
    );
}

#[test]
fn unsigned_zip_is_not_ok_and_exits_nonzero() {
    let p = write_input("unsigned", &unsigned_zip());
    let out = verify_ota(&p, &["--json"]);
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    let j = json(&out);
    assert_eq!(j["ok"], false, "{j}");
    assert_eq!(j["checks"][0]["check"], "zip-signature", "{j}");
    assert_eq!(j["checks"][0]["verdict"], "absent", "{j}");
}

#[test]
fn allow_unsigned_exits_zero_but_stays_not_ok_and_says_not_verified() {
    let p = write_input("allow-unsigned", &unsigned_zip());
    let out = verify_ota(&p, &["--json", "--allow-unsigned"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(json(&out)["ok"], false);
    let text = verify_ota(&p, &["--allow-unsigned"]);
    assert_eq!(text.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("NOT VERIFIED"), "{stdout}");
    assert!(stdout.contains("absent"), "{stdout}");
}

#[test]
fn truncated_zip_is_an_error_not_absent() {
    let p = write_input("truncated", &OTA[..OTA.len() / 2]);
    let out = verify_ota(&p, &["--json"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("absent"),
        "{out:?}"
    );
}
