//! `android-doctor apk <file.apk>`: audit one APK file (manifest, package, version, signers, code, ...)
//! Issue #200.

use std::process::Command;

#[test]
fn apk_audit_reports_signers() {
    let apk = include_bytes!("fixtures/apk/v1.apk");
    let dir = std::env::temp_dir().join(format!("apk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk_path = dir.join("test.apk");
    std::fs::write(&apk_path, apk).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", apk_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // The v1.apk fixture has a signer
    assert!(
        !json["data"]["signers"].as_array().unwrap().is_empty(),
        "output: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn apk_audit_reports_verification() {
    let apk = include_bytes!("fixtures/apk/v1.apk");
    let dir = std::env::temp_dir().join(format!("apk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk_path = dir.join("test.apk");
    std::fs::write(&apk_path, apk).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", apk_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // The v1.apk fixture has verification info
    assert!(
        json["data"]["verification"].is_array(),
        "output: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn apk_audit_refuses_directory_input() {
    let dir = std::env::temp_dir().join(format!("apk-dir-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", dir.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("is a directory") || stderr.contains("not a file"));
}

#[test]
fn apk_audit_handles_invalid_apk() {
    let dir = std::env::temp_dir().join(format!("apk-invalid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk_path = dir.join("not-an-apk.apk");
    std::fs::write(&apk_path, b"not a valid zip file").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", apk_path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    // The parser reports the error rather than panicking, and the tool exits 2 (doctor/1)
    assert_eq!(out.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["exit_code"], 2);
    assert_eq!(json["schema"], "doctor/1");
    assert!(json["data"]["error"].is_string(), "output: {json}");

    let text = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", apk_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(text.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&text.stderr).contains("not-an-apk.apk"));
}

#[test]
fn apk_audit_text_output_shows_basic_info() {
    let apk = include_bytes!("fixtures/apk/v1.apk");
    let dir = std::env::temp_dir().join(format!("apk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let apk_path = dir.join("test.apk");
    std::fs::write(&apk_path, apk).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", apk_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Check that basic info is present
    assert!(
        stdout.contains("Signers:") || stdout.contains("signers"),
        "output: {}",
        stdout
    );
    assert!(
        stdout.contains("test.apk") || stdout.contains("APK:"),
        "output: {}",
        stdout
    );
}

fn v1_fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/apk/v1.apk")
}

#[test]
fn apk_json_uses_the_doctor1_envelope() {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", v1_fixture().to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["schema"], "doctor/1");
    assert_eq!(json["tool"], "android-doctor");
    assert_eq!(json["exit_code"], 0);
    assert!(json["score"]["value"].is_u64());
    assert!(json["data"]["signers"].is_array(), "data: {json}");
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.iter().any(|f| f["id"] == "apk-v1-only-signing"),
        "findings: {json}"
    );
    for f in findings {
        assert_eq!(f["fingerprint"].as_str().unwrap().len(), 16);
        assert!(f["location"]["kind"].is_string());
    }
}

#[test]
fn dex_flag_is_not_accepted_because_code_rules_always_run() {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["apk", v1_fixture().to_str().unwrap(), "--dex"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--dex"));
}
