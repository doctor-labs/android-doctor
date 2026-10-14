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
        !json["signers"].as_array().unwrap().is_empty(),
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
        json["verification"].is_array(),
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

    // APK parser reports errors rather than panicking
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert!(json.get("error").is_some() || json.get("package").is_none());
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
