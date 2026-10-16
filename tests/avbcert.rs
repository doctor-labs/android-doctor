//! `android-doctor avbcert ...` CLI wiring (issue #185). The byte layouts are unit-tested in
//! `src/avbcert.rs`; these runs check the flags, the refusals and the written files.

use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .output()
        .unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("avbcert-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The committed test-only keys in tests/fixtures/avbcert (keygen in a debug build is slow).
fn write_keys(dir: &Path, bits: usize) -> (PathBuf, PathBuf) {
    let pem = std::fs::read_to_string(format!(
        "{}/tests/fixtures/avbcert/testkey-{bits}.pem",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let key = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let priv_path = dir.join(format!("priv{bits}.pem"));
    let pub_path = dir.join(format!("pub{bits}.pem"));
    std::fs::write(&priv_path, pem).unwrap();
    let public: RsaPublicKey = key.to_public_key();
    std::fs::write(&pub_path, public.to_public_key_pem(LineEnding::LF).unwrap()).unwrap();
    (priv_path, pub_path)
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn permanent_attributes_pack_the_root_key_and_product_id() {
    let dir = scratch("attrs");
    let (_, root_pub) = write_keys(&dir, 2048);
    let product = dir.join("product.bin");
    std::fs::write(&product, [0x42u8; 16]).unwrap();
    let out = dir.join("attrs.bin");
    let res = run(&[
        "avbcert",
        "permanent-attributes",
        "--root-authority-key",
        p(&root_pub),
        "--product-id",
        p(&product),
        "-o",
        p(&out),
    ]);
    assert!(
        res.status.success(),
        "{}",
        String::from_utf8_lossy(&res.stderr)
    );
    let bytes = std::fs::read(&out).unwrap();
    // 4-byte version, 8-byte header + two 256-byte numbers for RSA-2048, then the 16-byte id
    assert_eq!(bytes.len(), 4 + 8 + 2 * 256 + 16);
    assert_eq!(bytes[..4], 1u32.to_le_bytes());
    assert_eq!(&bytes[bytes.len() - 16..], &[0x42u8; 16]);

    // a second write to the same path is refused, as the other writers do
    let again = run(&[
        "avbcert",
        "permanent-attributes",
        "--root-authority-key",
        p(&root_pub),
        "--product-id",
        p(&product),
        "-o",
        p(&out),
    ]);
    assert!(!again.status.success());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn make_refuses_an_authority_key_that_is_not_rsa_4096() {
    let dir = scratch("make");
    let (auth_priv, _) = write_keys(&dir, 2048);
    let (_, subject_pub) = write_keys(&dir, 2048);
    let id = dir.join("id.bin");
    std::fs::write(&id, b"product").unwrap();
    let out = dir.join("cert.bin");
    let res = run(&[
        "avbcert",
        "make",
        "--authority-key",
        p(&auth_priv),
        "--subject-key",
        p(&subject_pub),
        "--subject",
        p(&id),
        "--subject-key-version",
        "3",
        "-o",
        p(&out),
    ]);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("4096"));
    assert!(!out.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn metadata_refuses_certificates_that_are_not_1620_bytes() {
    let dir = scratch("meta");
    let cert = dir.join("short.bin");
    std::fs::write(&cert, vec![0u8; 1364]).unwrap();
    let out = dir.join("meta.bin");
    let res = run(&[
        "avbcert",
        "metadata",
        "--intermediate-key-certificate",
        p(&cert),
        "--product-key-certificate",
        p(&cert),
        "-o",
        p(&out),
    ]);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("1620"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unlock_credential_needs_the_challenge_and_key_together() {
    let dir = scratch("unlock");
    let cert = dir.join("cert.bin");
    std::fs::write(&cert, vec![0u8; 1620]).unwrap();
    let challenge = dir.join("challenge.bin");
    std::fs::write(&challenge, [1u8; 16]).unwrap();
    let out = dir.join("cred.bin");
    let res = run(&[
        "avbcert",
        "unlock-credential",
        "--intermediate-key-certificate",
        p(&cert),
        "--unlock-key-certificate",
        p(&cert),
        "--challenge",
        p(&challenge),
        "-o",
        p(&out),
    ]);
    assert!(
        !res.status.success(),
        "a challenge without a key must be refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
