//! `android-doctor avbmake`: write a new vbmeta image (avbtool make_vbmeta_image, no descriptors).
//! Issue #184. The output goes to a new path, never in place.

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::process::Command;

fn be_u32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

fn be_u64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("avbmake-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn none_writes_a_bare_header_with_the_rollback_index() {
    let dir = scratch("none");
    let out = dir.join("vbmeta.img");
    let o = run(&[
        "avbmake",
        "-o",
        out.to_str().unwrap(),
        "--algorithm",
        "NONE",
        "--rollback-index",
        "7",
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let b = std::fs::read(&out).unwrap();
    assert_eq!(b.len(), 256, "NONE with no descriptors is the header alone");
    assert_eq!(&b[0..4], b"AVB0");
    assert_eq!(be_u32(&b, 28), 0, "algorithm_type NONE");
    assert_eq!(be_u64(&b, 112), 7, "rollback_index");
}

#[test]
fn signed_2048_writes_a_digest_and_a_signature_that_verify() {
    let dir = scratch("rsa2048");
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let priv_pem = dir.join("priv.pem");
    std::fs::write(
        &priv_pem,
        key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let out = dir.join("vbmeta.img");
    let o = run(&[
        "avbmake",
        "-o",
        out.to_str().unwrap(),
        "--algorithm",
        "SHA256_RSA2048",
        "--key",
        priv_pem.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let b = std::fs::read(&out).unwrap();
    // header 256, auth block round64(32 + 256) = 320, aux block round64(8 + 2 * 2048 / 8) = 576
    assert_eq!(b.len(), 256 + 320 + 576);
    assert_eq!(be_u32(&b, 28), 1, "algorithm_type SHA256_RSA2048");
    let auth = &b[256..256 + 320];
    let aux = &b[256 + 320..];
    let mut hasher = Sha256::new();
    hasher.update(&b[..256]);
    hasher.update(aux);
    let digest = hasher.finalize();
    assert_eq!(
        &auth[0..32],
        digest.as_slice(),
        "hash is SHA-256 over header and aux block"
    );
    let public: RsaPublicKey = key.to_public_key();
    // DigestInfo prefix for SHA-256 (the same bytes avbtool puts in its PKCS#1 padding)
    let scheme = Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]
        .into_boxed_slice(),
    };
    public
        .verify(scheme, &digest, &auth[32..32 + 256])
        .expect("signature over the digest verifies with the key's public half");
}

#[test]
fn refuses_to_overwrite_and_needs_a_key_for_signed_algorithms() {
    let dir = scratch("refuse");
    let out = dir.join("vbmeta.img");
    std::fs::write(&out, b"x").unwrap();
    let o = run(&[
        "avbmake",
        "-o",
        out.to_str().unwrap(),
        "--algorithm",
        "NONE",
    ]);
    assert!(
        !o.status.success(),
        "existing output must not be replaced without --force"
    );
    let fresh = dir.join("fresh.img");
    let o = run(&[
        "avbmake",
        "-o",
        fresh.to_str().unwrap(),
        "--algorithm",
        "SHA256_RSA2048",
    ]);
    assert!(
        !o.status.success(),
        "a signed algorithm without --key must fail"
    );
    assert!(!fresh.exists());
}
