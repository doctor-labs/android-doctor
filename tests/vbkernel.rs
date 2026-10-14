//! `android-doctor vbkernel KERNEL.img [--key ROOT.pem]`: ChromeOS kernel partition (vboot 2.x)
//! keyblock, kernel preamble and body signatures. Issue #176.
//!
//! The fixture follows vboot_reference: `struct vb2_keyblock` (2struct.h, magic "CHROMEKB"),
//! `struct vb2_kernel_preamble` 2.2 (116 bytes), signatures as PKCS#1 v1.5 over the digest
//! of the signed range (2rsa.c), key data as little-endian words.

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

/// RSA keys are slow to generate in a debug build, so every test shares one set.
struct Keys {
    root: RsaPrivateKey,
    other_root: RsaPrivateKey,
    data: RsaPrivateKey,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::thread_rng();
        Keys {
            root: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            other_root: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            data: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
        }
    })
}

/// DigestInfo prefix for SHA-256 (vboot 2rsa.c sha256_tail, without the leading zero byte).
const SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const KEYBLOCK_SIZE: usize = 112 + 520 + 256; // header, RSA2048 data key data, keyblock signature
const PREAMBLE_SIZE: usize = 1024;
const BODY_LEN: usize = 4096;

fn sign(key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(data);
    let scheme = Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: SHA256_PREFIX.to_vec().into_boxed_slice(),
    };
    key.sign(scheme, &digest).unwrap()
}

/// vb2_public_key data: len (words), n0inv, n and rr as little-endian 32-bit words.
fn key_data(public: &RsaPublicKey) -> Vec<u8> {
    let n_be = public.n().to_bytes_be();
    let mut n_le = vec![0u8; 256 - n_be.len()];
    n_le.extend(n_be.iter().rev());
    let mut out = Vec::new();
    out.extend(64u32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(&n_le);
    out.extend(vec![0u8; 256]);
    out
}

fn put32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Build a signed kernel partition: keyblock (root key signs it), preamble and body
/// (data key signs the preamble and the body).
fn kernel_image(root: &RsaPrivateKey, data: &RsaPrivateKey) -> Vec<u8> {
    let kd = key_data(&RsaPublicKey::from(data));
    let mut kb = vec![0u8; KEYBLOCK_SIZE];
    kb[0..8].copy_from_slice(b"CHROMEKB");
    put32(&mut kb, 8, 2); // header_version_major
    put32(&mut kb, 12, 1); // header_version_minor
    put32(&mut kb, 16, KEYBLOCK_SIZE as u32);
    put32(&mut kb, 24, 632); // keyblock_signature.sig_offset (from keyblock start)
    put32(&mut kb, 32, 256); // keyblock_signature.sig_size
    put32(&mut kb, 40, 632); // keyblock_signature.data_size (header + data key data)
    put32(&mut kb, 80, 32); // data_key.key_offset (from the packed key struct at 80)
    put32(&mut kb, 88, kd.len() as u32); // data_key.key_size
    put32(&mut kb, 96, 4); // data_key.algorithm = VB2_ALG_RSA2048_SHA256
    kb[112..632].copy_from_slice(&kd);
    let keyblock_sig = sign(root, &kb[..632]);
    kb[632..888].copy_from_slice(&keyblock_sig);

    let body: Vec<u8> = (0..BODY_LEN).map(|i| (i * 7 + 3) as u8).collect();
    let mut pre = vec![0u8; PREAMBLE_SIZE];
    put32(&mut pre, 0, PREAMBLE_SIZE as u32); // preamble_size
    put32(&mut pre, 8, 372); // preamble_signature.sig_offset (from preamble start)
    put32(&mut pre, 16, 256); // preamble_signature.sig_size
    put32(&mut pre, 24, 372); // preamble_signature.data_size (header + body signature data)
    put32(&mut pre, 32, 2); // header_version_major
    put32(&mut pre, 36, 2); // header_version_minor
    put32(&mut pre, 40, 1); // kernel_version
    put32(&mut pre, 72, 116); // body_signature.sig_offset
    put32(&mut pre, 80, 256); // body_signature.sig_size
    put32(&mut pre, 88, BODY_LEN as u32); // body_signature.data_size
    let body_sig = sign(data, &body);
    pre[116..372].copy_from_slice(&body_sig);
    let pre_sig = sign(data, &pre[..372]);
    pre[372..628].copy_from_slice(&pre_sig);

    let mut img = kb;
    img.extend(pre);
    img.extend(body);
    img
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vbkernel-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .output()
        .unwrap()
}

fn run_json(image: &Path, key: Option<&Path>) -> (Option<i32>, serde_json::Value) {
    let mut args = vec!["vbkernel", image.to_str().unwrap(), "--json"];
    let key_str;
    if let Some(k) = key {
        key_str = k.to_str().unwrap().to_string();
        args.extend(["--key", key_str.as_str()]);
    }
    let out = run(&args);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", out));
    (out.status.code(), json)
}

fn write_root_pem(dir: &Path, root: &RsaPrivateKey) -> PathBuf {
    let path = dir.join("root_pub.pem");
    let pem = RsaPublicKey::from(root)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    std::fs::write(&path, pem).unwrap();
    path
}

#[test]
fn signed_kernel_verifies_against_the_root_key() {
    let (root, data) = (&keys().root, &keys().data);
    let dir = tmp_dir("valid");
    let img = dir.join("kernel.img");
    std::fs::write(&img, kernel_image(root, data)).unwrap();
    let key = write_root_pem(&dir, root);

    let (code, json) = run_json(&img, Some(&key));
    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["verdict"], "valid", "{json}");
    assert_eq!(json["keyblock"]["data_key_algorithm"], "RSA2048_SHA256");
    assert_eq!(json["keyblock"]["data_key_bits"], 2048);
    assert_eq!(json["preamble"]["header_version"], "2.2");
    assert_eq!(json["body"]["size"], BODY_LEN);
}

#[test]
fn body_byte_flip_is_invalid_and_exits_1() {
    let (root, data) = (&keys().root, &keys().data);
    let dir = tmp_dir("body");
    let mut img_bytes = kernel_image(root, data);
    let last = img_bytes.len() - 1;
    img_bytes[last] ^= 0x01;
    let img = dir.join("kernel.img");
    std::fs::write(&img, &img_bytes).unwrap();
    let key = write_root_pem(&dir, root);

    let (code, json) = run_json(&img, Some(&key));
    assert_eq!(code, Some(1), "{json}");
    assert_eq!(json["verdict"], "invalid", "{json}");
    assert_eq!(json["body"]["signature"], "invalid", "{json}");
}

#[test]
fn wrong_root_key_makes_the_keyblock_invalid() {
    let (root, data, other) = (&keys().root, &keys().data, &keys().other_root);
    let dir = tmp_dir("wrongroot");
    let img = dir.join("kernel.img");
    std::fs::write(&img, kernel_image(root, data)).unwrap();
    let key = write_root_pem(&dir, other);

    let (code, json) = run_json(&img, Some(&key));
    assert_eq!(code, Some(1), "{json}");
    assert_eq!(json["keyblock"]["signature"], "invalid", "{json}");
    assert_eq!(json["verdict"], "invalid", "{json}");
}

#[test]
fn without_a_root_key_the_keyblock_is_not_checked_and_the_verdict_is_not_valid() {
    let (root, data) = (&keys().root, &keys().data);
    let dir = tmp_dir("nokey");
    let img = dir.join("kernel.img");
    std::fs::write(&img, kernel_image(root, data)).unwrap();

    let (code, json) = run_json(&img, None);
    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["keyblock"]["signature"], "not-checked", "{json}");
    assert_eq!(json["preamble"]["signature"], "valid", "{json}");
    assert_eq!(json["body"]["signature"], "valid", "{json}");
    assert_eq!(json["verdict"], "unverified", "{json}");
}

#[test]
fn a_file_without_the_keyblock_magic_is_refused() {
    let dir = tmp_dir("notkernel");
    let img = dir.join("junk.img");
    std::fs::write(&img, vec![0x5au8; 4096]).unwrap();
    let out = run(&["vbkernel", img.to_str().unwrap()]);
    assert!(!out.status.success());
}
