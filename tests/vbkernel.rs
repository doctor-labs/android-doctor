//! `android-doctor vbkernel KERNEL.img [--key ROOT.pem]`: ChromeOS kernel partition (vboot 2.x)
//! keyblock, kernel preamble and body signatures. Issue #176.
//!
//! The fixture follows vboot_reference: `struct vb2_keyblock` (2struct.h, magic "CHROMEOS"),
//! `struct vb2_kernel_preamble` 2.2 (116 bytes), signatures as PKCS#1 v1.5 over the digest
//! of the signed range (2rsa.c), key data as little-endian words.

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
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
    fresh_root: RsaPrivateKey,
    fresh_data: RsaPrivateKey,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::thread_rng();
        Keys {
            root: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            other_root: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            data: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            fresh_root: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
            fresh_data: RsaPrivateKey::new(&mut rng, 2048).unwrap(),
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

/// Build a signed kernel partition: keyblock (root key signs it), preamble and body (data key
/// signs the preamble and the body). Signature offsets are struct-relative (2common.h:
/// `vb2_signature_data()` is `sig + sig_offset`), so `sig_offset` is the distance from the
/// `vb2_signature` struct itself to its data. `absolute` writes block-relative offsets instead,
/// the wrong reading, which must not verify.
fn kernel_image_with(root: &RsaPrivateKey, data: &RsaPrivateKey, absolute: bool) -> Vec<u8> {
    // where each signature's data sits, from the start of its block
    let kb_sig_at = 24; // keyblock_signature struct
    let kb_data = 632;
    let pre_sig_at = 8; // preamble_signature struct
    let pre_data = 372;
    let body_sig_at = 72; // body_signature struct
    let body_data = 116;
    let rel = |data_at: usize, struct_at: usize| {
        if absolute {
            data_at as u32
        } else {
            (data_at - struct_at) as u32
        }
    };

    let kd = key_data(&RsaPublicKey::from(data));
    let mut kb = vec![0u8; KEYBLOCK_SIZE];
    kb[0..8].copy_from_slice(b"CHROMEOS");
    put32(&mut kb, 8, 2); // header_version_major
    put32(&mut kb, 12, 1); // header_version_minor
    put32(&mut kb, 16, KEYBLOCK_SIZE as u32);
    put32(&mut kb, kb_sig_at, rel(kb_data, kb_sig_at)); // keyblock_signature.sig_offset
    put32(&mut kb, kb_sig_at + 8, 256); // keyblock_signature.sig_size
    put32(&mut kb, kb_sig_at + 16, kb_data as u32); // keyblock_signature.data_size
    put32(&mut kb, 80, 32); // data_key.key_offset (from the packed key struct at 80)
    put32(&mut kb, 88, kd.len() as u32); // data_key.key_size
    put32(&mut kb, 96, 4); // data_key.algorithm = VB2_ALG_RSA2048_SHA256
    kb[112..kb_data].copy_from_slice(&kd);
    let keyblock_sig = sign(root, &kb[..kb_data]);
    kb[kb_data..KEYBLOCK_SIZE].copy_from_slice(&keyblock_sig);

    let body: Vec<u8> = (0..BODY_LEN).map(|i| (i * 7 + 3) as u8).collect();
    let mut pre = vec![0u8; PREAMBLE_SIZE];
    put32(&mut pre, 0, PREAMBLE_SIZE as u32); // preamble_size
    put32(&mut pre, pre_sig_at, rel(pre_data, pre_sig_at)); // preamble_signature.sig_offset
    put32(&mut pre, pre_sig_at + 8, 256); // preamble_signature.sig_size
    put32(&mut pre, pre_sig_at + 16, pre_data as u32); // preamble_signature.data_size (header + body signature data)
    put32(&mut pre, 32, 2); // header_version_major
    put32(&mut pre, 36, 2); // header_version_minor
    put32(&mut pre, 40, 1); // kernel_version
    put32(&mut pre, body_sig_at, rel(body_data, body_sig_at)); // body_signature.sig_offset
    put32(&mut pre, body_sig_at + 8, 256); // body_signature.sig_size
    put32(&mut pre, body_sig_at + 16, BODY_LEN as u32); // body_signature.data_size
    let body_sig = sign(data, &body);
    pre[body_data..pre_data].copy_from_slice(&body_sig);
    let pre_sig = sign(data, &pre[..pre_data]);
    pre[pre_data..pre_data + 256].copy_from_slice(&pre_sig);

    let mut img = kb;
    img.extend(pre);
    img.extend(body);
    img
}

fn kernel_image(root: &RsaPrivateKey, data: &RsaPrivateKey) -> Vec<u8> {
    kernel_image_with(root, data, false)
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

#[test]
fn the_old_chromekb_magic_is_refused() {
    let (root, data) = (&keys().root, &keys().data);
    let dir = tmp_dir("oldmagic");
    let mut bytes = kernel_image(root, data);
    bytes[..8].copy_from_slice(b"CHROMEKB");
    let img = dir.join("kernel.img");
    std::fs::write(&img, &bytes).unwrap();
    let out = run(&["vbkernel", img.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("CHROMEOS"));
}

#[test]
fn absolute_signature_offsets_do_not_verify() {
    let (root, data) = (&keys().root, &keys().data);
    let dir = tmp_dir("absolute");
    let img = dir.join("kernel.img");
    std::fs::write(&img, kernel_image_with(root, data, true)).unwrap();
    let key = write_root_pem(&dir, root);

    // block-relative reading points the keyblock signature past its data: refused or invalid
    let out = run(&[
        "vbkernel",
        img.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "{out:?}");
}

fn write_private_pem(dir: &Path, name: &str, key: &RsaPrivateKey) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
    path
}

fn sign_run(image: &Path, data: &Path, root: &Path, output: &Path) -> Output {
    run(&[
        "vbsign",
        image.to_str().unwrap(),
        "--data-key",
        data.to_str().unwrap(),
        "--root-key",
        root.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ])
}

#[test]
fn a_re_signed_kernel_verifies_under_the_new_root_and_data_keys() {
    let k = keys();
    let dir = tmp_dir("sign-valid");
    let img = dir.join("old.img");
    std::fs::write(&img, kernel_image(&k.root, &k.data)).unwrap();
    let data_pem = write_private_pem(&dir, "data.pem", &k.fresh_data);
    let root_pem = write_private_pem(&dir, "root.pem", &k.fresh_root);
    let out = dir.join("new.img");

    let s = sign_run(&img, &data_pem, &root_pem, &out);
    assert!(s.status.success(), "{s:?}");
    let pub_pem = write_root_pem(&dir, &k.fresh_root);
    let (code, json) = run_json(&out, Some(&pub_pem));
    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["verdict"], "valid", "{json}");
    assert_eq!(json["keyblock"]["signature"], "valid", "{json}");
    assert_eq!(json["preamble"]["signature"], "valid", "{json}");
    assert_eq!(json["body"]["signature"], "valid", "{json}");
}

#[test]
fn a_re_signed_kernel_no_longer_verifies_under_the_old_root_key() {
    let k = keys();
    let dir = tmp_dir("sign-oldroot");
    let img = dir.join("old.img");
    std::fs::write(&img, kernel_image(&k.root, &k.data)).unwrap();
    let data_pem = write_private_pem(&dir, "data.pem", &k.fresh_data);
    let root_pem = write_private_pem(&dir, "root.pem", &k.fresh_root);
    let out = dir.join("new.img");
    assert!(sign_run(&img, &data_pem, &root_pem, &out).status.success());

    let old_pub = write_root_pem(&dir, &k.root);
    let (code, json) = run_json(&out, Some(&old_pub));
    assert_eq!(code, Some(1), "{json}");
    assert_eq!(json["keyblock"]["signature"], "invalid", "{json}");
}

#[test]
fn a_flipped_byte_in_a_re_signed_kernel_is_invalid() {
    let k = keys();
    let dir = tmp_dir("sign-flip");
    let img = dir.join("old.img");
    std::fs::write(&img, kernel_image(&k.root, &k.data)).unwrap();
    let data_pem = write_private_pem(&dir, "data.pem", &k.fresh_data);
    let root_pem = write_private_pem(&dir, "root.pem", &k.fresh_root);
    let out = dir.join("new.img");
    assert!(sign_run(&img, &data_pem, &root_pem, &out).status.success());

    let mut bytes = std::fs::read(&out).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let flipped = dir.join("flipped.img");
    std::fs::write(&flipped, &bytes).unwrap();
    let pub_pem = write_root_pem(&dir, &k.fresh_root);
    let (code, json) = run_json(&flipped, Some(&pub_pem));
    assert_eq!(code, Some(1), "{json}");
    assert_eq!(json["body"]["signature"], "invalid", "{json}");
    assert_eq!(json["verdict"], "invalid", "{json}");
}

#[test]
fn a_data_key_of_the_wrong_size_is_refused_and_no_output_is_written() {
    let k = keys();
    let dir = tmp_dir("sign-size");
    let img = dir.join("old.img");
    std::fs::write(&img, kernel_image(&k.root, &k.data)).unwrap();
    let small = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
    let data_pem = write_private_pem(&dir, "small.pem", &small);
    let root_pem = write_private_pem(&dir, "root.pem", &k.fresh_root);
    let out = dir.join("new.img");

    let s = sign_run(&img, &data_pem, &root_pem, &out);
    assert!(!s.status.success(), "{s:?}");
    assert!(!out.exists());
}
