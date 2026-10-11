//! `android-doctor avbkey KEY.pem`: the AVB public key blob (avbtool extract_public_key) and its SHA-256
//! (avbtool extract_public_key_digest). Issue #183.

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::process::Command;

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[test]
fn avbkey_writes_the_avb_public_key_blob_and_prints_its_digest() {
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let dir = std::env::temp_dir().join(format!("avbkey-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // a private key and its public half must give the same blob
    for (name, pem) in [
        (
            "priv.pem",
            key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        ),
        (
            "pub.pem",
            key.to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        ),
    ] {
        let pem_path = dir.join(name);
        let out_path = dir.join(format!("{name}.bin"));
        std::fs::write(&pem_path, pem).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
            .args([
                "avbkey",
                pem_path.to_str().unwrap(),
                "-o",
                out_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let blob = std::fs::read(&out_path).unwrap();
        // header: key_num_bits, n0inv; then modulus and rr, 256 bytes each
        assert_eq!(blob.len(), 8 + 2 * 256);
        assert_eq!(be_u32(&blob[0..4]), 2048);
        let n = key.n();
        assert_eq!(BigUint::from_bytes_be(&blob[8..264]), *n, "modulus");
        assert_eq!(
            BigUint::from_bytes_be(&blob[264..520]),
            (BigUint::from(1u8) << 4096) % n,
            "rr = 2^(2*bits) mod n"
        );
        let n0 = n.to_bytes_le()[..4]
            .iter()
            .rev()
            .fold(0u32, |a, b| (a << 8) | u32::from(*b));
        assert_eq!(
            n0.wrapping_mul(be_u32(&blob[4..8])),
            u32::MAX,
            "n0inv * n == -1 mod 2^32"
        );
        let digest = Sha256::digest(&blob)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&digest),
            "the SHA-256 of the blob is printed"
        );
    }
    // something that is not an RSA key is refused, exit 2
    let bad = dir.join("bad.pem");
    std::fs::write(&bad, "not a key").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(["avbkey", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
