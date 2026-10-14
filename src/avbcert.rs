//! avb_cert encoders (issue #185): the byte layouts of avbtool's `make_certificate`,
//! `make_cert_permanent_attributes`, `make_cert_metadata` and `make_cert_unlock_credential`
//! (avbtool.py, class `AvbTool`). Key generation is not here: avbtool reads keys made by
//! openssl, and so does this module.
//!
//! Layouts (all integers little-endian, as avbtool packs them with `<`):
//! - certificate: `u32 1`, AVB public key blob (1032 bytes for RSA-4096), SHA-256 of the subject
//!   id, SHA-256 of the usage string, `u64` subject key version, then a SHA512_RSA4096 signature
//!   by the authority over everything before it. 1108 + 512 = 1620 bytes.
//! - permanent attributes: `u32 1`, root authority public key blob, 16-byte product id.
//! - metadata: `u32 1`, intermediate certificate (1620 bytes), product key certificate (1620).
//! - unlock credential: `u32 1`, intermediate certificate, unlock certificate, and when a
//!   challenge and unlock key are given, a SHA512_RSA4096 signature over the 16-byte challenge.

use crate::avb::{load_rsa_public_key, pkcs1v15_sha512_prefix, public_key_blob};
use crate::detect::refuse_blocking_file;
use anyhow::{Context, Result, bail, ensure};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;

/// avbtool `EXPECTED_CERTIFICATE_SIZE`: a certificate for a 4096-bit authority key.
pub const CERT_LEN: usize = 1620;
/// avbtool `EXPECTED_PRODUCT_ID_SIZE`.
pub const PRODUCT_ID_LEN: usize = 16;
/// avbtool `EXPECTED_CHALLENGE_SIZE`.
pub const CHALLENGE_LEN: usize = 16;
/// avbtool requires SHA512_RSA4096 signing keys to be 4096 bits (`signature_num_bytes * 8`).
const SIGNING_KEY_BITS: usize = 4096;
/// Largest input file read; certificates and keys are far smaller.
const MAX_INPUT: u64 = 1 << 20;

/// avbtool `CERT_USAGE_SIGNING`.
pub const USAGE_SIGNING: &str = "com.google.android.things.vboot";
/// avbtool `CERT_USAGE_INTERMEDIATE_AUTHORITY`.
pub const USAGE_INTERMEDIATE: &str = "com.google.android.things.vboot.ca";
/// avbtool `CERT_USAGE_UNLOCK`.
pub const USAGE_UNLOCK: &str = "com.google.android.things.vboot.unlock";

/// `u32` format version written at the start of every avb_cert structure.
fn format_version() -> [u8; 4] {
    1u32.to_le_bytes()
}

/// PKCS#1 v1.5 SHA512_RSA4096 signature over `data` (avbtool `RSAPublicKey.sign` hashes first).
fn sign_sha512(key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        key.n().bits() == SIGNING_KEY_BITS,
        "SHA512_RSA4096 needs a {SIGNING_KEY_BITS}-bit RSA key, this one has {} bits",
        key.n().bits()
    );
    let digest = Sha512::digest(data);
    let scheme = Pkcs1v15Sign {
        hash_len: Some(64),
        prefix: pkcs1v15_sha512_prefix().into_boxed_slice(),
    };
    key.sign(scheme, &digest)
        .context("signing with the authority key")
}

/// `make_certificate`: a certificate binding `subject` (its public key, a subject id such as a
/// product id, a usage string and a version) under the authority's signature.
pub fn make_certificate(
    authority: &RsaPrivateKey,
    subject: &RsaPublicKey,
    subject_id: &[u8],
    usage: &str,
    version: u64,
) -> Result<Vec<u8>> {
    ensure!(usage.is_ascii(), "the usage string must be ASCII");
    let mut signed = Vec::new();
    signed.extend(format_version());
    signed.extend(public_key_blob(subject.n()));
    signed.extend(Sha256::digest(subject_id));
    signed.extend(Sha256::digest(usage.as_bytes()));
    signed.extend(version.to_le_bytes());
    let signature = sign_sha512(authority, &signed)?;
    signed.extend(signature);
    Ok(signed)
}

/// `make_cert_permanent_attributes`: the root authority key and product id whose hash is fused.
pub fn permanent_attributes(root: &RsaPublicKey, product_id: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        product_id.len() == PRODUCT_ID_LEN,
        "the product id must be {PRODUCT_ID_LEN} bytes, got {}",
        product_id.len()
    );
    let mut out = format_version().to_vec();
    out.extend(public_key_blob(root.n()));
    out.extend(product_id);
    Ok(out)
}

/// `make_cert_metadata`: the intermediate and product key certificates, as stored in a vbmeta.
pub fn metadata(intermediate: &[u8], product: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        intermediate.len() == CERT_LEN,
        "the intermediate key certificate must be {CERT_LEN} bytes, got {}",
        intermediate.len()
    );
    ensure!(
        product.len() == CERT_LEN,
        "the product key certificate must be {CERT_LEN} bytes, got {}",
        product.len()
    );
    let mut out = format_version().to_vec();
    out.extend(intermediate);
    out.extend(product);
    Ok(out)
}

/// `make_cert_unlock_credential`: the two certificates, plus the challenge signature when
/// `challenge` and `unlock_key` are both given (avbtool signs only in that case).
pub fn unlock_credential(
    intermediate: &[u8],
    unlock: &[u8],
    challenge: Option<&[u8]>,
    unlock_key: Option<&RsaPrivateKey>,
) -> Result<Vec<u8>> {
    ensure!(
        intermediate.len() == CERT_LEN,
        "the intermediate key certificate must be {CERT_LEN} bytes, got {}",
        intermediate.len()
    );
    ensure!(
        unlock.len() == CERT_LEN,
        "the unlock key certificate must be {CERT_LEN} bytes, got {}",
        unlock.len()
    );
    let mut out = format_version().to_vec();
    out.extend(intermediate);
    out.extend(unlock);
    if let (Some(challenge), Some(key)) = (challenge, unlock_key) {
        ensure!(
            challenge.len() == CHALLENGE_LEN,
            "the unlock challenge must be {CHALLENGE_LEN} bytes, got {}",
            challenge.len()
        );
        out.extend(sign_sha512(key, challenge)?);
    }
    Ok(out)
}

/// Read a small input file, refusing FIFOs, directories and oversized files first.
pub fn read_input(path: &Path) -> Result<Vec<u8>> {
    refuse_blocking_file(path)?;
    if path.is_dir() {
        bail!("{} is a directory, not a file", path.display());
    }
    let len = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    ensure!(
        len <= MAX_INPUT,
        "{} is {len} bytes, larger than the {MAX_INPUT}-byte limit",
        path.display()
    );
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// Load an RSA private key from a PEM file (PKCS#8 or PKCS#1).
pub fn load_private_key(path: &Path) -> Result<RsaPrivateKey> {
    let pem = String::from_utf8(read_input(path)?)
        .with_context(|| format!("{} is not text", path.display()))?;
    RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
        .with_context(|| format!("{} is not a PEM RSA private key", path.display()))
}

/// Load the public half of a PEM RSA key (a public or a private key file).
pub fn load_public_key(path: &Path) -> Result<RsaPublicKey> {
    let pem = String::from_utf8(read_input(path)?)
        .with_context(|| format!("{} is not text", path.display()))?;
    load_rsa_public_key(&pem).with_context(|| format!("{} is not an RSA key", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;

    // Test-only keys (tests/fixtures/avbcert). Generating an RSA-4096 key in a debug build
    // takes minutes, so the tests read these instead.
    fn key2048() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(include_str!("../tests/fixtures/avbcert/testkey-2048.pem"))
            .unwrap()
    }

    fn key4096() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(include_str!("../tests/fixtures/avbcert/testkey-4096.pem"))
            .unwrap()
    }

    fn verify_sha512(pubkey: &RsaPublicKey, data: &[u8], sig: &[u8]) -> bool {
        let scheme = Pkcs1v15Sign {
            hash_len: Some(64),
            prefix: pkcs1v15_sha512_prefix().into_boxed_slice(),
        };
        pubkey.verify(scheme, &Sha512::digest(data), sig).is_ok()
    }

    #[test]
    fn a_certificate_lays_out_the_fields_avbtool_writes_and_is_signed() {
        let authority = key4096();
        let subject = key4096().to_public_key();
        let product = b"0123456789abcdef";
        let cert = make_certificate(&authority, &subject, product, USAGE_SIGNING, 7).unwrap();
        // 4 + 1032 (RSA-4096 blob) + 32 + 32 + 8 = 1108 signed bytes; + 512 signature
        assert_eq!(cert.len(), CERT_LEN);
        assert_eq!(cert[..4], format_version());
        let blob = public_key_blob(subject.n());
        assert_eq!(&cert[4..4 + blob.len()], &blob[..]);
        let mut at = 4 + blob.len();
        assert_eq!(&cert[at..at + 32], &Sha256::digest(product)[..]);
        at += 32;
        assert_eq!(&cert[at..at + 32], &Sha256::digest(USAGE_SIGNING)[..]);
        at += 32;
        assert_eq!(cert[at..at + 8], 7u64.to_le_bytes());
        assert!(verify_sha512(
            &authority.to_public_key(),
            &cert[..1108],
            &cert[1108..]
        ));
    }

    #[test]
    fn a_small_authority_key_is_refused_as_avbtool_does() {
        let authority = key2048();
        let subject = key2048().to_public_key();
        let err = make_certificate(&authority, &subject, b"id", USAGE_SIGNING, 1).unwrap_err();
        assert!(err.to_string().contains("4096-bit"), "{err}");
    }

    #[test]
    fn permanent_attributes_are_version_root_key_and_product_id() {
        let root = key2048().to_public_key();
        let id = [0xabu8; 16];
        let attrs = permanent_attributes(&root, &id).unwrap();
        assert_eq!(attrs.len(), 4 + 8 + 2 * 256 + 16);
        assert_eq!(attrs[..4], format_version());
        assert_eq!(&attrs[4..4 + 8 + 2 * 256], &public_key_blob(root.n())[..]);
        assert_eq!(&attrs[attrs.len() - 16..], &id[..]);
        assert!(permanent_attributes(&root, &id[..15]).is_err());
    }

    #[test]
    fn metadata_and_unlock_credentials_need_full_size_certificates() {
        let cert = vec![0x5au8; CERT_LEN];
        let meta = metadata(&cert, &cert).unwrap();
        assert_eq!(meta.len(), 4 + 2 * CERT_LEN);
        assert!(metadata(&cert[..CERT_LEN - 1], &cert).is_err());
        assert!(metadata(&cert, &cert[..1364]).is_err());
        let plain = unlock_credential(&cert, &cert, None, None).unwrap();
        assert_eq!(plain.len(), 4 + 2 * CERT_LEN);
        assert!(unlock_credential(&cert, &cert[..10], None, None).is_err());
    }

    #[test]
    fn an_unlock_credential_signs_the_challenge_when_given_a_key() {
        let cert = vec![0x5au8; CERT_LEN];
        let unlock_key = key4096();
        let challenge = [0x11u8; 16];
        let cred = unlock_credential(&cert, &cert, Some(&challenge), Some(&unlock_key)).unwrap();
        assert_eq!(cred.len(), 4 + 2 * CERT_LEN + 512);
        assert!(verify_sha512(
            &unlock_key.to_public_key(),
            &challenge,
            &cred[4 + 2 * CERT_LEN..]
        ));
        assert!(unlock_credential(&cert, &cert, Some(&challenge[..8]), Some(&unlock_key)).is_err());
    }
}
