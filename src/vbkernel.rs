//! ChromeOS kernel partition (vboot 2.x) verification: the keyblock, the kernel preamble and the
//! kernel body (`vbkernel`, issue #176). `sign` (`vbsign`) re-signs an image with a data key and a root key.
//!
//! Layouts and constants are from vboot_reference: `firmware/2lib/include/2struct.h` (keyblock
//! magic "CHROMEOS", `vb2_keyblock` 112 bytes, `vb2_packed_key` 32 bytes, `vb2_signature` 24
//! bytes, `vb2_kernel_preamble` 2.2 = 116 bytes), `2crypto.h` (algorithm numbers) and `2rsa.c`
//! (PKCS#1 v1.5 DigestInfo, key data as little-endian words, big-endian signatures).
//! `vb2_signature.sig_offset` and `vb2_packed_key.key_offset` are relative to the address of
//! the struct that contains them (2common.h: `vb2_signature_data()` is `sig + sig_offset`).
//! The signed range is the first `data_size` bytes of the keyblock or preamble, or `data_size`
//! bytes of the kernel body.
//!
//! Not checked: the root key's own hash choice beyond the three PKCS#1 DigestInfo prefixes,
//! keyblock hashes for unsigned keys, the 2.0/2.1 preamble, and any device-side rollback data.

use crate::detect::refuse_blocking_file;
use anyhow::{Result, anyhow, ensure};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;

const KEYBLOCK_MAGIC: &[u8; 8] = b"CHROMEOS";
const KEYBLOCK_HEADER_LEN: usize = 112;
const PREAMBLE_2_2_LEN: usize = 116;
/// Largest kernel partition read; a real one is a few tens of MB.
const MAX_IMAGE: u64 = 512 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha512,
}

impl Hash {
    fn name(self) -> &'static str {
        match self {
            Hash::Sha1 => "SHA-1",
            Hash::Sha256 => "SHA-256",
            Hash::Sha512 => "SHA-512",
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// DigestInfo prefix (2rsa.c `*_tail` without the leading zero byte).
    fn prefix(self) -> Vec<u8> {
        match self {
            Hash::Sha1 => vec![
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            Hash::Sha256 => vec![
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Hash::Sha512 => vec![
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// `enum vb2_crypto_algorithm` (2crypto.h): RSA modulus bits, public exponent and hash.
fn alg_params(alg: u32) -> Option<(usize, u64, Hash, bool)> {
    if alg > 17 {
        return None;
    }
    let bits = [1024, 2048, 4096, 8192, 2048, 3072][(alg / 3) as usize];
    let exp3 = alg >= 12;
    let hash = [Hash::Sha1, Hash::Sha256, Hash::Sha512][(alg % 3) as usize];
    Some((bits, if exp3 { 3 } else { 65537 }, hash, exp3))
}

fn alg_name(alg: u32) -> String {
    match alg_params(alg) {
        Some((bits, _, hash, exp3)) => format!(
            "RSA{bits}{}_{}",
            if exp3 { "_EXP3" } else { "" },
            hash.name().replace('-', "")
        ),
        None => format!("unknown({alg})"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Valid,
    Invalid,
    NotChecked,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Invalid => "invalid",
            Status::NotChecked => "not-checked",
        }
    }
}

/// A `vb2_packed_key` with its RSA public key.
struct PackedKey {
    alg: u32,
    bits: usize,
    hash: Hash,
    key: RsaPublicKey,
}

/// A `vb2_signature`: offset and size of the signature bytes, and the length of the signed data.
struct Sig {
    offset: usize,
    size: usize,
    data_size: usize,
}

pub struct Report {
    file: String,
    keyblock_size: usize,
    data_key: PackedKey,
    root_status: Status,
    root_hash: Option<Hash>,
    root_given: bool,
    header_minor: u32,
    kernel_version: u32,
    preamble_size: usize,
    preamble_status: Status,
    body_offset: usize,
    body_size: usize,
    body_status: Status,
}

impl Report {
    fn verdict(&self) -> &'static str {
        let all = [self.root_status, self.preamble_status, self.body_status];
        if all.contains(&Status::Invalid) {
            "invalid"
        } else if all.contains(&Status::NotChecked) {
            "unverified"
        } else {
            "valid"
        }
    }

    pub fn any_invalid(&self) -> bool {
        self.verdict() == "invalid"
    }

    pub fn to_json(&self) -> Value {
        json!({
            "file": self.file,
            "format": "chromeos-kernel",
            "verdict": self.verdict(),
            "keyblock": {
                "size": self.keyblock_size,
                "data_key_algorithm": alg_name(self.data_key.alg),
                "data_key_bits": self.data_key.bits,
                "root_key": if self.root_given { "given" } else { "none" },
                "signature": self.root_status.name(),
                "signature_hash": self.root_hash.map(|h| h.name()),
            },
            "preamble": {
                "size": self.preamble_size,
                "header_version": format!("2.{}", self.header_minor),
                "kernel_version": self.kernel_version,
                "signature": self.preamble_status.name(),
            },
            "body": {
                "offset": self.body_offset,
                "size": self.body_size,
                "signature": self.body_status.name(),
            },
        })
    }

    pub fn to_text(&self) -> String {
        let root = match (self.root_status, self.root_hash) {
            (Status::Valid, Some(h)) => format!("valid ({})", h.name()),
            (s, _) => s.name().to_string(),
        };
        let root_note = if self.root_given {
            ""
        } else {
            " (no --key: the root key was not given)"
        };
        format!(
            "{}: ChromeOS kernel partition (keyblock {} bytes, preamble 2.{})\n  keyblock   {} data key, root signature: {}{}\n  preamble   signature (data key): {}\n  body       {} bytes at {}, signature (data key): {}\nverdict: {}",
            self.file,
            self.keyblock_size,
            self.header_minor,
            alg_name(self.data_key.alg),
            root,
            root_note,
            self.preamble_status.name(),
            self.body_size,
            self.body_offset,
            self.body_status.name(),
            self.verdict(),
        )
    }
}

fn range(b: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| anyhow!("range overflows"))?;
    ensure!(
        end <= b.len(),
        "range {start}+{len} is past the end of the image"
    );
    Ok(&b[start..end])
}

fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    let s = range(b, at, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a `vb2_signature` at `at`; its data is at `at + sig_offset` (struct-relative).
fn sig_at(b: &[u8], at: usize) -> Result<Sig> {
    Ok(Sig {
        offset: at
            .checked_add(u32_at(b, at)? as usize)
            .ok_or_else(|| anyhow!("signature offset overflows"))?,
        size: u32_at(b, at + 8)? as usize,
        data_size: u32_at(b, at + 16)? as usize,
    })
}

/// Read a `vb2_packed_key` whose header starts at `at` in `block`; `key_offset` is relative to it.
fn unpack_key(block: &[u8], at: usize) -> Result<PackedKey> {
    let key_offset = u32_at(block, at)? as usize;
    let key_size = u32_at(block, at + 8)? as usize;
    let alg = u32_at(block, at + 16)?;
    let (bits, exp, hash, _) =
        alg_params(alg).ok_or_else(|| anyhow!("unsupported key algorithm {alg}"))?;
    let sig_bytes = bits / 8;
    ensure!(
        key_size == 2 * sig_bytes + 8,
        "key data is {key_size} bytes, expected {} for {}",
        2 * sig_bytes + 8,
        alg_name(alg)
    );
    let kd = range(block, at + key_offset, key_size)?;
    let words = u32::from_le_bytes([kd[0], kd[1], kd[2], kd[3]]) as usize;
    ensure!(
        words * 4 == sig_bytes,
        "key length word {words} does not match {bits} bits"
    );
    // n is little-endian 32-bit words: reversing the byte string gives the big-endian modulus
    let n_be: Vec<u8> = kd[8..8 + sig_bytes].iter().rev().copied().collect();
    let key = rsa_key(&n_be, exp)?;
    Ok(PackedKey {
        alg,
        bits,
        hash,
        key,
    })
}

fn rsa_key(n_be: &[u8], exp: u64) -> Result<RsaPublicKey> {
    let n = BigUint::from_bytes_be(n_be);
    let e = BigUint::from(exp);
    // the crate caps RsaPublicKey::new at 4096 bits; vboot also has 8192-bit keys
    if n.bits() <= 4096 {
        RsaPublicKey::new(n, e).map_err(|e| anyhow!("invalid RSA key: {e}"))
    } else {
        Ok(RsaPublicKey::new_unchecked(n, e))
    }
}

/// PKCS#1 v1.5 verification of `sig` over `signed` with `hash`.
fn verify_with(key: &RsaPublicKey, hash: Hash, sig: &[u8], signed: &[u8]) -> bool {
    if sig.len() != key.size() {
        return false;
    }
    let digest = hash.digest(signed);
    let scheme = Pkcs1v15Sign {
        hash_len: Some(digest.len()),
        prefix: hash.prefix().into_boxed_slice(),
    };
    key.verify(scheme, &digest, sig).is_ok()
}

fn verify_block(key: &PackedKey, block: &[u8], sig: &Sig) -> Result<Status> {
    ensure!(
        sig.data_size <= block.len(),
        "signed data is past the end of its block"
    );
    let bytes = range(block, sig.offset, sig.size)?;
    Ok(
        if verify_with(&key.key, key.hash, bytes, &block[..sig.data_size]) {
            Status::Valid
        } else {
            Status::Invalid
        },
    )
}

/// Verify a ChromeOS kernel partition image. `root` is the public key that signed the keyblock;
/// without it the keyblock signature is reported as not checked.
pub fn verify(path: &Path, root: Option<&RsaPublicKey>) -> Result<Report> {
    refuse_blocking_file(path)?;
    let meta = std::fs::metadata(path)?;
    ensure!(
        meta.len() <= MAX_IMAGE,
        "{} is larger than {MAX_IMAGE} bytes",
        path.display()
    );
    let image = std::fs::read(path)?;
    verify_image(&path.display().to_string(), &image, root)
}

fn check_magic(name: &str, image: &[u8]) -> Result<()> {
    ensure!(
        image.len() >= KEYBLOCK_HEADER_LEN && &image[..8] == KEYBLOCK_MAGIC,
        "{name} has no ChromeOS keyblock (CHROMEOS) at offset 0"
    );
    Ok(())
}

/// Keyblock size from its header; the keyblock is the first `size` bytes of the image.
fn keyblock_len(image: &[u8]) -> Result<usize> {
    ensure!(
        u32_at(image, 8)? == 2,
        "unsupported keyblock header version"
    );
    let size = u32_at(image, 16)? as usize;
    ensure!(
        size >= KEYBLOCK_HEADER_LEN,
        "keyblock is smaller than its header"
    );
    Ok(size)
}

/// Size of the preamble at `at` (the end of the keyblock); anything older than 2.2 is refused.
fn preamble_len(image: &[u8], at: usize) -> Result<usize> {
    let size = u32_at(image, at)? as usize;
    ensure!(
        u32_at(image, at + 32)? == 2,
        "unsupported kernel preamble header version"
    );
    let minor = u32_at(image, at + 36)?;
    ensure!(minor >= 2, "kernel preamble 2.{minor} is older than 2.2");
    ensure!(
        size >= PREAMBLE_2_2_LEN,
        "kernel preamble is smaller than 2.2"
    );
    Ok(size)
}

fn verify_image(name: &str, image: &[u8], root: Option<&RsaPublicKey>) -> Result<Report> {
    check_magic(name, image)?;

    // keyblock: vb2_keyblock
    let keyblock_size = keyblock_len(image)?;
    let keyblock = range(image, 0, keyblock_size)?;
    let data_key = unpack_key(keyblock, 80)?;
    let kb_sig = sig_at(keyblock, 24)?;

    let (root_status, root_hash) = match root {
        None => (Status::NotChecked, None),
        Some(root) => {
            let signed = range(keyblock, 0, kb_sig.data_size)?;
            let sig = range(keyblock, kb_sig.offset, kb_sig.size)?;
            let found = [Hash::Sha256, Hash::Sha512, Hash::Sha1]
                .into_iter()
                .find(|h| verify_with(root, *h, sig, signed));
            match found {
                Some(h) => (Status::Valid, Some(h)),
                None => (Status::Invalid, None),
            }
        }
    };

    // kernel preamble: vb2_kernel_preamble 2.x, after the keyblock
    let preamble_size = preamble_len(image, keyblock_size)?;
    let header_minor = u32_at(image, keyblock_size + 36)?;
    let preamble = range(image, keyblock_size, preamble_size)?;
    let kernel_version = u32_at(preamble, 40)?;
    let pre_sig = sig_at(preamble, 8)?;
    let preamble_status = verify_block(&data_key, preamble, &pre_sig)?;

    // kernel body: signed by the data key, body_signature in the preamble
    let body_sig = sig_at(preamble, 72)?;
    // Body start: the keyblock (keyblock_size) and the preamble (preamble_size) precede it.
    // The fetched vboot headers say the preamble is followed by the body; no fetched file
    // has the body-offset line, so this is inferred from those size comments.
    let body_offset = keyblock_size
        .checked_add(preamble_size)
        .ok_or_else(|| anyhow!("body offset overflows"))?;
    let body = range(image, body_offset, body_sig.data_size)?;
    let body_bytes = range(preamble, body_sig.offset, body_sig.size)?;
    let body_status = if verify_with(&data_key.key, data_key.hash, body_bytes, body) {
        Status::Valid
    } else {
        Status::Invalid
    };

    Ok(Report {
        file: name.to_string(),
        keyblock_size,
        data_key,
        root_status,
        root_hash,
        root_given: root.is_some(),
        header_minor,
        kernel_version,
        preamble_size,
        preamble_status,
        body_offset,
        body_size: body_sig.data_size,
        body_status,
    })
}

/// PKCS#1 v1.5 signature over `data` with `hash`: the signing side of `verify_with`.
fn sign_with(key: &RsaPrivateKey, hash: Hash, data: &[u8]) -> Result<Vec<u8>> {
    let digest = hash.digest(data);
    let scheme = Pkcs1v15Sign {
        hash_len: Some(digest.len()),
        prefix: hash.prefix().into_boxed_slice(),
    };
    key.sign(scheme, &digest)
        .map_err(|e| anyhow!("signing failed: {e}"))
}

/// The `vb2_public_key` data of `public` (vboot 2rsa.h): length in 32-bit words, n0inv
/// (-1 / n[0] mod 2^32), n and rr (R^2 mod n with R = 2^bits), n and rr little-endian.
fn packed_key_data(public: &RsaPublicKey, bits: usize) -> Result<Vec<u8>> {
    let sig_bytes = bits / 8;
    let n = public.n();
    ensure!(
        n.bits() == bits,
        "modulus is {} bits, expected {bits}",
        n.bits()
    );
    let le = |v: &BigUint| -> Vec<u8> {
        let be = v.to_bytes_be();
        let mut out = vec![0u8; sig_bytes.saturating_sub(be.len())];
        out.extend(be);
        out.reverse();
        out
    };
    let n_le = le(n);
    let n0 = u32::from_le_bytes([n_le[0], n_le[1], n_le[2], n_le[3]]);
    // Newton iteration for the inverse of the odd n0 mod 2^32, then negate
    let mut inv = n0;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
    }
    let n0inv = inv.wrapping_neg();
    let rr = (BigUint::from(1u8) << (2 * bits)) % n;
    let mut out = Vec::with_capacity(2 * sig_bytes + 8);
    out.extend(((sig_bytes / 4) as u32).to_le_bytes());
    out.extend(n0inv.to_le_bytes());
    out.extend(n_le);
    out.extend(le(&rr));
    Ok(out)
}

/// Re-sign a kernel partition (the inverse of [`verify`]). `data` replaces the data key recorded
/// in the keyblock and signs the preamble and the body; `root` signs the keyblock with SHA-256.
/// The layout and algorithm are kept: the data key must have the modulus size and public exponent
/// the keyblock already records, and the root key must match the keyblock signature size. The
/// result is verified with the root public key before it is returned.
pub fn sign(
    name: &str,
    image: &[u8],
    data: &RsaPrivateKey,
    root: &RsaPrivateKey,
) -> Result<Vec<u8>> {
    check_magic(name, image)?;
    let mut out = image.to_vec();
    let keyblock_size = keyblock_len(&out)?;
    let old = unpack_key(range(&out, 0, keyblock_size)?, 80)?;
    let (_, exp, _, _) =
        alg_params(old.alg).ok_or_else(|| anyhow!("unsupported key algorithm {}", old.alg))?;
    ensure!(
        data.n().bits() == old.bits && data.e() == &BigUint::from(exp),
        "the data key must be {} bits with exponent {exp} to match {}",
        old.bits,
        alg_name(old.alg)
    );

    // the new data key, packed where the old one was (same length, so the layout is kept)
    let kd = packed_key_data(&RsaPublicKey::from(data), old.bits)?;
    let kd_at = 80 + u32_at(&out, 80)? as usize;
    range(&out, kd_at, kd.len())?;
    out[kd_at..kd_at + kd.len()].copy_from_slice(&kd);

    // keyblock signature (root key, over the signed range of the keyblock, which includes the data key)
    let kb_sig = sig_at(&out[..keyblock_size], 24)?;
    ensure!(
        kb_sig.size == root.size(),
        "the root key is {} bytes, the keyblock signature is {}",
        root.size(),
        kb_sig.size
    );
    ensure!(
        kb_sig.data_size <= keyblock_size && kb_sig.offset + kb_sig.size <= keyblock_size,
        "keyblock signature is outside the keyblock"
    );
    let kb_signature = sign_with(root, Hash::Sha256, &out[..kb_sig.data_size])?;
    out[kb_sig.offset..kb_sig.offset + kb_sig.size].copy_from_slice(&kb_signature);

    // body signature (data key), stored in the preamble; the preamble signature covers it
    let pre_at = keyblock_size;
    let preamble_size = preamble_len(&out, pre_at)?;
    let body_at = pre_at
        .checked_add(preamble_size)
        .ok_or_else(|| anyhow!("body offset overflows"))?;
    let body_sig = sig_at(range(&out, pre_at, preamble_size)?, 72)?;
    ensure!(
        body_sig.size == data.size() && body_sig.offset + body_sig.size <= preamble_size,
        "the body signature does not fit the preamble for a {} byte data key",
        data.size()
    );
    let body_signature = sign_with(data, old.hash, range(&out, body_at, body_sig.data_size)?)?;
    let at = pre_at + body_sig.offset;
    out[at..at + body_sig.size].copy_from_slice(&body_signature);

    // preamble signature (data key)
    let pre_sig = sig_at(range(&out, pre_at, preamble_size)?, 8)?;
    ensure!(
        pre_sig.size == data.size()
            && pre_sig.data_size <= preamble_size
            && pre_sig.offset + pre_sig.size <= preamble_size,
        "the preamble signature does not fit the preamble"
    );
    let pre_signature = sign_with(data, old.hash, range(&out, pre_at, pre_sig.data_size)?)?;
    let at = pre_at + pre_sig.offset;
    out[at..at + pre_sig.size].copy_from_slice(&pre_signature);

    let report = verify_image(name, &out, Some(&RsaPublicKey::from(root)))?;
    ensure!(
        report.verdict() == "valid",
        "the signed image does not verify (verdict {})",
        report.verdict()
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_key_constants_satisfy_the_montgomery_identities() {
        // any odd modulus with its top bit set will do; no key needs generating
        let n = BigUint::from_bytes_be(&[0xc1u8; 128]);
        let public = RsaPublicKey::new_unchecked(n.clone(), BigUint::from(65537u32));
        let kd = packed_key_data(&public, 1024).unwrap();
        assert_eq!(kd.len(), 2 * 128 + 8);
        assert_eq!(u32::from_le_bytes([kd[0], kd[1], kd[2], kd[3]]), 32);
        let n0inv = u32::from_le_bytes([kd[4], kd[5], kd[6], kd[7]]);
        let n_le = &kd[8..136];
        assert_eq!(BigUint::from_bytes_le(n_le), n);
        let n0 = u32::from_le_bytes([n_le[0], n_le[1], n_le[2], n_le[3]]);
        assert_eq!(
            n0.wrapping_mul(n0inv),
            u32::MAX,
            "n0inv is -1 / n[0] mod 2^32"
        );
        let rr = BigUint::from_bytes_le(&kd[136..264]);
        assert_eq!(
            rr,
            (BigUint::from(1u8) << 2048usize) % &n,
            "rr is R^2 mod n"
        );
    }
}
