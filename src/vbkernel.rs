//! ChromeOS kernel partition (vboot 2.x) verification: the keyblock, the kernel preamble and the
//! kernel body (`vbkernel`, issue #176). Read-only; signing is not built.
//!
//! Layouts and constants are from vboot_reference: `firmware/2lib/include/2struct.h` (keyblock
//! magic "CHROMEKB", `vb2_keyblock` 112 bytes, `vb2_packed_key` 32 bytes, `vb2_signature` 24
//! bytes, `vb2_kernel_preamble` 2.2 = 116 bytes), `2crypto.h` (algorithm numbers) and `2rsa.c`
//! (PKCS#1 v1.5 DigestInfo, key data as little-endian words, big-endian signatures).
//! Signature offsets are relative to the start of the block that holds them (keyblock or
//! preamble); the signed range is the first `data_size` bytes of that block (keyblock and
//! preamble) or of the body (kernel body).
//!
//! Not checked: the root key's own hash choice beyond the three PKCS#1 DigestInfo prefixes,
//! keyblock hashes for unsigned keys, the 2.0/2.1 preamble, and any device-side rollback data.

use crate::detect::refuse_blocking_file;
use anyhow::{Result, anyhow, bail, ensure};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;

const KEYBLOCK_MAGIC: &[u8; 8] = b"CHROMEKB";
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

fn sig_at(b: &[u8], at: usize) -> Result<Sig> {
    Ok(Sig {
        offset: u32_at(b, at)? as usize,
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
    if image.len() < KEYBLOCK_HEADER_LEN || &image[..8] != KEYBLOCK_MAGIC {
        bail!(
            "{} has no ChromeOS keyblock (CHROMEKB) at offset 0",
            path.display()
        );
    }

    // keyblock: vb2_keyblock
    ensure!(
        u32_at(&image, 8)? == 2,
        "unsupported keyblock header version"
    );
    let keyblock_size = u32_at(&image, 16)? as usize;
    ensure!(
        keyblock_size >= KEYBLOCK_HEADER_LEN,
        "keyblock is smaller than its header"
    );
    let keyblock = range(&image, 0, keyblock_size)?;
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
    let preamble_size = u32_at(&image, keyblock_size)? as usize;
    ensure!(
        u32_at(&image, keyblock_size + 32)? == 2,
        "unsupported kernel preamble header version"
    );
    let header_minor = u32_at(&image, keyblock_size + 36)?;
    ensure!(
        header_minor >= 2,
        "kernel preamble 2.{header_minor} is older than 2.2"
    );
    ensure!(
        preamble_size >= PREAMBLE_2_2_LEN,
        "kernel preamble is smaller than 2.2"
    );
    let preamble = range(&image, keyblock_size, preamble_size)?;
    let kernel_version = u32_at(preamble, 40)?;
    let pre_sig = sig_at(preamble, 8)?;
    let preamble_status = verify_block(&data_key, preamble, &pre_sig)?;

    // kernel body: signed by the data key, body_signature in the preamble
    let body_sig = sig_at(preamble, 72)?;
    let body_offset = keyblock_size
        .checked_add(preamble_size)
        .ok_or_else(|| anyhow!("body offset overflows"))?;
    let body = range(&image, body_offset, body_sig.data_size)?;
    let body_bytes = range(preamble, body_sig.offset, body_sig.size)?;
    let body_status = if verify_with(&data_key.key, data_key.hash, body_bytes, body) {
        Status::Valid
    } else {
        Status::Invalid
    };

    Ok(Report {
        file: path.display().to_string(),
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
