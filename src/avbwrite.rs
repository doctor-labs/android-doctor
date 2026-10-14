//! Writing AVB `vbmeta` images: the part of avbtool `make_vbmeta_image` that needs no descriptors.
//! The image is a header, an authentication block (SHA-256 digest and, for the RSA algorithms, a
//! PKCS#1 v1.5 signature over header and auxiliary block) and an auxiliary block that holds the
//! AVB public key. Layout from AOSP libavb `avb_vbmeta_image.h` (Apache-2.0), and byte-checked
//! against AOSP avbtool `_generate_vbmeta_blob` (see the README row). All integers are big-endian.
use anyhow::{Context, Result, ensure};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

const HEADER_LEN: usize = 256;
const AUTH_ALIGN: usize = 64;
const RELEASE_MAX: usize = 47;

/// The algorithms avbtool knows without a descriptor-only path: name, AVB algorithm type, and
/// RSA modulus size in bits (0 for NONE, which takes no key).
pub const ALGORITHMS: &[(&str, u32, usize)] = &[
    ("NONE", 0, 0),
    ("SHA256_RSA2048", 1, 2048),
    ("SHA256_RSA4096", 2, 4096),
    ("SHA256_RSA8192", 3, 8192),
];

/// What to put in the header. The defaults match `avbtool make_vbmeta_image` with no options.
pub struct Options<'a> {
    pub algorithm: &'a str,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    /// When non-zero, the image is zero-padded to a multiple of this many bytes.
    pub padding_size: u64,
    pub release_string: &'a str,
}

/// PKCS#1 v1.5 scheme for a SHA-256 digest that is already computed (the DigestInfo prefix is
/// written out here, so it does not depend on the digest crate's trait versions).
fn sha256_scheme() -> Pkcs1v15Sign {
    Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]
        .into_boxed_slice(),
    }
}

fn round_up(n: usize, to: usize) -> usize {
    n.div_ceil(to) * to
}

/// Read a PEM RSA private key, PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
pub fn parse_private_key(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .context("invalid PEM RSA private key")
}

/// Build a vbmeta image. `key` is required for the RSA algorithms and must match their size.
pub fn make_vbmeta(opts: &Options, key: Option<&RsaPrivateKey>) -> Result<Vec<u8>> {
    let &(_, alg_type, bits) = ALGORITHMS
        .iter()
        .find(|a| a.0 == opts.algorithm)
        .with_context(|| {
            let names: Vec<_> = ALGORITHMS.iter().map(|a| a.0).collect();
            format!(
                "unknown algorithm {} (one of {})",
                opts.algorithm,
                names.join(", ")
            )
        })?;
    ensure!(
        opts.release_string.len() <= RELEASE_MAX,
        "release string is longer than {RELEASE_MAX} bytes"
    );

    // Auxiliary block: the public key (descriptors and metadata are not written by this path).
    let mut aux = Vec::new();
    if bits > 0 {
        let key = key.context("this algorithm needs a signing key (--key)")?;
        ensure!(
            key.size() * 8 == bits,
            "{} needs a {bits}-bit RSA key, this one is {} bits",
            opts.algorithm,
            key.size() * 8
        );
        aux.extend_from_slice(&crate::avb::public_key_blob(key.n()));
    }
    let pk_size = aux.len();
    let aux_size = round_up(aux.len(), AUTH_ALIGN);
    aux.resize(aux_size, 0);

    // Authentication block: SHA-256 digest, then the signature, padded.
    let (hash_len, sig_len) = if bits > 0 { (32, bits / 8) } else { (0, 0) };
    let auth_size = round_up(hash_len + sig_len, AUTH_ALIGN);

    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(b"AVB0");
    h.extend_from_slice(&1u32.to_be_bytes()); // required libavb major
    h.extend_from_slice(&0u32.to_be_bytes()); // required libavb minor
    h.extend_from_slice(&(auth_size as u64).to_be_bytes());
    h.extend_from_slice(&(aux_size as u64).to_be_bytes());
    h.extend_from_slice(&alg_type.to_be_bytes());
    h.extend_from_slice(&0u64.to_be_bytes()); // hash offset
    h.extend_from_slice(&(hash_len as u64).to_be_bytes());
    h.extend_from_slice(&(hash_len as u64).to_be_bytes()); // signature offset
    h.extend_from_slice(&(sig_len as u64).to_be_bytes());
    h.extend_from_slice(&0u64.to_be_bytes()); // public key offset (no descriptors before it)
    h.extend_from_slice(&(pk_size as u64).to_be_bytes());
    h.extend_from_slice(&(pk_size as u64).to_be_bytes()); // public key metadata offset
    h.extend_from_slice(&0u64.to_be_bytes()); // public key metadata size
    h.extend_from_slice(&0u64.to_be_bytes()); // descriptors offset
    h.extend_from_slice(&0u64.to_be_bytes()); // descriptors size
    h.extend_from_slice(&opts.rollback_index.to_be_bytes());
    h.extend_from_slice(&opts.flags.to_be_bytes());
    h.extend_from_slice(&opts.rollback_index_location.to_be_bytes());
    let mut release = [0u8; RELEASE_MAX + 1];
    release[..opts.release_string.len()].copy_from_slice(opts.release_string.as_bytes());
    h.extend_from_slice(&release);
    h.extend_from_slice(&[0u8; 80]); // reserved
    debug_assert_eq!(h.len(), HEADER_LEN);

    let mut auth = Vec::with_capacity(auth_size);
    if let Some(key) = key.filter(|_| bits > 0) {
        let mut hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&aux);
        let digest = hasher.finalize();
        let sig = key
            .sign(sha256_scheme(), &digest)
            .context("signing the vbmeta header")?;
        ensure!(
            sig.len() == sig_len,
            "signature is {} bytes, expected {sig_len}",
            sig.len()
        );
        auth.extend_from_slice(&digest);
        auth.extend_from_slice(&sig);
    }
    auth.resize(auth_size, 0);

    let mut out = Vec::with_capacity(HEADER_LEN + auth_size + aux_size);
    out.extend_from_slice(&h);
    out.extend_from_slice(&auth);
    out.extend_from_slice(&aux);
    if opts.padding_size > 0 {
        let padded = round_up(out.len(), opts.padding_size as usize);
        out.resize(padded, 0);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NONE header alone is 256 bytes and carries the algorithm type and rollback index.
    #[test]
    fn none_header_is_256_bytes_with_the_given_fields() {
        let img = make_vbmeta(
            &Options {
                algorithm: "NONE",
                rollback_index: 9,
                flags: 2,
                rollback_index_location: 0,
                padding_size: 0,
                release_string: "test 1",
            },
            None,
        )
        .unwrap();
        assert_eq!(img.len(), 256);
        assert_eq!(&img[0..4], b"AVB0");
        assert_eq!(u32::from_be_bytes(img[28..32].try_into().unwrap()), 0);
        assert_eq!(u64::from_be_bytes(img[112..120].try_into().unwrap()), 9);
        assert_eq!(u32::from_be_bytes(img[120..124].try_into().unwrap()), 2);
    }

    /// Padding rounds the whole image up, and an RSA algorithm refuses a key of the wrong size.
    #[test]
    fn padding_and_key_size_are_enforced() {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let opts = Options {
            algorithm: "SHA256_RSA2048",
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            padding_size: 0,
            release_string: "",
        };
        assert!(make_vbmeta(&opts, Some(&key)).is_err());
        let none = Options {
            algorithm: "NONE",
            padding_size: 4096,
            ..opts
        };
        assert_eq!(make_vbmeta(&none, None).unwrap().len(), 4096);
    }
}
