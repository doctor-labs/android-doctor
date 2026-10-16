//! Writing AVB `vbmeta` images and partition hash footers: the parts of avbtool `make_vbmeta_image`,
//! `add_hash_footer` and `erase_footer` that this crate mirrors. A vbmeta image is a header, an
//! authentication block (SHA-256 digest and, for the RSA algorithms, a PKCS#1 v1.5 signature over
//! header and auxiliary block) and an auxiliary block holding the descriptors and the AVB public
//! key. Layout from AOSP libavb `avb_vbmeta_image.h`, `avb_hash_descriptor.h` and `avb_footer.h`
//! (Apache-2.0), byte-checked against AOSP avbtool 1.3.0 (see the README rows). All integers are
//! big-endian.
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
const FOOTER_LEN: usize = 64;
const MAX_VBMETA: usize = 64 * 1024;
const MAX_FOOTER: usize = 4096;
const HASH_DESCRIPTOR_TAG: u64 = 2;
const HASHTREE_DESCRIPTOR_TAG: u64 = 1;

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

/// What a hash footer covers: the partition name in the hash descriptor, the partition size the
/// result is padded to, the block size, and the salt (hashed in front of the image).
pub struct FooterOptions<'a> {
    pub partition: &'a str,
    pub partition_size: u64,
    pub block_size: u64,
    pub salt: &'a [u8],
    /// Write a dm-verity hash tree (avbtool add_hashtree_footer, SHA-256, no FEC) instead of one hash descriptor
    pub hashtree: bool,
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

/// Decode a hex string (even length) into bytes.
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.is_ascii() && s.len().is_multiple_of(2),
        "hex value must be an even number of ASCII digits"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).with_context(|| format!("bad hex digits in {s}"))
        })
        .collect()
}

/// Read a PEM RSA private key, PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
pub fn parse_private_key(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .context("invalid PEM RSA private key")
}

/// Build a vbmeta image with no descriptors. `key` is required for the RSA algorithms.
pub fn make_vbmeta(opts: &Options, key: Option<&RsaPrivateKey>) -> Result<Vec<u8>> {
    make_vbmeta_with(opts, key, &[])
}

/// Build a vbmeta image whose auxiliary block starts with `descriptors` (already encoded, each a
/// multiple of 8 bytes), followed by the public key. `key` is required for the RSA algorithms and
/// must match their size.
pub fn make_vbmeta_with(
    opts: &Options,
    key: Option<&RsaPrivateKey>,
    descriptors: &[u8],
) -> Result<Vec<u8>> {
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

    // Auxiliary block: descriptors, then the public key (no metadata).
    let mut aux = descriptors.to_vec();
    let desc_size = aux.len();
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
    let pk_size = aux.len() - desc_size;
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
    h.extend_from_slice(&(desc_size as u64).to_be_bytes()); // public key offset
    h.extend_from_slice(&(pk_size as u64).to_be_bytes());
    h.extend_from_slice(&((desc_size + pk_size) as u64).to_be_bytes()); // public key metadata offset
    h.extend_from_slice(&0u64.to_be_bytes()); // public key metadata size
    h.extend_from_slice(&0u64.to_be_bytes()); // descriptors offset
    h.extend_from_slice(&(desc_size as u64).to_be_bytes()); // descriptors size
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

/// Encode an AVB hash descriptor (tag 2) for SHA-256: the image size, salt and digest, padded to
/// 8 bytes. Field order from libavb `avb_hash_descriptor.h`.
pub fn hash_descriptor(partition: &str, image_size: u64, salt: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&HASH_DESCRIPTOR_TAG.to_be_bytes());
    d.extend_from_slice(&0u64.to_be_bytes()); // num_bytes_following, set below
    d.extend_from_slice(&image_size.to_be_bytes());
    let mut alg = [0u8; 32];
    alg[..6].copy_from_slice(b"sha256");
    d.extend_from_slice(&alg);
    d.extend_from_slice(&(partition.len() as u32).to_be_bytes());
    d.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    d.extend_from_slice(&(digest.len() as u32).to_be_bytes());
    d.extend_from_slice(&0u32.to_be_bytes()); // flags
    d.extend_from_slice(&[0u8; 60]); // reserved
    d.extend_from_slice(partition.as_bytes());
    d.extend_from_slice(salt);
    d.extend_from_slice(digest);
    d.resize(round_up(d.len(), 8), 0);
    let following = (d.len() - 16) as u64;
    d[8..16].copy_from_slice(&following.to_be_bytes());
    d
}

/// Encode an AVB hashtree descriptor (tag 1) for dm-verity SHA-256 without FEC, padded to 8 bytes.
/// Field order from libavb `avb_hashtree_descriptor.h`.
pub fn hashtree_descriptor(
    partition: &str,
    image_size: u64,
    tree: (u64, u64),
    block: u32,
    salt: &[u8],
    root: &[u8],
) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&HASHTREE_DESCRIPTOR_TAG.to_be_bytes());
    d.extend_from_slice(&0u64.to_be_bytes()); // num_bytes_following, set below
    d.extend_from_slice(&1u32.to_be_bytes()); // dm_verity_version
    d.extend_from_slice(&image_size.to_be_bytes());
    d.extend_from_slice(&tree.0.to_be_bytes()); // tree offset
    d.extend_from_slice(&tree.1.to_be_bytes()); // tree size
    d.extend_from_slice(&block.to_be_bytes()); // data block size
    d.extend_from_slice(&block.to_be_bytes()); // hash block size
    d.extend_from_slice(&0u32.to_be_bytes()); // FEC roots
    d.extend_from_slice(&0u64.to_be_bytes()); // FEC offset
    d.extend_from_slice(&0u64.to_be_bytes()); // FEC size
    let mut alg = [0u8; 32];
    alg[..6].copy_from_slice(b"sha256");
    d.extend_from_slice(&alg);
    d.extend_from_slice(&(partition.len() as u32).to_be_bytes());
    d.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    d.extend_from_slice(&(root.len() as u32).to_be_bytes());
    d.extend_from_slice(&0u32.to_be_bytes()); // flags
    d.extend_from_slice(&[0u8; 60]); // reserved
    d.extend_from_slice(partition.as_bytes());
    d.extend_from_slice(salt);
    d.extend_from_slice(root);
    d.resize(round_up(d.len(), 8), 0);
    let following = (d.len() - 16) as u64;
    d[8..16].copy_from_slice(&following.to_be_bytes());
    d
}

fn has_footer(image: &[u8]) -> bool {
    image.len() >= FOOTER_LEN && &image[image.len() - FOOTER_LEN..][..4] == b"AVBf"
}

/// Build a partition image with an AVB hash footer, as avbtool `add_hash_footer`: the image
/// padded to the block size, the vbmeta image (one hash descriptor, optionally signed), zero fill,
/// and a last block whose final 64 bytes are the footer. The output is exactly `partition_size`
/// bytes. The input is only read.
pub fn hash_footer(
    image: &[u8],
    fo: &FooterOptions,
    opts: &Options,
    key: Option<&RsaPrivateKey>,
) -> Result<Vec<u8>> {
    let block = fo.block_size as usize;
    ensure!(
        block > 0 && fo.partition_size.is_multiple_of(fo.block_size),
        "partition size {} is not a multiple of the block size {}",
        fo.partition_size,
        fo.block_size
    );
    ensure!(
        !has_footer(image),
        "the image already has an AVB footer; erase it first"
    );
    let max_metadata = (MAX_VBMETA + MAX_FOOTER) as u64;
    ensure!(
        fo.partition_size >= max_metadata,
        "partition size {} is below the {max_metadata} bytes of metadata",
        fo.partition_size
    );
    ensure!(
        image.len() as u64 <= fo.partition_size - max_metadata,
        "image of {} bytes does not fit in partition size {} with its metadata",
        image.len(),
        fo.partition_size
    );

    let mut out = image.to_vec();
    out.resize(round_up(out.len(), block), 0);
    let desc = if fo.hashtree {
        let probe = crate::avb::HashtreeDescriptor {
            partition: fo.partition.to_string(),
            algorithm: "sha256".to_string(),
            version: 1,
            image_size: image.len() as u64,
            tree_offset: 0,
            tree_size: 0,
            data_block_size: block as u32,
            hash_block_size: block as u32,
            fec_num_roots: 0,
            fec_offset: 0,
            fec_size: 0,
            salt: fo.salt.to_vec(),
            root_digest: Vec::new(),
            flags: 0,
        };
        let (root, tree) =
            crate::hashtree::build(&mut std::io::Cursor::new(image), image.len() as u64, &probe)?;
        let data_size = out.len() as u64;
        let tree_offset = data_size;
        out.extend_from_slice(&tree);
        out.resize(round_up(out.len(), block), 0);
        hashtree_descriptor(
            fo.partition,
            data_size,
            (tree_offset, tree.len() as u64),
            block as u32,
            fo.salt,
            &root,
        )
    } else {
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(fo.salt);
            hasher.update(image);
            hasher.finalize()
        };
        hash_descriptor(fo.partition, image.len() as u64, fo.salt, &digest)
    };
    let vbmeta = make_vbmeta_with(opts, key, &desc)?;
    let vbmeta_offset = out.len();
    out.extend_from_slice(&vbmeta);
    out.resize(round_up(out.len(), block), 0);
    let partition = fo.partition_size as usize;
    ensure!(
        out.len() <= partition - block,
        "vbmeta does not fit before the footer block"
    );
    out.resize(partition - FOOTER_LEN, 0);
    out.extend_from_slice(b"AVBf");
    out.extend_from_slice(&1u32.to_be_bytes()); // footer major
    out.extend_from_slice(&0u32.to_be_bytes()); // footer minor
    out.extend_from_slice(&(image.len() as u64).to_be_bytes()); // original image size
    out.extend_from_slice(&(vbmeta_offset as u64).to_be_bytes());
    out.extend_from_slice(&(vbmeta.len() as u64).to_be_bytes());
    out.extend_from_slice(&[0u8; 28]); // reserved
    debug_assert_eq!(out.len(), partition);
    Ok(out)
}

/// The image without its AVB footer and the vbmeta it points to: the first `original_image_size`
/// bytes (avbtool `erase_footer` without `--keep_hashtree`).
pub fn erase_footer(image: &[u8]) -> Result<Vec<u8>> {
    ensure!(has_footer(image), "the image has no AVB footer");
    let f = &image[image.len() - FOOTER_LEN..];
    let major = u32::from_be_bytes(f[4..8].try_into().unwrap());
    ensure!(major == 1, "unsupported AVB footer version {major}");
    let original = u64::from_be_bytes(f[12..20].try_into().unwrap());
    ensure!(
        original <= (image.len() - FOOTER_LEN) as u64,
        "footer says the original image is {original} bytes, longer than this image"
    );
    Ok(image[..original as usize].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(release: &str) -> Options<'_> {
        Options {
            algorithm: "NONE",
            rollback_index: 0,
            flags: 0,
            rollback_index_location: 0,
            padding_size: 0,
            release_string: release,
        }
    }

    fn sample() -> Vec<u8> {
        (0..1000).flat_map(|_| 0..=255u8).collect()
    }

    /// The NONE header alone is 256 bytes and carries the algorithm type and rollback index.
    #[test]
    fn none_header_is_256_bytes_with_the_given_fields() {
        let img = make_vbmeta(
            &Options {
                rollback_index: 9,
                flags: 2,
                release_string: "test 1",
                ..none("")
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
            ..none("")
        };
        assert!(make_vbmeta(&opts, Some(&key)).is_err());
        let padded = Options {
            algorithm: "NONE",
            padding_size: 4096,
            ..opts
        };
        assert_eq!(make_vbmeta(&padded, None).unwrap().len(), 4096);
    }

    /// Byte-identical to avbtool 1.3.0 `add_hash_footer --image img --partition_size 1048576
    /// --partition_name boot --salt 00112233445566778899aabbccddeeff --algorithm NONE
    /// --internal_release_string "android-doctor test"` on the same 256000-byte input.
    #[test]
    fn hash_footer_matches_avbtool_bytes() {
        let image = sample();
        let salt = unhex("00112233445566778899aabbccddeeff").unwrap();
        let out = hash_footer(
            &image,
            &FooterOptions {
                partition: "boot",
                partition_size: 1048576,
                block_size: 4096,
                salt: &salt,
                hashtree: false,
            },
            &none("android-doctor test"),
            None,
        )
        .unwrap();
        assert_eq!(
            crate::avb::hex(&Sha256::digest(&out)),
            "be18a4a603142710144e86ddd9b7dda7ab946a7f0a440918fe5ca588445da081"
        );
    }

    /// The footer points at a vbmeta whose one hash descriptor carries sha256(salt || image).
    #[test]
    fn footer_points_at_a_vbmeta_with_the_hash_descriptor() {
        let image = sample();
        let salt = unhex("00112233445566778899aabbccddeeff").unwrap();
        let out = hash_footer(
            &image,
            &FooterOptions {
                partition: "boot",
                partition_size: 1048576,
                block_size: 4096,
                salt: &salt,
                hashtree: false,
            },
            &none("x"),
            None,
        )
        .unwrap();
        let f = &out[out.len() - FOOTER_LEN..];
        assert_eq!(&f[..4], b"AVBf");
        assert_eq!(u64::from_be_bytes(f[12..20].try_into().unwrap()), 256000);
        let at = u64::from_be_bytes(f[20..28].try_into().unwrap()) as usize;
        let len = u64::from_be_bytes(f[28..36].try_into().unwrap()) as usize;
        assert_eq!(at, 258048);
        let meta = crate::avb::parse(&out[at..at + len], None).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(&image);
        match &meta.descriptors[..] {
            [crate::avb::Descriptor::Hash(h)] => {
                assert_eq!(h.partition, "boot");
                assert_eq!(h.algorithm, "sha256");
                assert_eq!(h.image_size, 256000);
                assert_eq!(h.salt, salt);
                assert_eq!(h.digest, hasher.finalize().to_vec());
            }
            other => panic!("expected one hash descriptor, got {other:?}"),
        }
    }

    /// With `hashtree`, the tree sits where the descriptor says and its root matches the image.
    #[test]
    fn hashtree_footer_places_a_verifiable_tree() {
        let image = sample();
        let out = hash_footer(
            &image,
            &FooterOptions {
                partition: "system",
                partition_size: 1048576,
                block_size: 4096,
                salt: &[7u8; 16],
                hashtree: true,
            },
            &none("x"),
            None,
        )
        .unwrap();
        let f = &out[out.len() - FOOTER_LEN..];
        let at = u64::from_be_bytes(f[20..28].try_into().unwrap()) as usize;
        let len = u64::from_be_bytes(f[28..36].try_into().unwrap()) as usize;
        let meta = crate::avb::parse(&out[at..at + len], None).unwrap();
        match &meta.descriptors[..] {
            [crate::avb::Descriptor::Hashtree(h)] => {
                let tree = crate::hashtree::hash_tree(&image, h).unwrap();
                let at = h.tree_offset as usize;
                assert_eq!(&out[at..at + h.tree_size as usize], &tree[..]);
            }
            other => panic!("expected one hashtree descriptor, got {other:?}"),
        }
    }

    /// Erasing the footer gives back the original bytes; a footer is refused twice and a
    /// partition too small for its metadata is refused.
    #[test]
    fn erase_round_trips_and_refusals_hold() {
        let image = sample();
        let fo = |size| FooterOptions {
            partition: "boot",
            partition_size: size,
            block_size: 4096,
            salt: &[1, 2, 3, 4],
            hashtree: false,
        };
        let out = hash_footer(&image, &fo(1048576), &none("x"), None).unwrap();
        assert_eq!(erase_footer(&out).unwrap(), image);
        assert!(erase_footer(&image).is_err());
        assert!(hash_footer(&out, &fo(1048576), &none("x"), None).is_err());
        assert!(hash_footer(&image, &fo(4096), &none("x"), None).is_err());
    }
}
