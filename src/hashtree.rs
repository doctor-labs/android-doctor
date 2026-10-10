//! dm-verity hash tree generation for partitions rebuilt from a payload.
//!
//! A delta payload omits the dm-verity hash tree (and any FEC parity), so an image rebuilt
//! from one is not verifiable until the tree is regenerated. This computes the tree from the
//! AVB hashtree descriptor so `avbtool verify` accepts the result.
//!
//! Layout (AVB spec): data is split into `data_block_size` blocks; each level of the tree
//! hashes every `hash_block_size`-byte block of the level below, using the descriptor salt and
//! digest algorithm; the tree is stored big-endian, padded to a whole block at each level,
//! until a single root digest remains.
use anyhow::{Context, Result, ensure};
use std::io::{Read, Seek, SeekFrom};

/// Refuse absurd allocations driven by descriptor fields.
const MAX_TREE_BYTES: u64 = 4 << 30;

#[derive(Clone, Copy, PartialEq)]
enum Alg {
    Sha1,
    Sha256,
    Sha512,
}

impl Alg {
    fn parse(name: &str) -> Result<Alg> {
        Ok(match name {
            "sha1" => Alg::Sha1,
            "sha256" => Alg::Sha256,
            "sha512" => Alg::Sha512,
            other => anyhow::bail!("unsupported digest algorithm {other:?}"),
        })
    }

    fn len(self) -> usize {
        match self {
            Alg::Sha1 => 20,
            Alg::Sha256 => 32,
            Alg::Sha512 => 64,
        }
    }

    /// `hash(salt || data)`, per the AVB hashtree digest rule.
    fn digest(self, salt: &[u8], data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Alg::Sha1 => sha1::Sha1::new()
                .chain_update(salt)
                .chain_update(data)
                .finalize()
                .to_vec(),
            Alg::Sha256 => sha2::Sha256::new()
                .chain_update(salt)
                .chain_update(data)
                .finalize()
                .to_vec(),
            Alg::Sha512 => sha2::Sha512::new()
                .chain_update(salt)
                .chain_update(data)
                .finalize()
                .to_vec(),
        }
    }
}

/// Level offsets inside the tree and the tree size, as avbtool's `calc_hash_level_offsets`: levels
/// are stored top first, so level 0 (the digests of the data) is the last and largest.
fn level_layout(
    image_size: u64,
    data_block: u64,
    hash_block: u64,
    stored_digest: u64,
) -> Result<(Vec<u64>, u64)> {
    let (mut sizes, mut size) = (Vec::new(), image_size);
    let mut tree_size = 0u64;
    let mut block = data_block;
    while size > block {
        let n = size.div_ceil(block);
        let level = (n * stored_digest).div_ceil(hash_block) * hash_block;
        sizes.push(level);
        tree_size = tree_size
            .checked_add(level)
            .context("tree size overflows")?;
        ensure!(
            tree_size <= MAX_TREE_BYTES,
            "hashtree: tree would be over {MAX_TREE_BYTES} bytes, refusing"
        );
        size = level;
        block = hash_block;
    }
    let offsets = (0..sizes.len())
        .map(|n| sizes[n + 1..].iter().sum())
        .collect();
    Ok((offsets, tree_size))
}

/// The root digest and the stored tree of `image_size` bytes read from `r`, for descriptor `d`.
/// Digests are stored padded with zeros to a power of two (a sha1 digest takes 32 bytes), levels
/// top first, each padded to whole hash blocks: byte for byte what `avbtool add_hashtree_footer`
/// writes and `verify_image` recomputes.
pub fn build<R: Read + Seek>(
    r: &mut R,
    image_size: u64,
    d: &crate::avb::HashtreeDescriptor,
) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(d.data_block_size > 0, "hashtree: data_block_size is zero");
    ensure!(d.hash_block_size > 0, "hashtree: hash_block_size is zero");
    let (data_block, hash_block) = (u64::from(d.data_block_size), u64::from(d.hash_block_size));
    ensure!(
        data_block <= 1 << 20 && hash_block <= 1 << 20,
        "hashtree: block sizes over 1 MiB are refused"
    );
    let alg = Alg::parse(&d.algorithm)?;
    let dlen = alg.len() as u64;
    ensure!(
        hash_block >= dlen,
        "hashtree: hash_block_size {hash_block} is smaller than a {dlen}-byte digest"
    );
    ensure!(
        image_size > data_block,
        "hashtree: the image is not larger than one block, so there is no tree"
    );
    let stored = dlen.next_power_of_two();
    let (offsets, tree_size) = level_layout(image_size, data_block, hash_block, stored)?;
    let mut tree = vec![0u8; tree_size as usize];
    let pad = vec![0u8; (stored - dlen) as usize];
    let mut buf = vec![0u8; data_block as usize];
    let (mut src_size, mut level_out) = (image_size, Vec::new());
    for (n, &off) in offsets.iter().enumerate() {
        level_out = Vec::new();
        let mut remaining = src_size;
        let block = if n == 0 { data_block } else { hash_block };
        let mut at = 0u64;
        while remaining > 0 {
            let take = remaining.min(block) as usize;
            let mut chunk = vec![0u8; block as usize];
            if n == 0 {
                r.seek(SeekFrom::Start(at))?;
                r.read_exact(&mut buf[..take])
                    .context("reading the image")?;
                chunk[..take].copy_from_slice(&buf[..take]);
            } else {
                let from = (offsets[n - 1] + at) as usize;
                chunk[..take].copy_from_slice(&tree[from..from + take]);
            }
            level_out.extend(alg.digest(&d.salt, &chunk));
            level_out.extend(&pad);
            remaining -= take as u64;
            at += take as u64;
        }
        level_out.resize(
            level_out.len().div_ceil(hash_block as usize) * hash_block as usize,
            0,
        );
        tree[off as usize..off as usize + level_out.len()].copy_from_slice(&level_out);
        src_size = level_out.len() as u64;
    }
    let root = alg.digest(&d.salt, &level_out);
    Ok((root, tree))
}

/// Compute the dm-verity hash tree for `image` described by `d`.
///
/// Returns the tree bytes ready to sit at `d.tree_offset`. The computed root digest is checked
/// against the descriptor, so a mismatch is an error rather than a silently unverifiable image.
pub fn hash_tree(image: &[u8], d: &crate::avb::HashtreeDescriptor) -> Result<Vec<u8>> {
    let (root, tree) = build(&mut std::io::Cursor::new(image), image.len() as u64, d)?;
    ensure!(
        root == d.root_digest,
        "hashtree: computed root {} does not match the descriptor root {}",
        hex(&root),
        hex(&d.root_digest)
    );
    Ok(tree)
}

/// What recomputing a hashtree descriptor against an image file found.
#[derive(Debug, Clone, PartialEq)]
pub enum TreeCheck {
    /// The data hashes to the root digest and the stored tree is the one the data produces.
    Ok,
    /// The data hashes to the root digest, but the stored tree is zeroed (`ZeRoHaSH`, or empty):
    /// the tree must be regenerated before the device can verify the partition.
    Zeroed,
    /// The data does not hash to the descriptor's root digest.
    RootMismatch,
    /// The root digest matches but the stored tree differs (or lies outside the file).
    TreeMismatch,
    Unsupported(String),
}

/// Recompute the tree of the image file at `path` for `d` and compare the root digest and the
/// stored tree, as avbtool's `HashtreeDescriptor.verify` does. The FEC data is not checked.
pub fn verify_file(
    path: &std::path::Path,
    d: &crate::avb::HashtreeDescriptor,
) -> Result<TreeCheck> {
    crate::detect::refuse_blocking_file(path)?;
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = f.metadata()?.len();
    if d.data_block_size != d.hash_block_size {
        return Ok(TreeCheck::Unsupported(
            "data and hash block sizes differ".into(),
        ));
    }
    if let Err(e) = Alg::parse(&d.algorithm) {
        return Ok(TreeCheck::Unsupported(format!("{e}")));
    }
    if d.image_size > len {
        return Ok(TreeCheck::RootMismatch);
    }
    let (root, tree) = match build(&mut f, d.image_size, d) {
        Ok(v) => v,
        Err(e) if e.to_string().contains("no tree") => {
            return Ok(TreeCheck::Unsupported(format!("{e}")));
        }
        Err(e) => return Err(e),
    };
    if !d.root_digest.is_empty() && root != d.root_digest {
        return Ok(TreeCheck::RootMismatch);
    }
    let end = d.tree_offset.checked_add(d.tree_size);
    if d.tree_size == 0 {
        return Ok(TreeCheck::Zeroed);
    }
    if end.is_none_or(|e| e > len) || d.tree_size > MAX_TREE_BYTES {
        return Ok(TreeCheck::TreeMismatch);
    }
    f.seek(SeekFrom::Start(d.tree_offset))?;
    let mut ondisk = vec![0u8; d.tree_size as usize];
    f.read_exact(&mut ondisk)?;
    Ok(if ondisk == tree {
        TreeCheck::Ok
    } else if ondisk.starts_with(b"ZeRoHaSH") {
        TreeCheck::Zeroed
    } else {
        TreeCheck::TreeMismatch
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(data_bs: u32, hash_bs: u32, root: &str) -> crate::avb::HashtreeDescriptor {
        crate::avb::HashtreeDescriptor {
            partition: "test".into(),
            algorithm: "sha256".into(),
            version: 1,
            image_size: 8192,
            tree_offset: 0,
            tree_size: 0,
            data_block_size: data_bs,
            hash_block_size: hash_bs,
            fec_num_roots: 0,
            fec_offset: 0,
            fec_size: 0,
            salt: (0u8..32).collect(),
            root_digest: hex_bytes(root),
            flags: 0,
        }
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn image() -> Vec<u8> {
        (0..8192u32).map(|i| ((i * 7 + 3) % 256) as u8).collect()
    }

    /// The expected roots come from avbtool itself (see the cases), not from this code. The
    /// multi-level and sha1/sha512 layouts are checked against avbtool-made images in avb.rs.
    #[test]
    fn a_tree_matches_an_independent_implementation_of_the_avb_spec() {
        let img = image();
        // roots from avbtool 1.3.0's own generate_hash_tree (sha256, salt 0..32, 8192 bytes)
        let cases = [
            (
                4096,
                4096,
                "f90b2b23f4f78e4d2b702a66d59f80bedcc4fcbe42c87a6fa95ab37f18bbade2",
                4096,
            ),
            (
                1024,
                1024,
                "518fd01721a742c5f14573ae582506f0c00e12bed28ade0ae6c2b0a24574a53d",
                1024,
            ),
            (
                512,
                512,
                "5f2f4054f5e6080fb67f9cd1862eab00a587c3316545b777a09bd9994db3921d",
                512,
            ),
        ];
        for (data_bs, hash_bs, root, tree_len) in cases {
            let d = desc(data_bs, hash_bs, root);
            let tree = hash_tree(&img, &d).unwrap();
            assert_eq!(
                tree.len(),
                tree_len,
                "tree length for data={data_bs} hash={hash_bs}"
            );
        }
    }

    #[test]
    fn a_wrong_root_digest_is_an_error_not_a_silent_wrong_tree() {
        let d = desc(
            4096,
            4096,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let e = hash_tree(&image(), &d).unwrap_err().to_string();
        assert!(e.contains("does not match"), "{e}");
    }

    #[test]
    fn a_zero_block_size_is_refused_rather_than_dividing_by_zero() {
        assert!(hash_tree(&image(), &desc(0, 4096, "00")).is_err());
        assert!(hash_tree(&image(), &desc(4096, 0, "00")).is_err());
    }

    #[test]
    fn a_hash_block_smaller_than_a_digest_is_refused() {
        assert!(hash_tree(&image(), &desc(4096, 16, "00")).is_err());
    }

    #[test]
    fn an_unsupported_algorithm_is_reported_not_treated_as_sha256() {
        let mut d = desc(4096, 4096, "00");
        d.algorithm = "md5".into();
        let e = hash_tree(&image(), &d).unwrap_err().to_string();
        assert!(e.contains("unsupported"), "{e}");
    }

    #[test]
    fn a_partial_final_data_block_is_padded_not_dropped() {
        // 8193 bytes: the last block is 1 byte and must be zero-padded to 4096.
        let mut img = image();
        img.push(9);
        let d = desc(
            4096,
            4096,
            "f90b2b23f4f78e4d2b702a66d59f80bedcc4fcbe42c87a6fa95ab37f18bbade2",
        );
        // The root WILL differ from the 8192-byte case; what matters is that it does not
        // panic and does not reuse the previous root.
        assert!(
            hash_tree(&img, &d).is_err(),
            "changed data must change the root"
        );
        let _ = hash_tree(&img, &d).unwrap_err();
    }

    #[test]
    fn an_empty_image_does_not_panic() {
        let d = desc(4096, 4096, "00");
        assert!(
            hash_tree(&[], &d).is_err(),
            "empty image has no valid root here"
        );
    }
}
