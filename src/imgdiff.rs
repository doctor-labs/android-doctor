//! IMGDIFF2 patches (AOSP `imgdiff`), as used by `imgdiff` commands in incremental block OTAs.
//!
//! ```
//! "IMGDIFF2", u32 chunk count, then per chunk a u32 type (all little-endian):
//!   0 NORMAL  u64 src_start, u64 src_len, u64 patch_offset      bsdiff patch at patch_offset
//!   2 DEFLATE u64 src_start, u64 src_len, u64 patch_offset, u64 src_expanded_len,
//!             u64 target_len, u32 level, u32 method, u32 window_bits, u32 mem_level, u32 strategy
//!             inflate the source deflate stream, bspatch it, deflate the result again
//!   3 RAW     u32 length, then the bytes
//! ```
//! `patch_offset` is relative to the start of the patch. The chunk outputs are concatenated.
//!
//! A DEFLATE chunk must be re-compressed exactly as the original encoder did, which only works
//! when the deflate implementation here produces the same bytes as zlib for these parameters.
//! Only the default `mem_level` 8 and strategy 0 are attempted, and the result must have the
//! declared length; the transfer list's target hash (version 3 and later) is the final check.
//! Written from the AOSP source's description; validated against spec-built patches only.
use anyhow::{Context, Result, bail, ensure};
use std::io::{Read, Write};

const MAX_CHUNKS: usize = 1 << 20;
const MAX_EXPANDED: u64 = 1 << 30;

fn u32at(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).context("imgdiff: patch is truncated")?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64at(b: &[u8], at: usize) -> Result<u64> {
    let s = b.get(at..at + 8).context("imgdiff: patch is truncated")?;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}

fn src_slice(src: &[u8], start: u64, len: u64) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .context("imgdiff: source range overflows")?;
    src.get(start as usize..end as usize)
        .context("imgdiff: chunk reads past the source")
}

fn chunk_patch(patch: &[u8], off: u64) -> Result<&[u8]> {
    patch
        .get(off as usize..)
        .context("imgdiff: patch offset is outside the patch")
}

pub fn apply(patch: &[u8], src: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        patch.len() >= 12 && &patch[..8] == b"IMGDIFF2",
        "imgdiff: bad magic"
    );
    let n = u32at(patch, 8)? as usize;
    ensure!(n <= MAX_CHUNKS, "imgdiff: implausible chunk count {n}");
    let (mut at, mut out) = (12usize, Vec::new());
    for _ in 0..n {
        let ty = u32at(patch, at)?;
        at += 4;
        match ty {
            0 => {
                let (s, l, po) = (
                    u64at(patch, at)?,
                    u64at(patch, at + 8)?,
                    u64at(patch, at + 16)?,
                );
                at += 24;
                out.extend(crate::bsdiff::apply(
                    chunk_patch(patch, po)?,
                    src_slice(src, s, l)?,
                )?);
            }
            3 => {
                let len = u32at(patch, at)? as usize;
                at += 4;
                out.extend_from_slice(
                    patch
                        .get(at..at + len)
                        .context("imgdiff: raw chunk is truncated")?,
                );
                at += len;
            }
            2 => {
                let f: Vec<u64> = (0..5)
                    .map(|k| u64at(patch, at + 8 * k))
                    .collect::<Result<_>>()?;
                let p: Vec<u32> = (0..5)
                    .map(|k| u32at(patch, at + 40 + 4 * k))
                    .collect::<Result<_>>()?;
                at += 60;
                let (s, l, po, expanded_len, target_len) = (f[0], f[1], f[2], f[3], f[4]);
                let (level, method, window_bits, mem_level, strategy) =
                    (p[0], p[1], p[2] as i32, p[3], p[4]);
                ensure!(
                    method == 8 && window_bits < 0 && mem_level == 8 && strategy == 0 && level <= 9,
                    "imgdiff: deflate chunk uses parameters this build cannot reproduce exactly \
                     (method {method}, windowBits {window_bits}, memLevel {mem_level}, strategy {strategy})"
                );
                ensure!(
                    expanded_len <= MAX_EXPANDED,
                    "imgdiff: implausible expanded length"
                );
                let mut expanded = Vec::new();
                flate2::read::DeflateDecoder::new(src_slice(src, s, l)?)
                    .take(MAX_EXPANDED + 1)
                    .read_to_end(&mut expanded)
                    .context("imgdiff: the source chunk is not a deflate stream")?;
                ensure!(
                    expanded.len() as u64 == expanded_len,
                    "imgdiff: expanded source has the wrong length"
                );
                let patched = crate::bsdiff::apply(chunk_patch(patch, po)?, &expanded)?;
                let mut enc =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(level));
                enc.write_all(&patched)?;
                let packed = enc.finish()?;
                if packed.len() as u64 != target_len {
                    bail!(
                        "imgdiff: re-compressing a deflate chunk gave {} bytes, the patch expects {target_len} \
                         (this build's deflate is not byte-identical to the encoder's zlib)",
                        packed.len()
                    );
                }
                out.extend(packed);
            }
            other => bail!("imgdiff: unsupported chunk type {other}"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fx {
        ($n:literal) => {
            include_bytes!(concat!("../tests/fixtures/imgdiff/", $n))
        };
    }

    // Raw deflate (memLevel 8, default strategy) from upstream zlib 1.3.2 built by clang from the
    // source libz-sys ships (not through flate2), patches from the real bsdiff4. Python's zlib is
    // Apple's modified one on macOS and differs from upstream at levels 4 and up, so it is not used.
    #[test]
    fn deflate_chunks_are_recompressed_exactly_when_flate2_matches_zlib() {
        for (level, src, patch, tgt) in [
            (
                1,
                &fx!("deflate1.src")[..],
                &fx!("deflate1.patch")[..],
                &fx!("deflate1.tgt")[..],
            ),
            (
                6,
                &fx!("deflate6.src")[..],
                &fx!("deflate6.patch")[..],
                &fx!("deflate6.tgt")[..],
            ),
            (
                9,
                &fx!("deflate9.src")[..],
                &fx!("deflate9.patch")[..],
                &fx!("deflate9.tgt")[..],
            ),
        ] {
            let got = apply(patch, src);
            match got {
                Ok(v) => assert!(v == tgt, "level {level}: output differs from zlib's"),
                Err(e) => panic!("level {level}: {e:#}"),
            }
        }
    }

    #[test]
    fn unsupported_parameters_and_hostile_patches_are_refused() {
        let patch = fx!("deflate6.patch").to_vec();
        let src = fx!("deflate6.src");
        // memLevel 9 cannot be reproduced: refused, not guessed
        let mut p = patch.clone();
        p[12 + 4 + 40 + 12..12 + 4 + 40 + 16].copy_from_slice(&9u32.to_le_bytes());
        assert!(
            apply(&p, src)
                .unwrap_err()
                .to_string()
                .contains("cannot reproduce")
        );
        assert!(apply(b"IMGDIFF1", src).is_err());
        for cut in 0..patch.len() {
            let _ = apply(&patch[..cut], src);
        }
        for at in (0..patch.len()).step_by(3) {
            let mut v = patch.clone();
            v[at] ^= 0xff;
            let _ = apply(&v, src);
        }
    }
}
