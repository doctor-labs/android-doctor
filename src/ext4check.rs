//! Read-only ext journal replay (an in-memory overlay) and an e2fsck-class consistency check.
//!
//! Layouts follow e2fsprogs: `lib/ext2fs/ext2_fs.h` (superblock and group descriptor offsets and the
//! 64bit `_hi` halves), `lib/ext2fs/kernel-jbd.h` and `e2fsck/recovery.c` (jbd2 block types, tag
//! layout and flags, revoke records). Nothing is written: replayed blocks are served from the journal
//! bytes, and the image file is never modified.

use crate::ext4fs::{Fs, Journal, le16, le32};
use crate::findings::{self, Finding, Severity};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR: u32 = 1;
const JBD2_COMMIT: u32 = 2;
const JBD2_REVOKE: u32 = 5;
const JBD2_INCOMPAT_64BIT: u32 = 0x2;
const JBD2_INCOMPAT_CSUM_V2: u32 = 0x8;
const JBD2_INCOMPAT_CSUM_V3: u32 = 0x10;
const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;
/// The most block groups the check walks; more is refused as corrupt.
const MAX_GROUPS: u64 = 1 << 20;
/// Byte offset of `s_journal_inum` in the ext superblock.
const SB_JOURNAL_INUM: usize = 0xE0;

fn be16(b: &[u8], at: usize) -> u32 {
    u32::from(u16::from_be_bytes([b[at], b[at + 1]]))
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Where a replayed filesystem block gets its new content: a journal block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replayed {
    /// Journal block holding the content (block 0 is the journal superblock).
    pub journal_block: u64,
    /// The tag had the escape flag, so the first four bytes are restored to the jbd2 magic.
    pub escaped: bool,
    /// Sequence number of the committed transaction whose tag wins.
    pub sequence: u32,
}

/// The replay plan: the filesystem blocks the committed transactions would overwrite.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Overlay {
    pub blocks: BTreeMap<u64, Replayed>,
    /// Journal block size; the overlay serves blocks of this size.
    pub block_size: usize,
    /// Committed transactions walked from `s_start`.
    pub transactions: u32,
    /// Revoke entries found in committed transactions.
    pub revoke_records: u32,
    /// Blocks whose latest tag a later revoke entry cancels.
    pub cancelled: u32,
}

impl Overlay {
    /// Walk the log from `s_start` the way e2fsck recovery does, recording only. `jbytes` is the
    /// journal as `Fs::journal` returns it. Only committed transactions count, so a torn tail is
    /// ignored. The walk stops at the first block whose magic or sequence breaks the chain.
    pub fn plan(j: &Journal, fs_block_size: u64, jbytes: &[u8]) -> Result<Overlay> {
        let mut ov = Overlay::default();
        if j.start == 0 {
            return Ok(ov);
        }
        ensure!(
            u64::from(j.block_size) == fs_block_size,
            "journal block size {} differs from the filesystem block size {fs_block_size}; replay is not attempted",
            j.block_size
        );
        let bs = j.block_size as usize;
        ov.block_size = bs;
        let first = u64::from(j.first);
        let max = u64::from(j.max_blocks);
        ensure!(
            first >= 1 && first < max,
            "journal s_first {first} is outside its {max} blocks"
        );
        let avail = (jbytes.len() / bs) as u64;
        let inc = j.feature_incompat;
        let is64 = inc & JBD2_INCOMPAT_64BIT != 0;
        let csum3 = inc & JBD2_INCOMPAT_CSUM_V3 != 0;
        let tag_bytes = if csum3 {
            16
        } else {
            let sz = 12
                + if inc & JBD2_INCOMPAT_CSUM_V2 != 0 {
                    2
                } else {
                    0
                };
            if is64 { sz } else { sz - 4 }
        };
        let rec_bytes = if is64 { 8 } else { 4 };
        // The log is circular: positions past s_maxlen wrap to s_first.
        let wrap = |x: u64| if x >= max { first + (x - max) } else { x };
        let mut at = wrap(u64::from(j.start));
        let mut want = j.sequence;
        let mut txn: Vec<(u64, Replayed)> = Vec::new();
        let mut txn_revokes: Vec<u64> = Vec::new();
        let mut committed: Vec<(u64, Replayed)> = Vec::new();
        let mut revokes: Vec<(u64, u32)> = Vec::new();
        for _ in 0..max {
            if at >= avail {
                break;
            }
            let off = (at as usize) * bs;
            let b = &jbytes[off..off + bs];
            if be32(b, 0) != JBD2_MAGIC || be32(b, 8) != want {
                break;
            }
            let next = match be32(b, 4) {
                JBD2_DESCRIPTOR => {
                    let mut p = 12;
                    let mut data = at + 1;
                    while p + tag_bytes <= bs {
                        let (lo, flags) = if csum3 {
                            (be32(b, p), be32(b, p + 4))
                        } else {
                            (be32(b, p), be16(b, p + 6))
                        };
                        let blk = u64::from(lo)
                            | if is64 {
                                u64::from(be32(b, p + 8)) << 32
                            } else {
                                0
                            };
                        p += tag_bytes;
                        if flags & TAG_SAME_UUID == 0 {
                            p += 16;
                        }
                        txn.push((
                            blk,
                            Replayed {
                                journal_block: wrap(data),
                                escaped: flags & TAG_ESCAPE != 0,
                                sequence: want,
                            },
                        ));
                        data = wrap(data + 1);
                        if flags & TAG_LAST != 0 {
                            break;
                        }
                    }
                    data
                }
                JBD2_COMMIT => {
                    committed.append(&mut txn);
                    revokes.extend(txn_revokes.drain(..).map(|blk| (blk, want)));
                    ov.transactions += 1;
                    want = want.wrapping_add(1);
                    at + 1
                }
                JBD2_REVOKE => {
                    let end = (be32(b, 12) as usize).min(bs);
                    let mut p = 16;
                    while p + rec_bytes <= end {
                        let blk = if is64 {
                            (u64::from(be32(b, p)) << 32) | u64::from(be32(b, p + 4))
                        } else {
                            u64::from(be32(b, p))
                        };
                        txn_revokes.push(blk);
                        p += rec_bytes;
                    }
                    at + 1
                }
                _ => break,
            };
            at = wrap(next);
        }
        // The latest committed tag per block wins; a revoke with a later sequence cancels it.
        let mut latest: BTreeMap<u64, Replayed> = BTreeMap::new();
        for (blk, r) in committed {
            latest.insert(blk, r);
        }
        let mut revoked_at: BTreeMap<u64, u32> = BTreeMap::new();
        for (blk, seq) in revokes {
            ov.revoke_records += 1;
            let e = revoked_at.entry(blk).or_insert(seq);
            *e = (*e).max(seq);
        }
        for (blk, r) in latest {
            if revoked_at.get(&blk).is_some_and(|&s| s > r.sequence) {
                ov.cancelled += 1;
            } else {
                ov.blocks.insert(blk, r);
            }
        }
        Ok(ov)
    }

    /// The content of filesystem block `fsblk` after replay, or `None` when no committed tag names it.
    pub fn block(&self, jbytes: &[u8], fsblk: u64) -> Option<Vec<u8>> {
        let r = self.blocks.get(&fsblk)?;
        let start = usize::try_from(r.journal_block)
            .ok()?
            .checked_mul(self.block_size)?;
        let mut v = jbytes
            .get(start..start.checked_add(self.block_size)?)?
            .to_vec();
        if r.escaped {
            v[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        }
        Some(v)
    }

    /// The replay plan as text. Nothing is written.
    pub fn dump(&self) -> String {
        let mut out = format!(
            "Replay plan (read-only overlay, image not modified):\n  committed transactions: {}\n  revoke entries: {}\n  blocks overwritten: {} ({} cancelled by a later revoke)\n",
            self.transactions,
            self.revoke_records,
            self.blocks.len(),
            self.cancelled
        );
        for (fsblk, r) in &self.blocks {
            out.push_str(&format!(
                "  fs block {fsblk} <- journal block {} (seq {}{})\n",
                r.journal_block,
                r.sequence,
                if r.escaped { ", escaped" } else { "" }
            ));
        }
        out
    }

    /// The replay plan as JSON. Nothing is written.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "transactions": self.transactions,
            "revoke_records": self.revoke_records,
            "cancelled": self.cancelled,
            "blocks": self.blocks.iter().map(|(fsblk, r)| serde_json::json!({
                "fs_block": fsblk,
                "journal_block": r.journal_block,
                "sequence": r.sequence,
                "escaped": r.escaped,
            })).collect::<Vec<_>>(),
        })
    }
}

fn replay_for(fs: &Fs) -> Result<(Vec<u8>, Overlay)> {
    let jb = fs.journal()?;
    let j = Journal::parse(&jb)?;
    let ov = Overlay::plan(&j, fs.bs, &jb)?;
    Ok((jb, ov))
}

fn read_block(fs: &Fs, ov: &Overlay, jb: &[u8], n: u64) -> Result<Vec<u8>> {
    match ov.block(jb, n) {
        Some(b) => Ok(b),
        None => fs.block(n),
    }
}

/// `len` bytes at byte offset `off`, with replayed blocks taken from the journal.
fn read_bytes(fs: &Fs, ov: &Overlay, jb: &[u8], off: u64, len: usize) -> Result<Vec<u8>> {
    let bs = fs.bs;
    let mut out = Vec::with_capacity(len);
    let mut at = off;
    while out.len() < len {
        let block = read_block(fs, ov, jb, at / bs)?;
        let within = (at % bs) as usize;
        let take = (bs as usize - within).min(len - out.len());
        out.extend_from_slice(&block[within..within + take]);
        at += take as u64;
    }
    Ok(out)
}

/// One finding on the shared model. The fingerprint keys on the rule, the image and the subject.
fn finding(
    rule: &str,
    severity: Severity,
    scope: &str,
    subject: &str,
    message: String,
    gap: bool,
) -> Finding {
    Finding {
        rule: rule.to_string(),
        category: "filesystem".to_string(),
        severity,
        scope: scope.to_string(),
        subject: subject.to_string(),
        key: String::new(),
        message,
        remedy: (!gap).then(|| {
            "repair a copy of the image with e2fsck -f; this tool never writes the image"
                .to_string()
        }),
        gap,
        uri: None,
        fingerprint: findings::fingerprint(rule, scope, subject, ""),
        baseline_state: None,
    }
}

/// Whether a bitmap block lies inside the filesystem, and how many of its first bits are clear.
enum Bitmap {
    Free(u64),
    Outside,
    Unchecked,
}

fn free_bits(fs: &Fs, ov: &Overlay, jb: &[u8], block: u64, n: u64) -> Result<Bitmap> {
    if block >= fs.blocks {
        return Ok(Bitmap::Outside);
    }
    if n > 8 * fs.bs {
        return Ok(Bitmap::Unchecked);
    }
    let bm = read_block(fs, ov, jb, block)?;
    let free = (0..n)
        .filter(|&i| ((bm[(i / 8) as usize] >> (i % 8)) & 1) == 0)
        .count();
    Ok(Bitmap::Free(free as u64))
}

/// Cross-check the superblock, the group descriptors and the allocation bitmaps, as the superblock
/// and bitmap passes of e2fsck do, after an in-memory replay of the journal. Returns the findings and
/// the group count. A check that cannot run is a gap finding, never a pass.
pub fn fsck(fs: &Fs, scope: &str) -> Result<(Vec<Finding>, u64)> {
    let mut out = Vec::new();
    let raw = fs.read_exact(1024, 1024)?;
    let (jb, ov) = if le32(&raw, SB_JOURNAL_INUM) == 0 {
        (Vec::new(), Overlay::default())
    } else {
        replay_for(fs).unwrap_or_else(|e| {
            out.push(finding(
                "ext/fsck-journal",
                Severity::Info,
                scope,
                "journal",
                format!("journal not replayed, the checks read the image as stored: {e:#}"),
                true,
            ));
            (Vec::new(), Overlay::default())
        })
    };
    let sb = read_bytes(fs, &ov, &jb, 1024, 1024)?;
    let first = u64::from(le32(&sb, 20));
    let bpg = u64::from(le32(&sb, 32));
    let ipg = u64::from(le32(&sb, 40));
    let inodes = u64::from(le32(&sb, 0));
    ensure!(
        fs.blocks > first && bpg > 0 && ipg > 0,
        "the superblock has zero group sizes or no data blocks"
    );
    let groups = (fs.blocks - first).div_ceil(bpg);
    ensure!(
        groups <= MAX_GROUPS,
        "{groups} block groups is over the limit"
    );
    let is64 = fs.desc_size >= 64;
    let ds = fs.desc_size;
    let (mut sum_fb, mut sum_fi) = (0u64, 0u64);
    for g in 0..groups {
        let d = read_bytes(fs, &ov, &jb, fs.gdt + g * ds, ds as usize)?;
        let subject = format!("group {g}");
        let bb = u64::from(le32(&d, 0))
            | if is64 {
                u64::from(le32(&d, 0x20)) << 32
            } else {
                0
            };
        let ib = u64::from(le32(&d, 4))
            | if is64 {
                u64::from(le32(&d, 0x24)) << 32
            } else {
                0
            };
        let fb = u64::from(le16(&d, 12))
            | if is64 {
                u64::from(le16(&d, 0x2C)) << 16
            } else {
                0
            };
        let fi = u64::from(le16(&d, 14))
            | if is64 {
                u64::from(le16(&d, 0x2E)) << 16
            } else {
                0
            };
        sum_fb += fb;
        sum_fi += fi;
        let nb = bpg.min(fs.blocks - (first + g * bpg));
        let ni = ipg.min(inodes.saturating_sub(g * ipg));
        match free_bits(fs, &ov, &jb, bb, nb)? {
            Bitmap::Outside => out.push(finding(
                "ext/fsck-bitmap-location",
                Severity::Medium,
                scope,
                &subject,
                format!("{subject}: block bitmap at block {bb} is outside the filesystem"),
                false,
            )),
            Bitmap::Unchecked => out.push(finding(
                "ext/fsck-group-free-blocks",
                Severity::Info,
                scope,
                &subject,
                format!("{subject}: block bitmap cannot be checked, its group holds more bits than one block"),
                true,
            )),
            Bitmap::Free(c) if c != fb => out.push(finding(
                "ext/fsck-group-free-blocks",
                Severity::Medium,
                scope,
                &subject,
                format!("{subject}: block bitmap has {c} free blocks, the group descriptor says {fb}"),
                false,
            )),
            Bitmap::Free(_) => {}
        }
        match free_bits(fs, &ov, &jb, ib, ni)? {
            Bitmap::Outside => out.push(finding(
                "ext/fsck-bitmap-location",
                Severity::Medium,
                scope,
                &subject,
                format!("{subject}: inode bitmap at block {ib} is outside the filesystem"),
                false,
            )),
            Bitmap::Unchecked => out.push(finding(
                "ext/fsck-group-free-inodes",
                Severity::Info,
                scope,
                &subject,
                format!("{subject}: inode bitmap cannot be checked, its group holds more bits than one block"),
                true,
            )),
            Bitmap::Free(c) if c != fi => out.push(finding(
                "ext/fsck-group-free-inodes",
                Severity::Medium,
                scope,
                &subject,
                format!("{subject}: inode bitmap has {c} free inodes, the group descriptor says {fi}"),
                false,
            )),
            Bitmap::Free(_) => {}
        }
    }
    let total_fb = u64::from(le32(&sb, 12))
        | if is64 {
            u64::from(le32(&sb, 0x158)) << 32
        } else {
            0
        };
    let total_fi = u64::from(le32(&sb, 16));
    if sum_fb != total_fb {
        out.push(finding(
            "ext/fsck-free-blocks",
            Severity::Medium,
            scope,
            "superblock",
            format!(
                "superblock has {total_fb} free blocks, the group descriptors add up to {sum_fb}"
            ),
            false,
        ));
    }
    if sum_fi != total_fi {
        out.push(finding(
            "ext/fsck-free-inodes",
            Severity::Medium,
            scope,
            "superblock",
            format!(
                "superblock has {total_fi} free inodes, the group descriptors add up to {sum_fi}"
            ),
            false,
        ));
    }
    Ok((out, groups))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: usize = 1024;

    fn be(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }

    fn le32_put(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn le16_put(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    /// A jbd2 block header at journal block `n`.
    fn header(j: &mut [u8], n: usize, ty: u32, seq: u32) {
        be(j, n * BS, JBD2_MAGIC);
        be(j, n * BS + 4, ty);
        be(j, n * BS + 8, seq);
    }

    /// A 10-block journal (1 KiB blocks). Txn 5 (blocks 1-4) writes fs block 100 and fs block 200
    /// (escaped). Txn 6 (blocks 5-8) revokes fs block 100 and writes fs block 300. Block 9 is a
    /// descriptor for txn 7 that never commits.
    fn journal() -> Vec<u8> {
        let mut j = vec![0u8; 10 * BS];
        header(&mut j, 0, 4, 0);
        be(&mut j, 12, BS as u32);
        be(&mut j, 16, 10);
        be(&mut j, 20, 1);
        be(&mut j, 24, 5);
        be(&mut j, 28, 1);
        header(&mut j, 1, 1, 5);
        be(&mut j, BS + 12, 100);
        j[BS + 18..BS + 20].copy_from_slice(&0u16.to_be_bytes());
        be(&mut j, BS + 36, 200);
        j[BS + 42..BS + 44].copy_from_slice(&11u16.to_be_bytes());
        j[2 * BS..3 * BS].fill(0xAA);
        j[3 * BS..4 * BS].fill(0xBB);
        j[3 * BS..3 * BS + 4].fill(0);
        header(&mut j, 4, 2, 5);
        header(&mut j, 5, 5, 6);
        be(&mut j, 5 * BS + 12, 20);
        be(&mut j, 5 * BS + 16, 100);
        header(&mut j, 6, 1, 6);
        be(&mut j, 6 * BS + 12, 300);
        j[6 * BS + 18..6 * BS + 20].copy_from_slice(&8u16.to_be_bytes());
        j[7 * BS..8 * BS].fill(0xCC);
        header(&mut j, 8, 2, 6);
        header(&mut j, 9, 1, 7);
        be(&mut j, 9 * BS + 12, 400);
        j[9 * BS + 18..9 * BS + 20].copy_from_slice(&8u16.to_be_bytes());
        j
    }

    #[test]
    fn replay_applies_committed_tags_and_skips_revoked_and_torn_ones() {
        let j = journal();
        let parsed = Journal::parse(&j).unwrap();
        let ov = Overlay::plan(&parsed, BS as u64, &j).unwrap();
        assert_eq!(ov.transactions, 2);
        assert_eq!(ov.revoke_records, 1);
        assert_eq!(ov.cancelled, 1);
        assert_eq!(
            ov.blocks.keys().copied().collect::<Vec<_>>(),
            vec![200, 300]
        );
        assert_eq!(
            ov.blocks[&200],
            Replayed {
                journal_block: 3,
                escaped: true,
                sequence: 5
            }
        );
        assert_eq!(ov.blocks[&300].journal_block, 7);
        assert!(ov.block(&j, 100).is_none(), "revoked block is not overlaid");
        assert!(ov.block(&j, 400).is_none(), "torn transaction is ignored");
        let fixed = ov.block(&j, 200).unwrap();
        assert_eq!(&fixed[..4], &JBD2_MAGIC.to_be_bytes(), "escape restored");
        assert!(fixed[4..].iter().all(|&b| b == 0xBB));
        assert!(ov.block(&j, 300).unwrap().iter().all(|&b| b == 0xCC));
        assert!(ov.dump().contains("fs block 300 <- journal block 7"));
    }

    #[test]
    fn a_clean_journal_has_nothing_to_replay() {
        let mut j = vec![0u8; 4 * BS];
        header(&mut j, 0, 4, 0);
        be(&mut j, 12, BS as u32);
        be(&mut j, 16, 4);
        be(&mut j, 20, 1);
        be(&mut j, 24, 1);
        let parsed = Journal::parse(&j).unwrap();
        assert_eq!(
            Overlay::plan(&parsed, BS as u64, &j).unwrap(),
            Overlay::default()
        );
    }

    /// A one-group ext2 image: 64 blocks of 1 KiB, 16 inodes. Blocks 1-5 are in use (superblock,
    /// descriptor table, bitmaps, inode table) and inodes 1-2 are in use.
    fn small_image(sb_free_blocks: u32, gd_free_blocks: u16) -> Vec<u8> {
        let mut img = vec![0u8; 64 * BS];
        let sb = 1024;
        le32_put(&mut img, sb, 16);
        le32_put(&mut img, sb + 4, 64);
        le32_put(&mut img, sb + 12, sb_free_blocks);
        le32_put(&mut img, sb + 16, 14);
        le32_put(&mut img, sb + 20, 1);
        le32_put(&mut img, sb + 32, 8192);
        le32_put(&mut img, sb + 40, 16);
        le16_put(&mut img, sb + 56, 0xEF53);
        le32_put(&mut img, sb + 76, 1);
        le16_put(&mut img, sb + 88, 128);
        let gd = 2 * BS;
        le32_put(&mut img, gd, 3);
        le32_put(&mut img, gd + 4, 4);
        le32_put(&mut img, gd + 8, 5);
        le16_put(&mut img, gd + 12, gd_free_blocks);
        le16_put(&mut img, gd + 14, 14);
        img[3 * BS] = 0b0001_1111;
        img[4 * BS] = 0b0000_0011;
        img
    }

    fn fsck_rules(img: Vec<u8>) -> Vec<String> {
        let fs = Fs::from_bytes(img).unwrap();
        let (found, groups) = fsck(&fs, "t").unwrap();
        assert_eq!(groups, 1);
        found.into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn fsck_passes_a_consistent_image_and_names_each_mismatch() {
        assert!(fsck_rules(small_image(58, 58)).is_empty());
        assert_eq!(
            fsck_rules(small_image(60, 57)),
            vec!["ext/fsck-group-free-blocks", "ext/fsck-free-blocks"]
        );
    }
}
