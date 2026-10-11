//! Build a raw partition image from block-OTA data (`*.new.dat`) following a transfer list.
use crate::transfer_list::{Command, Patch, Ranges, Source, TransferList};
use anyhow::{Context, Result, bail, ensure};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

pub const BLOCK_SIZE: usize = 4096;

/// The block ranges a command writes (its target).
fn command_ranges(cmd: &Command) -> &[(u64, u64)] {
    match cmd {
        Command::New(r) | Command::Zero(r) | Command::Erase(r) => r,
        Command::Transfer(t) => &t.tgt,
        Command::Stash(..) | Command::Free(_) => &[],
    }
}

/// Decompress a `.new.dat.br` stream on the fly, so no temporary `.new.dat` file is needed.
///
/// This is the hot path for a block OTA: brotli decode is essentially the entire cost of
/// rebuilding a partition. The vendored C decoder measured 391 MB/s against the pure-Rust
/// `brotli` crate's 250 MB/s on real firmware, so it is worth the FFI (#74). The pure-Rust
/// decoder is still used to COMPRESS in tests, which keeps the two implementations honest
/// about each other.
pub fn brotli_reader<R: Read>(input: R) -> impl Read {
    crate::libbrotli::BrotliDecoderReader::new(input)
}

/// Size in bytes of the image a transfer list describes. Header line 2 only counts the blocks
/// written; the image spans the furthest range of any command (an `erase` usually reaches the
/// end of the partition).
pub fn image_size(list: &TransferList) -> Result<u64> {
    let end = list
        .commands
        .iter()
        .flat_map(command_ranges)
        .map(|&(_, end)| end)
        .max()
        .unwrap_or(0);
    end.checked_mul(BLOCK_SIZE as u64)
        .context("image size overflows")
}

/// Build the image described by `list` into `out`, reading the contents of `new` ranges from
/// `data` in order. `zero` and `erase` ranges stay zero, so `out` must start empty.
pub fn apply<R: Read, W: Write + Seek>(
    list: &TransferList,
    mut data: R,
    out: &mut W,
) -> Result<()> {
    ensure!(
        !list.is_incremental(),
        "this transfer list holds incremental commands (move/bsdiff/imgdiff/stash); it needs the previous build"
    );
    let size = image_size(list)?;
    if size > 0 {
        out.seek(SeekFrom::Start(size - 1))?;
        out.write_all(&[0])?;
    }
    let mut block = [0u8; BLOCK_SIZE];
    for cmd in &list.commands {
        if let Command::New(ranges) = cmd {
            for &(start, end) in ranges {
                out.seek(SeekFrom::Start(start * BLOCK_SIZE as u64))?;
                for _ in start..end {
                    data.read_exact(&mut block)
                        .context("data ended before all new blocks were written")?;
                    out.write_all(&block)?;
                }
            }
        }
    }
    if data.read(&mut [0u8; 1])? != 0 {
        bail!("data has more blocks than the transfer list describes");
    }
    Ok(())
}

/// Largest source/target buffer or total stash an incremental command may build (hostile-input bound).
const MAX_BUFFER: u64 = 1 << 30;

fn block_count(r: &Ranges) -> u64 {
    r.iter().map(|(a, b)| b - a).sum()
}

fn sha1_hex(d: &[u8]) -> String {
    Sha1::digest(d).iter().map(|b| format!("{b:02x}")).collect()
}

fn read_ranges<F: Read + Seek>(f: &mut F, r: &Ranges, image_len: u64) -> Result<Vec<u8>> {
    let n = block_count(r) * BLOCK_SIZE as u64;
    ensure!(n <= MAX_BUFFER, "{n} bytes of blocks is over the limit");
    let mut out = Vec::with_capacity(n as usize);
    for &(a, b) in r {
        ensure!(
            b * BLOCK_SIZE as u64 <= image_len,
            "blocks {a}-{b} lie past the image"
        );
        f.seek(SeekFrom::Start(a * BLOCK_SIZE as u64))?;
        let start = out.len();
        out.resize(start + ((b - a) as usize) * BLOCK_SIZE, 0);
        f.read_exact(&mut out[start..])?;
    }
    Ok(out)
}

fn write_ranges<F: Write + Seek>(f: &mut F, r: &Ranges, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() as u64 == block_count(r) * BLOCK_SIZE as u64,
        "{} bytes do not fill {} blocks",
        data.len(),
        block_count(r)
    );
    let mut at = 0;
    for &(a, b) in r {
        f.seek(SeekFrom::Start(a * BLOCK_SIZE as u64))?;
        let n = ((b - a) as usize) * BLOCK_SIZE;
        f.write_all(&data[at..at + n])?;
        at += n;
    }
    Ok(())
}

/// Copy `data` (whole blocks) into `buf` at the block positions `loc` names, in order.
fn scatter(buf: &mut [u8], loc: &Ranges, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() as u64 == block_count(loc) * BLOCK_SIZE as u64,
        "stash or source size does not match its locations"
    );
    let mut at = 0;
    for &(a, b) in loc {
        let (s, n) = (a as usize * BLOCK_SIZE, (b - a) as usize * BLOCK_SIZE);
        buf.get_mut(s..s + n)
            .context("a source location lies outside the source buffer")?
            .copy_from_slice(&data[at..at + n]);
        at += n;
    }
    Ok(())
}

fn source_buffer<F: Read + Seek>(
    src: &Source,
    stashes: &HashMap<String, Vec<u8>>,
    f: &mut F,
    image_len: u64,
) -> Result<Vec<u8>> {
    ensure!(
        src.blocks * BLOCK_SIZE as u64 <= MAX_BUFFER,
        "source buffer is over the limit"
    );
    let mut buf = vec![0u8; src.blocks as usize * BLOCK_SIZE];
    if !src.ranges.is_empty() {
        let data = read_ranges(f, &src.ranges, image_len)?;
        match &src.loc {
            None => buf
                .get_mut(..data.len())
                .context("source ranges are larger than the source buffer")?
                .copy_from_slice(&data),
            Some(loc) => scatter(&mut buf, loc, &data)?,
        }
    }
    for (id, loc) in &src.stashes {
        let data = stashes
            .get(id)
            .with_context(|| format!("stash {id} was never saved (or already freed)"))?;
        scatter(&mut buf, loc, data)?;
    }
    Ok(buf)
}

/// Rebuild a partition of an incremental block OTA in place: `image` holds the old partition and
/// is rewritten as the commands run, exactly as the device's updater does, so a command that
/// reads blocks an earlier command overwrote sees what the device saw. `data` yields the `new`
/// blocks in order, `patches` is the whole `*.patch.dat`. Hashes (version 3 and later) are
/// checked, so a wrong old image fails instead of producing a plausible one.
pub fn apply_incremental<R: Read>(
    list: &TransferList,
    mut data: R,
    patches: &[u8],
    image: &mut std::fs::File,
) -> Result<()> {
    let size = image_size(list)?;
    let mut len = image.metadata()?.len();
    if len < size {
        image.set_len(size)?;
        len = size;
    }
    let mut stashes: HashMap<String, Vec<u8>> = HashMap::new();
    let mut stashed = 0u64;
    let mut block = [0u8; BLOCK_SIZE];
    let zeros = vec![0u8; BLOCK_SIZE];
    for (n, cmd) in list.commands.iter().enumerate() {
        let step = |e: anyhow::Error| e.context(format!("transfer list command {}", n + 1));
        match cmd {
            Command::New(ranges) => {
                for &(a, b) in ranges {
                    image.seek(SeekFrom::Start(a * BLOCK_SIZE as u64))?;
                    for _ in a..b {
                        data.read_exact(&mut block)
                            .context("data ended before all new blocks were written")?;
                        image.write_all(&block)?;
                    }
                }
            }
            Command::Zero(ranges) | Command::Erase(ranges) => {
                for &(a, b) in ranges {
                    image.seek(SeekFrom::Start(a * BLOCK_SIZE as u64))?;
                    for _ in a..b {
                        image.write_all(&zeros)?;
                    }
                }
            }
            Command::Stash(id, ranges) => {
                let d = read_ranges(image, ranges, len).map_err(step)?;
                if list.version >= 3 && id.len() == 40 && sha1_hex(&d) != id.to_ascii_lowercase() {
                    return Err(step(anyhow::anyhow!(
                        "stash {id}: the blocks do not match their hash (is --base the build this update starts from?)"
                    )));
                }
                stashed += d.len() as u64;
                ensure!(
                    stashed <= MAX_BUFFER,
                    "stashes total more than {MAX_BUFFER} bytes"
                );
                stashes.insert(id.clone(), d);
            }
            Command::Free(id) => {
                if let Some(d) = stashes.remove(id) {
                    stashed -= d.len() as u64;
                }
            }
            Command::Transfer(t) => {
                let buf = source_buffer(&t.src, &stashes, image, len).map_err(step)?;
                if let Some(want) = &t.src_sha1 {
                    ensure!(
                        &sha1_hex(&buf) == want,
                        "command {}: source blocks do not match their hash (is --base the build this update starts from?)",
                        n + 1
                    );
                }
                let out = match t.kind {
                    Patch::Move => buf,
                    Patch::Bsdiff | Patch::Imgdiff => {
                        let (off, plen) = t.patch.context("missing patch range")?;
                        let end = off.checked_add(plen).context("patch range overflows")?;
                        let patch = patches
                            .get(off as usize..end as usize)
                            .with_context(|| {
                                format!("patch {off}+{plen} lies outside the patch data")
                            })
                            .map_err(step)?;
                        if t.kind == Patch::Bsdiff {
                            crate::bsdiff::apply(patch, &buf).map_err(step)?
                        } else {
                            crate::imgdiff::apply(patch, &buf).map_err(step)?
                        }
                    }
                };
                if let Some(want) = &t.tgt_sha1 {
                    ensure!(
                        &sha1_hex(&out) == want,
                        "command {}: the rebuilt blocks do not match the target hash",
                        n + 1
                    );
                }
                write_ranges(image, &t.tgt, &out).map_err(step)?;
            }
        }
    }
    if data.read(&mut [0u8; 1])? != 0 {
        bail!("data has more blocks than the transfer list describes");
    }
    image.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_list;
    use std::io::Cursor;

    fn blk(b: u8) -> Vec<u8> {
        vec![b; BLOCK_SIZE]
    }

    fn run(list: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let list = transfer_list::parse(list)?;
        let mut out = Cursor::new(Vec::new());
        apply(&list, Cursor::new(data), &mut out)?;
        Ok(out.into_inner())
    }

    fn assert_blocks(img: &[u8], expect: &[u8]) {
        assert_eq!(img.len(), expect.len() * BLOCK_SIZE);
        for (i, &b) in expect.iter().enumerate() {
            assert_eq!(
                img[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                blk(b)[..],
                "block {i}"
            );
        }
    }

    #[test]
    fn writes_new_blocks_in_order_at_their_offsets() {
        let data = [blk(1), blk(2), blk(3)].concat();
        let img = run("4\n6\n0\n0\nnew 4,0,1,4,6\n", data).unwrap();
        assert_blocks(&img, &[1, 0, 0, 0, 2, 3]);
    }

    #[test]
    fn zero_and_erase_stay_zero_and_count_toward_size() {
        let img = run("4\n3\n0\n0\nnew 2,0,1\nzero 2,1,2\nerase 2,2,3\n", blk(7)).unwrap();
        assert_blocks(&img, &[7, 0, 0]);
    }

    #[test]
    fn short_data_is_an_error() {
        let e = run("4\n2\n0\n0\nnew 2,0,2\n", blk(1)).unwrap_err();
        assert!(e.to_string().contains("ended before"), "{e}");
    }

    #[test]
    fn extra_data_is_an_error() {
        let e = run("4\n2\n0\n0\nnew 2,0,1\n", [blk(1), blk(2)].concat()).unwrap_err();
        assert!(e.to_string().contains("more blocks"), "{e}");
    }

    #[test]
    fn image_spans_the_furthest_range_of_any_command() {
        // header count (1) is smaller than where the ranges end, as in real lists
        let img = run("4\n1\n0\n0\nnew 2,4,5\nerase 2,5,6\n", blk(7)).unwrap();
        assert_blocks(&img, &[0, 0, 0, 0, 7, 0]);
        let img = run("4\n1\n0\n0\nnew 2,0,1\nerase 2,3,6\n", blk(7)).unwrap();
        assert_blocks(&img, &[7, 0, 0, 0, 0, 0]);
        let img = run("4\n1\n0\n0\nnew 2,0,1\nzero 2,1,4\n", blk(7)).unwrap();
        assert_blocks(&img, &[7, 0, 0, 0]);
    }

    #[test]
    fn image_size_is_the_furthest_range_end_in_bytes() {
        let size = |t: &str| image_size(&transfer_list::parse(t).unwrap()).unwrap();
        assert_eq!(
            size("4\n1\n0\n0\nnew 2,4,5\nerase 2,5,6\n"),
            6 * BLOCK_SIZE as u64
        );
        assert_eq!(
            size("4\n9\n0\n0\nnew 2,0,1\nzero 2,1,3\n"),
            3 * BLOCK_SIZE as u64
        );
        assert_eq!(size("4\n0\n0\n0\n"), 0);
        let huge = transfer_list::parse("4\n1\n0\n0\nerase 2,0,18446744073709551615\n").unwrap();
        assert!(image_size(&huge).is_err());
    }

    #[test]
    fn absurd_range_end_is_an_error() {
        let e = run("4\n1\n0\n0\nerase 2,0,18446744073709551615\n", vec![]).unwrap_err();
        assert!(e.to_string().contains("overflows"), "{e}");
    }

    #[test]
    fn brotli_stream_round_trips_into_an_image() {
        let mut packed = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut packed, 4096, 5, 22);
            w.write_all(&[blk(1), blk(2)].concat()).unwrap();
        }
        let list = transfer_list::parse("4\n3\n0\n0\nnew 2,0,1\nnew 2,2,3\n").unwrap();
        let mut out = Cursor::new(Vec::new());
        apply(&list, brotli_reader(Cursor::new(packed)), &mut out).unwrap();
        assert_blocks(&out.into_inner(), &[1, 0, 2]);
    }

    #[test]
    fn corrupt_brotli_input_is_an_error() {
        let list = transfer_list::parse("4\n1\n0\n0\nnew 2,0,1\n").unwrap();
        let mut out = Cursor::new(Vec::new());
        let bad = Cursor::new(vec![0xffu8; BLOCK_SIZE]);
        assert!(apply(&list, brotli_reader(bad), &mut out).is_err());
    }

    // tests/fixtures/blockota/ is an incremental block OTA made by a Python script that applies
    // the same commands in place with the real `bsdiff4`: stash, bsdiff (backward seeks), move
    // from a stash, plain move, a move that mixes partition blocks and a stash at set positions,
    // imgdiff (NORMAL + RAW chunks), free and new. `expected.img` is its result.
    const OLD: &[u8] = include_bytes!("../tests/fixtures/blockota/old.img");
    const LIST: &str = include_str!("../tests/fixtures/blockota/system.transfer.list");
    const NEW_DAT: &[u8] = include_bytes!("../tests/fixtures/blockota/system.new.dat");
    const PATCH_DAT: &[u8] = include_bytes!("../tests/fixtures/blockota/system.patch.dat");
    const EXPECTED: &[u8] = include_bytes!("../tests/fixtures/blockota/expected.img");

    fn rebuild(tag: &str, old: &[u8], list: &str) -> Result<Vec<u8>> {
        let d = crate::testutil::Scratch::new(tag);
        let p = d.join("image");
        std::fs::write(&p, old).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let list = transfer_list::parse(list).unwrap();
        apply_incremental(&list, NEW_DAT, PATCH_DAT, &mut f)?;
        Ok(std::fs::read(&p).unwrap())
    }

    #[test]
    fn an_incremental_block_update_rebuilds_the_new_image() {
        let got = rebuild("incr-ok", OLD, LIST).unwrap();
        assert_eq!(got.len(), EXPECTED.len());
        assert!(got == EXPECTED, "rebuilt image differs from the reference");
    }

    #[test]
    fn a_wrong_old_image_is_caught_by_the_hashes() {
        let mut wrong = OLD.to_vec();
        wrong[5 * BLOCK_SIZE + 7] ^= 1; // block 5 feeds a plain move
        let e = rebuild("incr-wrong", &wrong, LIST).unwrap_err();
        assert!(format!("{e:#}").contains("hash"), "{e:#}");
        let mut wrong = OLD.to_vec();
        wrong[100] ^= 1; // block 0 is stashed under its hash
        let e = rebuild("incr-wrong2", &wrong, LIST).unwrap_err();
        assert!(format!("{e:#}").contains("hash"), "{e:#}");
    }

    #[test]
    fn the_full_ota_path_refuses_incremental_commands() {
        let list = transfer_list::parse(LIST).unwrap();
        assert!(list.is_incremental());
        let e = apply(&list, NEW_DAT, &mut Cursor::new(Vec::new())).unwrap_err();
        assert!(e.to_string().contains("previous build"), "{e}");
    }

    #[test]
    fn version_1_and_2_lists_run_without_hashes() {
        let mut old = Vec::new();
        for b in 1..=4u8 {
            old.extend(blk(b));
        }
        // v1: copy block 0 over block 3
        let got = rebuild_no_patch("incr-v1", &old, "1\n4\nmove 2,0,1 2,3,4\n");
        assert_eq!(&got[3 * BLOCK_SIZE..], &blk(1)[..]);
        // v2: stash block 1, overwrite it from block 2, then restore the stash into block 2
        let got = rebuild_no_patch(
            "incr-v2",
            &old,
            "2\n4\n1\n1\nstash s1 2,1,2\nmove 2,1,2 1 2,2,3\nmove 2,2,3 1 - s1:2,0,1\nfree s1\n",
        );
        assert_eq!(&got[BLOCK_SIZE..2 * BLOCK_SIZE], &blk(3)[..]);
        assert_eq!(&got[2 * BLOCK_SIZE..3 * BLOCK_SIZE], &blk(2)[..]);
    }

    fn rebuild_no_patch(tag: &str, old: &[u8], list: &str) -> Vec<u8> {
        let d = crate::testutil::Scratch::new(tag);
        let p = d.join("image");
        std::fs::write(&p, old).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let list = transfer_list::parse(list).unwrap();
        apply_incremental(&list, &b""[..], &[], &mut f).unwrap();
        std::fs::read(&p).unwrap()
    }

    #[test]
    fn hostile_incremental_lists_fail_cleanly() {
        for l in [
            "3\n4\n0\n0\nmove 0000000000000000000000000000000000000000 2,0,1 1 2,9,10\n", // past the image
            "2\n4\n0\n0\nmove 2,0,1 1 - nope:2,0,1\n", // unknown stash
            "2\n4\n0\n0\nbsdiff 0 99999 2,0,1 1 2,1,2\n", // patch outside data
            "2\n4\n0\n0\nimgdiff 0 4 2,0,1 1 2,1,2\n", // not IMGDIFF2
        ] {
            let old = vec![0u8; 4 * BLOCK_SIZE];
            let d = crate::testutil::Scratch::new("incr-hostile");
            let p = d.join("image");
            std::fs::write(&p, &old).unwrap();
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&p)
                .unwrap();
            let list = transfer_list::parse(l).unwrap();
            assert!(
                apply_incremental(&list, &b""[..], &[1, 2, 3, 4], &mut f).is_err(),
                "{l}"
            );
        }
    }
}
