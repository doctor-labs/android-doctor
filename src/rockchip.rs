//! Rockchip firmware containers: `RKFW` (loader + `RKAF` image), `RKAF` (the `update.img` part
//! table) and `SSFW` (a table of child images). Read from the public layouts used by `rkunpack`
//! (rkflashtool), `rk2918_tools` (`img_unpack`, `afptool`, `rkcrc.h`, `mkkrnlimg`) and `afptool-rs`
//! (SSFW); no code is taken from them. All integers are little-endian.
//!
//! RKFW header (0x66 bytes): `"RKFW"`, u16 header length (0x66), ... loader offset u32 @0x19 and
//! length u32 @0x1D, RKAF image offset u32 @0x21 and length u32 @0x25. A 32-character ASCII MD5 of
//! the bytes before it may follow the image; when present it is checked.
//!
//! RKAF header (0x8C bytes, then up to 16 part records of 112 bytes): `"RKAF"`, u32 `length`
//! (the container is `length + 4` bytes), model[34], id[30], manufacturer[56], u32, u32 version,
//! u32 part count @0x88. A part record is name[32], file name[60], u32 nand size, u32 `pos`
//! (offset in the container), u32 nand address, u32 padded size, u32 `size`. The part named
//! `SELF` describes the container itself and is skipped. At `length` sits a CRC-32 of the bytes
//! before it: MSB-first, polynomial 0x04C10DB7, initial value 0, no final xor (`rkcrc.h`).
//! `parameter` parts are wrapped as `"PARM"` + u32 length + text + CRC and `kernel` images as
//! `"KRNL"` + u32 length + data + CRC; both wrappers are removed.
//!
//! SSFW header (0x40 bytes): `"SSFW"`, u32 header size, u32 version, u32 merge version, u32 image
//! count @0x10; at the header size, `count` entries of u64 offset + u64 length. Each child that is
//! itself RKFW or RKAF is expanded (names prefixed `img<i>-`), anything else is written whole.
//!
//! Caveat: validated against spec-built synthetic fixtures only (no real device image), and the
//! SSFW layout rests on a single implementation (afptool-rs). Anything that does not fit the
//! bounds or the CRC is refused, never half-read.
use crate::oem::{Item, clean_name, le32, range_item, read_at};
use anyhow::{Result, bail, ensure};
use md5::{Digest, Md5};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub(crate) const RKFW_MAGIC: [u8; 4] = *b"RKFW";
pub(crate) const RKAF_MAGIC: [u8; 4] = *b"RKAF";
pub(crate) const SSFW_MAGIC: [u8; 4] = *b"SSFW";

const RKFW_HEADER: u64 = 0x66;
const RKAF_HEADER: u64 = 0x8C;
const RKAF_PART: u64 = 112;
const RKAF_MAX_PARTS: u64 = 16;
const SSFW_HEADER: u64 = 0x40;
const SSFW_MAX_IMAGES: u64 = 256;

/// The Rockchip CRC table value: MSB-first CRC-32 with polynomial 0x04C10DB7.
fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, e) in t.iter_mut().enumerate() {
        let mut c = (i as u32) << 24;
        for _ in 0..8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04C1_0DB7
            } else {
                c << 1
            };
        }
        *e = c;
    }
    t
}

/// RKCRC over `len` bytes of `f` from `at` (init 0, no final xor).
fn rkcrc(f: &mut File, at: u64, len: u64) -> Result<u32> {
    let t = crc_table();
    f.seek(SeekFrom::Start(at))?;
    let (mut crc, mut left) = (0u32, len);
    let mut buf = vec![0u8; 1 << 20];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..want])?;
        ensure!(n > 0, "rockchip: container ends early");
        for &b in &buf[..n] {
            crc = (crc << 8) ^ t[((crc >> 24) ^ u32::from(b)) as usize];
        }
        left -= n as u64;
    }
    Ok(crc)
}

fn cstr(raw: &[u8]) -> &[u8] {
    &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())]
}

fn with_img(mut n: String) -> String {
    if !n.ends_with(".img") {
        n.push_str(".img");
    }
    n
}

pub(crate) fn parse_rkfw(f: &mut File, file_len: u64) -> Result<Vec<Item>> {
    ensure!(
        file_len >= RKFW_HEADER,
        "rockchip-rkfw: too short for a header"
    );
    let mut h = [0u8; RKFW_HEADER as usize];
    read_at(f, 0, &mut h)?;
    ensure!(h[..4] == RKFW_MAGIC, "rockchip-rkfw: bad magic");
    ensure!(
        u16::from_le_bytes([h[4], h[5]]) == RKFW_HEADER as u16,
        "rockchip-rkfw: unexpected header length"
    );
    let (lo, ll) = (u64::from(le32(&h, 0x19)), u64::from(le32(&h, 0x1d)));
    let (io, il) = (u64::from(le32(&h, 0x21)), u64::from(le32(&h, 0x25)));
    ensure!(
        lo >= RKFW_HEADER && io >= RKFW_HEADER,
        "rockchip-rkfw: loader or image offset lies inside the header"
    );
    ensure!(
        io.checked_add(il).is_some_and(|e| e <= file_len),
        "rockchip-rkfw: the image runs past the end of the file"
    );
    // The 32-character MD5 trailer, when the file has one right after the image.
    if io + il + 32 <= file_len {
        let mut t = [0u8; 32];
        read_at(f, io + il, &mut t)?;
        if t.iter().all(u8::is_ascii_hexdigit) {
            f.seek(SeekFrom::Start(0))?;
            let mut md = Md5::new();
            let mut buf = vec![0u8; 1 << 20];
            let mut left = io + il;
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = f.read(&mut buf[..want])?;
                ensure!(n > 0, "rockchip-rkfw: file ends early");
                md.update(&buf[..n]);
                left -= n as u64;
            }
            let got: String = md.finalize().iter().map(|b| format!("{b:02x}")).collect();
            ensure!(
                got.as_bytes().eq_ignore_ascii_case(&t),
                "rockchip-rkfw: the MD5 trailer does not match the file (corrupt or modified)"
            );
        }
    }
    let mut items = Vec::new();
    if ll > 0 {
        items.push(range_item(f, "loader.img".into(), lo, ll, file_len)?);
    }
    items.extend(parse_rkaf_at(f, io, il, file_len, "")?);
    Ok(items)
}

pub(crate) fn parse_rkaf(f: &mut File, file_len: u64) -> Result<Vec<Item>> {
    parse_rkaf_at(f, 0, file_len, file_len, "")
}

fn parse_rkaf_at(
    f: &mut File,
    base: u64,
    avail: u64,
    file_len: u64,
    prefix: &str,
) -> Result<Vec<Item>> {
    ensure!(
        avail >= RKAF_HEADER,
        "rockchip-rkaf: too short for a header"
    );
    let mut h = [0u8; RKAF_HEADER as usize];
    read_at(f, base, &mut h)?;
    ensure!(h[..4] == RKAF_MAGIC, "rockchip-rkaf: bad magic");
    let length = u64::from(le32(&h, 4));
    let total = length + 4;
    ensure!(
        total <= avail && total >= RKAF_HEADER,
        "rockchip-rkaf: declared size {total} does not fit the {avail} bytes available"
    );
    let n = u64::from(le32(&h, 0x88));
    ensure!(
        (1..=RKAF_MAX_PARTS).contains(&n) && RKAF_HEADER + n * RKAF_PART <= total,
        "rockchip-rkaf: implausible part count {n}"
    );
    let mut stored = [0u8; 4];
    read_at(f, base + length, &mut stored)?;
    ensure!(
        rkcrc(f, base, length)? == u32::from_le_bytes(stored),
        "rockchip-rkaf: the CRC does not match (corrupt, truncated or modified image)"
    );
    let mut table = vec![0u8; (n * RKAF_PART) as usize];
    read_at(f, base + RKAF_HEADER, &mut table)?;
    let mut items = Vec::new();
    for p in table.chunks(RKAF_PART as usize) {
        let file_name = cstr(&p[32..92]);
        let (pos, size) = (u64::from(le32(p, 0x60)), u64::from(le32(p, 0x6c)));
        if file_name == b"SELF" || size == 0 {
            continue;
        }
        let name = clean_name(&p[..32])?;
        ensure!(
            pos.checked_add(size).is_some_and(|e| e <= total),
            "rockchip-rkaf: {name}: data {pos}+{size} lies outside the image"
        );
        let (mut off, mut len) = (base + pos, size);
        // remove the PARM / KRNL wrappers (8-byte header, 4-byte CRC)
        if size >= 12 {
            let mut w = [0u8; 8];
            read_at(f, off, &mut w)?;
            if w[..4] == *b"PARM" || w[..4] == *b"KRNL" {
                let inner = u64::from(le32(&w, 4));
                ensure!(
                    inner + 12 <= size,
                    "rockchip-rkaf: {name}: wrapper length {inner} does not fit"
                );
                off += 8;
                len = inner;
            }
        }
        items.push(range_item(
            f,
            with_img(format!("{prefix}{name}")),
            off,
            len,
            file_len,
        )?);
    }
    ensure!(!items.is_empty(), "rockchip-rkaf: the image lists no parts");
    Ok(items)
}

pub(crate) fn parse_ssfw(f: &mut File, file_len: u64) -> Result<Vec<Item>> {
    ensure!(
        file_len >= SSFW_HEADER,
        "rockchip-ssfw: too short for a header"
    );
    let mut h = [0u8; SSFW_HEADER as usize];
    read_at(f, 0, &mut h)?;
    ensure!(h[..4] == SSFW_MAGIC, "rockchip-ssfw: bad magic");
    let (hs, count) = (u64::from(le32(&h, 4)), u64::from(le32(&h, 0x10)));
    ensure!(
        hs >= SSFW_HEADER && (1..=SSFW_MAX_IMAGES).contains(&count) && hs + count * 16 <= file_len,
        "rockchip-ssfw: implausible header (size {hs}, {count} images)"
    );
    let mut table = vec![0u8; (count * 16) as usize];
    read_at(f, hs, &mut table)?;
    let mut items = Vec::new();
    for (i, e) in table.chunks(16).enumerate() {
        let off = u64::from_le_bytes(e[..8].try_into().unwrap());
        let len = u64::from_le_bytes(e[8..].try_into().unwrap());
        ensure!(
            off >= hs + count * 16 && off.checked_add(len).is_some_and(|x| x <= file_len),
            "rockchip-ssfw: image {i} ({off}+{len}) lies outside the file"
        );
        let mut magic = [0u8; 4];
        if len >= 4 {
            read_at(f, off, &mut magic)?;
        }
        let prefix = format!("img{i}-");
        if magic == RKAF_MAGIC {
            items.extend(parse_rkaf_at(f, off, len, file_len, &prefix)?);
        } else if magic == RKFW_MAGIC {
            bail!(
                "rockchip-ssfw: image {i} is an RKFW; nested RKFW inside SSFW is not supported (extract it from the SSFW by offset first)"
            );
        } else {
            items.push(range_item(f, format!("img{i}.img"), off, len, file_len)?);
        }
    }
    Ok(items)
}

/// A synthetic RKAF holding `parts` (name, bytes), with a valid CRC (test fixture).
#[cfg(test)]
pub(crate) fn build_rkaf_for_test(parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut head = vec![0u8; RKAF_HEADER as usize + parts.len() * RKAF_PART as usize + 1];
    head.truncate(RKAF_HEADER as usize + parts.len() * RKAF_PART as usize);
    head[..4].copy_from_slice(&RKAF_MAGIC);
    head[0x88..0x8c].copy_from_slice(&(parts.len() as u32).to_le_bytes());
    let mut body = Vec::new();
    let mut pos = head.len() as u32;
    for (i, (name, data)) in parts.iter().enumerate() {
        let wrapped = if *name == "parameter" {
            [
                b"PARM".to_vec(),
                (data.len() as u32).to_le_bytes().to_vec(),
                data.clone(),
                vec![0; 4],
            ]
            .concat()
        } else {
            data.clone()
        };
        let r = RKAF_HEADER as usize + i * RKAF_PART as usize;
        head[r..r + name.len()].copy_from_slice(name.as_bytes());
        head[r + 32..r + 32 + name.len() + 4].copy_from_slice(format!("{name}.img").as_bytes());
        head[r + 0x60..r + 0x64].copy_from_slice(&pos.to_le_bytes());
        head[r + 0x6c..r + 0x70].copy_from_slice(&(wrapped.len() as u32).to_le_bytes());
        pos += wrapped.len() as u32;
        body.extend(wrapped);
    }
    let mut out = [head, body].concat();
    let length = out.len() as u32;
    out[4..8].copy_from_slice(&length.to_le_bytes());
    let t = crc_table();
    let crc = out.iter().fold(0u32, |c, &b| {
        (c << 8) ^ t[((c >> 24) ^ u32::from(b)) as usize]
    });
    out.extend(crc.to_le_bytes());
    out
}

/// A synthetic RKFW wrapping a loader and an RKAF, with the MD5 trailer (test fixture).
#[cfg(test)]
pub(crate) fn build_rkfw_for_test(loader: &[u8], rkaf: &[u8], md5_trailer: bool) -> Vec<u8> {
    let mut h = vec![0u8; RKFW_HEADER as usize];
    h[..4].copy_from_slice(&RKFW_MAGIC);
    h[4..6].copy_from_slice(&(RKFW_HEADER as u16).to_le_bytes());
    let lo = RKFW_HEADER as u32;
    let io = lo + loader.len() as u32;
    h[0x19..0x1d].copy_from_slice(&lo.to_le_bytes());
    h[0x1d..0x21].copy_from_slice(&(loader.len() as u32).to_le_bytes());
    h[0x21..0x25].copy_from_slice(&io.to_le_bytes());
    h[0x25..0x29].copy_from_slice(&(rkaf.len() as u32).to_le_bytes());
    let mut out = [h, loader.to_vec(), rkaf.to_vec()].concat();
    if md5_trailer {
        let d: String = Md5::digest(&out)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        out.extend(d.as_bytes());
    }
    out
}

/// A synthetic SSFW holding `children` (test fixture).
#[cfg(test)]
pub(crate) fn build_ssfw_for_test(children: &[Vec<u8>]) -> Vec<u8> {
    let mut h = vec![0u8; SSFW_HEADER as usize];
    h[..4].copy_from_slice(&SSFW_MAGIC);
    h[4..8].copy_from_slice(&(SSFW_HEADER as u32).to_le_bytes());
    h[8..12].copy_from_slice(&1u32.to_le_bytes());
    h[0x10..0x14].copy_from_slice(&(children.len() as u32).to_le_bytes());
    let mut table = Vec::new();
    let mut body = Vec::new();
    let mut off = SSFW_HEADER + children.len() as u64 * 16;
    for c in children {
        table.extend(off.to_le_bytes());
        table.extend((c.len() as u64).to_le_bytes());
        off += c.len() as u64;
        body.extend(c);
    }
    [h, table, body].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::ExtractOptions;
    use crate::oem::tests::{expected, fake_parts};
    use crate::oem::{Kind, detect, extract, list};
    use crate::testutil::Scratch;

    fn parts() -> Vec<(&'static str, Vec<u8>)> {
        let mut p = vec![("parameter", b"FIRMWARE_VER: 4.4\nCMDLINE: x\n".to_vec())];
        p.extend(fake_parts());
        p
    }

    #[test]
    fn the_crc_table_matches_the_published_rkcrc_table() {
        // first, second, ninth, seventeenth and last entries of rkcrc.h's `_t`
        let t = crc_table();
        assert_eq!(
            [t[0], t[1], t[2], t[8], t[16], t[255]],
            [
                0,
                0x04c1_0db7,
                0x0982_1b6e,
                0x2608_6db8,
                0x4c10_db70,
                0xb1f8_80b4
            ]
        );
    }

    #[test]
    fn rkaf_lists_and_extracts_with_wrappers_removed() {
        let d = Scratch::new("rk-rkaf");
        let p = d.join("update.img");
        std::fs::write(&p, build_rkaf_for_test(&parts())).unwrap();
        assert_eq!(detect(&p), Some(Kind::RockchipRkaf));
        let opts = ExtractOptions::default();
        let l = list(Kind::RockchipRkaf, &p, &opts).unwrap();
        assert_eq!(
            l,
            [
                ("boot.img".to_string(), 100),
                ("parameter.img".to_string(), 29),
                ("system.img".to_string(), 4096)
            ]
        );
        let out = d.join("out");
        extract(Kind::RockchipRkaf, &p, &out, &opts).unwrap();
        assert_eq!(
            std::fs::read(out.join("boot.img")).unwrap(),
            expected("boot")
        );
        assert_eq!(
            std::fs::read(out.join("system.img")).unwrap(),
            expected("system")
        );
        assert_eq!(
            std::fs::read(out.join("parameter.img")).unwrap(),
            b"FIRMWARE_VER: 4.4\nCMDLINE: x\n"
        );
    }

    #[test]
    fn rkfw_yields_the_loader_and_the_rkaf_parts_and_checks_the_md5() {
        let d = Scratch::new("rk-rkfw");
        let rkaf = build_rkaf_for_test(&parts());
        let p = d.join("fw.img");
        std::fs::write(&p, build_rkfw_for_test(&[0xAB; 64], &rkaf, true)).unwrap();
        assert_eq!(detect(&p), Some(Kind::RockchipRkfw));
        let names: Vec<_> = list(Kind::RockchipRkfw, &p, &ExtractOptions::default())
            .unwrap()
            .into_iter()
            .map(|x| x.0)
            .collect();
        assert_eq!(
            names,
            ["boot.img", "loader.img", "parameter.img", "system.img"]
        );
        // one flipped byte under the trailer: refused
        let mut bad = build_rkfw_for_test(&[0xAB; 64], &rkaf, true);
        bad[RKFW_HEADER as usize + 3] ^= 1;
        std::fs::write(&p, &bad).unwrap();
        let e = list(Kind::RockchipRkfw, &p, &ExtractOptions::default()).unwrap_err();
        assert!(e.to_string().contains("MD5"), "{e}");
    }

    #[test]
    fn a_corrupt_rkaf_is_refused_by_its_crc() {
        let d = Scratch::new("rk-crc");
        let mut v = build_rkaf_for_test(&parts());
        let n = v.len();
        v[n - 60] ^= 1; // inside the data
        let p = d.join("update.img");
        std::fs::write(&p, &v).unwrap();
        let e = list(Kind::RockchipRkaf, &p, &ExtractOptions::default()).unwrap_err();
        assert!(e.to_string().contains("CRC"), "{e}");
    }

    #[test]
    fn ssfw_expands_rkaf_children_and_writes_others_whole() {
        let d = Scratch::new("rk-ssfw");
        let p = d.join("fw.img");
        let ssfw = build_ssfw_for_test(&[build_rkaf_for_test(&fake_parts()), vec![9; 33]]);
        std::fs::write(&p, ssfw).unwrap();
        assert_eq!(detect(&p), Some(Kind::RockchipSsfw));
        let names: Vec<_> = list(Kind::RockchipSsfw, &p, &ExtractOptions::default())
            .unwrap()
            .into_iter()
            .map(|x| x.0)
            .collect();
        assert_eq!(names, ["img0-boot.img", "img0-system.img", "img1.img"]);
    }

    #[test]
    fn hostile_input_is_refused_without_panic() {
        let d = Scratch::new("rk-bad");
        let opts = ExtractOptions::default();
        let seeds = [
            ("rkaf", build_rkaf_for_test(&parts())),
            (
                "rkfw",
                build_rkfw_for_test(&[1; 16], &build_rkaf_for_test(&parts()), true),
            ),
            (
                "ssfw",
                build_ssfw_for_test(&[build_rkaf_for_test(&parts())]),
            ),
        ];
        for (kind, good) in seeds {
            let k = match kind {
                "rkaf" => Kind::RockchipRkaf,
                "rkfw" => Kind::RockchipRkfw,
                _ => Kind::RockchipSsfw,
            };
            let p = d.join(format!("{kind}.img"));
            // the MD5 trailer is optional, so cutting only into it leaves a valid file
            let trailer = if kind == "rkfw" { 32 } else { 0 };
            for cut in 0..good.len() - 1 - trailer {
                std::fs::write(&p, &good[..cut]).unwrap();
                assert!(
                    list(k, &p, &opts).is_err(),
                    "{kind} cut at {cut} was accepted"
                );
            }
            for at in (0..good.len().min(600)).step_by(1) {
                let mut v = good.clone();
                v[at] = v[at].wrapping_add(0x80);
                std::fs::write(&p, &v).unwrap();
                let _ = list(k, &p, &opts); // must not panic or hang
            }
        }
    }
}
