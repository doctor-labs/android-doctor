//! `ramdisk-edit`: put files into, or remove them from, the uncompressed cpio ramdisk of a boot
//! image (header versions 0 to 2) and write the result to a NEW image. The input is never changed.
//! Without `--yes` nothing is written; the output is verified by reading it back with `bootimg::read`
//! and `ramdisk::read_ramdisk` before it is renamed into place.
//! ponytail: uncompressed newc ramdisks only (gzip, lz4 and friends are refused), header versions 0 to 2,
//! mtime 0 for new entries, whole source file read into memory (256 MiB cap), no vendor_ramdisk.

use crate::bootimg;
use crate::detect::refuse_blocking_file;
use crate::extract::create_part;
use crate::ramdisk::{self, Compression};
use crate::treeout::clean_path;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const TRAILER: &str = "TRAILER!!!";
const CPIO_HEADER_LEN: usize = 110;
const MAX_PUT: u64 = 256 << 20;
const MAX_HEADER: u64 = 1 << 20;
const MODE_TYPE: u32 = 0o170000;
const MODE_DIR: u32 = 0o040000;
const MODE_FILE: u32 = 0o100000;

/// One newc record: the 13 header fields (0 ino, 1 mode, 4 nlink, 6 size, 11 namesize), the name and the data.
struct Record {
    fields: [u32; 13],
    name: String,
    data: Vec<u8>,
}

/// One requested change.
pub enum Op {
    Put { src: PathBuf, dest: String },
    Rm(String),
}

/// What the edit did, and what the read-back must find.
#[derive(Default)]
struct Checks {
    plan: Vec<String>,
    puts: Vec<(String, String)>,
    rms: Vec<String>,
}

/// A fully built output image, held in memory until it is written.
struct Built {
    bytes: Vec<u8>,
    orig_head: Vec<u8>,
    head: Vec<u8>,
    order: Vec<String>,
    kept: Vec<(String, Vec<u8>)>,
    entry_count: usize,
    checks: Checks,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn hex8(b: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(b)
        .ok()
        .filter(|s| s.bytes().all(|c| c.is_ascii_hexdigit()))
        .context("cpio header field is not hex")?;
    Ok(u32::from_str_radix(s, 16)?)
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn read_at(f: &mut File, at: u64, n: u64) -> Result<Vec<u8>> {
    ensure!(
        n <= ramdisk::MAX_DECOMPRESSED,
        "a section of {n} bytes is too large"
    );
    f.seek(SeekFrom::Start(at))?;
    let mut b = vec![0u8; n as usize];
    f.read_exact(&mut b).context("file ends inside a section")?;
    Ok(b)
}

/// True when every byte from `from` to the end of the file is zero.
fn tail_is_zero(f: &mut File, from: u64) -> Result<bool> {
    f.seek(SeekFrom::Start(from))?;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(true);
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
    }
}

fn parse_cpio(buf: &[u8]) -> Result<Vec<Record>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        let rest = buf.get(at..).unwrap_or(&[]);
        ensure!(
            rest.len() >= CPIO_HEADER_LEN,
            "cpio ends before its trailer"
        );
        ensure!(
            &rest[..6] == b"070701",
            "not a cpio newc archive (bad entry magic)"
        );
        let mut fields = [0u32; 13];
        for (i, f) in fields.iter_mut().enumerate() {
            *f = hex8(&rest[6 + 8 * i..14 + 8 * i])?;
        }
        let namesize = fields[11] as usize;
        ensure!(
            (1..=4096).contains(&namesize),
            "entry name of {namesize} bytes is not valid"
        );
        let name_at = at + CPIO_HEADER_LEN;
        let raw = buf
            .get(name_at..name_at + namesize)
            .context("cpio ends inside a name")?;
        ensure!(raw[namesize - 1] == 0, "entry name is not NUL-terminated");
        let name = String::from_utf8_lossy(&raw[..namesize - 1]).into_owned();
        let data_at = align4(name_at + namesize);
        let data_end = data_at
            .checked_add(fields[6] as usize)
            .context("entry size overflows")?;
        let data = buf
            .get(data_at..data_end)
            .with_context(|| format!("cpio ends inside {name}"))?;
        if name == TRAILER {
            let tail = buf.get(align4(data_end)..).unwrap_or(&[]);
            ensure!(
                tail.iter().all(|&b| b == 0),
                "data after the cpio trailer (a second archive?) is not supported"
            );
            return Ok(out);
        }
        out.push(Record {
            fields,
            name,
            data: data.to_vec(),
        });
        at = align4(data_end);
    }
}

fn put_record(out: &mut Vec<u8>, mut f: [u32; 13], name: &str, data: &[u8]) -> Result<()> {
    f[6] = u32::try_from(data.len()).context("entry is larger than 4 GiB")?;
    f[11] = (name.len() + 1) as u32;
    f[12] = 0;
    out.extend_from_slice(b"070701");
    for v in f {
        out.extend_from_slice(format!("{v:08x}").as_bytes());
    }
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.resize(align4(out.len()), 0);
    out.extend_from_slice(data);
    out.resize(align4(out.len()), 0);
    Ok(())
}

fn emit_cpio(records: &[Record]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for r in records {
        put_record(&mut out, r.fields, &r.name, &r.data)?;
    }
    put_record(
        &mut out,
        [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        TRAILER,
        &[],
    )?;
    out.resize(out.len().next_multiple_of(512), 0);
    Ok(out)
}

/// `path` as the reader names it (no leading slash, no `.`), refusing `..` and the archive root.
fn norm(p: &str) -> Result<String> {
    let p = clean_path(p.trim_start_matches("/"))?;
    ensure!(!p.is_empty(), "path {p:?} names the archive root");
    Ok(p)
}

fn find(records: &[Record], path: &str) -> Option<usize> {
    records
        .iter()
        .position(|r| clean_path(&r.name).ok().as_deref() == Some(path))
}

/// Source bytes and their permission bits (0o644 where the platform has no mode).
fn read_source(src: &Path) -> Result<(Vec<u8>, u32)> {
    let meta = std::fs::metadata(src).with_context(|| format!("reading {}", src.display()))?;
    ensure!(meta.is_file(), "{} is not a regular file", src.display());
    ensure!(
        meta.len() <= MAX_PUT,
        "{} is larger than 256 MiB",
        src.display()
    );
    #[cfg(unix)]
    let perm = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let perm = 0o644;
    Ok((std::fs::read(src)?, perm))
}

fn apply(records: &mut Vec<Record>, ops: &[Op]) -> Result<Checks> {
    let mut checks = Checks::default();
    let mut seen = HashSet::new();
    for op in ops {
        match op {
            Op::Put { src, dest } => {
                let path = norm(dest)?;
                ensure!(seen.insert(path.clone()), "{path} is named more than once");
                let (data, perm) = read_source(src)?;
                let sha: String = Sha256::digest(&data)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let len = data.len();
                let mode = MODE_FILE | perm;
                match find(records, &path) {
                    Some(i) => {
                        let r = &mut records[i];
                        ensure!(
                            r.fields[1] & MODE_TYPE == MODE_FILE,
                            "{path} exists and is not a regular file"
                        );
                        ensure!(
                            r.fields[4] <= 1,
                            "{path} is hard-linked; refusing to change its data"
                        );
                        r.fields[1] = mode;
                        r.data = data;
                    }
                    None => {
                        let ino = records
                            .iter()
                            .map(|r| r.fields[0])
                            .max()
                            .unwrap_or(0)
                            .checked_add(1)
                            .context("inode numbers are exhausted")?;
                        records.push(Record {
                            fields: [ino, mode, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                            name: path.clone(),
                            data,
                        });
                    }
                }
                checks
                    .plan
                    .push(format!("put {} -> /{path} ({len} bytes)", src.display()));
                checks.puts.push((path, sha));
            }
            Op::Rm(p) => {
                let path = norm(p)?;
                ensure!(seen.insert(path.clone()), "{path} is named more than once");
                let i =
                    find(records, &path).with_context(|| format!("no entry {path} to remove"))?;
                if records[i].fields[1] & MODE_TYPE == MODE_DIR {
                    let prefix = format!("{path}/");
                    ensure!(
                        !records
                            .iter()
                            .any(|r| clean_path(&r.name).is_ok_and(|n| n.starts_with(&prefix))),
                        "{path} is a directory with entries in it"
                    );
                }
                records.remove(i);
                checks.plan.push(format!("rm {path}"));
                checks.rms.push(path);
            }
        }
    }
    Ok(checks)
}

fn build(input: &Path, ops: &[Op]) -> Result<Built> {
    refuse_blocking_file(input)?;
    let image = bootimg::read(input)?;
    let mut f = File::open(input)?;
    let len = f.metadata()?.len();
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)
        .context("file is shorter than a boot image header")?;
    ensure!(
        &magic == b"ANDROID!",
        "not a boot image with an ANDROID! header (vendor boot images are not edited)"
    );
    let mut secs = image.sections.clone();
    secs.sort_by_key(|s| s.offset);
    for s in &secs {
        ensure!(
            matches!(s.name.as_str(), "kernel" | "ramdisk" | "second" | "dtb"),
            "section {} is not supported (kernel, ramdisk, second and dtb only)",
            s.name
        );
    }
    ensure!(
        secs.first().is_some_and(|s| s.name == "kernel"),
        "the image does not start with a kernel section"
    );
    ensure!(
        secs.iter().filter(|s| s.name == "ramdisk").count() == 1,
        "the image needs exactly one ramdisk section"
    );
    let kernel_at = secs[0].offset;
    ensure!(
        kernel_at <= MAX_HEADER,
        "the header is {kernel_at} bytes; that is too large"
    );
    let orig_head = read_at(&mut f, 0, kernel_at)?;
    ensure!(orig_head.len() >= 44, "the header is shorter than 44 bytes");
    let version = le32(&orig_head, 40);
    ensure!(
        version <= 2,
        "header version {version} is not edited (versions 0 to 2 only)"
    );
    let page = le32(&orig_head, 36) as u64;
    ensure!(
        page >= 512 && page.is_power_of_two() && kernel_at % page == 0,
        "page size {page} does not fit this header"
    );

    let rd = secs
        .iter()
        .find(|s| s.name == "ramdisk")
        .context("no ramdisk")?;
    let raw = read_at(&mut f, rd.offset, rd.size)?;
    ensure!(
        matches!(ramdisk::compression_of(&raw), Some(Compression::None)),
        "the ramdisk is not an uncompressed cpio (newc) archive; compressed ramdisks are not edited yet"
    );
    let mut records = parse_cpio(&raw)?;
    let checks = apply(&mut records, ops)?;
    let new_rd = emit_cpio(&records)?;
    let mut head = orig_head.clone();
    head[16..20].copy_from_slice(&u32::try_from(new_rd.len())?.to_le_bytes());

    let page = page as usize;
    let mut bytes = head.clone();
    let mut order = Vec::new();
    let mut kept = Vec::new();
    for s in &secs {
        let data = if s.name == "ramdisk" {
            new_rd.clone()
        } else {
            let d = read_at(&mut f, s.offset, s.size)?;
            kept.push((s.name.clone(), d.clone()));
            d
        };
        bytes.extend_from_slice(&data);
        bytes.resize(bytes.len().div_ceil(page) * page, 0);
        order.push(s.name.clone());
    }
    let last = secs.last().context("no sections")?;
    let end = (last.offset + last.size).div_ceil(page as u64) * page as u64;
    if len > end {
        ensure!(
            tail_is_zero(&mut f, end)?,
            "{} has data after its last section (an AVB footer, for example); that is not carried over",
            input.display()
        );
    }
    Ok(Built {
        bytes,
        orig_head,
        head,
        order,
        kept,
        entry_count: records.len(),
        checks,
    })
}

/// Read the written image back with the repo own readers and compare it with what was built.
fn verify(part: &Path, built: &Built) -> Result<()> {
    let written = std::fs::read(part)?;
    let hl = built.head.len();
    ensure!(
        written.get(..hl) == Some(built.head.as_slice()),
        "the written header differs from the built header"
    );
    ensure!(
        written[..16] == built.orig_head[..16] && written[20..hl] == built.orig_head[20..hl],
        "the written header changed fields other than the ramdisk size"
    );
    let image = bootimg::read(part)?;
    let names: Vec<&str> = image.sections.iter().map(|s| s.name.as_str()).collect();
    ensure!(
        names == built.order,
        "sections read back are {names:?}, expected {:?}",
        built.order
    );
    for s in &image.sections {
        let bytes = written
            .get(s.offset as usize..(s.offset + s.size) as usize)
            .with_context(|| format!("{} reads past the end of the file", s.name))?;
        if s.name == "ramdisk" {
            let rep = ramdisk::read_ramdisk(Cursor::new(bytes), None)?;
            ensure!(
                rep.entries.len() == built.entry_count,
                "ramdisk reads back {} entries, expected {}",
                rep.entries.len(),
                built.entry_count
            );
            for (path, sha) in &built.checks.puts {
                let e = rep
                    .entries
                    .iter()
                    .find(|e| &e.path == path)
                    .with_context(|| format!("{path} is missing after the edit"))?;
                ensure!(
                    e.sha256.as_deref() == Some(sha.as_str()),
                    "{path} does not hold its source bytes"
                );
            }
            for path in &built.checks.rms {
                ensure!(
                    !rep.entries.iter().any(|e| &e.path == path),
                    "{path} is still there after the removal"
                );
            }
        } else {
            let want = built
                .kept
                .iter()
                .find(|(n, _)| n == &s.name)
                .map(|(_, b)| b.as_slice());
            ensure!(want == Some(bytes), "{} changed", s.name);
        }
    }
    Ok(())
}

/// The `ramdisk-edit` command: `--put SRC=DEST` and `--rm PATH` into `output`.
pub fn run(
    input: &Path,
    puts: &[String],
    rms: &[String],
    output: &Path,
    force: bool,
    yes: bool,
) -> Result<()> {
    let mut ops = Vec::new();
    for p in puts {
        let (src, dest) = p
            .rsplit_once('=')
            .with_context(|| format!("--put {p:?} is not SRC=DEST"))?;
        ops.push(Op::Put {
            src: PathBuf::from(src),
            dest: dest.to_string(),
        });
    }
    for r in rms {
        ops.push(Op::Rm(r.clone()));
    }
    ensure!(
        !ops.is_empty(),
        "nothing to do: give --put SRC=DEST or --rm PATH"
    );
    ensure!(
        output.symlink_metadata().is_err() || force,
        "{} already exists; pass --force to overwrite",
        output.display()
    );
    if let (Ok(a), Ok(b)) = (input.canonicalize(), output.canonicalize()) {
        ensure!(a != b, "the output is the input; choose a new file");
    }
    let built = build(input, &ops)?;
    if !yes {
        for line in &built.checks.plan {
            println!("would {line}");
        }
        println!(
            "would write {} ({} bytes, {} ramdisk entries); nothing written, pass --yes to write",
            output.display(),
            built.bytes.len(),
            built.entry_count
        );
        return Ok(());
    }
    let mut part = output.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let written = (|| -> Result<()> {
        let mut out = create_part(&part)?;
        out.write_all(&built.bytes)?;
        out.sync_all()?;
        drop(out);
        verify(&part, &built)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, output)?;
    for line in &built.checks.plan {
        println!("{line}");
    }
    println!(
        "wrote {} and read it back: {} ramdisk entries, sections {:?} unchanged",
        output.display(),
        built.entry_count,
        built
            .kept
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpio(files: &[(&str, &[u8])]) -> Vec<u8> {
        let recs: Vec<Record> = files
            .iter()
            .enumerate()
            .map(|(i, (name, data))| Record {
                fields: [i as u32 + 1, 0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                name: name.to_string(),
                data: data.to_vec(),
            })
            .collect();
        emit_cpio(&recs).unwrap()
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ramdisk-edit-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn boot(d: &Path, ramdisk: &[u8]) -> PathBuf {
        let parts = bootimg::Parts {
            header_version: 2,
            page_size: 4096,
            kernel: vec![7u8; 5000],
            ramdisk: ramdisk.to_vec(),
            second: vec![],
            dtb: vec![9u8; 300],
            cmdline: "console=ttyS0".into(),
        };
        let p = d.join("boot.img");
        let mut f = File::create(&p).unwrap();
        bootimg::pack(&parts, &mut f).unwrap();
        p
    }

    fn names_in(img: &Path) -> Vec<String> {
        let image = bootimg::read(img).unwrap();
        let rd = image.sections.iter().find(|s| s.name == "ramdisk").unwrap();
        let bytes = std::fs::read(img).unwrap();
        let bytes = &bytes[rd.offset as usize..(rd.offset + rd.size) as usize];
        ramdisk::read_ramdisk(Cursor::new(bytes), None)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.path)
            .collect()
    }

    #[test]
    fn put_and_rm_write_a_new_image_and_leave_the_input_alone() {
        let d = dir("roundtrip");
        let input = boot(&d, &cpio(&[("init", b"init-script"), ("sbin/old", b"x")]));
        let before = std::fs::read(&input).unwrap();
        let src = d.join("adbd");
        std::fs::write(&src, b"new adbd bytes").unwrap();
        let out = d.join("out.img");
        run(
            &input,
            &[format!("{}=/sbin/adbd", src.display())],
            &["sbin/old".into()],
            &out,
            false,
            true,
        )
        .unwrap();
        assert_eq!(std::fs::read(&input).unwrap(), before);
        let names = names_in(&out);
        assert!(names.contains(&"sbin/adbd".to_string()), "{names:?}");
        assert!(names.contains(&"init".to_string()), "{names:?}");
        assert!(!names.contains(&"sbin/old".to_string()), "{names:?}");
    }

    #[test]
    fn dry_run_writes_nothing_and_existing_output_needs_force() {
        let d = dir("dryrun");
        let input = boot(&d, &cpio(&[("init", b"init-script")]));
        let out = d.join("out.img");
        run(&input, &[], &["init".into()], &out, false, false).unwrap();
        assert!(!out.exists());
        std::fs::write(&out, b"keep me").unwrap();
        let e = run(&input, &[], &["init".into()], &out, false, true).unwrap_err();
        assert!(e.to_string().contains("--force"), "{e}");
        assert_eq!(std::fs::read(&out).unwrap(), b"keep me");
    }
}
