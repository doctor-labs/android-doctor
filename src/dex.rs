//! DEX parser: header (with checksum and signature checks), string/type/proto/field/method
//! tables, class definitions with their fields and methods, and the code of each method
//! (decoded far enough to list the methods, fields, strings and types it references).
//!
//! Layout and Dalvik instruction formats follow the AOSP documents "Dalvik Executable format" and
//! "Dalvik bytecode" (Apache-2.0). Input is hostile: every table is checked against the file length
//! and every walk is bounded.

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::io::Read;
use std::path::Path;

/// Largest single dex we read, and the most dex bytes read from one archive.
const MAX_DEX_BYTES: u64 = 64 << 20;
const MAX_TOTAL_BYTES: u64 = 256 << 20;
const MAX_DEX_FILES: usize = 100;
const NO_INDEX: u32 = 0xffff_ffff;

#[derive(Debug, Clone)]
pub struct Header {
    pub version: String,
    pub checksum: u32,
    pub checksum_ok: bool,
    pub signature: String,
    pub signature_ok: bool,
    pub file_size: u32,
    pub header_size: u32,
    pub map_off: u32,
    pub data_size: u32,
}

#[derive(Debug, Clone)]
pub struct Proto {
    pub shorty: String,
    pub ret: String,
    pub params: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FieldRef {
    pub class: String,
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct MethodRef {
    pub class: String,
    pub name: String,
    pub proto: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ref {
    /// "method", "field", "string", "type"
    pub kind: &'static str,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct Code {
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    pub tries: u16,
    /// Length of the instruction stream in 16-bit units.
    pub units: u32,
    /// Offset of the first instruction unit in the file.
    pub insns_off: usize,
    pub refs: Vec<Ref>,
}

#[derive(Debug, Clone)]
pub struct Member {
    /// Index into the field or method table.
    pub idx: usize,
    pub flags: u32,
    pub code: Option<Code>,
}

#[derive(Debug, Clone)]
pub struct Class {
    pub descriptor: String,
    pub flags: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub static_fields: Vec<Member>,
    pub instance_fields: Vec<Member>,
    pub direct_methods: Vec<Member>,
    pub virtual_methods: Vec<Member>,
}

#[derive(Debug, Clone)]
pub struct Dex {
    pub name: String,
    pub header: Header,
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub protos: Vec<Proto>,
    pub fields: Vec<FieldRef>,
    pub methods: Vec<MethodRef>,
    pub classes: Vec<Class>,
    /// Things that did not parse (a bad class, a truncated code item); the rest is still shown.
    pub warnings: Vec<String>,
}

// --- Reading helpers ---

fn u16at(d: &[u8], o: usize) -> Result<u16> {
    let b = d
        .get(o..o.checked_add(2).context("offset")?)
        .context("truncated")?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32at(d: &[u8], o: usize) -> Result<u32> {
    let b = d
        .get(o..o.checked_add(4).context("offset")?)
        .context("truncated")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn uleb(d: &[u8], at: &mut usize) -> Result<u32> {
    let (mut v, mut shift) = (0u32, 0);
    loop {
        let b = *d.get(*at).context("truncated uleb128")?;
        *at += 1;
        v |= u32::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        if b & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
        ensure!(shift < 35, "uleb128 too long");
    }
}

fn adler32(d: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in d.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// Modified UTF-8 (NUL as C0 80, supplementary characters as surrogate pairs).
fn mutf8(b: &[u8]) -> String {
    let mut units = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let (u, n) = match c {
            0..=0x7f => (u16::from(c), 1),
            _ if c & 0xe0 == 0xc0 && i + 1 < b.len() => {
                ((u16::from(c & 0x1f) << 6) | u16::from(b[i + 1] & 0x3f), 2)
            }
            _ if c & 0xf0 == 0xe0 && i + 2 < b.len() => (
                (u16::from(c & 0x0f) << 12)
                    | (u16::from(b[i + 1] & 0x3f) << 6)
                    | u16::from(b[i + 2] & 0x3f),
                3,
            ),
            _ => (0xfffd, 1),
        };
        units.push(u);
        i += n;
    }
    String::from_utf16_lossy(&units)
}

// --- Dalvik opcodes ---

struct Op {
    name: &'static str,
    fmt: &'static str,
}

fn ops() -> &'static [Option<Op>; 256] {
    use std::sync::OnceLock;
    static T: OnceLock<[Option<Op>; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t: [Option<Op>; 256] = std::array::from_fn(|_| None);
        for l in include_str!("dex_ops.txt").lines() {
            let mut p = l.split(' ');
            if let (Some(h), Some(name), Some(fmt)) = (p.next(), p.next(), p.next()) {
                t[usize::from(u8::from_str_radix(h, 16).unwrap_or(0))] = Some(Op { name, fmt });
            }
        }
        t
    })
}

fn fmt_units(fmt: &str) -> usize {
    match fmt {
        "10x" | "12x" | "11n" | "11x" | "10t" => 1,
        "20t" | "22x" | "21t" | "21s" | "21h" | "21c" | "23x" | "22b" | "22t" | "22s" | "22c" => 2,
        "30t" | "32x" | "31i" | "31t" | "31c" | "35c" | "3rc" => 3,
        "45cc" | "4rc" => 4,
        _ => 5, // 51l
    }
}

/// What an instruction's index operand points at.
fn index_kind(op: u8) -> Option<&'static str> {
    Some(match op {
        0x1a | 0x1b => "string",
        0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25 => "type",
        0x52..=0x6d => "field",
        0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb => "method",
        0xfc | 0xfd => "call_site",
        0xfe => "method_handle",
        0xff => "proto",
        _ => return None,
    })
}

/// One decoded instruction: its start (unit index), length in units, and opcode (None for a
/// switch or array payload, which is data, not code).
struct Insn {
    at: usize,
    len: usize,
    op: Option<u8>,
}

/// The instruction at `at`, or None when the stream is truncated or the opcode is unassigned.
fn decode(code: &[u16], at: usize) -> Option<Insn> {
    let u = *code.get(at)?;
    let (lo, hi) = ((u & 0xff) as u8, u >> 8);
    if lo == 0 && hi != 0 {
        let len = match hi {
            0x01 => usize::from(*code.get(at + 1)?) * 2 + 4,
            0x02 => usize::from(*code.get(at + 1)?) * 4 + 2,
            0x03 => {
                let w = usize::from(*code.get(at + 1)?);
                let n = usize::from(*code.get(at + 2)?) | usize::from(*code.get(at + 3)?) << 16;
                (n.checked_mul(w)?.checked_add(1)? / 2) + 4
            }
            _ => return None,
        };
        return Some(Insn { at, len, op: None });
    }
    let op = ops()[usize::from(lo)].as_ref()?;
    let len = fmt_units(op.fmt);
    (at + len <= code.len()).then_some(Insn {
        at,
        len,
        op: Some(lo),
    })
}

// --- Parsing ---

struct P<'a> {
    d: &'a [u8],
    strings: Vec<String>,
    types: Vec<String>,
}

impl P<'_> {
    fn s(&self, i: u32) -> String {
        self.strings
            .get(i as usize)
            .cloned()
            .unwrap_or_else(|| format!("<string#{i}>"))
    }
    fn t(&self, i: u32) -> String {
        self.types
            .get(i as usize)
            .cloned()
            .unwrap_or_else(|| format!("<type#{i}>"))
    }
}

/// A table of `count` entries of `size` bytes at `off`, checked against the file.
fn table(d: &[u8], what: &str, count: u32, off: u32, size: usize) -> Result<usize> {
    let (count, off) = (count as usize, off as usize);
    if count == 0 {
        return Ok(off);
    }
    let end = count.checked_mul(size).and_then(|n| n.checked_add(off));
    ensure!(
        end.is_some_and(|e| e <= d.len()),
        "{what} table lies outside the file"
    );
    Ok(off)
}

pub fn parse(name: &str, d: &[u8]) -> Result<Dex> {
    if d.starts_with(b"cdex") {
        bail!("compact dex (cdex) is not supported");
    }
    ensure!(d.len() >= 0x70, "too short for a dex header");
    ensure!(
        &d[..4] == b"dex\n" && d[7] == 0,
        "not a dex file (bad magic)"
    );
    let version = String::from_utf8_lossy(&d[4..7]).into_owned();
    ensure!(
        version.bytes().all(|b| b.is_ascii_digit()),
        "bad dex version"
    );
    let endian = u32at(d, 40)?;
    ensure!(
        endian == 0x1234_5678,
        "unsupported endian tag {endian:#x} (only little-endian dex)"
    );
    let file_size = u32at(d, 32)?;
    let mut warnings = Vec::new();
    if file_size as usize != d.len() {
        warnings.push(format!(
            "header file_size {file_size} differs from the file length {}",
            d.len()
        ));
    }
    let end = (file_size as usize).min(d.len());
    let checksum = u32at(d, 8)?;
    let sig = &d[12..32];
    let header = Header {
        version,
        checksum,
        checksum_ok: end >= 12 && adler32(&d[12..end]) == checksum,
        signature: sig.iter().map(|b| format!("{b:02x}")).collect(),
        signature_ok: end >= 32 && Sha1::digest(&d[32..end]).as_slice() == sig,
        file_size,
        header_size: u32at(d, 36)?,
        map_off: u32at(d, 52)?,
        data_size: u32at(d, 104)?,
    };
    let (n_str, o_str) = (u32at(d, 56)?, u32at(d, 60)?);
    let (n_ty, o_ty) = (u32at(d, 64)?, u32at(d, 68)?);
    let (n_pr, o_pr) = (u32at(d, 72)?, u32at(d, 76)?);
    let (n_f, o_f) = (u32at(d, 80)?, u32at(d, 84)?);
    let (n_m, o_m) = (u32at(d, 88)?, u32at(d, 92)?);
    let (n_c, o_c) = (u32at(d, 96)?, u32at(d, 100)?);
    let o_str = table(d, "string_ids", n_str, o_str, 4)?;
    let o_ty = table(d, "type_ids", n_ty, o_ty, 4)?;
    let o_pr = table(d, "proto_ids", n_pr, o_pr, 12)?;
    let o_f = table(d, "field_ids", n_f, o_f, 8)?;
    let o_m = table(d, "method_ids", n_m, o_m, 8)?;
    let o_c = table(d, "class_defs", n_c, o_c, 32)?;

    let mut p = P {
        d,
        strings: Vec::with_capacity(n_str as usize),
        types: Vec::new(),
    };
    for i in 0..n_str as usize {
        let off = u32at(d, o_str + i * 4)? as usize;
        let s = (|| -> Result<String> {
            let mut at = off;
            uleb(d, &mut at)?;
            let rest = d.get(at..).context("string outside the file")?;
            let n = rest
                .iter()
                .position(|&b| b == 0)
                .context("unterminated string")?;
            Ok(mutf8(&rest[..n]))
        })();
        p.strings.push(s.unwrap_or_else(|e| {
            warnings.push(format!("string #{i}: {e}"));
            String::new()
        }));
    }
    for i in 0..n_ty as usize {
        let idx = u32at(d, o_ty + i * 4)?;
        let s = p.s(idx);
        p.types.push(s);
    }
    let mut protos = Vec::with_capacity(n_pr as usize);
    for i in 0..n_pr as usize {
        let b = o_pr + i * 12;
        let params_off = u32at(d, b + 8)? as usize;
        let mut params = Vec::new();
        if params_off != 0 {
            let n = u32at(d, params_off)? as usize;
            ensure!(n <= d.len() / 2, "type list too long");
            for k in 0..n {
                params.push(p.t(u32::from(u16at(d, params_off + 4 + k * 2)?)));
            }
        }
        protos.push(Proto {
            shorty: p.s(u32at(d, b)?),
            ret: p.t(u32at(d, b + 4)?),
            params,
        });
    }
    let mut fields = Vec::with_capacity(n_f as usize);
    for i in 0..n_f as usize {
        let b = o_f + i * 8;
        fields.push(FieldRef {
            class: p.t(u32::from(u16at(d, b)?)),
            ty: p.t(u32::from(u16at(d, b + 2)?)),
            name: p.s(u32at(d, b + 4)?),
        });
    }
    let mut methods = Vec::with_capacity(n_m as usize);
    for i in 0..n_m as usize {
        let b = o_m + i * 8;
        methods.push(MethodRef {
            class: p.t(u32::from(u16at(d, b)?)),
            proto: usize::from(u16at(d, b + 2)?),
            name: p.s(u32at(d, b + 4)?),
        });
    }
    let mut dex = Dex {
        name: name.to_string(),
        header,
        strings: Vec::new(),
        types: Vec::new(),
        protos,
        fields,
        methods,
        classes: Vec::new(),
        warnings,
    };
    let mut classes = Vec::with_capacity(n_c as usize);
    for i in 0..n_c as usize {
        match class_at(&p, &dex, o_c + i * 32) {
            Ok(c) => classes.push(c),
            Err(e) => dex.warnings.push(format!("class_def #{i}: {e:#}")),
        }
    }
    dex.classes = classes;
    dex.strings = p.strings;
    dex.types = p.types;
    Ok(dex)
}

fn opt(i: u32, f: impl Fn(u32) -> String) -> Option<String> {
    (i != NO_INDEX).then(|| f(i))
}

fn class_at(p: &P, dex: &Dex, b: usize) -> Result<Class> {
    let d = p.d;
    let mut c = Class {
        descriptor: p.t(u32at(d, b)?),
        flags: u32at(d, b + 4)?,
        superclass: opt(u32at(d, b + 8)?, |i| p.t(i)),
        interfaces: Vec::new(),
        source_file: opt(u32at(d, b + 16)?, |i| p.s(i)),
        static_fields: Vec::new(),
        instance_fields: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: Vec::new(),
    };
    let ifs = u32at(d, b + 12)? as usize;
    if ifs != 0 {
        let n = u32at(d, ifs)? as usize;
        ensure!(n <= d.len() / 2, "interface list too long");
        for k in 0..n {
            c.interfaces
                .push(p.t(u32::from(u16at(d, ifs + 4 + k * 2)?)));
        }
    }
    let cd = u32at(d, b + 24)? as usize;
    if cd == 0 {
        return Ok(c);
    }
    let mut at = cd;
    let counts = [
        uleb(d, &mut at)?,
        uleb(d, &mut at)?,
        uleb(d, &mut at)?,
        uleb(d, &mut at)?,
    ];
    for (n, is_method, dst) in [
        (counts[0], false, 0),
        (counts[1], false, 1),
        (counts[2], true, 2),
        (counts[3], true, 3),
    ] {
        ensure!(n as usize <= d.len(), "member count too large");
        let (mut idx, mut out) = (0u32, Vec::new());
        for _ in 0..n {
            idx = idx.wrapping_add(uleb(d, &mut at)?);
            let flags = uleb(d, &mut at)?;
            let code = if is_method {
                let off = uleb(d, &mut at)? as usize;
                (off != 0).then(|| code_at(p, dex, off)).transpose()?
            } else {
                None
            };
            out.push(Member {
                idx: idx as usize,
                flags,
                code,
            });
        }
        match dst {
            0 => c.static_fields = out,
            1 => c.instance_fields = out,
            2 => c.direct_methods = out,
            _ => c.virtual_methods = out,
        }
    }
    Ok(c)
}

fn insns(d: &[u8], off: usize, units: usize) -> Result<Vec<u16>> {
    let end = units.checked_mul(2).and_then(|n| n.checked_add(off));
    let bytes = end
        .and_then(|e| d.get(off..e))
        .context("code outside the file")?;
    Ok(bytes
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect())
}

fn ref_text(p: &P, dex: &Dex, kind: &str, idx: u32) -> Option<Ref> {
    Some(match kind {
        "method" => Ref {
            kind: "method",
            text: method_name(dex, idx as usize)?,
        },
        "field" => Ref {
            kind: "field",
            text: field_name(dex, idx as usize)?,
        },
        "string" => Ref {
            kind: "string",
            text: p.strings.get(idx as usize)?.clone(),
        },
        "type" => Ref {
            kind: "type",
            text: p.types.get(idx as usize)?.clone(),
        },
        _ => return None,
    })
}

fn code_at(p: &P, dex: &Dex, off: usize) -> Result<Code> {
    let d = p.d;
    let units = u32at(d, off + 12)?;
    let code = insns(d, off + 16, units as usize)?;
    let mut refs: Vec<Ref> = Vec::new();
    let mut at = 0;
    while at < code.len() {
        let Some(i) = decode(&code, at) else { break };
        if let Some(op) = i.op
            && let Some(kind) = index_kind(op)
        {
            let idx = match ops()[usize::from(op)].as_ref().map(|o| o.fmt) {
                Some("31c") => u32::from(code[at + 1]) | u32::from(code[at + 2]) << 16,
                _ => u32::from(code[at + 1]),
            };
            // string refs from string/jumbo come with the string table of the *parser*, which
            // is not yet in `dex`; method/field refs use the tables already built.
            if let Some(r) = ref_text(p, dex, kind, idx)
                && !refs.contains(&r)
            {
                refs.push(r);
            }
        }
        at += i.len;
    }
    Ok(Code {
        registers: u16at(d, off)?,
        ins: u16at(d, off + 2)?,
        outs: u16at(d, off + 4)?,
        tries: u16at(d, off + 6)?,
        units,
        insns_off: off + 16,
        refs,
    })
}

// --- Names ---

/// `Lcom/foo/Bar;` as `com.foo.Bar`; arrays and primitives are left readable too.
pub fn pretty(desc: &str) -> String {
    let dims = desc.bytes().take_while(|&b| b == b'[').count();
    let base = &desc[dims..];
    let name = match base {
        "V" => "void".into(),
        "Z" => "boolean".into(),
        "B" => "byte".into(),
        "S" => "short".into(),
        "C" => "char".into(),
        "I" => "int".into(),
        "J" => "long".into(),
        "F" => "float".into(),
        "D" => "double".into(),
        b if b.starts_with('L') && b.ends_with(';') => b[1..b.len() - 1].replace('/', "."),
        b => b.to_string(),
    };
    format!("{name}{}", "[]".repeat(dims))
}

pub fn proto_sig(dex: &Dex, i: usize) -> String {
    match dex.protos.get(i) {
        Some(p) => format!("({}){}", p.params.concat(), p.ret),
        None => "(?)?".into(),
    }
}

/// `Lcom/foo/Bar;->name(I)V`
pub fn method_name(dex: &Dex, i: usize) -> Option<String> {
    let m = dex.methods.get(i)?;
    Some(format!(
        "{}->{}{}",
        m.class,
        m.name,
        proto_sig(dex, m.proto)
    ))
}

/// `Lcom/foo/Bar;->name:I`
pub fn field_name(dex: &Dex, i: usize) -> Option<String> {
    let f = dex.fields.get(i)?;
    Some(format!("{}->{}:{}", f.class, f.name, f.ty))
}

// --- Input ---

/// The dex files in `path`: a `.dex`, or every `classes*.dex` at the root of an APK/zip.
pub fn read_input(path: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    crate::detect::refuse_blocking_file(path)?;
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    if n == 4 && &magic == b"dex\n" {
        let mut v = magic.to_vec();
        f.take(MAX_DEX_BYTES).read_to_end(&mut v)?;
        return Ok(vec![(crate::display_name(path), v)]);
    }
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path)?)
        .with_context(|| format!("{} is neither a dex file nor an APK/zip", path.display()))?;
    let mut names: Vec<String> = zip
        .file_names()
        .filter(|n| {
            n.strip_prefix("classes")
                .and_then(|r| r.strip_suffix(".dex"))
                .is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(String::from)
        .collect();
    // classes.dex, classes2.dex, ... classes10.dex in numeric order
    names.sort_by_key(|n| n[7..n.len() - 4].parse::<u32>().unwrap_or(1));
    ensure!(
        !names.is_empty(),
        "{} holds no classes*.dex",
        path.display()
    );
    names.truncate(MAX_DEX_FILES);
    let (mut out, mut total) = (Vec::new(), 0u64);
    for n in names {
        let e = zip.by_name(&n)?;
        ensure!(
            e.size() <= MAX_DEX_BYTES,
            "{n} is larger than {MAX_DEX_BYTES} bytes"
        );
        total += e.size();
        ensure!(
            total <= MAX_TOTAL_BYTES,
            "the dex files total more than {MAX_TOTAL_BYTES} bytes"
        );
        let mut v = Vec::new();
        e.take(MAX_DEX_BYTES).read_to_end(&mut v)?;
        out.push((n, v));
    }
    Ok(out)
}

// --- Disassembly ---

fn lit(v: i64) -> String {
    if v < 0 {
        format!("-{:#x}", -v)
    } else {
        format!("{v:#x}")
    }
}

fn regs_range(c: u16, n: u16) -> String {
    format!(
        "{{v{c} .. v{}}}",
        u32::from(c) + u32::from(n).saturating_sub(1)
    )
}

fn operands(dex: &Dex, strings: &[String], code: &[u16], i: &Insn, op: u8, fmt: &str) -> String {
    let a = i.at;
    let u = |k: usize| code.get(a + k).copied().unwrap_or(0);
    let hi = u(0) >> 8;
    let idx_text = |idx: u32| match index_kind(op) {
        Some("string") => format!(
            "{:?}",
            strings.get(idx as usize).map_or("?", |s| s.as_str())
        ),
        Some("type") => dex.types_get(idx),
        Some("field") => field_name(dex, idx as usize).unwrap_or_else(|| format!("field@{idx}")),
        Some("method") => method_name(dex, idx as usize).unwrap_or_else(|| format!("method@{idx}")),
        Some(k) => format!("{k}@{idx}"),
        None => format!("{idx}"),
    };
    let i32at = |k: usize| (u32::from(u(k)) | u32::from(u(k + 1)) << 16) as i32;
    match fmt {
        "10x" => String::new(),
        "12x" => format!("v{}, v{}", hi & 0xf, hi >> 4),
        "11n" => format!(
            "v{}, {}",
            hi & 0xf,
            lit(i64::from(((hi >> 4) as i8) << 4 >> 4))
        ),
        "11x" => format!("v{hi}"),
        "10t" => format!("{:+}", hi as i8),
        "20t" => format!("{:+}", u(1) as i16),
        "22x" => format!("v{hi}, v{}", u(1)),
        "21t" => format!("v{hi}, {:+}", u(1) as i16),
        "21s" => format!("v{hi}, {}", lit(i64::from(u(1) as i16))),
        "21h" => format!("v{hi}, {}", lit(i64::from(u(1) as i16) << 16)),
        "21c" => format!("v{hi}, {}", idx_text(u32::from(u(1)))),
        "23x" => format!("v{hi}, v{}, v{}", u(1) & 0xff, u(1) >> 8),
        "22b" => format!(
            "v{hi}, v{}, {}",
            u(1) & 0xff,
            lit(i64::from((u(1) >> 8) as i8))
        ),
        "22t" => format!("v{}, v{}, {:+}", hi & 0xf, hi >> 4, u(1) as i16),
        "22s" => format!(
            "v{}, v{}, {}",
            hi & 0xf,
            hi >> 4,
            lit(i64::from(u(1) as i16))
        ),
        "22c" => format!("v{}, v{}, {}", hi & 0xf, hi >> 4, idx_text(u32::from(u(1)))),
        "30t" => format!("{:+}", i32at(1)),
        "32x" => format!("v{}, v{}", u(1), u(2)),
        "31i" => format!("v{hi}, {}", lit(i64::from(i32at(1)))),
        "31t" => format!("v{hi}, {:+}", i32at(1)),
        "31c" => format!("v{hi}, {}", idx_text(i32at(1) as u32)),
        "35c" | "45cc" => {
            let n = usize::from(hi >> 4).min(5);
            let r = [
                u(2) & 0xf,
                (u(2) >> 4) & 0xf,
                (u(2) >> 8) & 0xf,
                u(2) >> 12,
                hi & 0xf,
            ];
            let args = r[..n]
                .iter()
                .map(|x| format!("v{x}"))
                .collect::<Vec<_>>()
                .join(", ");
            let extra = if fmt == "45cc" {
                format!(", proto@{}", u(3))
            } else {
                String::new()
            };
            format!("{{{args}}}, {}{extra}", idx_text(u32::from(u(1))))
        }
        "3rc" | "4rc" => {
            let extra = if fmt == "4rc" {
                format!(", proto@{}", u(3))
            } else {
                String::new()
            };
            format!(
                "{}, {}{extra}",
                regs_range(u(2), hi),
                idx_text(u32::from(u(1)))
            )
        }
        _ => {
            let v = u64::from(u(1))
                | u64::from(u(2)) << 16
                | u64::from(u(3)) << 32
                | u64::from(u(4)) << 48;
            format!("v{hi}, {}", lit(v as i64))
        }
    }
}

impl Dex {
    fn types_get(&self, i: u32) -> String {
        self.types
            .get(i as usize)
            .cloned()
            .unwrap_or_else(|| format!("type@{i}"))
    }
}

/// Disassemble one method's code: `offset: mnemonic operands`, one line per instruction.
pub fn disassemble(dex: &Dex, data: &[u8], code: &Code) -> Vec<String> {
    let Ok(units) = insns(data, code.insns_off, code.units as usize) else {
        return vec!["<code outside the file>".into()];
    };
    let mut out = Vec::new();
    let mut at = 0;
    while at < units.len() {
        let Some(i) = decode(&units, at) else {
            out.push(format!("{at:04x}: <undecodable>"));
            break;
        };
        out.push(match i.op {
            Some(op) => {
                let o = ops()[usize::from(op)].as_ref().expect("decoded");
                let args = operands(dex, &dex.strings, &units, &i, op, o.fmt);
                format!("{at:04x}: {} {args}", o.name)
                    .trim_end()
                    .to_string()
            }
            None => format!("{at:04x}: <payload, {} units>", i.len),
        });
        at += i.len;
    }
    out
}

// --- Output ---

/// What to list besides the header and counts.
#[derive(Default, Clone)]
pub struct Select {
    pub classes: bool,
    pub methods: bool,
    pub fields: bool,
    pub strings: bool,
    pub refs: bool,
    /// Disassemble the methods of classes whose descriptor or name contains this.
    pub code: Option<String>,
    /// Keep only entries containing this text.
    pub grep: Option<String>,
}

fn keep(sel: &Select, s: &str) -> bool {
    sel.grep.as_ref().is_none_or(|g| s.contains(g.as_str()))
}

impl Class {
    fn all_methods(&self) -> impl Iterator<Item = &Member> {
        self.direct_methods.iter().chain(&self.virtual_methods)
    }
}

pub fn to_json(dexes: &[Dex], datas: &[Vec<u8>], sel: &Select) -> Value {
    json!(dexes.iter().zip(datas).map(|(x, data)| {
        let h = &x.header;
        let mut o = json!({
            "name": x.name,
            "header": {
                "version": h.version, "checksum": format!("{:08x}", h.checksum), "checksum_ok": h.checksum_ok,
                "signature": h.signature, "signature_ok": h.signature_ok, "file_size": h.file_size,
                "header_size": h.header_size, "map_off": h.map_off, "data_size": h.data_size,
            },
            "counts": {
                "strings": x.strings.len(), "types": x.types.len(), "protos": x.protos.len(),
                "fields": x.fields.len(), "methods": x.methods.len(), "classes": x.classes.len(),
                "defined_methods": x.classes.iter().map(|c| c.all_methods().count()).sum::<usize>(),
            },
            "warnings": x.warnings,
        });
        if sel.classes {
            o["classes"] = json!(x.classes.iter().filter(|c| keep(sel, &c.descriptor)).map(|c| json!({
                "descriptor": c.descriptor, "name": pretty(&c.descriptor), "access_flags": c.flags,
                "superclass": c.superclass, "interfaces": c.interfaces, "source_file": c.source_file,
                "static_fields": c.static_fields.len(), "instance_fields": c.instance_fields.len(),
                "direct_methods": c.direct_methods.len(), "virtual_methods": c.virtual_methods.len(),
            })).collect::<Vec<_>>());
        }
        if sel.methods {
            o["methods"] = json!(x.classes.iter().flat_map(|c| c.all_methods().map(move |m| (c, m)))
                .filter_map(|(c, m)| Some((c, m, method_name(x, m.idx)?)))
                .filter(|(_, _, n)| keep(sel, n))
                .map(|(c, m, n)| json!({
                    "class": c.descriptor, "method": n, "access_flags": m.flags,
                    "registers": m.code.as_ref().map(|k| k.registers),
                    "ins": m.code.as_ref().map(|k| k.ins),
                    "outs": m.code.as_ref().map(|k| k.outs),
                    "tries": m.code.as_ref().map(|k| k.tries),
                    "units": m.code.as_ref().map(|k| k.units),
                })).collect::<Vec<_>>());
        }
        if sel.methods {
            o["protos"] = json!(x.protos.iter().map(|p| json!({
                "shorty": p.shorty, "return": p.ret, "params": p.params,
            })).collect::<Vec<_>>());
        }
        if sel.fields {
            o["fields"] = json!(x.classes.iter().flat_map(|c| c.static_fields.iter().chain(&c.instance_fields).map(move |m| (c, m)))
                .filter_map(|(c, m)| Some((c, m, field_name(x, m.idx)?)))
                .filter(|(_, _, n)| keep(sel, n))
                .map(|(c, m, n)| json!({"class": c.descriptor, "field": n, "access_flags": m.flags}))
                .collect::<Vec<_>>());
        }
        if sel.strings {
            o["strings"] = json!(x.strings.iter().filter(|s| keep(sel, s)).collect::<Vec<_>>());
        }
        if sel.refs {
            o["references"] = json!(x.classes.iter().flat_map(|c| c.all_methods())
                .filter_map(|m| Some((method_name(x, m.idx)?, m.code.as_ref()?)))
                .filter(|(n, k)| keep(sel, n) || k.refs.iter().any(|r| keep(sel, &r.text)))
                .map(|(n, k)| json!({
                    "method": n,
                    "refs": k.refs.iter().filter(|r| sel.grep.is_none() || keep(sel, &r.text) || keep(sel, &n))
                        .map(|r| json!({"kind": r.kind, "text": r.text})).collect::<Vec<_>>(),
                })).collect::<Vec<_>>());
        }
        if let Some(q) = &sel.code {
            o["code"] = json!(code_listing(x, data, q).into_iter()
                .map(|(m, lines)| json!({"method": m, "instructions": lines})).collect::<Vec<_>>());
        }
        o
    }).collect::<Vec<_>>())
}

fn code_listing(x: &Dex, data: &[u8], q: &str) -> Vec<(String, Vec<String>)> {
    x.classes
        .iter()
        .filter(|c| c.descriptor.contains(q) || pretty(&c.descriptor).contains(q))
        .flat_map(|c| c.all_methods())
        .filter_map(|m| {
            Some((
                method_name(x, m.idx)?,
                disassemble(x, data, m.code.as_ref()?),
            ))
        })
        .collect()
}

pub fn to_text(dexes: &[Dex], datas: &[Vec<u8>], sel: &Select) -> String {
    let mut o = Vec::new();
    for (x, data) in dexes.iter().zip(datas) {
        let h = &x.header;
        let ok = |b: bool| if b { "ok" } else { "MISMATCH" };
        o.push(format!(
            "{}: dex {}, {} bytes, checksum {:08x} ({}), signature {} ({})",
            x.name,
            h.version,
            h.file_size,
            h.checksum,
            ok(h.checksum_ok),
            &h.signature[..8.min(h.signature.len())],
            ok(h.signature_ok)
        ));
        o.push(format!(
            "  {} strings, {} types, {} protos, {} fields, {} methods, {} classes ({} defined methods)",
            x.strings.len(), x.types.len(), x.protos.len(), x.fields.len(), x.methods.len(),
            x.classes.len(), x.classes.iter().map(|c| c.all_methods().count()).sum::<usize>()
        ));
        for w in &x.warnings {
            o.push(format!("  warning: {w}"));
        }
        if sel.classes {
            for c in x.classes.iter().filter(|c| keep(sel, &c.descriptor)) {
                o.push(format!(
                    "class {} flags {:#06x} extends {}{}",
                    pretty(&c.descriptor),
                    c.flags,
                    c.superclass.as_deref().map_or("-".into(), pretty),
                    if c.interfaces.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " implements {}",
                            c.interfaces
                                .iter()
                                .map(|i| pretty(i))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                ));
            }
        }
        if sel.methods {
            for m in x.classes.iter().flat_map(|c| c.all_methods()) {
                if let Some(n) = method_name(x, m.idx).filter(|n| keep(sel, n)) {
                    o.push(format!("method {n} flags {:#06x}", m.flags));
                }
            }
        }
        if sel.fields {
            for m in x
                .classes
                .iter()
                .flat_map(|c| c.static_fields.iter().chain(&c.instance_fields))
            {
                if let Some(n) = field_name(x, m.idx).filter(|n| keep(sel, n)) {
                    o.push(format!("field {n} flags {:#06x}", m.flags));
                }
            }
        }
        if sel.strings {
            o.extend(
                x.strings
                    .iter()
                    .filter(|s| keep(sel, s))
                    .map(|s| format!("string {s:?}")),
            );
        }
        if sel.refs {
            for m in x.classes.iter().flat_map(|c| c.all_methods()) {
                let (Some(n), Some(k)) = (method_name(x, m.idx), m.code.as_ref()) else {
                    continue;
                };
                let rs: Vec<&Ref> = k
                    .refs
                    .iter()
                    .filter(|r| sel.grep.is_none() || keep(sel, &n) || keep(sel, &r.text))
                    .collect();
                if !rs.is_empty() {
                    o.push(n);
                    o.extend(rs.iter().map(|r| format!("    {} {}", r.kind, r.text)));
                }
            }
        }
        if let Some(q) = &sel.code {
            for (m, lines) in code_listing(x, data, q) {
                o.push(m);
                o.extend(lines.into_iter().map(|l| format!("    {l}")));
            }
        }
    }
    o.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// `javac --release 8` + `d8 --min-api 24` over tests/fixtures/dex/Main.java.
    const DEMO: &[u8] = include_bytes!("../tests/fixtures/dex/demo.dex");

    fn demo() -> Dex {
        parse("demo.dex", DEMO).unwrap()
    }

    fn method<'a>(x: &'a Dex, name: &str) -> &'a Member {
        x.classes
            .iter()
            .flat_map(|c| c.all_methods())
            .find(|m| method_name(x, m.idx).is_some_and(|n| n.contains(name)))
            .unwrap_or_else(|| panic!("no method {name}"))
    }

    #[test]
    fn header_and_tables_match_dexdump() {
        let x = demo();
        // `dexdump -f` on the same file: dex 037, 71 strings, 31 types, 15 protos, 7 fields,
        // 27 method ids, 3 classes.
        assert_eq!(x.header.version, "037");
        assert!(x.header.checksum_ok && x.header.signature_ok);
        assert_eq!(
            (
                x.strings.len(),
                x.types.len(),
                x.protos.len(),
                x.fields.len(),
                x.methods.len(),
                x.classes.len()
            ),
            (71, 31, 15, 7, 27, 3)
        );
        assert!(x.warnings.is_empty(), "{:?}", x.warnings);
    }

    #[test]
    fn classes_members_and_names() {
        let x = demo();
        let main = x
            .classes
            .iter()
            .find(|c| c.descriptor == "Ldemo/Main;")
            .unwrap();
        assert_eq!(pretty(&main.descriptor), "demo.Main");
        assert_eq!(main.interfaces, ["Ljava/lang/Runnable;"]);
        assert_eq!(main.source_file.as_deref(), Some("Main.java"));
        assert_eq!(main.superclass.as_deref(), Some("Ljava/lang/Object;"));
        assert_eq!(main.instance_fields.len(), 2); // count, big
        assert_eq!(main.static_fields.len(), 1); // KEY
        let run = method(&x, "Ldemo/Main;->run()V");
        assert!(run.code.as_ref().unwrap().registers > 0);
        assert_eq!(pretty("[[I"), "int[][]");
    }

    #[test]
    fn strings_decode_modified_utf8() {
        let x = demo();
        // an embedded NUL (C0 80) and a supplementary character (surrogate pair, CESU-8)
        assert!(
            x.strings.iter().any(|s| s == "s3cr3t-\u{0}-\u{1f600}"),
            "{:?}",
            x.strings
        );
        assert_eq!(
            mutf8(&[0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]),
            "\u{0}\u{1f600}"
        );
    }

    #[test]
    fn references_come_from_the_code() {
        let x = demo();
        let refs = &method(&x, "Ldemo/Main;->run()V")
            .code
            .as_ref()
            .unwrap()
            .refs;
        let has = |k: &str, t: &str| refs.iter().any(|r| r.kind == k && r.text == t);
        assert!(has(
            "method",
            "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
        ));
        assert!(has("string", "demo.Main"));
        assert!(has("field", "Ldemo/Main;->count:I"));
        assert!(has("type", "Ljava/util/ArrayList;"));
    }

    #[test]
    fn disassembly_decodes_switches_and_payloads() {
        let x = demo();
        let sw = method(&x, "->sw(I)I");
        let lines = disassemble(&x, DEMO, sw.code.as_ref().unwrap());
        assert!(lines.iter().any(|l| l.contains("-switch ")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("<payload")), "{lines:?}");
        let run = method(&x, "Ldemo/Main;->run()V");
        let text = disassemble(&x, DEMO, run.code.as_ref().unwrap()).join("\n");
        assert!(
            text.contains("invoke-static {v0}, Ljava/lang/Class;->forName"),
            "{text}"
        );
        assert!(text.contains("const-string"), "{text}");
    }

    #[test]
    fn every_opcode_has_the_width_the_spec_gives() {
        // 224 assigned opcodes; spot-check the widths the table is built from.
        let count = ops().iter().flatten().count();
        assert_eq!(count, 224);
        let w = |n: &str| {
            ops()
                .iter()
                .flatten()
                .find(|o| o.name == n)
                .map(|o| fmt_units(o.fmt))
        };
        assert_eq!(
            [
                w("nop"),
                w("const/16"),
                w("const"),
                w("const-wide"),
                w("invoke-virtual"),
                w("invoke-polymorphic")
            ],
            [Some(1), Some(2), Some(3), Some(5), Some(3), Some(4)]
        );
    }

    #[test]
    fn a_corrupt_dex_is_reported_not_trusted() {
        let mut bad = DEMO.to_vec();
        *bad.last_mut().unwrap() ^= 1; // inside the data area: checksum and signature break
        let x = parse("bad", &bad).unwrap();
        assert!(!x.header.checksum_ok && !x.header.signature_ok);
        assert!(
            parse("x", b"cdex\x00\x00\x00\x00")
                .unwrap_err()
                .to_string()
                .contains("cdex")
        );
        assert!(parse("x", b"dex\n037\0").is_err());
        let mut be = DEMO.to_vec();
        be[40..44].copy_from_slice(&0x7856_3412u32.to_le_bytes());
        assert!(parse("x", &be).unwrap_err().to_string().contains("endian"));
    }

    #[test]
    fn hostile_truncations_and_flips_never_panic() {
        for cut in (0..DEMO.len()).step_by(7) {
            let _ = parse("t", &DEMO[..cut]);
        }
        for at in 0..DEMO.len() {
            let mut v = DEMO.to_vec();
            v[at] ^= 0xff;
            if let Ok(x) = parse("f", &v) {
                for m in x.classes.iter().flat_map(|c| c.all_methods()) {
                    if let Some(c) = &m.code {
                        disassemble(&x, &v, c);
                    }
                }
            }
        }
    }

    #[test]
    fn an_apk_yields_its_classes_dex_files_in_numeric_order() {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default();
        for n in [
            "classes10.dex",
            "classes2.dex",
            "classes.dex",
            "assets/classes3.dex",
            "other.dex",
        ] {
            w.start_file(n, o).unwrap();
            w.write_all(DEMO).unwrap();
        }
        let dir = crate::testutil::Scratch::new("dex-apk");
        let p = dir.join("a.apk");
        std::fs::write(&p, w.finish().unwrap().into_inner()).unwrap();
        let names: Vec<_> = read_input(&p).unwrap().into_iter().map(|f| f.0).collect();
        assert_eq!(names, ["classes.dex", "classes2.dex", "classes10.dex"]);
        std::fs::write(dir.join("n.apk"), b"PK\x03\x04junk").unwrap();
        assert!(read_input(&dir.join("n.apk")).is_err());
    }
}
