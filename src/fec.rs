//! dm-verity forward error correction (FEC), the Reed-Solomon parity Android keeps next to a
//! partition: generate it, verify a file against it, and repair a file with it.
//!
//! Layout (AOSP `fec` / libfec, as `avbroot fec` writes it; all little-endian):
//!
//! * Blocks are 4096 bytes. The code is RS(255, 255 - roots) over GF(2^8), field polynomial
//!   0x11d, first consecutive root 0, primitive element 1. `roots` (the "parity bytes per RS
//!   block") is 2 to 24; AOSP uses 2.
//! * With `rsn = 255 - roots`, `blocks = ceil(len / 4096)` and `rounds = ceil(blocks / rsn)`,
//!   codeword `(i, j)` for round `i < rounds` and byte `j < 4096` is the byte `j` of blocks
//!   `i + k * rounds` for `k < rsn` (zeros past the last block), followed by its `roots` parity
//!   bytes.
//! * The parity bytes of round `i` fill `roots` blocks at `i * roots * 4096`, laid out
//!   `j * roots + m`. All rounds make `fec_size = rounds * roots * 4096` bytes.
//! * The file ends with one more block that holds the header twice, in its first and last 60
//!   bytes: `0xFECFECFE`, version 0, size 60, `roots`, `fec_size`, u64 input size, and the SHA-256
//!   of the parity. Reading uses the last copy.
//!
//! Repair corrects up to `roots / 2` wrong bytes per codeword (Berlekamp-Massey, a search for
//! the error positions and Forney's formula) and re-checks every correction against the
//! syndromes; a codeword it cannot fix is counted, never guessed at.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const BLOCK: usize = 4096;
const MAGIC: u32 = 0xFECF_ECFE;
const HEADER: usize = 60;
pub const MIN_ROOTS: usize = 2;
pub const MAX_ROOTS: usize = 24;
/// Refuse inputs whose parity would not fit (2^32 blocks of 4096 bytes is 16 TiB).
const MAX_BLOCKS: u64 = 1 << 32;

struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf {
    fn new() -> Gf {
        let (mut exp, mut log) = ([0u8; 512], [0u8; 256]);
        let mut x = 1u16;
        for (i, e) in exp.iter_mut().enumerate().take(255) {
            *e = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    fn inv(&self, a: u8) -> u8 {
        self.exp[255 - self.log[a as usize] as usize]
    }

    /// The generator polynomial's coefficients after the leading 1, highest degree first.
    fn generator(&self, roots: usize) -> Vec<u8> {
        let mut g = vec![1u8];
        for i in 0..roots {
            let r = self.exp[i];
            let mut next = vec![0u8; g.len() + 1];
            for (j, &c) in g.iter().enumerate() {
                next[j] ^= c;
                next[j + 1] ^= self.mul(c, r);
            }
            g = next;
        }
        g.split_off(1)
    }

    fn table(&self, c: u8) -> [u8; 256] {
        std::array::from_fn(|x| self.mul(c, x as u8))
    }
}

/// Shape of the code for an input of `len` bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shape {
    pub roots: usize,
    pub blocks: u64,
    pub rounds: u64,
}

impl Shape {
    pub fn new(len: u64, roots: usize) -> Result<Shape> {
        ensure!(
            (MIN_ROOTS..=MAX_ROOTS).contains(&roots),
            "parity bytes per block must be {MIN_ROOTS} to {MAX_ROOTS}, got {roots}"
        );
        ensure!(
            len > 0 && len.is_multiple_of(BLOCK as u64),
            "input size ({len}) is not a nonzero multiple of the FEC block size ({BLOCK})"
        );
        let blocks = len / BLOCK as u64;
        ensure!(blocks <= MAX_BLOCKS, "input is too large");
        let rsn = (255 - roots) as u64;
        Ok(Shape {
            roots,
            blocks,
            rounds: blocks.div_ceil(rsn),
        })
    }

    pub fn rsn(&self) -> usize {
        255 - self.roots
    }

    /// Bytes of parity (without the trailing header block).
    pub fn parity_len(&self) -> u64 {
        self.rounds * self.roots as u64 * BLOCK as u64
    }

    /// Size of the whole FEC file: the parity and the header block.
    pub fn file_len(&self) -> u64 {
        self.parity_len() + BLOCK as u64
    }

    /// Block of the input holding codeword symbol `k` of round `i` (`None` past the data: zeros).
    fn source_block(&self, i: u64, k: usize) -> Option<u64> {
        let b = i + k as u64 * self.rounds;
        (b < self.blocks).then_some(b)
    }
}

fn read_block(f: &mut File, block: u64, buf: &mut [u8; BLOCK]) -> Result<()> {
    f.seek(SeekFrom::Start(block * BLOCK as u64))?;
    f.read_exact(buf).context("input ends early")?;
    Ok(())
}

/// The parity of round `i`: `roots * 4096` bytes, laid out `j * roots + m`.
fn round_parity(
    gf: &Gf,
    tabs: &[[u8; 256]],
    f: &mut File,
    shape: &Shape,
    i: u64,
) -> Result<Vec<u8>> {
    let roots = shape.roots;
    let mut par = vec![[0u8; BLOCK]; roots];
    let mut buf = [0u8; BLOCK];
    let _ = gf;
    for k in 0..shape.rsn() {
        match shape.source_block(i, k) {
            Some(b) => read_block(f, b, &mut buf)?,
            None => buf = [0u8; BLOCK],
        }
        for j in 0..BLOCK {
            let fb = usize::from(buf[j] ^ par[0][j]);
            for m in 0..roots - 1 {
                par[m][j] = par[m + 1][j] ^ tabs[m][fb];
            }
            par[roots - 1][j] = tabs[roots - 1][fb];
        }
    }
    let mut out = vec![0u8; roots * BLOCK];
    for j in 0..BLOCK {
        for m in 0..roots {
            out[j * roots + m] = par[m][j];
        }
    }
    Ok(out)
}

fn tables(gf: &Gf, roots: usize) -> Vec<[u8; 256]> {
    gf.generator(roots).iter().map(|&c| gf.table(c)).collect()
}

fn header(shape: &Shape, input_len: u64, parity_hash: &[u8]) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    h[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    h[8..12].copy_from_slice(&(HEADER as u32).to_le_bytes());
    h[12..16].copy_from_slice(&(shape.roots as u32).to_le_bytes());
    h[16..20].copy_from_slice(&(shape.parity_len() as u32).to_le_bytes());
    h[20..28].copy_from_slice(&input_len.to_le_bytes());
    h[28..60].copy_from_slice(parity_hash);
    h
}

/// Write the FEC file for `input` to `out` (parity, then the header block).
pub fn generate(input: &Path, out: &mut impl Write, roots: usize) -> Result<Shape> {
    crate::detect::refuse_blocking_file(input)?;
    let mut f = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    let len = f.metadata()?.len();
    let shape = Shape::new(len, roots)?;
    ensure!(
        shape.parity_len() <= u64::from(u32::MAX),
        "the parity would not fit the header's 32-bit size"
    );
    let gf = Gf::new();
    let tabs = tables(&gf, roots);
    let mut hash = Sha256::new();
    for i in 0..shape.rounds {
        let p = round_parity(&gf, &tabs, &mut f, &shape, i)?;
        hash.update(&p);
        out.write_all(&p)?;
    }
    let mut last = vec![0u8; BLOCK];
    let h = header(&shape, len, &hash.finalize());
    last[..HEADER].copy_from_slice(&h);
    last[BLOCK - HEADER..].copy_from_slice(&h);
    out.write_all(&last)?;
    Ok(shape)
}

/// The header of a FEC file, checked against its size.
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub roots: usize,
    pub fec_size: u64,
    pub input_size: u64,
    pub hash: Vec<u8>,
}

fn read_header(fec: &mut File) -> Result<Header> {
    let len = fec.metadata()?.len();
    ensure!(
        len >= BLOCK as u64 && len % BLOCK as u64 == 0,
        "the FEC file is not a whole number of blocks"
    );
    let mut h = [0u8; HEADER];
    fec.seek(SeekFrom::Start(len - HEADER as u64))?;
    fec.read_exact(&mut h)?;
    let u32at = |at: usize| u32::from_le_bytes(h[at..at + 4].try_into().unwrap());
    ensure!(u32at(0) == MAGIC, "the FEC file has no header (bad magic)");
    ensure!(
        u32at(4) == 0 && u32at(8) as usize == HEADER,
        "unsupported FEC header version or size"
    );
    let hd = Header {
        roots: u32at(12) as usize,
        fec_size: u64::from(u32at(16)),
        input_size: u64::from_le_bytes(h[20..28].try_into().unwrap()),
        hash: h[28..].to_vec(),
    };
    let shape = Shape::new(hd.input_size, hd.roots)
        .context("the FEC header describes an impossible code")?;
    ensure!(
        hd.fec_size == shape.parity_len() && len == shape.file_len(),
        "the FEC file size does not match its header"
    );
    Ok(hd)
}

/// Outcome of checking or repairing a file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub roots: usize,
    pub blocks: u64,
    pub rounds: u64,
    /// The parity in the FEC file hashes to the header's SHA-256.
    pub fec_intact: bool,
    /// Codewords with at least one wrong byte (data or parity).
    pub bad_codewords: u64,
    /// Data bytes corrected (repair only).
    pub corrected_bytes: u64,
    /// Codewords with more errors than the code can correct.
    pub uncorrectable: u64,
}

impl Report {
    pub fn clean(&self) -> bool {
        self.fec_intact && self.bad_codewords == 0
    }
}

fn load(input: &Path, fec: &Path) -> Result<(File, File, Header, Shape)> {
    crate::detect::refuse_blocking_file(input)?;
    crate::detect::refuse_blocking_file(fec)?;
    let f = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    let mut g = File::open(fec).with_context(|| format!("opening {}", fec.display()))?;
    let hd = read_header(&mut g)?;
    let len = f.metadata()?.len();
    ensure!(
        len == hd.input_size,
        "the input is {len} bytes, the FEC data was made for {}",
        hd.input_size
    );
    let shape = Shape::new(len, hd.roots)?;
    Ok((f, g, hd, shape))
}

fn parity_hash(g: &mut File, shape: &Shape) -> Result<Vec<u8>> {
    g.seek(SeekFrom::Start(0))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut left = shape.parity_len();
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        g.read_exact(&mut buf[..n])?;
        h.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(h.finalize().to_vec())
}

/// Check `input` against `fec`: every codeword's parity must be what the data produces.
pub fn verify(input: &Path, fec: &Path) -> Result<Report> {
    let (mut f, mut g, hd, shape) = load(input, fec)?;
    let gf = Gf::new();
    let tabs = tables(&gf, shape.roots);
    let mut rep = Report {
        roots: shape.roots,
        blocks: shape.blocks,
        rounds: shape.rounds,
        ..Default::default()
    };
    rep.fec_intact = parity_hash(&mut g, &shape)? == hd.hash;
    let mut stored = vec![0u8; shape.roots * BLOCK];
    for i in 0..shape.rounds {
        let want = round_parity(&gf, &tabs, &mut f, &shape, i)?;
        g.seek(SeekFrom::Start(i * (shape.roots * BLOCK) as u64))?;
        g.read_exact(&mut stored)?;
        rep.bad_codewords += (0..BLOCK)
            .filter(|&j| {
                want[j * shape.roots..(j + 1) * shape.roots]
                    != stored[j * shape.roots..(j + 1) * shape.roots]
            })
            .count() as u64;
    }
    Ok(rep)
}

/// Correct `cw` (255 symbols, data then parity) in place. `Ok(n)` is the number of symbols
/// changed; `Err` means the codeword has more errors than the code can fix.
fn correct(gf: &Gf, cw: &mut [u8; 255], roots: usize) -> Result<usize, ()> {
    // syndromes S_t = c(alpha^t), c(x) = sum cw[p] x^(254 - p)
    let mut syn = vec![0u8; roots];
    for (t, s) in syn.iter_mut().enumerate() {
        let a = gf.exp[t];
        for &c in cw.iter() {
            *s = gf.mul(*s, a) ^ c;
        }
    }
    if syn.iter().all(|&s| s == 0) {
        return Ok(0);
    }
    // Berlekamp-Massey: error locator lambda(x), lowest degree first
    let (mut lambda, mut prev) = (vec![1u8], vec![1u8]);
    let (mut l, mut m, mut b) = (0usize, 1usize, 1u8);
    for n in 0..roots {
        let mut d = syn[n];
        for i in 1..=l {
            if let Some(&c) = lambda.get(i) {
                d ^= gf.mul(c, syn[n - i]);
            }
        }
        if d == 0 {
            m += 1;
        } else if 2 * l <= n {
            let t = lambda.clone();
            let scale = gf.mul(d, gf.inv(b));
            if lambda.len() < prev.len() + m {
                lambda.resize(prev.len() + m, 0);
            }
            for (i, &p) in prev.iter().enumerate() {
                lambda[i + m] ^= gf.mul(scale, p);
            }
            l = n + 1 - l;
            prev = t;
            b = d;
            m = 1;
        } else {
            let scale = gf.mul(d, gf.inv(b));
            if lambda.len() < prev.len() + m {
                lambda.resize(prev.len() + m, 0);
            }
            for (i, &p) in prev.iter().enumerate() {
                lambda[i + m] ^= gf.mul(scale, p);
            }
            m += 1;
        }
    }
    while lambda.last() == Some(&0) {
        lambda.pop();
    }
    let deg = lambda.len() - 1;
    if deg == 0 || deg > roots / 2 {
        return Err(());
    }
    // error positions: symbol p has locator X = alpha^(254 - p); lambda(X^-1) = 0
    let eval = |poly: &[u8], x: u8| poly.iter().rev().fold(0u8, |acc, &c| gf.mul(acc, x) ^ c);
    let mut found = Vec::new();
    for p in 0..255usize {
        let xinv = gf.exp[(255 - (254 - p)) % 255];
        if eval(&lambda, xinv) == 0 {
            found.push(p);
        }
    }
    if found.len() != deg {
        return Err(());
    }
    // omega(x) = S(x) lambda(x) mod x^roots
    let mut omega = vec![0u8; roots];
    for (i, o) in omega.iter_mut().enumerate() {
        for j in 0..=i.min(deg) {
            *o ^= gf.mul(lambda[j], syn[i - j]);
        }
    }
    // formal derivative of lambda (characteristic 2: only odd terms survive)
    let dl: Vec<u8> = (1..lambda.len())
        .map(|i| if i % 2 == 1 { lambda[i] } else { 0 })
        .collect();
    let mut fixed = *cw;
    for &p in &found {
        let x = gf.exp[254 - p];
        let xinv = gf.inv(x);
        let denom = eval(&dl, xinv);
        if denom == 0 {
            return Err(());
        }
        // first consecutive root 0: e = X * omega(X^-1) / lambda'(X^-1)
        let e = gf.mul(gf.mul(x, eval(&omega, xinv)), gf.inv(denom));
        fixed[p] ^= e;
    }
    // accept only a codeword whose syndromes are now all zero
    for t in 0..roots {
        let a = gf.exp[t];
        let s = fixed.iter().fold(0u8, |acc, &c| gf.mul(acc, a) ^ c);
        if s != 0 {
            return Err(());
        }
    }
    let changed = found.len();
    *cw = fixed;
    Ok(changed)
}

/// Repair `input` using `fec`, writing the corrected copy to `out` (created exclusively; the
/// caller renames it into place). Corrects up to `roots / 2` wrong bytes per codeword.
pub fn repair(input: &Path, fec: &Path, out: &mut File) -> Result<Report> {
    let (mut f, mut g, hd, shape) = load(input, fec)?;
    let gf = Gf::new();
    let roots = shape.roots;
    let mut rep = Report {
        roots,
        blocks: shape.blocks,
        rounds: shape.rounds,
        ..Default::default()
    };
    rep.fec_intact = parity_hash(&mut g, &shape)? == hd.hash;
    f.seek(SeekFrom::Start(0))?;
    std::io::copy(&mut f, out).context("copying the input")?;
    let rsn = shape.rsn();
    let mut data = vec![vec![0u8; BLOCK]; rsn];
    let mut parity = vec![0u8; roots * BLOCK];
    let mut buf = [0u8; BLOCK];
    for i in 0..shape.rounds {
        for (k, block) in data.iter_mut().enumerate() {
            match shape.source_block(i, k) {
                Some(b) => {
                    read_block(&mut f, b, &mut buf)?;
                    block.copy_from_slice(&buf);
                }
                None => block.fill(0),
            }
        }
        g.seek(SeekFrom::Start(i * (roots * BLOCK) as u64))?;
        g.read_exact(&mut parity)?;
        let mut touched = vec![false; rsn];
        for j in 0..BLOCK {
            let mut cw = [0u8; 255];
            for k in 0..rsn {
                cw[k] = data[k][j];
            }
            cw[rsn..rsn + roots].copy_from_slice(&parity[j * roots..(j + 1) * roots]);
            let orig = cw;
            match correct(&gf, &mut cw, roots) {
                Ok(0) => {}
                Ok(_) => {
                    rep.bad_codewords += 1;
                    for k in 0..rsn {
                        if cw[k] != orig[k] {
                            data[k][j] = cw[k];
                            touched[k] = true;
                            rep.corrected_bytes += 1;
                        }
                    }
                }
                Err(()) => {
                    rep.bad_codewords += 1;
                    rep.uncorrectable += 1;
                }
            }
        }
        for k in 0..rsn {
            if touched[k]
                && let Some(b) = shape.source_block(i, k)
            {
                out.seek(SeekFrom::Start(b * BLOCK as u64))?;
                out.write_all(&data[k])?;
            }
        }
    }
    out.flush()?;
    if hd.roots == 0 {
        bail!("unreachable");
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;

    /// Deterministic input; the same formula generated the reference files below.
    fn data(blocks: usize) -> Vec<u8> {
        (0..blocks as u64 * BLOCK as u64)
            .map(|o| ((o.wrapping_mul(2654435761).wrapping_add((o >> 12) * 40503)) >> 5) as u8)
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn fec_of(
        d: &Scratch,
        name: &str,
        input: &[u8],
        roots: usize,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let (inp, fec) = (d.join(format!("{name}.bin")), d.join(format!("{name}.fec")));
        std::fs::write(&inp, input).unwrap();
        let mut out = std::fs::File::create(&fec).unwrap();
        generate(&inp, &mut out, roots).unwrap();
        (inp, fec)
    }

    /// SHA-256 of the FEC files that `avbroot fec generate -p <roots>` (AOSP's header format)
    /// wrote for the same inputs: parity layout, interleaving and the header are byte-identical.
    #[test]
    fn generated_fec_equals_avbroots_byte_for_byte() {
        let d = Scratch::new("fec-ref");
        for (blocks, roots, want) in [
            (
                10,
                2,
                "9f1d30ffa5879beb64fd0c8f5a3992e2aaea5744f85d184ee252aa2ab77339a3",
            ),
            (
                300,
                2,
                "38f3f45eff2e42a21be3c062f0651100594e9099f2294248d554fe43e708522e",
            ),
            (
                253,
                24,
                "17679a5bd930d0429742fc3318da8bd7fd2b296023276f20a09a35fb45fdd788",
            ),
            (
                600,
                6,
                "1ea2e8281c201909e1c568050ec4a08ef8d7ebb25800156a8f6480a590c2ca5e",
            ),
        ] {
            let (_, fec) = fec_of(&d, &format!("r{blocks}-{roots}"), &data(blocks), roots);
            let got = Sha256::digest(std::fs::read(fec).unwrap());
            assert_eq!(hex(&got), want, "{blocks} blocks, {roots} roots");
        }
    }

    #[test]
    fn verify_accepts_the_intact_file_and_flags_damage() {
        let d = Scratch::new("fec-verify");
        let (inp, fec) = fec_of(&d, "v", &data(300), 2);
        let r = verify(&inp, &fec).unwrap();
        assert!(r.clean() && r.rounds == 2 && r.blocks == 300, "{r:?}");
        let mut bad = data(300);
        bad[5 * BLOCK + 9] ^= 0x40;
        std::fs::write(&inp, &bad).unwrap();
        let r = verify(&inp, &fec).unwrap();
        assert!(!r.clean() && r.bad_codewords == 1 && r.fec_intact, "{r:?}");
        // a different size than the FEC data was made for is refused
        std::fs::write(&inp, &bad[..BLOCK * 299]).unwrap();
        assert!(
            verify(&inp, &fec)
                .unwrap_err()
                .to_string()
                .contains("made for")
        );
    }

    #[test]
    fn repair_fixes_up_to_half_the_parity_bytes_per_codeword() {
        let d = Scratch::new("fec-repair");
        for roots in [2usize, 6, 24] {
            let orig = data(300);
            let (inp, fec) = fec_of(&d, &format!("p{roots}"), &orig, roots);
            let shape = Shape::new(orig.len() as u64, roots).unwrap();
            // roots/2 wrong bytes in each of several codewords (same round and byte, other blocks)
            let mut bad = orig.clone();
            let mut hits = 0;
            for (i, j) in [(0u64, 0usize), (1, 17), (0, 4095), (1, 2048)] {
                for k in 0..roots / 2 {
                    if let Some(b) = shape.source_block(i, k * 7 + 1) {
                        bad[b as usize * BLOCK + j] ^= 0x5a + k as u8;
                        hits += 1;
                    }
                }
            }
            std::fs::write(&inp, &bad).unwrap();
            let out = d.join(format!("p{roots}.fixed"));
            let mut f = std::fs::File::create(&out).unwrap();
            let r = repair(&inp, &fec, &mut f).unwrap();
            assert_eq!(
                (r.uncorrectable, r.corrected_bytes),
                (0, hits),
                "roots {roots}: {r:?}"
            );
            assert!(
                std::fs::read(&out).unwrap() == orig,
                "roots {roots}: not restored"
            );
        }
    }

    #[test]
    fn more_errors_than_the_code_corrects_are_counted_not_guessed() {
        let d = Scratch::new("fec-too-many");
        let orig = data(20);
        let (inp, fec) = fec_of(&d, "t", &orig, 2);
        let mut bad = orig.clone();
        bad[3] ^= 1; // two wrong bytes in one codeword (blocks 0 and 1, byte 3): roots/2 = 1
        bad[BLOCK + 3] ^= 1;
        std::fs::write(&inp, &bad).unwrap();
        let mut f = std::fs::File::create(d.join("t.fixed")).unwrap();
        let r = repair(&inp, &fec, &mut f).unwrap();
        assert_eq!(r.uncorrectable, 1, "{r:?}");
        assert_eq!(
            r.corrected_bytes, 0,
            "an uncorrectable codeword must be left as it was"
        );
    }

    #[test]
    fn bad_inputs_are_refused_cleanly() {
        let d = Scratch::new("fec-bad");
        let (inp, fec) = fec_of(&d, "b", &data(10), 2);
        let junk = d.join("junk.fec");
        std::fs::write(&junk, vec![7u8; BLOCK * 3]).unwrap();
        assert!(verify(&inp, &junk).is_err());
        std::fs::write(d.join("odd.bin"), vec![1u8; 4097]).unwrap();
        let mut sink = Vec::new();
        assert!(generate(&d.join("odd.bin"), &mut sink, 2).is_err());
        assert!(generate(&inp, &mut sink, 1).is_err() && generate(&inp, &mut sink, 25).is_err());
        std::fs::write(d.join("empty.bin"), b"").unwrap();
        assert!(generate(&d.join("empty.bin"), &mut sink, 2).is_err());
        // every truncation and a flipped header byte of a real FEC file
        let good = std::fs::read(&fec).unwrap();
        for cut in (0..good.len()).step_by(997) {
            std::fs::write(&junk, &good[..cut]).unwrap();
            let _ = verify(&inp, &junk);
        }
        for at in (good.len() - HEADER..good.len()).step_by(3) {
            let mut v = good.clone();
            v[at] ^= 0xff;
            std::fs::write(&junk, &v).unwrap();
            let _ = verify(&inp, &junk);
        }
    }
}
