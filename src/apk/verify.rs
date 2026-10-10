//! Cryptographic verification of APK signatures: v1 (JAR: MANIFEST.MF / .SF / PKCS#7 block),
//! v2, v3 and v3.1 (signing block: content digests and signatures), plus v4 (`.idsig`) detection.
//!
//! The same checks `apksigner verify` makes, from the AOSP definitions (Apache-2.0). Nothing is
//! executed. A scheme that cannot be judged (unknown algorithm, unsupported curve) is reported as
//! `NotChecked`, never as verified.

use super::*;
use p256::ecdsa::{Signature as EcSig, VerifyingKey, signature::hazmat::PrehashVerifier};
use rsa::BigUint;
use sha1::Sha1;
use sha2::{Sha384, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Invalid,
    NotChecked,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Invalid => "invalid",
            Verdict::NotChecked => "not-checked",
        }
    }
}

/// The outcome for one signature scheme ("v1", "v2", "v3", "v3.1", "v4").
#[derive(Debug, Clone, PartialEq)]
pub struct SchemeCheck {
    pub scheme: &'static str,
    pub verdict: Verdict,
    pub detail: String,
    /// v3 signer SDK range.
    pub min_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
}

fn check(scheme: &'static str, verdict: Verdict, detail: impl Into<String>) -> SchemeCheck {
    SchemeCheck {
        scheme,
        verdict,
        detail: detail.into(),
        min_sdk: None,
        max_sdk: None,
    }
}

// --- Hashes ---

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

enum Hasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(h: Hash) -> Self {
        match h {
            Hash::Sha1 => Hasher::Sha1(Sha1::new()),
            Hash::Sha256 => Hasher::Sha256(Sha256::new()),
            Hash::Sha384 => Hasher::Sha384(Sha384::new()),
            Hash::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
    fn update(&mut self, d: &[u8]) {
        match self {
            Hasher::Sha1(x) => x.update(d),
            Hasher::Sha256(x) => x.update(d),
            Hasher::Sha384(x) => x.update(d),
            Hasher::Sha512(x) => x.update(d),
        }
    }
    fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Sha1(x) => x.finalize().iter().copied().collect(),
            Hasher::Sha256(x) => x.finalize().iter().copied().collect(),
            Hasher::Sha384(x) => x.finalize().iter().copied().collect(),
            Hasher::Sha512(x) => x.finalize().iter().copied().collect(),
        }
    }
}

impl Hash {
    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        let mut h = Hasher::new(self);
        for p in parts {
            h.update(p);
        }
        h.finish()
    }
    fn len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }
    /// The DER DigestInfo prefix of a PKCS#1 v1.5 signature (RFC 8017 section 9.2).
    fn prefix(self) -> &'static [u8] {
        match self {
            Hash::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            Hash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Hash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Hash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
    fn from_digest_oid(oid: &[u8]) -> Option<Hash> {
        Some(match oid {
            [0x2b, 0x0e, 0x03, 0x02, 0x1a] => Hash::Sha1,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Hash::Sha256,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Hash::Sha384,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Hash::Sha512,
            _ => return None,
        })
    }
}

// --- Public keys and raw signature checks ---

enum Key {
    Rsa {
        n: BigUint,
        e: BigUint,
    },
    Ec(Vec<u8>),
    Dsa {
        p: BigUint,
        q: BigUint,
        g: BigUint,
        y: BigUint,
    },
    Other(&'static str),
}

#[derive(Clone, Copy)]
enum Alg {
    Pkcs1(Hash),
    Pss(Hash),
    Ecdsa(Hash),
    Dsa(Hash),
}

/// The raw DER elements (header included) directly inside `data`.
fn kids(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let Ok((_, n)) = der_one(&data[at..]) else {
            break;
        };
        out.push(&data[at..at + n]);
        at += n;
    }
    out
}

fn payload(raw: &[u8]) -> &[u8] {
    der_one(raw).map_or(&[], |(d, _)| d.payload)
}

fn big(raw_int: &[u8]) -> BigUint {
    BigUint::from_bytes_be(payload(raw_int))
}

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_DSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];

/// Parse a SubjectPublicKeyInfo. `None` means malformed.
fn parse_spki(spki: &[u8]) -> Option<Key> {
    let (seq, _) = der_one(spki).ok()?;
    if seq.tag != 0x30 {
        return None;
    }
    let k = kids(seq.payload);
    let (alg, bits) = (k.first()?, k.get(1)?);
    let bits = der_one(bits).ok()?.0;
    if bits.tag != 0x03 || bits.payload.is_empty() {
        return None;
    }
    let key = &bits.payload[1..];
    let ak = kids(payload(alg));
    let oid = payload(ak.first()?);
    Some(match oid {
        OID_RSA => {
            let seq = der_one(key).ok()?.0;
            let f = kids(seq.payload);
            let (n, e) = (big(f.first()?), big(f.get(1)?));
            if n.bits() > 8192 || e.bits() > 64 {
                Key::Other("RSA key too large to verify")
            } else {
                Key::Rsa { n, e }
            }
        }
        OID_EC => {
            if payload(ak.get(1)?) == OID_P256 {
                Key::Ec(key.to_vec())
            } else {
                Key::Other("EC curve other than P-256")
            }
        }
        OID_DSA => {
            let f = kids(payload(ak.get(1)?));
            let (p, q, g) = (big(f.first()?), big(f.get(1)?), big(f.get(2)?));
            let y = big(der_one(key).ok().map(|_| key)?);
            if p.bits() > 4096 || q.bits() > 512 {
                Key::Other("DSA key too large to verify")
            } else {
                Key::Dsa { p, q, g, y }
            }
        }
        _ => Key::Other("unknown public key algorithm"),
    })
}

/// `sig^e mod n` as exactly `k` bytes (k = modulus length), or None if out of range.
fn rsa_raw(n: &BigUint, e: &BigUint, sig: &[u8]) -> Option<Vec<u8>> {
    let k = n.bits().div_ceil(8);
    if sig.len() != k {
        return None;
    }
    let s = BigUint::from_bytes_be(sig);
    if &s >= n {
        return None;
    }
    let m = s.modpow(e, n).to_bytes_be();
    let mut out = vec![0u8; k.checked_sub(m.len())?];
    out.extend(m);
    Some(out)
}

fn mgf1(seed: &[u8], len: usize, h: Hash) -> Vec<u8> {
    let mut out = Vec::new();
    let mut c = 0u32;
    while out.len() < len {
        out.extend(h.digest(&[seed, &c.to_be_bytes()]));
        c += 1;
    }
    out.truncate(len);
    out
}

fn pss_ok(n: &BigUint, e: &BigUint, h: Hash, msg: &[u8], sig: &[u8]) -> Option<bool> {
    let em_bits = n.bits() - 1;
    let em_len = em_bits.div_ceil(8);
    let full = rsa_raw(n, e, sig)?;
    let (lead, em) = full.split_at(full.len().checked_sub(em_len)?);
    if lead.iter().any(|&b| b != 0) {
        return Some(false);
    }
    let (hl, sl) = (h.len(), h.len()); // Android: salt length equals the digest length
    if em_len < hl + sl + 2 || em[em_len - 1] != 0xbc {
        return Some(false);
    }
    let masked = &em[..em_len - hl - 1];
    let hash = &em[em_len - hl - 1..em_len - 1];
    let mut db: Vec<u8> = masked
        .iter()
        .zip(mgf1(hash, masked.len(), h))
        .map(|(a, b)| a ^ b)
        .collect();
    db[0] &= 0xffu8 >> (8 * em_len - em_bits);
    let split = em_len - hl - sl - 2;
    if db[..split].iter().any(|&b| b != 0) || db[split] != 1 {
        return Some(false);
    }
    let salt = &db[split + 1..];
    let m_hash = h.digest(&[msg]);
    Some(h.digest(&[&[0u8; 8], &m_hash, salt]) == hash)
}

fn dsa_ok(
    key: (&BigUint, &BigUint, &BigUint, &BigUint),
    h: Hash,
    msg: &[u8],
    sig: &[u8],
) -> Option<bool> {
    let (p, q, g, y) = key;
    let seq = der_one(sig).ok()?.0;
    let f = kids(seq.payload);
    let (r, s) = (big(f.first()?), big(f.get(1)?));
    let zero = BigUint::from(0u8);
    if r == zero || s == zero || &r >= q || &s >= q {
        return Some(false);
    }
    let d = h.digest(&[msg]);
    let qb = q.bits();
    let mut z = BigUint::from_bytes_be(&d);
    if d.len() * 8 > qb {
        z >>= d.len() * 8 - qb;
    }
    let two = BigUint::from(2u8);
    let w = s.modpow(&(q - &two), q); // q is prime
    let u1 = (&z * &w) % q;
    let u2 = (&r * &w) % q;
    let v = ((g.modpow(&u1, p) * y.modpow(&u2, p)) % p) % q;
    Some(v == r)
}

fn verify_sig(key: &Key, alg: Alg, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let bad = || "signature does not verify".to_string();
    match (key, alg) {
        (Key::Other(why), _) => Err(format!("not checked: {why}")),
        (Key::Rsa { n, e }, Alg::Pkcs1(h)) => {
            let em = rsa_raw(n, e, sig).ok_or_else(bad)?;
            let mut want = vec![0u8, 1];
            let t = [h.prefix(), &h.digest(&[msg])].concat();
            want.resize(em.len().checked_sub(t.len() + 1).ok_or_else(bad)?, 0xff);
            want.push(0);
            want.extend(t);
            if want == em { Ok(()) } else { Err(bad()) }
        }
        (Key::Rsa { n, e }, Alg::Pss(h)) => match pss_ok(n, e, h, msg, sig) {
            Some(true) => Ok(()),
            _ => Err(bad()),
        },
        (Key::Ec(point), Alg::Ecdsa(h)) => {
            let vk =
                VerifyingKey::from_sec1_bytes(point).map_err(|_| "bad EC point".to_string())?;
            let s = EcSig::from_der(sig).map_err(|_| bad())?;
            vk.verify_prehash(&h.digest(&[msg]), &s).map_err(|_| bad())
        }
        (Key::Dsa { p, q, g, y }, Alg::Dsa(h)) => match dsa_ok((p, q, g, y), h, msg, sig) {
            Some(true) => Ok(()),
            _ => Err(bad()),
        },
        _ => Err("signature algorithm does not match the public key type".into()),
    }
}

// --- Certificates ---

/// (serial raw INTEGER, SubjectPublicKeyInfo raw) of a full DER certificate.
fn cert_serial_spki(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let c = der_one(cert).ok()?.0;
    let tbs = der_one(kids(c.payload).first()?).ok()?.0;
    let t = kids(tbs.payload);
    let i = usize::from(t.first()?.first() == Some(&0xa0));
    Some((payload(t.get(i)?), t.get(i + 5)?))
}

// --- v2 / v3 / v3.1 ---

const V31_BLOCK_ID: u32 = 0x1b93ad61;

/// (algorithm, how to verify, is a verity-digest variant)
fn sig_alg(id: u32) -> Option<(Alg, bool)> {
    use Hash::*;
    Some(match id {
        0x0101 => (Alg::Pss(Sha256), false),
        0x0102 => (Alg::Pss(Sha512), false),
        0x0103 => (Alg::Pkcs1(Sha256), false),
        0x0104 => (Alg::Pkcs1(Sha512), false),
        0x0201 => (Alg::Ecdsa(Sha256), false),
        0x0202 => (Alg::Ecdsa(Sha512), false),
        0x0301 => (Alg::Dsa(Sha256), false),
        0x0421 => (Alg::Pkcs1(Sha256), true),
        0x0423 => (Alg::Ecdsa(Sha256), true),
        0x0425 => (Alg::Dsa(Sha256), true),
        _ => return None,
    })
}

fn alg_hash(a: Alg) -> Hash {
    match a {
        Alg::Pkcs1(h) | Alg::Pss(h) | Alg::Ecdsa(h) | Alg::Dsa(h) => h,
    }
}

struct Located<'a> {
    bytes: &'a [u8],
    start: usize,
    cd_off: usize,
    eocd: usize,
    cache: Vec<(Hash, Vec<u8>)>,
}

impl Located<'_> {
    /// The v2 content digest: a SHA tree over 1 MiB chunks of the entries, the central directory
    /// and the EOCD (whose central-directory offset is taken to be the signing block start).
    fn content_digest(&mut self, h: Hash) -> Vec<u8> {
        if let Some((_, d)) = self.cache.iter().find(|(x, _)| *x == h) {
            return d.clone();
        }
        let mut eocd = self.bytes[self.eocd..].to_vec();
        eocd[16..20].copy_from_slice(&(self.start as u32).to_le_bytes());
        let sections: [&[u8]; 3] = [
            &self.bytes[..self.start],
            &self.bytes[self.cd_off..self.eocd],
            &eocd,
        ];
        let (mut all, mut count) = (Vec::new(), 0u32);
        for s in sections {
            for chunk in s.chunks(1 << 20) {
                all.extend(h.digest(&[&[0xa5], &(chunk.len() as u32).to_le_bytes(), chunk]));
                count += 1;
            }
        }
        let d = h.digest(&[&[0x5a], &count.to_le_bytes(), &all]);
        self.cache.push((h, d.clone()));
        d
    }
}

type Pairs<'a> = Vec<(u32, &'a [u8])>;

/// `(algorithm id, bytes)` items of a length-prefixed sequence of length-prefixed
/// `u32 id | u32 len | bytes` records.
fn id_records(seq: &[u8]) -> Option<Vec<(u32, &[u8])>> {
    let (mut at, mut out) = (0, Vec::new());
    while at < seq.len() {
        let rec = lp(seq, &mut at)?;
        let mut r = 4;
        out.push((le32(rec, 0).ok()?, lp(rec, &mut r)?));
    }
    Some(out)
}

/// Verify one v2/v3 signer. Ok(range) when verified, Err((verdict, why)) otherwise.
fn verify_signer(
    signer: &[u8],
    v3: bool,
    loc: &mut Located,
) -> Result<(Option<u32>, Option<u32>), (Verdict, String)> {
    let mal = || (Verdict::Invalid, "malformed signer".to_string());
    let mut at = 0;
    let signed = lp(signer, &mut at).ok_or_else(mal)?;
    let (outer_sdk, sigs) = if v3 {
        let (a, b) = (
            le32(signer, at).map_err(|_| mal())?,
            le32(signer, at + 4).map_err(|_| mal())?,
        );
        at += 8;
        (Some((a, b)), lp(signer, &mut at).ok_or_else(mal)?)
    } else {
        (None, lp(signer, &mut at).ok_or_else(mal)?)
    };
    let pubkey = lp(signer, &mut at).ok_or_else(mal)?;
    let mut s = 0;
    let digests = id_records(lp(signed, &mut s).ok_or_else(mal)?).ok_or_else(mal)?;
    let certs = lp(signed, &mut s).ok_or_else(mal)?;
    let range = if v3 {
        let (a, b) = (
            le32(signed, s).map_err(|_| mal())?,
            le32(signed, s + 4).map_err(|_| mal())?,
        );
        if outer_sdk != Some((a, b)) {
            return Err((
                Verdict::Invalid,
                "SDK range differs between signed and unsigned data".into(),
            ));
        }
        (Some(a), Some(b))
    } else {
        (None, None)
    };
    let cert = lp(certs, &mut 0).ok_or_else(mal)?;
    match cert_serial_spki(cert) {
        Some((_, spki)) if spki == pubkey => {}
        _ => {
            return Err((
                Verdict::Invalid,
                "public key does not match the signer certificate".into(),
            ));
        }
    }
    let key = parse_spki(pubkey).ok_or_else(mal)?;
    let sigs = id_records(sigs).ok_or_else(mal)?;
    let mut checked = Vec::new();
    for (id, sig) in &sigs {
        let Some((alg, verity)) = sig_alg(*id) else {
            continue; // unknown algorithm: ignored, as the platform does
        };
        match verify_sig(&key, alg, signed, sig) {
            Ok(()) => {}
            Err(e) if e.starts_with("not checked") => return Err((Verdict::NotChecked, e)),
            Err(e) => return Err((Verdict::Invalid, format!("algorithm 0x{id:04x}: {e}"))),
        }
        if !verity {
            checked.push((*id, alg_hash(alg)));
        }
    }
    if checked.is_empty() {
        return Err((
            Verdict::NotChecked,
            "no supported signature algorithm".into(),
        ));
    }
    for (id, h) in checked {
        let Some((_, want)) = digests.iter().find(|(d, _)| *d == id) else {
            return Err((
                Verdict::Invalid,
                format!("no digest for signature algorithm 0x{id:04x}"),
            ));
        };
        if *want != loc.content_digest(h).as_slice() {
            return Err((
                Verdict::Invalid,
                "content digest mismatch: the APK was modified after it was signed".into(),
            ));
        }
    }
    Ok(range)
}

fn verify_blocks(bytes: &[u8]) -> Vec<SchemeCheck> {
    let Some(b) = locate_block(bytes) else {
        return Vec::new();
    };
    let mut loc = Located {
        bytes,
        start: b.start,
        cd_off: b.cd_off,
        eocd: b.eocd,
        cache: Vec::new(),
    };
    let pairs: Pairs = b.pairs;
    let mut out = Vec::new();
    for (id, name, v3) in [
        (V2_BLOCK_ID, "v2", false),
        (V3_BLOCK_ID, "v3", true),
        (V31_BLOCK_ID, "v3.1", true),
    ] {
        let Some((_, value)) = pairs.iter().find(|(i, _)| *i == id) else {
            continue;
        };
        let mut c = check(name, Verdict::Verified, "digests and signatures verify");
        let Some(seq) = lp(value, &mut 0) else {
            out.push(check(name, Verdict::Invalid, "malformed signing block"));
            continue;
        };
        let (mut at, mut n) = (0, 0);
        while let Some(signer) = lp(seq, &mut at) {
            n += 1;
            match verify_signer(signer, v3, &mut loc) {
                Ok((lo, hi)) => {
                    c.min_sdk = c.min_sdk.or(lo);
                    c.max_sdk = c.max_sdk.or(hi);
                }
                Err((v, why)) => {
                    c.verdict = v;
                    c.detail = why;
                    break;
                }
            }
        }
        if at != seq.len() {
            c = check(name, Verdict::Invalid, "malformed signer list");
        } else if n == 0 {
            c = check(name, Verdict::Invalid, "no signers");
        }
        out.push(c);
    }
    out
}

// --- v1 (JAR) ---

/// Total bytes we will hash across all entries of one APK.
const MAX_HASH_BYTES: u64 = 2 << 30;

struct Section<'a> {
    raw: &'a [u8],
    name: Option<String>,
    attrs: Vec<(String, String)>,
}

/// Split a MANIFEST.MF or .SF into its main section and named sections, keeping raw bytes (a
/// section digest covers them exactly, including the blank line that ends them).
fn jar_sections(data: &[u8]) -> Vec<Section<'_>> {
    let (mut out, mut start, mut at) = (Vec::new(), 0, 0);
    while start < data.len() {
        // end of section = a blank line
        let mut end = data.len();
        while at < data.len() {
            let nl = data[at..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(data.len(), |p| at + p + 1);
            let line = &data[at..nl];
            at = nl;
            if line == b"\n" || line == b"\r\n" {
                end = at;
                break;
            }
        }
        let raw = &data[start..end];
        let text = String::from_utf8_lossy(raw)
            .replace("\r\n", "\n")
            .replace("\n ", "");
        let attrs: Vec<(String, String)> = text
            .lines()
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_string(), v.trim().to_string()))
            .collect();
        let name = attrs
            .iter()
            .find(|(k, _)| k == "Name")
            .map(|(_, v)| v.clone());
        if !attrs.is_empty() {
            out.push(Section { raw, name, attrs });
        }
        start = end;
        at = end;
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(d: &[u8]) -> String {
    let mut s = String::new();
    for c in d.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            s.push(if i <= c.len() {
                B64[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    s
}

/// The strongest `<alg>-Digest<suffix>` attribute in a section: (hash, base64 value).
fn best_digest<'a>(attrs: &'a [(String, String)], suffix: &str) -> Option<(Hash, &'a str)> {
    for (label, h) in [
        ("SHA-512", Hash::Sha512),
        ("SHA-384", Hash::Sha384),
        ("SHA-256", Hash::Sha256),
        ("SHA1", Hash::Sha1),
        ("SHA-1", Hash::Sha1),
    ] {
        let key = format!("{label}-Digest{suffix}");
        if let Some((_, v)) = attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(&key)) {
            return Some((h, v));
        }
    }
    None
}

struct SignerInfo<'a> {
    serial: &'a [u8],
    digest: Option<Hash>,
    attrs: Option<&'a [u8]>,
    sig_oid: &'a [u8],
    signature: &'a [u8],
}

/// (certificates, the single SignerInfo) of a PKCS#7 SignedData block.
fn parse_p7(der: &[u8]) -> Option<(Vec<&[u8]>, SignerInfo<'_>)> {
    let ci = der_one(der).ok()?.0;
    let ck = kids(ci.payload);
    let sd = der_one(payload(ck.get(1)?)).ok()?.0;
    let f = kids(sd.payload);
    let certs = f.iter().find(|x| x[0] == 0xa0).map(|c| kids(payload(c)))?;
    let infos = kids(payload(f.iter().rev().find(|x| x[0] == 0x31)?));
    if infos.len() != 1 {
        return None;
    }
    let s = kids(payload(infos[0]));
    let sid = kids(payload(s.get(1)?));
    let digest = Hash::from_digest_oid(payload(kids(payload(s.get(2)?)).first()?));
    let mut i = 3;
    let attrs = (s.get(i)?[0] == 0xa0).then(|| {
        i += 1;
        s[i - 1]
    });
    let sig_oid = payload(kids(payload(s.get(i)?)).first()?);
    Some((
        certs,
        SignerInfo {
            serial: payload(sid.get(1)?),
            digest,
            attrs,
            sig_oid,
            signature: payload(s.get(i + 1)?),
        },
    ))
}

fn p7_alg(si: &SignerInfo) -> Option<Alg> {
    use Hash::*;
    let rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    let ec = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04];
    let o = si.sig_oid;
    let h = si.digest;
    Some(match o {
        _ if o == OID_RSA => Alg::Pkcs1(h?),
        _ if o == OID_EC => Alg::Ecdsa(h?), // the signer states only the key type
        _ if o == OID_DSA || o == [0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03] => {
            Alg::Dsa(h.or(Some(Sha1))?)
        }
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02] => Alg::Dsa(Sha256),
        _ if o.starts_with(&rsa) && o.len() == 9 => Alg::Pkcs1(match o[8] {
            5 => Sha1,
            11 => Sha256,
            12 => Sha384,
            13 => Sha512,
            _ => return None,
        }),
        _ if o.starts_with(&ec) => Alg::Ecdsa(match o {
            [.., 4, 1] => Sha1,
            [.., 4, 3, 2] => Sha256,
            [.., 4, 3, 3] => Sha384,
            [.., 4, 3, 4] => Sha512,
            _ => return None,
        }),
        _ => return None,
    })
}

type Zip<'a> = ZipArchive<Cursor<&'a [u8]>>;

fn hash_entry(zip: &mut Zip, name: &str, h: Hash, budget: &mut u64) -> Result<Vec<u8>, String> {
    let mut f = zip
        .by_name(name)
        .map_err(|_| format!("{name} is not in the APK"))?;
    let mut hs = Hasher::new(h);
    let mut buf = [0u8; 65536];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{name} is unreadable: {e}"))?;
        if n == 0 {
            return Ok(hs.finish());
        }
        *budget = budget
            .checked_sub(n as u64)
            .ok_or("APK expands beyond the verification limit")?;
        hs.update(&buf[..n]);
    }
}

fn is_sig_file(upper: &str) -> bool {
    upper.strip_prefix("META-INF/").is_some_and(|r| {
        !r.contains('/')
            && (r == "MANIFEST.MF"
                || [".SF", ".RSA", ".DSA", ".EC"]
                    .iter()
                    .any(|e| r.ends_with(e)))
    })
}

fn verify_v1(bytes: &[u8]) -> Option<(SchemeCheck, bool, bool)> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).ok()?;
    let names: Vec<String> = zip.file_names().map(String::from).collect();
    let find = |want: &str| names.iter().find(|n| n.eq_ignore_ascii_case(want)).cloned();
    let sfs: Vec<&String> = names
        .iter()
        .filter(|n| {
            n.to_ascii_uppercase().starts_with("META-INF/")
                && n.to_ascii_uppercase().ends_with(".SF")
        })
        .collect();
    if sfs.is_empty() {
        return None; // no JAR signature at all
    }
    let fail = |why: String| Some((check("v1", Verdict::Invalid, why), false, false));
    let Some(mf_name) = find("META-INF/MANIFEST.MF") else {
        return fail("META-INF/MANIFEST.MF is missing".into());
    };
    let Some(mf) = read_entry(&mut zip, &mf_name) else {
        return Some((
            check("v1", Verdict::NotChecked, "MANIFEST.MF too large to read"),
            false,
            false,
        ));
    };
    let msecs = jar_sections(&mf);
    let mut budget = MAX_HASH_BYTES;
    let (mut claims2, mut claims3) = (false, false);
    for sf_name in sfs {
        let stem = &sf_name[..sf_name.len() - 3];
        let Some(blk) = [".RSA", ".DSA", ".EC"]
            .iter()
            .find_map(|e| find(&format!("{stem}{e}")))
        else {
            return fail(format!("{sf_name} has no signature block file"));
        };
        let (Some(sf), Some(p7)) = (read_entry(&mut zip, sf_name), read_entry(&mut zip, &blk))
        else {
            return Some((
                check(
                    "v1",
                    Verdict::NotChecked,
                    "signature file too large to read",
                ),
                false,
                false,
            ));
        };
        // 1. the PKCS#7 signature over the .SF
        let Some((certs, si)) = parse_p7(&p7) else {
            return fail(format!("{blk}: malformed PKCS#7 signature"));
        };
        let Some(cert) = certs
            .iter()
            .find(|c| cert_serial_spki(c).is_some_and(|(s, _)| s == si.serial))
            .or(certs.first())
        else {
            return fail(format!("{blk}: no signer certificate"));
        };
        let Some((_, spki)) = cert_serial_spki(cert) else {
            return fail(format!("{blk}: malformed certificate"));
        };
        let Some(alg) = p7_alg(&si) else {
            return Some((
                check(
                    "v1",
                    Verdict::NotChecked,
                    format!("{blk}: unsupported signature algorithm"),
                ),
                false,
                false,
            ));
        };
        let Some(key) = parse_spki(spki) else {
            return fail(format!("{blk}: malformed public key"));
        };
        let owned;
        let signed: &[u8] = match si.attrs {
            Some(a) => {
                let want = payload_md(a);
                if want.as_deref() != Some(alg_hash(alg).digest(&[&sf]).as_slice()) {
                    return fail(format!("{blk}: messageDigest does not match {sf_name}"));
                }
                owned = [&[0x31][..], &a[1..]].concat(); // SET OF, as signed
                &owned
            }
            None => &sf,
        };
        match verify_sig(&key, alg, signed, si.signature) {
            Ok(()) => {}
            Err(e) if e.starts_with("not checked") => {
                return Some((check("v1", Verdict::NotChecked, e), false, false));
            }
            Err(e) => return fail(format!("{blk}: {e}")),
        }
        // 2. the .SF vouches for MANIFEST.MF
        let ssecs = jar_sections(&sf);
        let main = ssecs.first().map(|s| &s.attrs[..]).unwrap_or(&[]);
        if let Some((_, v)) = main.iter().find(|(k, _)| k == "X-Android-APK-Signed") {
            claims2 |= v.split(',').any(|x| x.trim() == "2");
            claims3 |= v.split(',').any(|x| x.trim() == "3");
        }
        let whole_ok =
            best_digest(main, "-Manifest").is_some_and(|(h, v)| b64(&h.digest(&[&mf])) == v);
        if !whole_ok {
            for m in msecs.iter().filter(|m| m.name.is_some()) {
                let s = ssecs.iter().find(|s| s.name == m.name);
                let ok = s
                    .and_then(|s| best_digest(&s.attrs, ""))
                    .is_some_and(|(h, v)| b64(&h.digest(&[m.raw])) == v);
                if !ok {
                    return fail(format!(
                        "{sf_name} does not match MANIFEST.MF (section {})",
                        m.name.as_deref().unwrap_or("")
                    ));
                }
            }
        }
        // 3. MANIFEST.MF vouches for every entry
        for m in msecs
            .iter()
            .filter_map(|m| Some((m.name.as_ref()?, best_digest(&m.attrs, "")?)))
        {
            let (name, (h, want)) = m;
            match hash_entry(&mut zip, name, h, &mut budget) {
                Ok(d) if b64(&d) == want => {}
                Ok(_) => return fail(format!("{name}: digest does not match MANIFEST.MF")),
                Err(e) if e.contains("verification limit") => {
                    return Some((check("v1", Verdict::NotChecked, e), false, false));
                }
                Err(e) => return fail(e),
            }
        }
        for n in &names {
            let up = n.to_ascii_uppercase();
            if n.ends_with('/') || is_sig_file(&up) {
                continue;
            }
            if !msecs
                .iter()
                .any(|m| m.name.as_deref() == Some(n) && best_digest(&m.attrs, "").is_some())
            {
                return fail(format!("{n} is not covered by MANIFEST.MF"));
            }
        }
    }
    Some((
        check(
            "v1",
            Verdict::Verified,
            "manifest, signature file and entry digests verify",
        ),
        claims2,
        claims3,
    ))
}

/// The messageDigest signed attribute (OID 1.2.840.113549.1.9.4).
fn payload_md(attrs: &[u8]) -> Option<Vec<u8>> {
    kids(payload(attrs)).into_iter().find_map(|a| {
        let k = kids(payload(a));
        if payload(k.first()?) != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04] {
            return None;
        }
        Some(payload(kids(payload(k.get(1)?)).first()?).to_vec())
    })
}

/// Verify every signature scheme present in the APK. Empty when it is unsigned.
pub fn verify_apk(bytes: &[u8]) -> Vec<SchemeCheck> {
    let mut out = Vec::new();
    let v1 = verify_v1(bytes);
    let blocks = verify_blocks(bytes);
    let (mut c2, mut c3) = (false, false);
    if let Some((c, a, b)) = v1 {
        (c2, c3) = (a, b);
        out.push(c);
    }
    // Rollback protection: a v1 signature that says v2/v3 signed the APK, with the block gone.
    for (claimed, scheme) in [(c2, "v2"), (c3, "v3")] {
        if claimed && !blocks.iter().any(|b| b.scheme == scheme) {
            out.push(check(scheme, Verdict::Invalid, "the v1 signature says this scheme signed the APK, but its block is missing (stripped?)"));
        }
    }
    out.extend(blocks);
    out
}

/// The v4 entry for an APK whose `.idsig` sidecar is present. Detection only: the incremental
/// Merkle tree is not recomputed.
pub fn v4_detected() -> SchemeCheck {
    check(
        "v4",
        Verdict::NotChecked,
        "a .idsig sidecar is present; v4 is detected but not verified",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &[u8] = include_bytes!("../../tests/fixtures/apk/v1.apk");
    const V23: &[u8] = include_bytes!("../../tests/fixtures/apk/v23.apk");
    const EC: &[u8] = include_bytes!("../../tests/fixtures/apk/ec.apk");
    const DSA: &[u8] = include_bytes!("../../tests/fixtures/apk/dsa.apk");

    fn verdicts(apk: &[u8]) -> Vec<(&'static str, Verdict)> {
        verify_apk(apk)
            .iter()
            .map(|c| (c.scheme, c.verdict))
            .collect()
    }

    fn flip(apk: &[u8], needle: &[u8]) -> Vec<u8> {
        let at = apk
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("needle");
        let mut v = apk.to_vec();
        v[at] ^= 1;
        v
    }

    use Verdict::*;

    #[test]
    fn apksigner_signed_apks_verify() {
        assert_eq!(verdicts(V1), [("v1", Verified)]);
        assert_eq!(verdicts(V23), [("v2", Verified), ("v3", Verified)]);
        let c = verify_apk(V23);
        assert_eq!(
            (c[1].min_sdk, c[1].max_sdk),
            (Some(24), Some(i32::MAX as u32))
        );
        // ECDSA P-256 in all three schemes, and a DSA JAR signature.
        assert_eq!(
            verdicts(EC),
            [("v1", Verified), ("v2", Verified), ("v3", Verified)]
        );
        assert_eq!(verdicts(DSA), [("v1", Verified)]);
    }

    #[test]
    fn a_modified_entry_breaks_v1_and_the_block_digests() {
        assert_eq!(verdicts(&flip(V1, b"hello world")), [("v1", Invalid)]);
        assert_eq!(
            verdicts(&flip(V23, b"hello world")),
            [("v2", Invalid), ("v3", Invalid)]
        );
        assert_eq!(
            verdicts(&flip(EC, b"hello world")),
            [("v1", Invalid), ("v2", Invalid), ("v3", Invalid)]
        );
        assert_eq!(verdicts(&flip(DSA, b"hello world")), [("v1", Invalid)]);
    }

    /// Rewrite an APK, letting `f` change the bytes of the entries it names.
    fn rewrite(apk: &[u8], f: impl Fn(&str, &mut Vec<u8>)) -> Vec<u8> {
        use std::io::Write;
        let mut zip = ZipArchive::new(Cursor::new(apk)).unwrap();
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..zip.len() {
            let mut e = zip.by_index(i).unwrap();
            let (name, mut data) = (e.name().to_string(), Vec::new());
            e.read_to_end(&mut data).unwrap();
            f(&name, &mut data);
            w.start_file(&name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(&data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn a_modified_signature_file_or_block_fails() {
        assert_eq!(verdicts(&rewrite(V1, |_, _| {})), [("v1", Verified)]);
        let sf = rewrite(V1, |n, d| {
            if n.ends_with(".SF") {
                d[0] ^= 1;
            }
        });
        assert_eq!(verdicts(&sf), [("v1", Invalid)]);
        let blk = rewrite(V1, |n, d| {
            if n.ends_with(".RSA") {
                *d.last_mut().unwrap() ^= 1;
            }
        });
        assert_eq!(verdicts(&blk), [("v1", Invalid)]);
    }

    #[test]
    fn an_added_entry_is_not_covered() {
        // Rename an entry in both its local header and the central directory: the manifest
        // no longer lists the new name.
        let mut v = V1.to_vec();
        for at in v
            .windows(5)
            .enumerate()
            .filter(|(_, w)| *w == b"a.txt")
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
        {
            v[at] = b'b';
        }
        assert_eq!(verdicts(&v), [("v1", Invalid)]);
    }

    #[test]
    fn a_stripped_signing_block_is_caught_by_the_v1_rollback_marker() {
        // Re-zipping drops the signing block; the .SF still says v2 and v3 signed the APK.
        let stripped = rewrite(EC, |_, _| {});
        assert_eq!(
            verdicts(&stripped),
            [("v1", Verified), ("v2", Invalid), ("v3", Invalid)]
        );
    }

    #[test]
    fn rsa_pss_signature_verifies() {
        let n = BigUint::parse_bytes(b"afeee1a493144e906e0c2321a890c4c7515d90dd34cabbd2470f136258bfc1ce00817919b8d3a785f78e1c4dd329d63899f81c0e3d0df65e11fa762f8e37686ae9cd980ae295aed742c1ccd4f505b9af091e44d859b2ff0515d3e6e29de61d2ccb0b4670cb4b89827b80bae83bb53e03cf71db00af57cc63822bdf518538906c5d200e948bcbc22dd10fa2f95eaa11222faf1bff765c07b43a338cf07ad01c5d247f204f50290e898054c831c36035ab9ef52819bcbe0701b00619ac77f583a87f6cc7b7eb3b36335e21d7ad439eb0fb4ad56c8ce77941578ad3e188018b75080523f0058fb0ef515786c6368353a28bba4f1b0cbf00794d19d610ce5241b6f3", 16).unwrap();
        let sig: Vec<u8> = (0.."820e8c6e410973a58328473b211e492d1168f7f37b46a7751bf258684270f654d5679a6fa450814d9cd9f4c9bd188ac27a26c8ce8b3ed736b8e96f36d9b424e18f1d2106f306ea9d396aa7c107f9049ceace55889920f31d36cf165093e399df5359972e92a55bface57e636214a8486091e623312b7906d98f697d073e3c15b3aaa4ff1e990e3e668aec1fd9980f35e120a0ad5dd946cced37a2e5e31f54119a4e1240a496b70061650d934222c75e1a765c9a5e4954852a9dd4887df18cd5b0a2797448610efcdefb12627e4928bd1c0467a7f4f16cbb6dee096774bbf976485de78199a198b3446c2a912f59d770d31a6987780b98ea29986106f62d3e10c".len() / 2)
            .map(|i| u8::from_str_radix(&"820e8c6e410973a58328473b211e492d1168f7f37b46a7751bf258684270f654d5679a6fa450814d9cd9f4c9bd188ac27a26c8ce8b3ed736b8e96f36d9b424e18f1d2106f306ea9d396aa7c107f9049ceace55889920f31d36cf165093e399df5359972e92a55bface57e636214a8486091e623312b7906d98f697d073e3c15b3aaa4ff1e990e3e668aec1fd9980f35e120a0ad5dd946cced37a2e5e31f54119a4e1240a496b70061650d934222c75e1a765c9a5e4954852a9dd4887df18cd5b0a2797448610efcdefb12627e4928bd1c0467a7f4f16cbb6dee096774bbf976485de78199a198b3446c2a912f59d770d31a6987780b98ea29986106f62d3e10c"[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let key = Key::Rsa {
            n,
            e: BigUint::from(65537u32),
        };
        let alg = Alg::Pss(Hash::Sha256);
        assert!(verify_sig(&key, alg, b"pss test message", &sig).is_ok());
        assert!(verify_sig(&key, alg, b"pss test messagf", &sig).is_err());
    }

    #[test]
    fn hostile_truncations_and_flips_never_panic() {
        for apk in [V1, V23, EC, DSA] {
            for cut in (0..apk.len()).step_by(37) {
                verify_apk(&apk[..cut]);
            }
            for at in (0..apk.len()).step_by(53) {
                let mut v = apk.to_vec();
                v[at] ^= 0xff;
                verify_apk(&v);
            }
        }
    }

    #[test]
    fn invalid_and_unverified_schemes_become_posture_findings() {
        let info = ApkInfo {
            verification: vec![
                check("v2", Invalid, "bad"),
                check("v3", NotChecked, "curve"),
                v4_detected(),
                check("v1", Verified, "ok"),
            ],
            ..Default::default()
        };
        let rules: Vec<_> = info.posture(0).iter().map(|p| p.0).collect();
        assert_eq!(rules, ["apk-signature-invalid", "apk-signature-unverified"]);
    }
}
