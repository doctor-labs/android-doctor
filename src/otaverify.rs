//! Signature checks for an OTA package: the whole-file zip signature that `signapk` appends, and
//! the update_engine payload signatures (metadata signature and payload signature).
//!
//! Layouts follow AOSP: `RecoverySystem.verifyPackage` / `signapk` for the zip footer (Apache-2.0),
//! `update_metadata.proto` and `payload_consumer/payload_verifier.cc` for the payload. A signature
//! proves the bytes were not changed since signing; it proves who signed only if the key is one
//! you trust, so the report says which key was used: `--cert`, else the package's own
//! `META-INF/com/android/otacert` (integrity only).

use crate::apk::verify::{
    Hash, Hasher, Key, p7_hash, p7_verify, public_key, verify_rsa_sha256_digest,
};
use anyhow::{Context, Result, ensure};
use prost::Message;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone, PartialEq, prost::Message)]
struct Signature {
    #[prost(bytes = "vec", optional, tag = "2")]
    data: Option<Vec<u8>>,
    #[prost(fixed32, optional, tag = "3")]
    unpadded_signature_size: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Signatures {
    #[prost(message, repeated, tag = "1")]
    signatures: Vec<Signature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Invalid,
    /// The package carries no such signature.
    Absent,
    /// There is a signature this tool could not judge (no key, unsupported algorithm).
    NotChecked,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Invalid => "invalid",
            Verdict::Absent => "absent",
            Verdict::NotChecked => "not-checked",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub what: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

fn check(what: &'static str, verdict: Verdict, detail: impl Into<String>) -> Check {
    Check {
        what,
        verdict,
        detail: detail.into(),
    }
}

#[derive(Debug)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn any_invalid(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Invalid)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ok": !self.any_invalid(),
            "checks": self.checks.iter().map(|c| json!({
                "check": c.what, "verdict": c.verdict.name(), "detail": c.detail,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn to_text(&self) -> String {
        self.checks
            .iter()
            .map(|c| format!("{:<26} {:<12} {}", c.what, c.verdict.name(), c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

const FOOTER: u64 = 6;
const EOCD: u64 = 22;
const MAX_P7: u64 = 1 << 20;
const OTACERT: &str = "META-INF/com/android/otacert";

fn read_exact_at(f: &mut File, at: u64, len: usize) -> Result<Vec<u8>> {
    f.seek(SeekFrom::Start(at))?;
    let mut v = vec![0u8; len];
    f.read_exact(&mut v).context("file ends early")?;
    Ok(v)
}

/// SHA-256 (or `h`) of `len` bytes of `f` from `at`.
fn hash_range(f: &mut File, at: u64, len: u64, h: Hash) -> Result<Vec<u8>> {
    f.seek(SeekFrom::Start(at))?;
    let mut hs = Hasher::new(h);
    let mut buf = vec![0u8; 1 << 20];
    let mut left = len;
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..want])?;
        ensure!(n > 0, "file ends early");
        hs.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hs.finish())
}

fn keys_from(cert: Option<&Path>, embedded: Option<Vec<u8>>) -> Result<(Vec<Key>, String)> {
    if let Some(p) = cert {
        crate::detect::refuse_blocking_file(p)?;
        let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
        let k = public_key(&bytes).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
        return Ok((vec![k], format!("--cert {}", p.display())));
    }
    if let Some(b) = embedded
        && let Ok(k) = public_key(&b)
    {
        return Ok((
            vec![k],
            "the package's own otacert (integrity only: pass --cert to check who signed)".into(),
        ));
    }
    Ok((Vec::new(), String::new()))
}

/// The `signapk` whole-file signature: a PKCS#7 block in the zip comment, followed by a 6-byte
/// footer (`signature start`, 0xFFFF, `comment size`), over everything before the comment length.
fn zip_signature(path: &Path, cert: Option<&Path>) -> Result<Check> {
    const WHAT: &str = "zip-signature";
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = f.metadata()?.len();
    if len < EOCD + FOOTER {
        return Ok(check(WHAT, Verdict::Absent, "too short to carry a footer"));
    }
    let foot = read_exact_at(&mut f, len - FOOTER, FOOTER as usize)?;
    let (sig_start, comment) = (
        u64::from(u16::from_le_bytes([foot[0], foot[1]])),
        u64::from(u16::from_le_bytes([foot[4], foot[5]])),
    );
    if foot[2..4] != [0xff, 0xff] || sig_start <= FOOTER {
        return Ok(check(
            WHAT,
            Verdict::Absent,
            "no whole-file signature footer",
        ));
    }
    if sig_start > comment || comment + EOCD > len || sig_start - FOOTER > MAX_P7 {
        return Ok(check(
            WHAT,
            Verdict::Invalid,
            "the signature footer is inconsistent",
        ));
    }
    let p7 = read_exact_at(&mut f, len - sig_start, (sig_start - FOOTER) as usize)?;
    let Some(h) = p7_hash(&p7) else {
        return Ok(check(
            WHAT,
            Verdict::NotChecked,
            "unsupported or malformed PKCS#7 signature",
        ));
    };
    let digest = hash_range(&mut f, 0, len - comment - 2, h)?;
    let signer = match p7_verify(&p7, &digest) {
        Ok(c) => c,
        Err(e) if e.starts_with("not checked") => return Ok(check(WHAT, Verdict::NotChecked, e)),
        Err(e) => return Ok(check(WHAT, Verdict::Invalid, e)),
    };
    let fp: String = Sha256::digest(&signer)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let embedded = crate::otameta::read_member(path, OTACERT, 1 << 16)
        .ok()
        .flatten();
    let (keys, source) = keys_from(cert, embedded)?;
    let trust = match (public_key(&signer), keys.first()) {
        (Ok(a), Some(b)) if a.same_as(b) => format!("signer is {source}"),
        (Ok(_), Some(_)) => {
            return Ok(check(
                WHAT,
                Verdict::Invalid,
                format!("the signature is valid but its signer ({fp}) is not {source}"),
            ));
        }
        _ => "the signer was not compared with any trusted key (pass --cert)".to_string(),
    };
    Ok(check(
        WHAT,
        Verdict::Verified,
        format!("signer sha256 {fp}; {trust}"),
    ))
}

/// Verify a `Signatures` proto over `digest` (SHA-256) with any of `keys`.
fn check_signatures(
    what: &'static str,
    blob: &[u8],
    digest: &[u8],
    keys: &[Key],
    source: &str,
) -> Check {
    let sigs = match Signatures::decode(blob) {
        Ok(s) if !s.signatures.is_empty() => s.signatures,
        _ => {
            return check(
                what,
                Verdict::Invalid,
                "the signature block does not decode",
            );
        }
    };
    if keys.is_empty() {
        return check(
            what,
            Verdict::NotChecked,
            format!(
                "{} signature(s) present but there is no public key (pass --cert)",
                sigs.len()
            ),
        );
    }
    let mut last = String::new();
    for s in &sigs {
        let data = s.data.as_deref().unwrap_or(&[]);
        let data = &data[..data
            .len()
            .min(s.unpadded_signature_size.map_or(data.len(), |n| n as usize))];
        for k in keys {
            match verify_rsa_sha256_digest(k, digest, data) {
                Ok(()) => return check(what, Verdict::Verified, format!("matches {source}")),
                Err(e) => last = e,
            }
        }
    }
    if last.starts_with("not checked") {
        check(what, Verdict::NotChecked, last)
    } else {
        check(
            what,
            Verdict::Invalid,
            format!("no signature verifies against {source}"),
        )
    }
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().expect("8 bytes"))
}

/// The payload's metadata signature (over header + manifest) and payload signature (over
/// everything up to the signatures).
fn payload_signatures(
    loc: &crate::payload::Located,
    cert: Option<&Path>,
    zip: Option<&Path>,
) -> Result<Vec<Check>> {
    let mut f = File::open(&loc.path)?;
    let hdr = read_exact_at(&mut f, loc.base, 24)?;
    ensure!(&hdr[..4] == b"CrAU", "not a payload");
    let (manifest_size, meta_sig_size) = (
        be64(&hdr[12..20]),
        u64::from(u32::from_be_bytes(hdr[20..24].try_into()?)),
    );
    ensure!(
        manifest_size <= 64 << 20 && 24 + manifest_size + meta_sig_size <= loc.len,
        "payload header sizes do not fit the payload"
    );
    let raw = read_exact_at(&mut f, loc.base + 24, manifest_size as usize)?;
    let manifest = crate::payload::pb::DeltaArchiveManifest::decode(&raw[..])
        .context("decoding the manifest")?;
    let embedded = zip.and_then(|z| {
        crate::otameta::read_member(z, OTACERT, 1 << 16)
            .ok()
            .flatten()
    });
    let (keys, source) = keys_from(cert, embedded)?;
    let mut out = Vec::new();
    // metadata signature
    if meta_sig_size == 0 {
        out.push(check(
            "payload-metadata-signature",
            Verdict::Absent,
            "the payload header declares none",
        ));
    } else {
        let blob = read_exact_at(
            &mut f,
            loc.base + 24 + manifest_size,
            meta_sig_size as usize,
        )?;
        let digest = hash_range(&mut f, loc.base, 24 + manifest_size, Hash::Sha256)?;
        out.push(check_signatures(
            "payload-metadata-signature",
            &blob,
            &digest,
            &keys,
            &source,
        ));
    }
    // payload signature
    let data_base = 24 + manifest_size + meta_sig_size;
    match (manifest.signatures_offset, manifest.signatures_size) {
        (Some(off), Some(size)) if size > 0 => {
            let (start, end) = (
                data_base.checked_add(off),
                data_base.checked_add(off).and_then(|s| s.checked_add(size)),
            );
            match (start, end) {
                (Some(start), Some(end)) if end <= loc.len && size <= MAX_P7 => {
                    let blob = read_exact_at(&mut f, loc.base + start, size as usize)?;
                    let digest = hash_range(&mut f, loc.base, start, Hash::Sha256)?;
                    out.push(check_signatures(
                        "payload-signature",
                        &blob,
                        &digest,
                        &keys,
                        &source,
                    ));
                }
                _ => out.push(check(
                    "payload-signature",
                    Verdict::Invalid,
                    "the signature range lies outside the payload",
                )),
            }
        }
        _ => out.push(check(
            "payload-signature",
            Verdict::Absent,
            "the manifest declares none",
        )),
    }
    Ok(out)
}

/// Verify what `input` (an OTA zip, a `payload.bin`, or a directory holding one) signs.
pub fn verify(input: &Path, cert: Option<&Path>) -> Result<Report> {
    crate::detect::refuse_blocking_file(input)?;
    let mut checks = Vec::new();
    let is_zip = input.is_file() && {
        let mut m = [0u8; 2];
        File::open(input)?.read_exact(&mut m).is_ok() && &m == b"PK"
    };
    if is_zip {
        checks.push(zip_signature(input, cert)?);
    }
    match crate::payload::locate(input, None)? {
        Some(loc) => checks.extend(payload_signatures(&loc, cert, is_zip.then_some(input))?),
        None if !is_zip => anyhow::bail!(
            "{} is neither an OTA zip nor an A/B payload",
            input.display()
        ),
        None => {}
    }
    Ok(Report { checks })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;

    // Made by tests/fixtures/ota/make.py with python-cryptography and `openssl cms`.
    const OTA: &[u8] = include_bytes!("../tests/fixtures/ota/ota-signed.zip");
    const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ota/cert.pem");
    const OTHER: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ota/other-cert.pem"
    );

    fn run(bytes: &[u8], cert: Option<&str>) -> Vec<(&'static str, Verdict)> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = Scratch::new(&format!(
            "otaverify-{}",
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let p = d.join("ota.zip");
        std::fs::write(&p, bytes).unwrap();
        let r = verify(&p, cert.map(Path::new)).unwrap();
        r.checks.iter().map(|c| (c.what, c.verdict)).collect()
    }

    use Verdict::*;

    #[test]
    fn signed_by_independent_tools_verifies_with_the_embedded_and_the_given_cert() {
        let want = vec![
            ("zip-signature", Verified),
            ("payload-metadata-signature", Verified),
            ("payload-signature", Verified),
        ];
        assert_eq!(run(OTA, None), want);
        assert_eq!(run(OTA, Some(CERT)), want);
    }

    #[test]
    fn a_different_trusted_cert_fails_every_signature() {
        assert_eq!(
            run(OTA, Some(OTHER)),
            vec![
                ("zip-signature", Invalid),
                ("payload-metadata-signature", Invalid),
                ("payload-signature", Invalid)
            ]
        );
    }

    #[test]
    fn a_changed_byte_breaks_the_zip_signature_and_the_payload_signature() {
        // a byte inside payload.bin's signed region (the manifest)
        let at = OTA.windows(4).position(|w| w == b"CrAU").unwrap() + 30;
        let mut v = OTA.to_vec();
        v[at] ^= 1;
        let got = run(&v, None);
        assert_eq!(got[0], ("zip-signature", Invalid));
        assert!(
            got.iter()
                .any(|c| c.0.starts_with("payload") && c.1 == Invalid),
            "{got:?}"
        );
    }

    #[test]
    fn a_changed_signature_byte_is_invalid_and_no_footer_is_absent() {
        let mut v = OTA.to_vec();
        let n = v.len();
        v[n - 40] ^= 1; // inside the PKCS#7 block
        assert_eq!(run(&v, None)[0].1, Invalid);
        // drop the comment: a plain zip has no whole-file signature, and that is said
        let eocd = OTA
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 5, 6])
            .unwrap();
        let mut plain = OTA[..eocd + 20].to_vec();
        plain.extend([0, 0]);
        assert_eq!(run(&plain, None)[0], ("zip-signature", Absent));
    }

    #[test]
    fn hostile_truncations_and_flips_never_panic() {
        let d = Scratch::new("otaverify-fuzz");
        let p = d.join("f.zip");
        for cut in (0..OTA.len()).step_by(41) {
            std::fs::write(&p, &OTA[..cut]).unwrap();
            let _ = verify(&p, None);
        }
        for at in (0..OTA.len()).step_by(29) {
            let mut v = OTA.to_vec();
            v[at] ^= 0xff;
            std::fs::write(&p, &v).unwrap();
            let _ = verify(&p, None);
        }
    }
}
