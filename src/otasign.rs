//! Re-signing an OTA package: `ota-strip` removes the signapk whole-file signature (the PKCS#7
//! block and footer in the zip comment) and the `META-INF/com/android/otacert` entry; `ota-sign`
//! writes a new whole-file signature with an RSA key and reads it back through `verify-ota`.
//!
//! Layouts mirror `otaverify.rs`, which follows AOSP `signapk` and `RecoverySystem.verifyPackage`:
//! the digest covers every byte before the 2-byte EOCD comment length, the comment is a detached
//! CMS SignedData with signed attributes, and a 6-byte footer ends the file.
//! Design: the signer's issuer and serial are copied from the certificate, and the certificate
//! is embedded so a verifier can find it. Only the signature is checked on write; the chain is not.
//! Unverified on a device: no recovery or update_engine run; the output is checked by this
//! crate's own verifier only.

use crate::avbwrite::sha256_scheme;
use crate::otaverify;
use anyhow::{Context, Result, bail, ensure};
use doctor_core::{Envelope, Score};
use rsa::RsaPrivateKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const EOCD_LEN: usize = 22;
const OTACERT: &str = "META-INF/com/android/otacert";

const OID_SHA256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
];
const OID_DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];
const OID_CONTENT_TYPE: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
];
const OID_MESSAGE_DIGEST: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
];
const OID_RSA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

fn u16le(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn u32le(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
}

/// Offset of the end-of-central-directory record whose comment runs to the end of the file.
fn find_eocd(z: &[u8]) -> Option<usize> {
    if z.len() < EOCD_LEN {
        return None;
    }
    let lowest = z.len().saturating_sub(EOCD_LEN + u16::MAX as usize);
    (lowest..=z.len() - EOCD_LEN)
        .rev()
        .find(|&i| z[i..i + 4] == EOCD_SIG && u16le(z, i + 20) == z.len() - i - EOCD_LEN)
}

/// Strip result: the new bytes and what was removed.
pub struct Stripped {
    pub bytes: Vec<u8>,
    pub otacert: bool,
    pub signature_comment: bool,
}

/// Remove the zip comment (the whole-file signature) and the otacert entry. Other entries are
/// copied byte for byte; only offsets in the central directory change.
pub fn strip(z: &[u8]) -> Result<Stripped> {
    let e = find_eocd(z).context("no end-of-central-directory record at the end: not a zip")?;
    let count = u16le(z, e + 10);
    let cd_size = u32le(z, e + 12);
    let cd_off = u32le(z, e + 16);
    ensure!(
        count != 0xffff && cd_size != 0xffff_ffff && cd_off != 0xffff_ffff,
        "zip64 archives are not supported"
    );
    ensure!(
        cd_off.checked_add(cd_size) == Some(e),
        "unexpected data between the central directory and the end record"
    );
    let mut entries = Vec::with_capacity(count);
    let mut p = cd_off;
    for _ in 0..count {
        ensure!(
            p + 46 <= e && z[p..p + 4] == CD_SIG,
            "central directory entry is malformed"
        );
        let (nlen, xlen, clen) = (u16le(z, p + 28), u16le(z, p + 30), u16le(z, p + 32));
        let len = 46 + nlen + xlen + clen;
        ensure!(p + len <= e, "central directory entry runs past its end");
        let name = String::from_utf8_lossy(&z[p + 46..p + 46 + nlen]).into_owned();
        let local = u32le(z, p + 42);
        ensure!(
            local < cd_off,
            "local header offset is past the central directory"
        );
        entries.push((p, len, name, local));
        p += len;
    }
    ensure!(p == e, "central directory size does not match its entries");

    // The otacert record runs from its local header to the next record (or the directory).
    let cert = entries.iter().position(|x| x.2 == OTACERT);
    let (gap_from, gap_to) = match cert {
        Some(k) => {
            let start = entries[k].3;
            let end = entries
                .iter()
                .map(|x| x.3)
                .filter(|&o| o > start)
                .min()
                .unwrap_or(cd_off);
            (start, end)
        }
        None => (cd_off, cd_off),
    };
    let removed = gap_to - gap_from;
    let mut cd = Vec::new();
    for (i, (start, len, _, local)) in entries.iter().enumerate() {
        if Some(i) == cert {
            continue;
        }
        let mut rec = z[*start..start + len].to_vec();
        let new_local = if *local >= gap_to {
            local - removed
        } else {
            *local
        };
        rec[42..46].copy_from_slice(&(new_local as u32).to_le_bytes());
        cd.extend_from_slice(&rec);
    }
    let new_cd_off = gap_from + (cd_off - gap_to);
    let mut eocd = z[e..e + EOCD_LEN].to_vec();
    let kept = count - usize::from(cert.is_some());
    eocd[8..10].copy_from_slice(&(kept as u16).to_le_bytes());
    eocd[10..12].copy_from_slice(&(kept as u16).to_le_bytes());
    eocd[12..16].copy_from_slice(&(cd.len() as u32).to_le_bytes());
    eocd[16..20].copy_from_slice(&(new_cd_off as u32).to_le_bytes());
    let signature_comment = u16le(z, e + 20) != 0;
    eocd[20..22].copy_from_slice(&[0, 0]);

    let mut bytes = Vec::with_capacity(z.len());
    bytes.extend_from_slice(&z[..gap_from]);
    bytes.extend_from_slice(&z[gap_to..cd_off]);
    bytes.extend_from_slice(&cd);
    bytes.extend_from_slice(&eocd);
    Ok(Stripped {
        bytes,
        otacert: cert.is_some(),
        signature_comment,
    })
}

/// Minimal DER TLV (short and long length forms).
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = body.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&x| x == 0)
            .collect();
        v.push(0x80 | bytes.len() as u8);
        v.extend_from_slice(&bytes);
    }
    v.extend_from_slice(body);
    v
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

fn set(parts: &[&[u8]]) -> Vec<u8> {
    der(0x31, &parts.concat())
}

/// Read one TLV: (tag, content, rest). Single-byte tags only.
fn read_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (n, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let k = l0 & 0x7f;
        if k == 0 || k > 4 {
            return None;
        }
        let n = b
            .get(2..2 + k)?
            .iter()
            .fold(0usize, |a, &x| (a << 8) | x as usize);
        (n, 2 + k)
    };
    let end = hdr.checked_add(n)?;
    Some((tag, b.get(hdr..end)?, b.get(end..)?))
}

/// The whole TLV of each element of `b`.
fn children(mut b: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (_, _, rest) = read_tlv(b)?;
        out.push(&b[..b.len() - rest.len()]);
        b = rest;
    }
    Some(out)
}

/// The issuer and the serial number of a certificate, as whole DER TLVs.
fn issuer_and_serial(cert: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (t, c, _) = read_tlv(cert).context("the signer certificate is not DER")?;
    ensure!(t == 0x30, "the signer certificate is not a DER sequence");
    let (t, tbs, _) = read_tlv(c).context("the signer certificate has no body")?;
    ensure!(t == 0x30, "the signer certificate has no TBS sequence");
    let mut items = children(tbs).context("malformed TBS certificate")?;
    if items.first().map(|x| x[0]) == Some(0xa0) {
        items.remove(0);
    }
    ensure!(
        items.len() >= 3 && items[0][0] == 0x02 && items[2][0] == 0x30,
        "the signer certificate has no serial and issuer"
    );
    Ok((items[2].to_vec(), items[0].to_vec()))
}

/// Append a whole-file signature to a zip that has no comment. The signature covers every byte
/// before the EOCD comment length, which is the same range `verify-ota` hashes.
pub fn sign(z: &[u8], key: &RsaPrivateKey, cert_der: &[u8]) -> Result<Vec<u8>> {
    let e = find_eocd(z).context("no end-of-central-directory record at the end: not a zip")?;
    ensure!(
        u16le(z, e + 20) == 0,
        "the package already has a zip comment (a signature?): run patch ota-strip first"
    );
    let body = &z[..z.len() - 2];
    let content_digest = Sha256::digest(body);
    let (issuer, serial) = issuer_and_serial(cert_der)?;

    let attrs_body = [
        seq(&[OID_CONTENT_TYPE, &set(&[OID_DATA])]),
        seq(&[OID_MESSAGE_DIGEST, &set(&[&der(0x04, &content_digest)])]),
    ]
    .concat();
    // Signed attributes are signed as a SET (tag 0x31); the SignerInfo carries them as [0].
    let signed_attrs = der(0x31, &attrs_body);
    let sig = key
        .sign(sha256_scheme(), &Sha256::digest(&signed_attrs))
        .context("signing the package")?;
    let signer = seq(&[
        &der(0x02, &[1]),
        &seq(&[&issuer, &serial]),
        &seq(&[OID_SHA256]),
        &der(0xa0, &attrs_body),
        &seq(&[OID_RSA]),
        &der(0x04, &sig),
    ]);
    let signed_data = seq(&[
        &der(0x02, &[1]),
        &set(&[&seq(&[OID_SHA256])]),
        &seq(&[OID_DATA]),
        &der(0xa0, cert_der),
        &set(&[&signer]),
    ]);
    let p7 = seq(&[OID_SIGNED_DATA, &der(0xa0, &signed_data)]);

    let total = p7.len() + 6;
    ensure!(
        total <= u16::MAX as usize,
        "the signature block is too large for a zip comment"
    );
    let c = (total as u16).to_le_bytes();
    let mut out = body.to_vec();
    out.extend_from_slice(&c);
    out.extend_from_slice(&p7);
    out.extend_from_slice(&[c[0], c[1], 0xff, 0xff, c[0], c[1]]);
    Ok(out)
}

/// Refuse an unsafe output: the input itself, or an existing file without `--force`.
fn check_output(input: &Path, output: &Path, force: bool) -> Result<()> {
    crate::detect::refuse_blocking_file(input)?;
    ensure!(
        output.symlink_metadata().is_err() || force,
        "{} already exists; pass --force to replace it",
        output.display()
    );
    if let (Ok(a), Ok(b)) = (input.canonicalize(), output.canonicalize()) {
        ensure!(a != b, "the output is the input; choose a new file");
    }
    Ok(())
}

/// Write `bytes` to `<output>.part`, let `check` look at the part, then rename it into place.
fn write_checked(
    output: &Path,
    bytes: &[u8],
    check: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let mut part = output.as_os_str().to_owned();
    part.push(".part");
    let part = std::path::PathBuf::from(part);
    let result = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .with_context(|| format!("creating {}", part.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        check(&part)?;
        std::fs::rename(&part, output)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    result
}

fn envelope(data: Value) -> Value {
    Envelope::new(
        "android-doctor",
        env!("CARGO_PKG_VERSION"),
        0,
        Score::new(100, "ota-resign/1", 0),
        Vec::new(),
        data,
    )
    .to_value()
}

/// `ota-strip`: write a copy of the package with the signature comment and otacert removed.
pub fn strip_command(input: &Path, output: &Path, force: bool, json: bool) -> Result<String> {
    check_output(input, output, force)?;
    let z = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let s = strip(&z)?;
    write_checked(output, &s.bytes, |_| Ok(()))?;
    let data = json!({
        "output": output.display().to_string(),
        "removed": {"otacert": s.otacert, "signature_comment": s.signature_comment},
        "bytes": s.bytes.len(),
        "verified": false,
    });
    if json {
        return Ok(serde_json::to_string_pretty(&envelope(data))?);
    }
    Ok(format!(
        "wrote {} ({} bytes): otacert {}, signature comment {}; not verified",
        output.display(),
        s.bytes.len(),
        if s.otacert { "removed" } else { "absent" },
        if s.signature_comment {
            "removed"
        } else {
            "absent"
        },
    ))
}

/// `ota-sign`: write a copy of the (unsigned) package with a whole-file signature. The output is
/// read back with `verify-ota` against `cert` before it is renamed into place.
pub fn sign_command(
    input: &Path,
    key: &Path,
    cert: &Path,
    output: &Path,
    force: bool,
    json: bool,
) -> Result<String> {
    check_output(input, output, force)?;
    let z = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let key = crate::avbcert::load_private_key(key)?;
    let cert_bytes = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
    let cert_der = crate::otameta::pem_to_der(&cert_bytes)?;
    let signed = sign(&z, &key, &cert_der)?;
    write_checked(output, &signed, |part| {
        let report = otaverify::verify(part, Some(cert))?;
        let ok = report
            .checks
            .iter()
            .any(|c| c.what == "zip-signature" && c.verdict == otaverify::Verdict::Verified);
        if !ok || report.any_invalid() {
            bail!("the signed package does not verify with {}", cert.display());
        }
        Ok(())
    })?;
    let data = json!({
        "output": output.display().to_string(),
        "bytes": signed.len(),
        "signed_by": format!("--cert {}", cert.display()),
        "verified": true,
    });
    if json {
        return Ok(serde_json::to_string_pretty(&envelope(data))?);
    }
    Ok(format!(
        "wrote {} ({} bytes); verify-ota --cert {} reports the zip signature verified",
        output.display(),
        signed.len(),
        cert.display()
    ))
}

/// AVB header flag: dm-verity hashtree disabled.
pub const FLAG_HASHTREE_DISABLED: u32 = 1 << 0;
/// AVB header flag: verification disabled.
pub const FLAG_VERIFICATION_DISABLED: u32 = 1 << 1;

/// Rebuild a vbmeta image with flag bits cleared, keeping its descriptors, rollback index,
/// rollback index location and release string. With `key` it is signed again with the image's own
/// algorithm (the key must have that size). Without `key` the result is algorithm NONE
/// (unsigned), as `avbtool make_vbmeta_image --algorithm NONE` writes it: an unlocked device
/// accepts it, a locked one does not.
pub fn clear_flags(image: &[u8], clear: u32, key: Option<&RsaPrivateKey>) -> Result<Vec<u8>> {
    ensure!(
        image.len() >= 256 && image[..4] == *b"AVB0",
        "not a vbmeta image (no AVB0 header)"
    );
    let u32_at = |at: usize| u32::from_be_bytes(image[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_be_bytes(image[at..at + 8].try_into().unwrap());
    let auth = usize::try_from(u64_at(12))?;
    let aux = usize::try_from(u64_at(20))?;
    let alg = u32_at(28);
    let aux_start = 256usize.checked_add(auth).context("bad block sizes")?;
    let aux_end = aux_start.checked_add(aux).context("bad block sizes")?;
    ensure!(aux_end <= image.len(), "the vbmeta image is truncated");
    let aux_block = &image[aux_start..aux_end];
    let d_off = usize::try_from(u64_at(96))?;
    let d_len = usize::try_from(u64_at(104))?;
    let descriptors = aux_block
        .get(d_off..d_off.checked_add(d_len).context("bad descriptor size")?)
        .context("the descriptors run past the auxiliary block")?;
    let release_raw = &image[128..176];
    let end = release_raw.iter().position(|&b| b == 0).unwrap_or(48);
    let release = String::from_utf8_lossy(&release_raw[..end]).into_owned();
    let algorithm = match key {
        Some(_) => {
            ensure!(
                alg != 0,
                "the image is unsigned (algorithm NONE): nothing to re-sign with --key"
            );
            crate::avbwrite::ALGORITHMS
                .iter()
                .find(|a| a.1 == alg)
                .context("unknown algorithm")?
                .0
        }
        None => "NONE",
    };
    let opts = crate::avbwrite::Options {
        algorithm,
        rollback_index: u64_at(112),
        flags: u32_at(120) & !clear,
        rollback_index_location: u32_at(124),
        padding_size: if image.len().is_multiple_of(4096) {
            4096
        } else {
            0
        },
        release_string: &release,
    };
    crate::avbwrite::make_vbmeta_with(&opts, key, descriptors)
}

/// `vbmeta-flags`: write a copy of a vbmeta image with the verification flags cleared.
pub fn clear_flags_command(
    input: &Path,
    hashtree: bool,
    verification: bool,
    key: Option<&Path>,
    output: &Path,
    force: bool,
    json: bool,
) -> Result<String> {
    ensure!(
        hashtree || verification,
        "nothing to clear: pass --clear-hashtree-disabled and/or --clear-verification-disabled"
    );
    let clear = (if hashtree { FLAG_HASHTREE_DISABLED } else { 0 })
        | (if verification {
            FLAG_VERIFICATION_DISABLED
        } else {
            0
        });
    check_output(input, output, force)?;
    let image = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let key = key.map(crate::avbcert::load_private_key).transpose()?;
    let out = clear_flags(&image, clear, key.as_ref())?;
    let before = crate::avb::parse(&image, None)?;
    write_checked(output, &out, |part| {
        let after = crate::avb::parse(&std::fs::read(part)?, None)?;
        ensure!(
            after.flags == before.flags & !clear,
            "the flags did not read back as written"
        );
        ensure!(
            after.descriptors.len() == before.descriptors.len(),
            "the descriptors did not read back"
        );
        ensure!(
            after.digest_ok != Some(false),
            "the header digest does not match the header"
        );
        Ok(())
    })?;
    let signed = key.is_some();
    let data = json!({
        "output": output.display().to_string(),
        "bytes": out.len(),
        "flags": {"before": before.flags, "after": before.flags & !clear},
        "signed": signed,
        "verified": false,
    });
    if json {
        return Ok(serde_json::to_string_pretty(&envelope(data))?);
    }
    Ok(format!(
        "wrote {} ({} bytes): flags {:#x} -> {:#x}; {}; not verified on a device",
        output.display(),
        out.len(),
        before.flags,
        before.flags & !clear,
        if signed {
            "re-signed with --key"
        } else {
            "UNSIGNED (algorithm NONE): accepted only on an unlocked device; pass --key to re-sign"
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Scratch;
    use rsa::pkcs8::EncodePublicKey;
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            w.start_file(*name, opt).unwrap();
            std::io::Write::write_all(&mut w, data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn read_entries(z: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut a = zip::ZipArchive::new(Cursor::new(z)).unwrap();
        (0..a.len())
            .map(|i| {
                let mut f = a.by_index(i).unwrap();
                let mut v = Vec::new();
                std::io::Read::read_to_end(&mut f, &mut v).unwrap();
                (f.name().to_string(), v)
            })
            .collect()
    }

    /// A throwaway RSA key and a minimal self-signed X.509 certificate for it. The verifier does
    /// not check the certificate's own signature, only its serial and public key.
    fn key_and_cert() -> (RsaPrivateKey, Vec<u8>) {
        let key = crate::avbcert::generate_key(2048).unwrap();
        let spki = key.to_public_key().to_public_key_der().unwrap();
        let alg = seq(&[OID_SHA256]);
        let name = seq(&[&set(&[&seq(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03],
            &der(0x0c, b"throwaway"),
        ])])]);
        let tbs = seq(&[
            &der(0xa0, &der(0x02, &[2])),
            &der(0x02, &[7]),
            &alg,
            &name,
            &seq(&[]),
            &name,
            spki.as_bytes(),
        ]);
        let cert = seq(&[&tbs, &alg, &der(0x03, &[0])]);
        (key, cert)
    }

    fn package() -> Vec<u8> {
        stored_zip(&[
            ("data.bin", b"payload bytes that are not compressed"),
            ("META-INF/com/android/metadata", b"ota-type=FULL\n"),
            (OTACERT, b"placeholder otacert"),
        ])
    }

    #[test]
    fn strip_drops_otacert_and_keeps_other_entries() {
        let s = strip(&package()).unwrap();
        assert!(s.otacert && !s.signature_comment);
        assert_eq!(
            read_entries(&s.bytes),
            vec![
                (
                    "data.bin".to_string(),
                    b"payload bytes that are not compressed".to_vec()
                ),
                (
                    "META-INF/com/android/metadata".to_string(),
                    b"ota-type=FULL\n".to_vec()
                ),
            ]
        );
    }

    #[test]
    fn strip_of_a_clean_package_is_the_identity() {
        let z = stored_zip(&[("a", b"one"), ("b", b"two")]);
        let s = strip(&z).unwrap();
        assert!(!s.otacert && !s.signature_comment);
        assert_eq!(s.bytes, z);
    }

    #[test]
    fn sign_then_strip_gives_back_the_unsigned_bytes() {
        let z = stored_zip(&[("a", b"one"), ("b", b"two")]);
        let (key, cert) = key_and_cert();
        let signed = sign(&z, &key, &cert).unwrap();
        assert_ne!(signed, z);
        assert!(strip(&signed).unwrap().signature_comment);
        assert_eq!(strip(&signed).unwrap().bytes, z);
    }

    #[test]
    fn signed_package_verifies_and_a_changed_byte_does_not() {
        let scratch = Scratch::new("ota-sign-roundtrip");
        let (key, cert) = key_and_cert();
        let cert_path = scratch.join("cert.der");
        std::fs::write(&cert_path, &cert).unwrap();
        let signed = sign(&package(), &key, &cert).unwrap();
        let ok = scratch.join("signed.zip");
        std::fs::write(&ok, &signed).unwrap();
        let r = otaverify::verify(&ok, Some(&cert_path)).unwrap();
        assert!(
            r.checks
                .iter()
                .any(|c| c.what == "zip-signature" && c.verdict == otaverify::Verdict::Verified),
            "{:?}",
            r.checks
        );
        let mut tampered = signed.clone();
        tampered[30] ^= 0x01;
        let bad = scratch.join("tampered.zip");
        std::fs::write(&bad, &tampered).unwrap();
        let r = otaverify::verify(&bad, Some(&cert_path)).unwrap();
        assert!(r.any_invalid(), "{:?}", r.checks);
    }

    #[test]
    fn sign_refuses_a_package_that_already_has_a_comment() {
        let (key, cert) = key_and_cert();
        let signed = sign(&package(), &key, &cert).unwrap();
        assert!(sign(&signed, &key, &cert).is_err());
    }

    #[test]
    fn clearing_flags_re_signs_and_keeps_the_descriptors() {
        let (key, _) = key_and_cert();
        let desc = crate::avbwrite::hash_descriptor("boot", 1024, &[1u8; 4], &[2u8; 32]);
        let opts = crate::avbwrite::Options {
            algorithm: "SHA256_RSA2048",
            rollback_index: 3,
            flags: 3,
            rollback_index_location: 0,
            padding_size: 4096,
            release_string: "test",
        };
        let img = crate::avbwrite::make_vbmeta_with(&opts, Some(&key), &desc).unwrap();
        let out = clear_flags(
            &img,
            FLAG_HASHTREE_DISABLED | FLAG_VERIFICATION_DISABLED,
            Some(&key),
        )
        .unwrap();
        let before = crate::avb::parse(&img, None).unwrap();
        let after = crate::avb::parse(&out, None).unwrap();
        assert_eq!((before.flags, after.flags), (3, 0));
        assert_eq!(after.rollback_index, 3);
        assert_eq!(after.descriptors.len(), 1);
        assert_eq!(after.digest_ok, Some(true));
        assert_eq!(out.len(), 4096);
    }

    #[test]
    fn clearing_flags_without_a_key_is_an_unsigned_image() {
        let (key, _) = key_and_cert();
        let desc = crate::avbwrite::hash_descriptor("boot", 1024, &[1u8; 4], &[2u8; 32]);
        let opts = crate::avbwrite::Options {
            algorithm: "SHA256_RSA2048",
            rollback_index: 0,
            flags: 3,
            rollback_index_location: 0,
            padding_size: 0,
            release_string: "",
        };
        let img = crate::avbwrite::make_vbmeta_with(&opts, Some(&key), &desc).unwrap();
        let out = clear_flags(&img, FLAG_VERIFICATION_DISABLED, None).unwrap();
        let after = crate::avb::parse(&out, None).unwrap();
        assert_eq!((after.algorithm, after.flags), (0, 1));
        assert_eq!(after.descriptors.len(), 1);
        assert!(clear_flags(&out, 1, Some(&key)).is_err());
    }

    #[test]
    fn command_refuses_to_overwrite_its_input() {
        let scratch = Scratch::new("ota-strip-input");
        let input = scratch.join("ota.zip");
        std::fs::write(&input, package()).unwrap();
        assert!(strip_command(&input, &input, true, false).is_err());
        assert!(strip_command(&input, &scratch.join("out.zip"), false, true).is_ok());
        assert!(strip_command(&input, &scratch.join("out.zip"), false, true).is_err());
    }
}
