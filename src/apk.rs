//! APK inspection: package name and version from the binary AndroidManifest,
//! and signing certificates from the v1 (META-INF PKCS#7), v2 and v3 signing blocks.
//!
//! Formats follow the AOSP definitions (Apache-2.0): the binary XML layout from
//! `ResourceTypes.h`, the APK Signature Scheme v2/v3 from `apk_signature_scheme.h`,
//! and PKCS#7 (RFC 5652) for the v1 META-INF certs. All paths and sizes are bounds-checked.

use crate::audit::Severity;
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

pub(crate) mod verify;
pub use verify::{SchemeCheck, Verdict, v4_detected, verify_apk};
mod rules;

/// AOSP public test-key certificate subject CNs (Apache-2.0, AOSP test keys).
const AOSP_TEST_KEY_SUBJECTS: &[&str] =
    &["Android", "platform", "shared", "testkey", "media", "root"];

/// Maximum APK size we will read into memory (10 MB).
pub const MAX_APK_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum size of a single entry inside an APK zip (5 MB).
const MAX_ENTRY_BYTES: usize = 5 * 1024 * 1024;

// --- Public types ---

/// A signer found in the v1 META-INF area (PKCS#7) or the v2/v3 signing block.
#[derive(Debug, Clone, PartialEq)]
pub struct Signer {
    /// "v1", "v2", or "v3" -- which signing scheme this signer belongs to.
    pub scheme: &'static str,
    /// SHA-256 hex of the signer X.509 certificate.
    pub cert_sha256: String,
    /// The certificate subject CN, for display.
    pub subject_cn: Option<String>,
    /// Whether the cert subject matches a known AOSP public test key.
    pub is_aosp_test_key: bool,
    /// Whether the cert subject is the Android SDK debug keystore ("CN=Android Debug").
    pub is_debug_cert: bool,
    /// Certificate validity window as Unix seconds (notBefore, notAfter), when it parsed.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// OID name of the signatureAlgorithm in the signer's certificate, e.g. "sha1WithRSAEncryption".
    pub sig_alg: Option<&'static str>,
    /// Bit length of the certificate's RSA public key modulus (when it is RSA).
    pub rsa_bits: Option<u32>,
}

/// The auditable contents of one APK.
#[derive(Debug, Clone, Default)]
pub struct ApkInfo {
    pub path: String,
    pub package_name: String,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub signers: Vec<Signer>,
    /// Signature verification per scheme (v1, v2, v3, v3.1, v4); empty when unsigned.
    pub verification: Vec<SchemeCheck>,
    /// Security-relevant manifest attributes (see `ManifestAttrs`).
    pub manifest: ManifestAttrs,
    /// Findings from the code rules over the DEX (see `rules`).
    pub code_issues: Vec<ManifestIssue>,
}

impl ApkInfo {
    /// Manifest hardening problems, derived from real manifest attributes only.
    pub fn issues(&self) -> Vec<ManifestIssue> {
        let mut v = manifest_issues(&self.manifest);
        v.extend(self.code_issues.iter().cloned());
        v
    }

    pub fn has_test_key(&self) -> bool {
        self.signers.iter().any(|s| s.is_aosp_test_key)
    }

    /// Weak signing posture, as `(rule, detail)`. `now` is Unix seconds from the host clock
    /// (firmware has no trusted clock), so certificate dates are judged against it.
    pub fn posture(&self, now: i64) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        let has = |v: &str| self.signers.iter().any(|s| s.scheme == v);
        if has("v1") && !has("v2") && !has("v3") {
            out.push((
                "apk-v1-only-signing",
                "signed with APK Signature Scheme v1 only (no v2/v3): exposed to Janus-class tampering on older platforms".to_string(),
            ));
        }
        for s in &self.signers {
            let cn = s.subject_cn.as_deref().unwrap_or("");
            if s.is_debug_cert || s.is_aosp_test_key {
                let what = if s.is_debug_cert {
                    "the Android debug keystore certificate"
                } else {
                    "a known AOSP test/platform key"
                };
                out.push((
                    "apk-debug-signing-cert",
                    format!("signer (CN={cn}) is {what}"),
                ));
            }
            if let Some(na) = s.not_after.filter(|&na| na < now) {
                out.push((
                    "apk-cert-expired",
                    format!(
                        "signer (CN={cn}) expired {} (as of {}, host clock; firmware has no trusted clock)",
                        ymd(na),
                        ymd(now)
                    ),
                ));
            }
            if let Some(nb) = s.not_before.filter(|&nb| nb > now) {
                out.push((
                    "apk-cert-not-yet-valid",
                    format!(
                        "signer (CN={cn}) is not valid before {} (as of {}, host clock)",
                        ymd(nb),
                        ymd(now)
                    ),
                ));
            }
            if let Some(alg) = s.sig_alg
                && matches!(
                    alg,
                    "md5WithRSAEncryption"
                        | "sha1WithRSAEncryption"
                        | "dsaWithSHA1"
                        | "ecdsaWithSHA1"
                )
            {
                out.push((
                    "apk-cert-weak-hash",
                    format!(
                        "signer (CN={cn}) certificate is signed with {alg}: collisions are practical"
                    ),
                ));
            }
            if let Some(bits) = s.rsa_bits.filter(|&b| b < 2048) {
                out.push((
                    "apk-cert-weak-key",
                    format!("signer (CN={cn}) uses a {bits}-bit RSA key (under 2048)"),
                ));
            }
        }
        for c in &self.verification {
            match c.verdict {
                Verdict::Invalid => out.push((
                    "apk-signature-invalid",
                    format!("{} signature does not verify: {}", c.scheme, c.detail),
                )),
                Verdict::NotChecked if c.scheme != "v4" => out.push((
                    "apk-signature-unverified",
                    format!("{} signature not verified: {}", c.scheme, c.detail),
                )),
                _ => {}
            }
        }
        // The same cert usually signs both v1 and v2: report each finding once.
        let mut seen = Vec::new();
        out.retain(|p| {
            let new = !seen.contains(p);
            seen.push(p.clone());
            new
        });
        out
    }
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

/// `YYYY-MM-DD` for Unix seconds (inverse of `days_from_civil`).
pub fn ymd(secs: i64) -> String {
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// One APK audit result: the parsed info plus any error encountered.
#[derive(Debug, Clone, Default)]
pub struct ApkAudit {
    pub info: Option<ApkInfo>,
    pub error: Option<String>,
}

/// Parsed attributes from a binary AndroidManifest.xml.
#[derive(Debug, Clone, Default)]
pub struct ManifestAttrs {
    pub package_name: String,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    /// `<uses-sdk android:targetSdkVersion>` when it is a plain integer.
    pub target_sdk: Option<u32>,
    /// `<uses-sdk android:minSdkVersion>` when it is a plain integer.
    pub min_sdk: Option<u32>,
    /// `<manifest android:sharedUserId>`.
    pub shared_user_id: Option<String>,
    /// `<application>` booleans. `None` means absent or not a literal boolean (for example
    /// a `@bool/` reference), which is never reported.
    pub debuggable: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub allow_backup: Option<bool>,
    pub test_only: Option<bool>,
    pub has_network_security_config: bool,
    /// `<application android:allowTaskReparenting>` when it is a literal boolean.
    pub task_reparenting: bool,
    /// `<application android:permission>`: the default guard for every component.
    pub app_permission: bool,
    /// `<application android:directBootAware>` being true.
    pub direct_boot_aware: bool,
    /// Top-level `<permission>` declarations: (name, protectionLevel & 0xf).
    pub permissions: Vec<(String, u32)>,
    /// `<application android:taskAffinity>`: inherited by activities unless overridden.
    /// `None` means absent; an empty string is the StrandHogg mitigation and is kept.
    pub app_task_affinity: Option<String>,
    /// Activities, services, receivers and providers declared under `<application>`.
    pub components: Vec<Component>,
}

/// One manifest component and the attributes the exported check needs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Component {
    /// "activity", "service", "receiver" or "provider".
    pub kind: String,
    pub name: String,
    /// `android:exported` when it is a literal boolean.
    pub exported: Option<bool>,
    /// `android:permission` (or both read and write permissions on a provider) is set.
    pub guarded: bool,
    /// `android:permission` value (the guarding permission name).
    pub permission: Option<String>,
    /// `android:enabled="false"`.
    pub disabled: bool,
    pub has_intent_filter: bool,
    /// `android:directBootAware` on this component being true.
    pub direct_boot_aware: bool,
    /// An intent filter handles `android.intent.action.MAIN` (a launcher entry point).
    pub main_action: bool,
    /// `android:launchMode` on this activity (integer data). `None` when absent.
    pub launch_mode: Option<u32>,
    /// `android:taskAffinity` on this activity, or inherited from the application. `None`
    /// when unset anywhere; an empty string is the StrandHogg mitigation and is kept.
    pub task_affinity: Option<String>,
    /// `android:allowTaskReparenting` on this activity, or inherited from the application.
    pub task_reparenting: bool,
    /// Every `<intent-filter>` under this component, with its activities, categories and data.
    pub intent_filters: Vec<IntentFilter>,
    /// `android:grantUriPermissions` on a provider: when true, any URI it serves can be granted
    /// to another app.
    pub grant_uri_permissions: bool,
    /// Broad path grants on a provider: from `<grant-uri-permission>` / `<path-permission>`
    /// children whose path/pathPrefix/pathPattern covers every path.
    pub broad_paths: Vec<String>,
}

/// One `<intent-filter>`: the actions, categories and data (scheme/host/path/mimeType) it
/// declares. A component can have several; each is kept separate rather than merged, since a
/// data spec only applies to the actions declared alongside it, not to the component as a whole.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data: Vec<IntentData>,
    /// `<intent-filter android:priority>`: integer data, can read as `a.data as i32`.
    pub priority: Option<i32>,
}

/// One `<data>` element inside an intent filter (a deep-link surface).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IntentData {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub mime_type: Option<String>,
}

/// One manifest finding: the rule, its severity and what was seen.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestIssue {
    pub rule: &'static str,
    pub severity: Severity,
    pub detail: String,
}

// --- Binary helpers ---

fn le16(data: &[u8], off: usize) -> Result<u16> {
    ensure!(off + 2 <= data.len(), "le16: truncated at {off}");
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn le32(data: &[u8], off: usize) -> Result<u32> {
    ensure!(off + 4 <= data.len(), "le32: truncated at {off}");
    Ok(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

#[allow(dead_code)]
fn le64(data: &[u8], off: usize) -> Result<u64> {
    ensure!(off + 8 <= data.len(), "le64: truncated at {off}");
    Ok(u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

/// Parse the string pool that begins a binary XML document.
fn parse_string_pool(data: &[u8]) -> Result<(Vec<String>, usize)> {
    // RES_STRING_POOL_TYPE (AOSP ResourceTypes.h, Apache-2.0).
    let chunk_type = le16(data, 0)?;
    ensure!(
        chunk_type == 0x0001,
        "string pool: expected RES_STRING_POOL_TYPE 0x0001, got {chunk_type:#06x}"
    );
    let header_size = le16(data, 2)? as usize;
    let chunk_size = le32(data, 4)? as usize;
    ensure!(chunk_size <= data.len(), "string pool: chunk too large");
    let str_count = le32(data, 8)? as usize;
    // ResStringPool_header.flags: bit 0x100 (UTF8_FLAG) means every entry is encoded as UTF-8
    // (aapt2's default since API 21-ish builds), not the UTF-16LE this format defaults to
    // otherwise. Reading UTF-8 bytes as UTF-16 code units silently garbles every string: no
    // bounds are violated, so nothing errors, but every tag/attribute name then fails to match
    // anything and the whole manifest parses to empty (seen on a real APK: Netflix.apk).
    let is_utf8 = le32(data, 16)? & 0x100 != 0;
    let strings_start = le32(data, 20)? as usize;
    ensure!(
        strings_start <= chunk_size,
        "string pool: strings start past chunk"
    );
    // A hostile header can claim billions of strings; the offset table must fit in the data.
    ensure!(
        header_size.saturating_add(str_count.saturating_mul(4)) <= data.len(),
        "string pool: {str_count} strings do not fit"
    );
    let mut offsets = Vec::with_capacity(str_count);
    for i in 0..str_count {
        let off = header_size + 4 * i;
        ensure!(off + 4 <= data.len(), "string pool: offset entry truncated");
        offsets.push(le32(data, off)? as usize);
    }
    let mut strings = Vec::with_capacity(str_count);
    for off in offsets {
        let (s, _) = if is_utf8 {
            read_utf8_pool_entry(data, strings_start + off)?
        } else {
            read_utf16(data, strings_start + off)?
        };
        strings.push(s);
    }
    Ok((strings, strings_start))
}

/// Decode one ResStringPool UTF-8 length prefix: 1 byte, or 2 when the high bit of the first
/// is set (the low 7 bits of the first byte become the high bits of a 15-bit length). Used
/// twice per entry (AOSP ResourceTypes.cpp `decodeLength`, Apache-2.0): once for the UTF-16
/// character count (unused here, strings are kept as UTF-8 throughout), once for the byte count.
fn decode_utf8_pool_length(data: &[u8], pos: usize) -> Result<(usize, usize)> {
    ensure!(pos < data.len(), "utf8 pool: length byte missing");
    let b0 = data[pos] as usize;
    if b0 & 0x80 == 0 {
        return Ok((b0, 1));
    }
    ensure!(pos + 1 < data.len(), "utf8 pool: length byte missing");
    Ok((((b0 & 0x7f) << 8) | data[pos + 1] as usize, 2))
}

/// Read one UTF-8-pool string: a UTF-16 char-count prefix (skipped), a byte-count prefix, then
/// that many UTF-8 bytes. Invalid UTF-8 (a hostile or merely odd manifest) is replaced, not
/// rejected, same as `read_utf16` already tolerates truncation rather than failing the pool.
fn read_utf8_pool_entry(data: &[u8], start: usize) -> Result<(String, usize)> {
    let (_char_len, n1) = decode_utf8_pool_length(data, start)?;
    let (byte_len, n2) = decode_utf8_pool_length(data, start + n1)?;
    let bytes_start = start + n1 + n2;
    ensure!(bytes_start <= data.len(), "utf8 pool: entry past chunk");
    let end = (bytes_start + byte_len).min(data.len());
    let s = String::from_utf8_lossy(&data[bytes_start..end]).into_owned();
    Ok((s, end - start))
}

/// Read a UTF-16LE string from data at offset start.
fn read_utf16(data: &[u8], start: usize) -> Result<(String, usize)> {
    ensure!(start + 2 <= data.len(), "utf16: truncated");
    let char_len = le16(data, start)? as usize;
    let mut s = String::with_capacity(char_len);
    let mut pos = start + 2;
    for _ in 0..char_len {
        // A hostile or merely odd pool can claim more units than the chunk holds; stop at
        // what is actually there rather than failing the whole manifest.
        if pos + 2 > data.len() {
            break;
        }
        let ch = le16(data, pos)? as u16;
        pos += 2;
        if let Some(c) = char::from_u32(ch as u32) {
            s.push(c);
        }
    }
    // Each entry is followed by a terminating 0x0000 (AOSP ResourceTypes.h).
    if pos + 2 <= data.len() {
        pos += 2;
    }
    Ok((s, pos - start))
}

/// An attribute entry in a start tag.
struct Attr {
    ns_idx: usize,
    name_idx: usize,
    value: String,
    /// Res_value dataType and data. Always read: aapt1 also stores the source text in
    /// rawValue for booleans, so the typed value is the only reliable one.
    data_type: u8,
    data: u32,
}

impl Attr {
    /// A literal boolean/int value (types 0x10..=0x1f, as `TypedArray.getBoolean` accepts).
    /// A string or a `@reference` is `None`: never guess.
    fn as_bool(&self) -> Option<bool> {
        (0x10..=0x1f)
            .contains(&self.data_type)
            .then_some(self.data != 0)
    }
}

/// Size of ResXMLTree_node: ResChunk_header (8) + lineNumber (4) + comment (4).
const ATTR_EXT_BASE: usize = 16;

fn parse_start_tag(
    data: &[u8],
    chunk_off: usize,
    strings: &[String],
) -> Result<(String, Vec<Attr>)> {
    let chunk = &data[chunk_off..];
    ensure!(chunk.len() >= 32, "start tag: chunk too small");
    // ResXMLTree_attrExt (AOSP ResourceTypes.h, Apache-2.0) begins ATTR_EXT_BASE bytes into
    // the chunk and is laid out ns, name, attributeStart, attributeSize, attributeCount.
    let name_idx = le32(chunk, ATTR_EXT_BASE + 4)? as usize;
    let name = strings.get(name_idx).cloned().unwrap_or_default();
    let attr_start = le16(chunk, ATTR_EXT_BASE + 8)? as usize;
    let attr_size = le16(chunk, ATTR_EXT_BASE + 10)? as usize;
    let attr_count = le16(chunk, ATTR_EXT_BASE + 12)? as usize;
    // ResXMLTree_attribute is exactly 20 bytes, optionally followed by a typed value
    // (AOSP ResourceTypes.h).
    ensure!(attr_size >= 20, "start tag: attr entry too small");
    let mut attrs = Vec::with_capacity(attr_count);
    // ResXMLTree_attrExt (AOSP ResourceTypes.h): attributeStart is relative to the start
    // of the attrExt, which begins 16 bytes into the chunk (after the ResXMLTree_node header).
    let mut pos = ATTR_EXT_BASE + attr_start;
    for _ in 0..attr_count {
        ensure!(pos + attr_size <= chunk.len(), "start tag: attr past chunk");
        let ns_idx = le32(chunk, pos)? as usize;
        let nm_idx = le32(chunk, pos + 4)? as usize;
        let raw_val_off = le32(chunk, pos + 8)? as usize;
        // Res_value (AOSP ResourceTypes.h): size u16, res0 u8, dataType u8, data u32.
        let dt = chunk[pos + 15];
        let data_word = le32(chunk, pos + 16)?;
        let value = if raw_val_off == 0xFFFFFFFF {
            format_typed_value(dt, &chunk[pos + 16..pos + 20])?
        } else {
            // AOSP ResXMLTree_attribute.rawValue is an INDEX into the string pool, not a
            // byte offset (verified against a real APK), so resolve through the pool.
            strings.get(raw_val_off).cloned().unwrap_or_default()
        };
        attrs.push(Attr {
            ns_idx,
            name_idx: nm_idx,
            value,
            data_type: dt,
            data: data_word,
        });
        pos += attr_size;
    }
    Ok((name, attrs))
}

fn format_typed_value(data_type: u8, data: &[u8]) -> Result<String> {
    ensure!(data.len() >= 4, "typed value: data too short");
    match data_type {
        0x01 => Ok("(string)".to_string()),
        0x10 => Ok(le32(data, 0)?.to_string()),
        0x11 => Ok(format!("0x{:X}", le32(data, 0)?)),
        0x12 => Ok(le32(data, 0)?.to_string()),
        _ => Ok(format!("(type {})", data_type)),
    }
}

pub(crate) fn parse_manifest(data: &[u8]) -> Result<ManifestAttrs> {
    ensure!(!data.is_empty(), "manifest: empty");
    // A binary XML file begins with the RES_XML_TYPE (0x0003) header; the string pool is
    // the first chunk after that 8-byte header (AOSP ResourceTypes.h, Apache-2.0).
    let file_type = le16(data, 0)?;
    ensure!(
        file_type == 0x0003,
        "manifest: expected RES_XML_TYPE 0x0003, got {file_type:#06x}"
    );
    // ResXMLTree_header: type u16, headerSize u16, size u32 (AOSP ResourceTypes.h).
    let xml_header = le16(data, 2)? as usize;
    ensure!(
        xml_header >= 8 && xml_header <= data.len(),
        "manifest: bad xml header"
    );
    // parse_string_pool returns offsets relative to the pool chunk; rebase onto the
    // whole buffer so parse_start_tag can index them directly.
    let (pool, pool_strings_start) = parse_string_pool(&data[xml_header..])?;
    let _strings_start = xml_header + pool_strings_start;
    let pool_chunk_size = le32(&data[xml_header..], 4)? as usize;
    let mut result = ManifestAttrs::default();
    // RES_XML_RESOURCE_MAP_TYPE: one resource id per attribute-name string, which says which
    // attribute a name really is (an app can define its own `exported`).
    let mut res_ids: Vec<u32> = Vec::new();
    // Open tags, each with the index of its component when it is one.
    let mut stack: Vec<(String, Option<usize>)> = Vec::new();
    let mut pos = xml_header + pool_chunk_size;
    while pos + 8 <= data.len() {
        let ct = le16(data, pos)?;
        let cs = le32(data, pos + 4)? as usize;
        // A chunk smaller than its own header would never advance `pos`.
        ensure!(
            cs >= 8 && pos + cs <= data.len(),
            "manifest: bad chunk size {cs}"
        );
        match ct {
            0x0180 => {
                let end = pos + cs - (cs - 8) % 4;
                res_ids = (pos + 8..end)
                    .step_by(4)
                    .filter_map(|o| le32(data, o).ok())
                    .collect();
            }
            0x0103 => {
                stack.pop();
            }
            0x0102 => {
                let (tag, attrs) = parse_start_tag(data, pos, &pool)?;
                let mut comp = None;
                read_tag(
                    &tag,
                    &attrs,
                    &pool,
                    &res_ids,
                    &stack,
                    &mut result,
                    &mut comp,
                );
                stack.push((tag, comp));
            }
            _ => {}
        }
        pos += cs;
    }
    Ok(result)
}

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";
/// Most components kept per manifest: a hostile manifest cannot grow this without bound.
const MAX_COMPONENTS: usize = 5000;

/// Framework attribute resource ids (android.R.attr, stable public API).
const ANDROID_ATTRS: &[(u32, &str)] = &[
    (0x0101_0003, "name"),
    (0x0101_0006, "permission"),
    (0x0101_0007, "readPermission"),
    (0x0101_0008, "writePermission"),
    (0x0101_0009, "protectionLevel"),
    (0x0101_000b, "sharedUserId"),
    (0x0101_0012, "taskAffinity"),
    (0x0101_001d, "launchMode"),
    (0x0101_000e, "enabled"),
    (0x0101_000f, "debuggable"),
    (0x0101_0010, "exported"),
    (0x0101_0270, "targetSdkVersion"),
    (0x0101_020c, "minSdkVersion"),
    (0x0101_0272, "testOnly"),
    (0x0101_0280, "allowBackup"),
    (0x0101_0204, "allowTaskReparenting"),
    (0x0101_04ec, "usesCleartextTraffic"),
    (0x0101_0527, "networkSecurityConfig"),
    (0x0101_0026, "mimeType"),
    (0x0101_0027, "scheme"),
    (0x0101_0028, "host"),
    (0x0101_0029, "port"),
    (0x0101_002a, "path"),
    (0x0101_002b, "pathPrefix"),
    (0x0101_002c, "pathPattern"),
    (0x0101_001b, "grantUriPermissions"),
    (0x0101_001c, "priority"),
    (0x0101_0505, "directBootAware"),
];

/// The `android:` local name of an attribute, or None when it is not a framework attribute.
/// With a resource map the resource id decides (authoritative, survives stripped names);
/// without one, the namespace URI must be the android namespace and the local name decides.
fn android_attr<'a>(a: &Attr, pool: &'a [String], res_ids: &[u32]) -> Option<&'a str> {
    match res_ids.get(a.name_idx).copied().filter(|&id| id != 0) {
        Some(id) => ANDROID_ATTRS
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, n)| *n),
        None => (pool.get(a.ns_idx).map(String::as_str) == Some(ANDROID_NS))
            .then(|| pool.get(a.name_idx).map(String::as_str))
            .flatten(),
    }
}

/// Fold one start tag into `out`. `stack` holds the enclosing open tags.
fn read_tag(
    tag: &str,
    attrs: &[Attr],
    pool: &[String],
    res_ids: &[u32],
    stack: &[(String, Option<usize>)],
    out: &mut ManifestAttrs,
    comp_slot: &mut Option<usize>,
) {
    let parent = stack.last();
    let in_app = parent.is_some_and(|(p, _)| p == "application");
    let is_component = matches!(tag, "activity" | "service" | "receiver" | "provider");
    let mut c = Component {
        kind: tag.to_string(),
        ..Default::default()
    };
    let (mut read_perm, mut write_perm) = (false, false);
    let mut perm_name: Option<String> = None;
    let mut perm_level: Option<u32> = None;
    let mut comp_dba = false;
    for a in attrs {
        if tag == "manifest" {
            match pool.get(a.name_idx).map(String::as_str) {
                Some("package") => out.package_name = a.value.clone(),
                Some("versionCode") => out.version_code = Some(a.value.clone()),
                Some("versionName") => out.version_name = Some(a.value.clone()),
                _ => {}
            }
        }
        let Some(name) = android_attr(a, pool, res_ids) else {
            continue;
        };
        match (tag, name) {
            ("manifest", "sharedUserId") if !a.value.is_empty() => {
                out.shared_user_id = Some(a.value.clone())
            }
            ("uses-sdk", "targetSdkVersion") if (0x10..=0x1f).contains(&a.data_type) => {
                out.target_sdk = Some(a.data)
            }
            ("uses-sdk", "minSdkVersion") if (0x10..=0x1f).contains(&a.data_type) => {
                out.min_sdk = Some(a.data)
            }
            ("application", "debuggable") => out.debuggable = a.as_bool(),
            ("application", "usesCleartextTraffic") => out.uses_cleartext_traffic = a.as_bool(),
            ("application", "allowBackup") => out.allow_backup = a.as_bool(),
            ("application", "testOnly") => out.test_only = a.as_bool(),
            ("application", "networkSecurityConfig") => out.has_network_security_config = true,
            ("application", "permission") => out.app_permission = !a.value.is_empty(),
            ("application", "directBootAware") => {
                if a.as_bool() == Some(true) {
                    out.direct_boot_aware = true;
                }
            }
            ("permission", "name")
                if parent.is_some_and(|(p, _)| p == "manifest") && !a.value.is_empty() =>
            {
                perm_name = Some(a.value.clone())
            }
            ("permission", "protectionLevel") if (0x10..=0x1f).contains(&a.data_type) => {
                perm_level = Some(a.data & 0xf)
            }
            ("application", "allowTaskReparenting") => {
                out.task_reparenting = a.as_bool() == Some(true)
            }
            ("application", "taskAffinity") => out.app_task_affinity = Some(a.value.clone()),
            _ if is_component && in_app => match name {
                "name" => c.name = a.value.clone(),
                "exported" => c.exported = a.as_bool(),
                "enabled" => c.disabled = a.as_bool() == Some(false),
                "permission" => {
                    c.guarded = !a.value.is_empty();
                    c.permission = if a.value.is_empty() {
                        None
                    } else {
                        Some(a.value.clone())
                    };
                }
                "readPermission" => read_perm = !a.value.is_empty(),
                "writePermission" => write_perm = !a.value.is_empty(),
                "launchMode" if (0x10..=0x1f).contains(&a.data_type) => {
                    c.launch_mode = Some(a.data)
                }
                "taskAffinity" => c.task_affinity = Some(a.value.clone()),
                "allowTaskReparenting" => c.task_reparenting = a.as_bool() == Some(true),
                "grantUriPermissions" => c.grant_uri_permissions = a.as_bool() == Some(true),
                "directBootAware" if a.as_bool() == Some(true) => {
                    comp_dba = true;
                }
                _ => {}
            },
            _ => {}
        }
    }
    if tag == "permission"
        && parent.is_some_and(|(p, _)| p == "manifest")
        && let Some(name) = perm_name
    {
        out.permissions.push((name, perm_level.unwrap_or(0)));
    }
    if is_component && in_app {
        if out.components.len() < MAX_COMPONENTS {
            c.guarded |= read_perm && write_perm;
            // Inherit application-level taskAffinity and allowTaskReparenting
            // when the activity does not set its own.
            if c.task_affinity.is_none() {
                c.task_affinity = out.app_task_affinity.clone();
            }
            c.direct_boot_aware = comp_dba;
            out.components.push(c);
            *comp_slot = Some(out.components.len() - 1);
        }
    } else if tag == "intent-filter"
        && let Some((_, Some(i))) = parent
    {
        out.components[*i].has_intent_filter = true;
        let priority = attrs
            .iter()
            .find(|a| android_attr(a, pool, res_ids) == Some("priority"))
            .filter(|a| (0x10..=0x1f).contains(&a.data_type))
            .map(|a| a.data as i32);
        out.components[*i].intent_filters.push(IntentFilter {
            priority,
            ..IntentFilter::default()
        });
    } else if matches!(tag, "grant-uri-permission" | "path-permission")
        && let Some((_, Some(i))) = parent
        && out.components[*i].kind == "provider"
    {
        let get = |n: &str| {
            attrs
                .iter()
                .find(|a| android_attr(a, pool, res_ids) == Some(n))
                .map(|a| a.value.clone())
                .filter(|v| !v.is_empty())
        };
        if let Some(v) = get("path")
            && v == "/"
        {
            out.components[*i].broad_paths.push("path=/".into());
        }
        if let Some(v) = get("pathPrefix")
            && v == "/"
        {
            out.components[*i].broad_paths.push("pathPrefix=/".into());
        }
        if let Some(v) = get("pathPattern")
            && (v == ".*" || v == "/.*")
        {
            out.components[*i]
                .broad_paths
                .push(format!("pathPattern={}", v));
        }
    } else if let [.., (_, Some(i)), (f, _)] = stack
        && f == "intent-filter"
    {
        // `name` on action/category is the android namespace attribute shared with every
        // other tag; find() over all matches (not just the first) in case of a stray duplicate.
        let name_attr = || {
            attrs
                .iter()
                .find(|a| android_attr(a, pool, res_ids) == Some("name"))
                .map(|a| a.value.clone())
        };
        if tag == "action" && name_attr().as_deref() == Some("android.intent.action.MAIN") {
            out.components[*i].main_action = true;
        }
        let Some(filter) = out.components[*i].intent_filters.last_mut() else {
            return;
        };
        match tag {
            "action" => {
                if let Some(v) = name_attr() {
                    filter.actions.push(v);
                }
            }
            "category" => {
                if let Some(v) = name_attr() {
                    filter.categories.push(v);
                }
            }
            "data" => {
                let get = |n: &str| {
                    attrs
                        .iter()
                        .find(|a| android_attr(a, pool, res_ids) == Some(n))
                        .map(|a| a.value.clone())
                        .filter(|v| !v.is_empty())
                };
                filter.data.push(IntentData {
                    scheme: get("scheme"),
                    host: get("host"),
                    port: get("port"),
                    path: get("path"),
                    mime_type: get("mimeType"),
                });
            }
            _ => {}
        }
    }
}

/// The documented `android:exported` defaults, which depend on the component and targetSdk:
/// - an explicit literal `exported` always wins;
/// - a provider is exported by default only when targetSdk < 17 (unknown targetSdk: not
///   reported, we do not guess);
/// - activity/service/receiver are exported by default exactly when they declare an
///   intent filter, up to targetSdk 30; from 31 the attribute is mandatory for such
///   components, so an absent one is an invalid manifest and is not reported.
///
/// Returns `Some(implicit)` when the component is exported.
fn exported(c: &Component, target_sdk: Option<u32>) -> Option<bool> {
    match c.exported {
        Some(true) => Some(false),
        Some(false) => None,
        None if c.kind == "provider" => target_sdk.filter(|&t| t < 17).map(|_| true),
        None => (c.has_intent_filter && target_sdk.is_none_or(|t| t < 31)).then_some(true),
    }
}

fn manifest_issues(m: &ManifestAttrs) -> Vec<ManifestIssue> {
    use Severity::*;
    let mut out = Vec::new();
    let mut issue = |rule, severity, detail: String| {
        out.push(ManifestIssue {
            rule,
            severity,
            detail,
        })
    };
    // Exported and unguarded, grouped by (rule, severity). An implicit export (the default,
    // no literal attribute) is reported one level lower than an explicit one. The permission
    // is only checked for presence: its protection level lives in another package.
    let mut groups: Vec<(&'static str, Severity, Vec<String>)> = Vec::new();
    for c in &m.components {
        // A launcher entry point is meant to be exported; a disabled component is unreachable.
        if c.disabled || m.app_permission || c.guarded || (c.kind == "activity" && c.main_action) {
            continue;
        }
        let Some(implicit) = exported(c, m.target_sdk) else {
            continue;
        };
        let (rule, severity) = match (c.kind == "provider", implicit) {
            (true, false) => ("apk-exported-provider", High),
            (true, true) => ("apk-exported-provider", Medium),
            (false, false) => ("apk-exported-component", Medium),
            (false, true) => ("apk-exported-component", Warn),
        };
        let label = format!(
            "{} {}{}",
            c.kind,
            c.name,
            if implicit { " (implicit)" } else { "" }
        );
        match groups.iter_mut().find(|g| g.0 == rule && g.1 == severity) {
            Some(g) => g.2.push(label),
            None => groups.push((rule, severity, vec![label])),
        }
    }
    for (rule, severity, names) in groups {
        let shown = names.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
        let more = names.len().saturating_sub(5);
        let tail = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        issue(
            rule,
            severity,
            format!(
                "{} exported without a permission: {shown}{tail}",
                names.len()
            ),
        );
    }
    // Exported components guarded by a permission the app declares as normal (0) or dangerous (1).
    for c in &m.components {
        if c.disabled || !c.guarded || c.permission.is_none() {
            continue;
        }
        if exported(c, m.target_sdk).is_none() {
            continue;
        }
        let perm = c.permission.as_deref().unwrap();
        let level = m
            .permissions
            .iter()
            .find(|(name, _)| name == perm)
            .map(|(_, level)| level & 0xf);
        if let Some(0 | 1) = level {
            let label = match level.unwrap() {
                0 => "normal",
                _ => "dangerous",
            };
            issue(
                "apk-exported-weak-permission",
                Medium,
                format!(
                    "{} {} is exported behind {}, a {} permission any app can request",
                    c.kind, c.name, perm, label
                ),
            );
        }
    }
    // Custom permissions declared as normal (0) or dangerous (1): any app can request them.
    let weak: Vec<&String> = m
        .permissions
        .iter()
        .filter(|(_, level)| level & 0xf == 0 || level & 0xf == 1)
        .map(|(name, _)| name)
        .collect();
    if !weak.is_empty() {
        let shown = weak
            .iter()
            .take(5)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let more = weak.len().saturating_sub(5);
        let tail = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        issue(
            "apk-custom-permission-weak",
            Warn,
            format!(
                "custom permissions any app can request (not signature-protected): {shown}{tail}"
            ),
        );
    }
    // minSdkVersion below 23 installs on releases before runtime permissions that no longer get updates.
    if let Some(n) = m.min_sdk
        && n < 23
    {
        issue(
            "apk-min-sdk-old",
            Warn,
            format!(
                "minSdkVersion {n} installs on Android releases before runtime permissions (API 23) that no longer get security updates"
            ),
        );
    }
    // StrandHogg-style task-hijacking attributes, reported per activity.
    for c in &m.components {
        if c.kind != "activity" {
            continue;
        }
        if let Some(mode) = c.launch_mode {
            // 2 = singleTask, 3 = singleInstance.
            if mode == 2 || mode == 3 {
                issue(
                    "apk-launch-mode-singletask",
                    Medium,
                    format!(
                        "activity {} uses launchMode singleTask/singleInstance: StrandHogg-style task hijacking",
                        c.name
                    ),
                );
            }
        }
        if let Some(a) = &c.task_affinity
            && !a.is_empty()
        {
            issue(
                "apk-task-affinity",
                Medium,
                format!(
                    "activity {} sets taskAffinity {}: another app's task can host it",
                    c.name, a
                ),
            );
        }
        if c.task_reparenting {
            issue(
                "apk-task-reparenting",
                Medium,
                format!(
                    "activity {} allowTaskReparenting: the activity can move into another app's task",
                    c.name
                ),
            );
        }
    }
    if m.task_reparenting {
        issue(
            "apk-task-reparenting",
            Medium,
            "application android:allowTaskReparenting: an activity can move into another app's task".into(),
        );
    }
    if m.debuggable == Some(true) {
        issue(
            "apk-debuggable",
            High,
            "android:debuggable=true: anyone with adb can run code as this app".into(),
        );
    }
    if m.uses_cleartext_traffic == Some(true) {
        // With a networkSecurityConfig the attribute is ignored from API 24, so it is only a
        // hint that the config may permit cleartext (the config itself is not read).
        let (sev, note) = if m.has_network_security_config {
            (
                Warn,
                " (a networkSecurityConfig is set and overrides it on API 24+)",
            )
        } else {
            (Medium, "")
        };
        issue(
            "apk-cleartext-traffic",
            sev,
            format!("android:usesCleartextTraffic=true: HTTP allowed{note}"),
        );
    }
    if let Some(u) = &m.shared_user_id {
        issue(
            "apk-shared-user-id",
            Medium,
            format!(
                "android:sharedUserId=\"{u}\": shares a Linux uid and its permissions with other apps"
            ),
        );
    }
    if m.test_only == Some(true) {
        issue(
            "apk-test-only",
            Medium,
            "android:testOnly=true: a test build that should not ship".into(),
        );
    }
    if m.allow_backup == Some(true) {
        issue(
            "apk-allow-backup",
            Info,
            "android:allowBackup=true: app data can be pulled with adb backup".into(),
        );
    }
    // Provider URI/path grants, reported per provider.
    for c in &m.components {
        if c.kind != "provider" {
            continue;
        }
        if c.grant_uri_permissions {
            issue(
                "apk-provider-grant-uri",
                Medium,
                format!(
                    "provider {} sets grantUriPermissions: any URI it serves can be granted to another app",
                    c.name
                ),
            );
        }
        if !c.broad_paths.is_empty() {
            let paths: Vec<_> = c.broad_paths.iter().map(String::as_str).collect();
            issue(
                "apk-provider-broad-path",
                Medium,
                format!(
                    "provider {} grants or guards every path ({})",
                    c.name,
                    paths.join(", ")
                ),
            );
        }
    }
    // Intent-filter priorities above 100, SMS port receivers, dialer secret codes, directBootAware.
    let mut dba_names: Vec<String> = Vec::new();
    if m.direct_boot_aware {
        dba_names.push("application".into());
    }
    for c in &m.components {
        if c.disabled {
            continue;
        }
        for f in &c.intent_filters {
            if let Some(p) = f.priority
                && p > 100
            {
                issue(
                    "apk-intent-priority-high",
                    Warn,
                    format!(
                        "{} {} has an intent filter with priority {p} (above 100), so it receives ordered broadcasts such as incoming SMS before other apps",
                        c.kind, c.name
                    ),
                );
            }
            let has_sms = f
                .actions
                .iter()
                .any(|a| a == "android.intent.action.DATA_SMS_RECEIVED");
            if has_sms
                && f.data.iter().any(|d| d.port.is_some())
                && let Some(d) = f.data.iter().find(|d| d.port.is_some())
            {
                issue(
                    "apk-sms-port-receiver",
                    Medium,
                    format!(
                        "{} {} receives binary SMS on port {}",
                        c.kind,
                        c.name,
                        d.port.as_deref().unwrap_or("")
                    ),
                );
            }
            let has_secret = f
                .actions
                .iter()
                .any(|a| a == "android.provider.Telephony.SECRET_CODE");
            if has_secret
                && f.data
                    .iter()
                    .any(|d| d.scheme.as_deref() == Some("android_secret_code"))
                && let Some(d) = f
                    .data
                    .iter()
                    .find(|d| d.scheme.as_deref() == Some("android_secret_code"))
            {
                issue(
                    "apk-dialer-secret-code",
                    Warn,
                    format!(
                        "{} {} opens on the dialer code *#*#{}#*#*",
                        c.kind,
                        c.name,
                        d.host.as_deref().unwrap_or("")
                    ),
                );
            }
        }
        if c.direct_boot_aware {
            dba_names.push(format!("{} {}", c.kind, c.name));
        }
    }
    if !dba_names.is_empty() {
        let shown: Vec<String> = dba_names.iter().take(5).cloned().collect();
        let more = dba_names.len().saturating_sub(5);
        let tail = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        issue(
            "apk-direct-boot-aware",
            Info,
            format!(
                "runs before the user unlocks the device (directBootAware): {}{}",
                shown.join(", "),
                tail
            ),
        );
    }
    out
}

// --- Minimal ASN.1/DER reader ---
// Only what we need to walk PKCS#7 / X.509 (RFC 5652 / 5280).

struct Der<'a> {
    tag: u8,
    payload: &'a [u8],
}

fn der_len(data: &[u8]) -> Result<(usize, usize)> {
    ensure!(!data.is_empty(), "der_len: empty");
    let first = data[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    ensure!(n != 0 && n <= 4, "der_len: invalid long form {n}");
    ensure!(data.len() > n, "der_len: truncated");
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[1 + i] as usize;
    }
    Ok((len, 1 + n))
}

fn der_one<'a>(data: &'a [u8]) -> Result<(Der<'a>, usize)> {
    ensure!(!data.is_empty(), "der: empty");
    let tag = data[0];
    let (len, n) = der_len(&data[1..])?;
    let hdr = 1 + n;
    ensure!(data.len() >= hdr + len, "der: element truncated");
    let payload = &data[hdr..hdr + len];
    Ok((Der { tag, payload }, hdr + len))
}

struct DerIter<'a> {
    data: &'a [u8],
}
impl<'a> DerIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}
impl<'a> Iterator for DerIter<'a> {
    type Item = Der<'a>;
    fn next(&mut self) -> Option<Der<'a>> {
        if self.data.is_empty() {
            return None;
        }
        let (d, n) = der_one(self.data).ok()?;
        self.data = &self.data[n..];
        Some(d)
    }
}

/// Parse an X.509 Time (UTCTime 0x17 or GeneralizedTime 0x18, in Zulu) to Unix seconds.
fn parse_time(d: &Der) -> Option<i64> {
    let s = std::str::from_utf8(d.payload).ok()?;
    let (year, rest) = match d.tag {
        0x17 => {
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = rest.get(r)?;
        t.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (mo, day, h, mi) = (num(0..2)?, num(2..4)?, num(4..6)?, num(6..8)?);
    let sec = num(8..10).unwrap_or(0);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&day) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(year, mo, day) * 86400 + h * 3600 + mi * 60 + sec)
}

/// Read (notBefore, notAfter) from a Certificate. Accepts the full DER Certificate (v2/v3) or
/// just its body, the TBSCertificate + algorithm + signature items (the v1 path).
fn cert_validity(cert: &[u8]) -> Option<(i64, i64)> {
    let (first, _) = der_one(cert).ok()?;
    let tbs = match DerIter::new(first.payload).next() {
        Some(inner) if inner.tag == 0x30 => inner,
        _ => first,
    };
    let mut f = DerIter::new(tbs.payload).peekable();
    if f.peek()?.tag == 0xA0 {
        f.next(); // [0] version
    }
    // serial, signature algorithm, issuer, then validity
    let validity = f.nth(3)?;
    let mut t = DerIter::new(validity.payload);
    Some((parse_time(&t.next()?)?, parse_time(&t.next()?)?))
}

/// Debug flag and validity window for one certificate.
fn cert_meta(cert: &[u8], cn: Option<&str>) -> (bool, Option<i64>, Option<i64>) {
    let v = cert_validity(cert);
    let debug = cn.is_some_and(|c| c.eq_ignore_ascii_case("Android Debug"));
    (debug, v.map(|v| v.0), v.map(|v| v.1))
}

// --- Certificate signature algorithm and RSA key size ---
//
// OID value bytes (the content octets of the OID, without the 0x06 tag or length) for the
// signature algorithms we recognise (RFC 8017 / 5754):
//   1.2.840.113549.1.1.4  md5WithRSAEncryption
//   1.2.840.113549.1.1.5  sha1WithRSAEncryption
//   1.2.840.113549.1.1.11 sha256WithRSAEncryption
//   1.2.840.113549.1.1.12 sha384WithRSAEncryption
//   1.2.840.113549.1.1.13 sha512WithRSAEncryption
//   1.2.840.10040.4.3     dsaWithSHA1
//   1.2.840.10045.4.1     ecdsaWithSHA1
//   1.2.840.10045.4.3.2   ecdsaWithSHA256
//   1.2.840.10045.4.3.3   ecdsaWithSHA384
//   1.2.840.10045.4.3.4   ecdsaWithSHA512
// rsaEncryption (1.2.840.113549.1.1.1) value bytes: 2a 86 48 86 f7 0d 01 01 01
const RSA_E_KEY: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

/// Read the outer Certificate's signatureAlgorithm OID from a DER X.509 cert and return its
/// name. The outer Certificate is `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`,
/// so the second element's AlgorithmIdentifier SEQUENCE contains the OID.
pub fn cert_sig_alg(cert: &[u8]) -> Option<&'static str> {
    let (outer, _) = der_one(cert).ok()?;
    if (outer.tag & 0x1F) != 0x10 {
        return None;
    }
    let mut it = DerIter::new(outer.payload);
    let _tbs = it.next()?;
    let sig_alg = it.next()?;
    // sig_alg.payload is the contents of the AlgorithmIdentifier SEQUENCE: OID followed by
    // optional parameters. The first element is the OID (tag 0x06).
    let mut params = DerIter::new(sig_alg.payload);
    let oid = params.next()?;
    if oid.tag != 0x06 {
        return None;
    }
    match oid.payload {
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04" => Some("md5WithRSAEncryption"),
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05" => Some("sha1WithRSAEncryption"),
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b" => Some("sha256WithRSAEncryption"),
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c" => Some("sha384WithRSAEncryption"),
        b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d" => Some("sha512WithRSAEncryption"),
        b"\x2a\x86\x48\xce\x38\x04\x03" => Some("dsaWithSHA1"),
        b"\x2a\x86\x48\xce\x3d\x04\x01" => Some("ecdsaWithSHA1"),
        b"\x2a\x86\x48\xce\x3d\x04\x03\x02" => Some("ecdsaWithSHA256"),
        b"\x2a\x86\x48\xce\x3d\x04\x03\x03" => Some("ecdsaWithSHA384"),
        b"\x2a\x86\x48\xce\x3d\x04\x03\x04" => Some("ecdsaWithSHA512"),
        _ => None,
    }
}

/// Decode the RSA modulus bit length from a DER X.509 certificate's subjectPublicKeyInfo,
/// when the key algorithm is rsaEncryption (1.2.840.113549.1.1.1).
pub fn cert_rsa_bits(cert: &[u8]) -> Option<u32> {
    let (outer, _) = der_one(cert).ok()?;
    if (outer.tag & 0x1F) != 0x10 {
        return None;
    }
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut top = DerIter::new(outer.payload);
    let tbs = top.next()?;
    if (tbs.tag & 0x1F) != 0x10 {
        return None;
    }
    // TBSCertificate ::= SEQUENCE { [0] version, serial, signature, issuer, validity,
    //   subject, subjectPublicKeyInfo, ... }
    // Skip [0] version if present (tag 0xA0), then iterate serial/signature/issuer/validity/subject/SPKI.
    let mut tbs_payload = tbs.payload;
    if let Ok((first, consumed)) = der_one(tbs_payload)
        && first.tag == 0xA0
    {
        tbs_payload = &tbs_payload[consumed..];
    }
    let mut tbs_fields = DerIter::new(tbs_payload);
    let _serial = tbs_fields.next()?;
    let _sig_alg = tbs_fields.next()?;
    let _issuer = tbs_fields.next()?;
    let _validity = tbs_fields.next()?;
    let _subject = tbs_fields.next()?;
    let spki = tbs_fields.next()?;
    if (spki.tag & 0x1F) != 0x10 {
        return None;
    }
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let mut spki_fields = DerIter::new(spki.payload);
    let algo = spki_fields.next()?;
    if (algo.tag & 0x1F) != 0x10 {
        return None;
    }
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters }
    let mut algo_fields = DerIter::new(algo.payload);
    let key_oid_el = algo_fields.next()?;
    if key_oid_el.tag != 0x06 {
        return None;
    }
    if key_oid_el.payload != RSA_E_KEY {
        return None; // not an RSA key
    }
    let bit_string = spki_fields.next()?;
    if bit_string.tag != 0x03 {
        return None;
    }
    // The BIT STRING payload is: unused-bits byte (1) + RSAPublicKey DER.
    let bs_payload = &bit_string.payload;
    if bs_payload.is_empty() {
        return None;
    }
    let rsa = &bs_payload[1..]; // skip unused-bits byte
    let (rsa_seq, _) = der_one(rsa).ok()?;
    if (rsa_seq.tag & 0x1F) != 0x10 {
        return None;
    }
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let mut rsa_fields = DerIter::new(rsa_seq.payload);
    let modulus = rsa_fields.next()?;
    if modulus.tag != 0x02 {
        return None;
    }
    // A modulus is an unsigned big-endian INTEGER; a leading 0x00 byte may be present as a
    // sign marker. Ignore it when computing the bit length.
    let mut m = modulus.payload;
    if m.first() == Some(&0x00) {
        m = &m[1..];
    }
    let bits = m.len() * 8;
    // Subtract leading zero bytes that aren't part of the value.
    let mut leading = 0usize;
    for b in m {
        if *b == 0 {
            leading += 1;
        } else {
            break;
        }
    }
    Some((bits - leading * 8) as u32)
}

/// Extract the CN from an X.509 certificate.
///
/// Walks the DER tree looking for the commonName attribute OID (2.5.4.3, encoded
/// `55 04 03`) and returns the printable string that follows it. A positional walk of
/// Name/RDN would depend on field ordering; searching for the OID does not.
fn extract_cn_from_cert(cert_body: &[u8]) -> Option<String> {
    find_cn(cert_body, 0)
}

/// Depth-first search for a CN attribute, bounded so a hostile certificate cannot
/// make this expensive.
fn find_cn(buf: &[u8], depth: usize) -> Option<String> {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return None;
    }
    let mut at = 0usize;
    while at + 2 <= buf.len() {
        let tag = buf[at];
        if tag & 0x1F == 0x1F {
            return None; // high-tag-number form: not something we need to walk into
        }
        let (len, hdr) = match der_len(&buf[at + 1..]) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let body = at + 1 + hdr;
        let end = body.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        // An AttributeTypeAndValue is SEQUENCE { OID, value }. Recognize it structurally.
        if tag == 0x06 && buf[body..end] == [0x55, 0x04, 0x03] && end < buf.len() {
            let vt = buf[end];
            let (vlen, vhdr) = der_len(&buf[end + 1..]).ok()?;
            let vstart = end + 1 + vhdr;
            if (vt & 0x1F) == 0x0C || vt == 0x13 || vt == 0x16 {
                // UTF8String, PrintableString, IA5String
                return Some(String::from_utf8_lossy(&buf[vstart..vstart + vlen]).into_owned());
            }
            if vt == 0x1E {
                // BMPString: UTF-16BE
                let raw = &buf[vstart..vstart + vlen];
                let mut units: Vec<u16> = Vec::with_capacity(raw.len() / 2);
                let mut i = 0;
                while i + 1 < raw.len() {
                    units.push(u16::from_be_bytes([raw[i], raw[i + 1]]));
                    i += 2;
                }
                return String::from_utf16(&units).ok();
            }
        }
        if tag & 0x20 != 0 {
            // Constructed: descend.
            if let Some(found) = find_cn(&buf[body..end], depth + 1) {
                return Some(found);
            }
        }
        at = end;
    }
    None
}

/// Decode a DER length starting at `at`, returning (value, bytes consumed including tag-len).
/// (CN, SHA-256 hex, certificate bytes) for one PKCS#7 certificate.
type P7Cert = (String, Option<String>, Vec<u8>);

/// Extract signer certificates from PKCS#7 SignedData.
fn extract_pkcs7_certs(p7_der: &[u8]) -> Result<Vec<P7Cert>> {
    let ci = der_one(p7_der)?.0;
    ensure!((ci.tag & 0x1F) == 0x10, "pkcs7: not a SEQUENCE");
    let mut ci_fields = DerIter::new(ci.payload);
    let _ = ci_fields.next(); // contentType OID
    let content = ci_fields.next();
    let content = match content {
        Some(d) if (d.tag & 0x1F) == 0x00 && (d.tag & 0x80) != 0 => d, // [0] context
        _ => bail!("pkcs7: content not at [0]"),
    };
    let (sd, _) = der_one(content.payload)?;
    ensure!((sd.tag & 0x1F) == 0x10, "pkcs7: signed data not SEQUENCE");
    // SignedData fields are version, digestAlgorithms, encapContentInfo and then optionally
    // certificates and crls. encapContentInfo is absent in many signatures, so find the
    // certificates SET by shape rather than by position.
    // certificates is [0] IMPLICIT SET OF Certificate, so its DER tag is 0xA0. Matching a
    // plain SET (0x31) finds digestAlgorithms instead, which is a few bytes long.
    let mut certs = None;
    for f in DerIter::new(sd.payload) {
        if f.tag == 0xA0 {
            certs = Some(f);
            break;
        }
    }
    let mut result = Vec::new();
    if let Some(certs_set) = certs {
        // SET
        for cert_wrapped in DerIter::new(certs_set.payload) {
            let cert_der = if cert_wrapped.tag == 0xA0 {
                der_one(cert_wrapped.payload)?.0.payload
            } else if (cert_wrapped.tag & 0x1F) == 0x10 {
                cert_wrapped.payload
            } else {
                continue;
            };
            let cn = extract_cn_from_cert(cert_der);
            let digest = Sha256::digest(cert_der)
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            result.push((cn.unwrap_or_default(), Some(digest), cert_der.to_vec()));
        }
    }
    Ok(result)
}

// --- APK Signature Scheme v2/v3 signing block (AOSP apk_signature_scheme.h) ---
//
// The signing block sits between the zip entries and the End Of Central Directory
// record. It is bracketed by the 16-byte magic below (as a "footer" right before the
// EOCD and again as the "header" at the start of the block) plus uint64 block-size
// fields. Inside are length-prefixed entries tagged by their 32-bit ID:
//   0x7109871a == APK Signature Scheme v2 block
//   0xf05368c0 == APK Signature Scheme v3 block (0x1b93ad61 is v3.1)
// (AOSP, Apache-2.0.)
const V2_BLOCK_ID: u32 = 0x7109871a;
const V3_BLOCK_ID: u32 = 0xf05368c0;
/// The zip End Of Central Directory record signature (AOSP, Apache-2.0).
const EOCD_SIG: u32 = 0x06054b50;
const EOCD_MIN_SIZE: usize = 22;

// --- Entry points ---

/// Read one APK from `path` and audit it.
///
/// Never executes anything: the APK is only read as a ZIP, its binary AndroidManifest.xml is
/// parsed, and its v1 META-INF certificates are decoded. An unreadable or malformed APK
/// comes back as `ApkAudit::error`, never a panic and never a silent skip.
/// Audit an in-memory APK.
pub fn audit_apk_bytes(path: &Path, bytes: &[u8]) -> ApkAudit {
    let r = (|| -> Result<ApkInfo> {
        let mut zip = ZipArchive::new(Cursor::new(bytes)).context("not a valid zip")?;
        let attrs = match read_entry(&mut zip, "AndroidManifest.xml") {
            Some(b) => parse_manifest(&b).ok(),
            None => None,
        };
        let mut signers = Vec::new();
        let names: Vec<String> = zip.file_names().map(String::from).collect();
        for name in names {
            let upper = name.to_ascii_uppercase();
            if !(upper.starts_with("META-INF/")
                && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC")))
            {
                continue;
            }
            let Some(der) = read_entry(&mut zip, &name) else {
                continue;
            };
            let Ok(certs) = extract_pkcs7_certs(&der) else {
                continue;
            };
            for (cn, sha, cert) in certs {
                let (is_debug_cert, not_before, not_after) = cert_meta(&cert, Some(&cn));
                signers.push(Signer {
                    scheme: "v1",
                    cert_sha256: sha.unwrap_or_default(),
                    subject_cn: Some(cn.clone()),
                    is_aosp_test_key: AOSP_TEST_KEY_SUBJECTS.iter().any(|t| cn.contains(t)),
                    is_debug_cert,
                    not_before,
                    not_after,
                    sig_alg: cert_sig_alg(&cert),
                    rsa_bits: cert_rsa_bits(&cert),
                });
            }
        }
        signers.extend(v2_signers(bytes));
        let activities = attrs.as_ref().map_or(0, |a| {
            a.components.iter().filter(|c| c.kind == "activity").count()
        });
        let mut code_issues = code_issues(&mut zip, activities);
        code_issues.extend(native_issues(&mut zip));
        Ok(ApkInfo {
            path: path.display().to_string(),
            package_name: attrs
                .as_ref()
                .map(|a| a.package_name.clone())
                .unwrap_or_default(),
            version_code: attrs.as_ref().and_then(|a| a.version_code.clone()),
            version_name: attrs.as_ref().and_then(|a| a.version_name.clone()),
            signers,
            verification: verify_apk(bytes),
            manifest: attrs.unwrap_or_default(),
            code_issues,
        })
    })();
    match r {
        Ok(info) => ApkAudit {
            info: Some(info),
            error: None,
        },
        Err(e) => ApkAudit {
            info: None,
            error: Some(format!("{e:#}")),
        },
    }
}

/// Largest dex and total dex bytes the code rules will parse out of one APK.
const MAX_DEX_ENTRY: u64 = 32 * 1024 * 1024;
const MAX_DEX_TOTAL: u64 = 64 * 1024 * 1024;

/// Run the code rules over the APK's `classes*.dex`. A dex that cannot be read or parsed is said
/// so (`apk-code-unscanned`), never skipped as if it were clean.
fn code_issues(zip: &mut ZipArchive<Cursor<&[u8]>>, activities: usize) -> Vec<ManifestIssue> {
    let mut names: Vec<String> = zip
        .file_names()
        .filter(|n| {
            n.strip_prefix("classes")
                .and_then(|r| r.strip_suffix(".dex"))
                .is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(String::from)
        .collect();
    names.sort();
    let (mut dexes, mut failed, mut total) = (Vec::new(), Vec::new(), 0u64);
    for n in names {
        let bytes = zip.by_name(&n).ok().and_then(|f| {
            total += f.size();
            (f.size() <= MAX_DEX_ENTRY && total <= MAX_DEX_TOTAL).then(|| {
                let mut v = Vec::new();
                f.take(MAX_DEX_ENTRY).read_to_end(&mut v).ok().map(|_| v)
            })?
        });
        match bytes.map(|b| (crate::dex::parse(&n, &b), b)) {
            Some((Ok(d), b)) => dexes.push((d, b)),
            Some((Err(e), _)) => failed.push(format!("{n}: {e:#}")),
            None => failed.push(format!("{n}: too large or unreadable")),
        }
    }
    if dexes.is_empty() && failed.is_empty() {
        return Vec::new(); // no dex (a native-only APK): nothing to judge
    }
    let mut out = rules::scan(&dexes, activities);
    if !failed.is_empty() {
        out.push(ManifestIssue {
            rule: "apk-code-unscanned",
            severity: Severity::Info,
            detail: format!("code rules did not run on {}", failed.join("; ")),
        });
    }
    out
}

/// Largest single `.so` and total `.so` bytes the native rules will inspect in one APK.
const MAX_SO_ENTRY: u64 = 32 * 1024 * 1024;
const MAX_SO_TOTAL: u64 = 128 * 1024 * 1024;

/// Run the ELF hardening rules over the APK's `lib/<abi>/*.so` entries.
fn native_issues(zip: &mut ZipArchive<Cursor<&[u8]>>) -> Vec<ManifestIssue> {
    let mut names: Vec<String> = zip
        .file_names()
        .filter(|n| n.starts_with("lib/") && n.ends_with(".so"))
        .map(String::from)
        .collect();
    names.sort();
    let mut total: u64 = 0;
    // Collect per-rule: (rule_id, severity, reason, Vec<entry_names>)
    let mut per_rule: Vec<(&'static str, Severity, &'static str, Vec<String>)> = Vec::new();
    for n in names {
        let ok_size = zip
            .by_name(&n)
            .map(|f| f.size())
            .map(|s| {
                total += s;
                s <= MAX_SO_ENTRY && total <= MAX_SO_TOTAL
            })
            .unwrap_or(false);
        if !ok_size {
            continue;
        }
        let bytes = zip.by_name(&n).ok().and_then(|mut f| {
            let mut v = Vec::new();
            f.read_to_end(&mut v).ok().map(|_| v)
        });
        let Some(bytes) = bytes else {
            continue;
        };
        if !bytes.starts_with(b"\x7fELF") {
            continue;
        }
        let Ok(Some(info)) = crate::elf::parse(&bytes) else {
            continue;
        };
        for (sev, rule, reason) in crate::elf::issues(&info) {
            let pos = per_rule.iter().position(|(r, _, _, _)| *r == rule);
            if let Some(p) = pos {
                per_rule[p].3.push(n.clone());
            } else {
                per_rule.push((rule, sev, reason, vec![n.clone()]));
            }
        }
    }
    per_rule
        .into_iter()
        .map(|(rule, severity, reason, names)| {
            let count = names.len();
            let label = if count == 1 { "library" } else { "libraries" };
            let list = if count <= 5 {
                names.join(", ")
            } else {
                format!("{} (+{} more)", names[..5].join(", "), count - 5)
            };
            ManifestIssue {
                rule,
                severity,
                detail: format!("{count} native {label}: {list}: {reason}"),
            }
        })
        .collect()
}

/// Read one entry out of the archive, refusing anything over the per-entry limit.
fn read_entry(zip: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<Vec<u8>> {
    let f = zip.by_name(name).ok()?;
    if f.size() as usize > MAX_ENTRY_BYTES {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_ENTRY_BYTES as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Find the APK Signing Block and return the signed-data bytes it certifies.
///
/// Layout (AOSP apk_signature_scheme.h, Apache-2.0):
///
///   ... zip entries ... | uint64 size of block | pairs | uint64 size of block |
///   16-byte magic | zip EOCD
///
/// Each pair is `uint64 length` followed by `uint32 id` and that many bytes of value.
/// The signed data the signers cover is the concatenation of the three EOCD-present
/// regions, so we recover it by locating the block and slicing around it.
fn v2_signers(bytes: &[u8]) -> Vec<Signer> {
    let Some(block) = signing_block(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, value) in block {
        let scheme = match id {
            V2_BLOCK_ID => "v2",
            V3_BLOCK_ID => "v3",
            _ => continue,
        };
        for s in signers_in_block(value) {
            out.push(Signer { scheme, ..s });
        }
    }
    out
}

/// The signing block pairs: (block id, value bytes).
fn signing_block(bytes: &[u8]) -> Option<Vec<(u32, &[u8])>> {
    locate_block(bytes).map(|b| b.pairs)
}

/// Where the signing block sits, and its pairs.
struct Block<'a> {
    /// Offset of the block's leading size field (the end of the signed entries).
    start: usize,
    cd_off: usize,
    eocd: usize,
    pairs: Vec<(u32, &'a [u8])>,
}

fn locate_block(bytes: &[u8]) -> Option<Block<'_>> {
    if bytes.len() < EOCD_MIN_SIZE + 2 * 8 + MAGIC_LEN {
        return None;
    }
    // The block sits immediately before the zip central directory (not before the EOCD):
    //   entries | size | pairs | size | magic | central directory | EOCD
    // The EOCD can carry a trailing comment, so find it by scanning back from the end.
    let tail = bytes.len().saturating_sub(EOCD_MIN_SIZE + 0xFFFF);
    let eocd = (tail..=bytes.len() - EOCD_MIN_SIZE)
        .rev()
        .find(|&i| le32(bytes, i).ok() == Some(EOCD_SIG))?;
    let cd_off = le32(bytes, eocd + 16).ok()? as usize;
    if cd_off > eocd {
        return None;
    }
    let magic_at = cd_off.checked_sub(MAGIC_LEN)?;
    if bytes[magic_at..magic_at + MAGIC_LEN] != MAGIC {
        return None;
    }
    let size_at = magic_at.checked_sub(8)?;
    // The block size counts the pairs plus the trailing size field and magic (24 bytes).
    let block_size = le64(bytes, size_at).ok()? as usize;
    if block_size < 24 {
        return None;
    }
    let block_start = size_at.checked_sub(block_size - 24)?.checked_sub(8)?;
    let mut out = Vec::new();
    let mut at = block_start + 8; // skip the leading size field
    let end = size_at;
    while at + 12 <= end {
        let len = le64(bytes, at).ok()? as usize;
        if len < 4 || at.checked_add(8 + len).is_none_or(|e| e > end) {
            break;
        }
        let id = le32(bytes, at + 8).ok()?;
        let vstart = at + 12;
        let vend = vstart + len - 4;
        out.push((id, &bytes[vstart..vend]));
        at += 8 + len;
    }
    Some(Block {
        start: block_start,
        cd_off,
        eocd,
        pairs: out,
    })
}

/// Extract signers from one v2/v3 block value: a length-prefixed sequence of length-prefixed
/// signers.
fn signers_in_block(value: &[u8]) -> Vec<Signer> {
    let mut out = Vec::new();
    let Some(seq) = lp(value, &mut 0) else {
        return out;
    };
    let mut at = 0;
    while let Some(signer) = lp(seq, &mut at) {
        out.extend(signer_from(signer));
    }
    out
}

/// A uint32-length-prefixed field at `*at`, advancing past it.
fn lp<'a>(data: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = le32(data, *at).ok()? as usize;
    let end = (*at).checked_add(4)?.checked_add(len)?;
    let out = data.get(*at + 4..end)?;
    *at = end;
    Some(out)
}

/// One v2/v3 signer: `signed data | signatures | public key`, each length-prefixed. The signed
/// data holds `digests | certificates | ...`, and the first certificate is the signer's own.
fn signer_from(signer: &[u8]) -> Option<Signer> {
    let signed = lp(signer, &mut 0)?;
    let mut at = 0;
    lp(signed, &mut at)?; // digests
    let certs = lp(signed, &mut at)?;
    let der = lp(certs, &mut 0)?;
    let cn = extract_cn_from_cert(der);
    let (is_debug_cert, not_before, not_after) = cert_meta(der, cn.as_deref());
    Some(Signer {
        scheme: "v2",
        cert_sha256: Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        is_aosp_test_key: cn
            .as_deref()
            .is_some_and(|c| AOSP_TEST_KEY_SUBJECTS.iter().any(|t| c.contains(t))),
        subject_cn: cn,
        is_debug_cert,
        not_before,
        not_after,
        sig_alg: cert_sig_alg(der),
        rsa_bits: cert_rsa_bits(der),
    })
}

/// The 16-byte APK Signing Block magic (AOSP, Apache-2.0).
const MAGIC: [u8; 16] = *b"APK Sig Block 42";
const MAGIC_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal but real APK: a ZIP holding a binary AndroidManifest.xml and a
    /// META-INF signature entry.
    fn apk_bytes(with_manifest: bool) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default();
        if with_manifest {
            w.start_file("AndroidManifest.xml", opt).unwrap();
            w.write_all(b"\x03\x00\x08\x00 fake binary manifest")
                .unwrap();
        }
        w.start_file("META-INF/CERT.RSA", opt).unwrap();
        w.write_all(b"\x30\x82 not really pkcs7").unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn an_apk_is_parsed_rather_than_reported_unreadable() {
        let a = audit_apk_bytes(std::path::Path::new("/system/app/X.apk"), &apk_bytes(true));
        assert!(a.error.is_none(), "{:?}", a.error);
        let info = a.info.expect("info");
        assert_eq!(info.path, "/system/app/X.apk");
    }

    #[test]
    fn an_apk_with_no_manifest_still_parses_without_error() {
        let a = audit_apk_bytes(std::path::Path::new("/x.apk"), &apk_bytes(false));
        assert!(a.error.is_none(), "{:?}", a.error);
        assert!(a.info.expect("info").package_name.is_empty());
    }

    #[test]
    fn a_file_that_is_not_a_zip_is_reported_not_panicked_on() {
        let a = audit_apk_bytes(std::path::Path::new("/x.apk"), b"definitely not a zip");
        assert!(a.info.is_none());
        assert!(a.error.is_some(), "an unreadable apk must say so");
    }

    #[test]
    fn a_malformed_certificate_does_not_panic_and_yields_no_signers() {
        let a = audit_apk_bytes(std::path::Path::new("/x.apk"), &apk_bytes(true));
        let info = a.info.expect("info");
        assert!(
            info.signers.is_empty(),
            "garbage DER must not become a signer"
        );
    }

    fn apk_with_dex(dex: &[u8]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default();
        w.start_file("classes.dex", opt).unwrap();
        w.write_all(dex).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn code_rules_run_on_the_dex_of_an_apk_and_a_bad_dex_is_said_not_skipped() {
        let risky = include_bytes!("../tests/fixtures/dex/risky.dex");
        let a = audit_apk_bytes(Path::new("/x.apk"), &apk_with_dex(risky));
        let rules: Vec<_> = a.info.unwrap().issues().iter().map(|i| i.rule).collect();
        assert!(rules.contains(&"apk-code-ssl-trust"), "{rules:?}");
        assert!(!rules.contains(&"apk-code-unscanned"));
        let a = audit_apk_bytes(Path::new("/x.apk"), &apk_with_dex(b"dex\n035\0 truncated"));
        let issues = a.info.unwrap().issues();
        let un = issues
            .iter()
            .find(|i| i.rule == "apk-code-unscanned")
            .expect("unscanned");
        assert!(un.detail.contains("classes.dex"), "{}", un.detail);
        // no dex at all (a native-only APK) is not reported as unscanned
        let a = audit_apk_bytes(Path::new("/x.apk"), &apk_bytes(true));
        assert!(
            a.info
                .unwrap()
                .issues()
                .iter()
                .all(|i| !i.rule.starts_with("apk-code"))
        );
    }

    // --- Synthetic binary-AXML encoder ---

    #[derive(Clone)]
    enum V {
        Bool(bool),
        /// aapt1 style: rawValue is the string "true"/"false" and the typed value is a boolean.
        LegacyBool(bool),
        Int(u32),
        Str(&'static str),
    }
    /// An attribute: (namespace: android or none, local name, value).
    type A = (bool, &'static str, V);
    struct El {
        name: &'static str,
        attrs: Vec<A>,
        kids: Vec<El>,
    }
    fn el(name: &'static str, attrs: Vec<A>, kids: Vec<El>) -> El {
        El { name, attrs, kids }
    }
    fn a(name: &'static str, v: V) -> A {
        (true, name, v)
    }
    fn t() -> V {
        V::Bool(true)
    }
    fn f() -> V {
        V::Bool(false)
    }

    fn u16le(o: &mut Vec<u8>, v: u16) {
        o.extend(v.to_le_bytes());
    }
    fn u32le(o: &mut Vec<u8>, v: u32) {
        o.extend(v.to_le_bytes());
    }
    fn intern(pool: &mut Vec<String>, s: &str) -> u32 {
        match pool.iter().position(|p| p == s) {
            Some(i) => i as u32,
            None => {
                pool.push(s.to_string());
                (pool.len() - 1) as u32
            }
        }
    }

    fn encode_el(e: &El, pool: &mut Vec<String>, out: &mut Vec<u8>, ns: u32) {
        let name = intern(pool, e.name);
        let mut body = Vec::new();
        for (android, n, v) in &e.attrs {
            let n_idx = intern(pool, n);
            let (raw, ty, data) = match v {
                // aapt2 style: rawValue -1, typed boolean 0xFFFFFFFF / 0.
                V::Bool(b) => (u32::MAX, 0x12u8, if *b { u32::MAX } else { 0 }),
                V::LegacyBool(b) => (
                    intern(pool, if *b { "true" } else { "false" }),
                    0x12u8,
                    if *b { u32::MAX } else { 0 },
                ),
                V::Int(i) => (u32::MAX, 0x10, *i),
                V::Str(s) => {
                    let i = intern(pool, s);
                    (i, 0x03, i)
                }
            };
            u32le(&mut body, if *android { ns } else { u32::MAX });
            u32le(&mut body, n_idx);
            u32le(&mut body, raw);
            u16le(&mut body, 8);
            body.push(0);
            body.push(ty);
            u32le(&mut body, data);
        }
        // RES_XML_START_ELEMENT_TYPE: node header (16) + attrExt (20) + attributes.
        u16le(out, 0x0102);
        u16le(out, 16);
        u32le(out, 36 + body.len() as u32);
        u32le(out, 1);
        u32le(out, u32::MAX);
        u32le(out, u32::MAX);
        u32le(out, name);
        u16le(out, 20);
        u16le(out, 20);
        u16le(out, e.attrs.len() as u16);
        out.extend([0u8; 6]);
        out.extend(body);
        for k in &e.kids {
            encode_el(k, pool, out, ns);
        }
        // RES_XML_END_ELEMENT_TYPE.
        u16le(out, 0x0103);
        u16le(out, 16);
        u32le(out, 24);
        u32le(out, 1);
        u32le(out, u32::MAX);
        u32le(out, u32::MAX);
        u32le(out, name);
    }

    /// Encode a whole binary XML document. With `resmap`, android attribute names get their
    /// resource ids in a RES_XML_RESOURCE_MAP chunk, as aapt2 emits.
    fn axml(root: &El, resmap: bool) -> Vec<u8> {
        let mut pool = Vec::new();
        let ns = intern(&mut pool, ANDROID_NS);
        let mut elems = Vec::new();
        encode_el(root, &mut pool, &mut elems, ns);
        let mut sp = Vec::new();
        let mut offs = Vec::new();
        for s in &pool {
            offs.push(sp.len() as u32);
            let u: Vec<u16> = s.encode_utf16().collect();
            u16le(&mut sp, u.len() as u16);
            for c in u {
                u16le(&mut sp, c);
            }
            u16le(&mut sp, 0);
        }
        while sp.len() % 4 != 0 {
            sp.push(0);
        }
        let hdr = 28 + 4 * pool.len();
        let mut pc = Vec::new();
        u16le(&mut pc, 0x0001);
        u16le(&mut pc, 28);
        u32le(&mut pc, (hdr + sp.len()) as u32);
        u32le(&mut pc, pool.len() as u32);
        u32le(&mut pc, 0);
        u32le(&mut pc, 0);
        u32le(&mut pc, hdr as u32);
        u32le(&mut pc, 0);
        for o in offs {
            u32le(&mut pc, o);
        }
        pc.extend(sp);
        let mut body = pc;
        if resmap {
            u16le(&mut body, 0x0180);
            u16le(&mut body, 8);
            u32le(&mut body, 8 + 4 * pool.len() as u32);
            for s in &pool {
                let id = ANDROID_ATTRS
                    .iter()
                    .find(|(_, n)| n == s)
                    .map_or(0, |(i, _)| *i);
                u32le(&mut body, id);
            }
        }
        body.extend(elems);
        let mut out = Vec::new();
        u16le(&mut out, 0x0003);
        u16le(&mut out, 8);
        u32le(&mut out, 8 + body.len() as u32);
        out.extend(body);
        out
    }

    /// Same as `axml`, but with a UTF8_FLAG string pool (aapt2's modern default), to prove the
    /// parser reads that encoding rather than silently misreading it as UTF-16 (issue: a real
    /// UTF-8-pool APK, Netflix.apk, parsed to an empty manifest with no error).
    fn axml_utf8(root: &El, resmap: bool) -> Vec<u8> {
        fn encode_len(out: &mut Vec<u8>, n: usize) {
            if n < 0x80 {
                out.push(n as u8);
            } else {
                out.push(0x80 | ((n >> 8) as u8 & 0x7f));
                out.push((n & 0xff) as u8);
            }
        }
        let mut pool = Vec::new();
        let ns = intern(&mut pool, ANDROID_NS);
        let mut elems = Vec::new();
        encode_el(root, &mut pool, &mut elems, ns);
        let mut sp = Vec::new();
        let mut offs = Vec::new();
        for s in &pool {
            offs.push(sp.len() as u32);
            let utf8 = s.as_bytes();
            encode_len(&mut sp, s.encode_utf16().count()); // UTF-16 char count (unused on read)
            encode_len(&mut sp, utf8.len());
            sp.extend_from_slice(utf8);
            sp.push(0);
        }
        while sp.len() % 4 != 0 {
            sp.push(0);
        }
        let hdr = 28 + 4 * pool.len();
        let mut pc = Vec::new();
        u16le(&mut pc, 0x0001);
        u16le(&mut pc, 28);
        u32le(&mut pc, (hdr + sp.len()) as u32);
        u32le(&mut pc, pool.len() as u32);
        u32le(&mut pc, 0);
        u32le(&mut pc, 0x0100); // UTF8_FLAG
        u32le(&mut pc, hdr as u32);
        u32le(&mut pc, 0);
        for o in offs {
            u32le(&mut pc, o);
        }
        pc.extend(sp);
        let mut body = pc;
        if resmap {
            u16le(&mut body, 0x0180);
            u16le(&mut body, 8);
            u32le(&mut body, 8 + 4 * pool.len() as u32);
            for s in &pool {
                let id = ANDROID_ATTRS
                    .iter()
                    .find(|(_, n)| n == s)
                    .map_or(0, |(i, _)| *i);
                u32le(&mut body, id);
            }
        }
        body.extend(elems);
        let mut out = Vec::new();
        u16le(&mut out, 0x0003);
        u16le(&mut out, 8);
        u32le(&mut out, 8 + body.len() as u32);
        out.extend(body);
        out
    }

    fn apk_with(manifest: &[u8]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file(
            "AndroidManifest.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        w.write_all(manifest).unwrap();
        w.finish().unwrap().into_inner()
    }

    /// `<manifest>` wrapping `<uses-sdk target>` and one `<application>`.
    fn manifest(top: Vec<A>, target: u32, app: Vec<A>, comps: Vec<El>) -> El {
        el(
            "manifest",
            [vec![(false, "package", V::Str("com.example.fx"))], top].concat(),
            vec![
                el(
                    "uses-sdk",
                    vec![a("targetSdkVersion", V::Int(target))],
                    vec![],
                ),
                el("application", app, comps),
            ],
        )
    }

    /// Issues for a manifest, through the real APK path, with and without a resource map.
    fn issues(m: &El) -> Vec<(&'static str, Severity)> {
        let mut seen: Vec<Vec<(&'static str, Severity)>> = Vec::new();
        for resmap in [true, false] {
            let r = audit_apk_bytes(Path::new("/x.apk"), &apk_with(&axml(m, resmap)));
            assert!(r.error.is_none(), "{:?}", r.error);
            let info = r.info.unwrap();
            assert_eq!(info.package_name, "com.example.fx");
            seen.push(info.issues().iter().map(|i| (i.rule, i.severity)).collect());
        }
        assert_eq!(seen[0], seen[1], "resource-map and name-only paths agree");
        seen.remove(0)
    }
    fn comp(kind: &'static str, attrs: Vec<A>, kids: Vec<El>) -> El {
        el(kind, [vec![a("name", V::Str(".C"))], attrs].concat(), kids)
    }
    fn filter(action: &'static str) -> El {
        el(
            "intent-filter",
            vec![],
            vec![el("action", vec![a("name", V::Str(action))], vec![])],
        )
    }

    #[test]
    fn utf8_flagged_string_pool_is_read_correctly() {
        // A real APK (Netflix.apk, encountered auditing a firmware image) ships a manifest
        // whose string pool has UTF8_FLAG set. Reading it as UTF-16 silently garbles every tag
        // and attribute name: no bounds are violated, so parsing "succeeds" with an empty
        // package name and zero components, no error anywhere.
        let m = manifest(
            vec![],
            33,
            vec![],
            vec![comp(
                "activity",
                vec![a("exported", t())],
                vec![filter("android.intent.action.MAIN")],
            )],
        );
        let utf16_bytes = axml(&m, true);
        let utf8_bytes = axml_utf8(&m, true);
        for (label, bytes) in [("utf16", utf16_bytes), ("utf8", utf8_bytes)] {
            let r = audit_apk_bytes(Path::new("/x.apk"), &apk_with(&bytes));
            let info = r.info.unwrap_or_else(|| panic!("{label}: {:?}", r.error));
            assert_eq!(info.package_name, "com.example.fx", "{label}");
            assert_eq!(info.manifest.components.len(), 1, "{label}");
            assert_eq!(info.manifest.components[0].kind, "activity", "{label}");
            assert_eq!(
                info.manifest.components[0].intent_filters[0].actions,
                ["android.intent.action.MAIN"],
                "{label}"
            );
        }
    }

    #[test]
    fn intent_filter_actions_categories_and_data_are_extracted() {
        let custom_filter = el(
            "intent-filter",
            vec![],
            vec![
                el(
                    "action",
                    vec![a("name", V::Str("com.example.CUSTOM"))],
                    vec![],
                ),
                el(
                    "category",
                    vec![a("name", V::Str("android.intent.category.DEFAULT"))],
                    vec![],
                ),
                el(
                    "data",
                    vec![
                        a("scheme", V::Str("myapp")),
                        a("host", V::Str("open")),
                        a("path", V::Str("/x")),
                    ],
                    vec![],
                ),
            ],
        );
        // Two intent-filters on the same component must stay separate: a data spec on the
        // second filter must never leak onto the first's actions.
        let m = manifest(
            vec![],
            33,
            vec![],
            vec![comp(
                "activity",
                vec![],
                vec![filter("android.intent.action.MAIN"), custom_filter],
            )],
        );
        for resmap in [true, false] {
            let r = audit_apk_bytes(Path::new("/x.apk"), &apk_with(&axml(&m, resmap)));
            let info = r.info.unwrap();
            let c = &info.manifest.components[0];
            assert!(c.main_action, "resmap={resmap}");
            assert_eq!(c.intent_filters.len(), 2, "resmap={resmap}");
            assert_eq!(c.intent_filters[0].actions, ["android.intent.action.MAIN"]);
            assert_eq!(c.intent_filters[0].data, [], "MAIN filter has no data");
            assert_eq!(c.intent_filters[1].actions, ["com.example.CUSTOM"]);
            assert_eq!(
                c.intent_filters[1].categories,
                ["android.intent.category.DEFAULT"]
            );
            assert_eq!(
                c.intent_filters[1].data,
                [IntentData {
                    scheme: Some("myapp".to_string()),
                    host: Some("open".to_string()),
                    port: None,
                    path: Some("/x".to_string()),
                    mime_type: None,
                }]
            );
        }
    }

    #[test]
    fn task_hijacking_attributes_are_reported() {
        let has = |m: &El, rule: &str| {
            issues(m)
                .iter()
                .any(|(r, s)| *r == rule && *s == Severity::Medium)
        };
        let single = manifest(
            vec![],
            27,
            vec![],
            vec![comp(
                "activity",
                vec![a("exported", f()), a("launchMode", V::Int(2))],
                vec![],
            )],
        );
        assert!(has(&single, "apk-launch-mode-singletask"));
        let instance = manifest(
            vec![],
            27,
            vec![],
            vec![comp(
                "activity",
                vec![a("exported", f()), a("launchMode", V::Int(3))],
                vec![],
            )],
        );
        assert!(has(&instance, "apk-launch-mode-singletask"));
        let affinity = manifest(
            vec![],
            27,
            vec![],
            vec![comp(
                "activity",
                vec![
                    a("exported", f()),
                    a("taskAffinity", V::Str("com.evil.task")),
                ],
                vec![],
            )],
        );
        assert!(has(&affinity, "apk-task-affinity"));
        let reparent = manifest(vec![], 27, vec![a("allowTaskReparenting", t())], vec![]);
        assert!(has(&reparent, "apk-task-reparenting"));
        // standard launch mode, the empty-affinity mitigation, no reparenting: none of the three
        let clean = manifest(
            vec![],
            27,
            vec![a("taskAffinity", V::Str(""))],
            vec![comp(
                "activity",
                vec![
                    a("exported", f()),
                    a("launchMode", V::Int(0)),
                    a("taskAffinity", V::Str("")),
                ],
                vec![],
            )],
        );
        let rules: Vec<_> = issues(&clean).into_iter().map(|(r, _)| r).collect();
        for r in [
            "apk-launch-mode-singletask",
            "apk-task-affinity",
            "apk-task-reparenting",
        ] {
            assert!(!rules.contains(&r), "{r} in {rules:?}");
        }
    }

    #[test]
    fn framework_attribute_ids_match_android_r_attr() {
        // android.R.attr values from android-36/android.jar
        for (id, name) in [
            (0x0101_002a, "path"),
            (0x0101_002b, "pathPrefix"),
            (0x0101_002c, "pathPattern"),
            (0x0101_001b, "grantUriPermissions"),
            (0x0101_0026, "mimeType"),
            (0x0101_0027, "scheme"),
            (0x0101_0028, "host"),
            (0x0101_0029, "port"),
        ] {
            assert!(
                ANDROID_ATTRS.contains(&(id, name)),
                "{name} must be {id:#x}"
            );
        }
    }

    #[test]
    fn provider_uri_grants_and_broad_paths_are_reported() {
        let has = |m: &El, rule: &str| issues(m).iter().any(|(r, _)| *r == rule);
        let grant = manifest(
            vec![],
            33,
            vec![],
            vec![comp(
                "provider",
                vec![a("exported", f()), a("grantUriPermissions", t())],
                vec![],
            )],
        );
        assert!(has(&grant, "apk-provider-grant-uri"));
        let broad_grant = manifest(
            vec![],
            33,
            vec![],
            vec![comp(
                "provider",
                vec![a("exported", f())],
                vec![el(
                    "grant-uri-permission",
                    vec![a("pathPrefix", V::Str("/"))],
                    vec![],
                )],
            )],
        );
        assert!(has(&broad_grant, "apk-provider-broad-path"));
        let broad_perm = manifest(
            vec![],
            33,
            vec![],
            vec![comp(
                "provider",
                vec![a("exported", f())],
                vec![el("path-permission", vec![a("path", V::Str("/"))], vec![])],
            )],
        );
        assert!(has(&broad_perm, "apk-provider-broad-path"));
        let narrow = manifest(
            vec![],
            33,
            vec![],
            vec![comp(
                "provider",
                vec![a("exported", f())],
                vec![el(
                    "grant-uri-permission",
                    vec![a("pathPrefix", V::Str("/shared/"))],
                    vec![],
                )],
            )],
        );
        assert!(
            !has(&narrow, "apk-provider-broad-path") && !has(&narrow, "apk-provider-grant-uri")
        );
    }

    #[test]
    fn exported_component_guarded_by_a_weak_permission_is_reported() {
        let has = |m: &El, rule: &str| issues(m).iter().any(|(r, _)| *r == rule);
        // <permission name=P protectionLevel=L/> next to <application>, one exported service guarded by P.
        let with_level = |level: u32| {
            el(
                "manifest",
                vec![(false, "package", V::Str("com.example.fx"))],
                vec![
                    el("uses-sdk", vec![a("targetSdkVersion", V::Int(33))], vec![]),
                    el(
                        "permission",
                        vec![
                            a("name", V::Str("com.example.fx.SYNC")),
                            a("protectionLevel", V::Int(level)),
                        ],
                        vec![],
                    ),
                    el(
                        "application",
                        vec![],
                        vec![comp(
                            "service",
                            vec![
                                a("exported", t()),
                                a("permission", V::Str("com.example.fx.SYNC")),
                            ],
                            vec![],
                        )],
                    ),
                ],
            )
        };
        assert!(
            has(&with_level(0), "apk-exported-weak-permission"),
            "normal"
        );
        assert!(
            has(&with_level(1), "apk-exported-weak-permission"),
            "dangerous"
        );
        assert!(
            !has(&with_level(2), "apk-exported-weak-permission"),
            "signature"
        );
        // flags above the base level do not change it: signature|privileged (0x12) is still signature
        assert!(
            !has(&with_level(0x12), "apk-exported-weak-permission"),
            "signature|privileged"
        );
        // the guard keeps the component out of the unguarded-export rules either way
        assert!(!has(&with_level(0), "apk-exported-component"));
    }

    #[test]
    fn custom_permissions_without_signature_and_an_old_min_sdk_are_reported() {
        let has = |m: &El, rule: &str| issues(m).iter().any(|(r, _)| *r == rule);
        let app = |min: u32, levels: &[u32]| {
            let mut kids = vec![el(
                "uses-sdk",
                vec![
                    a("minSdkVersion", V::Int(min)),
                    a("targetSdkVersion", V::Int(34)),
                ],
                vec![],
            )];
            for (i, level) in levels.iter().enumerate() {
                let name: &'static str =
                    ["com.example.fx.A", "com.example.fx.B", "com.example.fx.C"][i];
                kids.push(el(
                    "permission",
                    vec![
                        a("name", V::Str(name)),
                        a("protectionLevel", V::Int(*level)),
                    ],
                    vec![],
                ));
            }
            kids.push(el("application", vec![], vec![]));
            el(
                "manifest",
                vec![(false, "package", V::Str("com.example.fx"))],
                kids,
            )
        };
        // normal (0) and dangerous (1) custom permissions are reported once, together; signature (2, 0x12) is not
        let weak = issues(&app(26, &[0, 1, 0x12]));
        assert_eq!(
            weak.iter()
                .filter(|(r, _)| *r == "apk-custom-permission-weak")
                .count(),
            1
        );
        assert!(!has(&app(26, &[2, 0x12]), "apk-custom-permission-weak"));
        // minSdkVersion below 23 (before runtime permissions) is reported; 23 is not
        assert!(has(&app(22, &[]), "apk-min-sdk-old"));
        assert!(!has(&app(23, &[]), "apk-min-sdk-old"));
    }

    #[test]
    fn intent_priority_sms_port_secret_code_and_direct_boot_are_reported() {
        let has = |m: &El, rule: &str| issues(m).iter().any(|(r, _)| *r == rule);
        let action = |n: &'static str| el("action", vec![a("name", V::Str(n))], vec![]);
        let receiver = |filter_attrs: Vec<A>, kids: Vec<El>| {
            manifest(
                vec![],
                33,
                vec![],
                vec![comp(
                    "receiver",
                    vec![
                        a("exported", t()),
                        a("permission", V::Str("com.example.fx.GUARD")),
                    ],
                    vec![el("intent-filter", filter_attrs, kids)],
                )],
            )
        };
        // a filter priority above 100 jumps the ordered-broadcast queue; 100 does not
        let sms = || action("android.provider.Telephony.SMS_RECEIVED");
        assert!(has(
            &receiver(vec![a("priority", V::Int(999))], vec![sms()]),
            "apk-intent-priority-high"
        ));
        assert!(!has(
            &receiver(vec![a("priority", V::Int(100))], vec![sms()]),
            "apk-intent-priority-high"
        ));
        // a data-SMS receiver bound to a port
        let data_sms = receiver(
            vec![],
            vec![
                action("android.intent.action.DATA_SMS_RECEIVED"),
                el(
                    "data",
                    vec![a("scheme", V::Str("sms")), a("port", V::Str("8901"))],
                    vec![],
                ),
            ],
        );
        assert!(has(&data_sms, "apk-sms-port-receiver"));
        // a dialer secret code (*#*#4636#*#*-style)
        let secret = receiver(
            vec![],
            vec![
                action("android.provider.Telephony.SECRET_CODE"),
                el(
                    "data",
                    vec![
                        a("scheme", V::Str("android_secret_code")),
                        a("host", V::Str("4636")),
                    ],
                    vec![],
                ),
            ],
        );
        assert!(has(&secret, "apk-dialer-secret-code"));
        assert!(
            issues(&secret)
                .iter()
                .all(|(r, _)| *r != "apk-sms-port-receiver")
        );
        // directBootAware on the application runs code before the user unlocks the device
        let dba = manifest(vec![], 33, vec![a("directBootAware", t())], vec![]);
        assert!(has(&dba, "apk-direct-boot-aware"));
        assert!(!has(
            &manifest(vec![], 33, vec![], vec![]),
            "apk-direct-boot-aware"
        ));
    }

    #[test]
    fn exported_component_without_permission_is_medium() {
        for kind in ["activity", "service", "receiver"] {
            let m = manifest(
                vec![],
                33,
                vec![],
                vec![comp(kind, vec![a("exported", t())], vec![])],
            );
            assert_eq!(
                issues(&m),
                [("apk-exported-component", Severity::Medium)],
                "{kind}"
            );
        }
    }

    #[test]
    fn exported_provider_without_permission_is_high() {
        let m = manifest(
            vec![],
            33,
            vec![],
            vec![comp("provider", vec![a("exported", t())], vec![])],
        );
        assert_eq!(issues(&m), [("apk-exported-provider", Severity::High)]);
    }

    #[test]
    fn exported_component_guards_do_not_fire() {
        let p = a("permission", V::Str("com.example.PERM"));
        // permission on the component, exported=false, no exported attr and no filter,
        // disabled, provider with read+write permissions, application-level permission.
        let cases: Vec<El> = vec![
            manifest(
                vec![],
                33,
                vec![],
                vec![comp("service", vec![a("exported", t()), p.clone()], vec![])],
            ),
            manifest(
                vec![],
                33,
                vec![],
                vec![comp("service", vec![a("exported", f())], vec![])],
            ),
            manifest(vec![], 28, vec![], vec![comp("service", vec![], vec![])]),
            manifest(
                vec![],
                33,
                vec![],
                vec![comp(
                    "service",
                    vec![a("exported", t()), a("enabled", f())],
                    vec![],
                )],
            ),
            manifest(
                vec![],
                33,
                vec![],
                vec![comp(
                    "provider",
                    vec![
                        a("exported", t()),
                        a("readPermission", V::Str("r")),
                        a("writePermission", V::Str("w")),
                    ],
                    vec![],
                )],
            ),
            manifest(
                vec![],
                33,
                vec![p.clone()],
                vec![comp("provider", vec![a("exported", t())], vec![])],
            ),
            // a provider with only a read permission is still open for writes
        ];
        for m in &cases {
            assert!(issues(m).is_empty(), "{:?}", issues(m));
        }
        let half = manifest(
            vec![],
            33,
            vec![],
            vec![comp(
                "provider",
                vec![a("exported", t()), a("readPermission", V::Str("r"))],
                vec![],
            )],
        );
        assert_eq!(issues(&half), [("apk-exported-provider", Severity::High)]);
    }

    #[test]
    fn launcher_activity_is_not_flagged_but_other_exported_activity_is() {
        let main = filter("android.intent.action.MAIN");
        let launcher = comp("activity", vec![a("exported", t())], vec![main]);
        assert!(issues(&manifest(vec![], 33, vec![], vec![launcher])).is_empty());
        let view = comp(
            "activity",
            vec![a("exported", t())],
            vec![filter("android.intent.action.VIEW")],
        );
        assert_eq!(
            issues(&manifest(vec![], 33, vec![], vec![view])),
            [("apk-exported-component", Severity::Medium)]
        );
    }

    #[test]
    fn implicit_export_follows_the_documented_defaults_one_level_lower() {
        let svc = || comp("service", vec![], vec![filter("x.ACTION")]);
        // intent filter, no attribute, targetSdk 30: exported by default, reported at warn.
        assert_eq!(
            issues(&manifest(vec![], 30, vec![], vec![svc()])),
            [("apk-exported-component", Severity::Warn)]
        );
        // targetSdk 31+ with an absent attribute is not a valid manifest: not reported.
        assert!(issues(&manifest(vec![], 33, vec![], vec![svc()])).is_empty());
        // provider default-exported only below API 17, then at medium rather than high.
        let prov = || comp("provider", vec![], vec![]);
        assert_eq!(
            issues(&manifest(vec![], 16, vec![], vec![prov()])),
            [("apk-exported-provider", Severity::Medium)]
        );
        assert!(issues(&manifest(vec![], 17, vec![], vec![prov()])).is_empty());
    }

    #[test]
    fn debuggable_is_high_and_false_is_clean() {
        let on = manifest(vec![], 33, vec![a("debuggable", t())], vec![]);
        assert_eq!(issues(&on), [("apk-debuggable", Severity::High)]);
        assert!(issues(&manifest(vec![], 33, vec![a("debuggable", f())], vec![])).is_empty());
        assert!(issues(&manifest(vec![], 33, vec![], vec![])).is_empty());
    }

    #[test]
    fn cleartext_is_medium_and_only_when_explicitly_true() {
        let on = manifest(vec![], 33, vec![a("usesCleartextTraffic", t())], vec![]);
        assert_eq!(issues(&on), [("apk-cleartext-traffic", Severity::Medium)]);
        let off = manifest(vec![], 33, vec![a("usesCleartextTraffic", f())], vec![]);
        assert!(issues(&off).is_empty());
        // targetSdk 28+ defaults to no cleartext: an absent attribute is not a finding.
        assert!(issues(&manifest(vec![], 28, vec![], vec![])).is_empty());
        // a network security config overrides the attribute: downgraded.
        let nsc = manifest(
            vec![],
            33,
            vec![
                a("usesCleartextTraffic", t()),
                a("networkSecurityConfig", V::Int(0x7f10_0001)),
            ],
            vec![],
        );
        assert_eq!(issues(&nsc), [("apk-cleartext-traffic", Severity::Warn)]);
    }

    #[test]
    fn shared_user_id_is_medium_and_absent_is_clean() {
        let on = manifest(
            vec![a("sharedUserId", V::Str("android.uid.system"))],
            33,
            vec![],
            vec![],
        );
        assert_eq!(issues(&on), [("apk-shared-user-id", Severity::Medium)]);
        assert!(issues(&manifest(vec![], 33, vec![], vec![])).is_empty());
    }

    #[test]
    fn allow_backup_true_is_info_and_false_or_absent_is_clean() {
        let on = manifest(vec![], 33, vec![a("allowBackup", t())], vec![]);
        assert_eq!(issues(&on), [("apk-allow-backup", Severity::Info)]);
        assert!(issues(&manifest(vec![], 33, vec![a("allowBackup", f())], vec![])).is_empty());
        assert!(issues(&manifest(vec![], 33, vec![], vec![])).is_empty());
    }

    #[test]
    fn test_only_is_medium_and_false_is_clean() {
        let on = manifest(vec![], 33, vec![a("testOnly", t())], vec![]);
        assert_eq!(issues(&on), [("apk-test-only", Severity::Medium)]);
        assert!(issues(&manifest(vec![], 33, vec![a("testOnly", f())], vec![])).is_empty());
    }

    #[test]
    fn only_a_typed_boolean_counts_not_a_string_or_a_foreign_attribute() {
        // The string "true" is not a boolean value.
        let s = manifest(vec![], 33, vec![a("debuggable", V::Str("true"))], vec![]);
        assert!(issues(&s).is_empty());
        // An app-defined `debuggable` in its own (non-android) namespace is not android:debuggable.
        let own = manifest(vec![], 33, vec![(false, "debuggable", t())], vec![]);
        let r = audit_apk_bytes(Path::new("/x.apk"), &apk_with(&axml(&own, false)));
        assert!(r.info.unwrap().issues().is_empty());
        // aapt1 style: rawValue holds the source text and the typed value still says true.
        let old = manifest(
            vec![],
            33,
            vec![a("debuggable", V::LegacyBool(true))],
            vec![],
        );
        assert_eq!(issues(&old), [("apk-debuggable", Severity::High)]);
    }

    #[test]
    fn many_issues_are_all_reported_with_a_cap_on_the_component_list() {
        let comps: Vec<El> = (0..8)
            .map(|_| comp("receiver", vec![a("exported", t())], vec![]))
            .collect();
        let m = manifest(vec![], 33, vec![a("debuggable", t())], comps);
        let r = audit_apk_bytes(Path::new("/x.apk"), &apk_with(&axml(&m, true)));
        let list = r.info.unwrap().issues();
        let d = &list
            .iter()
            .find(|i| i.rule == "apk-exported-component")
            .unwrap()
            .detail;
        assert!(
            d.starts_with("8 exported") && d.contains("and 3 more"),
            "{d}"
        );
        assert!(list.iter().any(|i| i.rule == "apk-debuggable"));
    }

    #[test]
    fn hostile_manifests_never_panic_or_hang() {
        let m = manifest(
            vec![a("sharedUserId", V::Str("s"))],
            33,
            vec![a("debuggable", t())],
            vec![comp(
                "provider",
                vec![a("exported", t())],
                vec![filter("x")],
            )],
        );
        let good = axml(&m, true);
        // Every truncation, and every single-byte corruption, of a valid manifest.
        for n in 0..good.len() {
            let _ = parse_manifest(&good[..n]);
        }
        for i in 0..good.len() {
            let mut b = good.clone();
            b[i] ^= 0xFF;
            let _ = parse_manifest(&b);
        }
        // A chunk whose size is 0 would never advance the cursor.
        let mut zero = good.clone();
        let pool_size = u32::from_le_bytes(good[12..16].try_into().unwrap()) as usize;
        let first = 8 + pool_size;
        zero[first + 4..first + 8].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_manifest(&zero).is_err());
        // Garbage and an APK whose manifest is garbage still audit without error.
        assert!(parse_manifest(&[0xFF; 64]).is_err());
        let r = audit_apk_bytes(
            Path::new("/x.apk"),
            &apk_with(&[0x03, 0x00, 0x08, 0x00, 1, 2, 3]),
        );
        assert!(r.error.is_none() && r.info.unwrap().issues().is_empty());
    }

    // --- signing posture fixtures: synthetic APKs, DER certs and signing blocks built here ---

    const NOW: i64 = 1_800_000_000; // 2027-01-15

    /// A 1024-bit RSA cert signed with SHA-1, CN=weak.
    const WEAK_CERT_HEX: &str = "308201fa30820163a003020102021408da1805815262963eafe7df0622a7d4f0f22978300d06092a864886f70d0101050500300f310d300b06035504030c047765616b301e170d3236313031313131313235385a170d3336313030383131313235385a300f310d300b06035504030c047765616b30819f300d06092a864886f70d010101050003818d0030818902818100b1ce9fd45895811978a52c2f1f4fad18366a6203e75b17a163b43efefe94a9316a3bd05725ef6ed49af4ff30c21c1fa427e8d96b188496f88a565bba549946a620e19f4db68c216d614b6b9db70ee209439037c7405ecc856425f99f8f32e9e56d8b0b9ce82ade764355cf9dc6ede7aec2de4572d0c8891b41ad0b1acc94a6970203010001a3533051301d0603551d0e04160414e415966a37b52c38558a4a8d1ce5048123e3f682301f0603551d23041830168014e415966a37b52c38558a4a8d1ce5048123e3f682300f0603551d130101ff040530030101ff300d06092a864886f70d01010505000381810093ce2aee4a20a3bad486521188b372ea73893a4a712d044dfae6e8b3f0ec53ddd3e8bac9e36f22518e75ebe94a1f2b9cc09b0f736b3a84945cf770ed6a8783536a81a9cb276fa074d452f376606b39cb69dee3d4672b50d690996ef339ccb887a0f442f8cdd1ad233676417c45f4d486a0f26df7dea9df5d994e4f031a69b02a";

    /// A 2048-bit RSA cert signed with SHA-256, CN=strong.
    const STRONG_CERT_HEX: &str = "30820303308201eba00302010202144e7bd78387b8c895a9ab066fd81423e9155d2838300d06092a864886f70d01010b05003011310f300d06035504030c067374726f6e67301e170d3236313031313131313235385a170d3336313030383131313235385a3011310f300d06035504030c067374726f6e6730820122300d06092a864886f70d01010105000382010f003082010a02820101008c4b011af0517a508b786a9d5a41e51a7e631aa2642b1d11eb739c6aa0c3525565f2e0b35aa950d14096d8ee860ea4ed630d52a453f66aef96bcaedf3a383a287ee79d616dfffc622c4e23c67352347d36dac9723977fac1302b9f09183ae0f62a23c7a71eee50906591a4d8c709be619e1ee50c222afd552406b0bbbce50447e2d992a171c796c86c21fc3abb66c9a697447f5681aca7ce29bcd0fa8a0274b74f8226fa2a803ab6f09f73f99271266889047d90b1970fc01df25a8123fcefd0a8d4ceabfca86d243883b11ec945f86da0942f372dd8aae70bff31ec0deccfbc771041110769cdd4514c6d21e960ffec755f47832e000152c804c764a2cf42130203010001a3533051301d0603551d0e04160414a94ea5d6e4be78f0c166a0e323c6164032fb5fb5301f0603551d23041830168014a94ea5d6e4be78f0c166a0e323c6164032fb5fb5300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100079942c59d09d6b7ecbc785d830c06084bca4c5d0e55efd2bfa4b1d27e4fd2127fb8cfef3214b12982f18ed311876e88ac16a587e79a9894ff676020f4c57fb3a99be92cfb314014d4c61722dc54f868d873ae7dcbb2c1ba813654cdabbd55ce983de4e385f7a8dd4b4e45de74c3868ffbeed3a1bbb2632df700905489f7b75e73212c4dd0752a71edc2b4e89fc3321531f381616ca6d56f0d97a07b241170f30750f4479d47be2b1c9cbe4d01e669b14c3ced55ee6e4d15468eb1c701285f9d38836ccd65a0a68a48ab68063db842f7fa0b467f21a1a76918f0b1676f76f6cb1b621936901a475258e5dfb2d3c58b0dacbf785125f81d3cc2312c9b108b70fc";

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        match body.len() {
            n if n < 128 => v.push(n as u8),
            n => v.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        v.extend(body);
        v
    }

    /// A DER X.509 Certificate with the given CN and UTCTime validity ("YYMMDDHHMMSSZ").
    fn cert(cn: &str, nb: &str, na: &str) -> Vec<u8> {
        let name = der(
            0x30,
            &der(
                0x31,
                &der(
                    0x30,
                    &[der(0x06, &[0x55, 0x04, 0x03]), der(0x0C, cn.as_bytes())].concat(),
                ),
            ),
        );
        let alg = der(0x30, &der(0x06, &[0x2A, 0x03]));
        let tbs = der(
            0x30,
            &[
                der(0xA0, &der(0x02, &[2])),
                der(0x02, &[1]),
                alg.clone(),
                name.clone(),
                der(
                    0x30,
                    &[der(0x17, nb.as_bytes()), der(0x17, na.as_bytes())].concat(),
                ),
                name,
                der(0x30, &[]),
            ]
            .concat(),
        );
        der(0x30, &[tbs, alg, der(0x03, &[0, 0])].concat())
    }

    /// PKCS#7 SignedData carrying `cert` (the shape `extract_pkcs7_certs` walks).
    fn pkcs7(cert: &[u8]) -> Vec<u8> {
        let sd = der(
            0x30,
            &[
                der(0x02, &[1]),
                der(0x31, &[]),
                der(0x30, &der(0x06, &[0x2A])),
                der(0xA0, cert),
            ]
            .concat(),
        );
        der(0x30, &[der(0x06, &[0x2A]), der(0xA0, &sd)].concat())
    }

    fn lp32(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_le_bytes()[..], b].concat()
    }

    /// An APK zip. `v1` adds a META-INF/CERT.RSA; `v2` inserts a v2 signing block before the
    /// central directory, as a real signer does.
    fn signed_apk(v1: Option<&[u8]>, v2: Option<&[u8]>) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default();
        w.start_file("AndroidManifest.xml", opt).unwrap();
        w.write_all(b"x").unwrap();
        if let Some(c) = v1 {
            w.start_file("META-INF/CERT.RSA", opt).unwrap();
            w.write_all(&pkcs7(c)).unwrap();
        }
        let mut z = w.finish().unwrap().into_inner();
        let Some(c) = v2 else { return z };
        let signed = [lp32(&[]), lp32(&lp32(c)), lp32(&[])].concat();
        let signer = [lp32(&signed), lp32(&[]), lp32(&[])].concat();
        let value = lp32(&lp32(&signer));
        let pair = [
            &(4 + value.len() as u64).to_le_bytes()[..],
            &V2_BLOCK_ID.to_le_bytes(),
            &value,
        ]
        .concat();
        let size = (pair.len() + 24) as u64;
        let block = [&size.to_le_bytes()[..], &pair, &size.to_le_bytes(), &MAGIC].concat();
        let eocd = z.len() - EOCD_MIN_SIZE;
        let cd = u32::from_le_bytes(z[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        z.splice(cd..cd, block.iter().copied());
        let eocd = z.len() - EOCD_MIN_SIZE;
        z[eocd + 16..eocd + 20].copy_from_slice(&((cd + block.len()) as u32).to_le_bytes());
        z
    }

    fn rules_for(bytes: &[u8]) -> Vec<&'static str> {
        let a = audit_apk_bytes(Path::new("/system/app/X.apk"), bytes);
        assert!(a.error.is_none(), "{:?}", a.error);
        // The synthetic fixtures carry fake signatures; the cert posture is what these test.
        a.info
            .unwrap()
            .posture(NOW)
            .iter()
            .map(|p| p.0)
            .filter(|r| !r.starts_with("apk-signature"))
            .collect()
    }

    const OK_NB: &str = "200101000000Z";
    const OK_NA: &str = "400101000000Z";

    #[test]
    fn a_v1_only_apk_is_flagged() {
        let c = cert("Acme Release", OK_NB, OK_NA);
        assert_eq!(
            rules_for(&signed_apk(Some(&c), None)),
            ["apk-v1-only-signing"]
        );
    }

    #[test]
    fn a_v2_signed_apk_is_not_v1_only_and_a_clean_one_has_no_findings() {
        let c = cert("Acme Release", OK_NB, OK_NA);
        // v2 alone, and v1+v2 (the usual shape), are both fine.
        assert!(rules_for(&signed_apk(None, Some(&c))).is_empty());
        assert!(rules_for(&signed_apk(Some(&c), Some(&c))).is_empty());
        let info = audit_apk_bytes(Path::new("/x.apk"), &signed_apk(None, Some(&c)))
            .info
            .unwrap();
        assert_eq!(info.signers.len(), 1);
        assert_eq!(info.signers[0].scheme, "v2");
        assert_eq!(info.signers[0].subject_cn.as_deref(), Some("Acme Release"));
    }

    #[test]
    fn the_android_debug_cert_is_flagged_for_both_schemes() {
        let c = cert("Android Debug", OK_NB, OK_NA);
        assert_eq!(
            rules_for(&signed_apk(None, Some(&c))),
            ["apk-debug-signing-cert"]
        );
        assert_eq!(
            rules_for(&signed_apk(Some(&c), None)),
            ["apk-v1-only-signing", "apk-debug-signing-cert"]
        );
        let info = audit_apk_bytes(Path::new("/x.apk"), &signed_apk(None, Some(&c)))
            .info
            .unwrap();
        assert!(info.signers[0].is_debug_cert);
    }

    #[test]
    fn an_aosp_test_key_is_flagged_as_a_weak_signing_cert() {
        let c = cert("testkey", OK_NB, OK_NA);
        assert_eq!(
            rules_for(&signed_apk(None, Some(&c))),
            ["apk-debug-signing-cert"]
        );
    }

    #[test]
    fn an_expired_certificate_is_flagged_against_the_given_clock() {
        let c = cert("Acme Release", OK_NB, "210101000000Z");
        let apk = signed_apk(None, Some(&c));
        assert_eq!(rules_for(&apk), ["apk-cert-expired"]);
        let info = audit_apk_bytes(Path::new("/x.apk"), &apk).info.unwrap();
        let detail = &info.posture(NOW)[0].1;
        assert!(detail.contains("expired 2021-01-01"), "{detail}");
        assert!(detail.contains("as of 2027-01-15"), "{detail}");
        assert!(detail.contains("no trusted clock"), "{detail}");
        // Before expiry the same APK is clean.
        assert!(
            info.posture(1_600_000_000)
                .iter()
                .all(|p| p.0.starts_with("apk-signature"))
        );
    }

    #[test]
    fn a_certificate_not_yet_valid_is_flagged() {
        let c = cert("Acme Release", "490101000000Z", "491231000000Z");
        assert_eq!(
            rules_for(&signed_apk(None, Some(&c))),
            ["apk-cert-not-yet-valid"]
        );
    }

    #[test]
    fn validity_times_parse_both_encodings_and_reject_junk() {
        let t = |tag: u8, s: &str| {
            parse_time(&Der {
                tag,
                payload: s.as_bytes(),
            })
        };
        assert_eq!(t(0x17, "210101000000Z"), Some(1_609_459_200));
        assert_eq!(t(0x17, "2101010000Z"), Some(1_609_459_200)); // no seconds
        assert_eq!(t(0x18, "20210101000000Z"), Some(1_609_459_200));
        assert_eq!(t(0x17, "500101000000Z"), Some(-631_152_000)); // YY>=50 -> 19YY
        assert_eq!(t(0x17, "21ab01000000Z"), None);
        assert_eq!(t(0x17, "211301000000Z"), None);
        assert_eq!(t(0x17, "2"), None);
        assert_eq!(ymd(1_609_459_200), "2021-01-01");
        assert_eq!(ymd(0), "1970-01-01");
    }

    #[test]
    fn a_truncated_or_corrupt_signing_block_never_panics() {
        let c = cert("Acme Release", OK_NB, OK_NA);
        let apk = signed_apk(Some(&c), Some(&c));
        for n in (0..apk.len()).step_by(3) {
            if let Some(i) = audit_apk_bytes(Path::new("/x.apk"), &apk[..n]).info {
                let _ = i.posture(NOW);
            }
        }
        // Flip every byte in turn: still no panic.
        for i in 0..apk.len() {
            let mut b = apk.clone();
            b[i] ^= 0xFF;
            if let Some(info) = audit_apk_bytes(Path::new("/x.apk"), &b).info {
                let _ = info.posture(NOW);
            }
        }
    }

    #[test]
    fn native_libraries_get_the_elf_hardening_rules() {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default();
        w.start_file("lib/arm64-v8a/libbad.so", opt).unwrap();
        w.write_all(&crate::elf::tests::unhardened_so()).unwrap();
        w.start_file("lib/arm64-v8a/libgood.so", opt).unwrap();
        w.write_all(&crate::elf::tests::hardened_so()).unwrap();
        w.start_file("assets/plugin.so", opt).unwrap();
        w.write_all(&crate::elf::tests::unhardened_so()).unwrap();
        let bytes = w.finish().unwrap().into_inner();
        let a = audit_apk_bytes(std::path::Path::new("/x.apk"), &bytes);
        let info = a.info.expect("a zip without a manifest still audits");
        let native: Vec<_> = info
            .issues()
            .into_iter()
            .filter(|i| i.rule.starts_with("elf-"))
            .collect();
        assert!(
            native
                .iter()
                .any(|i| i.rule == "elf-no-relro" && i.detail.contains("lib/arm64-v8a/libbad.so")),
            "{native:?}"
        );
        assert!(native.iter().any(|i| i.rule == "elf-exec-stack"));
        assert!(native
            .iter()
            .all(|i| !i.detail.contains("libgood.so") && !i.detail.contains("assets/plugin.so")));
    }

    /// Decode a hex string into bytes (test-only helper).
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn cert_strength_reads_the_signature_hash_and_rsa_size() {
        let weak = hex_decode(WEAK_CERT_HEX);
        let strong = hex_decode(STRONG_CERT_HEX);
        assert_eq!(cert_sig_alg(&weak), Some("sha1WithRSAEncryption"));
        assert_eq!(cert_rsa_bits(&weak), Some(1024));
        assert_eq!(cert_sig_alg(&strong), Some("sha256WithRSAEncryption"));
        assert_eq!(cert_rsa_bits(&strong), Some(2048));
        assert_eq!(cert_sig_alg(b"junk"), None);
        assert_eq!(cert_rsa_bits(b"junk"), None);
        // ECDSA P-256 signed with SHA-1: the weak hash is recognised, and there is no RSA size
        let ec = hex_decode(
            "308201743082011ca00302010202142639b3e3bffa203e16b398d8a6b4b554820e4f76300906072a8648ce3d04013011310f300d06035504030c0665637765616b301e170d3236313031313131353335345a170d3336313030383131353335345a3011310f300d06035504030c0665637765616b3059301306072a8648ce3d020106082a8648ce3d030107034200049accae7e3d654e584cbe2aca5cff7cc0348d8d8c8bdf5903193dc5d93c39571d4555f8e84bb8e4cfa251c025d71c7f34ea19cd4a1dba358cf539ec0e59d5ea1aa3533051301d0603551d0e041604142c3f730875e5979ca06d7e474e3b66b8bf397a85301f0603551d230418301680142c3f730875e5979ca06d7e474e3b66b8bf397a85300f0603551d130101ff040530030101ff300906072a8648ce3d04010347003044022070004537604b0a9648dd47bb90cb5662f31b36a18157cdcf4fef1655813e4b8a02206d6c0be7c0a290e2a9951fc659d41a2ef33e11e0fb4a1925d6c1293b8c27e8d8",
        );
        assert_eq!(cert_sig_alg(&ec), Some("ecdsaWithSHA1"));
        assert_eq!(cert_rsa_bits(&ec), None);
    }

    #[test]
    fn posture_flags_weak_signer_certificates() {
        let weak_der = hex_decode(WEAK_CERT_HEX);
        let strong_der = hex_decode(STRONG_CERT_HEX);
        // A Signer built from the weak cert: sha1/1024
        let s_weak = Signer {
            scheme: "v1",
            cert_sha256: String::new(),
            subject_cn: Some("weak".to_string()),
            is_aosp_test_key: false,
            is_debug_cert: false,
            not_before: None,
            not_after: None,
            sig_alg: cert_sig_alg(&weak_der),
            rsa_bits: cert_rsa_bits(&weak_der),
        };
        // A Signer built from the strong cert: sha256/2048
        let s_strong = Signer {
            scheme: "v1",
            cert_sha256: String::new(),
            subject_cn: Some("strong".to_string()),
            is_aosp_test_key: false,
            is_debug_cert: false,
            not_before: None,
            not_after: None,
            sig_alg: cert_sig_alg(&strong_der),
            rsa_bits: cert_rsa_bits(&strong_der),
        };
        // Build an ApkInfo with the weak signer and check posture.
        let apk_weak = ApkInfo {
            path: "/x.apk".into(),
            signers: vec![s_weak],
            ..Default::default()
        };
        let rules_weak: Vec<_> = apk_weak
            .posture(NOW)
            .iter()
            .map(|p| p.0)
            .filter(|r| !r.starts_with("apk-signature"))
            .collect();
        assert!(rules_weak.contains(&"apk-cert-weak-hash"), "{rules_weak:?}");
        assert!(rules_weak.contains(&"apk-cert-weak-key"), "{rules_weak:?}");
        // The strong signer produces neither rule.
        let apk_strong = ApkInfo {
            path: "/x.apk".into(),
            signers: vec![s_strong],
            ..Default::default()
        };
        let rules_strong: Vec<_> = apk_strong
            .posture(NOW)
            .iter()
            .map(|p| p.0)
            .filter(|r| !r.starts_with("apk-signature"))
            .collect();
        assert!(
            !rules_strong.contains(&"apk-cert-weak-hash")
                && !rules_strong.contains(&"apk-cert-weak-key"),
            "{rules_strong:?}"
        );
    }
}
