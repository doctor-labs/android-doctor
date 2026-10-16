//! `apk-compare`: two builds of one APK side by side. File sizes, an entry-level file diff
//! (added, removed, changed by CRC-32 and size), the `uses-feature` names from the manifest, and
//! a patch-size estimate. Reads the zip directory and AndroidManifest.xml only; no other entry is
//! decompressed, and nothing touches the network (so no download size).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use zip::ZipArchive;

use crate::apk::ManifestAttrs;
use crate::term::sanitize;

/// Largest APK read whole into memory.
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
/// Most zip entries listed per build.
const MAX_ENTRIES: usize = 100_000;
/// Largest AndroidManifest.xml handed to the manifest parser.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
/// Entries printed per section in the text output; the rest are counted.
const TEXT_SHOW: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub size: u64,
    pub compressed: u64,
    pub crc: u32,
}

#[derive(Debug, Default)]
pub struct Build {
    pub file_bytes: u64,
    pub entries: BTreeMap<String, Entry>,
    /// The parsed manifest, or `None` when it is missing or could not be read.
    pub manifest: Option<ManifestAttrs>,
    /// `uses-feature` names, or `None` when the manifest was not read.
    pub features: Option<BTreeSet<String>>,
}

#[derive(Debug, Default)]
pub struct Diff {
    pub added: Vec<(String, Entry)>,
    pub removed: Vec<(String, Entry)>,
    pub changed: Vec<(String, Entry, Entry)>,
    pub unchanged: usize,
}

#[derive(Debug)]
pub struct Compare {
    pub old: Build,
    pub new: Build,
    pub diff: Diff,
}

/// Compare two APK files on disk.
pub fn compare_files(old: &Path, new: &Path) -> Result<Compare> {
    let read = |p: &Path| -> Result<Vec<u8>> {
        let meta = std::fs::metadata(p)?;
        // A FIFO or device would block the read forever, so only regular files are opened.
        ensure!(meta.is_file(), "{}: not a regular file", p.display());
        let len = meta.len();
        ensure!(
            len <= MAX_INPUT_BYTES,
            "{}: {len} bytes, more than the {MAX_INPUT_BYTES} this command reads",
            p.display()
        );
        Ok(std::fs::read(p)?)
    };
    compare(&read(old)?, &read(new)?)
}

/// Compare two APKs held in memory.
pub fn compare(old: &[u8], new: &[u8]) -> Result<Compare> {
    let a = read_build(old).context("old APK")?;
    let b = read_build(new).context("new APK")?;
    let diff = diff_builds(&a, &b);
    Ok(Compare {
        old: a,
        new: b,
        diff,
    })
}

fn read_build(bytes: &[u8]) -> Result<Build> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))?;
    ensure!(
        zip.len() <= MAX_ENTRIES,
        "{} zip entries, more than the {MAX_ENTRIES} this command reads",
        zip.len()
    );
    let mut entries = BTreeMap::new();
    for i in 0..zip.len() {
        // The raw entry: its header gives the sizes and CRC without decompressing anything.
        let f = zip.by_index_raw(i)?;
        entries.insert(
            f.name().to_string(),
            Entry {
                size: f.size(),
                compressed: f.compressed_size(),
                crc: f.crc32(),
            },
        );
    }
    let manifest = zip.by_name("AndroidManifest.xml").ok().and_then(|f| {
        let mut buf = Vec::new();
        f.take(MAX_MANIFEST_BYTES).read_to_end(&mut buf).ok()?;
        crate::apk::parse_manifest(&buf).ok()
    });
    let features = manifest
        .as_ref()
        .map(|m| m.uses_features.iter().cloned().collect());
    Ok(Build {
        file_bytes: bytes.len() as u64,
        entries,
        manifest,
        features,
    })
}

fn diff_builds(old: &Build, new: &Build) -> Diff {
    let mut d = Diff::default();
    for (name, n) in &new.entries {
        match old.entries.get(name) {
            None => d.added.push((name.clone(), *n)),
            Some(o) if o.crc == n.crc && o.size == n.size => d.unchanged += 1,
            Some(o) => d.changed.push((name.clone(), *o, *n)),
        }
    }
    d.removed = old
        .entries
        .iter()
        .filter(|(k, _)| !new.entries.contains_key(*k))
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    d
}

/// Bytes a naive patch would ship: the new build's compressed size of every added or changed entry.
pub fn patch_estimate(diff: &Diff) -> u64 {
    diff.added.iter().map(|(_, e)| e.compressed).sum::<u64>()
        + diff
            .changed
            .iter()
            .map(|(_, _, n)| n.compressed)
            .sum::<u64>()
}

impl Compare {
    /// `uses-feature` names added and removed, or `None` when either manifest was not read.
    pub fn feature_diff(&self) -> Option<(Vec<String>, Vec<String>)> {
        let (o, n) = (self.old.features.as_ref()?, self.new.features.as_ref()?);
        Some((
            n.difference(o).cloned().collect(),
            o.difference(n).cloned().collect(),
        ))
    }

    /// The doctor/1 envelope. Compare is not a health check, so it has no findings and a fixed score.
    pub fn to_json(&self) -> Value {
        let score = doctor_core::Score::new(100, "apk-compare/1", 0);
        doctor_core::Envelope::new(
            "android-doctor",
            env!("CARGO_PKG_VERSION"),
            0,
            score,
            Vec::new(),
            self.data(),
        )
        .to_value()
    }

    fn data(&self) -> Value {
        let d = &self.diff;
        let delta = self.new.file_bytes as i64 - self.old.file_bytes as i64;
        let features = self
            .feature_diff()
            .map(|(added, removed)| json!({"added": added, "removed": removed}));
        json!({
            "old": side(&self.old),
            "new": side(&self.new),
            "size": {
                "old_file_bytes": self.old.file_bytes,
                "new_file_bytes": self.new.file_bytes,
                "delta_bytes": delta,
            },
            "entries": {
                "unchanged": d.unchanged,
                "added": d.added.iter().map(|(n, e)| json!({"name": n, "size": e.size, "compressed": e.compressed})).collect::<Vec<_>>(),
                "removed": d.removed.iter().map(|(n, e)| json!({"name": n, "size": e.size, "compressed": e.compressed})).collect::<Vec<_>>(),
                "changed": d.changed.iter().map(|(n, o, e)| json!({"name": n, "old_size": o.size, "new_size": e.size, "old_compressed": o.compressed, "new_compressed": e.compressed})).collect::<Vec<_>>(),
            },
            "features": features,
            "patch_estimate": {
                "bytes": patch_estimate(d),
                "method": "compressed size of every added or changed entry in the new build; no delta encoding",
            },
        })
    }

    /// Human text; `old` and `new` are the labels shown for the two files.
    pub fn to_text(&self, old: &str, new: &str) -> String {
        let d = &self.diff;
        let pkg = |b: &Build| {
            b.manifest
                .as_ref()
                .map(|m| m.package_name.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(manifest not read)".into())
        };
        let delta = self.new.file_bytes as i64 - self.old.file_bytes as i64;
        let mut out = format!("apk-compare: {} -> {}\n", sanitize(old), sanitize(new));
        out += &format!(
            "package: {} -> {}\n",
            sanitize(&pkg(&self.old)),
            sanitize(&pkg(&self.new))
        );
        out += &format!(
            "file size: {} -> {} bytes ({:+})\n",
            self.old.file_bytes, self.new.file_bytes, delta
        );
        out += &format!(
            "entries: {} unchanged, {} changed, {} added, {} removed\n",
            d.unchanged,
            d.changed.len(),
            d.added.len(),
            d.removed.len()
        );
        for (n, e) in d.added.iter().take(TEXT_SHOW) {
            out += &format!("  + {} ({} bytes)\n", sanitize(n), e.compressed);
        }
        for (n, o, e) in d.changed.iter().take(TEXT_SHOW) {
            out += &format!("  ~ {} ({} -> {} bytes)\n", sanitize(n), o.size, e.size);
        }
        for (n, e) in d.removed.iter().take(TEXT_SHOW) {
            out += &format!("  - {} ({} bytes)\n", sanitize(n), e.size);
        }
        for len in [d.added.len(), d.changed.len(), d.removed.len()] {
            if len > TEXT_SHOW {
                out += &format!("  ... {} more\n", len - TEXT_SHOW);
            }
        }
        match self.feature_diff() {
            Some((a, r)) if a.is_empty() && r.is_empty() => out += "features: no change\n",
            Some((a, r)) => {
                out += "features:\n";
                for f in &a {
                    out += &format!("  + {}\n", sanitize(f));
                }
                for f in &r {
                    out += &format!("  - {}\n", sanitize(f));
                }
            }
            None => out += "features: not read (manifest missing or unparsed)\n",
        }
        out += &format!(
            "patch estimate: {} bytes (compressed size of added and changed entries; no delta encoding)\n",
            patch_estimate(d)
        );
        out
    }
}

fn side(b: &Build) -> Value {
    let m = b.manifest.as_ref();
    json!({
        "file_bytes": b.file_bytes,
        "entries": b.entries.len(),
        "manifest_read": m.is_some(),
        "package": m.map(|m| m.package_name.as_str()).filter(|s| !s.is_empty()),
        "version_code": m.and_then(|m| m.version_code.clone()),
        "version_name": m.and_then(|m| m.version_name.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    const PLAIN: &[u8] = include_bytes!("../tests/fixtures/apk/plain.apk");

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, body) in files {
            w.start_file(*name, opt).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn identical_builds_have_no_entry_changes_and_no_patch() {
        let a = zip_of(&[("a", b"one"), ("b", b"two")]);
        let c = compare(&a, &a).unwrap();
        assert!(c.diff.added.is_empty() && c.diff.removed.is_empty() && c.diff.changed.is_empty());
        assert_eq!(c.diff.unchanged, 2);
        assert_eq!(patch_estimate(&c.diff), 0);
    }

    #[test]
    fn added_removed_and_changed_entries_are_listed_and_priced() {
        let old = zip_of(&[("keep", b"same"), ("gone", b"xxxx"), ("edit", b"v1")]);
        let new = zip_of(&[
            ("keep", b"same"),
            ("edit", b"v2 longer"),
            ("new.so", b"12345"),
        ]);
        let c = compare(&old, &new).unwrap();
        let names = |v: &[(String, Entry)]| v.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
        assert_eq!(names(&c.diff.added), ["new.so"]);
        assert_eq!(names(&c.diff.removed), ["gone"]);
        assert_eq!(
            c.diff
                .changed
                .iter()
                .map(|x| x.0.as_str())
                .collect::<Vec<_>>(),
            ["edit"]
        );
        assert_eq!(c.diff.unchanged, 1);
        // Stored entries: compressed == size. The changed entry (9 bytes) plus the added one (5).
        assert_eq!(patch_estimate(&c.diff), 14);
    }

    #[test]
    fn a_real_manifest_gives_the_package_and_a_feature_list() {
        let c = compare(PLAIN, PLAIN).unwrap();
        let m = c.old.manifest.as_ref().expect("plain.apk has a manifest");
        assert!(!m.package_name.is_empty());
        assert!(c.old.features.is_some());
        assert_eq!(c.feature_diff(), Some((vec![], vec![])));
    }

    #[test]
    fn feature_names_are_diffed_as_sets() {
        let build = |names: &[&str]| Build {
            features: Some(names.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        let c = Compare {
            old: build(&["camera", "nfc"]),
            new: build(&["camera", "gps"]),
            diff: Diff::default(),
        };
        assert_eq!(
            c.feature_diff(),
            Some((vec!["gps".to_string()], vec!["nfc".to_string()]))
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(compare(b"not a zip at all", PLAIN).is_err());
    }
}
