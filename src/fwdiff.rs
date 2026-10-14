//! `diff`: compare two firmware builds at the file-system level. Each image is read with the
//! same readers as `audit` (ext2/3/4, erofs, f2fs) and audited; the two trees are then compared by
//! path and SHA-256, along with modes, owners, SELinux labels, file capabilities, build and ADB
//! properties and init services. What got worse becomes findings (rules `diff-*`) so the diff
//! gates CI like `audit`; the raw file-level changes go under `data`. Nothing is extracted.
use crate::audit::{self, ImageAudit, Service};
use crate::avb::{self, Descriptor, Vbmeta};
use crate::findings::{self, Finding, Severity};
use crate::term::sanitize;
use crate::tree::{Entry, Kind, Tree};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Statuses a file change can have (`--only` takes these).
pub const STATUSES: [&str; 4] = ["added", "removed", "modified", "metadata"];
/// How many changes per image the text report lists before pointing at `--json`.
const TEXT_CAP: usize = 25;

struct HashW(Sha256);

impl std::io::Write for HashW {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Audit one image and fill in the SHA-256 of every regular file.
fn load(name: &str, path: &Path) -> Result<ImageAudit> {
    let tree = Tree::open(path)?;
    let entries = tree.entries()?;
    let mut a = audit::analyse(name, &entries, &mut |p| {
        let mut buf = Vec::new();
        tree.cat_path(p, &mut buf)?;
        Ok(buf)
    })?;
    for e in a.entries.iter_mut().filter(|e| e.kind == Kind::File) {
        let mut h = HashW(Sha256::new());
        tree.cat_path(&e.path, &mut h)
            .with_context(|| format!("hashing {}", e.path))?;
        e.sha256 = Some(h.0.finalize().iter().map(|b| format!("{b:02x}")).collect());
    }
    Ok(a)
}

fn stem(p: &Path) -> String {
    p.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image")
        .to_string()
}

/// Pair the inputs: two image files, or two directories of images matched by file stem (an image
/// on one side only is compared against an empty tree).
type Pair = (String, Option<PathBuf>, Option<PathBuf>);

fn pairs(old: &Path, new: &Path) -> Result<Vec<Pair>> {
    match (old.is_dir(), new.is_dir()) {
        (false, false) => Ok(vec![(
            stem(new),
            Some(old.to_path_buf()),
            Some(new.to_path_buf()),
        )]),
        (true, true) => {
            let list = |d: &Path| -> Result<BTreeMap<String, PathBuf>> {
                Ok(audit::image_list(&[d.to_path_buf()])?
                    .into_iter()
                    .map(|p| (stem(&p), p))
                    .collect())
            };
            let (o, n) = (list(old)?, list(new)?);
            let names: BTreeSet<&String> = o.keys().chain(n.keys()).collect();
            Ok(names
                .into_iter()
                .map(|k| (k.clone(), o.get(k).cloned(), n.get(k).cloned()))
                .collect())
        }
        _ => anyhow::bail!("give two image files or two directories of images, not one of each"),
    }
}

pub struct Change {
    path: String,
    status: &'static str,
    old: Option<Value>,
    new: Option<Value>,
}

pub struct ImageDiff {
    name: String,
    /// `both`, `added` (image only in the new build) or `removed`.
    presence: &'static str,
    changes: Vec<Change>,
    unchanged: usize,
    props: Vec<Value>,
    services: Vec<Value>,
}

fn side(e: &Entry) -> Value {
    json!({
        "kind": e.kind.name(), "size": e.size, "sha256": e.sha256, "link": e.link,
        "mode": format!("{:04o}", e.mode & 0o7777), "uid": e.uid, "gid": e.gid,
        "label": audit::label_of(e),
        "capability": e.xattrs.iter().find(|(k, _)| k == "security.capability").map(|(_, v)| v),
    })
}

fn same_content(a: &Entry, b: &Entry) -> bool {
    a.kind == b.kind
        && match a.kind {
            Kind::File => a.sha256 == b.sha256,
            Kind::Symlink => a.link == b.link,
            Kind::Dir => true,
            _ => a.rdev == b.rdev,
        }
}

fn same_meta(a: &Entry, b: &Entry) -> bool {
    side(a)["mode"] == side(b)["mode"]
        && (a.uid, a.gid) == (b.uid, b.gid)
        && audit::label_of(a) == audit::label_of(b)
        && side(a)["capability"] == side(b)["capability"]
}

fn diff_files(old: &ImageAudit, new: &ImageAudit) -> (Vec<Change>, usize) {
    let map = |a: &ImageAudit| -> BTreeMap<String, Entry> {
        a.entries
            .iter()
            .map(|e| (e.path.clone(), e.clone()))
            .collect()
    };
    let (o, n) = (map(old), map(new));
    let paths: BTreeSet<&String> = o.keys().chain(n.keys()).collect();
    let (mut out, mut unchanged) = (Vec::new(), 0);
    for p in paths {
        let (a, b) = (o.get(p), n.get(p));
        let status = match (a, b) {
            // A directory appearing or vanishing says nothing its files do not.
            (None, Some(e)) | (Some(e), None) if e.kind == Kind::Dir => continue,
            (None, Some(_)) => "added",
            (Some(_), None) => "removed",
            (Some(a), Some(b)) if !same_content(a, b) => "modified",
            (Some(a), Some(b)) if !same_meta(a, b) => "metadata",
            (Some(e), _) => {
                unchanged += usize::from(e.kind != Kind::Dir);
                continue;
            }
            _ => continue,
        };
        out.push(Change {
            path: p.clone(),
            status,
            old: a.map(side),
            new: b.map(side),
        });
    }
    (out, unchanged)
}

fn is_root(s: &Service) -> bool {
    s.user.as_deref().is_none_or(|u| u == "root")
}

fn diff_services(old: &ImageAudit, new: &ImageAudit) -> Vec<Value> {
    let key = |s: &Service| (s.file.clone(), s.name.clone());
    let o: BTreeMap<_, _> = old.services.iter().map(|s| (key(s), s)).collect();
    let n: BTreeMap<_, _> = new.services.iter().map(|s| (key(s), s)).collect();
    let show = |s: &Service| json!({"command": s.command, "user": s.user, "seclabel": s.seclabel, "disabled": s.disabled});
    let mut out = Vec::new();
    for k in o.keys().chain(n.keys()).collect::<BTreeSet<_>>() {
        let (a, b) = (o.get(k), n.get(k));
        let status = match (a, b) {
            (None, Some(_)) => "added",
            (Some(_), None) => "removed",
            (Some(a), Some(b)) if show(a) != show(b) => "changed",
            _ => continue,
        };
        out.push(json!({"file": k.0, "name": k.1, "status": status,
            "old": a.map(|s| show(s)), "new": b.map(|s| show(s))}));
    }
    out
}

fn diff_props(old: &ImageAudit, new: &ImageAudit) -> Vec<Value> {
    let m = |a: &ImageAudit| -> BTreeMap<(String, String), String> {
        a.props
            .iter()
            .map(|p| ((p.file.clone(), p.key.clone()), p.value.clone()))
            .collect()
    };
    let (o, n) = (m(old), m(new));
    o.keys()
        .chain(n.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|k| o.get(*k) != n.get(*k))
        .map(|k| json!({"file": k.0, "key": k.1, "old": o.get(k), "new": n.get(k)}))
        .collect()
}

fn is_sepolicy(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("sepolicy")
        || p.contains("etc/selinux/")
        || [
            "file_contexts",
            "property_contexts",
            "service_contexts",
            "seapp_contexts",
        ]
        .iter()
        .any(|n| p.ends_with(n))
}

/// One AVB change between the old and the new vbmeta of an image.
struct AvbChange {
    rule: &'static str,
    severity: Severity,
    subject: String,
    message: String,
    remedy: &'static str,
}

/// AVB changes between two vbmeta images: the rollback index lowered, a security state newly set
/// (verification or hashtree disabled, unlocked device), a partition descriptor added or removed,
/// or a partition's hash algorithm changed. Digests and salts change with every rebuild, so they
/// are not findings.
fn avb_changes(name: &str, old: &Vbmeta, new: &Vbmeta) -> Vec<AvbChange> {
    let mut out = Vec::new();
    if new.rollback_index < old.rollback_index {
        out.push(AvbChange {
            rule: "diff-avb-rollback-index",
            severity: Severity::High,
            subject: name.into(),
            message: format!(
                "rollback index lowered from {} to {}",
                old.rollback_index, new.rollback_index
            ),
            remedy: "Never ship a lower rollback index: devices that saw the higher one refuse it",
        });
    }
    let before = old.security_states();
    for s in new
        .security_states()
        .into_iter()
        .filter(|s| !before.contains(s))
    {
        out.push(AvbChange {
            rule: "diff-avb-security-state",
            severity: Severity::High,
            subject: name.into(),
            message: format!("{}: {}", s.as_str(), s.explanation()),
            remedy: "Build the vbmeta without the flag that disables verification",
        });
    }
    // Partition descriptors keyed by kind and partition name; the value is the hash algorithm.
    let descriptors = |m: &Vbmeta| -> BTreeMap<(&'static str, String), Option<String>> {
        m.descriptors
            .iter()
            .filter_map(|d| match d {
                Descriptor::Hash(h) => {
                    Some((("hash", h.partition.clone()), Some(h.algorithm.clone())))
                }
                Descriptor::Hashtree(h) => {
                    Some((("hashtree", h.partition.clone()), Some(h.algorithm.clone())))
                }
                Descriptor::ChainPartition { partition, .. } => {
                    Some((("chain", partition.clone()), None))
                }
                _ => None,
            })
            .collect()
    };
    let (o, n) = (descriptors(old), descriptors(new));
    for k in o.keys().chain(n.keys()).collect::<BTreeSet<_>>() {
        let (kind, partition) = (k.0, &k.1);
        let change = match (o.get(k), n.get(k)) {
            (Some(Some(a)), Some(Some(b))) if a != b => Some((
                "diff-avb-hash-algorithm",
                format!("{kind} descriptor for {partition} changed hash algorithm from {a} to {b}"),
            )),
            (None, Some(_)) => Some((
                "diff-avb-descriptor",
                format!("{kind} descriptor for {partition} was added"),
            )),
            (Some(_), None) => Some((
                "diff-avb-descriptor",
                format!("{kind} descriptor for {partition} was removed"),
            )),
            _ => None,
        };
        if let Some((rule, message)) = change {
            out.push(AvbChange {
                rule,
                severity: Severity::Medium,
                subject: partition.clone(),
                message,
                remedy: "Review the partition's verification chain before shipping",
            });
        }
    }
    out
}

/// Whether a file carries an AVB header (`AVB0` at the start) or footer (`AVBf` in its last 64
/// bytes). Plain filesystem images carry neither, so they are not AVB images at all.
fn has_avb_marker(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 4];
    if f.read_exact(&mut head).is_ok() && &head == b"AVB0" {
        return true;
    }
    let Ok(len) = f.seek(SeekFrom::End(0)) else {
        return false;
    };
    let mut tail = [0u8; 4];
    len >= 64
        && f.seek(SeekFrom::End(-64)).is_ok()
        && f.read_exact(&mut tail).is_ok()
        && &tail == b"AVBf"
}

/// The AVB changes of one image pair. An image whose vbmeta cannot be read is noted as
/// `diff-avb-unchecked` when it has an AVB marker, so its AVB state is never silently skipped;
/// an image with no AVB marker is not an AVB image and is left out.
fn avb_pair(name: &str, old: &Path, new: &Path) -> Vec<AvbChange> {
    match (avb::read_input(old, None), avb::read_input(new, None)) {
        (Ok(x), Ok(y)) => avb_changes(name, &x, &y),
        (x, y) => [("old", old, x.err()), ("new", new, y.err())]
            .into_iter()
            .filter_map(|(side, path, err)| {
                let err = err?;
                has_avb_marker(path).then(|| AvbChange {
                    rule: "diff-avb-unchecked",
                    severity: Severity::Info,
                    subject: format!("{name} ({side})"),
                    message: format!(
                        "the {side} image's AVB vbmeta could not be read, so AVB was not checked: {err:#}"
                    ),
                    remedy: "Fix or re-sign the image so its vbmeta parses, then diff again",
                })
            })
            .collect(),
    }
}

/// What the new build does worse than the old one.
fn security_findings(
    old: &ImageAudit,
    new: &ImageAudit,
    d: &ImageDiff,
    avb_diffs: &[AvbChange],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |rule: String,
                   severity,
                   subject: &str,
                   key: &str,
                   message: String,
                   remedy: Option<String>| {
        out.push(
            Finding {
                rule,
                category: "security".into(),
                severity,
                scope: new.name.clone(),
                subject: subject.to_string(),
                key: key.to_string(),
                message,
                remedy,
                gap: false,
                uri: None,
                fingerprint: String::new(),
                baseline_state: None,
            }
            .seal(!subject.is_empty()),
        )
    };
    // Every audit finding about a path or name that the old build did not have.
    let known: BTreeSet<(&str, &str, &str)> = old
        .findings
        .iter()
        .zip(&old.finding_keys)
        .map(|(f, (s, k))| (f.rule, s.as_str(), k.as_str()))
        .collect();
    for (f, (s, k)) in new.findings.iter().zip(&new.finding_keys) {
        if s.is_empty() || f.severity == audit::Severity::Info || known.contains(&(f.rule, s, k)) {
            continue;
        }
        add(
            format!("diff-{}", f.rule),
            f.severity.unified(),
            s,
            k,
            format!("new in this build: {}", f.detail),
            findings::help(f.rule).map(|h| h.remedy.to_string()),
        );
    }
    let old_setuid: BTreeSet<&str> = old.setuid.iter().map(|s| s.path.as_str()).collect();
    for s in new
        .setuid
        .iter()
        .filter(|s| !old_setuid.contains(s.path.as_str()))
    {
        add(
            "diff-new-setuid".into(),
            Severity::High,
            &s.path,
            "",
            format!(
                "/{} is newly setuid/setgid ({:04o}, uid {})",
                s.path,
                s.mode & 0o7777,
                s.uid
            ),
            Some("Drop the setuid bit, or confirm the file needs it".into()),
        );
    }
    let old_caps: BTreeSet<&(String, String)> = old.capabilities.iter().collect();
    for c in new.capabilities.iter().filter(|c| !old_caps.contains(c)) {
        add(
            "diff-new-capability".into(),
            Severity::Medium,
            &c.0,
            &c.1,
            format!("/{} has new or changed file capabilities ({})", c.0, c.1),
            Some("Grant only the capabilities the binary needs".into()),
        );
    }
    for v in &d.services {
        let (Some(file), Some(name)) = (v["file"].as_str(), v["name"].as_str()) else {
            continue;
        };
        let Some(s) = new
            .services
            .iter()
            .find(|s| s.file == file && s.name == name)
        else {
            continue;
        };
        let was_root = old
            .services
            .iter()
            .find(|o| o.file == file && o.name == name)
            .is_some_and(is_root);
        if is_root(s) && !was_root {
            add(
                "diff-root-service".into(),
                if s.disabled {
                    Severity::Low
                } else {
                    Severity::Medium
                },
                file,
                name,
                format!("service {name} in {file} now runs as root ({})", s.command),
                Some("Give the service its own user and SELinux domain".into()),
            );
        }
    }
    for c in d
        .changes
        .iter()
        .filter(|c| c.status != "removed" && c.status != "metadata")
    {
        if is_sepolicy(&c.path) {
            let h = c
                .new
                .as_ref()
                .and_then(|n| n["sha256"].as_str())
                .unwrap_or("");
            add(
                "diff-sepolicy-changed".into(),
                Severity::Medium,
                &c.path,
                h,
                format!("SELinux policy file /{} was {}", c.path, c.status),
                Some("Review the policy change before shipping".into()),
            );
        }
    }
    for c in avb_diffs {
        add(
            c.rule.into(),
            c.severity,
            &c.subject,
            "",
            c.message.clone(),
            Some(c.remedy.into()),
        );
    }
    for p in &d.props {
        let (file, key) = (
            p["file"].as_str().unwrap_or(""),
            p["key"].as_str().unwrap_or(""),
        );
        let show = |v: &Value| v.as_str().unwrap_or("(unset)").to_string();
        let (o, n) = (show(&p["old"]), show(&p["new"]));
        add(
            "diff-prop-changed".into(),
            Severity::Info,
            file,
            &format!("{key}={n}"),
            format!("{key} in {file}: {o} -> {n}"),
            None,
        );
    }
    out
}

pub struct Outcome {
    pub findings: Vec<Finding>,
    pub images: Vec<ImageDiff>,
}

pub fn run(old: &Path, new: &Path) -> Result<Outcome> {
    let (mut all, mut images) = (Vec::new(), Vec::new());
    for (name, o, n) in pairs(old, new)? {
        let empty = || ImageAudit {
            name: name.clone(),
            ..Default::default()
        };
        let a = match &o {
            Some(p) => load(&name, p).with_context(|| format!("reading {}", p.display()))?,
            None => empty(),
        };
        let b = match &n {
            Some(p) => load(&name, p).with_context(|| format!("reading {}", p.display()))?,
            None => empty(),
        };
        let (changes, unchanged) = diff_files(&a, &b);
        let d = ImageDiff {
            name: name.clone(),
            presence: match (&o, &n) {
                (Some(_), Some(_)) => "both",
                (None, _) => "added",
                _ => "removed",
            },
            changes,
            unchanged,
            props: diff_props(&a, &b),
            services: diff_services(&a, &b),
        };
        let avb_diffs = match (&o, &n) {
            (Some(p), Some(q)) => avb_pair(&name, p, q),
            _ => Vec::new(),
        };
        all.extend(security_findings(&a, &b, &d, &avb_diffs));
        images.push(d);
    }
    Ok(Outcome {
        findings: all,
        images,
    })
}

fn keep<'a>(d: &'a ImageDiff, only: &'a [String]) -> impl Iterator<Item = &'a Change> {
    d.changes
        .iter()
        .filter(move |c| only.is_empty() || only.iter().any(|o| o == c.status))
}

pub fn to_json(images: &[ImageDiff], only: &[String]) -> Value {
    json!({ "images": images.iter().map(|d| {
        let count = |s: &str| d.changes.iter().filter(|c| c.status == s).count();
        json!({
            "name": d.name,
            "presence": d.presence,
            "counts": {"added": count("added"), "removed": count("removed"),
                "modified": count("modified"), "metadata": count("metadata"),
                "unchanged": d.unchanged},
            "files": keep(d, only).map(|c| json!({
                "path": c.path, "status": c.status, "old": c.old, "new": c.new,
            })).collect::<Vec<_>>(),
            "properties": d.props,
            "services": d.services,
        })
    }).collect::<Vec<_>>() })
}

pub fn to_text(images: &[ImageDiff], only: &[String]) -> String {
    let mut lines = Vec::new();
    for d in images {
        let count = |s: &str| d.changes.iter().filter(|c| c.status == s).count();
        lines.push(format!(
            "{} ({}): {} added, {} removed, {} modified, {} metadata-only, {} unchanged",
            sanitize(&d.name),
            d.presence,
            count("added"),
            count("removed"),
            count("modified"),
            count("metadata"),
            d.unchanged
        ));
        let shown: Vec<_> = keep(d, only).collect();
        for c in shown.iter().take(TEXT_CAP) {
            lines.push(format!("  {:<8} /{}", c.status, sanitize(&c.path)));
        }
        if shown.len() > TEXT_CAP {
            lines.push(format!(
                "  ... {} more (see --json)",
                shown.len() - TEXT_CAP
            ));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sepolicy_paths_are_recognised() {
        assert!(is_sepolicy("system/etc/selinux/plat_sepolicy.cil"));
        assert!(is_sepolicy("vendor/etc/selinux/vendor_file_contexts"));
        assert!(!is_sepolicy("system/etc/hosts"));
    }

    fn vbmeta(rollback_index: u64, flags: u32, descriptors: Vec<Descriptor>) -> Vbmeta {
        Vbmeta {
            libavb: (1, 0),
            algorithm: 0,
            rollback_index,
            flags,
            rollback_index_location: 0,
            release: String::new(),
            auth_size: 0,
            aux_size: 0,
            signature_len: 0,
            public_key_bits: None,
            public_key_sha256: None,
            public_key_metadata_len: 0,
            digest_ok: None,
            signature_verified: crate::avb::SignatureStatus::Absent,
            descriptors,
            footer: None,
            coverage: None,
        }
    }

    fn hash(partition: &str, algorithm: &str) -> Descriptor {
        Descriptor::Hash(crate::avb::HashDescriptor {
            partition: partition.into(),
            algorithm: algorithm.into(),
            image_size: 0,
            salt: vec![],
            digest: vec![],
            flags: 0,
        })
    }

    fn rules(v: &[AvbChange]) -> Vec<(&'static str, Severity)> {
        v.iter().map(|c| (c.rule, c.severity)).collect()
    }

    #[test]
    fn avb_rollback_index_going_down_is_high_and_going_up_is_quiet() {
        let old = vbmeta(5, 0, vec![]);
        assert_eq!(
            rules(&avb_changes("vbmeta", &old, &vbmeta(4, 0, vec![]))),
            vec![("diff-avb-rollback-index", Severity::High)]
        );
        assert!(avb_changes("vbmeta", &old, &vbmeta(6, 0, vec![])).is_empty());
    }

    #[test]
    fn avb_newly_disabled_verification_is_high_but_an_inherited_one_is_not() {
        let old = vbmeta(1, 0, vec![]);
        let disabled = vbmeta(1, 2, vec![]);
        assert_eq!(
            rules(&avb_changes("vbmeta", &old, &disabled)),
            vec![("diff-avb-security-state", Severity::High)]
        );
        assert!(avb_changes("vbmeta", &disabled, &disabled).is_empty());
    }

    #[test]
    fn avb_descriptor_added_removed_or_re_algorithmed_is_reported() {
        let old = vbmeta(1, 0, vec![hash("boot", "sha256"), hash("dtbo", "sha256")]);
        let new = vbmeta(1, 0, vec![hash("boot", "sha1"), hash("vendor", "sha256")]);
        assert_eq!(
            rules(&avb_changes("vbmeta", &old, &new)),
            vec![
                ("diff-avb-hash-algorithm", Severity::Medium),
                ("diff-avb-descriptor", Severity::Medium),
                ("diff-avb-descriptor", Severity::Medium),
            ]
        );
    }

    #[test]
    fn an_unreadable_vbmeta_with_an_avb_marker_is_noted_not_skipped() {
        let d = crate::testutil::Scratch::new("avb-unchecked");
        let plain = d.join("plain.img");
        let broken = d.join("broken.img");
        std::fs::write(&plain, vec![0u8; 4096]).unwrap();
        // A footer that points at a vbmeta block with no AVB0 magic.
        let mut img = vec![0u8; 128];
        let mut footer = vec![0u8; 64];
        footer[..4].copy_from_slice(b"AVBf");
        footer[20..28].copy_from_slice(&0u64.to_be_bytes());
        footer[28..36].copy_from_slice(&64u64.to_be_bytes());
        img.truncate(64);
        img.extend_from_slice(&footer);
        std::fs::write(&broken, img).unwrap();
        // The plain image is no AVB image: nothing to say.
        assert!(avb_pair("system", &plain, &plain).is_empty());
        let found = avb_pair("system", &plain, &broken);
        assert_eq!(
            found.len(),
            1,
            "{:?}",
            found.iter().map(|c| c.rule).collect::<Vec<_>>()
        );
        assert_eq!(found[0].rule, "diff-avb-unchecked");
        assert_eq!(found[0].severity, Severity::Info);
        assert!(found[0].subject.contains("new"));
    }

    #[test]
    fn avb_digest_churn_on_the_same_descriptors_is_not_a_finding() {
        let old = vbmeta(1, 0, vec![hash("boot", "sha256")]);
        let mut new = old.clone();
        new.descriptors = vec![Descriptor::Hash(crate::avb::HashDescriptor {
            partition: "boot".into(),
            algorithm: "sha256".into(),
            image_size: 9,
            salt: vec![1],
            digest: vec![2],
            flags: 0,
        })];
        assert!(avb_changes("vbmeta", &old, &new).is_empty());
    }
}
