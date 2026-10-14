//! `apk-diff`: compare two builds of one APK. Each side is read and audited with the same APK
//! reader as `audit` (`apk::audit_apk_bytes`); the two are then compared on requested permissions,
//! manifest components (exported or new) and the signing certificates. What got worse becomes a
//! finding (rules `apk-diff-*`) so the diff gates CI like `diff`; the raw changes go under `data`.
//! Nothing is installed or run.
use crate::apk::{ApkInfo, Component, MAX_APK_BYTES, audit_apk_bytes};
use crate::findings::{Finding, Severity};
use crate::permissions;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What changed between the two APKs: the findings and the raw change data.
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub data: Value,
    pub text: String,
}

/// Read and audit one APK. Refuses files over the APK size cap and anything the reader rejects.
fn load(path: &Path) -> Result<ApkInfo> {
    let len = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if len > MAX_APK_BYTES {
        bail!(
            "{}: {len} bytes is over the {MAX_APK_BYTES}-byte APK limit",
            path.display()
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let audit = audit_apk_bytes(path, &bytes);
    audit.info.ok_or_else(|| {
        anyhow!(
            "{}: {}",
            path.display(),
            audit.error.unwrap_or_else(|| "not an APK".into())
        )
    })
}

/// A component is exported when it says so, or when it has an intent filter and no explicit
/// `android:exported` (the platform default for filters before Android 12).
fn exported(c: &Component) -> bool {
    c.exported.unwrap_or(c.has_intent_filter)
}

fn cert_set(a: &ApkInfo) -> BTreeSet<String> {
    a.signers.iter().map(|s| s.cert_sha256.clone()).collect()
}

/// Severity of a newly requested permission, from the permission catalogue: signature-level
/// permissions are High, runtime (dangerous) ones Medium, anything else Low.
fn permission_severity(name: &str) -> Severity {
    if permissions::is_signature(name) {
        Severity::High
    } else if permissions::is_dangerous(name) {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Compare the two audited builds. Pure: no I/O, so it is unit-tested on `ApkInfo` values.
pub fn compare(old: &ApkInfo, new: &ApkInfo) -> Outcome {
    let scope = if new.package_name.is_empty() {
        "apk".to_string()
    } else {
        new.package_name.clone()
    };
    let mut findings = Vec::new();
    let mut add =
        |rule: &str, severity, subject: &str, key: &str, message: String, remedy: &str| {
            findings.push(
                Finding {
                    rule: rule.into(),
                    category: "security".into(),
                    severity,
                    scope: scope.clone(),
                    subject: subject.to_string(),
                    key: key.to_string(),
                    message,
                    remedy: Some(remedy.to_string()),
                    gap: false,
                    uri: None,
                    fingerprint: String::new(),
                    baseline_state: None,
                }
                .seal(!subject.is_empty()),
            );
        };

    // Requested permissions: a permission the old build did not request.
    let old_perms: BTreeSet<&str> = old
        .manifest
        .uses_permissions
        .iter()
        .map(String::as_str)
        .collect();
    let new_perms: BTreeSet<&str> = new
        .manifest
        .uses_permissions
        .iter()
        .map(String::as_str)
        .collect();
    let perms_added: Vec<&str> = new_perms.difference(&old_perms).copied().collect();
    let perms_removed: Vec<&str> = old_perms.difference(&new_perms).copied().collect();
    for p in &perms_added {
        add(
            "apk-diff-new-permission",
            permission_severity(p),
            p,
            "",
            format!("new in this build: requests {p}"),
            "Drop the permission, or confirm the feature needs it",
        );
    }

    // Components: new, or newly exported without a guarding permission.
    let old_comps: BTreeMap<(&str, &str), &Component> = old
        .manifest
        .components
        .iter()
        .map(|c| ((c.kind.as_str(), c.name.as_str()), c))
        .collect();
    let mut comps_added = Vec::new();
    let mut comps_exported = Vec::new();
    for c in &new.manifest.components {
        if c.disabled || !exported(c) {
            continue;
        }
        let was = old_comps.get(&(c.kind.as_str(), c.name.as_str()));
        let newly_exported = was.is_none_or(|o| !exported(o));
        if !newly_exported {
            continue;
        }
        let what = if was.is_none() { "new" } else { "now exported" };
        if was.is_none() {
            comps_added.push(json!({"kind": c.kind, "name": c.name}));
        } else {
            comps_exported.push(json!({"kind": c.kind, "name": c.name}));
        }
        let severity = if c.guarded {
            Severity::Low
        } else {
            Severity::Medium
        };
        add(
            "apk-diff-exported-component",
            severity,
            &c.name,
            &c.kind,
            format!(
                "{what} {} {} is exported{}",
                c.kind,
                c.name,
                if c.guarded {
                    " behind a permission"
                } else {
                    " without a permission"
                }
            ),
            "Set android:exported=\"false\" or guard the component with a signature permission",
        );
    }

    // Signing certificates: any change of the signer set, when the old build was signed.
    let (old_certs, new_certs) = (cert_set(old), cert_set(new));
    let signer_changed = !old_certs.is_empty() && old_certs != new_certs;
    if signer_changed {
        let short = |s: &BTreeSet<String>| {
            s.iter()
                .map(|h| h.chars().take(16).collect::<String>())
                .collect::<Vec<_>>()
                .join(",")
        };
        add(
            "apk-diff-signer-changed",
            Severity::High,
            &scope,
            &short(&new_certs),
            format!(
                "signing certificate changed: {} -> {}",
                short(&old_certs),
                short(&new_certs)
            ),
            "Sign updates with the original key; a rotation needs a signing lineage Android accepts",
        );
    }

    let data = json!({
        "package": {"old": old.package_name, "new": new.package_name},
        "permissions": {"added": perms_added, "removed": perms_removed},
        "components": {"added": comps_added, "newly_exported": comps_exported},
        "signers": {
            "old": old_certs,
            "new": new_certs,
            "changed": signer_changed,
        },
    });
    let text = render_text(&data, old, new);
    Outcome {
        findings,
        data,
        text,
    }
}

fn render_text(d: &Value, old: &ApkInfo, new: &ApkInfo) -> String {
    let list = |v: &Value| {
        let items: Vec<String> = v
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| match x {
                        Value::String(s) => s.clone(),
                        other => format!(
                            "{} {}",
                            other["kind"].as_str().unwrap_or(""),
                            other["name"].as_str().unwrap_or("")
                        ),
                    })
                    .collect()
            })
            .unwrap_or_default();
        if items.is_empty() {
            "none".to_string()
        } else {
            items.join(", ")
        }
    };
    format!(
        "APK diff: {} {} -> {}\n  permissions added: {}\n  permissions removed: {}\n  components added: {}\n  components newly exported: {}\n  signer changed: {}\n",
        new.package_name,
        old.version_name.as_deref().unwrap_or("?"),
        new.version_name.as_deref().unwrap_or("?"),
        list(&d["permissions"]["added"]),
        list(&d["permissions"]["removed"]),
        list(&d["components"]["added"]),
        list(&d["components"]["newly_exported"]),
        if d["signers"]["changed"].as_bool() == Some(true) {
            "yes"
        } else {
            "no"
        },
    )
}

/// Compare two APK files (old, new).
pub fn run(old: &Path, new: &Path) -> Result<Outcome> {
    let (o, n) = (load(old)?, load(new)?);
    Ok(compare(&o, &n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apk::{ManifestAttrs, Signer};

    fn signer(sha: &str) -> Signer {
        Signer {
            scheme: "v2",
            cert_sha256: sha.into(),
            subject_cn: None,
            is_aosp_test_key: false,
            is_debug_cert: false,
            not_before: None,
            not_after: None,
            sig_alg: None,
            rsa_bits: None,
        }
    }

    fn comp(
        kind: &str,
        name: &str,
        exported: Option<bool>,
        filter: bool,
        guarded: bool,
    ) -> Component {
        Component {
            kind: kind.into(),
            name: name.into(),
            exported,
            has_intent_filter: filter,
            guarded,
            ..Component::default()
        }
    }

    fn apk(perms: &[&str], comps: Vec<Component>, certs: &[&str]) -> ApkInfo {
        ApkInfo {
            package_name: "com.example.app".into(),
            signers: certs.iter().map(|c| signer(c)).collect(),
            manifest: ManifestAttrs {
                package_name: "com.example.app".into(),
                uses_permissions: perms.iter().map(|p| p.to_string()).collect(),
                components: comps,
                ..ManifestAttrs::default()
            },
            ..ApkInfo::default()
        }
    }

    fn rules(o: &Outcome) -> Vec<(&str, Severity)> {
        o.findings
            .iter()
            .map(|f| (f.rule.as_str(), f.severity))
            .collect()
    }

    #[test]
    fn identical_builds_have_no_findings() {
        let a = apk(
            &["android.permission.INTERNET"],
            vec![comp("activity", "A", Some(false), false, false)],
            &["aa"],
        );
        let o = compare(&a, &a.clone());
        assert!(o.findings.is_empty(), "{:?}", rules(&o));
        assert_eq!(o.data["signers"]["changed"], json!(false));
    }

    #[test]
    fn new_permission_is_graded_by_protection_level() {
        let old = apk(&[], vec![], &["aa"]);
        let new = apk(
            &["android.permission.CAMERA", "android.permission.INTERNET"],
            vec![],
            &["aa"],
        );
        let o = compare(&old, &new);
        assert!(rules(&o).contains(&("apk-diff-new-permission", Severity::Medium)));
        assert!(rules(&o).contains(&("apk-diff-new-permission", Severity::Low)));
        assert_eq!(o.data["permissions"]["added"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn newly_exported_unguarded_component_is_medium() {
        let old = apk(
            &[],
            vec![comp("activity", "A", Some(false), false, false)],
            &["aa"],
        );
        let new = apk(
            &[],
            vec![comp("activity", "A", Some(true), false, false)],
            &["aa"],
        );
        let o = compare(&old, &new);
        assert_eq!(
            rules(&o),
            vec![("apk-diff-exported-component", Severity::Medium)]
        );
    }

    #[test]
    fn intent_filter_without_exported_attr_counts_as_exported() {
        let new = apk(&[], vec![comp("receiver", "R", None, true, false)], &["aa"]);
        let o = compare(&apk(&[], vec![], &["aa"]), &new);
        assert_eq!(
            rules(&o),
            vec![("apk-diff-exported-component", Severity::Medium)]
        );
        assert_eq!(
            o.findings[0].message,
            "new receiver R is exported without a permission"
        );
    }

    #[test]
    fn guarded_export_is_low_and_disabled_or_private_is_silent() {
        let new = apk(
            &[],
            vec![
                comp("service", "S", Some(true), false, true),
                comp("provider", "P", Some(false), false, false),
            ],
            &["aa"],
        );
        let o = compare(&apk(&[], vec![], &["aa"]), &new);
        assert_eq!(
            rules(&o),
            vec![("apk-diff-exported-component", Severity::Low)]
        );
    }

    #[test]
    fn signer_change_is_high_but_unsigned_old_build_is_not_compared() {
        let o = compare(&apk(&[], vec![], &["aa"]), &apk(&[], vec![], &["bb"]));
        assert_eq!(rules(&o), vec![("apk-diff-signer-changed", Severity::High)]);
        assert_eq!(o.data["signers"]["changed"], json!(true));
        let o = compare(&apk(&[], vec![], &[]), &apk(&[], vec![], &["bb"]));
        assert!(o.findings.is_empty());
    }
}
