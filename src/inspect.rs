//! On-demand decode of one property (`prop`) or one init service (`init`) from an image (#222).
//! Read-only and bounded: it reads the same property and `.rc` files `audit` reads, under the same
//! size and count caps, and only the ones it needs for the lookup.

use crate::audit::{MAX_TEXT_BYTES, MAX_TEXT_FILES};
use crate::initrc;
use crate::ramdisk::{MAX_PROP_FILE, is_prop_file};
use crate::tree::{Entry, Kind, Tree};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::path::Path;

/// One `key=value` line that sets the property, and the file it is in.
struct PropSource {
    file: String,
    value: String,
}

/// A service block from an `.rc` file.
struct ServiceSource {
    file: String,
    service: initrc::Service,
}

/// The regular, readable-size text files whose path `want` accepts, with the caps applied.
fn text_entries(entries: &[Entry], want: impl Fn(&str) -> bool) -> Result<Vec<&Entry>> {
    let mut picked = Vec::new();
    let mut bytes = 0u64;
    for e in entries {
        if !matches!(e.kind, Kind::File) || e.size > MAX_PROP_FILE || !want(&e.path) {
            continue;
        }
        bytes += e.size;
        if picked.len() >= MAX_TEXT_FILES || bytes > MAX_TEXT_BYTES {
            bail!(
                "the image has more than {MAX_TEXT_FILES} text files or {MAX_TEXT_BYTES} bytes of them: refusing to read them all"
            );
        }
        picked.push(e);
    }
    Ok(picked)
}

fn display_path(path: &str) -> &str {
    path.trim_start_matches('/')
}

/// Every `key=value` line that sets `name`, in image order, and how many property files were read.
fn prop_sources(tree: &Tree, entries: &[Entry], name: &str) -> Result<(Vec<PropSource>, usize)> {
    let files = text_entries(entries, is_prop_file)?;
    let mut hits = Vec::new();
    for e in &files {
        let mut buf = Vec::new();
        tree.cat_path(&e.path, &mut buf)?;
        let text = String::from_utf8_lossy(&buf);
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            if k.trim() == name {
                hits.push(PropSource {
                    file: display_path(&e.path).to_string(),
                    value: v.trim().to_string(),
                });
            }
        }
    }
    Ok((hits, files.len()))
}

/// Every `service <name>` block in the image's `.rc` files, and how many `.rc` files were read.
fn service_sources(
    tree: &Tree,
    entries: &[Entry],
    name: &str,
) -> Result<(Vec<ServiceSource>, usize)> {
    let files = text_entries(entries, |p| p.ends_with(".rc"))?;
    let mut hits = Vec::new();
    for e in &files {
        let mut buf = Vec::new();
        tree.cat_path(&e.path, &mut buf)?;
        let rc = initrc::parse(&String::from_utf8_lossy(&buf));
        for service in rc.services.into_iter().filter(|s| s.name == name) {
            hits.push(ServiceSource {
                file: display_path(&e.path).to_string(),
                service,
            });
        }
    }
    Ok((hits, files.len()))
}

fn prop_json(hits: &[PropSource], name: &str) -> Value {
    Value::Array(
        hits.iter()
            .map(|h| json!({ "key": name, "value": h.value, "file": h.file }))
            .collect(),
    )
}

fn service_json(hits: &[ServiceSource]) -> Value {
    Value::Array(
        hits.iter()
            .map(|h| {
                let s = &h.service;
                json!({
                    "file": h.file,
                    "name": s.name,
                    "path": s.path,
                    "args": s.args,
                    "classes": s.classes,
                    "user": s.user,
                    "groups": s.groups,
                    "capabilities": s.capabilities,
                    "seclabel": s.seclabel,
                    "disabled": s.disabled,
                    "oneshot": s.oneshot,
                    "critical": s.critical,
                    "sockets": s.sockets.iter().map(|k| json!({
                        "name": k.name, "kind": k.kind, "perm": k.perm,
                        "user": k.user, "group": k.group,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn prop_text(hits: &[PropSource], name: &str, searched: usize) -> String {
    if hits.is_empty() {
        return format!("{name} is not set (searched {searched} property files)");
    }
    hits.iter()
        .map(|h| format!("{name}={}  {}", h.value, h.file))
        .collect::<Vec<_>>()
        .join("\n")
}

fn service_text(hits: &[ServiceSource], name: &str, searched: usize) -> String {
    if hits.is_empty() {
        return format!("no service {name} (searched {searched} init .rc files)");
    }
    let mut out = Vec::new();
    for h in hits {
        let s = &h.service;
        out.push(format!(
            "service {} {} {}  ({})",
            s.name,
            s.path,
            s.args.join(" "),
            h.file
        ));
        if !s.classes.is_empty() {
            out.push(format!("  class {}", s.classes.join(" ")));
        }
        if let Some(u) = &s.user {
            out.push(format!("  user {u}"));
        }
        if !s.groups.is_empty() {
            out.push(format!("  group {}", s.groups.join(" ")));
        }
        if !s.capabilities.is_empty() {
            out.push(format!("  capabilities {}", s.capabilities.join(" ")));
        }
        if let Some(l) = &s.seclabel {
            out.push(format!("  seclabel {l}"));
        }
        for k in &s.sockets {
            out.push(format!("  socket {} {} {}", k.name, k.kind, k.perm));
        }
        for (on, flag) in [
            (s.disabled, "disabled"),
            (s.oneshot, "oneshot"),
            (s.critical, "critical"),
        ] {
            if on {
                out.push(format!("  {flag}"));
            }
        }
    }
    out.join("\n")
}

pub fn prop_command(image: &Path, name: &str, json: bool) -> Result<()> {
    let tree = Tree::open(image)?;
    let entries = tree.entries()?;
    let (hits, searched) = prop_sources(&tree, &entries, name)?;
    let text = if json {
        serde_json::to_string_pretty(&prop_json(&hits, name))?
    } else {
        prop_text(&hits, name, searched)
    };
    crate::print_out(&text)
}

pub fn init_command(image: &Path, service: &str, json: bool) -> Result<()> {
    let tree = Tree::open(image)?;
    let entries = tree.entries()?;
    let (hits, searched) = service_sources(&tree, &entries, service)?;
    let text = if json {
        serde_json::to_string_pretty(&service_json(&hits))?
    } else {
        service_text(&hits, service, searched)
    };
    crate::print_out(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_block_text_shows_its_flags_and_sockets() {
        let rc = initrc::parse(
            "service adbd /sbin/adbd --root\n    class core\n    disabled\n    socket adbd stream 660 system system\n",
        );
        let hits = vec![ServiceSource {
            file: "init.rc".into(),
            service: rc.services.into_iter().next().unwrap(),
        }];
        let text = service_text(&hits, "adbd", 1);
        assert!(
            text.starts_with("service adbd /sbin/adbd --root  (init.rc)"),
            "{text}"
        );
        assert!(text.contains("  class core"), "{text}");
        assert!(text.contains("  disabled"), "{text}");
        assert!(text.contains("  socket adbd stream 660"), "{text}");
    }

    #[test]
    fn a_missing_property_names_the_count_searched() {
        assert_eq!(
            prop_text(&[], "ro.x", 3),
            "ro.x is not set (searched 3 property files)"
        );
    }
}
