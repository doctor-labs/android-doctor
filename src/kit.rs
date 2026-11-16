//! android-doctor as a doctor-kit `Doctor`: the identity, the baseline parsing, the human report
//! and the JSON/SARIF rendering the shared kit pipeline (`finish_with`) calls. The domain stays
//! here: the rules and the findings are produced by `audit`, `doctor` and `fwdiff`.

use crate::term::{Renderer, Style, sanitize};
use crate::tree::{Entry, Kind, Tree};
use crate::{audit, doctor, findings};
use anyhow::Context;
use doctor_kit::baseline::Saved;
use doctor_kit::doctor_core::Score;
use doctor_kit::doctor_core::{BaselineState, Envelope, Finding};
use doctor_kit::{Check, Collected, Ctx, Doctor, Face, Node, ScanFailure, TargetKind, Theme};
use serde_json::Value;
use std::cell::Cell;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// A no-op progress sink.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopProgress;

impl doctor_kit::Progress for NoopProgress {
    fn event(&self, _e: &doctor_kit::ProgressEvent) {}
}

/// What one `audit` / `doctor scan` / `diff` run needs to present its result.
pub struct Report {
    /// The findings in scan order (SARIF lists them in this order).
    pub all: Vec<findings::Finding>,
    pub baseline_path: Option<PathBuf>,
    /// `--json` or `--score`: stdout is the machine report, the baseline note goes to stderr.
    pub machine: bool,
    /// The command's own text (per-image report, file changes).
    pub domain: Option<String>,
    /// It replaces the face when piped without `--face`; otherwise it precedes the face.
    pub domain_replaces_face: bool,
    pub face_explicit: bool,
    pub no_color: bool,
}

#[derive(Default)]
pub struct AndroidDoctor {
    /// Fingerprints of the findings that say a rule did not run. A baseline never vouches for one.
    pub gaps: HashSet<String>,
    pub report: Option<Report>,
    /// New (non-gap) findings under a baseline, for the gate message.
    pub new_findings: Cell<usize>,
    /// What `shell` and `explore` look at: a firmware directory or one image.
    pub subject: Option<PathBuf>,
}

/// Children listed per directory node; a hostile image can hold millions of entries.
const MAX_CHILDREN: usize = 5000;
/// Bytes of a file `cat`/`decode` shows.
const MAX_FILE_BYTES: usize = 64 << 10;

/// A writer that keeps the first `MAX_FILE_BYTES` and then stops the copy.
struct Capped(Vec<u8>);
impl std::io::Write for Capped {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let room = MAX_FILE_BYTES - self.0.len();
        self.0.extend_from_slice(&b[..b.len().min(room)]);
        if b.len() > room {
            return Err(std::io::Error::other("capped"));
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn entry_node(image: &Path, e: &Entry) -> Node {
    let name = e.path.rsplit('/').next().unwrap_or(&e.path);
    let kind = match e.kind {
        Kind::File => "file",
        Kind::Dir => "dir",
        Kind::Symlink => "symlink",
        _ => "special",
    };
    let link = e.link.as_deref().map(|l| format!(" -> {}", sanitize(l)));
    let mut n = Node::new(
        &sanitize(name),
        kind,
        format!(
            "{:04o} {}:{} {} bytes{}",
            e.mode,
            e.uid,
            e.gid,
            e.size,
            link.unwrap_or_default()
        ),
    )
    .meta("image", image.display().to_string())
    .meta("path", format!("/{}", e.path))
    .meta("mode", format!("{:04o}", e.mode))
    .meta("size", e.size);
    if let Some((_, label)) = e.xattrs.iter().find(|(k, _)| k == "security.selinux") {
        n = n.meta("selinux", sanitize(label));
    }
    n
}

/// `stat [sel]`: the entry's own metadata (inode, owner, mode, size, links, mtime, label), read
/// from the image's directory listing. The image root has no entry, so it is refused.
fn stat_command(
    s: &mut doctor_kit::session::Session<'_>,
    args: &[String],
) -> Result<doctor_kit::session::Reply, String> {
    let node = s.node(args.first().map(String::as_str))?;
    let image = node
        .meta
        .get("image")
        .and_then(Value::as_str)
        .map(String::from);
    let path = node
        .meta
        .get("path")
        .and_then(Value::as_str)
        .map(String::from);
    let (Some(image), Some(path)) = (image, path) else {
        return Err("stat: not inside an opened image; `cd` into one first".into());
    };
    let (parent, name) = path
        .rsplit_once('/')
        .ok_or_else(|| "stat: not a file in the image".to_string())?;
    if name.is_empty() {
        return Err("stat: the image root has no entry of its own; `info` shows it".into());
    }
    let parent = if parent.is_empty() { "/" } else { parent };
    let entries = Tree::open(Path::new(&image))
        .and_then(|t| t.list_dir(parent))
        .map_err(|e| format!("stat: {e:#}"))?;
    let e = entries
        .iter()
        .find(|e| e.path.rsplit('/').next() == Some(name))
        .ok_or_else(|| format!("stat: {path} is not in its directory listing"))?;
    let label = e
        .xattrs
        .iter()
        .find(|(k, _)| k == "security.selinux")
        .map_or_else(|| "-".to_string(), |(_, v)| sanitize(v));
    let link = e
        .link
        .as_deref()
        .map_or_else(String::new, |l| format!("\n  link: {}", sanitize(l)));
    let text = format!(
        "{path}\n  type: {}\n  mode: {:04o}\n  owner: {}:{}\n  size: {}\n  inode: {}  links: {}\n  mtime: {}\n  selinux: {label}{link}",
        e.kind.name(),
        e.mode,
        e.uid,
        e.gid,
        e.size,
        e.ino,
        e.nlink,
        e.mtime,
    );
    Ok(doctor_kit::session::Reply::new(
        text,
        crate::tree::entry_json(e),
    ))
}

/// `decode` of an init `.rc`: the counts, then one line per import, action and service.
fn initrc_view(text: &str) -> String {
    let rc = crate::initrc::parse(text);
    let mut lines = vec![format!(
        "{} imports, {} actions, {} services",
        rc.imports.len(),
        rc.actions.len(),
        rc.services.len()
    )];
    lines.extend(rc.imports.iter().map(|i| format!("import {}", sanitize(i))));
    lines.extend(
        rc.actions
            .iter()
            .map(|a| format!("on {}", sanitize(&a.triggers.join(" && ")))),
    );
    for s in &rc.services {
        let mut flags: Vec<String> = s.classes.iter().map(|c| format!("class {c}")).collect();
        if let Some(u) = &s.user {
            flags.push(format!("user {u}"));
        }
        let tail = if flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", sanitize(&flags.join(", ")))
        };
        lines.push(format!(
            "service {} {}{tail}",
            sanitize(&s.name),
            sanitize(&s.path)
        ));
    }
    lines.join("\n")
}

/// `decode` of a property file: `key = value` per property; comments and blank lines dropped.
fn props_view(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| format!("{} = {}", sanitize(k.trim()), sanitize(v.trim())))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse `-o <path>` and `--force` from session command args, returning (output, force, rest).
fn take_output_flag(args: &[String]) -> Result<(Option<PathBuf>, bool, Vec<String>), String> {
    let mut out = None;
    let mut force = false;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                let p = args
                    .get(i)
                    .ok_or_else(|| "expected a path after -o".to_string())?;
                out = Some(PathBuf::from(p));
            }
            "--force" => force = true,
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    Ok((out, force, rest))
}

/// `hexpatch <file> <from-hex> <to-hex> -o <output> [--force]`
/// Binary hex patch (magiskboot-style): replace every occurrence of a hex pattern.
fn hexpatch_command(
    _s: &mut doctor_kit::session::Session<'_>,
    args: &[String],
) -> Result<doctor_kit::session::Reply, String> {
    let (out, force, rest) = take_output_flag(args)?;
    if rest.len() != 3 {
        return Err(
            "usage: hexpatch <file> <from-hex> <to-hex> -o <output> [--force]".into(),
        );
    }
    let output =
        out.ok_or_else(|| "hexpatch needs -o <output> (never modifies the input)".to_string())?;
    let count = crate::hexpatch::run(Path::new(&rest[0]), &rest[1], &rest[2], &output, force)
        .map_err(|e| format!("hexpatch: {e:#}"))?;
    let text = format!(
        "patched {} occurrence(s) in {} -> {}",
        count,
        rest[0],
        output.display()
    );
    Ok(doctor_kit::session::Reply::new(
        text,
        serde_json::json!({"ok": true, "replacements": count, "output": output.display().to_string()}),
    ))
}

/// `cpio <boot.img> put <src> <dest> -o <output> [--force]`
/// `cpio <boot.img> rm <path> -o <output> [--force]`
/// Magiskboot-style cpio edit on an uncompressed ramdisk in a boot image (v0-2).
/// Writes a NEW image; the input is never changed.
fn cpio_command(
    _s: &mut doctor_kit::session::Session<'_>,
    args: &[String],
) -> Result<doctor_kit::session::Reply, String> {
    let (out, force, rest) = take_output_flag(args)?;
    let output =
        out.ok_or_else(|| "cpio needs -o <output> (never modifies the input)".to_string())?;
    if rest.len() < 2 {
        return Err(
            "usage: cpio <boot.img> put <src> <dest> -o <out> | cpio <boot.img> rm <path> -o <out>"
                .into(),
        );
    }
    let image = Path::new(&rest[0]);
    let op = rest[1].as_str();
    let (puts, rms): (Vec<String>, Vec<String>) = match op {
        "put" | "add" => {
            if rest.len() != 4 {
                return Err("usage: cpio <boot.img> put <src> <dest> -o <out>".into());
            }
            (vec![format!("{}={}", rest[2], rest[3])], vec![])
        }
        "rm" | "remove" | "del" => {
            if rest.len() != 3 {
                return Err("usage: cpio <boot.img> rm <path> -o <out>".into());
            }
            (vec![], vec![rest[2].clone()])
        }
        _ => {
            return Err(format!(
                "cpio: unknown operation {op:?} (supported: put, rm)"
            ));
        }
    };
    // Capture stdout from ramdisk_edit::run by running it; it prints plan on success.
    // We call with yes=true to actually write.
    crate::ramdisk_edit::run(image, &puts, &rms, &output, force, true)
        .map_err(|e| format!("cpio: {e:#}"))?;
    let action = if !puts.is_empty() {
        format!("put {}", puts[0])
    } else {
        format!("rm {}", rms[0])
    };
    let text = format!(
        "cpio {action} in {} -> {} (read back ok)",
        image.display(),
        output.display()
    );
    Ok(doctor_kit::session::Reply::new(
        text,
        serde_json::json!({
            "ok": true,
            "image": image.display().to_string(),
            "output": output.display().to_string(),
            "puts": puts,
            "rms": rms,
        }),
    ))
}

/// `dtb <file> print`
/// `dtb <file> patch [-o <output>] [--force] [--verity] [--encryption]`
/// Magiskboot-style DTB operations: print or patch verity/encryption markers in an FDT blob.
fn dtb_command(
    _s: &mut doctor_kit::session::Session<'_>,
    args: &[String],
) -> Result<doctor_kit::session::Reply, String> {
    if args.is_empty() {
        return Err("usage: dtb <file> print | dtb <file> patch -o <out> [--force] [--verity] [--encryption]".into());
    }
    let file = Path::new(&args[0]);
    let op = args.get(1).map(String::as_str).unwrap_or("print");
    match op {
        "print" => {
            let text = crate::dtb_edit::print_dtb(file).map_err(|e| format!("dtb: {e:#}"))?;
            Ok(doctor_kit::session::Reply::new(
                text,
                serde_json::json!({"file": file.display().to_string()}),
            ))
        }
        "patch" => {
            let (out, force, rest) = take_output_flag(&args[2..])?;
            let output = out.ok_or_else(|| {
                "dtb patch needs -o <output> (never modifies the input)".to_string()
            })?;
            let mut verity = false;
            let mut encryption = false;
            for r in &rest {
                match r.as_str() {
                    "--verity" => verity = true,
                    "--encryption" | "--encrypt" => encryption = true,
                    other => return Err(format!("dtb patch: unknown flag {other}")),
                }
            }
            if !verity && !encryption {
                verity = true;
                encryption = true;
            }
            let changes = crate::dtb_edit::run_patch(file, &output, verity, encryption, force)
                .map_err(|e| format!("dtb: {e:#}"))?;
            let text = format!(
                "dtb patch: blanked {} marker(s) in {} -> {} (verity={} encryption={})",
                changes,
                file.display(),
                output.display(),
                verity,
                encryption
            );
            Ok(doctor_kit::session::Reply::new(
                text,
                serde_json::json!({
                    "ok": true,
                    "file": file.display().to_string(),
                    "output": output.display().to_string(),
                    "changes": changes,
                    "verity": verity,
                    "encryption": encryption,
                }),
            ))
        }
        _ => Err(format!(
            "dtb: unknown operation {op:?} (supported: print, patch)"
        )),
    }
}

impl AndroidDoctor {
    /// The scan context of the interactive commands: nothing is walked, the root is the subject.
    #[cfg(any(feature = "shell", feature = "explore"))]
    pub fn ctx(&self) -> Ctx {
        let mut ctx = Ctx::detached(
            doctor_kit::Config::default(),
            doctor_kit::doctor_core::Severity::Critical,
        );
        if let Some(s) = &self.subject {
            ctx.root = s.clone();
        }
        ctx
    }

    /// The findings a human sees: all of them, or only the new ones under a baseline.
    fn shown(env: &Envelope) -> Vec<Finding> {
        let baselined = env.baseline.is_some();
        env.findings
            .iter()
            .filter(|f| !baselined || f.baseline_state == Some(BaselineState::New))
            .cloned()
            .collect()
    }

    /// `baseline FILE: N suppressed as known, M new[, K coverage gap(s) listed]`
    fn note(&self, env: &Envelope) -> Option<String> {
        let counts = env.baseline?;
        let path = self.report.as_ref()?.baseline_path.as_deref()?;
        let shown = Self::shown(env);
        let gaps = shown.iter().filter(|f| self.is_gap(f)).count();
        let listed = match gaps {
            0 => String::new(),
            n => format!(", {n} coverage gap(s) listed"),
        };
        Some(format!(
            "baseline {}: {} suppressed as known, {} new{listed}",
            path.display(),
            counts.unchanged,
            shown.len() - gaps
        ))
    }
}

/// A previous `--json` report, reduced to its fingerprints: a doctor/1 envelope (an object with a
/// `findings` array), or the pre-0.4 bare array. Anything else is an error, never an empty
/// baseline: a mistyped or wrong file silently disabling the gate would be worse than failing.
fn read_baseline(path: &Path) -> anyhow::Result<Saved> {
    let shown = path.display();
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read baseline {shown}"))?;
    let doc: Value = serde_json::from_str(&text)
        .with_context(|| format!("baseline {shown} is not valid JSON"))?;
    let rows = match &doc {
        Value::Array(a) => Some(a),
        Value::Object(o) => o.get("findings").and_then(Value::as_array),
        _ => None,
    };
    let Some(rows) = rows else {
        anyhow::bail!(
            "baseline {shown} is not an android-doctor report: expected the output of \
             `doctor scan --json` or `audit --json`"
        );
    };
    let mut fingerprints = HashSet::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(fp) = row.get("fingerprint").and_then(Value::as_str) else {
            anyhow::bail!(
                "baseline {shown} is not an android-doctor report: finding {} has no \
                 fingerprint (was it written by an older version?)",
                i + 1
            );
        };
        fingerprints.insert(fp.to_string());
    }
    Ok(Saved { fingerprints, doc })
}

impl Doctor for AndroidDoctor {
    fn name(&self) -> &str {
        "android-doctor"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn about(&self) -> &str {
        "Extract and audit Android OTA/ROM images"
    }
    fn categories(&self) -> Vec<&'static str> {
        vec!["security", "quality"]
    }
    fn checks(&self) -> Vec<Box<dyn Check>> {
        vec![]
    }
    /// `stat` in the shell, plus interactive ramdisk/boot/DTB editing commands (write to new outputs only).
    fn commands(&self) -> Vec<doctor_kit::session::Command> {
        vec![
            doctor_kit::session::Command {
                name: "stat",
                help: "stat [sel]         one file or directory of an opened image: mode, owner, size, links, mtime",
                flags: &[],
                run: stat_command,
            },
            doctor_kit::session::Command {
                name: "cpio",
                help: "cpio <boot.img> put <src> <dest> -o <out> [--force] | cpio <boot.img> rm <path> -o <out>  edit ramdisk (v0-2, compressed or plain cpio) into a new image",
                flags: &[],
                run: cpio_command,
            },
            doctor_kit::session::Command {
                name: "hexpatch",
                help: "hexpatch <file> <from-hex> <to-hex> -o <out> [--force]  binary hex patch (magiskboot-style), writes a new file",
                flags: &[],
                run: hexpatch_command,
            },
            doctor_kit::session::Command {
                name: "dtb",
                help: "dtb <file> print | dtb <file> patch -o <out> [--force] [--verity] [--encryption]  print or patch a DTB (magiskboot-style)",
                flags: &[],
                run: dtb_command,
            },
        ]
    }
    /// The subject is an image, a directory of images or two builds, chosen by the command.
    fn target(&self) -> TargetKind {
        TargetKind::Detached
    }
    fn is_gap(&self, f: &Finding) -> bool {
        self.gaps.contains(&f.fingerprint)
    }
    fn mcp_tools(&self) -> Option<Vec<doctor_kit::McpTool>> {
        Some(crate::mcp::tools())
    }
    /// The texts of the first MCP server: the answers to a bad call stay what they were.
    fn mcp_texts(&self) -> doctor_kit::mcp::McpTexts {
        doctor_kit::mcp::McpTexts {
            unknown_tool: "unknown tool {t}".into(),
            tool_error: "{e}".into(),
            server_info: Some(("android-doctor".into(), env!("CARGO_PKG_VERSION").into())),
            ..Default::default()
        }
    }
    fn score(&self, findings: &[Finding], _: &Ctx) -> Option<Score> {
        Some(findings::score_core(findings, &|f| self.is_gap(f)))
    }
    /// A directory gets the `doctor scan` health scan, an image gets the `audit` rules.
    fn collect(&self, _: &Ctx) -> Result<Collected, ScanFailure> {
        let subject = self
            .subject
            .as_deref()
            .ok_or_else(|| ScanFailure::new("no firmware directory or image given"))?;
        let found = if subject.is_dir() {
            doctor::scan_scoped(subject).map(findings::from_doctor)
        } else {
            audit::audit_image(subject).map(|a| findings::from_audit(&[a]))
        }
        .map_err(|e| ScanFailure::new(format!("{e:#}")))?;
        let gaps = found.iter().filter(|f| f.gap).count();
        Ok(Collected {
            findings: found.iter().map(findings::Finding::to_core).collect(),
            data: serde_json::json!({}),
            gaps,
        })
    }
    /// The findings tree of the kit, plus the firmware itself under `images`: image, directory,
    /// file, each level read when it is first opened (`expand`).
    fn tree(&self, env: &Envelope, ctx: &Ctx) -> Node {
        let mut root = doctor_kit::session::default_tree(env, ctx);
        if self.subject.is_some() {
            root = root.child(Node::new("images", "images", "the images and their files"));
        }
        root
    }
    fn expand(&self, _: &Envelope, _: &Ctx, _: &[String], node: &Node) -> Option<Vec<Node>> {
        let meta = |k: &str| node.meta.get(k).and_then(Value::as_str).map(String::from);
        let failed = |e: anyhow::Error| {
            vec![Node::new(
                "(unreadable)",
                "error",
                sanitize(&format!("{e:#}")),
            )]
        };
        match node.kind.as_str() {
            "images" => {
                let subject = self.subject.clone()?;
                Some(match audit::image_list(&[subject]) {
                    Ok(images) => images
                        .iter()
                        .map(|p| {
                            let name = p
                                .file_stem()
                                .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
                            Node::new(&sanitize(&name), "image", p.display().to_string())
                                .meta("image", p.display().to_string())
                                .meta("path", "/")
                        })
                        .collect(),
                    Err(e) => failed(e),
                })
            }
            "image" | "dir" => {
                let image = PathBuf::from(meta("image")?);
                let dir = meta("path")?;
                Some(match Tree::open(&image).and_then(|t| t.list_dir(&dir)) {
                    Ok(entries) => {
                        let mut kids: Vec<Node> = entries
                            .iter()
                            .take(MAX_CHILDREN)
                            .map(|e| entry_node(&image, e))
                            .collect();
                        if entries.len() > MAX_CHILDREN {
                            kids.push(Node::new(
                                "(more)",
                                "note",
                                format!("{} more entries not listed", entries.len() - MAX_CHILDREN),
                            ));
                        }
                        kids
                    }
                    Err(e) => failed(e),
                })
            }
            _ => None,
        }
    }
    /// A file's first 64 KiB: text as it is (control characters blanked), anything else as a hex dump.
    fn decode(&self, node: &Node) -> Option<String> {
        if node.kind != "file" {
            return None;
        }
        let image = node.meta.get("image")?.as_str()?;
        let path = node.meta.get("path")?.as_str()?;
        let mut buf = Capped(Vec::new());
        let read = Tree::open(Path::new(image)).and_then(|t| t.cat_path(path, &mut buf));
        let truncated = buf.0.len() >= MAX_FILE_BYTES;
        let base = path.rsplit('/').next().unwrap_or(path);
        let body = match std::str::from_utf8(&buf.0) {
            Ok(t) if base.ends_with(".rc") => initrc_view(t),
            Ok(t) if base.ends_with(".prop") => props_view(t),
            Ok(t) => t.lines().map(sanitize).collect::<Vec<_>>().join("\n"),
            Err(_) => doctor_kit::node::hexdump(&buf.0),
        };
        let tail = match (&read, truncated) {
            (Err(e), false) => format!("\n(read failed: {})", sanitize(&format!("{e:#}"))),
            (_, true) => format!("\n(first {} KiB)", MAX_FILE_BYTES >> 10),
            _ => String::new(),
        };
        Some(body + &tail)
    }
    /// `ci install` refuses to touch any existing workflow unless `--force`.
    fn ci_overwrite(&self) -> doctor_kit::install::Overwrite {
        doctor_kit::install::Overwrite::Never
    }
    /// Sorted keys, as `doctor_core::Envelope::to_value` writes them: the output of every release.
    fn render_json(&self, env: &Envelope) -> String {
        serde_json::to_string_pretty(&env.to_value()).expect("an envelope is JSON") + "\n"
    }
    /// The tool's own SARIF (rule help, locations, `baselineState`), in scan order and without a
    /// trailing newline, as every release wrote it.
    fn render_sarif(&self, env: &Envelope) -> String {
        let baselined = env.baseline.is_some();
        let keep: HashSet<String> = Self::shown(env)
            .into_iter()
            .map(|f| f.fingerprint)
            .collect();
        let all = self.report.as_ref().map_or(&[][..], |r| &r.all[..]);
        let shown: Vec<findings::Finding> = all
            .iter()
            .filter(|f| keep.contains(&f.fingerprint))
            .cloned()
            .collect();
        serde_json::to_string_pretty(&findings::to_sarif(&shown, &env.score, baselined))
            .expect("SARIF is JSON")
    }
    /// The old parsing and error wording, no size cap; the error is rendered as every error is.
    fn load_baseline(&self, path: &Path) -> Result<Saved, ScanFailure> {
        let no_color = self.report.as_ref().is_some_and(|r| r.no_color);
        read_baseline(path)
            .map_err(|e| ScanFailure::plain(Renderer::new(Style::detect(no_color)).error(&e)))
    }
    /// Counts the new findings for the gate message and, when stdout is machine output, prints the
    /// baseline summary to stderr.
    fn baseline_hook(&self, _saved: &Value, env: &mut Envelope) -> Result<(), ScanFailure> {
        let shown = Self::shown(env);
        self.new_findings
            .set(shown.iter().filter(|f| !self.is_gap(f)).count());
        if self.report.as_ref().is_some_and(|r| r.machine)
            && let Some(n) = self.note(env)
        {
            eprintln!("{n}");
        }
        Ok(())
    }
    /// `audit` keeps its per-image report when piped without `--face`; `diff` keeps its file
    /// changes ahead of the face; under a baseline only the new findings are listed.
    fn render_human(&self, env: &Envelope, face: &Face, theme: &Theme) -> Option<String> {
        let r = self.report.as_ref()?;
        let shown = Self::shown(env);
        let mut view = env.clone();
        view.findings = shown.clone();
        let face_text = || doctor_kit::face::render(*face, &view, theme);
        let tty = std::io::stdout().is_terminal();
        let mut text = match &r.domain {
            Some(t) if r.domain_replaces_face && !tty && !r.face_explicit => t.clone(),
            Some(t) if !r.domain_replaces_face => format!("{t}\n{}", face_text().trim_end()),
            _ => face_text().trim_end().to_string(),
        };
        if let Some(n) = self.note(env) {
            if shown.is_empty() {
                text = "no new findings".to_string();
            }
            text.push_str(&format!("\n{n}"));
        }
        Some(text + "\n")
    }
}
