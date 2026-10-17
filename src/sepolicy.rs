//! Text SELinux policy shipped in an image: the CIL sources (`*_sepolicy.cil`) and the
//! `*file_contexts` label files under `etc/selinux`. The compiled policy binary is not parsed.
//!
//! From the CIL, every `(typepermissive X)` is a domain that runs in permissive mode even when the
//! device enforces (CIL reference: secilc/docs/cil_type_statements.md, policy database version 23).
//! `(neverallow ...)` is a compile-time check; shipped CIL may still carry it. Its count is kept, and
//! a neverallow with plain names is matched exactly against plain `allow` rules. From the label files, an entry is flagged only when its label names a permissive domain.
use crate::tree::{Entry, Kind};
use anyhow::Result;
use serde_json::{Value, json};

/// Policy files read per image, their size, and the bytes of them.
pub const MAX_POLICY_FILES: usize = 64;
pub const MAX_POLICY_FILE_BYTES: u64 = 8 << 20;
pub const MAX_POLICY_TOTAL_BYTES: u64 = 64 << 20;
/// Parenthesis nesting and atoms the CIL parser accepts in one file.
const MAX_DEPTH: usize = 64;
const MAX_ATOMS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq)]
pub enum Sexp {
    Atom(String),
    List(Vec<Sexp>),
}

/// A plain `(allow|neverallow src tgt (class (perm ...)))`, names qualified by their block.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rule {
    pub src: String,
    pub tgt: String,
    pub class: String,
    pub perms: Vec<String>,
}

/// One CIL file: the domains it makes permissive, its neverallow count, and why it could not be read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CilFile {
    pub file: String,
    pub permissive: Vec<String>,
    pub neverallow: usize,
    pub allows: Vec<Rule>,
    pub neverallows: Vec<Rule>,
    pub error: Option<String>,
}

/// One file_contexts file: entries, lines that did not parse, and the labels that name a
/// permissive domain as `(path regex, context)`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContextsFile {
    pub file: String,
    pub entries: usize,
    pub malformed: usize,
    pub unconfined: Vec<(String, String)>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SepolicyAudit {
    pub cil: Vec<CilFile>,
    pub contexts: Vec<ContextsFile>,
    /// Policy files not read because of the count or size limits.
    pub skipped: usize,
    /// (file, rule) for each shipped allow that a neverallow forbids.
    pub violations: Vec<(String, String)>,
}

/// Parse CIL text. `;` starts a comment to the end of the line and `"..."` is one atom. Iterative,
/// so nesting cannot overflow the stack; nesting and atom count are capped.
pub fn parse(text: &str) -> Result<Vec<Sexp>, String> {
    let mut stack: Vec<Vec<Sexp>> = vec![Vec::new()];
    let mut atoms = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == ';' {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        if c == '(' {
            chars.next();
            if stack.len() > MAX_DEPTH {
                return Err(format!("nesting deeper than {MAX_DEPTH}"));
            }
            stack.push(Vec::new());
            continue;
        }
        if c == ')' {
            chars.next();
            if stack.len() == 1 {
                return Err("unbalanced ')'".into());
            }
            let Some(list) = stack.pop() else {
                return Err("unbalanced ')'".into());
            };
            let Some(top) = stack.last_mut() else {
                return Err("unbalanced ')'".into());
            };
            top.push(Sexp::List(list));
            continue;
        }
        let atom = if c == '"' {
            chars.next();
            let mut s = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some(c) => s.push(c),
                    None => return Err("unterminated string".into()),
                }
            }
            s
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '(' || c == ')' || c == ';' {
                    break;
                }
                s.push(c);
                chars.next();
            }
            s
        };
        atoms += 1;
        if atoms > MAX_ATOMS {
            return Err(format!("more than {MAX_ATOMS} atoms"));
        }
        let Some(top) = stack.last_mut() else {
            return Err("unbalanced input".into());
        };
        top.push(Sexp::Atom(atom));
    }
    if stack.len() != 1 {
        return Err("unclosed '('".into());
    }
    stack.pop().ok_or_else(|| "unbalanced input".to_string())
}

/// The domain name as the file means it: a `typepermissive` inside `(block healthd ...)` names
/// `healthd.process`, as the CIL reference example does.
fn qualify(block: &[String], name: &str) -> String {
    if block.is_empty() {
        name.to_string()
    } else {
        format!("{}.{name}", block.join("."))
    }
}

/// The rule when every name is plain. Attributes written with a star, complements (tilde, minus),
/// sets, nested permission lists and a bare class are not compared, so they give None.
fn plain_rule(block: &[String], src: &str, tgt: &str, cls: &[Sexp]) -> Option<Rule> {
    let plain = |s: &str| !s.is_empty() && !["*", "~", "-"].iter().any(|x| s.starts_with(x));
    let [Sexp::Atom(class), perms] = cls else {
        return None;
    };
    let perms = match perms {
        Sexp::Atom(p) => vec![p.clone()],
        Sexp::List(ps) => ps
            .iter()
            .map(|p| match p {
                Sexp::Atom(a) => Some(a.clone()),
                Sexp::List(_) => None,
            })
            .collect::<Option<Vec<_>>>()?,
    };
    if !plain(src)
        || !plain(tgt)
        || !plain(class.as_str())
        || perms.iter().any(|p| !plain(p.as_str()))
    {
        return None;
    }
    Some(Rule {
        src: qualify(block, src),
        tgt: qualify(block, tgt),
        class: class.clone(),
        perms,
    })
}

/// Allow rules that match a neverallow exactly (same source, target and class, and a shared
/// permission), as (file, rule). Attributes are not expanded, so a violation that holds only
/// through an attribute is not seen.
pub fn violations(cils: &[CilFile]) -> Vec<(String, String)> {
    let forbidden: Vec<&Rule> = cils.iter().flat_map(|c| &c.neverallows).collect();
    let mut out = Vec::new();
    for c in cils {
        for a in &c.allows {
            let hit = forbidden.iter().any(|n| {
                n.src == a.src
                    && n.tgt == a.tgt
                    && n.class == a.class
                    && a.perms.iter().any(|p| n.perms.contains(p))
            });
            if hit {
                let rule = format!(
                    "allow {} {} ({} ({}))",
                    a.src,
                    a.tgt,
                    a.class,
                    a.perms.join(" ")
                );
                out.push((c.file.clone(), rule));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn walk(nodes: &[Sexp], block: &mut Vec<String>, out: &mut CilFile) {
    for n in nodes {
        let Sexp::List(items) = n else { continue };
        match items.as_slice() {
            [Sexp::Atom(head), Sexp::Atom(name), ..] if head == "typepermissive" => {
                out.permissive.push(qualify(block, name));
            }
            [
                Sexp::Atom(head),
                Sexp::Atom(src),
                Sexp::Atom(tgt),
                Sexp::List(cls),
            ] if head == "allow" => {
                out.allows.extend(plain_rule(block, src, tgt, cls));
            }
            [
                Sexp::Atom(head),
                Sexp::Atom(src),
                Sexp::Atom(tgt),
                Sexp::List(cls),
            ] if head == "neverallow" => {
                out.neverallow += 1;
                out.neverallows.extend(plain_rule(block, src, tgt, cls));
            }
            [Sexp::Atom(head), ..] if head == "neverallow" => out.neverallow += 1,
            [Sexp::Atom(head), Sexp::Atom(name), rest @ ..] if head == "block" => {
                block.push(name.clone());
                walk(rest, block, out);
                block.pop();
            }
            _ => walk(items, block, out),
        }
    }
}

/// Read one CIL text into its permissive domains and neverallow count.
fn read_cil(file: &str, text: &str) -> CilFile {
    let mut out = CilFile {
        file: file.to_string(),
        ..Default::default()
    };
    match parse(text) {
        Ok(nodes) => walk(&nodes, &mut Vec::new(), &mut out),
        Err(e) => out.error = Some(e),
    }
    out.permissive.sort();
    out.permissive.dedup();
    out
}

/// Parse one file_contexts text: entry count, malformed line count, and the labels whose type
/// looks unconfined or permissive (filtered against the real permissive set by the caller).
fn read_contexts(text: &str) -> (usize, usize, Vec<(String, String)>) {
    let (mut entries, mut malformed) = (0usize, 0usize);
    let mut candidates = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let (re, ctx) = match toks.as_slice() {
            [re, ctx] => (*re, *ctx),
            [re, flag, ctx] if flag.starts_with('-') => (*re, *ctx),
            _ => {
                malformed += 1;
                continue;
            }
        };
        if ctx != "<<none>>" && ctx.split(':').count() < 3 {
            malformed += 1;
            continue;
        }
        entries += 1;
        let ty = ctx
            .split(':')
            .nth(2)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ty.contains("unconfined") || ty.contains("permissive") {
            candidates.push((re.to_string(), ctx.to_string()));
        }
    }
    (entries, malformed, candidates)
}

/// Whether a path is a CIL policy file or a file_contexts file under an `etc/selinux` directory.
fn kind_of(path: &str) -> Option<bool> {
    let padded = format!("/{}", path.trim_start_matches('/'));
    if !padded.contains("/etc/selinux/") {
        return None;
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    if base.ends_with("_sepolicy.cil") {
        Some(true)
    } else if base == "file_contexts" || base.ends_with("_file_contexts") {
        Some(false)
    } else {
        None
    }
}

/// Read every shipped text policy file of an image. `read` gets an in-image path.
pub fn scan(entries: &[Entry], read: &mut dyn FnMut(&str) -> Result<Vec<u8>>) -> SepolicyAudit {
    let mut out = SepolicyAudit::default();
    let mut budget = MAX_POLICY_TOTAL_BYTES;
    let mut files = 0usize;
    for e in entries {
        if e.kind != Kind::File {
            continue;
        }
        let Some(is_cil) = kind_of(&e.path) else {
            continue;
        };
        if files >= MAX_POLICY_FILES || e.size > MAX_POLICY_FILE_BYTES || e.size > budget {
            out.skipped += 1;
            continue;
        }
        files += 1;
        budget -= e.size;
        let bytes = match read(&e.path) {
            Ok(b) => b,
            Err(err) => {
                let error = Some(format!("{err:#}"));
                if is_cil {
                    out.cil.push(CilFile {
                        file: e.path.clone(),
                        error,
                        ..Default::default()
                    });
                } else {
                    out.contexts.push(ContextsFile {
                        file: e.path.clone(),
                        error,
                        ..Default::default()
                    });
                }
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        if is_cil {
            out.cil.push(read_cil(&e.path, &text));
        } else {
            let (entries, malformed, candidates) = read_contexts(&text);
            out.contexts.push(ContextsFile {
                file: e.path.clone(),
                entries,
                malformed,
                unconfined: candidates,
                error: None,
            });
        }
    }
    // A label is flagged only when its domain is also typepermissive in the shipped CIL.
    out.violations = violations(&out.cil);
    let permissive: Vec<&String> = out.cil.iter().flat_map(|c| &c.permissive).collect();
    for c in &mut out.contexts {
        c.unconfined.retain(|(_, ctx)| {
            ctx.split(':')
                .nth(2)
                .is_some_and(|ty| permissive.iter().any(|p| p.as_str() == ty))
        });
    }
    out
}

pub fn to_json(a: &SepolicyAudit) -> Value {
    json!({
        "cil_files": a.cil.iter().map(|c| json!({
            "file": c.file,
            "permissive_domains": c.permissive,
            "neverallow_statements": c.neverallow,
            "error": c.error,
        })).collect::<Vec<_>>(),
        "file_contexts": a.contexts.iter().map(|c| json!({
            "file": c.file,
            "entries": c.entries,
            "malformed_lines": c.malformed,
            "unconfined_labels": c.unconfined.iter()
                .map(|(re, ctx)| json!({"path": re, "context": ctx})).collect::<Vec<_>>(),
            "error": c.error,
        })).collect::<Vec<_>>(),
        "files_skipped": a.skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allow_that_matches_a_neverallow_is_a_violation() {
        let cil = "(neverallow untrusted_app app_data_file (file (write)))\n(allow untrusted_app app_data_file (file (write read)))\n(allow untrusted_app app_data_file (file (read)))\n";
        let v = violations(&[read_cil("x_sepolicy.cil", cil)]);
        assert_eq!(
            v,
            [(
                "x_sepolicy.cil".to_string(),
                "allow untrusted_app app_data_file (file (write read))".to_string()
            )]
        );
    }

    #[test]
    fn rules_with_attributes_or_complements_are_not_compared() {
        let cil = "(neverallow domain shell_data_file (file (write)))\n(allow shell shell_data_file (file (write)))\n(neverallow untrusted_app ~app_data_file (file (write)))\n(allow untrusted_app app_data_file (file (write)))\n";
        assert!(violations(&[read_cil("x.cil", cil)]).is_empty());
    }

    const CIL: &str = include_str!("../tests/fixtures/sepolicy/plat_sepolicy.cil");
    const CONTEXTS: &str = include_str!("../tests/fixtures/sepolicy/plat_file_contexts");

    #[test]
    fn the_tokenizer_handles_comments_strings_and_nesting() {
        let v = parse("; a (comment\n(a (b \"c d\") e)").unwrap();
        assert_eq!(
            v,
            vec![Sexp::List(vec![
                Sexp::Atom("a".into()),
                Sexp::List(vec![Sexp::Atom("b".into()), Sexp::Atom("c d".into())]),
                Sexp::Atom("e".into()),
            ])]
        );
        assert!(parse("(a (b)").is_err());
        assert!(parse("a)").is_err());
        assert!(parse("(\"open").is_err());
    }

    #[test]
    fn nesting_is_capped_and_the_cap_is_exact() {
        let at_cap = "(".repeat(MAX_DEPTH) + &")".repeat(MAX_DEPTH);
        assert!(parse(&at_cap).is_ok());
        let over = "(".repeat(MAX_DEPTH + 1) + &")".repeat(MAX_DEPTH + 1);
        assert!(parse(&over).is_err());
    }

    #[test]
    fn typepermissive_is_read_with_its_block_name_and_neverallow_counted() {
        let c = read_cil("plat_sepolicy.cil", CIL);
        assert!(c.error.is_none());
        assert_eq!(
            c.permissive,
            ["healthd.process", "shell_test_domain", "unconfined_test"]
        );
        assert_eq!(c.neverallow, 1);
    }

    #[test]
    fn a_broken_cil_file_is_reported_not_read_as_clean() {
        let c = read_cil("bad_sepolicy.cil", "(typepermissive x");
        assert!(c.error.is_some());
        assert!(c.permissive.is_empty());
    }

    #[test]
    fn file_contexts_are_counted_and_unconfined_candidates_kept() {
        let (entries, malformed, candidates) = read_contexts(CONTEXTS);
        assert_eq!(entries, 3);
        assert_eq!(malformed, 1);
        assert_eq!(
            candidates,
            [(
                "/dev/test_node".to_string(),
                "u:object_r:unconfined_test:s0".to_string()
            )]
        );
    }

    #[test]
    fn only_policy_paths_under_etc_selinux_are_taken() {
        assert_eq!(kind_of("etc/selinux/plat_sepolicy.cil"), Some(true));
        assert_eq!(
            kind_of("/system/etc/selinux/vendor_file_contexts"),
            Some(false)
        );
        assert_eq!(
            kind_of("system/system_ext/etc/selinux/x_sepolicy.cil"),
            Some(true)
        );
        assert_eq!(kind_of("etc/plat_sepolicy.cil"), None);
        assert_eq!(kind_of("etc/selinux/notes.txt"), None);
    }
}
