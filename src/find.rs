//! `find`: search an image's tree by name glob, SELinux label, setuid or setgid bit, extended attribute
//! or file content. Read-only and bounded like the other readers: the walk is the tree reader's, and
//! content is read only for regular files under a size cap and within a total budget. A file that was
//! not read is listed as not checked, never as clean.
use crate::tree::{Entry, Kind, Tree};
use anyhow::Result;
use std::path::Path;

/// Largest regular file `--grep` reads; larger ones are listed as not checked.
const GREP_FILE_MAX: usize = 1 << 20;
/// Total bytes `--grep` reads in one run; past it, the remaining files are listed as not checked.
const GREP_TOTAL_MAX: u64 = 256 << 20;

/// What to look for. Every filter that is set must match (AND).
#[derive(Default)]
pub struct Query {
    /// Directory to search under, without slashes at either end ("" is the root).
    pub under: String,
    /// Glob (`*`, `?`) for the file name.
    pub name: Option<String>,
    /// Glob for the SELinux label.
    pub selinux: Option<String>,
    pub setuid: bool,
    pub setgid: bool,
    /// An extended attribute name, and optionally a glob its value must match.
    pub xattr: Option<(String, Option<String>)>,
    /// Text that the content of a regular file must contain.
    pub grep: Option<String>,
}

impl Query {
    pub fn has_filter(&self) -> bool {
        self.name.is_some()
            || self.selinux.is_some()
            || self.setuid
            || self.setgid
            || self.xattr.is_some()
            || self.grep.is_some()
    }
}

#[derive(Default)]
pub struct Found {
    pub matches: Vec<Entry>,
    /// Regular files that `--grep` could not read, with the reason. Neither matches nor clean.
    pub not_checked: Vec<(String, String)>,
}

pub fn run(image: &Path, q: &Query) -> Result<Found> {
    let tree = Tree::open(image)?;
    let mut found = Found::default();
    let mut budget = GREP_TOTAL_MAX;
    for e in tree.entries()? {
        if !under(&e.path, &q.under) || !matches_meta(&e, q) {
            continue;
        }
        let Some(needle) = q.grep.as_deref() else {
            found.matches.push(e);
            continue;
        };
        if e.kind != Kind::File {
            continue;
        }
        if e.size > GREP_FILE_MAX as u64 || e.size > budget {
            let why = if e.size > GREP_FILE_MAX as u64 {
                format!("larger than {GREP_FILE_MAX} bytes")
            } else {
                "search budget used up".to_string()
            };
            found.not_checked.push((e.path.clone(), why));
            continue;
        }
        budget -= e.size;
        let mut buf = Capped::default();
        match tree.cat_path(&format!("/{}", e.path), &mut buf) {
            Ok(()) if contains(&buf.data, needle.as_bytes()) => found.matches.push(e),
            Ok(()) => {}
            Err(err) => found
                .not_checked
                .push((e.path.clone(), format!("could not read: {err}"))),
        }
    }
    Ok(found)
}

/// Collects a file's bytes, refusing to grow past the read cap.
#[derive(Default)]
struct Capped {
    data: Vec<u8>,
}

impl std::io::Write for Capped {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.data.len() + b.len() > GREP_FILE_MAX {
            return Err(std::io::Error::other("larger than the read limit"));
        }
        self.data.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn contains(data: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && data.windows(needle.len()).any(|w| w == needle)
}

/// Is `path` the directory `dir` itself or below it?
fn under(path: &str, dir: &str) -> bool {
    dir.is_empty()
        || path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn matches_meta(e: &Entry, q: &Query) -> bool {
    let base = e.path.rsplit('/').next().unwrap_or("");
    let label = xattr_value(e, "security.selinux");
    q.name.as_deref().is_none_or(|g| glob(g, base))
        && q.selinux
            .as_deref()
            .is_none_or(|g| label.is_some_and(|l| glob(g, l)))
        && (!q.setuid || e.mode & 0o4000 != 0)
        && (!q.setgid || e.mode & 0o2000 != 0)
        && q.xattr.as_ref().is_none_or(|(name, value)| {
            xattr_value(e, name).is_some_and(|v| value.as_deref().is_none_or(|g| glob(g, v)))
        })
}

/// The value of one extended attribute, without the trailing NUL that SELinux labels carry.
fn xattr_value<'a>(e: &'a Entry, name: &str) -> Option<&'a str> {
    e.xattrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.trim_end_matches('\0'))
}

/// Shell-style glob over the whole string: `*` matches any run, `?` one character.
pub fn glob(pat: &str, s: &str) -> bool {
    let (p, t) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None; // (pattern index after '*', text index it covers)
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi + 1, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}
