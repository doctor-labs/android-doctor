//! Pure line-diff for two text files, std-only (no new dependency).
//!
//! `diff_lines` returns the per-line edits (same / added / removed) with 1-based line numbers
//! on each side; `unified` renders them in standard unified-diff hunk format (`@@ -a,b +c,d @@`).
//! The diff is computed with a Myers-style LCS over the line vectors so it never allocates from
//! untrusted sizes: the product of the two line counts is capped, and an overflow falls back to a
//! whole-file replace hunk.
#![allow(dead_code)] // consumers (firmware diff of init.rc/fstab) land in a follow-up

/// One line of a diff. The `bool` is whether the line's source file lacked a trailing newline
/// (i.e. this is the last line and the file ended without `\n`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffLine {
    /// Same in both; text, old line number, new line number, no-trailing-newline flag.
    Same(String, usize, usize, bool),
    /// Added in new; text, old line number (always 0), new line number, no-trailing-newline flag.
    Added(String, usize, usize, bool),
    /// Removed from old; text, old line number, new line number (always 0), no-trailing-newline flag.
    Removed(String, usize, usize, bool),
}

/// Cap to avoid unbounded memory on huge inputs.
const MAX_PRODUCT: usize = 1_000_000;

/// A line for internal comparison: text + flag for "last line without trailing newline".
#[derive(Clone, Eq, PartialEq, Hash)]
struct Line {
    text: String,
    no_nl: bool,
}

/// Split text into lines for comparison. Each `Line` carries its text and whether the source
/// file ended without a trailing newline at that line.
fn split_lines(text: &str) -> Vec<Line> {
    if text.is_empty() {
        return vec![];
    }
    let ends_nl = text.ends_with('\n');
    let body = if ends_nl {
        &text[..text.len() - 1]
    } else {
        text
    };
    let parts: Vec<&str> = body.split('\n').collect();
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| Line {
            text: p.to_string(),
            no_nl: i == parts.len() - 1 && !ends_nl,
        })
        .collect()
}

/// Whether `text` ends with a trailing newline.
fn ends_with_newline(text: &str) -> bool {
    text.ends_with('\n')
}

/// Myers-style LCS diff producing a Vec of DiffLine.
pub fn diff_lines(old: &str, new: &str) -> Vec<DiffLine> {
    let old_lines = split_lines(old);
    let new_lines = split_lines(new);

    // Cap the product to guard against huge inputs.
    if old_lines.len().saturating_mul(new_lines.len()) > MAX_PRODUCT {
        // Fall back to whole-file replace.
        let mut out = Vec::new();
        for (oi, l) in (1usize..).zip(old_lines.iter()) {
            out.push(DiffLine::Removed(l.text.clone(), oi, 0, l.no_nl));
        }
        for (ni, l) in (1usize..).zip(new_lines.iter()) {
            out.push(DiffLine::Added(l.text.clone(), 0, ni, l.no_nl));
        }
        return out;
    }

    // Standard LCS DP table. dp[i][j] = length of LCS of old_lines[i..] and new_lines[j..].
    let m = old_lines.len();
    let n = new_lines.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in (0..m).rev() {
        for j in (0..n).rev() {
            if old_lines[i] == new_lines[j] {
                dp[i][j] = dp[i + 1][j + 1] + 1;
            } else {
                dp[i][j] = dp[i + 1][j].max(dp[i][j + 1]);
            }
        }
    }

    let mut out = Vec::new();
    let (mut oi, mut ni) = (1usize, 1usize);
    let (mut i, mut j) = (0usize, 0usize);
    while i < m && j < n {
        if old_lines[i] == new_lines[j] {
            out.push(DiffLine::Same(
                old_lines[i].text.clone(),
                oi,
                ni,
                old_lines[i].no_nl,
            ));
            i += 1;
            j += 1;
            oi += 1;
            ni += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push(DiffLine::Removed(
                old_lines[i].text.clone(),
                oi,
                0,
                old_lines[i].no_nl,
            ));
            i += 1;
            oi += 1;
        } else {
            out.push(DiffLine::Added(
                new_lines[j].text.clone(),
                0,
                ni,
                new_lines[j].no_nl,
            ));
            j += 1;
            ni += 1;
        }
    }
    while i < m {
        out.push(DiffLine::Removed(
            old_lines[i].text.clone(),
            oi,
            0,
            old_lines[i].no_nl,
        ));
        i += 1;
        oi += 1;
    }
    while j < n {
        out.push(DiffLine::Added(
            new_lines[j].text.clone(),
            0,
            ni,
            new_lines[j].no_nl,
        ));
        j += 1;
        ni += 1;
    }

    out
}

/// Count old lines (Same + Removed) in a diff sequence.
fn count_old(d: &[DiffLine]) -> usize {
    d.iter()
        .filter(|l| {
            matches!(
                l,
                DiffLine::Same(_, _, _, _) | DiffLine::Removed(_, _, _, _)
            )
        })
        .count()
}

/// Count new lines (Same + Added) in a diff sequence.
fn count_new(d: &[DiffLine]) -> usize {
    d.iter()
        .filter(|l| matches!(l, DiffLine::Same(_, _, _, _) | DiffLine::Added(_, _, _, _)))
        .count()
}

/// Format a unified-diff hunk header: `@@ -a,b +c,d @@`.
fn hunk_header(old_start: usize, old_count: usize, new_start: usize, new_count: usize) -> String {
    let fmt = |start: usize, count: usize| -> String {
        if count == 0 {
            format!("{start},0")
        } else if count == 1 {
            format!("{start}")
        } else {
            format!("{start},{count}")
        }
    };
    format!(
        "@@ -{} +{} @@\n",
        fmt(old_start, old_count),
        fmt(new_start, new_count)
    )
}

/// Find the first old line number in a hunk slice (from Same/Removed lines).
/// If the hunk has no old lines (only Added), return the insertion point:
/// `old_before`, the line before the insertion (0 at the start of the file), as diff -u prints it.
fn find_first_old(hunk: &[DiffLine], old_before: usize, old_total: usize) -> usize {
    for dl in hunk {
        match dl {
            DiffLine::Same(_, o, _, _) | DiffLine::Removed(_, o, _, _) => return *o,
            _ => {}
        }
    }
    // Pure additions.
    if old_total == 0 {
        0
    } else {
        old_before
    }
}

/// Find the first new line number in a hunk slice (from Same/Added lines).
/// If the hunk has no new lines (only Removed), return the insertion point.
fn find_first_new(hunk: &[DiffLine], new_before: usize, new_total: usize) -> usize {
    for dl in hunk {
        match dl {
            DiffLine::Same(_, _, n, _) | DiffLine::Added(_, _, n, _) => return *n,
            _ => {}
        }
    }
    // Pure removals.
    if new_total == 0 {
        0
    } else {
        new_before
    }
}

/// Count how many trailing Same lines are in the slice `d` (to use as preceding context).
fn count_pre_context(d: &[DiffLine], context: usize) -> usize {
    let mut c = 0;
    let mut k = d.len();
    while k > 0 && c < context {
        k -= 1;
        match &d[k] {
            DiffLine::Same(_, _, _, _) => c += 1,
            _ => break,
        }
    }
    c
}

/// Count how many leading Same lines are in the slice `d` (to use as trailing context).
fn count_trail_context(d: &[DiffLine], context: usize) -> usize {
    let mut c = 0;
    for dl in d {
        match dl {
            DiffLine::Same(_, _, _, _) => {
                if c < context {
                    c += 1;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    c
}

/// Render a unified diff (hunks only, no `---`/`+++` file headers).
/// `context` is the number of unchanged lines surrounding each change.
pub fn unified(old: &str, new: &str, context: usize) -> String {
    let d = diff_lines(old, new);
    if d.is_empty() {
        return String::new();
    }

    let _old_ends_nl = ends_with_newline(old);
    let _new_ends_nl = ends_with_newline(new);

    // Total number of old and new lines (for computing start positions of added-only / removed-only hunks).
    let old_total = count_old(&d);
    let new_total = count_new(&d);

    // Find all change regions: (start, end) index pairs into `d`.
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < d.len() {
        if matches!(
            d[i],
            DiffLine::Added(_, _, _, _) | DiffLine::Removed(_, _, _, _)
        ) {
            let start = i;
            while i < d.len()
                && matches!(
                    d[i],
                    DiffLine::Added(_, _, _, _) | DiffLine::Removed(_, _, _, _)
                )
            {
                i += 1;
            }
            regions.push((start, i));
        } else {
            i += 1;
        }
    }

    if regions.is_empty() {
        return String::new();
    }

    // Merge regions whose gap (Same lines between them) is <= 2*context.
    // This matches GNU diff: hunks are separate when the gap exceeds 2*context.
    let merge_gap = 2 * context;
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in regions {
        if let Some(&(_, prev_end)) = merged.last() {
            let gap = s - prev_end; // number of Same lines between
            if gap <= merge_gap {
                let last = merged.len() - 1;
                merged[last].1 = e;
                continue;
            }
        }
        merged.push((s, e));
    }

    let mut out = String::new();
    for (start, end) in &merged {
        // Expand with context lines.
        let pre = count_pre_context(&d[..*start], context);
        let begin = start - pre;
        let trail = count_trail_context(&d[*end..], context);
        let hunk_end = (*end + trail).min(d.len());
        let hunk = &d[begin..hunk_end];

        let old_count = count_old(hunk);
        let new_count = count_new(hunk);

        // Compute old_before / new_before at position `begin`.
        let (old_before, new_before) = line_nums_at(&d, begin);

        // old_start: first old line number in hunk (Same/Removed).
        // If the hunk starts with Added lines only, fall back to the insertion point.
        let old_start = find_first_old(hunk, old_before, old_total);
        // new_start: first new line number in hunk (Same/Added).
        // If the hunk starts with Removed lines only, fall back to the insertion point.
        let new_start = find_first_new(hunk, new_before, new_total);

        out.push_str(&hunk_header(old_start, old_count, new_start, new_count));

        for dl in hunk {
            match dl {
                DiffLine::Same(text, _, _, _) => {
                    out.push(' ');
                    out.push_str(text);
                    out.push('\n');
                }
                DiffLine::Removed(text, _, _, no_nl) => {
                    out.push('-');
                    out.push_str(text);
                    out.push('\n');
                    if *no_nl {
                        out.push_str("\\ No newline at end of file\n");
                    }
                }
                DiffLine::Added(text, _, _, no_nl) => {
                    out.push('+');
                    out.push_str(text);
                    out.push('\n');
                    if *no_nl {
                        out.push_str("\\ No newline at end of file\n");
                    }
                }
            }
        }
    }

    out
}

/// Compute the 1-based (old_line, new_line) position at diff index `idx`.
/// This is the line number of the line at position `idx` (or the position after the last
/// line before `idx` if `idx` points at an Added-only or Removed-only boundary).
fn line_nums_at(d: &[DiffLine], idx: usize) -> (usize, usize) {
    if idx == 0 {
        return (0, 0);
    }
    match &d[idx.saturating_sub(1)] {
        DiffLine::Same(_, o, n, _) => (*o, *n),
        DiffLine::Removed(_, o, _, _) => (*o, 0),
        DiffLine::Added(_, _, n, _) => (0, *n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Run real `diff -U <ctx>` on old/new content and return the hunk portion (without the
    /// `--- ` and `+++ ` file-header lines and their timestamps), so we compare only what
    /// our `unified()` function produces.
    fn diff_u(old: &str, new: &str, ctx: usize) -> String {
        // Use a thread-unique counter + nanos to avoid collisions across parallel tests.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "dsh-textdiff-{}-{}-{}",
            COUNTER.fetch_add(1, Ordering::Relaxed),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let oldp = dir.join("old.txt");
        let newp = dir.join("new.txt");
        std::fs::write(&oldp, old).unwrap();
        std::fs::write(&newp, new).unwrap();
        let out = Command::new("diff")
            .args([
                "-U",
                &ctx.to_string(),
                oldp.to_str().unwrap(),
                newp.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        // diff exits 1 when there are differences, 0 when identical. Both are fine.
        // If diff exits 2, something went wrong.
        assert!(
            out.status.code() == Some(0) || out.status.code() == Some(1),
            "diff -u failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        // Strip the two file-header lines (`---` and `+++`).
        let mut hunks = String::new();
        for line in text.lines() {
            if line.starts_with("--- ") {
                continue;
            }
            if line.starts_with("+++ ") {
                continue;
            }
            hunks.push_str(line);
            hunks.push('\n');
        }
        hunks
    }

    /// Verify our `unified()` output matches real `diff -u` hunk output for the given pair.
    fn check_against_diff(old: &str, new: &str, ctx: usize) {
        let expected = diff_u(old, new, ctx);
        let actual = unified(old, new, ctx);
        // For identical files, both should be empty.
        if expected.is_empty() {
            assert!(actual.is_empty(), "expected empty, got: {actual:?}");
            return;
        }
        assert_eq!(expected, actual, "old={old:?} new={new:?} ctx={ctx}");
    }

    #[test]
    fn identical_files_match_diff_u() {
        check_against_diff("a\nb\nc\n", "a\nb\nc\n", 3);
    }

    #[test]
    fn one_line_changed_matches_diff_u() {
        check_against_diff("line1\nline2\nline3\n", "line1\nchanged\nline3\n", 3);
    }

    #[test]
    fn line_added_matches_diff_u() {
        check_against_diff("line1\nline3\n", "line1\nline2\nline3\n", 3);
    }

    #[test]
    fn line_removed_matches_diff_u() {
        check_against_diff("line1\nline2\nline3\n", "line1\nline3\n", 3);
    }

    #[test]
    fn empty_to_nonempty_matches_diff_u() {
        check_against_diff("", "line1\nline2\n", 3);
    }

    #[test]
    fn nonempty_to_empty_matches_diff_u() {
        check_against_diff("line1\nline2\n", "", 3);
    }

    #[test]
    fn no_trailing_newline_matches_diff_u() {
        check_against_diff("line1\nline2", "line1\nchanged", 3);
    }

    #[test]
    fn only_old_lacks_trailing_newline_matches_diff_u() {
        check_against_diff("a\nb", "a\nb\nc\n", 3);
    }

    #[test]
    fn only_new_lacks_trailing_newline_matches_diff_u() {
        check_against_diff("a\nb\nc", "a\nb\nc\n", 3);
    }

    #[test]
    fn trailing_newline_only_diff_matches_diff_u() {
        // Same content, different trailing newline status.
        check_against_diff("a\nb\nc", "a\nb\nc\n", 3);
    }

    #[test]
    fn context_0_matches_diff_u() {
        check_against_diff("a\nb\nc\nd\ne\nf\ng\nh\n", "A\nb\nC\nd\nE\nf\nG\nh\n", 0);
    }

    #[test]
    fn context_1_matches_diff_u() {
        check_against_diff("a\nb\nc\nd\ne\nf\ng\nh\n", "A\nb\nC\nd\nE\nf\nG\nh\n", 1);
    }

    #[test]
    fn multi_hunk_matches_diff_u() {
        check_against_diff(
            "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\np\n",
            "a\nb\nC\nC\nC\ng\nh\ni\nj\nk\nK\n",
            3,
        );
    }

    #[test]
    fn insertion_at_start_matches_diff_u() {
        check_against_diff("a\nb\nc\n", "x\na\nb\nc\n", 0);
    }

    #[test]
    fn insertion_at_end_matches_diff_u() {
        check_against_diff("a\nb\nc\n", "a\nb\nc\nx\n", 0);
    }

    #[test]
    fn insertion_in_middle_matches_diff_u() {
        check_against_diff("a\nc\n", "a\nb\nc\n", 0);
    }

    #[test]
    fn deletion_at_start_matches_diff_u() {
        check_against_diff("a\nb\nc\n", "b\nc\n", 0);
    }

    #[test]
    fn deletion_at_end_matches_diff_u() {
        check_against_diff("a\nb\nc\n", "a\nb\n", 0);
    }

    #[test]
    fn both_empty_matches_diff_u() {
        check_against_diff("", "", 3);
    }

    #[test]
    fn cap_on_huge_inputs_falls_back_to_whole_file_replace() {
        let huge = "x\n".repeat(1000);
        let d = diff_lines(&huge, &huge);
        assert!(d.iter().all(|l| matches!(l, DiffLine::Same(_, _, _, _))));
    }

    #[test]
    fn same_lines_produce_empty_diff() {
        let d = diff_lines("a\nb\nc\n", "a\nb\nc\n");
        assert!(d.iter().all(|l| matches!(l, DiffLine::Same(_, _, _, _))));
    }

    #[test]
    fn added_line_is_detected() {
        let d = diff_lines("a\n", "a\nb\n");
        assert!(d.iter().any(|l| matches!(l, DiffLine::Added(_, _, _, _))));
    }
}
