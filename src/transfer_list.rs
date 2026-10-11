//! Parser for Android block-OTA `*.transfer.list` files, versions 1 to 4: `new`, `zero`, `erase`
//! for full OTAs, and `move`, `bsdiff`, `imgdiff`, `stash`, `free` for incremental ones.
//!
//! Layouts follow AOSP `blockimg.cc` (updater) and `blockimgdiff.py` (Apache-2.0):
//!
//! | version | `move`                                        | `bsdiff` / `imgdiff`                                             |
//! |---------|-----------------------------------------------|------------------------------------------------------------------|
//! | 1       | `<src_ranges> <tgt_ranges>`                   | `<offset> <len> <src_ranges> <tgt_ranges>`                       |
//! | 2       | `<tgt_ranges> <src>`                          | `<offset> <len> <tgt_ranges> <src>`                              |
//! | 3, 4    | `<src_sha1> <tgt_ranges> <src>`               | `<offset> <len> <src_sha1> <tgt_sha1> <tgt_ranges> <src>`        |
//!
//! where `<src>` (version 2 and later) is `<src_block_count> <src_ranges>|- [<src_loc>] [<id>:<loc> ...]`:
//! the source buffer holds `src_block_count` blocks; blocks read from the partition go where
//! `src_loc` says (in order; at the front when it is absent) and each stash is copied to its
//! `loc`. `stash <id> <ranges>` saves blocks of the partition as it is at that point, `free <id>`
//! drops one. Ranges are `N,a,b,c,d,...` (N numbers, half-open block pairs).
use anyhow::{Context, Result, bail};

/// Half-open block ranges `[start, end)`.
pub type Ranges = Vec<(u64, u64)>;

/// Where an incremental command's source blocks come from.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct Source {
    /// Blocks in the assembled source buffer.
    pub blocks: u64,
    /// Blocks read from the partition (empty for `-`).
    pub ranges: Ranges,
    /// Positions in the buffer for those blocks (`None`: the front, in order).
    pub loc: Option<Ranges>,
    /// `(stash id, positions in the buffer)`.
    pub stashes: Vec<(String, Ranges)>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Patch {
    Move,
    Bsdiff,
    Imgdiff,
}

/// `move`, `bsdiff` or `imgdiff`: build the source buffer, turn it into the target blocks.
#[derive(Debug, PartialEq, Clone)]
pub struct Transfer {
    pub kind: Patch,
    /// `(offset, length)` of the patch in `*.patch.dat` (not for `move`).
    pub patch: Option<(u64, u64)>,
    /// SHA-1 hex of the source buffer and of the target (version 3 and later).
    pub src_sha1: Option<String>,
    pub tgt_sha1: Option<String>,
    pub tgt: Ranges,
    pub src: Source,
}

#[derive(Debug, PartialEq)]
pub enum Command {
    New(Ranges),
    Zero(Ranges),
    Erase(Ranges),
    Transfer(Transfer),
    Stash(String, Ranges),
    Free(String),
}

#[derive(Debug, PartialEq)]
pub struct TransferList {
    pub version: u32,
    pub total_blocks: u64,
    pub commands: Vec<Command>,
}

impl TransferList {
    /// True when the list needs the previous build (anything beyond new/zero/erase).
    pub fn is_incremental(&self) -> bool {
        self.commands
            .iter()
            .any(|c| !matches!(c, Command::New(_) | Command::Zero(_) | Command::Erase(_)))
    }
}

/// Most commands, ranges per set and stash entries a list may hold (hostile-input bounds).
const MAX_COMMANDS: usize = 2_000_000;
const MAX_RANGES: usize = 1 << 20;

/// Parse `N,a,b,c,d,...` into `[a,b)` pairs; N must equal the count of numbers that follow.
fn parse_ranges(s: &str) -> Result<Ranges> {
    let nums = s
        .split(',')
        .map(|n| {
            n.parse::<u64>()
                .with_context(|| format!("bad range number {n:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let (&count, rest) = nums.split_first().context("empty range set")?;
    if rest.len() > MAX_RANGES * 2 {
        bail!("range set with {} numbers is over the limit", rest.len());
    }
    if count as usize != rest.len() || rest.len() % 2 != 0 {
        bail!(
            "range set {s:?}: count {count} does not match {} numbers",
            rest.len()
        );
    }
    rest.chunks(2)
        .map(|p| {
            if p[0] < p[1] {
                Ok((p[0], p[1]))
            } else {
                bail!("empty or reversed range {}-{}", p[0], p[1])
            }
        })
        .collect()
}

fn is_sha1(t: &str) -> bool {
    t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The `<src>` tail of version 2 and later: `count ranges|- [loc] [id:loc ...]`.
fn parse_source(toks: &[&str]) -> Result<Source> {
    let (count, rest) = toks.split_first().context("missing source block count")?;
    let blocks: u64 = count.parse().context("bad source block count")?;
    let (ranges_tok, mut rest) = rest.split_first().context("missing source ranges")?;
    let ranges = if *ranges_tok == "-" {
        Vec::new()
    } else {
        parse_ranges(ranges_tok)?
    };
    let mut src = Source {
        blocks,
        ranges,
        ..Default::default()
    };
    // a location set follows only when the partition blocks are not simply the front of the buffer
    if !src.ranges.is_empty()
        && let Some((t, r)) = rest.split_first()
        && !t.contains(':')
    {
        src.loc = Some(parse_ranges(t)?);
        rest = r;
    }
    for t in rest {
        let (id, loc) = t
            .split_once(':')
            .with_context(|| format!("bad stash reference {t:?}"))?;
        src.stashes.push((id.to_string(), parse_ranges(loc)?));
    }
    let size = |r: &Ranges| r.iter().map(|(a, b)| b - a).sum::<u64>();
    let placed = size(&src.ranges) + src.stashes.iter().map(|(_, l)| size(l)).sum::<u64>();
    if let Some(loc) = &src.loc {
        anyhow::ensure!(
            size(loc) == size(&src.ranges),
            "source location set does not match the source ranges"
        );
    }
    anyhow::ensure!(
        placed == blocks,
        "source blocks ({placed}) do not add up to the declared {blocks}"
    );
    Ok(src)
}

fn parse_transfer(name: &str, version: u32, toks: &[&str]) -> Result<Transfer> {
    let kind = match name {
        "move" => Patch::Move,
        "bsdiff" => Patch::Bsdiff,
        _ => Patch::Imgdiff,
    };
    let mut t = toks;
    let mut take = |what: &str| -> Result<&str> {
        let (h, r) = t.split_first().with_context(|| format!("missing {what}"))?;
        t = r;
        Ok(h)
    };
    let patch = if kind == Patch::Move {
        None
    } else {
        let off: u64 = take("patch offset")?.parse().context("bad patch offset")?;
        let len: u64 = take("patch length")?.parse().context("bad patch length")?;
        Some((off, len))
    };
    if version == 1 {
        let src = parse_ranges(take("source ranges")?)?;
        let tgt = parse_ranges(take("target ranges")?)?;
        anyhow::ensure!(t.is_empty(), "unexpected trailing fields");
        let blocks = src.iter().map(|(a, b)| b - a).sum();
        return Ok(Transfer {
            kind,
            patch,
            src_sha1: None,
            tgt_sha1: None,
            tgt,
            src: Source {
                blocks,
                ranges: src,
                ..Default::default()
            },
        });
    }
    let (mut src_sha1, mut tgt_sha1) = (None, None);
    if version >= 3 {
        let h = take("source hash")?;
        anyhow::ensure!(is_sha1(h), "bad source hash {h:?}");
        src_sha1 = Some(h.to_ascii_lowercase());
        if kind != Patch::Move {
            let h = take("target hash")?;
            anyhow::ensure!(is_sha1(h), "bad target hash {h:?}");
            tgt_sha1 = Some(h.to_ascii_lowercase());
        } else {
            tgt_sha1 = src_sha1.clone(); // a move leaves the data unchanged
        }
    }
    let tgt = parse_ranges(take("target ranges")?)?;
    let src = parse_source(t)?;
    Ok(Transfer {
        kind,
        patch,
        src_sha1,
        tgt_sha1,
        tgt,
        src,
    })
}

pub fn parse(text: &str) -> Result<TransferList> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let version: u32 = lines
        .next()
        .context("missing version line")?
        .parse()
        .context("bad version")?;
    if !(1..=4).contains(&version) {
        bail!("unsupported transfer list version {version}");
    }
    let total_blocks = lines
        .next()
        .context("missing total blocks line")?
        .parse()
        .context("bad total blocks")?;
    if version >= 2 {
        for what in ["stash entries", "max stash"] {
            lines
                .next()
                .with_context(|| format!("missing {what} line"))?;
        }
    }
    let mut commands = Vec::new();
    for line in lines {
        if commands.len() >= MAX_COMMANDS {
            bail!("more than {MAX_COMMANDS} commands");
        }
        let (name, args) = line
            .split_once(' ')
            .with_context(|| format!("malformed command {line:?}"))?;
        let toks: Vec<&str> = args.split_whitespace().collect();
        let at = || format!("in {line:?}");
        let ranges = |t: &str| parse_ranges(t.trim()).with_context(at);
        commands.push(match name {
            "new" => Command::New(ranges(args)?),
            "zero" => Command::Zero(ranges(args)?),
            "erase" => Command::Erase(ranges(args)?),
            "stash" if version >= 2 => {
                let [id, r] = toks[..] else {
                    bail!("stash takes an id and ranges {}", at())
                };
                Command::Stash(id.to_string(), ranges(r)?)
            }
            "free" if version >= 2 => {
                let [id] = toks[..] else {
                    bail!("free takes an id {}", at())
                };
                Command::Free(id.to_string())
            }
            "move" | "bsdiff" | "imgdiff" => {
                Command::Transfer(parse_transfer(name, version, &toks).with_context(at)?)
            }
            other => bail!("unsupported command {other:?}"),
        });
    }
    Ok(TransferList {
        version,
        total_blocks,
        commands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v4_with_all_commands() {
        let t = parse("4\n10\n0\n0\nnew 2,0,4\nzero 4,4,6,8,10\nerase 2,6,8\n").unwrap();
        assert_eq!(t.version, 4);
        assert_eq!(t.total_blocks, 10);
        assert_eq!(
            t.commands,
            vec![
                Command::New(vec![(0, 4)]),
                Command::Zero(vec![(4, 6), (8, 10)]),
                Command::Erase(vec![(6, 8)]),
            ]
        );
    }

    #[test]
    fn v1_has_no_stash_lines() {
        let t = parse("1\n8\nnew 2,0,8\n").unwrap();
        assert_eq!(t.commands, vec![Command::New(vec![(0, 8)])]);
    }

    #[test]
    fn rejects_unknown_commands() {
        let e = parse("4\n10\n0\n0\nfrobnicate 2,0,1\n").unwrap_err();
        assert!(e.to_string().contains("unsupported command"), "{e}");
        assert!(
            parse("1\n10\nstash a 2,0,1\n").is_err(),
            "stash is version 2+"
        );
    }

    #[test]
    fn rejects_bad_ranges() {
        assert!(parse("4\n10\n0\n0\nnew 3,0,4\n").is_err(), "count mismatch");
        assert!(parse("4\n10\n0\n0\nnew 2,5,5\n").is_err(), "empty range");
        assert!(parse("4\n10\n0\n0\nnew 2,x,5\n").is_err(), "not a number");
    }

    #[test]
    fn rejects_bad_header() {
        assert!(parse("5\n10\n0\n0\n").is_err(), "unknown version");
        assert!(parse("4\n10\n").is_err(), "missing stash lines");
        assert!(parse("").is_err(), "empty input");
    }

    #[test]
    fn parses_every_command_of_versions_1_to_4() {
        let t =
            parse("1\n8\nmove 2,0,2 2,4,6\nbsdiff 0 40 2,0,2 2,4,6\nimgdiff 40 9 2,2,3 2,6,7\n")
                .unwrap();
        let Command::Transfer(m) = &t.commands[0] else {
            panic!()
        };
        assert_eq!(
            (m.kind, &m.src.ranges, &m.tgt, m.src.blocks),
            (Patch::Move, &vec![(0, 2)], &vec![(4, 6)], 2)
        );
        let Command::Transfer(b) = &t.commands[1] else {
            panic!()
        };
        assert_eq!((b.kind, b.patch), (Patch::Bsdiff, Some((0, 40))));
        let Command::Transfer(i) = &t.commands[2] else {
            panic!()
        };
        assert_eq!((i.kind, i.patch), (Patch::Imgdiff, Some((40, 9))));
        assert!(t.is_incremental());

        let t = parse("2\n8\n1\n2\nstash s1 2,0,2\nmove 2,4,6 4 2,0,2 2,0,2 s1:2,2,4\nfree s1\n")
            .unwrap();
        assert_eq!(t.commands[0], Command::Stash("s1".into(), vec![(0, 2)]));
        let Command::Transfer(m) = &t.commands[1] else {
            panic!()
        };
        assert_eq!(m.src.loc, Some(vec![(0, 2)]));
        assert_eq!(m.src.stashes, vec![("s1".to_string(), vec![(2, 4)])]);
        assert_eq!(t.commands[2], Command::Free("s1".into()));

        let t = parse("3\n8\n0\n0\nmove aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2,4,6 2 - bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:2,0,2\nbsdiff 0 5 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 2,4,6 2 2,0,2\n").unwrap();
        let Command::Transfer(m) = &t.commands[0] else {
            panic!()
        };
        assert_eq!(
            (m.src_sha1.as_deref(), m.tgt_sha1.as_deref()),
            (
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            )
        );
        assert!(m.src.ranges.is_empty() && m.src.stashes.len() == 1);
        let Command::Transfer(b) = &t.commands[1] else {
            panic!()
        };
        assert_eq!(
            (b.src_sha1.as_deref(), b.tgt_sha1.as_deref()),
            (
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            )
        );
    }

    #[test]
    fn rejects_inconsistent_incremental_commands() {
        for bad in [
            "3\n8\n0\n0\nmove nothex 2,4,6 2 2,0,2\n",
            "2\n8\n0\n0\nmove 2,4,6 3 2,0,2\n", // 2 blocks of source, 3 declared
            "2\n8\n0\n0\nmove 2,4,6 2 2,0,2 2,0,1\n", // location set smaller than the ranges
            "2\n8\n0\n0\nbsdiff x 5 2,4,6 2 2,0,2\n",
            "1\n8\nmove 2,0,2\n",
            "2\n8\n0\n0\nfree\n",
        ] {
            assert!(parse(bad).is_err(), "{bad} was accepted");
        }
    }
}
