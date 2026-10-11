//! Streaming content scanning for firmware security indicators.
/// Skip files larger than this (2 MiB).
pub const MAX_SCAN_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Stop scanning after this many total bytes across all files (64 MiB).
pub const MAX_SCAN_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// One indicator found inside a file's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: String,
    pub severity: String,
    pub path: String,
    pub detail: String,
}

const PRIVATE_KEY_MARKERS: [&str; 7] = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY BLOCK",
];
const DEBUG_MARKERS: [&str; 2] = ["adb tcpip", "jtag"];

pub fn scan_bytes(path: &str, buf: &[u8]) -> Vec<Hit> {
    let mut out = Vec::new();
    for marker in PRIVATE_KEY_MARKERS {
        if contains(buf, marker.as_bytes()) {
            out.push(Hit {
                rule: "hardcoded_credentials".into(),
                severity: "high".into(),
                path: path.into(),
                detail: format!("contains {marker}"),
            });
        }
    }
    for m in aws_access_key_ids(buf) {
        out.push(Hit {
            rule: "cloud_credentials".into(),
            severity: "high".into(),
            path: path.into(),
            detail: format!("AWS access key id {m}"),
        });
    }
    for (provider, shown, severity) in provider_tokens(buf) {
        out.push(Hit {
            rule: "provider_tokens".into(),
            severity: severity.into(),
            path: path.into(),
            detail: format!("{provider} {shown}"),
        });
    }
    for d in debug_endpoints(buf) {
        out.push(Hit {
            rule: "debug_endpoints".into(),
            severity: "medium".into(),
            path: path.into(),
            detail: d,
        });
    }
    out
}

fn aws_access_key_ids(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if buf.len() < 20 {
        return out;
    }
    for i in 0..=(buf.len() - 4) {
        if i + 20 > buf.len() {
            break;
        }
        if (&buf[i..i + 4] == b"AKIA" || &buf[i..i + 4] == b"ASIA")
            && is_aws_key(&buf[i..i + 20])
            && let Ok(s) = std::str::from_utf8(&buf[i..i + 20])
        {
            out.push(s.to_string());
        }
    }
    out
}

fn is_aws_key(w: &[u8]) -> bool {
    if w.len() != 20 || (&w[0..4] != b"AKIA" && &w[0..4] != b"ASIA") {
        return false;
    }
    w[4..]
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

// --- Provider tokens ---
//
// API keys and access tokens of common services, matched by their fixed prefix and the length
// and alphabet of the rest (the published formats), with no regex engine. Written from the
// providers' own token documentation and MobSF's `secret_detection.py` list of services; a hit
// is shown redacted, never in full.

#[derive(Clone, Copy)]
enum Set {
    Alnum,
    UpperDigit,
    B64Url,
    B64,
    Hex,
    Digit,
}

fn in_set(s: Set, b: u8) -> bool {
    match s {
        Set::Alnum => b.is_ascii_alphanumeric(),
        Set::UpperDigit => b.is_ascii_uppercase() || b.is_ascii_digit(),
        Set::B64Url => b.is_ascii_alphanumeric() || b == b'_' || b == b'-',
        Set::B64 => b.is_ascii_alphanumeric() || b == b'+' || b == b'/',
        Set::Hex => b.is_ascii_hexdigit(),
        Set::Digit => b.is_ascii_digit(),
    }
}

/// One run of the token body: a literal separator, then `min..=max` characters of `set`.
struct Seg {
    sep: &'static [u8],
    set: Set,
    min: usize,
    max: usize,
}

const fn seg(sep: &'static [u8], set: Set, min: usize, max: usize) -> Seg {
    Seg { sep, set, min, max }
}

struct Provider {
    name: &'static str,
    prefix: &'static [u8],
    segs: &'static [Seg],
    /// The byte before the token must not be a letter, digit or `_` (for short, common prefixes).
    bounded: bool,
    severity: &'static str,
}

use Set::*;

const PROVIDERS: &[Provider] = &[
    Provider {
        name: "GitHub token",
        prefix: b"ghp_",
        segs: &[seg(b"", Alnum, 36, 36)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "GitHub token",
        prefix: b"gho_",
        segs: &[seg(b"", Alnum, 36, 36)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "GitHub token",
        prefix: b"ghu_",
        segs: &[seg(b"", Alnum, 36, 36)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "GitHub token",
        prefix: b"ghs_",
        segs: &[seg(b"", Alnum, 36, 36)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "GitHub token",
        prefix: b"ghr_",
        segs: &[seg(b"", Alnum, 36, 36)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "GitHub fine-grained token",
        prefix: b"github_pat_",
        segs: &[seg(b"", B64Url, 82, 82)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "GitLab token",
        prefix: b"glpat-",
        segs: &[seg(b"", B64Url, 20, 50)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Slack token",
        prefix: b"xoxb-",
        segs: &[seg(b"", B64Url, 24, 200)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Slack token",
        prefix: b"xoxp-",
        segs: &[seg(b"", B64Url, 24, 200)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Slack token",
        prefix: b"xoxa-",
        segs: &[seg(b"", B64Url, 24, 200)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Slack token",
        prefix: b"xoxr-",
        segs: &[seg(b"", B64Url, 24, 200)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Slack token",
        prefix: b"xapp-",
        segs: &[seg(b"", B64Url, 24, 200)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Slack webhook",
        prefix: b"hooks.slack.com/services/T",
        segs: &[
            seg(b"", UpperDigit, 8, 12),
            seg(b"/B", UpperDigit, 8, 12),
            seg(b"/", Alnum, 24, 24),
        ],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Discord webhook",
        prefix: b"discord.com/api/webhooks/",
        segs: &[seg(b"", Digit, 17, 20), seg(b"/", B64Url, 60, 90)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Stripe secret key",
        prefix: b"sk_live_",
        segs: &[seg(b"", Alnum, 24, 99)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Stripe restricted key",
        prefix: b"rk_live_",
        segs: &[seg(b"", Alnum, 24, 99)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "SendGrid key",
        prefix: b"SG.",
        segs: &[seg(b"", B64Url, 22, 22), seg(b".", B64Url, 43, 43)],
        bounded: true,
        severity: "high",
    },
    Provider {
        name: "npm token",
        prefix: b"npm_",
        segs: &[seg(b"", Alnum, 36, 36)],
        bounded: true,
        severity: "high",
    },
    Provider {
        name: "Google API key",
        prefix: b"AIza",
        segs: &[seg(b"", B64Url, 35, 35)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Google OAuth client secret",
        prefix: b"GOCSPX-",
        segs: &[seg(b"", B64Url, 28, 28)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Twilio API key",
        prefix: b"SK",
        segs: &[seg(b"", Hex, 32, 32)],
        bounded: true,
        severity: "high",
    },
    Provider {
        name: "Mailgun key",
        prefix: b"key-",
        segs: &[seg(b"", Hex, 32, 32)],
        bounded: true,
        severity: "high",
    },
    Provider {
        name: "Shopify token",
        prefix: b"shpat_",
        segs: &[seg(b"", Hex, 32, 32)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Shopify token",
        prefix: b"shpss_",
        segs: &[seg(b"", Hex, 32, 32)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Square access token",
        prefix: b"sq0atp-",
        segs: &[seg(b"", B64Url, 22, 22)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Square OAuth secret",
        prefix: b"sq0csp-",
        segs: &[seg(b"", B64Url, 43, 43)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "PyPI token",
        prefix: b"pypi-AgEIcHlwaS5vcmc",
        segs: &[seg(b"", B64Url, 50, 1000)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "DigitalOcean token",
        prefix: b"dop_v1_",
        segs: &[seg(b"", Hex, 64, 64)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Hugging Face token",
        prefix: b"hf_",
        segs: &[seg(b"", Alnum, 34, 40)],
        bounded: true,
        severity: "high",
    },
    Provider {
        name: "OpenAI key",
        prefix: b"sk-proj-",
        segs: &[seg(b"", B64Url, 40, 200)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Anthropic key",
        prefix: b"sk-ant-api03-",
        segs: &[seg(b"", B64Url, 80, 120)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Linear key",
        prefix: b"lin_api_",
        segs: &[seg(b"", Alnum, 40, 40)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Postman key",
        prefix: b"PMAK-",
        segs: &[seg(b"", Hex, 24, 24), seg(b"-", Hex, 34, 34)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Docker Hub token",
        prefix: b"dckr_pat_",
        segs: &[seg(b"", B64Url, 27, 27)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Databricks token",
        prefix: b"dapi",
        segs: &[seg(b"", Hex, 32, 32)],
        bounded: true,
        severity: "high",
    },
    Provider {
        name: "Atlassian API token",
        prefix: b"ATATT3xFfGF0",
        segs: &[seg(b"", B64Url, 100, 400)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Mapbox secret token",
        prefix: b"sk.eyJ",
        segs: &[seg(b"", B64Url, 60, 400)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "Azure storage account key",
        prefix: b"AccountKey=",
        segs: &[seg(b"", B64, 86, 86), seg(b"==", Alnum, 0, 0)],
        bounded: false,
        severity: "high",
    },
    Provider {
        name: "JSON Web Token",
        prefix: b"eyJ",
        segs: &[
            seg(b"", B64Url, 8, 4000),
            seg(b".eyJ", B64Url, 8, 4000),
            seg(b".", B64Url, 10, 4000),
        ],
        bounded: true,
        severity: "medium",
    },
];

/// First bytes of all prefixes, so a scan skips almost every byte with one table lookup.
fn first_bytes() -> &'static [Vec<usize>; 256] {
    use std::sync::OnceLock;
    static T: OnceLock<[Vec<usize>; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
        for (i, p) in PROVIDERS.iter().enumerate() {
            t[usize::from(p.prefix[0])].push(i);
        }
        t
    })
}

/// Length of the token starting at `buf[0]`, if it is `p`.
fn match_provider(p: &Provider, buf: &[u8]) -> Option<usize> {
    if !buf.starts_with(p.prefix) {
        return None;
    }
    let mut at = p.prefix.len();
    for (n, s) in p.segs.iter().enumerate() {
        if !buf[at..].starts_with(s.sep) {
            return None;
        }
        at += s.sep.len();
        let run = buf[at..]
            .iter()
            .take(s.max)
            .take_while(|&&b| in_set(s.set, b))
            .count();
        if run < s.min {
            return None;
        }
        // a fixed-size run must end there: more of the alphabet means a longer, different string
        if s.min == s.max && buf.get(at + run).is_some_and(|&b| in_set(s.set, b)) {
            return None;
        }
        // the last run of a ranged token is taken whole; the others stop at their separator
        let _ = n;
        at += run;
    }
    Some(at)
}

/// `(provider, redacted token, severity)` for every provider token in `buf`, once each.
fn provider_tokens(buf: &[u8]) -> Vec<(&'static str, String, &'static str)> {
    let table = first_bytes();
    let mut out: Vec<(&'static str, String, &'static str)> = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let cands = &table[usize::from(buf[i])];
        let mut advance = 1;
        if !cands.is_empty() {
            for &c in cands {
                let p = &PROVIDERS[c];
                if p.bounded && i > 0 && (buf[i - 1].is_ascii_alphanumeric() || buf[i - 1] == b'_')
                {
                    continue;
                }
                if let Some(len) = match_provider(p, &buf[i..]) {
                    let tok = &buf[i..i + len];
                    let keep = p.prefix.len().min(len - 1) + 2;
                    let shown = format!(
                        "{}... ({} chars)",
                        String::from_utf8_lossy(&tok[..keep.min(len)]),
                        len
                    );
                    if !out.iter().any(|(n, s, _)| *n == p.name && *s == shown) {
                        out.push((p.name, shown, p.severity));
                    }
                    advance = len;
                    break;
                }
            }
        }
        i += advance;
    }
    out
}

fn debug_endpoints(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for marker in DEBUG_MARKERS {
        if contains(buf, marker.as_bytes()) {
            out.push(format!("debug interface marker: {marker}"));
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardcoded_credentials_fires_on_private_key_markers_and_not_on_clean_text() {
        let clean = b"just a normal binary, nothing to see here";
        assert!(
            scan_bytes("x", clean).is_empty(),
            "clean text: {:?}",
            scan_bytes("x", clean)
        );

        for marker in [
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN PRIVATE KEY",
        ] {
            let buf = format!("some bytes {} more bytes", marker).into_bytes();
            let hits = scan_bytes("secret", &buf);
            let hc: Vec<_> = hits
                .iter()
                .filter(|h| h.rule == "hardcoded_credentials")
                .collect();
            assert_eq!(hc.len(), 1, "marker {} should fire", marker);
            assert_eq!(hc[0].detail, format!("contains {}", marker));
            assert_eq!(hc[0].severity, "high");
            assert_eq!(hc[0].path, "secret");
        }
    }

    #[test]
    fn cloud_credentials_fires_on_aws_key_id_and_not_on_short_or_lowercase() {
        let buf = b"endpoint=https://s3.amazonaws.com/AKIAIOSFODNN7EXAMPLE";
        let hits = scan_bytes("creds", buf);
        let cc: Vec<_> = hits
            .iter()
            .filter(|h| h.rule == "cloud_credentials")
            .collect();
        assert_eq!(cc.len(), 1);
        assert_eq!(cc[0].detail, "AWS access key id AKIAIOSFODNN7EXAMPLE");
        assert_eq!(cc[0].severity, "high");

        let lower = b"akiaiosfodnn7example is not a real key";
        assert!(
            scan_bytes("x", lower)
                .iter()
                .all(|h| h.rule != "cloud_credentials")
        );

        let short = b"AKIAIOSFODNN7";
        assert!(
            scan_bytes("x", short)
                .iter()
                .all(|h| h.rule != "cloud_credentials")
        );

        assert!(scan_bytes("x", b"hello world").is_empty());
    }

    #[test]
    fn debug_endpoints_fires_on_adb_tcpip_and_jtag_but_not_on_clean_text() {
        let clean = b"system property ro.secure=1";
        assert!(
            scan_bytes("x", clean).is_empty(),
            "clean: {:?}",
            scan_bytes("x", clean)
        );

        let hits = scan_bytes("diag", b"ro.debuggable=1 and adb tcpip 5555");
        let de: Vec<_> = hits
            .iter()
            .filter(|h| h.rule == "debug_endpoints")
            .collect();
        assert_eq!(de.len(), 1);
        assert_eq!(de[0].severity, "medium");
        assert!(de[0].detail.contains("adb tcpip"));

        let hits2 = scan_bytes("jtagfile", b"jtag enable");
        let de2: Vec<_> = hits2
            .iter()
            .filter(|h| h.rule == "debug_endpoints")
            .collect();
        assert_eq!(de2.len(), 1);
        assert!(de2[0].detail.contains("jtag"));
    }

    #[test]
    fn multiple_rules_fire_independently() {
        let buf = b"BEGIN RSA PRIVATE KEY here and AKIAIOSFODNN7EXAMPLE and adb tcpip";
        let hits = scan_bytes("multi", buf);
        let rules: Vec<_> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert!(rules.contains(&"hardcoded_credentials"));
        assert!(rules.contains(&"cloud_credentials"));
        assert!(rules.contains(&"debug_endpoints"));
        assert_eq!(hits.len(), 3);
    }

    // Token-shaped strings are built at run time so no literal in the source looks like a secret.
    fn rep(c: char, n: usize) -> String {
        std::iter::repeat_n(c, n).collect()
    }

    fn tokens(buf: &str) -> Vec<(String, String)> {
        scan_bytes("t", buf.as_bytes())
            .into_iter()
            .filter(|h| h.rule == "provider_tokens")
            .map(|h| (h.detail, h.severity))
            .collect()
    }

    #[test]
    fn provider_tokens_are_found_by_prefix_length_and_alphabet() {
        let cases: Vec<(&str, String)> = vec![
            ("GitHub token", format!("t=gh{}_{}", "p", rep('a', 36))),
            ("GitHub token", format!("gh{}_{}", "s", rep('B', 36))),
            (
                "GitHub fine-grained token",
                format!("github{}pat_{}", "_", rep('c', 82)),
            ),
            ("GitLab token", format!("gl{}-{}", "pat", rep('d', 20))),
            (
                "Slack token",
                format!("xo{}-1234567890-{}", "xb", rep('e', 20)),
            ),
            (
                "Slack webhook",
                format!(
                    "https://hooks.slack.com/services/T{}/B{}/{}",
                    rep('1', 9),
                    rep('2', 9),
                    rep('f', 24)
                ),
            ),
            (
                "Discord webhook",
                format!("discord.com/api/webhooks/{}/{}", rep('7', 18), rep('g', 68)),
            ),
            (
                "Stripe secret key",
                format!("sk{}live_{}", "_", rep('h', 24)),
            ),
            (
                "SendGrid key",
                format!("S{}.{}.{}", "G", rep('i', 22), rep('j', 43)),
            ),
            ("npm token", format!(" np{}_{}", "m", rep('k', 36))),
            ("Google API key", format!("AI{}{}", "za", rep('l', 35))),
            (
                "Google OAuth client secret",
                format!("GOC{}-{}", "SPX", rep('m', 28)),
            ),
            ("Twilio API key", format!("S{}{}", "K", rep('a', 32))),
            ("Mailgun key", format!(" ke{}-{}", "y", rep('b', 32))),
            ("Shopify token", format!("shp{}_{}", "at", rep('c', 32))),
            (
                "Square access token",
                format!("sq0{}-{}", "atp", rep('n', 22)),
            ),
            (
                "PyPI token",
                format!("py{}-AgEIcHlwaS5vcmc{}", "pi", rep('o', 60)),
            ),
            (
                "DigitalOcean token",
                format!("dop{}_{}", "_v1", rep('d', 64)),
            ),
            ("Hugging Face token", format!(" h{}_{}", "f", rep('p', 34))),
            ("OpenAI key", format!("sk-{}-{}", "proj", rep('q', 48))),
            (
                "Anthropic key",
                format!("sk-{}-api03-{}", "ant", rep('r', 90)),
            ),
            ("Linear key", format!("lin_{}_{}", "api", rep('s', 40))),
            (
                "Postman key",
                format!("PM{}-{}-{}", "AK", rep('a', 24), rep('b', 34)),
            ),
            (
                "Docker Hub token",
                format!("dckr{}_{}", "_pat", rep('t', 27)),
            ),
            ("Databricks token", format!(" da{}{}", "pi", rep('e', 32))),
            (
                "Azure storage account key",
                format!("Account{}={}==", "Key", rep('A', 86)),
            ),
            (
                "JSON Web Token",
                format!(
                    "ey{}.eyJ{}.{}",
                    "J".to_string() + &rep('h', 20),
                    rep('p', 30),
                    rep('s', 43)
                ),
            ),
        ];
        for (name, text) in cases {
            let got = tokens(&text);
            assert!(
                got.iter().any(|(d, _)| d.starts_with(name)),
                "{name} not found in {text:?}: {got:?}"
            );
            // never reported in full
            assert!(
                got.iter()
                    .all(|(d, _)| !d.contains(&text[text.len().saturating_sub(10)..])),
                "{name}: {got:?}"
            );
        }
    }

    #[test]
    fn near_misses_are_not_tokens() {
        let gh = |n: usize| format!("gh{}_{}", "p", rep('a', n));
        assert!(tokens(&gh(35)).is_empty(), "too short");
        assert!(
            tokens(&gh(37)).is_empty(),
            "longer than the format: a different string"
        );
        assert!(tokens(&format!("x{}", rep('a', 40))).is_empty());
        // a short common prefix inside a word is not a token
        assert!(tokens(&format!("task_{}", rep('a', 36))).is_empty());
        assert!(tokens(&format!("Ak{}", rep('a', 40))).is_empty());
        let sk = |p: &str| format!("{p}{}", rep('b', 32));
        assert!(
            tokens(&format!("x{}", sk("SK"))).is_empty(),
            "SK inside a word"
        );
        assert!(tokens(&rep('0', 200)).is_empty());
        assert!(tokens("").is_empty());
    }

    #[test]
    fn a_token_is_reported_once_with_its_severity_and_redacted() {
        let t = format!("gh{}_{}", "p", rep('Z', 36));
        let buf = format!("{t} {t}");
        let got = tokens(&buf);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(
            got[0].0.starts_with("GitHub token ghp_ZZ... (40 chars)"),
            "{got:?}"
        );
        assert_eq!(got[0].1, "high");
        let jwt = format!(
            "ey{}.eyJ{}.{}",
            "J".to_string() + &rep('h', 12),
            rep('p', 12),
            rep('s', 12)
        );
        assert_eq!(tokens(&jwt)[0].1, "medium");
    }

    #[test]
    fn more_key_formats_and_aws_session_keys_are_flagged() {
        let hits = scan_bytes(
            "k",
            b"-----BEGIN PGP PRIVATE KEY BLOCK----- and ASIAIOSFODNN7EXAMPLE",
        );
        let rules: Vec<_> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert!(
            rules.contains(&"hardcoded_credentials") && rules.contains(&"cloud_credentials"),
            "{hits:?}"
        );
    }

    #[test]
    fn a_large_buffer_scans_quickly_and_without_panics() {
        let mut big = vec![b'g'; 4 << 20];
        big.extend(format!("gh{}_{}", "p", rep('a', 36)).bytes());
        let start = std::time::Instant::now();
        assert_eq!(tokens(&String::from_utf8(big).unwrap()).len(), 1);
        assert!(start.elapsed().as_secs() < 10);
        for cut in 0..64 {
            let t = format!(
                "hooks.slack.com/services/T{}/B{}/{}",
                rep('1', 9),
                rep('2', 9),
                rep('f', 24)
            );
            let _ = tokens(&t[..t.len().saturating_sub(cut)]);
        }
    }
}
