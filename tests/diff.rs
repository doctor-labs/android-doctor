//! End-to-end tests for `diff`: two small generated erofs builds that differ in known ways.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ad-diff-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn file(mode: u16, data: &[u8]) -> Node {
    Node::File {
        mode: 0o100000 | mode,
        data: data.to_vec(),
        meta: NodeMeta::default(),
        xattrs: vec![],
    }
}

fn dir(entries: Vec<(&str, Node)>) -> Node {
    Node::Dir {
        mode: 0o040755,
        entries: entries
            .into_iter()
            .map(|(n, v)| (n.to_string(), v))
            .collect::<BTreeMap<_, _>>(),
        meta: NodeMeta::default(),
        xattrs: vec![],
    }
}

fn old_image() -> Vec<u8> {
    build_image(
        dir(vec![
            ("build.prop", file(0o644, b"ro.secure=1\nro.debuggable=0\n")),
            ("gone.txt", file(0o644, b"bye")),
            (
                "bin",
                dir(vec![
                    ("tool", file(0o755, b"version one")),
                    ("same", file(0o755, b"same")),
                    ("perm", file(0o644, b"perm")),
                ]),
            ),
            (
                "etc",
                dir(vec![
                    (
                        "init",
                        dir(vec![(
                            "a.rc",
                            file(0o644, b"service foo /bin/foo\n    user system\n"),
                        )]),
                    ),
                    (
                        "selinux",
                        dir(vec![("plat_sepolicy.cil", file(0o644, b"(allow a b)"))]),
                    ),
                ]),
            ),
        ]),
        12,
    )
    .unwrap()
}

fn new_image() -> Vec<u8> {
    build_image(
        dir(vec![
            ("build.prop", file(0o644, b"ro.secure=0\nro.debuggable=1\n")),
            ("added.txt", file(0o644, b"new")),
            ("evil\u{1b}[31mname.txt", file(0o644, b"x")),
            (
                "bin",
                dir(vec![
                    ("tool", file(0o755, b"version two")),
                    ("same", file(0o755, b"same")),
                    ("perm", file(0o755, b"perm")),
                    ("helper", file(0o4755, b"suid")),
                ]),
            ),
            ("xbin", dir(vec![("su", file(0o755, b"#!/bin/sh\n"))])),
            (
                "etc",
                dir(vec![
                    (
                        "init",
                        dir(vec![(
                            "a.rc",
                            file(
                                0o644,
                                b"service foo /bin/foo\n    user system\nservice bar /bin/bar\n",
                            ),
                        )]),
                    ),
                    (
                        "selinux",
                        dir(vec![("plat_sepolicy.cil", file(0o644, b"(allow a c)"))]),
                    ),
                ]),
            ),
        ]),
        12,
    )
    .unwrap()
}

struct Out {
    code: i32,
    stdout: String,
}

fn run(args: &[&std::ffi::OsStr]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    Out {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

fn setup(tag: &str) -> (Scratch, PathBuf, PathBuf) {
    let d = Scratch::new(tag);
    let (o, n) = (d.0.join("old.img"), d.0.join("new.img"));
    std::fs::write(&o, old_image()).unwrap();
    std::fs::write(&n, new_image()).unwrap();
    (d, o, n)
}

fn diff_json(o: &PathBuf, n: &PathBuf, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut a: Vec<&std::ffi::OsStr> =
        vec!["diff".as_ref(), o.as_ref(), n.as_ref(), "--json".as_ref()];
    a.extend(extra.iter().map(|s| std::ffi::OsStr::new(*s)));
    let r = run(&a);
    let v = serde_json::from_str(&r.stdout).unwrap_or_else(|e| panic!("{e}: {}", r.stdout));
    (r.code, v)
}

fn statuses(v: &serde_json::Value) -> BTreeMap<String, String> {
    v["data"]["images"][0]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["path"].as_str().unwrap().to_string(),
                f["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn every_known_difference_is_reported_and_the_envelope_conforms() {
    let (_d, o, n) = setup("main");
    let (code, v) = diff_json(&o, &n, &[]);
    // A new setuid file, su binary and ro.secure=0 are high: the default gate is high.
    assert_eq!(code, 1);
    assert_eq!(v["exit_code"], 1);
    assert_eq!(v["schema"], "doctor/1");
    assert_eq!(v["tool"], "android-doctor");
    for k in ["version", "score", "findings", "data"] {
        assert!(v.get(k).is_some(), "{k}");
    }

    let s = statuses(&v);
    assert_eq!(s["added.txt"], "added");
    assert_eq!(s["gone.txt"], "removed");
    assert_eq!(s["bin/tool"], "modified");
    assert_eq!(s["bin/perm"], "metadata");
    assert_eq!(s["bin/helper"], "added");
    assert_eq!(s["etc/selinux/plat_sepolicy.cil"], "modified");
    assert_eq!(s["build.prop"], "modified");
    assert!(
        !s.contains_key("bin/same"),
        "unchanged files are only counted"
    );
    assert_eq!(v["data"]["images"][0]["counts"]["unchanged"], 1);
    let tool = v["data"]["images"][0]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "bin/tool")
        .unwrap();
    assert_ne!(tool["old"]["sha256"], tool["new"]["sha256"]);
    assert_eq!(tool["new"]["sha256"].as_str().unwrap().len(), 64);

    let rows = v["findings"].as_array().unwrap();
    let ids: Vec<&str> = rows.iter().map(|f| f["id"].as_str().unwrap()).collect();
    for want in [
        "diff-new-setuid",
        "diff-su-binary",
        "diff-insecure-adb",
        "diff-debuggable-build",
        "diff-root-service",
        "diff-sepolicy-changed",
        "diff-prop-changed",
    ] {
        assert!(ids.contains(&want), "{want} in {ids:?}");
    }
    assert!(!ids.contains(&"diff-new-capability"));
    let svc = rows
        .iter()
        .find(|f| f["id"] == "diff-root-service")
        .unwrap();
    assert_eq!(svc["subject"], "etc/init/a.rc");
    assert!(svc["message"].as_str().unwrap().contains("bar"));
    assert_eq!(v["data"]["images"][0]["services"][0]["name"], "bar");
    for f in rows {
        for k in [
            "id",
            "fingerprint",
            "severity",
            "category",
            "message",
            "location",
            "remedy",
        ] {
            assert!(f.get(k).is_some(), "{k} in {f}");
        }
        assert!(
            ["critical", "high", "medium", "low", "info"]
                .contains(&f["severity"].as_str().unwrap())
        );
        assert!(["file", "image", "none"].contains(&f["location"]["kind"].as_str().unwrap()));
        let fp = f["fingerprint"].as_str().unwrap();
        assert!(
            fp.len() == 16
                && fp
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
    let (_, again) = diff_json(&o, &n, &[]);
    assert_eq!(v, again, "two runs give the same output");
}

/// The unified hunks GNU `diff -U3` prints for the same two texts (its `---`/`+++` headers dropped).
fn gnu_hunks(d: &Scratch, old: &str, new: &str) -> String {
    let (a, b) = (d.0.join("old.txt"), d.0.join("new.txt"));
    std::fs::write(&a, old).unwrap();
    std::fs::write(&b, new).unwrap();
    let out = Command::new("diff")
        .arg("-U3")
        .arg(&a)
        .arg(&b)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(2)
        .map(|l| format!("{l}\n"))
        .collect()
}

#[test]
fn changed_text_files_get_a_unified_diff_matching_gnu_diff() {
    let (d, o, n) = setup("textdiff");
    let (_, v) = diff_json(&o, &n, &[]);
    let files = v["data"]["images"][0]["files"].as_array().unwrap();
    let file = |p: &str| files.iter().find(|f| f["path"] == p).unwrap();

    // Text targets (.prop, .rc) get the line diff; a binary or other file does not.
    let prop = gnu_hunks(
        &d,
        "ro.secure=1\nro.debuggable=0\n",
        "ro.secure=0\nro.debuggable=1\n",
    );
    assert_eq!(file("build.prop")["unified_diff"], prop.as_str());
    let rc = gnu_hunks(
        &d,
        "service foo /bin/foo\n    user system\n",
        "service foo /bin/foo\n    user system\nservice bar /bin/bar\n",
    );
    assert_eq!(file("etc/init/a.rc")["unified_diff"], rc.as_str());
    assert!(file("bin/tool").get("unified_diff").is_none());
    assert!(
        file("etc/selinux/plat_sepolicy.cil")
            .get("unified_diff")
            .is_none()
    );

    let human = run(&["diff".as_ref(), o.as_ref(), n.as_ref()]).stdout;
    assert!(human.contains("      +ro.secure=0"), "{human}");
    assert!(human.contains("      -ro.secure=1"), "{human}");
}

#[test]
fn an_identical_pair_is_clean_and_exits_0() {
    let (_d, o, _) = setup("same");
    let (code, v) = diff_json(&o, &o, &[]);
    assert_eq!(code, 0);
    assert!(v["findings"].as_array().unwrap().is_empty());
    assert!(
        v["data"]["images"][0]["files"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn only_filters_the_file_list_but_not_the_findings() {
    let (_d, o, n) = setup("only");
    let (_, all) = diff_json(&o, &n, &[]);
    let (_, v) = diff_json(&o, &n, &["--only", "removed,metadata"]);
    let s = statuses(&v);
    assert_eq!(s.len(), 2, "{s:?}");
    assert_eq!(v["findings"], all["findings"]);
    let bad = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--only".as_ref(),
        "nope".as_ref(),
    ]);
    assert_eq!(bad.code, 2);
}

#[test]
fn baseline_and_fail_on_follow_the_exit_code_contract() {
    let (d, o, n) = setup("gate");
    let base = d.0.join("base.json");
    // Against its own envelope nothing is new: exit 0.
    let (_, v) = diff_json(&o, &n, &[]);
    std::fs::write(&base, v.to_string()).unwrap();
    let r = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--json".as_ref(),
        "--baseline".as_ref(),
        base.as_ref(),
    ]);
    assert_eq!(r.code, 0);
    // Against an empty baseline everything is new: exit 3.
    std::fs::write(&base, "[]").unwrap();
    let r = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--json".as_ref(),
        "--baseline".as_ref(),
        base.as_ref(),
    ]);
    assert_eq!(r.code, 3);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&r.stdout).unwrap()["exit_code"],
        3
    );
    // Raising the threshold above everything found lets it pass.
    let r = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--json".as_ref(),
        "--fail-on".as_ref(),
        "critical".as_ref(),
    ]);
    assert_eq!(r.code, 0);
    // Two different kinds of input is a usage error.
    let r = run(&["diff".as_ref(), o.as_ref(), d.0.as_ref()]);
    assert_eq!(r.code, 2);
}

#[test]
fn directories_of_images_pair_by_name_and_human_output_is_sanitized() {
    let (d, ..) = setup("dirs");
    let (a, b) = (d.0.join("a"), d.0.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("system.img"), old_image()).unwrap();
    std::fs::write(b.join("system.img"), new_image()).unwrap();
    std::fs::write(b.join("vendor.img"), old_image()).unwrap();
    let (_, v) = diff_json(&a, &b, &[]);
    let imgs = v["data"]["images"].as_array().unwrap();
    assert_eq!(imgs.len(), 2);
    assert_eq!(imgs[0]["name"], "system");
    assert_eq!(imgs[0]["presence"], "both");
    assert_eq!(imgs[1]["name"], "vendor");
    assert_eq!(imgs[1]["presence"], "added");
    let t = run(&["diff".as_ref(), a.as_ref(), b.as_ref()]);
    assert!(t.stdout.contains("added.txt"), "{}", t.stdout);
    assert!(t.stdout.contains("evil"), "{}", t.stdout);
    assert!(!t.stdout.contains('\u{1b}'), "an ESC reached the terminal");
}

#[test]
fn mcp_returns_the_cli_envelope_unchanged() {
    let (_d, o, n) = setup("mcp");
    let cli = run(&[
        "diff".as_ref(),
        o.as_ref(),
        n.as_ref(),
        "--fail-on".as_ref(),
        "low".as_ref(),
        "--json".as_ref(),
    ]);
    let call = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"diff","arguments":{"old":o.to_str().unwrap(),"new":n.to_str().unwrap(),"fail_on":"low"}}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{call}").unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child.wait().unwrap();
    let r: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(r["result"]["isError"], false, "{out}");
    assert_eq!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .trim_end(),
        cli.stdout.trim_end()
    );
}

/// An erofs filesystem with an AVB footer and vbmeta block appended, the layout of a hashtree
/// partition. The vbmeta is taken from the `avb` fixture (`a.img`) with its rollback index set.
fn avb_partition(rollback_index: u64) -> Vec<u8> {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/avb/a.img"
    ))
    .unwrap();
    let footer = &fixture[fixture.len() - 64..];
    let off = u64::from_be_bytes(footer[20..28].try_into().unwrap()) as usize;
    let size = u64::from_be_bytes(footer[28..36].try_into().unwrap()) as usize;
    let mut vbmeta = fixture[off..off + size].to_vec();
    vbmeta[112..120].copy_from_slice(&rollback_index.to_be_bytes());
    let mut img =
        build_image(dir(vec![("build.prop", file(0o644, b"ro.secure=1\n"))]), 12).unwrap();
    let original = img.len() as u64;
    let vbmeta_offset = img.len() as u64;
    img.extend_from_slice(&vbmeta);
    let mut f = vec![0u8; 64];
    f[..4].copy_from_slice(b"AVBf");
    f[4..8].copy_from_slice(&1u32.to_be_bytes());
    f[12..20].copy_from_slice(&original.to_be_bytes());
    f[20..28].copy_from_slice(&vbmeta_offset.to_be_bytes());
    f[28..36].copy_from_slice(&(vbmeta.len() as u64).to_be_bytes());
    img.extend_from_slice(&f);
    img
}

#[test]
fn a_lower_avb_rollback_index_is_a_high_diff_finding_and_an_equal_one_is_not() {
    let d = Scratch::new("avb-rollback");
    let (old, new, same) = (
        d.0.join("old.img"),
        d.0.join("new.img"),
        d.0.join("same.img"),
    );
    std::fs::write(&old, avb_partition(5)).unwrap();
    std::fs::write(&new, avb_partition(4)).unwrap();
    std::fs::write(&same, avb_partition(5)).unwrap();
    let hits = |v: &serde_json::Value| -> Vec<serde_json::Value> {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["id"] == "diff-avb-rollback-index")
            .cloned()
            .collect()
    };
    let (_, v) = diff_json(&old, &new, &[]);
    let found = hits(&v);
    assert_eq!(found.len(), 1, "{v}");
    assert_eq!(found[0]["severity"], "high");
    let (_, v) = diff_json(&old, &same, &[]);
    assert!(hits(&v).is_empty(), "{v}");
}

/// The AVB descriptor diff on a real pair (tests/corpus/avb-diff/key-chain-cmdline). The expected
/// values are AOSP avbtool 1.3.0 (android-15.0.0_r1) `info_image` on the same files:
///   old: Algorithm SHA256_RSA2048, Rollback Index 5 (location 0), Chain Partition descriptor
///        vendor_boot (location 1, key sha1 d83b43c4...), Kernel Cmdline 'androidboot.selinux=enforcing',
///        Prop ro.build.date.utc -> '1700000000', Hashtree descriptor system (Hash Algorithm sha256).
///   new: Algorithm SHA256_RSA4096 (key sha1 e0c66fca...), chain vendor_boot with that key,
///        Kernel Cmdline 'androidboot.selinux=permissive', Hashtree system (Hash Algorithm sha1),
///        Prop ro.build.date.utc -> '1700000100'.
/// The sha256 of each public key blob (`sha256sum` of `avbtool extract_public_key`) is 10fe8d79...
/// for testkey-2048 and b05df697... for testkey-4096, the values the parser reports.
#[test]
fn avb_descriptor_diff_matches_avbtool_info_image_on_a_real_pair() {
    use serde_json::json;
    let case =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/avb-diff/key-chain-cmdline");
    let (k2048, k4096) = (
        "10fe8d79d6130801cb4b372df38f518356b79ae4a4d9298288ac650eb595a509",
        "b05df6979a92679ba6323324d06c5be95f1259413b290c6fc6699f85691014bc",
    );
    let (code, v) = diff_json(&case.join("old.img"), &case.join("new.img"), &[]);
    let img = &v["data"]["images"][0];
    assert_eq!(
        img["avb_header"],
        json!([
            {"field": "algorithm", "old": "SHA256_RSA2048", "new": "SHA256_RSA4096"},
            {"field": "public_key_sha256", "old": k2048, "new": k4096},
        ]),
        "{img}"
    );
    assert_eq!(
        img["avb_descriptors"],
        json!([
            {"type": "chain_partition", "name": "vendor_boot", "status": "changed",
             "fields": [{"field": "public_key_sha256", "old": k2048, "new": k4096}]},
            {"type": "hashtree", "name": "system", "status": "changed",
             "fields": [{"field": "algorithm", "old": "sha256", "new": "sha1"}]},
            {"type": "kernel_cmdline", "name": "", "status": "changed",
             "fields": [{"field": "text", "old": "androidboot.selinux=enforcing",
                         "new": "androidboot.selinux=permissive"}]},
            {"type": "property", "name": "ro.build.date.utc", "status": "changed",
             "fields": [{"field": "value", "old": "1700000000", "new": "1700000100"}]},
        ]),
        "{img}"
    );
    let mut ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            "diff-avb-algorithm",
            "diff-avb-chain-key",
            "diff-avb-cmdline",
            "diff-avb-hash-algorithm",
            "diff-avb-signing-key",
        ],
        "{v}"
    );
    assert_eq!(code, 0, "medium findings do not fail the default gate: {v}");

    let text = run(&[
        std::ffi::OsStr::new("diff"),
        case.join("old.img").as_os_str(),
        case.join("new.img").as_os_str(),
    ]);
    assert!(
        text.stdout
            .contains("  avb header algorithm: SHA256_RSA2048 -> SHA256_RSA4096"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout
            .contains("  avb hashtree system: algorithm sha256 -> sha1"),
        "{}",
        text.stdout
    );

    let d = Scratch::new("avb-sarif");
    let sarif = d.0.join("out.sarif");
    diff_json(
        &case.join("old.img"),
        &case.join("new.img"),
        &["--sarif", sarif.to_str().unwrap()],
    );
    let sarif = std::fs::read_to_string(&sarif).unwrap();
    assert!(sarif.contains("diff-avb-cmdline"), "{sarif}");
}

/// Each committed AVB corpus pair (tests/corpus/avb-diff/<case>/) must report exactly the rows of
/// tests/corpus/expected/avb-diff-<case>.json; `UPDATE_CORPUS=1` rewrites them. Kept here rather
/// than in tests/corpus.rs, whose pass count the CI corpus gate asserts.
///
/// How the pairs were made, with AOSP avbtool 1.3.0 (android-15.0.0_r1) and the keys in
/// tests/fixtures/avbcert: `add_hash_footer` for boot and dtbo (4 KiB images, `--partition_size
/// 73728`), `add_hashtree_footer` for system (`--partition_size 131072 --block_size 4096
/// --do_not_generate_fec`, sha256 or sha1), `make_vbmeta_image` with `--include_descriptors_from_image`,
/// `--chain_partition vendor_boot:<slot>:<key>`, `--kernel_cmdline`, `--prop` and `--padding_size
/// 4096`, then `append_vbmeta_image --partition_size 49152` onto a copy of
/// tests/fixtures/erofs/erofs-zstd-4k.img.
#[test]
fn avb_diff_corpus_pairs_match_their_snapshots() {
    use serde_json::json;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut cases: Vec<String> = std::fs::read_dir(root.join("avb-diff"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    cases.sort();
    assert!(
        !cases.is_empty(),
        "no avb-diff cases under {}",
        root.display()
    );
    let update = std::env::var_os("UPDATE_CORPUS").is_some();
    for case in cases {
        let dir = root.join("avb-diff").join(&case);
        let (_, v) = diff_json(&dir.join("old.img"), &dir.join("new.img"), &[]);
        let mut got: Vec<serde_json::Value> = v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| json!({"id": f["id"], "severity": f["severity"], "subject": f["subject"]}))
            .collect();
        got.sort_by_key(|f| f.to_string());
        let snap = root.join("expected").join(format!("avb-diff-{case}.json"));
        if update {
            std::fs::write(&snap, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
            continue;
        }
        let mut want: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&snap).unwrap()).unwrap();
        want.sort_by_key(|f| f.to_string());
        assert_eq!(got, want, "{case}: findings differ from {}", snap.display());
    }
}
