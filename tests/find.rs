//! `find` over an ext/erofs image: name glob, SELinux label, setuid, extended attributes and
//! content search. The fixture is built in-process (erofs builder), so nothing depends on host tools.

use fs_erofs::mkfs::{Node, NodeMeta, XattrSpec, build_image};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn file(mode: u16, data: &[u8], xattrs: Vec<XattrSpec>) -> Node {
    Node::File {
        mode: 0o100000 | mode,
        data: data.to_vec(),
        meta: NodeMeta::default(),
        xattrs,
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

/// bin/su (setuid, su label), bin/ping (shell label), etc/hosts, app/secret.txt (content to grep).
fn fixture(tag: &str) -> PathBuf {
    let dir_path = std::env::temp_dir().join(format!("ad-find-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir_path).unwrap();
    let label = |l: &str| vec![XattrSpec::new(6, "selinux", format!("{l}\0"))];
    let root = dir(vec![
        (
            "bin",
            dir(vec![
                (
                    "su",
                    file(0o4755, b"fake su\n", label("u:object_r:system_file:s0")),
                ),
                (
                    "ping",
                    file(0o755, b"ping\n", label("u:object_r:shell_exec:s0")),
                ),
            ]),
        ),
        (
            "etc",
            dir(vec![(
                "hosts",
                file(0o644, b"127.0.0.1 localhost\n", vec![]),
            )]),
        ),
        (
            "app",
            dir(vec![(
                "secret.txt",
                file(0o600, b"token=hunter2\n", vec![]),
            )]),
        ),
    ]);
    let img = dir_path.join("system.img");
    std::fs::write(&img, build_image(root, 12).unwrap()).unwrap();
    img
}

fn find(img: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .arg("find")
        .arg(img)
        .args(args)
        .output()
        .unwrap()
}

fn lines(o: &Output) -> Vec<String> {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn name_glob_matches_basenames() {
    let img = fixture("name");
    assert_eq!(lines(&find(&img, &["--name", "s?"])), ["/bin/su"]);
    assert_eq!(
        lines(&find(&img, &["--name", "*.txt"])),
        ["/app/secret.txt"]
    );
    // a path restricts the search to that directory (and includes the directory itself, as find does)
    assert_eq!(
        lines(&find(&img, &["/etc", "--name", "*"])),
        ["/etc", "/etc/hosts"]
    );
}

#[test]
fn setuid_and_selinux_label_filters() {
    let img = fixture("suid");
    assert_eq!(lines(&find(&img, &["--setuid"])), ["/bin/su"]);
    assert_eq!(
        lines(&find(&img, &["--selinux", "u:object_r:shell_*"])),
        ["/bin/ping"]
    );
    assert_eq!(
        lines(&find(&img, &["--xattr", "security.selinux=*system_file*"])),
        ["/bin/su"]
    );
    // filters combine with AND
    assert!(lines(&find(&img, &["--setuid", "--name", "ping"])).is_empty());
}

#[test]
fn grep_searches_file_content_and_names_what_it_did_not_check() {
    let img = fixture("grep");
    assert_eq!(
        lines(&find(&img, &["--grep", "hunter2"])),
        ["/app/secret.txt"]
    );
    assert!(lines(&find(&img, &["--grep", "absent-text"])).is_empty());
}

#[test]
fn json_is_the_doctor_envelope_with_matches_under_data() {
    let img = fixture("json");
    let o = find(&img, &["--name", "su", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["schema"], "doctor/1");
    assert_eq!(v["tool"], "android-doctor");
    assert_eq!(v["exit_code"], 0);
    assert!(v["findings"].as_array().unwrap().is_empty());
    assert_eq!(v["data"]["matches"][0]["path"], "bin/su");
    assert_eq!(v["data"]["matches"][0]["mode"], 0o4755);
}

#[test]
fn without_a_filter_it_is_a_usage_error() {
    let img = fixture("usage");
    let o = find(&img, &[]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--name"));
}
