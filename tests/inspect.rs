//! `prop` and `init`: on-demand decode of one property or one init service from an image (#222).

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

fn file(data: &[u8]) -> Node {
    Node::File {
        mode: 0o100644,
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

const INIT_RC: &[u8] = b"on boot\n    start adbd\n\nservice adbd /apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0\n    class core\n    user root\n    group shell log\n    capabilities SETUID SETGID\n    disabled\n    seclabel u:r:adbd:s0\n";

/// A directory holding one erofs image: build.prop, default.prop and init.rc at its root.
fn image(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ad-inspect-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let root = dir(vec![
        (
            "build.prop",
            file(b"ro.build.type=userdebug\nro.secure=1\n"),
        ),
        ("default.prop", file(b"ro.secure=0\n")),
        ("init.rc", file(INIT_RC)),
    ]);
    let path = d.join("system.img");
    std::fs::write(&path, build_image(root, 12).unwrap()).unwrap();
    path
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn prop_names_every_file_that_sets_the_key() {
    let img = image("prop-text");
    let (code, out, err) = run(&["prop", img.to_str().unwrap(), "ro.secure"]);
    let _ = std::fs::remove_dir_all(img.parent().unwrap());
    assert_eq!(code, 0, "stderr: {err}");
    assert!(
        out.contains("ro.secure=1") && out.contains("build.prop"),
        "{out}"
    );
    assert!(
        out.contains("ro.secure=0") && out.contains("default.prop"),
        "{out}"
    );
}

#[test]
fn prop_json_is_a_plain_array_of_sources() {
    let img = image("prop-json");
    let (code, out, _) = run(&["prop", img.to_str().unwrap(), "ro.build.type", "--json"]);
    let _ = std::fs::remove_dir_all(img.parent().unwrap());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v[0]["key"], "ro.build.type");
    assert_eq!(v[0]["value"], "userdebug");
    assert_eq!(v[0]["file"], "build.prop");
}

#[test]
fn prop_not_set_says_how_much_was_searched() {
    let img = image("prop-missing");
    let (code, out, _) = run(&["prop", img.to_str().unwrap(), "ro.nope"]);
    let _ = std::fs::remove_dir_all(img.parent().unwrap());
    assert_eq!(code, 0);
    assert!(
        out.contains("not set") && out.contains("2 property files"),
        "{out}"
    );
}

#[test]
fn init_decodes_one_service() {
    let img = image("init-text");
    let (code, out, err) = run(&["init", img.to_str().unwrap(), "adbd"]);
    let _ = std::fs::remove_dir_all(img.parent().unwrap());
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("/apex/com.android.adbd/bin/adbd"), "{out}");
    assert!(out.contains("init.rc"), "{out}");
    assert!(
        out.contains("user root") && out.contains("SETUID SETGID"),
        "{out}"
    );
    assert!(!out.contains("on boot"), "{out}");
}

#[test]
fn init_json_has_the_service_fields() {
    let img = image("init-json");
    let (code, out, _) = run(&["init", img.to_str().unwrap(), "adbd", "--json"]);
    let _ = std::fs::remove_dir_all(img.parent().unwrap());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v[0]["name"], "adbd");
    assert_eq!(v[0]["file"], "init.rc");
    assert_eq!(v[0]["user"], "root");
    assert_eq!(v[0]["disabled"], true);
}

#[test]
fn init_unknown_service_says_how_much_was_searched() {
    let img = image("init-missing");
    let (code, out, _) = run(&["init", img.to_str().unwrap(), "nosuch"]);
    let _ = std::fs::remove_dir_all(img.parent().unwrap());
    assert_eq!(code, 0);
    assert!(
        out.contains("no service") && out.contains("1 init"),
        "{out}"
    );
}
