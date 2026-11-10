//! `sqlite` and the audit's SQLite rules. The database is `tests/fixtures/sqlite/app.db`, made by
//! python3's `sqlite3` module (3.46.1) with two tables and an index; its expected header and schema
//! below are python's read-only answers for the same file. The audit runs on an erofs image built
//! in-process, so nothing else is needed.

use fs_erofs::mkfs::{Node, NodeMeta, build_image};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

const APP_DB: &[u8] = include_bytes!("fixtures/sqlite/app.db");
const APP_DB_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sqlite/app.db");

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

/// An app's data directory: one world-readable and one private plaintext database, a file that
/// is not a database, a database-named file with no SQLite magic (as an encrypted one looks),
/// and a truncated file that starts with the magic.
fn image() -> Vec<u8> {
    let app = dir(vec![(
        "databases",
        dir(vec![
            ("open.db", file(0o644, APP_DB)),
            ("private.db", file(0o600, APP_DB)),
            ("notes.bin", file(0o644, b"not a database")),
            ("cipher.db", file(0o644, &[0x5a; 4096])),
        ]),
    )]);
    build_image(
        dir(vec![
            (
                "data",
                dir(vec![("data", dir(vec![("com.example.app", app)]))]),
            ),
            (
                "etc",
                dir(vec![(
                    "fake.db",
                    file(0o644, b"SQLite format 3\0 but truncated"),
                )]),
            ),
        ]),
        12,
    )
    .unwrap()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ad-sqlite-{tag}-{}", std::process::id()));
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

fn run(args: &[&std::ffi::OsStr]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_android-doctor"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn sqlite_verb_reports_the_header_and_schema_python_reads() {
    let (code, out, _) = run(&["sqlite".as_ref(), APP_DB_PATH.as_ref(), "--json".as_ref()]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&out).unwrap();
    // python3 sqlite3 PRAGMA page_size / page_count / freelist_count / encoding and sqlite_master.
    assert_eq!(v["page_size"], 4096);
    assert_eq!(v["page_count"], 4);
    assert_eq!(v["freelist_count"], 0);
    assert_eq!(v["text_encoding"], "UTF-8");
    assert_eq!(v["wal"], false);
    assert_eq!(
        v["schema"],
        json!([
            {"type": "table", "name": "accounts", "rootpage": 2, "sql": "CREATE TABLE accounts(id integer primary key, token text not null)"},
            {"type": "index", "name": "idx_token", "rootpage": 3, "sql": "CREATE INDEX idx_token on accounts(token)"},
            {"type": "table", "name": "prefs", "rootpage": 4, "sql": "CREATE TABLE prefs(key text, value text)"},
        ])
    );

    let (code, text, _) = run(&["sqlite".as_ref(), APP_DB_PATH.as_ref()]);
    assert_eq!(code, 0);
    assert!(text.starts_with("app.db: SQLite database"), "{text}");
    assert!(text.contains("page size 4096, 4 pages, 0 freelist pages, text encoding UTF-8"));
    assert!(
        text.contains("index idx_token (rootpage 3): CREATE INDEX idx_token on accounts(token)")
    );
}

#[test]
fn sqlite_verb_refuses_a_file_that_is_not_a_database() {
    let d = Scratch::new("not-db");
    let p = d.0.join("text.db");
    std::fs::write(
        &p,
        "plain text, no database here, long enough to pass the size check. ".repeat(4),
    )
    .unwrap();
    let (code, _, err) = run(&["sqlite".as_ref(), p.as_ref()]);
    assert_ne!(code, 0);
    assert!(err.contains("not a plaintext SQLite database"), "{err}");
}

#[test]
fn audit_lists_plaintext_databases_and_flags_world_readable_and_unencrypted_ones() {
    let d = Scratch::new("audit");
    let img = d.0.join("app.img");
    std::fs::write(&img, image()).unwrap();
    let (_, out, _) = run(&["audit".as_ref(), img.as_ref(), "--json".as_ref()]);
    let v: Value = serde_json::from_str(&out).unwrap();
    let image = &v["data"]["images"][0];

    // Only the two plaintext databases are listed: the encrypted-looking file, the truncated one
    // and the non-database are not.
    let dbs = image["sqlite_databases"].as_array().unwrap();
    let paths: Vec<&str> = dbs.iter().map(|x| x["path"].as_str().unwrap()).collect();
    assert_eq!(
        paths,
        [
            "data/data/com.example.app/databases/open.db",
            "data/data/com.example.app/databases/private.db"
        ]
    );
    assert_eq!(dbs[0]["mode"], "0644");
    assert_eq!(dbs[1]["mode"], "0600");
    assert_eq!(dbs[0]["schema"].as_array().unwrap().len(), 3);

    let rules: Vec<(&str, &str)> = image["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"].as_str().unwrap().starts_with("sqlite-"))
        .map(|f| (f["rule"].as_str().unwrap(), f["detail"].as_str().unwrap()))
        .collect();
    let world: Vec<_> = rules
        .iter()
        .filter(|r| r.0 == "sqlite-world-readable")
        .collect();
    let plain: Vec<_> = rules
        .iter()
        .filter(|r| r.0 == "sqlite-unencrypted")
        .collect();
    assert_eq!(world.len(), 1, "{rules:?}");
    assert!(
        world[0].1.contains("open.db") && world[0].1.contains("0644"),
        "{rules:?}"
    );
    assert_eq!(plain.len(), 2, "{rules:?}");
}

#[test]
fn an_image_without_plaintext_databases_has_no_sqlite_key() {
    let d = Scratch::new("none");
    let img = d.0.join("plain.img");
    std::fs::write(
        &img,
        build_image(
            dir(vec![(
                "etc",
                dir(vec![("hosts", file(0o644, b"127.0.0.1 localhost\n"))]),
            )]),
            12,
        )
        .unwrap(),
    )
    .unwrap();
    let (_, out, _) = run(&["audit".as_ref(), img.as_ref(), "--json".as_ref()]);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v["data"]["images"][0].get("sqlite_databases").is_none());
}
