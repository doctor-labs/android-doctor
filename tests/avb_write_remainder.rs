//! `avbextract` and `avbappend`: extract a vbmeta block and append one to a partition image (#184).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SALT: &str = "00112233445566778899aabbccddeeff";

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("avb-remainder-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(
        std::env::var("CARGO_BIN_EXE_android-doctor").expect("CARGO_BIN_EXE_android_doctor"),
    )
    .args(args)
    .output()
    .unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn footer_image(dir: &Path) -> (PathBuf, Vec<u8>) {
    let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let raw = dir.join("boot-raw.img");
    let out = dir.join("boot.img");
    std::fs::write(&raw, &data).unwrap();
    let o = run(&[
        "avbfooter",
        s(&raw),
        "-o",
        s(&out),
        "--partition-name",
        "boot",
        "--partition-size",
        "1048576",
        "--salt",
        SALT,
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    (out, data)
}

#[test]
fn extract_vbmeta_from_footer_round_trips_and_appends_back() {
    let dir = scratch("extract-append");
    let (img, raw) = footer_image(&dir);
    let vb = dir.join("vbmeta.img");
    let o = run(["avbextract", s(&img), "-o", s(&vb)].as_slice());
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let vb_bytes = std::fs::read(&vb).unwrap();
    assert!(vb_bytes.starts_with(b"AVB0"));

    let raw_path = dir.join("raw.img");
    std::fs::write(&raw_path, &raw).unwrap();
    let out = dir.join("appended.img");
    let o = run([
        "avbappend",
        s(&raw_path),
        "--vbmeta",
        s(&vb),
        "-o",
        s(&out),
        "--partition-size",
        "1048576",
    ]
    .as_slice());
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let rebuilt = std::fs::read(&out).unwrap();
    assert_eq!(rebuilt, std::fs::read(&img).unwrap(), "append of extracted vbmeta reproduces the footer image");
}

#[test]
fn extract_vbmeta_from_bare_vbmeta_writes_the_image() {
    let dir = scratch("extract-bare");
    let vb = dir.join("vbmeta.img");
    let o = run(["avbmake", "-o", s(&vb), "--algorithm", "NONE", "--rollback-index", "3"].as_slice());
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = dir.join("out.img");
    let o = run(["avbextract", s(&vb), "-o", s(&out)].as_slice());
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read(&vb).unwrap(), std::fs::read(&out).unwrap());
}
