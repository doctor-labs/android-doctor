//! The tools android-doctor offers over the Model Context Protocol. The JSON-RPC loop is
//! doctor-kit's (`Doctor::mcp_tools`); this module owns the tool schemas and the mapping of a
//! tool call to CLI arguments.
use anyhow::Result;
use doctor_kit::McpTool;
use doctor_kit::mcp::{ExecOpts, exec_self_fmt};
use serde_json::{Value, json};
use std::time::Duration;

/// Flags the findings tools accept besides the target path(s). Excluded over MCP: `--json`
/// (always on), `--score`, `--no-color` (never any colour in JSON), `help` and `version`.
const FLAGS: &str = r#""baseline":{"type":"string","description":"Previous --json envelope; marks findings new/unchanged and exits 3 on a new one"},"fail_on":{"type":"string","enum":["critical","high","medium","low","info"],"description":"Exit 1 (3 under baseline) at or above this severity"},"sarif":{"type":"string","description":"Also write SARIF 2.1.0 to this file""#;

/// The tools this server exposes, in MCP `tools/list` shape.
pub fn tool_list() -> Value {
    let one = r#""path":{"type":"string"}"#;
    let image = r#""image":{"type":"string","description":"Image file (ext2/3/4, erofs or f2fs)"}"#;
    let many = r#""paths":{"type":"array","items":{"type":"string"},"description":"Image files or directories"}"#;
    let schema = |p: &str, req: &str, flags: bool| {
        let f = if flags {
            format!(",{FLAGS}}}")
        } else {
            String::new()
        };
        format!(r#"{{"type":"object","properties":{{{p}{f}}},"required":[{req}]}}"#)
    };
    json!({ "tools": [
        tool("identify", "Identify the format of a firmware file (identify --json)",
              &schema(one, r#""path""#, false)),
        tool("doctor", "doctor scan --json: the doctor/1 envelope for a firmware directory",
              &schema(one, r#""path""#, true)),
        tool("audit", "audit --json: the doctor/1 envelope for partition images",
              &schema(&format!("{one},{many}"), "", true)),
        tool("diff", "diff --json: the doctor/1 envelope comparing two firmware builds file by file; findings are what the new build made worse",
              &schema(r#""old":{"type":"string","description":"Old image or directory of images"},"new":{"type":"string","description":"New image or directory of images"},"only":{"type":"array","items":{"type":"string","enum":["added","removed","modified","metadata"]},"description":"List only these file changes under data"}"#, r#""old","new""#, true)),
        tool("ls", "ls --json: list a directory (or show one file) inside an ext2/3/4, erofs or f2fs image, without extracting it; a JSON array of entries",
              &schema(&format!(r#"{image},"path":{{"type":"string","description":"Path inside the image (default /)"}}"#), r#""image""#, false)),
        tool("cat", "cat: the bytes of one regular file inside an ext2/3/4, erofs or f2fs image, as text; capped at 1 MiB",
              &schema(&format!(r#"{image},"path":{{"type":"string","description":"Path of the file inside the image"}}"#), r#""image","path""#, false)),
        tool("info", "info --json: the metadata of a firmware file or OTA",
              &schema(one, r#""path""#, false)),
        tool("vbmeta", "vbmeta --json: the header, key, signature, descriptors and hashes of an AVB vbmeta image (or a partition with an AVB footer)",
              &schema(one, r#""path""#, false)),
        tool("ramdisk", "ramdisk --json: the files listed in a boot image's ramdisk and its ADB properties (listed only, never extracted)",
              &schema(one, r#""path""#, false)),
        tool("files", "files --json: the files of an ext2/3/4, erofs or f2fs image with SELinux labels (listed only, never extracted)",
              &schema(image, r#""image""#, false)),
        tool("unpack", "unpack --json: the header of a boot or vendor_boot image (sections listed, never written)",
              &schema(one, r#""path""#, false)),
    ] })
}

/// Browsing tools: read-only (no output option is offered, so the CLI never writes) and bounded.
const BROWSE: [&str; 7] = ["ls", "cat", "info", "vbmeta", "ramdisk", "files", "unpack"];

/// The largest stdout a browsing tool returns; more is an error, never a truncated answer.
const BROWSE_MAX_BYTES: usize = 1 << 20;

/// The CLI arguments for a browsing tool call. `cat` prints raw bytes (it has no `--json`).
fn browse_args(name: &str, args: &Value) -> Result<Vec<String>> {
    let text = |k: &str| {
        args.get(k)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let need = |k: &str| {
        text(k)
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("missing required argument \"{k}\""))
    };
    let mut argv: Vec<String> = match name {
        "ls" => vec!["ls".into(), "--json".into(), "--".into(), need("image")?],
        "cat" => vec!["cat".into(), "--".into(), need("image")?, need("path")?],
        "files" => vec!["files".into(), "--json".into(), "--".into(), need("image")?],
        "info" | "vbmeta" | "ramdisk" | "unpack" => {
            vec![name.into(), "--json".into(), "--".into(), need("path")?]
        }
        other => anyhow::bail!("unknown tool {other}"),
    };
    if name == "ls" {
        argv.extend(text("path").map(String::from));
    }
    Ok(argv)
}

fn tool(name: &str, description: &str, schema: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": serde_json::from_str::<Value>(schema).expect("static schema parses"),
    })
}

/// The CLI arguments for a tool call (everything after the binary name).
fn cli_args(name: &str, args: &Value) -> Result<Vec<String>> {
    if BROWSE.contains(&name) {
        return browse_args(name, args);
    }
    let text = |k: &str| args.get(k).and_then(Value::as_str);
    let mut argv: Vec<String> = match name {
        "identify" => vec!["identify".into()],
        "doctor" => vec!["doctor".into(), "scan".into()],
        "audit" => vec!["audit".into()],
        "diff" => vec!["diff".into()],
        other => anyhow::bail!("unknown tool {other}"),
    };
    argv.push("--json".into());
    for (key, flag) in [
        ("baseline", "baseline"),
        ("fail_on", "fail-on"),
        ("sarif", "sarif"),
    ] {
        if let Some(v) = text(key) {
            if name == "identify" {
                anyhow::bail!("identify takes only \"path\"");
            }
            argv.push(format!("--{flag}={v}"));
        }
    }
    if name == "diff" {
        let (Some(old), Some(new)) = (text("old"), text("new")) else {
            anyhow::bail!("missing required arguments \"old\" and \"new\"");
        };
        if let Some(a) = args.get("only").and_then(Value::as_array) {
            let v: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            argv.push(format!("--only={}", v.join(",")));
        }
        argv.extend(["--".into(), old.into(), new.into()]);
        return Ok(argv);
    }
    let mut paths: Vec<String> = text("path").map(String::from).into_iter().collect();
    if let Some(a) = args.get("paths").and_then(Value::as_array) {
        paths.extend(a.iter().filter_map(Value::as_str).map(String::from));
    }
    if paths.is_empty() || (name != "audit" && paths.len() > 1) {
        anyhow::bail!("missing required argument \"path\"");
    }
    argv.push("--".into());
    argv.extend(paths);
    Ok(argv)
}

/// The tools in kit shape. Each runs the CLI itself with `--json`, so the reply is byte-identical
/// to the CLI's stdout. Exit 0, 1 and 3 are results (the envelope says which); anything else is
/// an error.
pub fn tools() -> Vec<McpTool> {
    tool_list()["tools"]
        .as_array()
        .expect("tool_list has tools")
        .iter()
        .map(|t| {
            let name = t["name"].as_str().expect("tool name").to_string();
            McpTool {
                name: name.clone(),
                description: t["description"].as_str().unwrap_or_default().to_string(),
                schema: t["inputSchema"].clone(),
                call: Box::new(move |args| {
                    let mut argv = vec!["--no-color".to_string()];
                    argv.extend(cli_args(&name, args).map_err(|e| format!("{e:#}"))?);
                    let opts = if BROWSE.contains(&name.as_str()) {
                        ExecOpts {
                            // exit 1 is a result here too (vbmeta: signature or hash mismatch)
                            ok_codes: vec![0, 1, 3],
                            timeout: Some(Duration::from_secs(60)),
                            max_bytes: BROWSE_MAX_BYTES,
                        }
                    } else {
                        ExecOpts {
                            ok_codes: vec![0, 1, 3],
                            // the CLI's output was never capped or timed
                            max_bytes: usize::MAX / 2,
                            ..Default::default()
                        }
                    };
                    exec_self_fmt(&argv, &opts, Some("{stderr} (exit {code})"))
                }),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::AndroidDoctor;
    use doctor_kit::mcp::handle;

    fn doctor() -> AndroidDoctor {
        AndroidDoctor::default()
    }

    fn req(method: &str, id: Option<i64>) -> Value {
        match id {
            Some(i) => json!({ "jsonrpc": "2.0", "id": i, "method": method, "params": {} }),
            None => json!({ "jsonrpc": "2.0", "method": method, "params": {} }),
        }
    }

    #[test]
    fn initialize_advertises_tool_capability() {
        let r = handle(&doctor(), &req("initialize", Some(1))).unwrap();
        assert_eq!(r["id"], 1);
        assert_eq!(r["jsonrpc"], "2.0");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert_eq!(r["result"]["serverInfo"]["name"], "android-doctor");
    }

    #[test]
    fn tools_list_returns_parseable_schemas() {
        let r = handle(&doctor(), &req("tools/list", Some(2))).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        for t in tools {
            assert!(t["name"].is_string());
            assert!(t["description"].is_string());
            assert!(t["inputSchema"]["type"] == "object");
        }
    }

    #[test]
    fn a_notification_gets_no_response() {
        // No id means notification: answering would be wrong.
        assert!(handle(&doctor(), &req("notifications/initialized", None)).is_none());
    }

    #[test]
    fn an_unknown_method_is_an_error_not_silence() {
        let r = handle(&doctor(), &req("does/not/exist", Some(3))).unwrap();
        assert_eq!(r["error"]["code"], -32601);
        assert!(r["result"].is_null());
    }

    #[test]
    fn calling_a_tool_without_its_argument_reports_an_error_not_a_crash() {
        let call = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "identify", "arguments": {} }
        });
        let r = handle(&doctor(), &call).unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("path")
        );
    }

    #[test]
    fn browse_tools_are_listed_and_read_only() {
        let r = handle(&doctor(), &req("tools/list", Some(6))).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        for name in ["ls", "cat", "info", "vbmeta", "ramdisk", "files", "unpack"] {
            let t = tools
                .iter()
                .find(|t| t["name"] == name)
                .unwrap_or_else(|| panic!("tool {name} missing"));
            // read-only: no option can ask for an output directory or a force overwrite
            let props = t["inputSchema"]["properties"].as_object().unwrap();
            assert!(
                !props.contains_key("output") && !props.contains_key("force"),
                "{name}"
            );
        }
    }

    #[test]
    fn browse_args_map_to_the_cli() {
        let a = json!({ "image": "sys.img", "path": "/etc" });
        assert_eq!(
            cli_args("ls", &a).unwrap(),
            ["ls", "--json", "--", "sys.img", "/etc"]
        );
        let a = json!({ "image": "sys.img", "path": "/etc/hosts" });
        assert_eq!(
            cli_args("cat", &a).unwrap(),
            ["cat", "--", "sys.img", "/etc/hosts"]
        );
        let a = json!({ "path": "boot.img" });
        assert_eq!(
            cli_args("unpack", &a).unwrap(),
            ["unpack", "--json", "--", "boot.img"]
        );
        assert!(cli_args("cat", &json!({ "image": "sys.img" })).is_err());
    }

    #[test]
    fn an_unknown_tool_is_an_error_result() {
        let call = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "nope", "arguments": { "path": "/tmp" } }
        });
        let r = handle(&doctor(), &call).unwrap();
        assert_eq!(r["result"]["isError"], true);
    }
}
