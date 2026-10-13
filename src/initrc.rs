//! init.rc grammar parser (AOSP system/core/init/README.md).
//
// Consumers (findings for caps/sockets/imports) land in a follow-up, so the
// public surface is currently unused outside of the test module.

#![allow(dead_code)] // consumers (findings for caps/sockets/imports) land in a follow-up

use std::mem;

#[derive(Debug, Default, PartialEq)]
pub struct InitRc {
    pub imports: Vec<String>,
    pub actions: Vec<Action>,
    pub services: Vec<Service>,
}

#[derive(Debug, PartialEq)]
pub struct Action {
    pub triggers: Vec<String>,
    pub commands: Vec<String>,
}

#[derive(Debug, Default, PartialEq)]
pub struct Service {
    pub name: String,
    pub path: String,
    pub args: Vec<String>,
    pub classes: Vec<String>,
    pub groups: Vec<String>,
    pub capabilities: Vec<String>,
    pub sockets: Vec<Socket>,
    pub user: Option<String>,
    pub seclabel: Option<String>,
    pub disabled: bool,
    pub oneshot: bool,
    pub critical: bool,
}

#[derive(Debug, PartialEq)]
pub struct Socket {
    pub name: String,
    pub kind: String,
    pub perm: String,
    pub user: Option<String>,
    pub group: Option<String>,
}

/// Join trailing `\` line continuations (mirrors the `parse_services` line-joiner
/// in audit.rs), dropping comment lines. Returns `(indented, line)` pairs so the
/// caller can still tell column-0 section headers from indented option/command lines.
/// The indentation flag reflects the leading whitespace of the *first* physical line
/// that composes the logical line (continuations inherit the first line's indent).
fn join_lines(text: &str) -> Vec<(bool, String)> {
    let mut out: Vec<(bool, String)> = Vec::new();
    let mut carry = String::new();
    let mut first_indented: Option<bool> = None;
    for raw in text.lines() {
        let is_comment = raw.trim_start().starts_with('#');
        if is_comment {
            continue;
        }
        let first = raw.chars().next();
        let line_indented = matches!(first, Some(c) if c.is_whitespace());
        if first_indented.is_none() {
            first_indented = Some(line_indented);
        }
        let trimmed = raw.trim_end();
        if trimmed.ends_with('\\') {
            let head = trimmed.strip_suffix('\\').unwrap_or(trimmed);
            carry.push_str(head);
            carry.push(' ');
            continue;
        }
        carry.push_str(trimmed);
        out.push((first_indented.unwrap_or(false), mem::take(&mut carry)));
        first_indented = None;
    }
    // A dangling continuation with no following line still produces a logical line.
    if !carry.is_empty() {
        out.push((first_indented.unwrap_or(false), carry));
    }
    out
}

/// Split a logical line into words, honouring double-quoted spans (quotes
/// removed). A quoted word becomes a single token.
fn split_words(line: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
            }
            c if in_quote => cur.push(c),
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    words.push(mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

pub fn parse(text: &str) -> InitRc {
    let mut rc = InitRc::default();
    let mut current: Option<Section> = None;
    for (indented, logical) in join_lines(text) {
        let trimmed = logical.trim();
        if trimmed.is_empty() {
            continue;
        }
        let words = split_words(trimmed);
        if words.is_empty() {
            continue;
        }
        // Indented lines belong to the open section; column-0 lines open/close sections.
        if !indented {
            match words[0].as_str() {
                "import" => {
                    if words.len() > 1 {
                        rc.imports.push(words[1].clone());
                    }
                    current = None;
                }
                "on" => {
                    let triggers = words[1..]
                        .split(|w: &String| w == "&&")
                        .map(|part| part.join(" "))
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>();
                    if triggers.is_empty() {
                        current = None;
                    } else {
                        let idx = rc.actions.len();
                        rc.actions.push(Action {
                            triggers,
                            commands: Vec::new(),
                        });
                        current = Some(Section::Action(idx));
                    }
                }
                "service" => {
                    if words.len() < 3 {
                        current = None;
                    } else {
                        let idx = rc.services.len();
                        let name = words[1].clone();
                        let path = words[2].clone();
                        let args = words[3..].to_vec();
                        rc.services.push(Service {
                            name,
                            path,
                            args,
                            ..Default::default()
                        });
                        current = Some(Section::Service(idx));
                    }
                }
                _ => {
                    current = None;
                }
            }
        } else if let Some(section) = &current {
            match section {
                Section::Action(idx) => {
                    rc.actions[*idx].commands.push(trimmed.to_string());
                }
                Section::Service(idx) => {
                    let svc = &mut rc.services[*idx];
                    apply_option(svc, &words);
                }
            }
        }
        // An option/command line with no open section is ignored.
    }
    rc
}

#[derive(Clone, Copy)]
enum Section {
    Action(usize),
    Service(usize),
}

fn apply_option(svc: &mut Service, words: &[String]) {
    if words.is_empty() {
        return;
    }
    match words[0].as_str() {
        "class" => svc.classes = words[1..].to_vec(),
        "user" => svc.user = words.get(1).cloned(),
        "group" => svc.groups = words[1..].to_vec(),
        "capabilities" => svc.capabilities = words[1..].to_vec(),
        "socket" => {
            if words.len() >= 4 {
                svc.sockets.push(Socket {
                    name: words[1].clone(),
                    kind: words[2].clone(),
                    perm: words[3].clone(),
                    user: words.get(4).cloned(),
                    group: words.get(5).cloned(),
                });
            }
        }
        "seclabel" => svc.seclabel = words.get(1).cloned(),
        "disabled" => svc.disabled = true,
        "oneshot" => svc.oneshot = true,
        "critical" => svc.critical = true,
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Syntax per AOSP system/core/init/README.md: `import`, `on <trigger>[ && <trigger>]` actions,
    // `service <name> <path> [args]` with indented options; `\` continues a line, "..." quotes a word.
    const RC: &str = "\
# comment
import /init.usb.rc
import /vendor/etc/init/hw/init.${ro.hardware}.rc

on early-init
    write /proc/sys/kernel/sysrq 0
    mkdir /dev/cpuset 0750 system system

on boot && property:sys.boot_completed=1
    setprop sys.ready 1

on property:persist.sys.usb.config=adb
    start adbd

service adbd /system/bin/adbd --root_seclabel=u:r:su:s0 \\
    --msg \"hello world\"
    class core main
    user shell
    group shell log readproc
    capabilities NET_BIND_SERVICE SYS_NICE
    socket adbd stream 660 system system
    socket extra dgram 0600
    seclabel u:r:adbd:s0
    disabled
    oneshot
    critical

service bare /vendor/bin/bare
";

    #[test]
    fn imports_actions_and_services_are_parsed() {
        let rc = parse(RC);
        assert_eq!(
            rc.imports,
            ["/init.usb.rc", "/vendor/etc/init/hw/init.${ro.hardware}.rc"]
        );

        assert_eq!(rc.actions.len(), 3);
        assert_eq!(rc.actions[0].triggers, ["early-init"]);
        assert_eq!(
            rc.actions[0].commands,
            [
                "write /proc/sys/kernel/sysrq 0",
                "mkdir /dev/cpuset 0750 system system"
            ]
        );
        assert_eq!(
            rc.actions[1].triggers,
            ["boot", "property:sys.boot_completed=1"]
        );
        assert_eq!(rc.actions[1].commands, ["setprop sys.ready 1"]);
        assert_eq!(
            rc.actions[2].triggers,
            ["property:persist.sys.usb.config=adb"]
        );
        assert_eq!(rc.actions[2].commands, ["start adbd"]);

        assert_eq!(rc.services.len(), 2);
        let a = &rc.services[0];
        assert_eq!(
            (a.name.as_str(), a.path.as_str()),
            ("adbd", "/system/bin/adbd")
        );
        assert_eq!(
            a.args,
            ["--root_seclabel=u:r:su:s0", "--msg", "hello world"]
        );
        assert_eq!(a.classes, ["core", "main"]);
        assert_eq!(a.user.as_deref(), Some("shell"));
        assert_eq!(a.groups, ["shell", "log", "readproc"]);
        assert_eq!(a.capabilities, ["NET_BIND_SERVICE", "SYS_NICE"]);
        assert_eq!(
            a.sockets,
            [
                Socket {
                    name: "adbd".into(),
                    kind: "stream".into(),
                    perm: "660".into(),
                    user: Some("system".into()),
                    group: Some("system".into()),
                },
                Socket {
                    name: "extra".into(),
                    kind: "dgram".into(),
                    perm: "0600".into(),
                    user: None,
                    group: None,
                },
            ]
        );
        assert_eq!(a.seclabel.as_deref(), Some("u:r:adbd:s0"));
        assert!(a.disabled && a.oneshot && a.critical);

        // a service with no options keeps every default; options of `adbd` do not leak into it
        let b = &rc.services[1];
        assert_eq!(
            (b.name.as_str(), b.path.as_str()),
            ("bare", "/vendor/bin/bare")
        );
        assert!(b.args.is_empty() && b.classes.is_empty() && b.groups.is_empty());
        assert!(b.capabilities.is_empty() && b.sockets.is_empty());
        assert!(b.user.is_none() && b.seclabel.is_none());
        assert!(!b.disabled && !b.oneshot && !b.critical);
    }

    #[test]
    fn malformed_input_is_skipped_without_panicking() {
        assert_eq!(parse(""), InitRc::default());
        // a service needs a name and a path; an `on` needs a trigger
        assert!(parse("service\nservice x\n").services.is_empty());
        let rc = parse("on\n    start x\nservice y /bin/y\n    user root\n");
        assert!(
            rc.actions.is_empty(),
            "the commands under a trigger-less `on` attach to nothing"
        );
        assert_eq!(rc.services.len(), 1);
        // an option line before any section belongs to nothing
        assert_eq!(parse("    user root\n"), InitRc::default());
    }
}
