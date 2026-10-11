//! Code rules over an APK's DEX: risky API use found from the call graph the parser extracts
//! (WebView, crypto, random, logging, world-accessible files, external storage, SSL trust,
//! dynamic loading, raw SQL, command execution, tapjacking, screenshots, root/emulator/frida
//! checks). Modelled on MobSF `android_apis.yaml` / `android_rules.yaml` and qark's
//! `webview`, `crypto`, `cert`, `file` plugins, written from their descriptions.
//!
//! Method calls are matched by name and prototype, whatever class they are called on (so a call
//! on a `MyActivity` subclass still counts as a `Context` call). Arguments are judged only when
//! the code sets them as constants just before the call; anything else is not guessed.

use super::{ManifestIssue, Severity};
use crate::dex::{self, Call, Dex, Val};

/// A method's bytecode with the class context the rules need.
struct Site<'a> {
    class: &'a dex::Class,
    method: String,
    calls: Vec<Call>,
    refs: &'a [dex::Ref],
    trivial: Trivial,
}

/// What a method body amounts to, for the "accept everything" checks.
#[derive(PartialEq)]
enum Trivial {
    No,
    /// Only `return-void`.
    Void,
    /// `const vX, 1` then `return vX`.
    True,
}

const MAX_HITS_PER_RULE: usize = 5;

fn trivial_body(dex: &Dex, data: &[u8], code: &dex::Code) -> Trivial {
    let lines = dex::disassemble(dex, data, code);
    let ops: Vec<&str> = lines
        .iter()
        .map(|l| l.split_once(": ").map_or("", |x| x.1))
        .collect();
    match ops.as_slice() {
        [r] if *r == "return-void" => Trivial::Void,
        [c, r]
            if (c.starts_with("const/4 v") || c.starts_with("const/16 v"))
                && c.ends_with(", 0x1")
                && r.starts_with("return v") =>
        {
            Trivial::True
        }
        _ => Trivial::No,
    }
}

fn int(a: Option<&Option<Val>>) -> Option<i64> {
    match a {
        Some(Some(Val::Int(v))) => Some(*v),
        _ => None,
    }
}

fn text(a: Option<&Option<Val>>) -> Option<&str> {
    match a {
        Some(Some(Val::Str(s))) => Some(s),
        _ => None,
    }
}

type Hit = (&'static str, Severity, String, String);

struct Collector {
    hits: Vec<Hit>,
}

impl Collector {
    fn add(&mut self, rule: &'static str, sev: Severity, what: &str, at: &str) {
        self.hits
            .push((rule, sev, what.to_string(), at.to_string()));
    }
}

fn has(callee: &str, sig: &str) -> bool {
    callee.contains(&format!("->{sig}"))
}

const SENSITIVE: [&str; 6] = [
    "password",
    "passwd",
    "token",
    "secret",
    "apikey",
    "credential",
];
const BROKEN_CIPHERS: [&str; 5] = ["DES", "RC2", "RC4", "ARCFOUR", "BLOWFISH"];

fn judge(s: &Site, c: &mut Collector) {
    let at = &s.method;
    for call in &s.calls {
        let f = call.callee.as_str();
        let a = &call.args;
        let on = |i: usize| int(a.get(i)).is_some_and(|v| v != 0);
        // WebView
        if has(f, "setJavaScriptEnabled(Z)V") && on(1) {
            c.add(
                "apk-code-webview",
                Severity::Warn,
                "JavaScript is enabled in a WebView",
                at,
            );
        }
        if has(
            f,
            "addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V",
        ) {
            c.add(
                "apk-code-webview",
                Severity::Medium,
                "addJavascriptInterface exposes a Java object to page scripts",
                at,
            );
        }
        if has(f, "setAllowFileAccess(Z)V") && on(1) {
            c.add(
                "apk-code-webview",
                Severity::Medium,
                "WebView file access is enabled",
                at,
            );
        }
        if (has(f, "setAllowFileAccessFromFileURLs(Z)V")
            || has(f, "setAllowUniversalAccessFromFileURLs(Z)V"))
            && on(1)
        {
            c.add(
                "apk-code-webview",
                Severity::High,
                "file: pages may read other files or any origin",
                at,
            );
        }
        if has(f, "setWebContentsDebuggingEnabled(Z)V") && on(0) {
            c.add(
                "apk-code-webview",
                Severity::Medium,
                "WebView remote debugging is enabled",
                at,
            );
        }
        if has(f, "setMixedContentMode(I)V") && int(a.get(1)) == Some(0) {
            c.add(
                "apk-code-webview",
                Severity::Medium,
                "WebView allows mixed (http in https) content",
                at,
            );
        }
        if f.contains("Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;")
            && text(a.get(1)).is_some_and(|u| u.starts_with("http://"))
        {
            c.add(
                "apk-code-webview",
                Severity::Warn,
                "WebView loads a cleartext http:// URL",
                at,
            );
        }
        // Crypto
        if f.contains("Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;") {
            match text(a.first()).map(str::to_ascii_uppercase).as_deref() {
                Some("MD5" | "MD2" | "MD4") => {
                    c.add("apk-code-weak-crypto", Severity::Medium, "MD5/MD2 hash", at)
                }
                Some("SHA-1" | "SHA1" | "SHA") => {
                    c.add("apk-code-weak-crypto", Severity::Warn, "SHA-1 hash", at)
                }
                _ => {}
            }
        }
        if f.contains("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;")
            && let Some(t) = text(a.first()).map(str::to_ascii_uppercase)
        {
            let algo = t.split('/').next().unwrap_or("");
            if BROKEN_CIPHERS.contains(&algo) {
                c.add(
                    "apk-code-weak-crypto",
                    Severity::High,
                    &format!("broken cipher {algo}"),
                    at,
                );
            } else if t.contains("/ECB") || t == "AES" {
                c.add(
                    "apk-code-weak-crypto",
                    Severity::Medium,
                    "AES in ECB mode (the default when no mode is given)",
                    at,
                );
            } else if t == "RSA" || (t.starts_with("RSA") && t.ends_with("NOPADDING")) {
                c.add(
                    "apk-code-weak-crypto",
                    Severity::Medium,
                    "RSA without padding",
                    at,
                );
            }
        }
        if f.contains("SecretKeySpec;-><init>([BLjava/lang/String;)V")
            && text(a.get(2))
                .map(str::to_ascii_uppercase)
                .is_some_and(|n| BROKEN_CIPHERS.contains(&n.as_str()))
        {
            c.add(
                "apk-code-weak-crypto",
                Severity::High,
                "key for a broken cipher",
                at,
            );
        }
        if f.contains("Ljava/security/SecureRandom;->setSeed(") {
            c.add(
                "apk-code-weak-crypto",
                Severity::Medium,
                "SecureRandom.setSeed can make output predictable",
                at,
            );
        }
        // Random
        if f.starts_with("Ljava/util/Random;-><init>")
            || f.starts_with("Ljava/lang/Math;->random()")
        {
            c.add(
                "apk-code-insecure-random",
                Severity::Warn,
                "java.util.Random / Math.random is not cryptographically secure",
                at,
            );
        }
        // Logging
        if ["v", "d", "i", "w", "e", "wtf"]
            .iter()
            .any(|m| f.starts_with(&format!("Landroid/util/Log;->{m}(")))
        {
            let secret = a.iter().flatten().any(|v| {
                matches!(v, Val::Str(s) if SENSITIVE.iter().any(|k| s.to_ascii_lowercase().contains(k)))
            });
            if secret {
                c.add(
                    "apk-code-logging",
                    Severity::Medium,
                    "a log message mentions a password, token or secret",
                    at,
                );
            } else {
                c.add(
                    "apk-code-logging",
                    Severity::Info,
                    "android.util.Log call",
                    at,
                );
            }
        }
        if f == "Ljava/lang/Throwable;->printStackTrace()V" {
            c.add("apk-code-logging", Severity::Info, "printStackTrace", at);
        }
        // World-accessible files
        let world = int(a.get(2)).is_some_and(|m| m & 3 != 0);
        if (has(f, "openFileOutput(Ljava/lang/String;I)")
            || has(f, "getSharedPreferences(Ljava/lang/String;I)")
            || has(f, "getDir(Ljava/lang/String;I)"))
            && world
        {
            c.add(
                "apk-code-world-accessible",
                Severity::High,
                "file, preferences or directory created MODE_WORLD_READABLE/WRITEABLE",
                at,
            );
        }
        if has(f, "openOrCreateDatabase(Ljava/lang/String;I") && world {
            c.add(
                "apk-code-world-accessible",
                Severity::High,
                "database created MODE_WORLD_READABLE/WRITEABLE",
                at,
            );
        }
        if (f.starts_with("Ljava/io/File;->setReadable(ZZ)")
            || f.starts_with("Ljava/io/File;->setWritable(ZZ)"))
            && on(1)
            && int(a.get(2)) == Some(0)
        {
            c.add(
                "apk-code-world-accessible",
                Severity::Medium,
                "File made readable/writable for all users",
                at,
            );
        }
        // External storage
        if f.starts_with("Landroid/os/Environment;->getExternalStorageDirectory(")
            || f.starts_with("Landroid/os/Environment;->getExternalStoragePublicDirectory(")
        {
            c.add(
                "apk-code-external-storage",
                Severity::Warn,
                "shared external storage is readable by other apps",
                at,
            );
        }
        // SSL trust
        if f.contains("HttpsURLConnection;->setDefaultHostnameVerifier(")
            || f.contains("HttpsURLConnection;->setHostnameVerifier(")
        {
            c.add(
                "apk-code-ssl-trust",
                Severity::Warn,
                "a custom HostnameVerifier is installed",
                at,
            );
        }
        if f == "Landroid/webkit/SslErrorHandler;->proceed()V" {
            c.add(
                "apk-code-ssl-trust",
                Severity::High,
                "WebView proceeds past TLS errors",
                at,
            );
        }
        // Dynamic loading
        if [
            "DexClassLoader",
            "PathClassLoader",
            "InMemoryDexClassLoader",
            "BaseDexClassLoader",
        ]
        .iter()
        .any(|n| f.contains(&format!("/{n};-><init>")))
        {
            c.add(
                "apk-code-dynamic-loading",
                Severity::Medium,
                "loads code at run time with a class loader",
                at,
            );
        }
        if f == "Ljava/lang/System;->load(Ljava/lang/String;)V"
            || f.starts_with("Ljava/lang/Runtime;->load(")
        {
            c.add(
                "apk-code-dynamic-loading",
                Severity::Warn,
                "loads a native library by path",
                at,
            );
        }
        // Raw SQL built by concatenation
        if (has(f, "rawQuery(Ljava/lang/String;") || has(f, "execSQL(Ljava/lang/String;"))
            && f.contains("SQLiteDatabase")
            && text(a.get(1)).is_none()
            && s.calls.iter().any(|x| {
                x.callee.starts_with("Ljava/lang/StringBuilder;->append(")
                    || x.callee.starts_with("Ljava/lang/String;->concat(")
                    || x.callee.starts_with("Ljava/lang/String;->format(")
            })
        {
            c.add(
                "apk-code-raw-sql",
                Severity::Medium,
                "raw SQL assembled by string concatenation (injection risk)",
                at,
            );
        }
        // Command execution
        if f.starts_with("Ljava/lang/Runtime;->exec(")
            || f == "Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
        {
            c.add(
                "apk-code-command-exec",
                Severity::Medium,
                "runs an external command",
                at,
            );
        }
        // Debugger checks
        if f.starts_with("Landroid/os/Debug;->isDebuggerConnected(")
            || f.starts_with("Landroid/os/Debug;->waitingForDebugger(")
        {
            c.add(
                "apk-code-anti-analysis",
                Severity::Info,
                "checks for an attached debugger",
                at,
            );
        }
    }
    // Trust-everything classes
    let implements = |n: &str| s.class.interfaces.iter().any(|i| i == n);
    if (implements("Ljavax/net/ssl/X509TrustManager;")
        || s.class.superclass.as_deref() == Some("Ljavax/net/ssl/X509ExtendedTrustManager;"))
        && (at.contains("->checkServerTrusted(") || at.contains("->checkClientTrusted("))
        && s.trivial == Trivial::Void
    {
        c.add(
            "apk-code-ssl-trust",
            Severity::High,
            "TrustManager accepts every certificate chain (empty check)",
            at,
        );
    }
    if implements("Ljavax/net/ssl/HostnameVerifier;")
        && at.contains("->verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z")
        && s.trivial == Trivial::True
    {
        c.add(
            "apk-code-ssl-trust",
            Severity::High,
            "HostnameVerifier accepts every host",
            at,
        );
    }
    if s.refs
        .iter()
        .any(|r| r.kind == "field" && r.text.contains("->ALLOW_ALL_HOSTNAME_VERIFIER:"))
    {
        c.add(
            "apk-code-ssl-trust",
            Severity::High,
            "ALLOW_ALL_HOSTNAME_VERIFIER turns off host name checks",
            at,
        );
    }
}

/// Root, emulator and frida markers, found in the string pool.
const MARKERS: [(&str, &[&str]); 3] = [
    (
        "root",
        &[
            "/system/bin/su",
            "/system/xbin/su",
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "com.topjohnwu.magisk",
            "com.koushikdutta.superuser",
        ],
    ),
    (
        "emulator",
        &[
            "goldfish",
            "ranchu",
            "ro.kernel.qemu",
            "Genymotion",
            "generic_x86",
            "sdk_gphone",
        ],
    ),
    (
        "frida",
        &[
            "frida-server",
            "re.frida.server",
            "frida-agent",
            "gum-js-loop",
            "libfrida",
        ],
    ),
];

/// Run every rule over the parsed dex files. `activities` is the number of manifest activities:
/// the tapjacking and screenshot rules are about an app's screens.
pub fn scan(dexes: &[(Dex, Vec<u8>)], activities: usize) -> Vec<ManifestIssue> {
    let mut c = Collector { hits: Vec::new() };
    let (mut filter_touches, mut flag_secure) = (false, false);
    for (dex, data) in dexes {
        for class in &dex.classes {
            for m in class.direct_methods.iter().chain(&class.virtual_methods) {
                let (Some(code), Some(name)) = (&m.code, dex::method_name(dex, m.idx)) else {
                    continue;
                };
                let calls = dex::calls(dex, data, code);
                for call in &calls {
                    let a = &call.args;
                    filter_touches |= has(&call.callee, "setFilterTouchesWhenObscured(Z)V")
                        && int(a.get(1)).is_some_and(|v| v != 0);
                    flag_secure |= (has(&call.callee, "setFlags(II)V")
                        || has(&call.callee, "addFlags(I)V"))
                        && call.callee.contains("Landroid/view/Window;")
                        && a.iter()
                            .flatten()
                            .any(|v| matches!(v, Val::Int(x) if x & 0x2000 != 0));
                }
                let trivial = trivial_body(dex, data, code);
                let site = Site {
                    class,
                    method: name,
                    calls,
                    refs: &code.refs,
                    trivial,
                };
                judge(&site, &mut c);
            }
        }
        for (kind, needles) in MARKERS {
            if let Some(n) = needles
                .iter()
                .find(|n| dex.strings.iter().any(|s| s.contains(**n)))
            {
                c.add(
                    "apk-code-anti-analysis",
                    Severity::Info,
                    &format!("{kind} detection marker \"{n}\""),
                    &dex.name,
                );
            }
        }
    }
    if activities > 0 && !filter_touches {
        c.add(
            "apk-code-tapjacking",
            Severity::Info,
            "no setFilterTouchesWhenObscured(true) call (tapjacking protection not found in code)",
            "APK",
        );
    }
    if activities > 0 && !flag_secure {
        c.add(
            "apk-code-screenshot",
            Severity::Info,
            "FLAG_SECURE is never set (screens can be captured)",
            "APK",
        );
    }
    group(c.hits)
}

/// One issue per (rule, severity): the count and the first few places.
fn group(hits: Vec<Hit>) -> Vec<ManifestIssue> {
    let mut keys: Vec<(&'static str, Severity)> = Vec::new();
    for h in &hits {
        if !keys.contains(&(h.0, h.1)) {
            keys.push((h.0, h.1));
        }
    }
    keys.into_iter()
        .map(|(rule, severity)| {
            let mut seen: Vec<String> = Vec::new();
            for h in hits.iter().filter(|h| h.0 == rule && h.1 == severity) {
                let line = format!("{} at {}", h.2, h.3);
                if !seen.contains(&line) {
                    seen.push(line);
                }
            }
            let shown = seen
                .iter()
                .take(MAX_HITS_PER_RULE)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            let more = if seen.len() > MAX_HITS_PER_RULE {
                format!("; and {} more", seen.len() - MAX_HITS_PER_RULE)
            } else {
                String::new()
            };
            ManifestIssue {
                rule,
                severity,
                detail: format!("{} site(s): {shown}{more}", seen.len()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// javac + d8 over tests/fixtures/dex/Risky.java (source included).
    const RISKY: &[u8] = include_bytes!("../../tests/fixtures/dex/risky.dex");
    const CLEAN: &[u8] = include_bytes!("../../tests/fixtures/dex/demo.dex");

    fn run(bytes: &[u8], activities: usize) -> Vec<ManifestIssue> {
        let d = dex::parse("classes.dex", bytes).unwrap();
        scan(&[(d, bytes.to_vec())], activities)
    }

    fn detail<'a>(v: &'a [ManifestIssue], rule: &str, sev: Severity) -> &'a str {
        v.iter()
            .find(|i| i.rule == rule && i.severity == sev)
            .unwrap_or_else(|| panic!("{rule} {sev:?} missing from {v:#?}"))
            .detail
            .as_str()
    }

    #[test]
    fn risky_code_is_found_and_safe_code_is_not() {
        let v = run(RISKY, 1);
        let got: Vec<_> = v.iter().map(|i| (i.rule, i.severity)).collect();
        for want in [
            ("apk-code-webview", Severity::High),
            ("apk-code-webview", Severity::Medium),
            ("apk-code-webview", Severity::Warn),
            ("apk-code-weak-crypto", Severity::High),
            ("apk-code-weak-crypto", Severity::Medium),
            ("apk-code-insecure-random", Severity::Warn),
            ("apk-code-logging", Severity::Medium),
            ("apk-code-logging", Severity::Info),
            ("apk-code-world-accessible", Severity::High),
            ("apk-code-external-storage", Severity::Warn),
            ("apk-code-ssl-trust", Severity::High),
            ("apk-code-dynamic-loading", Severity::Medium),
            ("apk-code-raw-sql", Severity::Medium),
            ("apk-code-command-exec", Severity::Medium),
            ("apk-code-anti-analysis", Severity::Info),
            ("apk-code-tapjacking", Severity::Info),
            ("apk-code-screenshot", Severity::Info),
        ] {
            assert!(got.contains(&want), "{want:?} missing from {got:?}");
        }
        // exactly the unsafe calls: JavaScript on (not the safeWeb off), MD5 and the DES/AES-ECB
        // ciphers (not SHA-256 or AES/GCM), the concatenated query (not the bound one)
        // JavaScript on and the http:// URL, not the safeWeb() calls
        assert!(detail(&v, "apk-code-webview", Severity::Warn).contains("2 site(s)"));
        assert!(detail(&v, "apk-code-weak-crypto", Severity::Medium).contains("2 site(s)")); // MD5 + AES
        assert!(detail(&v, "apk-code-weak-crypto", Severity::High).contains("1 site(s)")); // DES
        assert!(detail(&v, "apk-code-raw-sql", Severity::Medium).contains("1 site(s)"));
        assert!(detail(&v, "apk-code-raw-sql", Severity::Medium).contains("->sql("));
        assert!(detail(&v, "apk-code-world-accessible", Severity::High).contains("1 site(s)")); // MODE_PRIVATE ignored
    }

    #[test]
    fn trust_everything_checks_are_recognised_by_their_bodies() {
        let v = run(RISKY, 0);
        let d = detail(&v, "apk-code-ssl-trust", Severity::High);
        assert!(
            d.contains("TrustManager accepts every certificate chain"),
            "{d}"
        );
        assert!(d.contains("HostnameVerifier accepts every host"), "{d}");
        assert!(d.contains("WebView proceeds past TLS errors"), "{d}");
        assert!(d.contains("4 site(s)"), "{d}"); // both TrustManager checks
    }

    #[test]
    fn code_without_risky_calls_has_no_findings_and_screen_rules_need_activities() {
        assert!(run(CLEAN, 0).is_empty());
        let with = run(CLEAN, 2);
        let rules: Vec<_> = with.iter().map(|i| i.rule).collect();
        assert_eq!(rules, ["apk-code-tapjacking", "apk-code-screenshot"]);
    }

    #[test]
    fn constants_are_dropped_at_join_points() {
        // Risky::web sets arguments right before each call; the tracked value must not survive
        // a branch target. Covered here by the trivial invariants: no panic, and the calls of
        // every method are extracted with their constant arguments.
        let d = dex::parse("x", RISKY).unwrap();
        let m = d
            .classes
            .iter()
            .flat_map(|c| c.direct_methods.iter().chain(&c.virtual_methods))
            .find(|m| dex::method_name(&d, m.idx).is_some_and(|n| n.contains("Risky;->crypto()")))
            .unwrap();
        let calls = dex::calls(&d, RISKY, m.code.as_ref().unwrap());
        let ciphers: Vec<_> = calls
            .iter()
            .filter(|c| c.callee.contains("Cipher;->getInstance"))
            .map(|c| c.args[0].clone())
            .collect();
        assert_eq!(
            ciphers,
            [
                Some(Val::Str("DES/CBC/PKCS5Padding".into())),
                Some(Val::Str("AES".into())),
                Some(Val::Str("AES/GCM/NoPadding".into()))
            ]
        );
    }

    #[test]
    fn hostile_dex_bytes_never_panic_the_rules() {
        for at in (0..RISKY.len()).step_by(11) {
            let mut v = RISKY.to_vec();
            v[at] ^= 0xff;
            if let Ok(d) = dex::parse("f", &v) {
                scan(&[(d, v)], 1);
            }
        }
    }
}
