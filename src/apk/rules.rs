//! Code rules over an APK's DEX: risky API use found from the call graph the parser extracts
//! (WebView, crypto, random, logging, world-accessible files, external storage, SSL trust,
//! dynamic loading, raw SQL, command execution, tapjacking, screenshots, root/emulator/frida
//! checks) and behaviour categories (telephony identifiers, SMS, location, device settings,
//! audio/video capture, sockets, native loading, PIM content URIs; `apk-code-behaviour-*`, info
//! only). Modelled on MobSF `android_apis.yaml` / `android_rules.yaml`, qark's `webview`, `crypto`,
//! `cert`, `file` plugins and androwarn's behaviour modules, written from their descriptions.
//!
//! Method calls are matched by name and prototype, whatever class they are called on (so a call
//! on a `MyActivity` subclass still counts as a `Context` call). Arguments are judged only when
//! the code sets them as constants just before the call; anything else is not guessed.

use super::{ManifestIssue, Severity};
use crate::dex::{self, Call, Dex, Val};
use std::collections::BTreeSet;

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
/// TelephonyManager getters that return a device or subscriber identifier.
const DEVICE_IDS: [&str; 5] = [
    "getDeviceId",
    "getImei",
    "getSubscriberId",
    "getSimSerialNumber",
    "getLine1Number",
];
const BROKEN_CIPHERS: [&str; 5] = ["DES", "RC2", "RC4", "ARCFOUR", "BLOWFISH"];

// Framework constants, checked with `javap -constants` against platforms/android-34/android.jar.
const FLAG_MUTABLE: i64 = 0x0200_0000; // PendingIntent.FLAG_MUTABLE
const RECEIVER_NOT_EXPORTED: i64 = 4; // Context.RECEIVER_NOT_EXPORTED

/// Whether the method names a target for an Intent (setPackage, setComponent, setClass,
/// setClassName, or a constructor taking a Context or Class). When it does, the method's Intents
/// are not judged implicit: the rules do not track which Intent each call receives. Ceiling: a
/// target set in another method is not seen, so such an Intent is still judged implicit.
fn names_target(calls: &[Call]) -> bool {
    const SETTERS: [&str; 4] = ["setPackage(", "setComponent(", "setClass(", "setClassName("];
    const CTORS: [&str; 2] = [
        "<init>(Landroid/content/Context;",
        "<init>(Ljava/lang/String;Landroid/net/Uri;Landroid/content/Context;",
    ];
    calls.iter().any(|c| {
        c.callee
            .strip_prefix("Landroid/content/Intent;->")
            .is_some_and(|r| SETTERS.iter().chain(CTORS.iter()).any(|m| r.starts_with(m)))
    })
}

fn judge(s: &Site, c: &mut Collector) {
    let at = &s.method;
    let (mut sms, mut device_id) = (false, false);
    let explicit = names_target(&s.calls);
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
        // SMS sent from code, and the device identifiers a malware sends off with it
        if f.starts_with("Landroid/telephony/SmsManager;->send") {
            c.add(
                "apk-code-sms-send",
                Severity::Medium,
                "sends an SMS from code",
                at,
            );
            sms = true;
        }
        if DEVICE_IDS
            .iter()
            .any(|n| f.starts_with(&format!("Landroid/telephony/TelephonyManager;->{n}(")))
        {
            device_id = true;
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
        // Dynamic receivers: no permission guards them and they are not RECEIVER_NOT_EXPORTED.
        // Flags and permission are judged only when they are constants (null is const 0).
        let flags_open = |i: usize| int(a.get(i)).is_some_and(|v| v & RECEIVER_NOT_EXPORTED == 0);
        let no_perm = |i: usize| a.get(i) == Some(&Some(Val::Int(0)));
        let proto = f.split_once("->registerReceiver(").map(|x| x.1);
        let open_receiver = match proto {
            Some(p) if p.starts_with("Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)") => true,
            Some(p) if p.starts_with("Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)") => flags_open(3),
            Some(p) if p.starts_with("Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)") => no_perm(3),
            Some(p) if p.starts_with("Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I)") => {
                no_perm(3) && flags_open(5)
            }
            _ => false,
        };
        if open_receiver {
            c.add(
                "apk-code-receiver-unprotected",
                Severity::Medium,
                "dynamic broadcast receiver has no permission and is not RECEIVER_NOT_EXPORTED: any app can send to it",
                at,
            );
        }
        // Implicit Intent wrapped in a PendingIntent: the recipient may fill in its target, and a
        // mutable PendingIntent lets it rewrite the fields that were left open.
        if !explicit
            && f.starts_with("Landroid/app/PendingIntent;->get")
            && f.contains("(Landroid/content/Context;ILandroid/content/Intent;I")
        {
            if int(a.get(3)).is_some_and(|v| v & FLAG_MUTABLE != 0) {
                c.add(
                    "apk-code-pending-implicit-intent",
                    Severity::Medium,
                    "mutable PendingIntent wraps an implicit Intent: a receiving app can redirect it",
                    at,
                );
            } else {
                c.add(
                    "apk-code-pending-implicit-intent",
                    Severity::Warn,
                    "PendingIntent wraps an implicit Intent with no explicit target",
                    at,
                );
            }
        }
        // Broadcasts without a receiver permission: any matching receiver in any app gets them.
        if !explicit
            && (has(f, "sendBroadcast(Landroid/content/Intent;)V")
                || (has(
                    f,
                    "sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V",
                ) && no_perm(2)))
        {
            c.add(
                "apk-code-broadcast-no-permission",
                Severity::Warn,
                "implicit broadcast sent without a receiver permission",
                at,
            );
        }
        // Behaviour categories (androwarn-style): the call is listed, not judged
        for (rule, what, sigs) in BEHAVIOURS {
            if sigs.iter().any(|p| f.contains(p)) {
                c.add(rule, Severity::Info, what, at);
            }
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
    // Method-level co-occurrence only: no data flow is traced from the identifier to the SMS.
    if sms && device_id {
        c.add(
            "apk-code-device-id-sms",
            Severity::High,
            "reads a device identifier and sends an SMS in the same method",
            at,
        );
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

/// Behaviour categories: Android APIs whose use the app's purpose should explain. Matched as
/// substrings of a call's callee (class, name and prototype), so a call on an app subclass such
/// as `abortBroadcast()` still counts. Method names checked against android.jar (API 34).
/// `exec` is not here: `apk-code-command-exec` already reports Runtime.exec and ProcessBuilder.
const BEHAVIOURS: [(&str, &str, &[&str]); 7] = [
    (
        "apk-code-behaviour-telephony",
        "telephony identifiers",
        &[
            "Landroid/telephony/TelephonyManager;->getDeviceId(",
            "Landroid/telephony/TelephonyManager;->getImei(",
            "Landroid/telephony/TelephonyManager;->getMeid(",
            "Landroid/telephony/TelephonyManager;->getSubscriberId(",
            "Landroid/telephony/TelephonyManager;->getSimSerialNumber(",
            "Landroid/telephony/TelephonyManager;->getLine1Number(",
        ],
    ),
    (
        "apk-code-behaviour-sms",
        "SMS interception",
        &[
            "Landroid/telephony/SmsMessage;->getMessageBody(",
            "Landroid/telephony/SmsMessage;->getOriginatingAddress(",
            "Landroid/telephony/SmsMessage;->createFromPdu(",
            "->abortBroadcast()V",
        ],
    ),
    (
        "apk-code-behaviour-location",
        "location",
        &[
            "Landroid/location/LocationManager;->requestLocationUpdates(",
            "Landroid/location/LocationManager;->getLastKnownLocation(",
            "Landroid/location/Location;->getLatitude()D",
            "Landroid/location/Location;->getLongitude()D",
            "Landroid/telephony/TelephonyManager;->getCellLocation()",
        ],
    ),
    (
        "apk-code-behaviour-settings",
        "device settings",
        &[
            "Landroid/provider/Settings$Secure;->putString(",
            "Landroid/provider/Settings$Secure;->putInt(",
            "Landroid/provider/Settings$Global;->putString(",
            "Landroid/provider/Settings$Global;->putInt(",
            "Landroid/provider/Settings$System;->putString(",
            "Landroid/provider/Settings$System;->putInt(",
        ],
    ),
    (
        "apk-code-behaviour-media",
        "audio and video capture",
        &[
            "Landroid/media/AudioRecord;->startRecording(",
            "Landroid/media/MediaRecorder;->start()V",
            "Landroid/hardware/Camera;->open(",
            "Landroid/hardware/Camera;->takePicture(",
            "Landroid/hardware/camera2/CameraManager;->openCamera(",
        ],
    ),
    (
        "apk-code-behaviour-sockets",
        "sockets",
        &[
            "Ljava/net/Socket;-><init>(",
            "Ljava/net/ServerSocket;-><init>(",
            "Ljava/net/DatagramSocket;-><init>(",
        ],
    ),
    (
        "apk-code-behaviour-native",
        "native code loading",
        &[
            "Ljava/lang/System;->loadLibrary(",
            "Ljava/lang/System;->load(",
            "Ljava/lang/Runtime;->loadLibrary(",
            "Ljava/lang/Runtime;->load(",
        ],
    ),
];

/// Content URIs of personal data (contacts, SMS, MMS, call log, calendar), found in the string pool.
const PIM_URIS: [&str; 5] = [
    "content://com.android.contacts",
    "content://sms",
    "content://mms",
    "content://call_log",
    "content://com.android.calendar",
];

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
        if let Some(uri) = PIM_URIS
            .iter()
            .find(|u| dex.strings.iter().any(|s| s.contains(**u)))
        {
            c.add(
                "apk-code-behaviour-pim",
                Severity::Info,
                &format!("PIM access (contacts, SMS, call log or calendar, \"{uri}\")"),
                &dex.name,
            );
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
    let mut issues = group(c.hits);
    issues.extend(endpoint_issues(dexes));
    issues
}

/// Scan every dex's string table for hardcoded public IP addresses and cleartext http:// URLs in
/// the dex string pool. Each distinct string is examined once.
fn endpoint_issues(dexes: &[(Dex, Vec<u8>)]) -> Vec<ManifestIssue> {
    let mut public_ips: Vec<String> = Vec::new();
    let mut cleartext_urls: Vec<String> = Vec::new();
    // one set across every dex: a string repeated in classes2.dex is still one hit
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (dex, _) in dexes {
        for s in &dex.strings {
            if !seen.insert(s.as_str()) {
                continue;
            }
            // Hardcoded public IPv4, optionally followed by ":port".
            if let Some(ip) = parse_public_ip(s) {
                public_ips.push(ip);
            }
            // Cleartext http:// URL with a non-private, non-namespace host.
            if let Some(url) = parse_cleartext_url(s) {
                cleartext_urls.push(url);
            }
        }
    }
    let mut out: Vec<ManifestIssue> = Vec::new();
    if !public_ips.is_empty() {
        public_ips.sort();
        let shown: Vec<&str> = public_ips
            .iter()
            .take(MAX_HITS_PER_RULE)
            .map(|s| s.as_str())
            .collect();
        let more = if public_ips.len() > MAX_HITS_PER_RULE {
            format!(" (and {} more)", public_ips.len() - MAX_HITS_PER_RULE)
        } else {
            String::new()
        };
        out.push(ManifestIssue {
            rule: "apk-code-hardcoded-ip",
            severity: Severity::Info,
            detail: format!(
                "public IP addresses in the code: {}{more}",
                shown.join(", ")
            ),
        });
    }
    if !cleartext_urls.is_empty() {
        cleartext_urls.sort();
        let shown: Vec<&str> = cleartext_urls
            .iter()
            .take(MAX_HITS_PER_RULE)
            .map(|s| s.as_str())
            .collect();
        let more = if cleartext_urls.len() > MAX_HITS_PER_RULE {
            format!(" (and {} more)", cleartext_urls.len() - MAX_HITS_PER_RULE)
        } else {
            String::new()
        };
        out.push(ManifestIssue {
            rule: "apk-code-cleartext-url",
            severity: Severity::Warn,
            detail: format!(
                "cleartext http:// URLs in the code: {}{more}",
                shown.join(", ")
            ),
        });
    }
    out
}

/// If `s` is an IPv4 literal (optionally with ":port"), return the bare address when it is a
/// globally-routable public address, else None.
fn parse_public_ip(s: &str) -> Option<String> {
    let addr = s.split(':').next()?;
    let ip: std::net::Ipv4Addr = addr.parse().ok()?;
    if !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_broadcast()
    {
        Some(ip.to_string())
    } else {
        None
    }
}

/// If `s` starts with "http://" and its host is a cleartext, non-private, non-namespace host,
/// return the full URL.
fn parse_cleartext_url(s: &str) -> Option<String> {
    if !s.starts_with("http://") {
        return None;
    }
    let rest = &s["http://".len()..];
    let host = rest.split(['/', '?', '#', ':']).next()?;
    if host.is_empty() {
        return None;
    }
    // Skip localhost / private IP ranges.
    if host == "localhost" {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
            return None;
        }
    } else {
        // Not an IP: must not be a private/dotted name that looks like a LAN host,
        // and must not be one of the XML namespace hosts we allow to use http.
        let ns = [
            "schemas.android.com",
            "www.w3.org",
            "ns.adobe.com",
            "xmlpull.org",
            "schemas.xmlsoap.org",
        ];
        if ns.contains(&host) {
            return None;
        }
    }
    Some(s.to_string())
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
    const ENDPOINTS: &[u8] = include_bytes!("../../tests/fixtures/dex/endpoints.dex");
    const BEHAVIOUR: &[u8] = include_bytes!("../../tests/fixtures/dex/behaviour.dex");
    /// javac + d8 over tests/fixtures/dex/Categories.java (source included).
    const CATEGORIES: &[u8] = include_bytes!("../../tests/fixtures/dex/categories.dex");

    #[test]
    fn behaviour_categories_are_listed_by_api_use() {
        // one rule id per category, so the 5-site detail cap never hides a category
        let v = run(CATEGORIES, 0);
        for (rule, cat) in [
            ("apk-code-behaviour-telephony", "telephony identifiers"),
            ("apk-code-behaviour-sms", "SMS interception"),
            ("apk-code-behaviour-location", "location"),
            ("apk-code-behaviour-settings", "device settings"),
            ("apk-code-behaviour-media", "audio and video capture"),
            ("apk-code-behaviour-sockets", "sockets"),
            ("apk-code-behaviour-native", "native code loading"),
            ("apk-code-behaviour-pim", "PIM access"),
        ] {
            let d = detail(&v, rule, Severity::Info);
            assert!(d.contains(cat), "{rule}: {d}");
        }
        assert!(
            run(CLEAN, 0)
                .iter()
                .all(|i| !i.rule.starts_with("apk-code-behaviour")),
            "demo.dex uses none of the behaviour APIs"
        );
    }

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
    fn sms_sending_and_device_identifier_exfiltration_are_found() {
        // behaviour.dex (tests/fixtures/dex/Behaviour.java): exfiltrate reads the IMEI and sends
        // it by SMS; spam sends an SMS alone; identify reads the IMEI alone
        let v = run(BEHAVIOUR, 0);
        let combo = detail(&v, "apk-code-device-id-sms", Severity::High);
        assert!(combo.contains("exfiltrate"), "{combo}");
        assert!(
            !combo.contains("spam") && !combo.contains("identify"),
            "{combo}"
        );
        let sms = detail(&v, "apk-code-sms-send", Severity::Medium);
        assert!(
            sms.starts_with("2 site(s)") && sms.contains("exfiltrate") && sms.contains("spam"),
            "{sms}"
        );
        assert!(
            run(CLEAN, 0)
                .iter()
                .all(|i| i.rule != "apk-code-sms-send" && i.rule != "apk-code-device-id-sms"),
            "demo.dex sends no SMS"
        );
    }

    #[test]
    fn hardcoded_public_ips_and_cleartext_urls_are_found() {
        // endpoints.dex (tests/fixtures/dex/Endpoints.java): one string of each kind
        let v = run(ENDPOINTS, 0);
        let ip = detail(&v, "apk-code-hardcoded-ip", Severity::Info);
        assert!(ip.contains("8.8.8.8") && ip.contains("203.0.113.7"), "{ip}");
        assert!(
            !ip.contains("192.168.1.10") && !ip.contains("1.2.3.4"),
            "private and version strings are not IPs: {ip}"
        );
        let url = detail(&v, "apk-code-cleartext-url", Severity::Warn);
        assert!(url.contains("http://api.example.com/v1/login"), "{url}");
        assert!(
            !url.contains("127.0.0.1")
                && !url.contains("schemas.android.com")
                && !url.contains("https://"),
            "loopback, XML namespaces and https are not cleartext endpoints: {url}"
        );
        assert!(
            run(CLEAN, 0)
                .iter()
                .all(|i| i.rule != "apk-code-hardcoded-ip" && i.rule != "apk-code-cleartext-url"),
            "demo.dex has no hardcoded endpoints"
        );
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
    fn intent_and_receiver_rules_judge_constants_and_skip_explicit_targets() {
        // tests/fixtures/dex/Ipc.java: one case per method, named in the details.
        const IPC: &[u8] = include_bytes!("../../tests/fixtures/dex/ipc.dex");
        let v = run(IPC, 0);
        let pending_mut = detail(&v, "apk-code-pending-implicit-intent", Severity::Medium);
        assert!(pending_mut.contains("implicitMutable"), "{pending_mut}");
        assert!(!pending_mut.contains("explicitTarget"), "{pending_mut}");
        let pending_imm = detail(&v, "apk-code-pending-implicit-intent", Severity::Warn);
        assert!(pending_imm.contains("implicitImmutable"), "{pending_imm}");
        assert!(!pending_imm.contains("explicitTarget"), "{pending_imm}");

        let recv = detail(&v, "apk-code-receiver-unprotected", Severity::Medium);
        for m in ["recvNoArgs", "recvExportedFlag", "recvNullPerm"] {
            assert!(recv.contains(m), "{m} missing from {recv}");
        }
        for m in ["recvNotExported", "recvPerm", "recvNullPermNotExported"] {
            assert!(!recv.contains(m), "{m} wrongly flagged in {recv}");
        }

        let bcast = detail(&v, "apk-code-broadcast-no-permission", Severity::Warn);
        assert!(bcast.contains("broadcastNoPerm"), "{bcast}");
        assert!(bcast.contains("broadcastNullPerm"), "{bcast}");
        assert!(!bcast.contains("broadcastPerm"), "{bcast}");
        assert!(!bcast.contains("explicitBroadcast"), "{bcast}");
        // no other rule fires on this fixture: pending (medium, low), receiver, broadcast
        assert_eq!(v.len(), 4, "{v:#?}");
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
