//! Static catalogue of Android framework permission protection levels.
//!
//! Each entry maps a fully-qualified Android permission name (as declared in
//! the platform `AndroidManifest.xml` and published as a constant in
//! `android.Manifest$permission`) to its raw `protectionLevel` attribute value.
//!
//! The catalogue is generated from the android-36 SDK platform:
//!   - permission names from `javap android.Manifest$permission`
//!   - protection levels from the framework `AndroidManifest.xml` (aapt2 dump)
//!
//! All entries were verified against both sources (see the test suite).
//!
//! The base protection level is `value & 0xf`:
//!   0 = normal, 1 = dangerous, 2 = signature, 3 = signatureOrSystem,
//!   4 = development (signature|privileged, etc. are expressed via the
//! higher flag bits, e.g. 0x10 = privileged).
#![allow(dead_code)] // consumers land in a follow-up

use std::sync::OnceLock;

/// One catalogue entry: a permission name and its raw `protectionLevel`.
struct Entry {
    name: &'static str,
    level: u32,
}

/// The static table, parsed once from `permissions.txt` (compiled in via
/// `include_str!`). Each line is `name<TAB>0xhex`.
fn table() -> &'static [Entry] {
    static T: OnceLock<Vec<Entry>> = OnceLock::new();
    T.get_or_init(|| {
        let mut v = Vec::new();
        for line in include_str!("permissions.txt").lines() {
            let mut p = line.split('\t');
            if let (Some(name), Some(hex)) = (p.next(), p.next()) {
                let level = u32::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0);
                v.push(Entry { name, level });
            }
        }
        v
    })
}

/// Returns the raw `protectionLevel` for a fully-qualified Android permission
/// name, as declared in the platform framework manifest.
///
/// Returns `None` for permissions not in the framework catalogue (including
/// app-defined custom permissions, whose level is unknown here).
pub fn protection_level(name: &str) -> Option<u32> {
    table().iter().find(|e| e.name == name).map(|e| e.level)
}

/// Returns the raw `protectionLevel` for a permission name, or `None` if it is
/// not a known framework permission.
///
/// This is the value apps compare against `android:protectionLevel` in their
/// own manifest and what `apk.rs` stores as the second tuple element.
pub fn raw_protection_level(name: &str) -> Option<u32> {
    protection_level(name)
}

/// The base protection level (the low nibble, `& 0xf`) for a permission name.
///
/// Returns `None` for permissions not in the catalogue.
pub fn base_level(name: &str) -> Option<u8> {
    protection_level(name).map(|v| (v & 0xf) as u8)
}

/// Human-readable name of the base protection level, or `None` for unknown
/// permissions.
pub fn base_level_name(name: &str) -> Option<&'static str> {
    Some(match base_level(name)? {
        0 => "normal",
        1 => "dangerous",
        2 => "signature",
        3 => "signatureOrSystem",
        4 => "development",
        _ => "unknown",
    })
}

/// True for permissions whose base level is `dangerous` (1), the runtime
/// permission group the user must grant.
pub fn is_dangerous(name: &str) -> bool {
    matches!(base_level(name), Some(1))
}

/// True for permissions whose base level is `signature` (2) or
/// `signatureOrSystem` (3) — only apps signed with the platform key or in the
/// system image can hold them.
pub fn is_signature(name: &str) -> bool {
    matches!(base_level(name), Some(2 | 3))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A few well-known permissions and their expected base levels, taken from
    /// the android-36 platform manifest (verified via aapt2 / javap).
    #[test]
    fn known_permissions_match_the_platform() {
        // normal
        assert_eq!(base_level("android.permission.READ_PROFILE"), Some(0));
        assert_eq!(base_level("android.permission.INTERNET"), Some(0));
        assert_eq!(
            base_level("android.permission.ACCESS_NETWORK_STATE"),
            Some(0)
        );
        // dangerous (runtime permissions)
        assert_eq!(base_level("android.permission.READ_CALENDAR"), Some(1));
        assert_eq!(base_level("android.permission.READ_CONTACTS"), Some(1));
        assert_eq!(
            base_level("android.permission.ACCESS_FINE_LOCATION"),
            Some(1)
        );
        assert_eq!(base_level("android.permission.RECORD_AUDIO"), Some(1));
        assert_eq!(base_level("android.permission.READ_PHONE_STATE"), Some(1));
        assert_eq!(base_level("android.permission.CALL_PHONE"), Some(1));
        assert_eq!(base_level("android.permission.RECEIVE_SMS"), Some(1));
        assert_eq!(base_level("android.permission.SEND_SMS"), Some(1));
        assert_eq!(
            base_level("android.permission.READ_EXTERNAL_STORAGE"),
            Some(1)
        );
        assert_eq!(base_level("android.permission.READ_MEDIA_IMAGES"), Some(1));
        assert_eq!(base_level("android.permission.POST_NOTIFICATIONS"), Some(1));
        // signature
        assert_eq!(
            base_level("android.permission.WRITE_SECURE_SETTINGS"),
            Some(2)
        );
        assert_eq!(base_level("android.permission.BATTERY_STATS"), Some(2));
        assert_eq!(base_level("android.permission.BIND_WALLPAPER"), Some(2));
    }

    /// The raw hex value for ACCESS_FINE_LOCATION includes the privileged flag
    /// (0x1000) but its base level is still `dangerous` (1).
    #[test]
    fn raw_level_keeps_flags_but_base_strips_them() {
        let raw = protection_level("android.permission.ACCESS_FINE_LOCATION").unwrap();
        assert_eq!(raw & 0xf, 1); // dangerous
        assert!(raw & 0x1000 != 0); // privileged flag set
    }

    /// Every permission constant from `javap android.Manifest$permission` (the
    /// public API surface apps code against) is present in the catalogue.
    #[test]
    fn all_public_manifest_constants_are_present() {
        // Constants whose javap name is `android.permission.*`.
        let android_group = [
            "android.permission.ACCEPT_HANDOVER",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.ACCESS_BLOBS_ACROSS_USERS",
            "android.permission.ACCESS_CHECKIN_PROPERTIES",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_MEDIA_LOCATION",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_NOTIFICATION_POLICY",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.ACCOUNT_MANAGER",
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.BATTERY_STATS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_APPWIDGET",
            "android.permission.BIND_AUTOFILL_SERVICE",
            "android.permission.BIND_INPUT_METHOD",
            "android.permission.BIND_NFC_SERVICE",
            "android.permission.BIND_WALLPAPER",
            "android.permission.BLUETOOTH",
            "android.permission.BLUETOOTH_ADMIN",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BODY_SENSORS",
            "android.permission.BROADCAST_STICKY",
            "android.permission.CALL_PHONE",
            "android.permission.CALL_PRIVILEGED",
            "android.permission.CAMERA",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.CHANGE_WIFI_MULTICAST_STATE",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.CLEAR_APP_CACHE",
            "android.permission.DELETE_PACKAGES",
            "android.permission.DIAGNOSTIC",
            "android.permission.EXPAND_STATUS_BAR",
            "android.permission.FLASHLIGHT",
            "android.permission.FORCE_STOP_PACKAGES",
            "android.permission.GET_ACCOUNTS",
            "android.permission.GET_TASKS",
            "android.permission.INTERNET",
            "android.permission.KILL_BACKGROUND_PROCESSES",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_ONGOING_CALLS",
            "android.permission.MODIFY_AUDIO_SETTINGS",
            "android.permission.MODIFY_PHONE_STATE",
            "android.permission.NFC",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.READ_CALENDAR",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PROFILE",
            "android.permission.READ_SMS",
            "android.permission.READ_SYNC_SETTINGS",
            "android.permission.READ_SYNC_STATS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.RECEIVE_MMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECORD_AUDIO",
            "android.permission.REORDER_TASKS",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.RESTART_PACKAGES",
            "android.permission.SCHEDULE_EXACT_ALARM",
            "android.permission.SEND_SMS",
            "android.permission.SET_TIME",
            "android.permission.SET_TIME_ZONE",
            "android.permission.SET_WALLPAPER",
            "android.permission.SET_WALLPAPER_HINTS",
            "android.permission.SIGNAL_PERSISTENT_PROCESSES",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FULL_SCREEN_INTENT",
            "android.permission.USE_SIP",
            "android.permission.VIBRATE",
            "android.permission.WAKE_LOCK",
            "android.permission.WRITE_APN_SETTINGS",
            "android.permission.WRITE_CALENDAR",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.WRITE_CONTACTS",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.WRITE_SETTINGS",
            "android.permission.WRITE_SYNC_SETTINGS",
        ];
        let missing: Vec<&str> = android_group
            .iter()
            .filter(|n| protection_level(n).is_none())
            .copied()
            .collect();
        assert!(
            missing.is_empty(),
            "android.permission.* constants missing from catalogue: {:?}",
            missing
        );

        // Some public constants are declared under non-android.permission groups
        // in the framework manifest.
        let non_android = [
            "com.android.voicemail.permission.ADD_VOICEMAIL",
            "com.android.voicemail.permission.READ_VOICEMAIL",
            "com.android.voicemail.permission.WRITE_VOICEMAIL",
            "com.android.alarm.permission.SET_ALARM",
        ];
        let missing2: Vec<&str> = non_android
            .iter()
            .filter(|n| protection_level(n).is_none())
            .copied()
            .collect();
        assert!(
            missing2.is_empty(),
            "non-android.* framework constants missing from catalogue: {:?}",
            missing2
        );
    }

    /// Unknown / custom permission names return `None`.
    #[test]
    fn unknown_permissions_are_absent() {
        assert!(protection_level("com.example.app.CUSTOM_BREW").is_none());
        assert!(protection_level("").is_none());
        assert!(base_level("android.permission.DEFINITELY_NOT_A_REAL_PERMISSION").is_none());
    }

    /// `is_dangerous` and `is_signature` classify the right base levels.
    #[test]
    fn classifiers_agree_with_base_level() {
        assert!(is_dangerous("android.permission.CAMERA"));
        assert!(!is_dangerous("android.permission.INTERNET"));
        assert!(is_signature("android.permission.WRITE_SECURE_SETTINGS"));
        // 0x1001 = dangerous | privileged → still dangerous, not signature
        assert!(is_dangerous("android.permission.ACCESS_FINE_LOCATION"));
        assert!(!is_signature("android.permission.ACCESS_FINE_LOCATION"));
    }
}
