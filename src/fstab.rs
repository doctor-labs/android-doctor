//! fstab file parsing and issue detection (AOSP libfstab format).

#[derive(Debug, Clone, PartialEq)]
pub struct FstabEntry {
    pub blk_device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub mnt_flags: Vec<String>,
    pub fs_mgr_flags: Vec<(String, Option<String>)>,
}

pub fn parse(text: &str) -> Vec<FstabEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let blk_device = cols[0].to_string();
        let mount_point = cols[1].to_string();
        let fs_type = cols[2].to_string();
        let mnt_flags = cols[3].split(',').map(|s| s.to_string()).collect();
        let fs_mgr_flags = if cols.len() >= 5 {
            cols[4]
                .split(',')
                .map(|s| {
                    let s = s.trim();
                    if let Some((k, v)) = s.split_once('=') {
                        (k.to_string(), Some(v.to_string()))
                    } else {
                        (s.to_string(), None)
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        entries.push(FstabEntry {
            blk_device,
            mount_point,
            fs_type,
            mnt_flags,
            fs_mgr_flags,
        });
    }
    entries
}

pub fn issues(entries: &[FstabEntry]) -> Vec<(&'static str, crate::audit::Severity, String)> {
    let system_points = ["/", "/system", "/vendor", "/product", "/system_ext", "/odm"];
    let mut result = Vec::new();
    for e in entries {
        let has_avb = e
            .fs_mgr_flags
            .iter()
            .any(|(k, _)| k == "avb" || k == "verify");
        if !has_avb && system_points.contains(&e.mount_point.as_str()) {
            result.push((
                "fstab-no-verity",
                crate::audit::Severity::Medium,
                format!(
                    "{} is mounted without dm-verity (no avb or verify flag)",
                    e.mount_point
                ),
            ));
        }
        if e.mount_point == "/data" {
            let has_encryption = e.fs_mgr_flags.iter().any(|(k, _)| {
                k == "fileencryption"
                    || k == "forceencrypt"
                    || k == "forcefdeorfbe"
                    || k == "encryptable"
            });
            if !has_encryption {
                result.push((
                    "fstab-data-unencrypted",
                    crate::audit::Severity::High,
                    "/data has no encryption flag".to_string(),
                ));
            } else if e.fs_mgr_flags.iter().any(|(k, _)| k == "encryptable")
                && !e.fs_mgr_flags.iter().any(|(k, _)| {
                    matches!(
                        k.as_str(),
                        "fileencryption" | "forceencrypt" | "forcefdeorfbe"
                    )
                })
            {
                result.push((
                    "fstab-data-encryption-optional",
                    crate::audit::Severity::Medium,
                    "/data uses encryptable= (encryption is optional)".to_string(),
                ));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const FSTAB: &str = "\
# Android fstab file.
/dev/block/by-name/system    /system   ext4 ro,barrier=1          wait,slotselect,avb=vbmeta_system,logical,first_stage_mount
/dev/block/by-name/vendor    /vendor   ext4 ro                    wait,logical
/dev/block/by-name/userdata  /data     f2fs noatime,nosuid,nodev  latemount,wait,check,encryptable=footer,quota
/dev/block/by-name/metadata  /metadata ext4 noatime,nosuid,nodev  wait,formattable
";

    #[test]
    fn parses_entries_and_fs_mgr_flags() {
        let e = parse(FSTAB);
        assert_eq!(e.len(), 4);
        assert_eq!(
            (e[0].mount_point.as_str(), e[0].fs_type.as_str()),
            ("/system", "ext4")
        );
        assert!(e[0].mnt_flags.iter().any(|f| f == "ro"));
        assert!(
            e[0].fs_mgr_flags
                .iter()
                .any(|(k, v)| k == "avb" && v.as_deref() == Some("vbmeta_system"))
        );
        assert!(
            e[0].fs_mgr_flags
                .iter()
                .any(|(k, v)| k == "slotselect" && v.is_none())
        );
    }

    #[test]
    fn flags_missing_verity_and_weak_data_encryption() {
        let rules = |text: &str| {
            issues(&parse(text))
                .into_iter()
                .map(|(r, _, d)| (r, d))
                .collect::<Vec<_>>()
        };
        let r = rules(FSTAB);
        assert!(
            r.iter()
                .any(|(rule, d)| *rule == "fstab-no-verity" && d.contains("/vendor")),
            "{r:?}"
        );
        assert!(
            !r.iter()
                .any(|(rule, d)| *rule == "fstab-no-verity" && d.contains("/system")),
            "{r:?}"
        );
        assert!(
            r.iter()
                .any(|(rule, _)| *rule == "fstab-data-encryption-optional"),
            "{r:?}"
        );
        // file-based encryption on /data is fine
        let fbe = "/dev/block/by-name/userdata /data f2fs noatime latemount,wait,fileencryption=aes-256-xts:aes-256-cts\n";
        assert!(rules(fbe).is_empty(), "{:?}", rules(fbe));
        // no encryption flag at all on /data
        let none = "/dev/block/by-name/userdata /data ext4 noatime wait,check\n";
        assert!(
            rules(none)
                .iter()
                .any(|(rule, _)| *rule == "fstab-data-unencrypted")
        );
    }
}
