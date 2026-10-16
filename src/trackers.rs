//! Third-party tracker and analytics SDKs found in an APK's dex code.
//!
//! Each entry is a vendor's published Java package prefix, the package its SDK ships its classes
//! under. Matching is a prefix test on the dotted class name, and every prefix ends with a dot so
//! that `com.adjust.sdk.` never matches `com.adjustments`. The list is hand-written from the
//! vendors' own package names (no tracker database is copied); it is a starting set, not a
//! complete one. A tracker is a disclosure item for the privacy policy, not a vulnerability.

/// (tracker name, package prefixes it ships under).
const TRACKERS: &[(&str, &[&str])] = &[
    ("Google Analytics", &["com.google.android.gms.analytics."]),
    ("Firebase Analytics", &["com.google.firebase.analytics."]),
    (
        "Firebase Crashlytics",
        &["com.google.firebase.crashlytics."],
    ),
    ("Google AdMob", &["com.google.android.gms.ads."]),
    (
        "Facebook SDK",
        &["com.facebook.appevents.", "com.facebook.ads."],
    ),
    ("AppsFlyer", &["com.appsflyer."]),
    ("Adjust", &["com.adjust.sdk."]),
    ("Amplitude", &["com.amplitude."]),
    ("Mixpanel", &["com.mixpanel.android."]),
    ("Flurry", &["com.flurry.android."]),
    ("Segment", &["com.segment.analytics."]),
    ("Branch", &["io.branch."]),
    ("OneSignal", &["com.onesignal."]),
    ("Braze", &["com.braze.", "com.appboy."]),
    ("Localytics", &["com.localytics.android."]),
    ("New Relic", &["com.newrelic.agent.android."]),
    ("Bugsnag", &["com.bugsnag.android."]),
    ("Sentry", &["io.sentry."]),
    ("comScore", &["com.comscore."]),
    ("Moat", &["com.moat.analytics."]),
    ("InMobi", &["com.inmobi."]),
    ("Unity Ads", &["com.unity3d.ads."]),
    ("AppLovin", &["com.applovin."]),
    ("ironSource", &["com.ironsource."]),
    ("Vungle", &["com.vungle."]),
    ("Chartboost", &["com.chartboost.sdk."]),
    ("Tapjoy", &["com.tapjoy."]),
    ("AdColony", &["com.adcolony.sdk."]),
    ("MoPub", &["com.mopub."]),
    ("Yandex AppMetrica", &["com.yandex.metrica."]),
    ("Umeng", &["com.umeng."]),
    ("Tencent Bugly", &["com.tencent.bugly."]),
    ("Huawei Analytics", &["com.huawei.hms.analytics."]),
];

/// Names of the trackers with a package prefix matching one of the class descriptors (`Lcom/x/Y;`),
/// in table order, each name once.
pub fn match_descriptors<'a>(descriptors: impl IntoIterator<Item = &'a str>) -> Vec<&'static str> {
    // `Lcom/adjust/sdk/Adjust;` -> `com.adjust.sdk.Adjust`
    // ponytail: linear scan over every class; a prefix trie if the table grows past a few hundred.
    let names: Vec<String> = descriptors
        .into_iter()
        .map(|d| {
            d.strip_prefix('L')
                .unwrap_or(d)
                .trim_end_matches(';')
                .replace('/', ".")
        })
        .collect();
    TRACKERS
        .iter()
        .filter(|(_, prefixes)| {
            names
                .iter()
                .any(|n| prefixes.iter().any(|p| n.starts_with(p)))
        })
        .map(|(name, _)| *name)
        .collect()
}

/// Tracker names found in the classes of the parsed dex files.
pub fn detect(dexes: &[(crate::dex::Dex, Vec<u8>)]) -> Vec<&'static str> {
    match_descriptors(
        dexes
            .iter()
            .flat_map(|(d, _)| d.classes.iter().map(|c| c.descriptor.as_str())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_class_under_a_tracker_package_names_it_once() {
        let found = match_descriptors([
            "Lcom/adjust/sdk/Adjust;",
            "Lcom/adjust/sdk/AdjustEvent;",
            "Lcom/example/app/Main;",
        ]);
        assert_eq!(found, vec!["Adjust"]);
    }

    #[test]
    fn the_prefix_must_end_at_a_package_boundary() {
        assert!(match_descriptors(["Lcom/adjustments/Foo;"]).is_empty());
    }

    #[test]
    fn an_app_without_tracker_packages_has_none() {
        assert!(match_descriptors(["Lcom/example/app/Main;"]).is_empty());
    }
}
