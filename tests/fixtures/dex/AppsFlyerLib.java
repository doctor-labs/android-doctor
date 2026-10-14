package com.appsflyer;

/**
 * Stub planted for the apk-tracker-sdk corpus case (issue #194). Only the class name and package
 * matter: the tracker rule matches the dex class descriptors. Not the real AppsFlyer SDK.
 */
public class AppsFlyerLib {
    private static final AppsFlyerLib INSTANCE = new AppsFlyerLib();

    public static AppsFlyerLib getInstance() {
        return INSTANCE;
    }

    public void init(String devKey) {
        this.devKey = devKey;
    }

    private String devKey;
}
