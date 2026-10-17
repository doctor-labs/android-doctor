package categories;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.hardware.Camera;
import android.location.Location;
import android.location.LocationManager;
import android.media.MediaRecorder;
import android.provider.Settings;
import android.telephony.SmsMessage;
import android.telephony.TelephonyManager;
import java.net.ServerSocket;
import java.net.Socket;

/** Behaviour categories for android-doctor's apk-code-behaviour tests (issue #206). */
public class Categories extends BroadcastReceiver {
    static final String CONTACTS = "content://com.android.contacts/data";

    void ids(TelephonyManager t) {
        t.getDeviceId();
        t.getSubscriberId();
        t.getLine1Number();
    }

    @Override
    public void onReceive(Context c, Intent i) {
        SmsMessage m = SmsMessage.createFromPdu(new byte[0]);
        m.getMessageBody();
        abortBroadcast();
    }

    void where(LocationManager lm, Location l) {
        lm.getLastKnownLocation("gps");
        l.getLatitude();
    }

    void settings(Context c) {
        Settings.Secure.putInt(c.getContentResolver(), "install_non_market_apps", 1);
    }

    void media() {
        new MediaRecorder().start();
        Camera.open();
    }

    void net() throws Exception {
        new Socket("example.com", 443);
        new ServerSocket(0);
    }

    void nat() {
        System.loadLibrary("native");
    }

    void safe(int x) {
        Math.max(x, 1);
    }
}
