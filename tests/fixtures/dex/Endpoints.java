package endpoints;

/** Hardcoded endpoints for android-doctor's apk-code-hardcoded-ip / apk-code-cleartext-url tests (issue #197). */
public class Endpoints {
    static final String API = "http://api.example.com/v1/login";
    static final String SECURE = "https://api.example.com/v1/login";
    static final String PUBLIC_IP = "8.8.8.8";
    static final String HOST_WITH_PORT = "203.0.113.7:8443";
    static final String LAN = "192.168.1.10";
    static final String LOOPBACK = "http://127.0.0.1:8080/debug";
    static final String NS = "http://schemas.android.com/apk/res/android";
    static final String VERSION = "1.2.3.4.5";

    static String[] all() {
        return new String[] {API, SECURE, PUBLIC_IP, HOST_WITH_PORT, LAN, LOOPBACK, NS, VERSION};
    }
}
