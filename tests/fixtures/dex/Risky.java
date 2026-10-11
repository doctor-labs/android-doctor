package risky;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.os.Environment;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.net.http.SslError;
import dalvik.system.DexClassLoader;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.crypto.Cipher;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public class Risky extends android.app.Activity {
    void web(WebView w) {
        w.getSettings().setJavaScriptEnabled(true);
        w.addJavascriptInterface(new Object(), "bridge");
        w.getSettings().setAllowUniversalAccessFromFileURLs(true);
        WebView.setWebContentsDebuggingEnabled(true);
        w.loadUrl("http://example.com/");
    }
    void safeWeb(WebView w) {
        w.getSettings().setJavaScriptEnabled(false);
        w.loadUrl("https://example.com/");
    }
    void crypto() throws Exception {
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA-256");
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher.getInstance("AES");
        Cipher.getInstance("AES/GCM/NoPadding");
    }
    void rnd() { new Random(); }
    void log() { Log.d("auth", "password reset requested"); Log.i("tag", "hello"); }
    @SuppressWarnings("deprecation")
    void files() throws Exception {
        openFileOutput("a", Context.MODE_WORLD_READABLE);
        getSharedPreferences("p", Context.MODE_PRIVATE);
    }
    void ext() { Environment.getExternalStorageDirectory(); }
    void load(String p) { new DexClassLoader(p, p, p, null); }
    void sql(SQLiteDatabase db, String name) { db.rawQuery("select * from t where n='" + name + "'", null); }
    void sqlSafe(SQLiteDatabase db, String name) { db.rawQuery("select * from t where n=?", new String[] {name}); }
    void exec() throws Exception { Runtime.getRuntime().exec("ls"); }
    void marker() { String s = "/system/xbin/su"; Log.v("x", s); }
    static class Trust implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
    static class Host implements HostnameVerifier {
        public boolean verify(String h, SSLSession s) { return true; }
    }
    static class Client extends WebViewClient {
        public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) { h.proceed(); }
    }
}
