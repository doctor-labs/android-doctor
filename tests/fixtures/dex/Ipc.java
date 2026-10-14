package ipc;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

/**
 * Intent, PendingIntent and receiver cases for android-doctor's apk-code-pending-implicit-intent,
 * apk-code-receiver-unprotected and apk-code-broadcast-no-permission tests (issue #212).
 * Each case is its own method so the rule details name it.
 */
public class Ipc extends android.app.Activity {
    static final String ACTION = "com.example.ACTION";
    static final String PERM = "com.example.PERM";

    PendingIntent implicitMutable(Context c) {
        Intent i = new Intent(ACTION);
        return PendingIntent.getBroadcast(c, 0, i, PendingIntent.FLAG_MUTABLE);
    }

    PendingIntent implicitImmutable(Context c) {
        Intent i = new Intent(ACTION);
        return PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_IMMUTABLE);
    }

    PendingIntent explicitTarget(Context c) {
        Intent i = new Intent(c, Ipc.class);
        return PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_IMMUTABLE);
    }

    void recvNoArgs(BroadcastReceiver r, IntentFilter f) {
        registerReceiver(r, f);
    }

    void recvExportedFlag(BroadcastReceiver r, IntentFilter f) {
        registerReceiver(r, f, 2);
    }

    void recvNullPerm(BroadcastReceiver r, IntentFilter f) {
        registerReceiver(r, f, null, null);
    }

    void recvNotExported(BroadcastReceiver r, IntentFilter f) {
        registerReceiver(r, f, 4);
    }

    void recvPerm(BroadcastReceiver r, IntentFilter f) {
        registerReceiver(r, f, PERM, null);
    }

    void recvNullPermNotExported(BroadcastReceiver r, IntentFilter f) {
        registerReceiver(r, f, null, null, 4);
    }

    void broadcastNoPerm(Context c) {
        c.sendBroadcast(new Intent(ACTION));
    }

    void broadcastNullPerm(Context c) {
        c.sendBroadcast(new Intent(ACTION), null);
    }

    void broadcastPerm(Context c) {
        c.sendBroadcast(new Intent(ACTION), PERM);
    }

    void explicitBroadcast(Context c) {
        Intent i = new Intent(ACTION);
        i.setPackage(c.getPackageName());
        c.sendBroadcast(i);
    }
}
