package com.zerosploit.core;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import com.zerosploit.R;
import com.zerosploit.ui.MainActivity;

/**
 * Keeps the process resident and shows scan state in the notification shade.
 *
 * <p>A foreground service is what lets long port scans survive the app being
 * backgrounded; without it Android would freeze the process mid-sweep.
 */
public class ScanService extends Service {

    private static final String CHANNEL = "zerosploit.scan";
    private static final int NOTIF_ID = 0x5A17;

    public static void start(Context c) {
        Intent i = new Intent(c, ScanService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) c.startForegroundService(i);
        else c.startService(i);
    }

    public static void stop(Context c) {
        c.stopService(new Intent(c, ScanService.class));
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
        startForeground(NOTIF_ID, build("ZeroSploit", "Ready"));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String title = intent == null ? "ZeroSploit" : intent.getStringExtra("title");
        String text = intent == null ? "Ready" : intent.getStringExtra("text");
        if (title == null) title = "ZeroSploit";
        if (text == null) text = "Ready";
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIF_ID, build(title, text));
        return START_STICKY;
    }

    /** Updates the shade text, e.g. with live scan progress. */
    public static void update(Context c, String title, String text) {
        Intent i = new Intent(c, ScanService.class);
        i.putExtra("title", title);
        i.putExtra("text", text);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) c.startForegroundService(i);
        else c.startService(i);
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null || nm.getNotificationChannel(CHANNEL) != null) return;
        NotificationChannel ch = new NotificationChannel(CHANNEL, "Scans",
                NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("ZeroSploit scan progress");
        ch.setShowBadge(false);
        nm.createNotificationChannel(ch);
    }

    private Notification build(String title, String text) {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, flags);

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
        }
        b.setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentIntent(pi)
                .setOngoing(true)
                .setShowWhen(false);
        return b.build();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
