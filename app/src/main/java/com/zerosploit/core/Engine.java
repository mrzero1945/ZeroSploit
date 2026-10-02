package com.zerosploit.core;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.zerosploit.util.Json;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owns the native library and funnels every engine event onto the main thread.
 *
 * <p>Events arrive on native worker threads. Screens register a {@link Listener}
 * and are called back on the main thread, so they can touch views directly.
 */
public final class Engine implements Native.Cb {

    private static final String TAG = "ZeroSploit";

    public interface Listener {
        /** @param jobId engine job id, or 0 for synchronous queries. */
        void onEvent(int jobId, String type, Object data);
    }

    private static Engine instance;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
    private final List<Map<String, Object>> logLines = new CopyOnWriteArrayList<>();
    private final AtomicBoolean ready = new AtomicBoolean(false);
    /** Captured at init so starter calls do not have to thread a Context. */
    private volatile Context app;

    private volatile String loadError;
    private volatile String helperPath;
    private volatile Object rootInfo;
    private volatile Object primaryIface;

    private Engine() {}

    public static synchronized Engine get() {
        if (instance == null) instance = new Engine();
        return instance;
    }

    /**
     * Loads {@code libzerosploit.so} and stages the privileged helper.
     * Safe to call repeatedly; runs on the main thread during startup, so the
     * helper copy is the only I/O it does.
     */
    public synchronized void init(Context context) {
        if (ready.get()) return;
        app = context.getApplicationContext();
        try {
            System.loadLibrary("zerosploit");
            try {
                helperPath = Helper.install(context.getApplicationContext());
            } catch (Throwable t) {
                // Not fatal: only the raw/802.11 modules need the helper, so the
                // rest of the app stays usable and the UI explains the gap.
                helperPath = "";
                Log.w(TAG, "privileged helper unavailable", t);
            }
            // filesDir is the app-private scratch area that native runCapture()
            // redirects command output into.
            Native.nativeInit(this, Native.Cb.class, helperPath,
                    context.getFilesDir().getAbsolutePath());
            Native.markLoaded();
            ready.set(true);
        } catch (Throwable t) {
            loadError = t.getClass().getSimpleName() + ": " + t.getMessage();
            Log.e(TAG, "native library failed to load", t);
        }
    }

    public boolean isReady() {
        return ready.get();
    }

    public String loadError() {
        return loadError;
    }

    /** @return false when the library is unavailable; check {@link #loadError()}. */
    private boolean guard(Context context) {
        if (ready.get()) return true;
        init(context);
        return ready.get();
    }

    /** Absolute path of the staged helper, or "" when it could not be unpacked. */
    public String helperPath() {
        return helperPath == null ? "" : helperPath;
    }

    /** True when root features (MITM, forge, deauth, monitor) can be used. */
    public boolean hasHelper() {
        return !helperPath().isEmpty();
    }

    public void addListener(Listener l) {
        listeners.addIfAbsent(l);
    }

    public void removeListener(Listener l) {
        listeners.remove(l);
    }

    public void shutdown() {
        if (ready.get()) {
            Native.nativeShutdown();
            ready.set(false);
        }
        listeners.clear();
    }

    // ---- event pump (called from native worker threads) -------------------
    /** Entry point invoked by the native sink; public because JNI looks it up. */
    @Override
    public void onEvent(int jobId, String type, String json) {
        final Object data;
        try {
            data = Json.parse(json);
        } catch (Throwable t) {
            // Runs on the JNI worker thread: an exception here would be cleared
            // by the native side and the event would vanish without a trace.
            Log.w(TAG, "bad payload for " + type, t);
            return;
        }
        main.post(() -> {
            if ("log".equals(type) && data instanceof Map) {
                logLines.add((Map<String, Object>) data);
                if (logLines.size() > 2000) logLines.remove(0);
            }
            if ("network".equals(type)) primaryIface = data;
            for (Listener l : listeners) {
                try {
                    l.onEvent(jobId, type, data);
                } catch (Throwable t) {
                    Log.w(TAG, "listener threw on " + type, t);
                }
            }
        });
    }

    /** Delivered on the main thread when a root probe finishes. */
    public interface RootCallback {
        void onRootInfo(Object info);
    }

    // ---- synchronous queries ---------------------------------------------
    /**
     * Asks Magisk for root. The su call blocks while the superuser prompt is on
     * screen waiting for the user, so it must never run on the main thread --
     * a 120s budget there is an immediate ANR.
     */
    public void requestRoot(RootCallback cb) {
        final Context c = app;
        if (!guard(c)) {
            if (cb != null) main.post(() -> cb.onRootInfo(null));
            return;
        }
        Thread t = new Thread(() -> {
            Object info = Json.parse(Native.nativeSync("root", ""));
            rootInfo = info;
            if (cb != null) main.post(() -> cb.onRootInfo(info));
        }, "zs-root");
        t.setDaemon(true);
        t.start();
    }

    /** Non-blocking root refresh used when a screen is shown. */
    public void refreshRoot(RootCallback cb) {
        requestRoot(cb);
    }

    public Object rootInfo(Context c) {
        if (!guard(c)) return null;
        return Json.parse(Native.nativeSync("root", ""));
    }

    public Object magiskInfo(Context c) {
        if (!guard(c)) return null;
        return Json.parse(Native.nativeSync("magisk", ""));
    }

    public Object ifaceList(Context c) {
        if (!guard(c)) return null;
        return Json.parse(Native.nativeSync("ifaces", ""));
    }

    public Object rawCaps(Context c, String iface) {
        if (!guard(c)) return null;
        return Json.parse(Native.nativeSync("rawcaps", iface == null ? "" : iface));
    }

    public Object sessionList(Context c) {
        if (!guard(c)) return null;
        return Json.parse(Native.nativeSync("sessions", ""));
    }

    public Object primaryIface(Context c) {
        if (!guard(c)) return null;
        return Json.parse(Native.nativeSync("primary", ""));
    }

    // ---- async starters ---------------------------------------------------
    public int networkInfo() {
        return guard(app) ? Native.nativeNetworkInfo() : -1;
    }

    public int discover(String cidr, int[] ports, int timeoutMs, int rounds) {
        return guard(app) ? Native.nativeDiscover(cidr, ports, timeoutMs, rounds) : -1;
    }

    public int portScan(String host, int from, int to, int timeoutMs, int threads) {
        return guard(app) ? Native.nativePortScan(host, from, to, timeoutMs, threads) : -1;
    }

    /**
     * Traces the path to {@code host} one TTL at a time.
     *
     * @param resolveMs reverse-DNS budget per hop; 0 skips resolution, which is
     *     what a run wants when the timing is the point
     */
    public int traceroute(String host, int maxHops, int port, int timeoutMs, int resolveMs) {
        return guard(app) ? Native.nativeTraceroute(host, maxHops, port, timeoutMs, resolveMs) : -1;
    }

    public int inspect(String host, int[] ports, int timeoutMs) {
        return guard(app) ? Native.nativeInspect(host, ports, timeoutMs) : -1;
    }

    public int exploits(String host, String portsCsv) {
        return guard(app) ? Native.nativeExploits(host, portsCsv) : -1;
    }

    public int loginAudit(String host, int port, String profile) {
        return guard(app) ? Native.nativeLoginAudit(host, port, profile) : -1;
    }

    public int shell(String host, int port, String user, String pass) {
        return guard(app) ? Native.nativeShell(host, port, user, pass) : -1;
    }

    public int mitmStart(String iface, String targetsCsv, int intervalMs) {
        return guard(app) ? Native.nativeMitmStart(iface, targetsCsv, intervalMs) : -1;
    }

    public int mitmSpoof(String iface, String targetsCsv, int intervalMs,
                         String spoofName, String spoofIp) {
        return guard(app) ? Native.nativeMitmSpoof(iface, targetsCsv, intervalMs,
                spoofName, spoofIp) : -1;
    }

    public int mitmStop() {
        return guard(app) ? Native.nativeMitmStop() : -1;
    }

    public int forge(String specCsv) {
        return guard(app) ? Native.nativeForge(specCsv) : -1;
    }

    public int wifiScan(String iface) {
        return guard(app) ? Native.nativeWifiScan(iface) : -1;
    }

    /**
     * Sends a deauthentication frame. With an empty {@code clientMac} the frame
     * is broadcast and every client of the access point drops; with one, only
     * that station does.
     *
     * @param freqMhz centre frequency of {@code bssid} in MHz, or 0 when unknown
     */
    public int deauth(String iface, String bssid, int intervalMs, int count,
                      String clientMac, int freqMhz) {
        return guard(app)
                ? Native.nativeDeauth(iface, bssid, intervalMs, count, clientMac, freqMhz)
                : -1;
    }

    public int deauth(String iface, String bssid, int intervalMs, int count,
                      String clientMac) {
        return deauth(iface, bssid, intervalMs, count, clientMac, 0);
    }

    /** Broadcasts to every client of the access point. */
    public int deauth(String iface, String bssid, int intervalMs, int count) {
        return deauth(iface, bssid, intervalMs, count, "", 0);
    }

    /**
     * Stations the deauth module can name a target in. {@code bssid} is required
     * unless {@code iface} is a soft AP, and {@code listenMs} sets how long the
     * monitor-mode path listens before reporting what it heard.
     *
     * @param freqMhz centre frequency to listen on in MHz, or 0 when unknown
     */
    public int staList(String iface, String bssid, int freqMhz, int listenMs) {
        return guard(app)
                ? Native.nativeStaList(iface, bssid, freqMhz, listenMs) : -1;
    }

    public int staList(String iface, String bssid, int listenMs) {
        return staList(iface, bssid, 0, listenMs);
    }

    /** Hotspot client list; a soft AP has no BSSID to watch. */
    public int staList(String iface) {
        return staList(iface, "", 0, 0);
    }

    /**
     * Switches the wifi radio off or on. Stopping it takes the hotspot down
     * entirely, which is the blunt end of the Wi-Fi Kill module.
     */
    public int radio(boolean on) {
        return guard(app) ? Native.nativeRadio(on) : -1;
    }

    public int monitor(String iface, boolean on) {
        return guard(app) ? Native.nativeMonitor(iface, on) : -1;
    }

    public int capabilities() {
        return guard(app) ? Native.nativeCapabilities() : -1;
    }

    public void cancel(Context c, int jobId) {
        if (guard(c) && jobId > 0) Native.nativeCancel(jobId);
    }

    public void cancelAll(Context c) {
        if (guard(c)) Native.nativeCancelAll();
    }

    public int activeJobs() {
        return guard(app) ? Native.nativeActiveCount() : 0;
    }
    // ---- log access -------------------------------------------------------
    public List<Map<String, Object>> logs() {
        return new ArrayList<>(logLines);
    }

    public void clearLogs() {
        logLines.clear();
    }
}
