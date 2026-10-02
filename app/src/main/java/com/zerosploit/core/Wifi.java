package com.zerosploit.core;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Access-point enumeration through the Android framework.
 *
 * <p>Native code cannot list APs: {@code SCAN_RESULTS_AVAILABLE} and
 * {@code getScanResults()} are framework APIs that require a location (or, from
 * API 33, nearby-devices) permission, so this is the one part of the Wi-Fi
 * module that lives in Java. The 802.11 injection side stays in the privileged
 * helper — this class only produces the BSSID list the deauth module needs.
 */
public final class Wifi {

    /** One visible access point, strongest first. */
    public static final class Ap {
        public final String ssid;
        public final String bssid;
        public final int level;    // dBm, negative
        public final int channel;
        public final int frequency;
        public final String caps;

        Ap(ScanResult r) {
            String s = r.SSID == null ? "" : r.SSID;
            if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
                s = s.substring(1, s.length() - 1);
            }
            this.ssid = s.isEmpty() ? "<hidden>" : s;
            this.bssid = r.BSSID == null ? "" : r.BSSID.toUpperCase();
            this.level = r.level;
            this.frequency = r.frequency;
            this.channel = channelFor(r.frequency);
            this.caps = r.capabilities == null ? "" : r.capabilities;
        }

        /** Approximate quality, mirroring what the platform shows in the UI. */
        public int bars() {
            if (level >= -55) return 4;
            if (level >= -67) return 3;
            if (level >= -78) return 2;
            return 1;
        }

        private boolean capsHas(String token) {
            return caps.contains(token);
        }

        /**
         * True when the access point offers WPA3 (SAE, or transition mode).
         *
         * <p>The platform's {@code capabilities} string names the highest AKM it
         * advertises, and a WPA3 network always has to offer at least SAE, so
         * this is a reliable read -- unlike the PMF bit below.
         */
        public boolean isWpa3() {
            return capsHas("WPA3") || capsHas("SAE");
        }

        /** True for WPA2-Personal, the case a forged deauth can still reach. */
        public boolean isWpa2Psk() {
            return !capsHas("EAP") && (capsHas("PSK") || capsHas("WPA2"));
        }

        /** True when the network is unencrypted. */
        public boolean isOpen() {
            return caps.isEmpty() || capsHas("ESS");
        }

        /**
         * Whether management frames are integrity protected (802.11w PMF).
         *
         * <p>{@link #isWpa3()} is a yes by definition: 802.11-2020 requires PMF
         * for WPA3, so a deauthentication frame that is not authenticated under
         * the PMK is discarded on arrival. That is a protocol guarantee, not a
         * guess.
         *
         * <p>For WPA2 the answer is genuinely unknown from here. PMF is
         * optional in WPA2 and the platform does not expose the RSN capabilities
         * element, so this returns false for a WPA2 network whether or not the
         * access point has it turned on. Callers must treat false on WPA2 as
         * "possibly protected", never as "not protected".
         */
        public boolean pmfGuaranteed() {
            return isWpa3();
        }

        /**
         * Why a deauthentication against this network may do nothing, or "" when
         * the network is a plausible target.
         *
         * <p>The deauth frames this app builds carry no message integrity code,
         * because producing one requires the network's pre-shared key. On a
         * network that verifies management frames there is nothing to spoof, so
         * the frame is dropped by the client without a single error being
         * reported anywhere -- the send succeeds, the counter climbs, and the
         * station stays connected. Surfacing that up front is the difference
         * between "this feature does not work here" and "this tool is broken".
         */
        public String deauthBlocker() {
            if (isOpen()) {
                return "This network is open. It has no association to tear down, "
                        + "so a deauthentication frame has nothing to interrupt.";
            }
            if (isWpa3()) {
                return "This is a WPA3 network, which requires protected management "
                        + "frames. Every deauthentication frame is discarded unless it "
                        + "carries a code derived from the network key, so it will not "
                        + "disconnect anyone.";
            }
            if (isWpa2Psk()) {
                return "WPA2 with protected management frames enabled will also discard "
                        + "these frames. Whether this access point has that on is not "
                        + "something a scan can report.";
            }
            return "WPA2 enterprise uses protected management frames on many access "
                    + "points, which would discard these frames. If the target stays "
                    + "connected, that is the likely reason.";
        }
    }

    public interface Callback {
        void onResult(List<Ap> aps, String warning);

        void onError(String message);
    }

    private static final long TIMEOUT_MS = 9000;

    private Wifi() {}

    /** @return true when the permission needed for scanning is already held. */
    public static boolean hasPermission(Context ctx) {
        String perm = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                ? Manifest.permission.NEARBY_WIFI_DEVICES
                : Manifest.permission.ACCESS_FINE_LOCATION;
        return ctx.checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED;
    }

    /** Permissions to request before scanning works on this API level. */
    public static String[] requiredPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String[]{
                    Manifest.permission.NEARBY_WIFI_DEVICES,
                    Manifest.permission.ACCESS_FINE_LOCATION};
        }
        return new String[]{Manifest.permission.ACCESS_FINE_LOCATION};
    }

    /**
     * Requests a scan and delivers the result on the main thread.
     *
     * <p>{@code startScan()} is throttled by the platform and often returns
     * false on the second call within the same window; in that case the cached
     * results are still reported, because they are the freshest data available.
     */
    /** Radio power state; a scan cannot do anything while this is false. */
    public static boolean isEnabled(Context ctx) {
        WifiManager wm = (WifiManager) ctx.getApplicationContext()
                .getSystemService(Context.WIFI_SERVICE);
        try {
            return wm != null && wm.isWifiEnabled();
        } catch (SecurityException e) {
            return false;
        }
    }

    public static void scan(final Context ctx, final Callback cb) {
        if (!hasPermission(ctx)) {
            cb.onError("Missing " + (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                    ? "Nearby devices / location" : "location") + " permission");
            return;
        }
        final Context app = ctx.getApplicationContext();
        final WifiManager wm = (WifiManager) app.getSystemService(Context.WIFI_SERVICE);
        if (wm == null) {
            cb.onError("WifiManager unavailable");
            return;
        }
        if (!wm.isWifiEnabled()) {
            cb.onError("Wi-Fi is off — enable it to enumerate access points");
            return;
        }

        final Handler main = new Handler(Looper.getMainLooper());
        final BroadcastReceiver[] rx = new BroadcastReceiver[1];
        final boolean[] done = {false};
        final IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);

        Runnable finish = () -> {
            if (done[0]) return;
            done[0] = true;
            if (rx[0] != null) {
                try {
                    app.unregisterReceiver(rx[0]);
                } catch (IllegalArgumentException ignored) {
                    // already gone
                }
                rx[0] = null;
            }
            List<ScanResult> results;
            try {
                results = wm.getScanResults();
            } catch (SecurityException e) {
                cb.onError("Permission revoked while scanning");
                return;
            }
            if (results == null || results.isEmpty()) {
                cb.onResult(new ArrayList<>(),
                        "No access points returned. Android throttles scans to roughly "
                                + "one every 15 seconds, so wait and try again.");
                return;
            }
            cb.onResult(toAps(results), null);
        };

        rx[0] = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                main.post(finish);
            }
        };
        try {
            app.registerReceiver(rx[0], filter);
        } catch (SecurityException e) {
            cb.onError("Cannot listen for scan results: " + e.getMessage());
            return;
        }

        boolean started;
        try {
            started = wm.startScan();
        } catch (SecurityException e) {
            started = false;
        }
        if (!started) {
            // Throttled or refused: the cached result set is still useful.
            main.postDelayed(finish, 400);
        }
        main.postDelayed(finish, TIMEOUT_MS);
    }

    private static List<Ap> toAps(List<ScanResult> results) {
        List<Ap> aps = new ArrayList<>(results.size());
        for (ScanResult r : results) {
            if (r.BSSID == null) continue;
            aps.add(new Ap(r));
        }
        Collections.sort(aps, new Comparator<Ap>() {
            @Override
            public int compare(Ap a, Ap b) {
                return Integer.compare(b.level, a.level);   // strongest first
            }
        });
        return aps;
    }

    /** Frequency to channel number, covering 2.4/5/6 GHz. */
    static int channelFor(int mhz) {
        if (mhz == 2484) return 14;
        if (mhz >= 2412 && mhz <= 2472) return (mhz - 2407) / 5;
        if (mhz >= 5000 && mhz <= 5900) return (mhz - 5000) / 5;
        if (mhz >= 5955 && mhz <= 7115) return (mhz - 5950) / 5;
        if (mhz == 5935) return 2;
        return 0;
    }
}
