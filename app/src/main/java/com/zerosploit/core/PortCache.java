package com.zerosploit.core;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Open-port results on disk, keyed by host.
 *
 * <p>A port scan costs minutes and its output is thrown away by anything that
 * discards the views it was drawn into. The module screen is rebuilt on every
 * push and pop, and {@link State} is process memory that a fresh
 * {@code adb install}, a rotation-driven recreate or a cold start all empty, so
 * the one expensive thing the app does was the one thing that never survived.
 *
 * <p>This holds the result of the last scan per host so the ports come back with
 * the screen. It is a cache, not a history: re-scanning overwrites the entry,
 * and an entry is dropped once {@link #MAX_HOSTS} other hosts have been
 * scanned, which keeps a long-lived install from accumulating a stale map of
 * every network it has ever seen.
 *
 * <p>Only ports the engine reported <em>open</em> are stored. Filtered ports are
 * deliberately not cached: a filtered port fed into the exploit module as a live
 * service is a false positive with a CVE attached to it, and that must not be
 * able to outlive the run that observed it.
 */
public final class PortCache {

    private PortCache() {}

    private static final String PREFS = "portscan";
    /** Comma-separated {@code host}, most recently scanned first. */
    private static final String KEY_ORDER = "order";
    private static final int MAX_HOSTS = 64;

    /** Writes a host's current open ports, newest scan first. */
    public static void save(Context c, State.Device d) {
        if (c == null || d == null || d.ip.isEmpty()) return;
        try {
            SharedPreferences p = prefs(c);
            StringBuilder sb = new StringBuilder();
            for (int port : d.openPorts) {
                if (port <= 0 || port > 65535) continue;
                if (sb.length() > 0) sb.append(',');
                sb.append(port);
                String svc = d.services.get(port);
                // Only a name that cannot contain the separator is written, so a
                // service string can never split one port into two on read-back.
                if (svc != null && !svc.isEmpty() && svc.indexOf(',') < 0
                        && svc.indexOf('|') < 0) {
                    sb.append('|').append(svc);
                }
            }
            p.edit()
                    .putString(key(d.ip), sb.toString())
                    .putLong(timeKey(d.ip), System.currentTimeMillis())
                    .apply();
            touch(p, d.ip);
        } catch (Throwable ignored) {
            // A cache that cannot be written is a missing convenience, not a
            // reason to fail a scan that already produced its results.
        }
    }

    /**
     * When the cached ports for {@code host} were observed, in epoch millis, or
     * 0 when there is no cache entry. The console prints this next to restored
     * ports: a result with no age attached reads as current, and port state
     * goes stale quietly.
     */
    public static long scannedAt(Context c, String host) {
        if (c == null || host == null || host.isEmpty()) return 0;
        try {
            return prefs(c).getLong(timeKey(host), 0L);
        } catch (Throwable t) {
            return 0L;
        }
    }

    /**
     * The cached port list for {@code host}, as port to service name, in the
     * order it was found. Does not touch any {@link State.Device}.
     *
     * <p>Separate from {@link #load} because the two answer different questions.
     * {@code load} merges into a live target and is only useful when that target
     * is missing ports; this returns the cached set itself, which is what a
     * screen has to draw. Asking {@code load} for the list to display returns
     * nothing whenever the process is still alive and the target already holds
     * the ports -- which is exactly the case the cache was added for.
     */
    public static Map<Integer, String> read(Context c, String host) {
        Map<Integer, String> out = new LinkedHashMap<>();
        if (c == null || host == null || host.isEmpty()) return out;
        try {
            String raw = prefs(c).getString(key(host), null);
            if (raw == null || raw.isEmpty()) return out;
            for (String part : raw.split(",")) {
                if (part.isEmpty()) continue;
                String svc = "";
                int bar = part.indexOf('|');
                if (bar >= 0) {
                    svc = part.substring(bar + 1);
                    part = part.substring(0, bar);
                }
                int port;
                try {
                    port = Integer.parseInt(part.trim());
                } catch (NumberFormatException ignored) {
                    continue;
                }
                if (port <= 0 || port > 65535) continue;
                out.put(port, svc);
            }
        } catch (Throwable ignored) {
            // A corrupt entry is a cold cache, not a failure.
        }
        return out;
    }

    /**
     * Merges a host's cached open ports into {@code d}, leaving ports the device
     * already knows about alone.
     *
     * @return the number of ports actually added, so the caller can tell a cache
     *         miss from a target that was already up to date
     */
    public static int load(Context c, State.Device d) {
        if (d == null) return 0;
        int added = 0;
        for (Map.Entry<Integer, String> e : read(c, d.ip).entrySet()) {
            if (d.openPorts.contains(e.getKey())) continue;
            d.openPorts.add(e.getKey());
            if (!e.getValue().isEmpty()) d.services.put(e.getKey(), e.getValue());
            added++;
        }
        return added;
    }

    /** Forgets one host, e.g. when the user clears a target's results. */
    public static void clear(Context c, String host) {
        if (c == null || host == null || host.isEmpty()) return;
        try {
            SharedPreferences p = prefs(c);
            p.edit().remove(key(host)).remove(timeKey(host)).apply();
            touch(p, host);
        } catch (Throwable ignored) {
            // see save()
        }
    }

    private static SharedPreferences prefs(Context c) {
        return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static String key(String host) {
        return "h:" + host;
    }

    private static String timeKey(String host) {
        return "t:" + host;
    }

    /**
     * Moves a host to the front of the LRU order and evicts past the cap.
     *
     * <p>Eviction has to delete the host's port list and timestamp too, not just
     * drop its name from the order: the cap is the only thing bounding this
     * file, and an entry dropped from the order while its ports stayed on disk
     * would still be served on the next read.
     */
    private static void touch(SharedPreferences p, String host) {
        String order = p.getString(KEY_ORDER, "");
        StringBuilder sb = new StringBuilder();
        sb.append(host);
        for (String h : order.split(",")) {
            if (h.isEmpty() || h.equals(host)) continue;
            sb.append(',').append(h);
        }
        SharedPreferences.Editor e = p.edit();
        while (count(sb) > MAX_HOSTS) {
            // Drop the tail, which is the least recently scanned host.
            int cut = sb.lastIndexOf(",");
            if (cut < 0) {
                e.remove(key(sb.toString())).remove(timeKey(sb.toString()));
                sb.setLength(0);
                break;
            }
            e.remove(key(sb.substring(cut + 1))).remove(timeKey(sb.substring(cut + 1)));
            sb.setLength(cut);
        }
        e.putString(KEY_ORDER, sb.toString()).apply();
    }

    private static int count(StringBuilder sb) {
        if (sb.length() == 0) return 0;
        int n = 1;
        for (int i = 0; i < sb.length(); i++) if (sb.charAt(i) == ',') n++;
        return n;
    }
}
