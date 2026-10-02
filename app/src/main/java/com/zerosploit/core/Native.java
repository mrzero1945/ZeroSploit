package com.zerosploit.core;

/**
 * Raw JNI surface. Every {@code native*} starter returns a job id immediately;
 * results arrive asynchronously on {@link Cb#onEvent}.
 *
 * <p>All methods must be called after {@link Engine} has loaded the library —
 * {@code Engine} is the intended entry point and enforces that.
 */
public final class Native {

    /** Event sink invoked from the engine's worker threads. */
    public interface Cb {
        void onEvent(int jobId, String type, String json);
    }

    private static boolean loaded;

    private Native() {}

    static void markLoaded() {
        loaded = true;
    }

    public static boolean isLoaded() {
        return loaded;
    }

    /**
     * Binds the listener and records where the privileged helper was staged.
     * Call once, before any starter.
     *
     * @param cb the listener instance
     * @param cbInterface the {@code Cb} interface itself, not the concrete
     *     class. It has to be passed explicitly: {@code GetObjectClass()} hands
     *     back the runtime class, and for a lambda that is a synthetic
     *     {@code ...$$ExternalSyntheticLambda0} which does not declare
     *     {@code onEvent} with the interface descriptor. Looking the method up
     *     on the interface works for every implementation and is what
     *     {@code getMethodID} is documented to require.
     * @param helperPath absolute path of the unpacked {@code zsraw} executable,
     *     or an empty string to fall back to probing next to the library.
     */
    public static native void nativeInit(Cb cb, Class<?> cbInterface, String helperPath,
            String scratchDir);

    /** Stops all jobs, kills any root helper process, releases global refs. */
    public static native void nativeShutdown();

    public static native void nativeCancel(int jobId);

    public static native void nativeCancelAll();

    public static native int nativeActiveCount();

    // ---- async starters -------------------------------------------------
    public static native int nativeNetworkInfo();

    public static native int nativeDiscover(String cidr, int[] ports, int timeoutMs, int rounds);

    public static native int nativePortScan(String host, int from, int to, int timeoutMs, int threads);

    /**
     * UDP traceroute to {@code host}.
     *
     * @param maxHops highest TTL to probe
     * @param port closed port the probes aim at; the destination's ICMP
     *     port-unreachable is what ends the trace
     * @param resolveMs reverse-DNS budget per hop, 0 to skip name resolution
     */
    public static native int nativeTraceroute(String host, int maxHops, int port,
                                              int timeoutMs, int resolveMs);

    public static native int nativeInspect(String host, int[] ports, int timeoutMs);

    public static native int nativeExploits(String host, String portsCsv);

    public static native int nativeLoginAudit(String host, int port, String profile);

    public static native int nativeShell(String host, int port, String user, String pass);

    public static native int nativeMitmStart(String iface, String targets, int intervalMs);

    /** Same capture as {@link #nativeMitmStart}, with a DNS name answered from a chosen address. */
    public static native int nativeMitmSpoof(String iface, String targets, int intervalMs,
            String spoofName, String spoofIp);

    public static native int nativeMitmStop();

    public static native int nativeForge(String specCsv);

    public static native int nativeWifiScan(String iface);

    /**
     * Sends a deauthentication frame for {@code count} frames, or until the job
     * is cancelled when {@code count} is 0.
     *
     * @param bssid the access point on a monitor-mode interface, the station to
     *     drop from a soft AP, or {@code all}
     * @param clientMac one station of that access point. Empty broadcasts, which
     *     reaches every client of the AP; a MAC here reaches only that station.
     * @param freqMhz centre frequency of {@code bssid} in MHz, or 0 when
     *     unknown. A monitor-mode radio transmits on exactly one channel, so a
     *     frame sent on the wrong one leaves the device normally and reaches
     *     nobody; the helper tunes the radio to this frequency first. A
     *     frequency rather than a channel number because channel numbers
     *     collide across bands -- 1 is both 2412 MHz and 5955 MHz.
     */
    public static native int nativeDeauth(String iface, String bssid, int intervalMs,
            int count, String clientMac, int freqMhz);

    /**
     * Stations the deauth module can name a target in, as a {@code staList}
     * event. A soft AP answers from hostapd; a station interface needs
     * {@code bssid}, because it has to listen and attribute frames itself.
     *
     * @param bssid access point to watch, or empty for a soft AP
     * @param freqMhz centre frequency to listen on in MHz, or 0 when unknown.
     *     Same reason as for {@link #nativeDeauth}: the radio hears one
     *     channel, so the wrong one yields an empty list that looks like
     *     "no clients".
     * @param listenMs how long the monitor-mode path listens before reporting
     */
    public static native int nativeStaList(String iface, String bssid, int freqMhz,
            int listenMs);

    /**
     * Turns the wifi radio off ({@code on == false}) or back on. The hotspot
     * goes down with it, so no client can reassociate.
     */
    public static native int nativeRadio(boolean on);

    public static native int nativeMonitor(String iface, boolean on);

    public static native int nativeCapabilities();

    // ---- synchronous queries --------------------------------------------
    /** ops: root | ifaces | magisk | rawcaps | sessions | primary. arg is iface for rawcaps. */
    public static native String nativeSync(String op, String arg);
}
