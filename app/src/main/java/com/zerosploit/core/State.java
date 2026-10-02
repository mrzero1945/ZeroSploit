package com.zerosploit.core;

import com.zerosploit.util.Json;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Process-wide scan state shared between screens.
 *
 * <p>The engine is stateless between calls, so whatever one screen learns
 * (interfaces, discovered devices, the selected target) has to live somewhere
 * the next screen can read. Everything is main-thread only: events are already
 * delivered on the main thread by {@link Engine}.
 */
public final class State {

    private State() {}

    public static final class Iface {
        public String name = "";
        public String ip = "";
        public String netmask = "";
        public String mac = "";
        public String cidr = "";
        public String gateway = "";
        public String bssid = "";
        public String ssid = "";
        public int prefix = 24;
        public boolean isWifi;
        public boolean isUp;
        /** False for interfaces the radio holds but that carry no address. */
        public boolean hasIp = true;
        /**
         * Kernel bookkeeping interfaces (tunnels, dummy, loopback). They are
         * real but never a scan target, and this device reports 38 of them,
         * which buried everything useful below the fold.
         */
        public boolean virtual;
        public boolean isGateway;
        public String error = "";

        public static Iface from(Object o) {
            Iface i = new Iface();
            i.name = Json.str(o, "name", "");
            i.hasIp = !Json.str(o, "ip", "").isEmpty();
            i.virtual = VIRTUAL_PREFIXES.stream().anyMatch(i.name::startsWith);
            i.ip = Json.str(o, "ip", "");
            i.netmask = Json.str(o, "netmask", "");
            i.mac = Json.str(o, "mac", "");
            i.cidr = Json.str(o, "cidr", "");
            i.gateway = Json.str(o, "gateway", "");
            i.bssid = Json.str(o, "bssid", "");
            i.ssid = Json.str(o, "ssid", "");
            i.prefix = Json.i(o, "prefix", 24);
            i.isWifi = Json.b(o, "isWifi", false);
            i.isUp = Json.b(o, "isUp", false);
            i.isGateway = Json.b(o, "isGateway", false);
            i.error = Json.str(o, "error", "");
            return i;
        }
    }

    public static final class Device {
        public String ip = "";
        public String mac = "";
        public String vendor = "";
        public String hostname = "";
        public String kind = "unknown";
        public boolean isGateway;
        public boolean alive;
        public String source = "";
        public boolean isWifi;
        /** BSSID of the AP this device was seen on; empty for non-802.11 sources. */
        public String bssid = "";
        public double rttMs;
        public final List<Integer> openPorts = new ArrayList<>();
        public final Map<Integer, String> services = new LinkedHashMap<>();

        public static Device from(Object o) {
            Device d = new Device();
            d.ip = Json.str(o, "ip", "");
            d.mac = Json.str(o, "mac", "");
            d.vendor = Json.str(o, "vendor", "");
            d.hostname = Json.str(o, "hostname", "");
            d.kind = Json.str(o, "kind", "unknown");
            d.isGateway = Json.b(o, "isGateway", false);
            d.alive = Json.b(o, "alive", false);
            d.source = Json.str(o, "source", "");
            d.bssid = Json.str(o, "bssid", "");
            d.isWifi = Json.b(o, "isWifi", !d.bssid.isEmpty());
            d.rttMs = Json.d(o, "rttMs", 0);
            List<Object> ports = Json.arr(Json.obj(o) == null ? null : Json.obj(o).get("openPorts"));
            if (ports != null) {
                for (Object p : ports) {
                    try {
                        d.openPorts.add((int) Double.parseDouble(String.valueOf(p)));
                    } catch (NumberFormatException ignored) {
                        // skip malformed entry
                    }
                }
            }
            return d;
        }

        /** Best available human label, in priority order. */
        public String label() {
            if (!hostname.isEmpty()) return hostname;
            if (!vendor.isEmpty()) return vendor;
            return kind.isEmpty() ? ip : kind;
        }
    }

    // ---- shared state -----------------------------------------------------
    public static final List<Iface> ifaces = new ArrayList<>();
    public static final List<Device> devices = new ArrayList<>();
    public static Device target;
    public static String primaryIface = "";
    public static String primaryCidr = "";
    public static String gateway = "";
    public static boolean rootGranted;
    public static String rootManager = "none";
    public static String rootDetail = "";

    /** Access points seen by the last WifiManager scan, strongest first. */
    public static final List<Wifi.Ap> aps = new ArrayList<>();

    /** Interface name prefixes that never make sense as a scan target. */
    private static final List<String> VIRTUAL_PREFIXES = java.util.Arrays.asList(
            "lo", "dummy", "gre", "gretap", "tunl", "tun", "sit", "ifb", "erspan",
            "ip6", "ip_vti", "p2p");

    /** True when the row is worth showing without the "show all" toggle. */
    public static boolean worthShowing(Iface i) {
        return !i.virtual && (i.hasIp || i.isWifi || i.isUp);
    }

    /**
     * Wireless interfaces, for the Wi-Fi module's interface picker. The soft-AP
     * interface (ap0) is included when the driver has it: it is a different
     * radio role from wlan0 and deauth on it goes through hostapd, so it has to
     * be selectable rather than folded into the station interface.
     */
    public static List<Iface> wirelessIfaces() {
        List<Iface> out = new ArrayList<>();
        for (Iface i : ifaces) {
            if (i.virtual) continue;
            if (i.isWifi || i.name.startsWith("wlan") || softApName(i.name)) {
                out.add(i);
            }
        }
        return out;
    }

    /**
     * The driver names the soft-AP role ap0/ap1, not apn0 (the packet log) and
     * not anything else starting with "ap", so the digit has to be there.
     */
    public static boolean softApName(String name) {
        return name.length() > 2 && name.startsWith("ap")
                && Character.isDigit(name.charAt(2));
    }

    /** BSSID chosen in the Wi-Fi module, used as the deauth target. */
    public static String selectedBssid = "";

    private static int discoverJob;
    private static final List<Device> found = new ArrayList<>();

    public static int discoverJob() {
        return discoverJob;
    }

    public static void beginDiscover(int jobId) {
        discoverJob = jobId;
        found.clear();
        devices.clear();
    }

    public static void addFound(Device d) {
        for (Device existing : found) {
            if (existing.ip.equals(d.ip)) {
                // Merge: keep the richer of the two records.
                if (d.hostname.isEmpty()) d.hostname = existing.hostname;
                if (d.vendor.isEmpty()) d.vendor = existing.vendor;
                if (d.mac.isEmpty()) d.mac = existing.mac;
                if (d.kind.equals("unknown")) d.kind = existing.kind;
                for (int p : existing.openPorts) d.openPorts.add(p);
                d.services.putAll(existing.services);
                found.set(found.indexOf(existing), d);
                return;
            }
        }
        found.add(d);
    }

    public static void endDiscover() {
        devices.clear();
        devices.addAll(found);
        discoverJob = 0;
    }

    public static void setInterfaces(Object payload) {
        ifaces.clear();
        List<Object> items = Json.arr(Json.obj(payload) == null ? null : Json.obj(payload).get("items"));
        if (items == null) return;
        for (Object o : items) {
            Iface i = Iface.from(o);
            if (i.name.isEmpty()) continue;
            ifaces.add(i);
            if (i.isGateway) {
                gateway = i.gateway.isEmpty() ? gateway : i.gateway;
            }
        }
        primaryIface = "";
        primaryCidr = "";
        pickPrimary();
    }

    /**
     * Chooses the interface a scan should run on.
     *
     * <p>Preference order: the default-route interface, then a wireless one
     * that holds an address, then the narrowest non-cellular subnet. A Wi-Fi
     * interface used as a hotspot (ap0) has an address and carries the clients,
     * so it is the right target here; a cellular /8 is never a useful sweep
     * target and used to be picked because the AP interface was filtered out.
     */
    private static void pickPrimary() {
        Iface best = null;
        for (Iface i : ifaces) {
            if (!i.hasIp || i.virtual) continue;
            if (i.isGateway) { best = i; break; }
            if (best == null) {
                if (i.isWifi) best = i;
            } else if (best.isWifi && !i.isWifi && i.prefix >= 16 && best.prefix < 16) {
                // keep the wireless one unless this is a normal LAN
            }
        }
        if (best == null) {
            for (Iface i : ifaces) {
                if (!i.hasIp || i.virtual) continue;
                if (i.prefix >= 16 && (best == null || i.prefix > best.prefix)) best = i;
            }
        }
        if (best != null) {
            primaryIface = best.name;
            primaryCidr = best.cidr;
        }
    }

    /**
     * Makes {@code name} the interface discovery runs on. Refuses an interface
     * with no address rather than falling back silently, so the UI can say why
     * wlan0 cannot be swept while it is down.
     */
    public static boolean selectIface(String name) {
        for (Iface i : ifaces) {
            if (!i.name.equals(name)) continue;
            primaryIface = i.name;
            primaryCidr = i.cidr;
            return i.hasIp;
        }
        return false;
    }

    public static Iface iface(String name) {
        for (Iface i : ifaces) if (i.name.equals(name)) return i;
        return null;
    }

    public static void setRoot(Object payload) {
        if (payload == null) return;
        // The capabilities payload uses rootGranted/rootManager/rootDetail, the
        // root payload granted/manager/detail. Absent keys must not reset known
        // state, or a capabilities event arriving mid-session flips the UI back
        // to "USER" right after root was granted.
        if (Json.has(payload, "granted")) {
            rootGranted = Json.b(payload, "granted", false);
        } else if (Json.has(payload, "rootGranted")) {
            rootGranted = Json.b(payload, "rootGranted", false);
        }
        if (Json.has(payload, "manager")) {
            rootManager = Json.str(payload, "manager", "none");
        } else if (Json.has(payload, "rootManager")) {
            rootManager = Json.str(payload, "rootManager", "none");
        }
        if (Json.has(payload, "detail")) {
            rootDetail = Json.str(payload, "detail", "");
        } else if (Json.has(payload, "rootDetail")) {
            rootDetail = Json.str(payload, "rootDetail", "");
        }
    }

    public static Device findByIp(String ip) {
        for (Device d : devices) {
            if (d.ip.equals(ip)) return d;
        }
        return null;
    }

    public static void clearDevices() {
        devices.clear();
        found.clear();
        target = null;
    }

    public static List<Device> sorted() {
        // found is the live accumulator, so rows appear as the sweep reports
        // them; devices is only the end-of-job copy of the same records.
        List<Device> copy = new ArrayList<>(found);
        Collections.sort(copy, (a, b) -> {
            if (a.isGateway != b.isGateway) return a.isGateway ? -1 : 1;
            return a.ip.compareTo(b.ip);
        });
        return copy;
    }
}
