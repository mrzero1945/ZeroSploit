package com.zerosploit.ui;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.zerosploit.core.Engine;
import com.zerosploit.core.PortCache;
import com.zerosploit.core.State;
import com.zerosploit.core.Wifi;

/**
 * Module screen: hosts the eight tools. Each tool gets a form built from the
 * target's known context, then runs through the engine and renders streaming
 * results into a console at the bottom.
 */
public class ModuleScreen implements MainActivity.Screen, Engine.Listener {

    /** Request code for the location/nearby-devices grant used by the scan. */
    private static final int REQ_WIFI_SCAN = 4201;
    /**
     * How long the monitor-mode client listing listens. Long enough that a
     * station with ordinary chatty traffic gets caught, short enough that the
     * "Listing…" state does not feel broken. Only the stations that transmit
     * inside this window are found, so it is a sample and not a census.
     */
    private static final int LISTEN_MS = 6000;

    private final Context c;
    private final MainActivity act;
    private final String key;
    private final LinearLayout page;
    /** page wrapped in a scroller; this is what view() hands out. */
    private final android.widget.ScrollView root;
    private final BoundedColumn results;
    private final Widgets.Bar progress;
    private final TextView statusLine;
    private final TextView runButton;

    /**
     * The results list, with a hard ceiling on how many rows it will hold.
     *
     * Several modules stream rows in from a long-running job: MITM adds one per
     * observed packet, the port scan one per open port, the station list one per
     * client. None of them is bounded, and every row is a real View, so a busy
     * network grew the view tree until the process was killed -- with no way to
     * see the first rows any more, because the ones you care about scroll away
     * under a million identical ones. Past the ceiling this drops rows and says
     * how many, instead of pretending the run produced what it did not.
     */
    private static final class BoundedColumn extends LinearLayout {
        /** Kept in step with the helper's own flow cap, with room for the rest. */
        private static final int MAX_ROWS = 600;
        private int dropped = 0;
        private View notice;

        BoundedColumn(Context c) { super(c); setOrientation(VERTICAL); }

        @Override
        public void addView(View child, int index, android.view.ViewGroup.LayoutParams lp) {
            if (getChildCount() >= MAX_ROWS) {
                dropped++;
                showNotice();
                return;
            }
            super.addView(child, index, lp);
        }

        void clearRows() {
            dropped = 0;
            notice = null;
            super.removeAllViews();
        }

        private void showNotice() {
            if (notice != null) {
                ((TextView) notice).setText("· " + dropped
                        + " further rows hidden (list capped at " + MAX_ROWS + ")");
                return;
            }
            notice = Widgets.mono(getContext(),
                    "· " + dropped + " further rows hidden (list capped at "
                            + MAX_ROWS + ")",
                    Design.T_MONO_SM, 400, Design.ORANGE);
            super.addView(notice, getChildCount());
        }
    }

    private int job = -1;
    private boolean running;

    /**
     * Ports this screen restored from {@link PortCache}, and the run they came
     * from. Kept apart from the live results so a cache hit is never drawn as
     * though the scan that is on screen produced it.
     */
    private final java.util.List<Integer> cachedPorts = new java.util.ArrayList<>();
    /** Service names that came with {@link #cachedPorts}, for the console rows. */
    private final java.util.Map<Integer, String> cachedServices = new java.util.HashMap<>();
    /** Epoch millis of the scan behind {@link #cachedPorts}, 0 when unknown. */
    private long cachedAt;

    /**
     * The value cell of each traceroute hop row, keyed by TTL.
     *
     * <p>Reverse DNS is resolved after the trace finishes rather than during it,
     * so a hop row is built once and then rewritten when its name turns up.
     * Without this the name would either delay the timing that the module
     * exists to show, or arrive with nowhere to go.
     */
    private final java.util.Map<Integer, android.widget.TextView> hopCells =
            new java.util.HashMap<>();

    /** BSSID the Wi-Fi module will target; empty until an AP is picked. */
    private String bssid = "";
    /** Container for the access-point list, built lazily by the Wi-Fi module. */
    private LinearLayout apList;
    private TextView apStatus;
    private TextView apButton;

    // ---- Wi-Fi interface / hotspot client selection ----------------------
    /** Interface the Wi-Fi module acts on. wlan0 and ap0 are both valid. */
    private String wifiIface = "";
    /** True when the picked interface is a soft AP, as the helper reports it. */
    private boolean apMode;
    /** Stations the hotspot has associated, from the helper's `sta` command. */
    private final java.util.List<Client> clients = new java.util.ArrayList<>();
    /** MAC picked from {@link #clients}; ignored while {@link #kickAll} is set. */
    private String clientMac = "";
    /** The client whose row was tapped, kept whole so its IP can be the target. */
    private Client selectedClient;
    /** Drop every associated station instead of the one that was picked. */
    private boolean kickAll;
    /** Job id of the in-flight client listing, or -1. */
    private int staJob = -1;
    /** Job id of the in-flight radio power toggle, or -1. */
    private int radioJob = -1;

    // ---- DNS spoofing target ---------------------------------------------
    /** Exact name the spoofed resolver answers for, e.g. "intranet.acme.test". */
    private String spoofName = "";
    /** Address that name resolves to. Both fields or neither: answering nothing
     *  leaves the victim with no working DNS at all. */
    private String spoofIp = "";
    /** The two DNS inputs, kept so raw events can refresh their enablement. */
    private android.widget.EditText spoofNameIn;
    private android.widget.EditText spoofIpIn;
    /** The radio's last known on/off state as reported by the helper. */
    private boolean radioOn = true;
    private LinearLayout ifaceList;
    private LinearLayout clientList;
    private TextView clientStatus;
    private TextView clientButton;
    /** Radio power button and its status line, rebuilt with the Wi-Fi form. */
    private TextView radioPower;
    private TextView radioStatus;
    /**
     * Monitor-mode toggle and state. A station interface in managed mode is
     * filtered by the hardware down to this phone's own traffic, so both the
     * client listing and the injection that follows it need this switched on
     * first -- there is no other route to a per-client target.
     */
    private TextView monitorPower;
    private TextView monitorStatus;
    private int monitorJob = -1;
    private boolean monitorOn;
    /** Card and child holding the Wi-Fi form, so it can be rebuilt in place. */
    private LinearLayout wifiCard;
    private View wifiFormHost;
    /** Live "sent n" line, updated in place while a deauth runs. */
    private TextView statsLine;
    /**
     * Same idea for MITM and for the frame forger: both report progress on a
     * timer, and appending a row per tick buries the run under its own
     * telemetry. The lines are created on first update and then rewritten.
     */
    private TextView mitmStatsLine;
    private TextView forgeStatsLine;

    /** One station associated with the phone's own hotspot. */
    private static final class Client {
        final String mac;
        final String ip;
        final int signal;
        final boolean hasSignal;

        Client(String mac, String ip, int signal, boolean hasSignal) {
            this.mac = mac;
            this.ip = ip;
            this.signal = signal;
            this.hasSignal = hasSignal;
        }

        static Client from(Object o) {
            return new Client(
                    com.zerosploit.util.Json.str(o, "mac", ""),
                    com.zerosploit.util.Json.str(o, "ip", ""),
                    com.zerosploit.util.Json.i(o, "signal", 0),
                    com.zerosploit.util.Json.b(o, "hasSignal", false));
        }
    }

    public ModuleScreen(MainActivity act, String key) {
        this.act = act;
        this.key = key;
        this.c = act;

        // Before configCard(), because the card renders the target's open ports
        // and a screen that is rebuilt from a cache has to show what the cache
        // holds -- not build itself around an empty list and fill it in later.
        restoreCached();

        LinearLayout content = Widgets.column(c);
        page = content;
        root = Widgets.scroller(c, page);
        content.addView(Widgets.navBar(c, Design.moduleLabel(key), targetSub(), true, v -> act.pop()));

        int accent = Design.moduleColor(key);
        int iconRes = Design.moduleIcon(key);
        if (iconRes != 0) {
            LinearLayout iconRow = Widgets.row(c);
            iconRow.setGravity(Gravity.CENTER);
            iconRow.addView(Widgets.icon(c, iconRes, accent),
                    new LinearLayout.LayoutParams(Widgets.dp(c, 40), Widgets.dp(c, 40)));
            content.addView(iconRow, margin(0, 10, 0, 0, 0));
        }

        content.addView(configCard(accent));

        progress = new Widgets.Bar(c);
        content.addView(progress, margin(16, 12, 6, 0, 0));
        statusLine = Widgets.mono(c, "ready", Design.T_MONO_SM, 400, Design.TEXT_3);
        content.addView(statusLine, margin(16, 6, 6, 0, 0));

        runButton = Widgets.button(c, runLabel(), 0, accent);
        runButton.setOnClickListener(v -> toggle());
        content.addView(runButton, margin(16, 12, 16, 0, 0));

        content.addView(Widgets.sectionHeader(c, "Console"));
        results = new BoundedColumn(c);
        results.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        results.setPadding(Widgets.dp(c, 12), Widgets.dp(c, 12), Widgets.dp(c, 12), Widgets.dp(c, 12));
        content.addView(results, margin(16, 0, 16, 0, 0));

        renderCached();
    }

    /**
     * Puts the target's last scan back on screen.
     *
     * <p>This is the whole reason the cache exists: a scan is minutes of work
     * and the screen holding it is disposable. Popping back to the tab and
     * pushing the module again used to come up with an empty console and a
     * target that looked like it had never been touched, so the only way to see
     * the ports again was to spend the minutes finding them a second time.
     *
     * <p>The list drawn is the cached set itself, not the set of ports this call
     * happened to add. The common case is a live process whose target still
     * holds every port, so a merge-and-report-what-changed would report nothing
     * and draw nothing while the data sat right there in memory.
     *
     * <p>Loaded into {@link State.Device} as well as drawn, because the other
     * modules read the ports off the target rather than off this screen: the
     * service inspector and the exploit finder are handed {@code openPorts},
     * and an empty list there is not a cache miss, it is a refusal to run.
     */
    private void restoreCached() {
        State.Device d = State.target;
        if (d == null || d.ip.isEmpty()) return;
        java.util.Map<Integer, String> cached = PortCache.read(c, d.ip);
        if (cached.isEmpty()) return;
        cachedAt = PortCache.scannedAt(c, d.ip);
        cachedServices.clear();
        cachedServices.putAll(cached);
        cachedPorts.addAll(cached.keySet());
        PortCache.load(c, d);
    }

    /** Draws the restored ports, dated, so they cannot pass for a live run. */
    private void renderCached() {
        if (cachedPorts.isEmpty()) return;
        State.Device d = State.target;
        String age = cachedAt > 0 ? relativeAge(cachedAt) : "earlier";
        results.addView(Widgets.kvRow(c, "cache",
                cachedPorts.size() + " open port(s) from " + (d == null ? "?" : d.ip)
                        + " · scanned " + age, Design.TEXT_2));
        for (int p : cachedPorts) {
            String svc = cachedServices.getOrDefault(p, "");
            if (svc.isEmpty() && d != null) svc = d.services.getOrDefault(p, "");
            results.addView(Widgets.kvRow(c, "port " + p,
                    svc.isEmpty() ? "open" : svc, Design.GREEN));
        }
    }

    /** Coarse "how long ago", which is the only precision a cache hit needs. */
    static String relativeAge(long then) {
        long s = Math.max(0, (System.currentTimeMillis() - then) / 1000);
        if (s < 60) return s + "s ago";
        if (s < 3600) return (s / 60) + "m ago";
        if (s < 86400) return (s / 3600) + "h ago";
        return (s / 86400) + "d ago";
    }

    private String targetSub() {
        return State.target == null ? "no target" : State.target.ip;
    }

    private String runLabel() {
        switch (key) {
            case "portscan": return "Start Port Scan";
            case "trace": return "Start Traceroute";
            case "service": return "Inspect Services";
            case "exploit": return "Find Exploits";
            case "login": return "Audit Logins";
            case "sessions": return "Open Session";
            case "mitm": return "Start MITM";
            case "sniffer": return "Start Sniffing";
            case "dns": {
                // Read the fields themselves rather than the values cached at
                // start(), so the label tracks typing rather than the last run.
                String n = spoofNameIn != null
                        ? spoofNameIn.getText().toString().trim() : spoofName;
                String a = spoofIpIn != null
                        ? spoofIpIn.getText().toString().trim() : spoofIp;
                if (n.isEmpty()) return "Set a name to spoof";
                if (a.isEmpty()) return "Set an address to answer with";
                return "Start DNS Spoofing";
            }
            case "hijack": return "Analyse TLS Sessions";
            case "forger": return "Send Frame";
            case "wifi":
                if (!apMode) {
                    // A named station is the interesting case and it is the whole
                    // reason the label has to differ: one client drops instead of
                    // the network, and the button should say which.
                    if (bssid.isEmpty()) return "Pick an Access Point";
                    if (kickAll) return "Deauthenticate All Clients";
                    if (!clientMac.isEmpty()) return "Deauthenticate " + clientMac;
                    return "Deauthenticate";
                }
                if (kickAll) return "Kick All Clients";
                if (clientMac.isEmpty()) return "Pick a Client";
                // Names the address that will actually be deauthenticated, not
                // the MAC behind it.
                String t = wifiTarget();
                return "Kick " + t;
            default: return "Run";
        }
    }

    /** Repaints the run button after the target changed under the user's finger. */
    private void updateRunLabel() {
        if (running || runButton == null) return;
        runButton.setText(runLabel());
    }

    /**
     * What the deauth helper is pointed at: a BSSID on a station interface, a
     * client MAC on the phone's own hotspot, or {@code all} for every station
     * the hotspot has associated. Empty when nothing has been picked yet.
     */
    private String wifiTarget() {
        if (!apMode) return bssid;
        if (kickAll) return "all";
        // The IP is sent as the target, not the MAC. The helper resolves it to
        // the station holding that address at kick time, so the frame cannot
        // drift onto a different client between listing and pressing the
        // button. A client with no address yet falls back to its MAC.
        if (selectedClient != null && !selectedClient.ip.isEmpty()) {
            return selectedClient.ip;
        }
        return clientMac;
    }

    /**
     * Centre frequency of the picked access point in MHz, or 0 when unknown.
     *
     * <p>Both injection and sniffing depend on this. A monitor-mode radio
     * handles exactly one channel and never scans, so the helper tunes it to
     * this frequency before sending or listening. Without it the run still
     * reports success -- frames leave the device and reach nobody, and a client
     * listing comes back empty for reasons that look exactly like "no clients".
     *
     * <p>The frequency is used rather than {@link Wifi.Ap#channel} because the
     * channel number is not unique: 6 GHz channel 1 and 2.4 GHz channel 1 are
     * both "1", and by the time the number reaches the helper the band it came
     * from is gone.
     *
     * <p>Read back out of {@link State#aps} rather than kept in a field: the
     * scan is what knows the frequency, and a second copy would be able to
     * disagree with the access point list on screen.
     */
    private int targetFrequency() {
        for (Wifi.Ap ap : State.aps) {
            if (ap.bssid.equals(bssid)) return ap.frequency;
        }
        return 0;
    }

    /** The picked access point, or null when none is selected or the scan aged out. */
    private Wifi.Ap targetAp() {
        for (Wifi.Ap ap : State.aps) {
            if (ap.bssid.equals(bssid)) return ap;
        }
        return null;
    }

    /**
     * The one station to drop, on a monitor-mode interface.
     *
     * <p>Empty means the broadcast frame, which is the pre-existing behaviour:
     * every client of the access point receives it. A soft AP never gets one --
     * there the target already names the station and hostapd drops exactly that
     * one, so a second address would be a conflicting instruction rather than a
     * narrower one.
     */
    private String wifiClient() {
        if (apMode || kickAll || clientMac.isEmpty()) return "";
        return clientMac;
    }

    // ---- per-module configuration forms -----------------------------------
    private View configCard(int accent) {
        LinearLayout card = Widgets.column(c);
        card.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        card.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 14), Widgets.dp(c, 16), Widgets.dp(c, 14));

        String host = State.target == null ? "" : State.target.ip;
        card.addView(kvRow("target", host, Design.TEXT));
        if (State.target != null && !State.target.openPorts.isEmpty()) {
            StringBuilder ps = new StringBuilder();
            for (int i = 0; i < State.target.openPorts.size(); i++) {
                if (i > 0) ps.append(", ");
                ps.append(State.target.openPorts.get(i));
            }
            card.addView(kvRow("open", ps.toString(), Design.GREEN));
        }

        if (key.equals("portscan")) {
            card.addView(Widgets.label(c, "Range 1–65535, threaded TCP connect.",
                    Design.T_FOOTNOTE, 400, Design.TEXT_2));
        } else if (key.equals("trace")) {
            card.addView(Widgets.label(c,
                    "Up to 30 hops, 1.2 s per hop, no reverse DNS — the timings are the point. "
                            + "A blank hop is a router that did not answer, which is a result, not a failure.",
                    Design.T_FOOTNOTE, 400, Design.TEXT_2));
        } else if (key.equals("service") || key.equals("exploit")) {
            card.addView(Widgets.label(c,
                    State.target != null && State.target.openPorts.isEmpty()
                            ? "No ports known yet — run a port scan or discovery first."
                            : "Runs against the target's discovered open ports.",
                    Design.T_FOOTNOTE, 400, Design.TEXT_2));
        } else if (key.equals("login")) {
            card.addView(Widgets.label(c,
                    "Checks a small default-credential list. Only run against systems you administer.",
                    Design.T_FOOTNOTE, 400, Design.ORANGE));
        } else if (key.equals("sniffer")) {
            card.addView(Widgets.label(c,
                    "Reads the traffic the MITM already relays and looks for credentials "
                            + "sent in the clear — HTTP Basic and Bearer, FTP, POP3, IMAP, "
                            + "SMTP AUTH, Telnet, Redis, MQTT, PostgreSQL and SNMP. Encrypted "
                            + "logins are not recovered. Traffic on your own network only.",
                    Design.T_FOOTNOTE, 400, Design.TEXT_2));
        } else if (key.equals("hijack")) {
            // The scope is stated here rather than discovered later: this reads
            // the handshake and does not decrypt payloads, so it cannot show
            // message bodies the way cSploit's hijacker does with its own CA.
            card.addView(Widgets.banner(c,
                    "Session analyser only — reports SNI, ALPN, protocol version and "
                            + "certificate details. It does not decrypt traffic, so message "
                            + "bodies stay encrypted.",
                    Design.CYAN, true));
            card.addView(Widgets.label(c,
                    "Flags certificates that are self-signed, expired, not yet valid, or "
                            + "carrying a short RSA key. Traffic on your own network only.",
                    Design.T_FOOTNOTE, 400, Design.TEXT_2));
        } else if (key.equals("mitm") || key.equals("forger") || key.equals("wifi")
                || key.equals("sniffer") || key.equals("dns") || key.equals("hijack")) {
            if (!State.rootGranted) {
                card.addView(Widgets.banner(c,
                        "Requires root (Magisk). Grant ZeroSploit superuser access to enable.",
                        Design.ORANGE, true));
            } else {
                card.addView(Widgets.banner(c,
                        "Root granted via " + State.rootManager + ". Traffic on your own network only.",
                        Design.RED, true));
            }
            if (!Engine.get().hasHelper()) {
                // The helper ships as an asset; if it is missing, every root
                // feature below would fail with a bare exec error, so say so.
                card.addView(Widgets.banner(c,
                        "Privileged helper unavailable — reinstall the APK. "
                                + "MITM, injection and monitor mode cannot run.",
                        Design.ORANGE, true));
            }
        }
        if (key.equals("dns")) {
            // The two fields decide the button label, so every keystroke has to
            // refresh it -- otherwise the label still reads "set a name" while
            // the name is typed in.
            final android.widget.EditText nameIn = input(c, "Name to answer for",
                    "intranet.acme.test", spoofName, true);
            final android.widget.EditText ipIn = input(c, "Answer with address",
                    "10.0.0.5", spoofIp, false);
            spoofNameIn = nameIn;
            spoofIpIn = ipIn;
            card.addView(nameIn);
            card.addView(ipIn);
            card.addView(Widgets.label(c,
                    "Matches that name exactly, any case. Everything else is forwarded "
                            + "untouched, so the target keeps working on the rest of the network. "
                            + "Spoofing rides on the same ARP poisoning as the MITM.",
                    Design.T_FOOTNOTE, 400, Design.TEXT_2));
        }
        if (key.equals("wifi")) {
            wifiCard = card;
            wifiFormHost = buildWifiForm();
            card.addView(wifiFormHost);
        }
        return card;
    }

    // ---- Wi-Fi access-point picker ---------------------------------------
    // Native code cannot enumerate APs (that is a framework API), so the list
    // comes from WifiManager and the chosen BSSID is what the deauth helper
    // needs to build 802.11 frames.
    //
    // The interface comes first because it decides what the rest of the form
    // means: on a soft AP (ap0) there are no APs to pick at all, the clients are
    // the phone's own hotspot users and hostapd is what drops them.
    // ---- free-text field ---------------------------------------------------
    // A single-line EditText that matches the card styling instead of the
    // platform's, which would be the one light-on-white control left in an
    // otherwise black UI. The caller reads the value back on start rather than
    // on every keystroke, so the field itself stays a dumb holder.
    private android.widget.EditText input(Context c, String hint, String sample,
                                          String value, boolean mono) {
        android.widget.EditText in = new android.widget.EditText(c);
        int pad = Widgets.dp(c, 14);
        in.setSingleLine(true);
        in.setText(value);
        in.setHint(hint);
        in.setHintTextColor(Design.TEXT_4);
        in.setTextSize(mono ? 13 : 15);
        in.setTextColor(Design.TEXT);
        in.setTypeface(mono
                ? android.graphics.Typeface.MONOSPACE
                : android.graphics.Typeface.DEFAULT);
        in.setPadding(pad, pad, pad, pad);
        in.setBackground(Widgets.round(Design.FILL_2, Widgets.dp(c, Design.R_CONTROL)));
        in.setTag(sample);
        // runLabel() reads the two DNS fields, so the button has to be relabelled
        // as they change. Without this the label still reads "set a name" with a
        // valid name typed in, which sends people looking for a control that is
        // already correct.
        in.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) {}
            @Override public void afterTextChanged(android.text.Editable e) {
                if (key.equals("dns")) updateRunLabel();
            }
        });
        LinearLayout.LayoutParams lp =
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = Widgets.dp(c, 6);
        lp.bottomMargin = Widgets.dp(c, 6);
        in.setLayoutParams(lp);
        return in;
    }

    private View buildWifiForm() {
        LinearLayout box = Widgets.column(c);

        // The two forms hold each other's views out of scope: a field left
        // pointing at a detached TextView would silently swallow the next
        // status update.
        apButton = null;
        apStatus = null;
        apList = null;
        clientButton = null;
        clientStatus = null;
        clientList = null;
        monitorPower = null;
        monitorStatus = null;

        if (wifiIface.isEmpty()) wifiIface = defaultWifiIface();
        box.addView(Widgets.label(c, "Interface", Design.T_FOOTNOTE, 600, Design.TEXT_2),
                margin(0, 12, 0, 0, 0));
        ifaceList = Widgets.column(c);
        box.addView(ifaceList, margin(0, 6, 0, 0, 0));
        renderIfaces();

        if (apMode) {
            addClientList(box, "Hotspot clients",
                    "hostapd holds the association table for the phone's own "
                            + "hotspot, so this list is the whole truth about "
                            + "who is on it.");
        } else {
            apButton = Widgets.button(c, "Scan Access Points", 0, Design.moduleColor(key));
            apButton.setOnClickListener(v -> requestScan((MainActivity) c));
            box.addView(apButton, margin(0, 12, 0, 0, 0));

            apStatus = Widgets.mono(c, "no scan yet", Design.T_MONO_SM, 400, Design.TEXT_3);
            box.addView(apStatus, margin(0, 8, 0, 0, 0));

            apList = Widgets.column(c);
            if (!State.aps.isEmpty()) showAps(State.aps, null);
            box.addView(apList, margin(0, 8, 0, 0, 0));

            addMonitorPower(box);
            addClientList(box, "Access point clients",
                    "Nobody owns the association table of an access point that is "
                            + "not the phone's own, so this list is built by "
                            + "listening in monitor mode and attributing frames "
                            + "to the access point above. A station that has "
                            + "associated but is idle during the listen window "
                            + "will not appear.");
        }

        addRadioPower(box);
        return box;
    }

    /**
     * The station picker, shared by both forms.
     *
     * <p>It reads the same {@code staList} event either way and means the same
     * thing by a row: tap one to name that station as the deauth target, or
     * leave it on "All clients" to fall back to the whole access point. What
     * differs is only where the list came from, which is why the explanation
     * differs -- on a foreign AP the list is an observation and is missing
     * silent clients, while the hotspot's is a table and is not.
     */
    private void addClientList(LinearLayout box, String title, String blurb) {
        box.addView(Widgets.label(c, title, Design.T_FOOTNOTE, 600, Design.TEXT_2),
                margin(0, 16, 0, 0, 0));
        clientButton = Widgets.button(c, "List Clients", 1, Design.moduleColor(key));
        clientButton.setOnClickListener(v -> requestStaList());
        box.addView(clientButton, margin(0, 6, 0, 0, 0));
        clientStatus = Widgets.mono(c, "not listed yet", Design.T_MONO_SM, 400,
                Design.TEXT_3);
        box.addView(clientStatus, margin(0, 8, 0, 0, 0));
        box.addView(Widgets.label(c, blurb, Design.T_FOOTNOTE, 400, Design.TEXT_3),
                margin(0, 8, 0, 0, 0));
        clientList = Widgets.column(c);
        box.addView(clientList, margin(0, 8, 0, 0, 0));
        renderClients();
    }

    /**
     * Monitor mode on the picked station interface.
     *
     * <p>This is the gate on the whole per-client path rather than an
     * optimisation: a managed-mode radio is filtered in hardware to this phone's
     * own traffic, so the client listing would come back empty and the
     * deauthentication frame could not be injected at all. It is a plain toggle
     * because it has a visible side effect -- the phone drops off the network it
     * is on while the interface is off the managed role.
     */
    private void addMonitorPower(LinearLayout box) {
        box.addView(Widgets.label(c, "Monitor mode", Design.T_FOOTNOTE, 600,
                Design.TEXT_2), margin(0, 20, 0, 0, 0));
        monitorPower = Widgets.button(c, monitorOn ? "Stop Monitor Mode" : "Start Monitor Mode",
                0, Design.moduleColor(key));
        monitorPower.setOnClickListener(v -> requestMonitor(!monitorOn));
        box.addView(monitorPower, margin(0, 6, 0, 0, 0));
        monitorStatus = Widgets.mono(c, monitorOn
                        ? "on — this phone is off the network it was on"
                        : "off — only this phone's own traffic is visible",
                Design.T_MONO_SM, 400, Design.TEXT_3);
        box.addView(monitorStatus, margin(0, 8, 0, 0, 0));
    }

    private void requestMonitor(boolean on) {
        if (monitorJob > 0) Engine.get().cancel(c, monitorJob);
        if (!State.rootGranted) {
            setMonitorState("needs root to change the interface type", Design.ORANGE);
            return;
        }
        if (!Engine.get().hasHelper()) {
            setMonitorState("privileged helper missing", Design.ORANGE);
            return;
        }
        if (monitorPower != null) {
            monitorPower.setEnabled(false);
            monitorPower.setText(on ? "Starting…" : "Stopping…");
        }
        setMonitorState("asking the driver for " + (on ? "monitor" : "managed")
                + " mode…", Design.TEXT_3);
        int id = Engine.get().monitor(wifiIface, on);
        if (id < 0) {
            if (monitorPower != null) {
                monitorPower.setEnabled(true);
                monitorPower.setText(monitorOn ? "Stop Monitor Mode" : "Start Monitor Mode");
            }
            setMonitorState(Engine.get().isReady() ? "Engine busy"
                    : String.valueOf(Engine.get().loadError()), Design.ORANGE);
            return;
        }
        monitorJob = id;
    }

    /**
     * Handles the helper's {@code monitorResult}. Leaving monitor mode also
     * invalidates the station list, which was read in the mode we just left, so
     * it is dropped rather than left on screen looking current.
     */
    private void onMonitorResult(Object data) {
        monitorJob = -1;
        boolean ok = com.zerosploit.util.Json.b(data, "ok", false);
        monitorOn = com.zerosploit.util.Json.b(data, "monitorMode", false);
        String msg = com.zerosploit.util.Json.str(data, "msg", "");
        String method = com.zerosploit.util.Json.str(data, "method", "");
        // The helper reports which interface monitor mode actually landed on.
        // Usually that is a second virtual interface it created, with the
        // original left associated; when the driver refused one, it is the
        // original and this device has just gone off the network. Everything
        // downstream has to use whichever it is, or the frames go out on an
        // interface that is not even in monitor mode.
        String iface = com.zerosploit.util.Json.str(data, "iface", "");
        if (monitorOn && !iface.isEmpty()) wifiIface = iface;
        if (monitorPower != null) {
            monitorPower.setEnabled(true);
            monitorPower.setText(monitorOn ? "Stop Monitor Mode" : "Start Monitor Mode");
        }
        if (!monitorOn && !clients.isEmpty()) {
            clients.clear();
            clientMac = "";
            selectedClient = null;
            kickAll = false;
            renderClients();
            updateRunLabel();
        }
        boolean lostLink = com.zerosploit.util.Json.b(data, "lostLink", false);
        String text = monitorOn
                ? "on " + wifiIface + (method.isEmpty() ? "" : " via " + method)
                : "off" + (msg.isEmpty() ? "" : " · " + msg);
        if (lostLink) text += " — " + wifiIface + " was the only interface, so this "
                + "device is off the network; reconnect before scanning again";
        setMonitorState(text, ok ? Design.TEXT_3 : Design.ORANGE);
    }

    private void setMonitorState(String text, int color) {
        if (monitorStatus == null) return;
        monitorStatus.setText(text);
        monitorStatus.setTextColor(color);
    }

    /**
     * The blunt end of this module: switch the radio itself off.
     *
     * Deauthenticating clients is a scalpel, but a client that keeps its
     * credentials just rejoins. Taking the radio down does not have that
     * problem, and on a phone running the hotspot it also takes the soft AP
     * with it, so it doubles as "shut the hotspot down". The flip side is that
     * it is not selective, so it is a plain labelled button and not the primary
     * run action.
     */
    private void addRadioPower(LinearLayout box) {
        box.addView(Widgets.label(c, "Radio", Design.T_FOOTNOTE, 600, Design.TEXT_2),
                margin(0, 20, 0, 0, 0));
        radioPower = Widgets.button(c, "Stop WiFi", 0, Design.ORANGE);
        radioPower.setOnClickListener(v -> requestRadio(!radioOn));
        box.addView(radioPower, margin(0, 6, 0, 0, 0));
        radioStatus = Widgets.mono(c, "", Design.T_MONO_SM, 400, Design.TEXT_3);
        box.addView(radioStatus, margin(0, 8, 0, 0, 0));
    }

    /**
     * Runs the one-shot power job. The reply arrives as a {@code radioResult}
     * event, which is handled separately from the module's own job so a busy
     * engine cannot make the button look stuck.
     */
    private void requestRadio(boolean on) {
        if (radioJob > 0) Engine.get().cancel(c, radioJob);
        if (!State.rootGranted) {
            setRadioState("needs root to change the radio", Design.ORANGE);
            return;
        }
        if (!Engine.get().hasHelper()) {
            setRadioState("privileged helper missing", Design.ORANGE);
            return;
        }
        if (radioPower != null) {
            radioPower.setEnabled(false);
            radioPower.setText(on ? "Starting…" : "Stopping…");
        }
        setRadioState("telling the framework to " + (on ? "enable" : "disable")
                + " wifi…", Design.TEXT_3);
        int id = Engine.get().radio(on);
        if (id < 0) {
            if (radioPower != null) {
                radioPower.setEnabled(true);
                radioPower.setText(radioOn ? "Start WiFi" : "Stop WiFi");
            }
            setRadioState(Engine.get().isReady() ? "Engine busy"
                    : String.valueOf(Engine.get().loadError()), Design.ORANGE);
            return;
        }
        radioJob = id;
    }

    private void onRadioResult(Object data) {
        radioJob = -1;
        boolean ok = com.zerosploit.util.Json.b(data, "ok", false);
        radioOn = com.zerosploit.util.Json.b(data, "on", false);
        String state = com.zerosploit.util.Json.str(data, "state", "");
        String msg = com.zerosploit.util.Json.str(data, "msg", "");
        if (radioPower != null) {
            radioPower.setEnabled(true);
            radioPower.setText(radioOn ? "Start WiFi" : "Stop WiFi");
        }
        // After stopping, the interfaces and the hotspot are gone by design, so
        // the module has to forget what it was showing.
        if (!radioOn) {
            apMode = false;
            // The interfaces are gone, so there is no interface left that could
            // still be in monitor mode.
            monitorOn = false;
            clients.clear();
            clientMac = "";
            selectedClient = null;
            kickAll = false;
            setClientState("", Design.TEXT_3);
            refreshWifiForm();
        }
        String text = radioOn ? "wifi is on" : "wifi is off";
        if (!state.isEmpty()) text += " · interfaces " + state;
        if (!msg.isEmpty() && !ok) text += " · " + msg;
        setRadioState(text, ok ? Design.TEXT_3 : Design.ORANGE);
        updateRunLabel();
    }

    private void setRadioState(String text, int color) {
        if (radioStatus == null) return;
        radioStatus.setText(text);
        radioStatus.setTextColor(color);
    }

    /**
     * Rebuilds the Wi-Fi form in place. The two forms (access points vs hotspot
     * clients) cannot both live in one hierarchy, and the answer that decides
     * which one applies only arrives after the helper has been asked.
     */
    private void refreshWifiForm() {
        if (wifiCard == null || wifiFormHost == null) return;
        int index = wifiCard.indexOfChild(wifiFormHost);
        if (index < 0) return;
        wifiCard.removeView(wifiFormHost);
        View fresh = buildWifiForm();
        wifiCard.addView(fresh, index, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        wifiFormHost = fresh;
    }

    /**
     * Interface the module starts on: the one the rest of the app is already
     * using when it is wireless, else the first radio the kernel reports.
     */
    private String defaultWifiIface() {
        java.util.List<State.Iface> all = State.wirelessIfaces();
        for (State.Iface i : all) {
            if (i.name.equals(State.primaryIface)) return i.name;
        }
        return all.isEmpty() ? "wlan0" : all.get(0).name;
    }

    /** ap0/ap1 and friends: the driver names the soft-AP role like this. */
    static boolean looksLikeSoftAp(String name) {
        return State.softApName(name);
    }

    private void renderIfaces() {
        if (ifaceList == null) return;
        ifaceList.removeAllViews();
        java.util.List<State.Iface> all = State.wirelessIfaces();
        if (all.isEmpty()) {
            ifaceList.addView(Widgets.label(c,
                    "No wireless interface reported — open the Network tab first.",
                    Design.T_FOOTNOTE, 400, Design.TEXT_3),
                    lp(ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT));
            return;
        }
        for (State.Iface i : all) {
            boolean selected = i.name.equals(wifiIface);
            StringBuilder sub = new StringBuilder(i.isUp ? "up" : "down");
            if (!i.ip.isEmpty()) sub.append(" · ").append(i.ip);
            // ap0 is the soft-AP role of the same radio, not a second radio:
            // its clients are dropped through hostapd instead of injection.
            if (looksLikeSoftAp(i.name)) sub.insert(0, "soft AP · ");
            LinearLayout r = Widgets.listRow(c, i.name, sub.toString(),
                    selected ? Design.moduleColor(key) : Design.TEXT_3, null);
            if (selected) {
                r.setBackground(Widgets.round(
                        Design.withAlpha(Design.moduleColor(key), 40),
                        Widgets.dp(c, Design.R_CARD)));
            }
            final String name = i.name;
            r.setOnClickListener(v -> onIfacePicked(name));
            ifaceList.addView(r);
        }
    }

    /** Switching interface re-asks the helper what that interface is. */
    private void onIfacePicked(String name) {
        if (name.equals(wifiIface)) return;
        wifiIface = name;
        apMode = false;
        clients.clear();
        clientMac = "";
        selectedClient = null;
        kickAll = false;
        refreshWifiForm();
        updateRunLabel();
        requestStaList();
    }

    /**
     * Asks the helper which stations the deauth module can name a target in.
     *
     * <p>On a soft AP that is hostapd's association table. On a station
     * interface it is a monitor-mode capture of {@link #LISTEN_MS}, and it
     * needs a BSSID to attribute frames to.
     *
     * <p>Monitor mode is not gated on the locally-tracked {@link #monitorOn}:
     * that flag can be stale the moment somebody changes the interface
     * elsewhere, and refusing here would block a capture that would have worked.
     * The helper is the single authority, and its NOT_MONITOR answer is
     * forwarded to the status line rather than swallowed.
     */
    private void requestStaList() {
        if (staJob > 0) Engine.get().cancel(c, staJob);
        if (!apMode && bssid.isEmpty()) {
            setClientState("pick an access point first", Design.ORANGE);
            return;
        }
        if (!State.rootGranted) {
            if (clientStatus != null) {
                clientStatus.setText(apMode ? "needs root to read hostapd"
                        : "needs root to listen on the air");
            }
            return;
        }
        if (!Engine.get().hasHelper()) {
            if (clientStatus != null) clientStatus.setText("privileged helper missing");
            return;
        }
        if (clientButton != null) {
            clientButton.setEnabled(false);
            clientButton.setText("Listing…");
        }
        if (clientStatus != null) {
            clientStatus.setText(apMode ? "reading " + wifiIface + "…"
                    : "listening " + LISTEN_MS / 1000 + "s for " + wifiIface + "…");
        }
        int id = apMode ? Engine.get().staList(wifiIface)
                : Engine.get().staList(wifiIface, bssid, targetFrequency(), LISTEN_MS);
        if (id < 0) {
            if (clientButton != null) {
                clientButton.setEnabled(true);
                clientButton.setText("List Clients");
            }
            if (clientStatus != null) clientStatus.setText(Engine.get().isReady()
                    ? "Engine busy" : String.valueOf(Engine.get().loadError()));
            return;
        }
        staJob = id;
    }

    private void onStaList(Object data) {
        staJob = -1;
        if (clientButton != null) {
            clientButton.setEnabled(true);
            clientButton.setText("List Clients");
        }
        String msg = com.zerosploit.util.Json.str(data, "msg", "");
        if ("error".equals(com.zerosploit.util.Json.str(data, "type", ""))) {
            setClientState(com.zerosploit.util.Json.str(data, "msg", "failed"),
                    Design.ORANGE);
            return;
        }
        boolean wasAp = apMode;
        apMode = com.zerosploit.util.Json.b(data, "apMode", false);
        String source = com.zerosploit.util.Json.str(data, "source", "");
        clients.clear();
        java.util.List<Object> items = com.zerosploit.util.Json.arr(
                com.zerosploit.util.Json.obj(data) == null ? null
                        : com.zerosploit.util.Json.obj(data).get("clients"));
        if (items != null) {
            for (Object o : items) {
                Client cl = Client.from(o);
                if (!cl.mac.isEmpty()) clients.add(cl);
            }
        }
        clientMac = "";
        selectedClient = null;
        kickAll = false;
        if (apMode != wasAp) {
            // The interface turned out to be a soft AP after all, so the access
            // point form is the wrong one; rebuild it as a client list.
            refreshWifiForm();
        } else {
            renderClients();
        }
        updateRunLabel();
        setClientState(clientSummary() + (msg.isEmpty() ? "" : " · " + msg),
                msg.isEmpty() || "hostapd".equals(source) ? Design.TEXT_3 : Design.ORANGE);
    }

    private String clientSummary() {
        // On a station interface the list belongs to the picked access point, not
        // to the interface, and naming it stops the two being confused.
        String where = apMode ? wifiIface : bssid;
        if (clients.isEmpty()) return "no station heard on " + where;
        return clients.size() + " station(s) on " + where;
    }

    private void setClientState(String text, int color) {
        if (clientStatus == null) return;
        clientStatus.setText(text);
        clientStatus.setTextColor(color);
    }

    /**
     * Reports what the picked access point means for a deauthentication, before
     * the run button is pressed.
     *
     * <p>Two facts, and both of them are things a run cannot report afterwards.
     * The channel is what the radio has to be tuned to, and getting it wrong is
     * invisible: the frames transmit fine and reach nobody. The security type
     * decides whether the frames are worth sending at all -- on a network that
     * verifies management frames they are discarded on arrival, and the send
     * still counts as a success.
     *
     * <p>So the honest case is stated up front rather than discovered through a
     * counter that climbs and a friend who stays online.
     */
    private void showDeauthCaveat() {
        if (apStatus == null) return;
        Wifi.Ap ap = targetAp();
        if (ap == null) {
            apStatus.setText("no access point selected");
            apStatus.setTextColor(Design.TEXT_3);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(ap.ssid);
        sb.append(ap.frequency > 0
                ? " · ch " + ap.channel + " / " + ap.frequency + " MHz (radio tuned here first)"
                : " · frequency unknown, the radio will stay where it is");
        String blocker = ap.deauthBlocker();
        // Not an error: the run is still allowed, it just may not land. Saying
        // so here is what keeps "it did nothing" from reading as a broken tool.
        apStatus.setText(sb.append(blocker.isEmpty() ? "" : " — " + blocker).toString());
        apStatus.setTextColor(blocker.isEmpty() ? Design.TEXT_3 : Design.ORANGE);
    }

    private void renderClients() {
        if (clientList == null) return;
        clientList.removeAllViews();
        // The fallback row means two different things in the two forms, and the
        // difference is the blast radius: a soft AP sweeps its own association
        // table one station at a time, while a station interface falls back to a
        // broadcast frame that every client of the access point receives.
        String allTitle = apMode ? "All clients" : "Every client";
        String allSub = apMode
                ? (kickAll ? "every associated station" : "kick everyone at once")
                : (kickAll ? "broadcast — the whole access point drops"
                           : "broadcast to all of them at once");
        LinearLayout all = Widgets.listRow(c, allTitle, allSub,
                kickAll ? Design.moduleColor(key) : Design.TEXT_3,
                kickAll ? Widgets.chip(c, "PICKED", Design.moduleColor(key)) : null);
        if (kickAll) {
            all.setBackground(Widgets.round(
                    Design.withAlpha(Design.moduleColor(key), 40), Widgets.dp(c, Design.R_CARD)));
        }
        all.setOnClickListener(v -> {
            kickAll = true;
            clientMac = "";
            selectedClient = null;
            renderClients();
            updateRunLabel();
        });
        clientList.addView(all);
        for (Client cl : clients) {
            // The address leads the row, because that is the target the button
            // will actually act on; the MAC is the supporting detail.
            StringBuilder sub = new StringBuilder();
            if (!cl.mac.isEmpty()) sub.append(cl.mac);
            if (cl.hasSignal) {
                if (sub.length() > 0) sub.append("  ·  ");
                sub.append(cl.signal).append(" dBm");
            }
            boolean selected = !kickAll && cl.mac.equals(clientMac);
            String title = cl.ip.isEmpty() ? cl.mac : cl.ip;
            LinearLayout r = Widgets.listRow(c, title, sub.toString(),
                    selected ? Design.moduleColor(key) : Design.TEXT_3,
                    selected ? Widgets.chip(c, "PICKED", Design.moduleColor(key)) : null);
            if (selected) {
                r.setBackground(Widgets.round(
                        Design.withAlpha(Design.moduleColor(key), 40),
                        Widgets.dp(c, Design.R_CARD)));
            }
            final Client picked = cl;
            r.setOnClickListener(v -> {
                clientMac = cl.mac;
                selectedClient = picked;
                kickAll = false;
                renderClients();
                updateRunLabel();
            });
            clientList.addView(r);
        }
    }


    private void requestScan(MainActivity host) {
        if (apButton != null) {
            apButton.setEnabled(false);
            apButton.setText("Scanning…");
        }
        if (apStatus != null) apStatus.setText("waiting for the platform scan…");

        if (!Wifi.hasPermission(c)) {
            host.requestPermissions(Wifi.requiredPermissions(), REQ_WIFI_SCAN);
            if (apButton != null) {
                apButton.setEnabled(true);
                apButton.setText("Scan Access Points");
            }
            if (apStatus != null) apStatus.setText("grant location access, then tap again");
            return;
        }
        Wifi.scan(c, new Wifi.Callback() {
            @Override
            public void onResult(java.util.List<Wifi.Ap> aps, String warning) {
                showAps(aps, warning);
            }

            @Override
            public void onError(String message) {
                if (apButton != null) {
                    apButton.setEnabled(true);
                    apButton.setText("Scan Access Points");
                }
                if (apStatus != null) apStatus.setText(message);
            }
        });
    }

    private void showAps(java.util.List<Wifi.Ap> aps, String warning) {
        State.aps.clear();
        State.aps.addAll(aps);
        if (apButton != null) {
            apButton.setEnabled(true);
            apButton.setText("Scan Access Points");
        }
        if (apList != null) apList.removeAllViews();
        if (apStatus != null) {
            apStatus.setText(warning != null ? warning
                    : aps.size() + " access point(s) · tap one to target it");
        }
        for (Wifi.Ap ap : aps) {
            String sub = "ch " + ap.channel + " · " + ap.level + " dBm · " + ap.bssid;
            // A channel of 0 means the platform reported a frequency this build
            // does not map. Saying "ch 0" would look like a real channel and hide
            // the fact that the radio cannot be tuned for this network.
            if (ap.channel <= 0) sub = "ch ? · " + ap.level + " dBm · " + ap.bssid;
            LinearLayout row = Widgets.listRow(c, ap.ssid, sub, Design.GREEN, null);
            boolean selected = bssid.equals(ap.bssid);
            if (selected) {
                row.setBackground(Widgets.round(
                        Design.withAlpha(Design.moduleColor(key), 40),
                        Widgets.dp(c, Design.R_CARD)));
            }
            row.setOnClickListener(v -> {
                // Stations heard belong to the access point that was picked when
                // they were heard. Keeping them across a change would offer
                // targets that are not associated with this one, and the frame
                // would be addressed to a client of a different network.
                if (!bssid.equals(ap.bssid)) {
                    bssid = ap.bssid;
                    State.selectedBssid = bssid;
                    clients.clear();
                    clientMac = "";
                    selectedClient = null;
                    kickAll = false;
                    setClientState("not listed for this access point", Design.TEXT_3);
                    updateRunLabel();
                }
                showAps(aps, warning);
            });
            if (apList != null) apList.addView(row);
        }
        // Once something is picked, the count line gives way to what that pick
        // means, so the channel and the security caveat are on screen before the
        // run button is pressed rather than discovered afterwards.
        if (!bssid.isEmpty()) showDeauthCaveat();
    }

    private LinearLayout kvRow(String k, String v, int color) {
        return Widgets.kvRow(c, k, v, color);
    }

    private LinearLayout.LayoutParams margin(int side, int top, int side2, int top2, int bottom) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.setMargins(Widgets.dp(c, side), Widgets.dp(c, top), Widgets.dp(c, side2), Widgets.dp(c, bottom));
        return p;
    }

    private LinearLayout.LayoutParams lp(int w, int h) {
        return new LinearLayout.LayoutParams(w, h);
    }

    // ---- run / cancel -----------------------------------------------------
    private void toggle() {
        if (running) {
            if (job > 0) Engine.get().cancel(c, job);
            stopRunning();
            return;
        }
        if (State.target == null && !key.equals("wifi")) {
            Toast2.show(c, "No target selected");
            return;
        }
        if (needsRoot() && !State.rootGranted) {
            Toast2.show(c, "This module needs root (Magisk) access");
            return;
        }
        if (key.equals("wifi") && wifiTarget().isEmpty()) {
            Toast2.show(c, apMode ? "Tap a hotspot client, or \"All clients\""
                    : "Tap an access point first");
            return;
        }        if (needsHelper() && !Engine.get().hasHelper()) {
            Toast2.show(c, "Privileged helper is missing — reinstall the APK");
            return;
        }
        results.clearRows();
        // A new run is the only thing that replaces the cached rows, so they go
        // with the rest of the console rather than staying on screen under the
        // live results as if both had just been produced.
        cachedPorts.clear();
        cachedServices.clear();
        cachedAt = 0;
        // Hop rows are keyed by TTL, and a rerun numbers them from 1 again, so
        // leaving the old cells behind would rewrite a row that no longer exists.
        hopCells.clear();
        statsLine = null;
        mitmStatsLine = null;
        forgeStatsLine = null;
        job = start();
        if (job < 0) {
            Toast2.show(c, Engine.get().isReady() ? "Engine busy" : String.valueOf(Engine.get().loadError()));
            return;
        }
        startRunning();
    }

    private boolean needsRoot() {
        return key.equals("mitm") || key.equals("forger") || key.equals("wifi")
                || key.equals("sniffer") || key.equals("dns") || key.equals("hijack");
    }

    /** Modules that exec the privileged helper through su. */
    private boolean needsHelper() {
        return needsRoot();
    }

    private int start() {
        State.Device d = State.target;
        if (d == null) d = new State.Device();
        switch (key) {
            case "portscan": return Engine.get().portScan(d.ip, 1, 65535, 260, 96);
            // 30 hops is past any real path on a LAN or a normal internet route,
            // and 33434 is a high UDP port that is reliably closed, so the
            // destination's ICMP port-unreachable is what ends the trace. Reverse
            // DNS is off: a resolver that takes seconds per hop is
            // indistinguishable from a hop that did not answer, which is the one
            // thing the numbers must not be.
            case "trace": return Engine.get().traceroute(d.ip, 30, 33434, 1200, 0);
            case "service": return Engine.get().inspect(d.ip, toArray(d.openPorts), 700);
            case "exploit": return Engine.get().exploits(d.ip, csv(d.openPorts));
            case "login": return Engine.get().loginAudit(d.ip, firstTelnet(d), "default");
            case "sessions": return Engine.get().shell(d.ip, 22, "", "");
            case "mitm": return Engine.get().mitmStart(State.primaryIface, d.ip, 1000);
            // The sniffer and the TLS analyser read the same capture the MITM
            // produces. They are separate modules because they answer different
            // questions and show different rows, not because they capture
            // differently -- one capture, three readings of it.
            case "sniffer": return Engine.get().mitmStart(State.primaryIface, d.ip, 1000);
            case "hijack": return Engine.get().mitmStart(State.primaryIface, d.ip, 1000);
            // Spoofing needs the gateway poisoned, which is what mitm does; the
            // last two arguments are the name to answer for and the address to
            // answer with. Both are required -- answering every name, or
            // answering with nothing, would break the target's DNS outright.
            case "dns":
                // Read the fields here rather than on every keystroke: the label
                // tracks the fields, the run is the only place the trimmed value
                // matters, and a half-typed domain is not an error to shout about.
                if (spoofNameIn != null) {
                    spoofName = spoofNameIn.getText().toString().trim();
                }
                if (spoofIpIn != null) {
                    spoofIp = spoofIpIn.getText().toString().trim();
                }
                if (spoofIp.isEmpty() || spoofName.isEmpty()) return -1;
                return Engine.get().mitmSpoof(State.primaryIface, d.ip, 1000,
                        spoofName, spoofIp);
            case "forger": return Engine.get().forge("1," + State.primaryCidr.split("/")[0] + "," + d.ip + ",40000,7,1,5,zs");
            // The interface matters here: deauth runs on wlan0, on the hotspot's
            // own ap0 it drops that hotspot's clients, and a count of 0 means
            // keep going until the run is cancelled. On a station interface
            // wifiClient() narrows the run to one station of the picked AP, and
            // targetChannel() pins the radio to that AP's channel. Zero on a
            // soft AP, where hostapd is already on the right channel.
            case "wifi": return Engine.get().deauth(wifiIface, wifiTarget(), 100, 0,
                    wifiClient(), apMode ? 0 : targetFrequency());
            default: return -1;
        }
    }

    private int firstTelnet(State.Device d) {
        for (int p : d.openPorts) if (p == 23) return 23;
        for (int p : d.openPorts) if (p == 22) return 22;
        return 23;
    }

    private int[] toArray(java.util.List<Integer> list) {
        int[] a = new int[list.size()];
        for (int i = 0; i < list.size(); i++) a[i] = list.get(i);
        return a;
    }

    private String csv(java.util.List<Integer> list) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) b.append(',');
            b.append(list.get(i));
        }
        return b.toString();
    }

    private void startRunning() {
        running = true;
        runButton.setText("Cancel");
        runButton.setBackground(Widgets.round(Design.RED, Widgets.dp(c, Design.R_CONTROL)));
        statusLine.setText("running…");
        progress.setProgress(0.02f, Design.moduleColor(key));
    }

    private void stopRunning() {
        running = false;
        job = -1;
        statsLine = null;
        mitmStatsLine = null;
        forgeStatsLine = null;
        runButton.setText(runLabel());
        runButton.setBackground(Widgets.round(Design.moduleColor(key), Widgets.dp(c, Design.R_CONTROL)));
        statusLine.setText("stopped");
        progress.setProgress(0f, Design.moduleColor(key));
    }

    // ---- traceroute rows ---------------------------------------------------
    /**
     * Formats one hop. A hop that did not answer shows as {@code *}, which is
     * what traceroute has always printed for it, and its timing is dropped
     * because there is none to show.
     */
    private static String hopValue(String addr, double rtt, boolean reached, String name) {
        if (addr.isEmpty()) return "*";
        String v = addr;
        if (!name.isEmpty()) v += "  " + name;
        if (rtt > 0) v += String.format("  %.2f ms", rtt);
        if (reached) v += "  [dest]";
        return v;
    }

    /**
     * Builds a hop row and remembers its value cell so a late reverse-DNS result
     * can rewrite it in place instead of appending a second row for the same hop.
     */
    private View hopRow(int ttl, String addr, double rtt, boolean reached, String name) {
        int color = addr.isEmpty() ? Design.TEXT_3 : reached ? Design.GREEN : Design.INDIGO;
        View row = Widgets.kvRow(c, "hop " + ttl, hopValue(addr, rtt, reached, name), color);
        TextView cell = (TextView) ((ViewGroup) row).getChildAt(1);
        hopCells.put(ttl, cell);
        return row;
    }

    // ---- events -----------------------------------------------------------
    @Override
    public void onEvent(int jid, String type, Object data) {
        // The client listing is its own job, so it has to be matched before the
        // run job: a deauth and a listing can never share an id.
        if ("staList".equals(type)) {
            if (jid == staJob) onStaList(data);
            return;
        }
        if ("radioResult".equals(type)) {
            onRadioResult(data);
            return;
        }
        if ("monitorResult".equals(type)) {
            if (jid == monitorJob) onMonitorResult(data);
            return;
        }
        if (jid != job) return;
        switch (type) {
            case "progress": {
                float pct = (float) com.zerosploit.util.Json.d(data, "pct", 0);
                progress.setProgress(pct, Design.moduleColor(key));
                statusLine.setText(String.format("%s  %.0f%%",
                        com.zerosploit.util.Json.str(data, "phase", ""), pct * 100));
                return;
            }
            case "log": {
                String level = com.zerosploit.util.Json.str(data, "level", "info");
                int color = level.equals("error") ? Design.RED
                        : level.equals("warn") ? Design.ORANGE : Design.TEXT_2;
                results.addView(Widgets.kvRow(c,
                        com.zerosploit.util.Json.str(data, "t", ""),
                        com.zerosploit.util.Json.str(data, "msg", ""), color));
                return;
            }
            case "hop": {
                int ttl = com.zerosploit.util.Json.i(data, "hop", 0);
                String addr = com.zerosploit.util.Json.str(data, "addr", "");
                double rtt = com.zerosploit.util.Json.d(data, "rttMs", 0);
                boolean reached = com.zerosploit.util.Json.b(data, "reached", false);
                results.addView(hopRow(ttl, addr, rtt, reached, ""));
                return;
            }
            case "hopName": {
                int ttl = com.zerosploit.util.Json.i(data, "hop", 0);
                String name = com.zerosploit.util.Json.str(data, "name", "");
                TextView cell = hopCells.get(ttl);
                if (cell == null || name.isEmpty()) return;
                String addr = com.zerosploit.util.Json.str(data, "addr", "");
                double rtt = com.zerosploit.util.Json.d(data, "rttMs", 0);
                boolean reached = com.zerosploit.util.Json.b(data, "reached", false);
                cell.setText(hopValue(addr, rtt, reached, name));
                cell.setTextColor(Design.TEXT);
                return;
            }
            case "port": {
                int p = com.zerosploit.util.Json.i(data, "port", 0);
                String svc = com.zerosploit.util.Json.str(data, "service", "");
                results.addView(Widgets.kvRow(c, "port " + p, svc.isEmpty() ? "open" : svc, Design.GREEN));
                if (State.target != null && p > 0 && !State.target.openPorts.contains(p)) {
                    State.target.openPorts.add(p);
                    if (!svc.isEmpty()) State.target.services.put(p, svc);
                    // Written per port rather than once at the end of the job: a
                    // scan of 65535 ports is minutes long and a cancelled run,
                    // a rotated screen or a killed process would otherwise throw
                    // away every port found up to that point.
                    PortCache.save(c, State.target);
                    cachedPorts.remove(Integer.valueOf(p));
                    cachedServices.remove(Integer.valueOf(p));
                }
                return;
            }
            case "service": {
                String name = com.zerosploit.util.Json.str(data, "name", "?");
                String ver = com.zerosploit.util.Json.str(data, "version", "");
                results.addView(Widgets.kvRow(c,
                        "svc " + com.zerosploit.util.Json.i(data, "port", 0),
                        name + (ver.isEmpty() ? "" : " " + ver), Design.TEAL));
                return;
            }
            case "portFiltered": {
                // Reachable-but-no-response ports. They are not open, so they
                // are drawn dimmed and are deliberately not added to
                // State.target.openPorts -- a filtered port that later gets fed
                // into the exploit module as a live service is a false positive
                // with a CVE attached to it.
                int p = com.zerosploit.util.Json.i(data, "port", 0);
                String svc = com.zerosploit.util.Json.str(data, "service", "");
                results.addView(Widgets.kvRow(c, "port " + p,
                        (svc.isEmpty() ? "filtered" : svc + " · filtered"),
                        Design.TEXT_2));
                return;
            }
            case "findings": {
                onFindings(data);
                return;
            }
            case "services": {
                onServices(data);
                return;
            }
            case "cred": {
                boolean ok = com.zerosploit.util.Json.b(data, "accepted", false);
                results.addView(Widgets.kvRow(c,
                        com.zerosploit.util.Json.str(data, "user", "?"),
                        com.zerosploit.util.Json.str(data, "pass", "") + (ok ? "  ✓" : ""),
                        ok ? Design.GREEN : Design.TEXT_2));
                return;
            }
            case "monitorResult": {
                boolean ok = com.zerosploit.util.Json.b(data, "ok", false);
                results.addView(Widgets.kvRow(c, "monitor",
                        ok ? "monitor mode on" : "could not switch to monitor mode",
                        ok ? Design.GREEN : Design.ORANGE));
                return;
            }
            case "raw": {
                // One JSON object per line from the helper. deauthStats arrives
                // ten times a second, so it updates a single line in place
                // instead of appending: otherwise a running kill buries the
                // console and every other line under it.
                String kind = com.zerosploit.util.Json.str(data, "type", "raw");
                switch (kind) {
                    case "mitmStarted": {
                        results.addView(Widgets.kvRow(c, "mitm",
                                "poisoning on " + com.zerosploit.util.Json.str(data, "iface", "?")
                                        + " · " + com.zerosploit.util.Json.i(data, "targets", 0)
                                        + " target(s)", Design.MINT));
                        String gw = com.zerosploit.util.Json.str(data, "gateway", "");
                        if (!gw.isEmpty()) {
                            results.addView(Widgets.kvRow(c, "gateway", gw, Design.TEXT_2));
                        }
                        return;
                    }
                    case "gatewayMac": {
                        results.addView(Widgets.kvRow(c, "gateway",
                                "resolved " + com.zerosploit.util.Json.str(data, "mac", "?"),
                                Design.TEXT_2));
                        return;
                    }
                    case "flow": {
                        // One row per observed flow. The MITM exists to show
                        // these, but the sniffer and the TLS analyser are pointed
                        // at the same capture and would bury the one thing they
                        // are for -- a flow row per packet says nothing.
                        if (key.equals("sniffer") || key.equals("hijack")
                                || key.equals("dns")) return;
                        // These are the point of the
                        // module, so they are appended rather than summarised.
                        results.addView(Widgets.kvRow(c,
                                com.zerosploit.util.Json.str(data, "proto", "?")
                                        + " → " + com.zerosploit.util.Json.i(data, "dport", 0),
                                com.zerosploit.util.Json.str(data, "src", "?")
                                        + " → " + com.zerosploit.util.Json.str(data, "dst", "?"),
                                Design.TEAL));
                        return;
                    }
                    case "tlsHello": {
                        // The SNI is the useful part: it says which site the
                        // target is actually talking to, which is usually not
                        // the IP the user typed.
                        String sni = com.zerosploit.util.Json.str(data, "sni", "");
                        String alpn = com.zerosploit.util.Json.str(data, "alpn", "");
                        boolean weak = com.zerosploit.util.Json.b(data, "weak", false);
                        results.addView(Widgets.kvRow(c,
                                sni.isEmpty() ? "tls (no SNI)" : sni,
                                (alpn.isEmpty() ? "" : alpn) + (weak ? "  weak version" : ""),
                                weak ? Design.ORANGE : Design.CYAN));
                        return;
                    }
                    case "tlsCert": {
                        // Certificate problems are listed above the identity, so
                        // an expired or weak-key cert is visible without the user
                        // having to read the subject first.
                        StringBuilder note = new StringBuilder(
                                com.zerosploit.util.Json.str(data, "subject", "?"));
                        if (com.zerosploit.util.Json.b(data, "selfSigned", false)) {
                            note.append("  ·  self-signed");
                        }
                        if (com.zerosploit.util.Json.b(data, "expired", false)) {
                            note.append("  ·  expired");
                        }
                        if (com.zerosploit.util.Json.b(data, "notYetValid", false)) {
                            note.append("  ·  not yet valid");
                        }
                        if (com.zerosploit.util.Json.b(data, "weakKey", false)) {
                            note.append("  ·  weak key");
                        }
                        String nv = com.zerosploit.util.Json.str(data, "notAfter", "");
                        if (!nv.isEmpty()) note.append("  ·  until ").append(nv);
                        boolean bad = com.zerosploit.util.Json.b(data, "selfSigned", false)
                                || com.zerosploit.util.Json.b(data, "expired", false)
                                || com.zerosploit.util.Json.b(data, "notYetValid", false)
                                || com.zerosploit.util.Json.b(data, "weakKey", false);
                        results.addView(Widgets.kvRow(c,
                                com.zerosploit.util.Json.str(data, "issuer", "?"),
                                note.toString(), bad ? Design.ORANGE : Design.TEXT_2));
                        return;
                    }
                    case "mitmStats": {
                        // Timer-driven, so it rewrites one line in place.
                        if (mitmStatsLine == null) {
                            mitmStatsLine = Widgets.mono(c, "", Design.T_MONO_SM, 400, Design.MINT);
                            results.addView(mitmStatsLine);
                        }
                        long flows = com.zerosploit.util.Json.l(data, "flows", 0);
                        long shown = com.zerosploit.util.Json.l(data, "shown", flows);
                        // Credentials and TLS findings only appear for the module
                        // that asked for them, so the line does not carry a zero
                        // for a counter the user is not even running.
                        StringBuilder st = new StringBuilder(String.format("mitm     %d arp · %d flows%s",
                                com.zerosploit.util.Json.i(data, "arpSent", 0), flows,
                                shown < flows ? " (showing " + shown + ")" : ""));
                        if (key.equals("sniffer")) {
                            st.append(" · ").append(
                                    com.zerosploit.util.Json.l(data, "creds", 0)).append(" creds");
                        }
                        if (key.equals("hijack")) {
                            st.append(" · ").append(
                                    com.zerosploit.util.Json.l(data, "tls", 0)).append(" tls");
                        }
                        if (key.equals("dns")) {
                            st.append(" · ").append(
                                    com.zerosploit.util.Json.l(data, "spoofed", 0)).append(" answered");
                        }
                        mitmStatsLine.setText(st.toString());
                        return;
                    }
                    case "mitmStopped": {
                        long flows = com.zerosploit.util.Json.l(data, "flows", 0);
                        long shown = com.zerosploit.util.Json.l(data, "shown", flows);
                        String note = com.zerosploit.util.Json.i(data, "arpSent", 0)
                                + " arp · " + flows + " flows";
                        if (shown < flows) {
                            // The list was deliberately truncated, so say so
                            // instead of letting a short list pass for a quiet
                            // network.
                            note += " · showing first " + shown;
                        }
                        results.addView(Widgets.kvRow(c, "mitm", "stopped · " + note,
                                Design.TEXT_2));
                        mitmStatsLine = null;
                        return;
                    }
                    case "restored": {
                        int n = com.zerosploit.util.Json.i(data, "count", 0);
                        // This is the row that matters most: it is the only
                        // confirmation the victim's routing was put back, so it
                        // is stated plainly instead of as a bare count.
                        results.addView(Widgets.kvRow(c, "restore",
                                n + " arp entr" + (n == 1 ? "y" : "ies") + " back to gateway "
                                        + com.zerosploit.util.Json.str(data, "gatewayMac", "?"),
                                Design.GREEN));
                        return;
                    }
                    case "forgeInfo": {
                        results.addView(Widgets.kvRow(c, "forge",
                                com.zerosploit.util.Json.str(data, "desc", "")
                                        + " · " + com.zerosploit.util.Json.i(data, "len", 0)
                                        + "B · x" + com.zerosploit.util.Json.i(data, "count", 0),
                                Design.MINT));
                        String hex = com.zerosploit.util.Json.str(data, "hex", "");
                        if (!hex.isEmpty()) {
                            // The bytes that are about to go on the wire. Shown
                            // so a frame can be checked before it is sent.
                            results.addView(Widgets.label(c, "      " + hex, 10, 400,
                                    Design.TEXT_2));
                        }
                        return;
                    }
                    case "forgeProgress": {
                        if (forgeStatsLine == null) {
                            forgeStatsLine = Widgets.mono(c, "", Design.T_MONO_SM, 400, Design.MINT);
                            results.addView(forgeStatsLine);
                        }
                        forgeStatsLine.setText(String.format("forge    %d / %d sent",
                                com.zerosploit.util.Json.i(data, "sent", 0),
                                com.zerosploit.util.Json.i(data, "total", 0)));
                        return;
                    }
                    case "forgeDone": {
                        int sent = com.zerosploit.util.Json.i(data, "sent", 0);
                        int req = com.zerosploit.util.Json.i(data, "requested", 0);
                        results.addView(Widgets.kvRow(c, "forge",
                                com.zerosploit.util.Json.str(data, "kind", "?") + " done · "
                                        + sent + " / " + req + " sent",
                                sent == req ? Design.GREEN : Design.ORANGE));
                        forgeStatsLine = null;
                        return;
                    }
                    case "deauthStarted": {
                        String target = com.zerosploit.util.Json.str(data, "target", "");
                        String method = com.zerosploit.util.Json.str(data, "method", "");
                        int freq = com.zerosploit.util.Json.i(data, "freqMhz", 0);
                        StringBuilder started = new StringBuilder("started on " + target);
                        // Only meaningful for the injection path: a soft AP is
                        // already on its own channel and is driven by hostapd.
                        if (freq > 0 && method.isEmpty()) {
                            started.append(" · tuned to ").append(freq).append(" MHz");
                        }
                        if (!method.isEmpty()) started.append(" · ").append(method);
                        results.addView(Widgets.kvRow(c, "deauth", started.toString(), Design.MINT));
                        // A tuning failure is not fatal but it does mean the
                        // frames are going onto an empty frequency, so it has to
                        // be on screen next to the run instead of only in a log.
                        String warn = com.zerosploit.util.Json.str(data, "warning", "");
                        if (!warn.isEmpty()) {
                            results.addView(Widgets.kvRow(c, "channel", warn, Design.ORANGE));
                        }
                        return;
                    }
                    case "deauthStats": {
                        int sent = com.zerosploit.util.Json.i(data, "sent", 0);
                        long ms = com.zerosploit.util.Json.l(data, "elapsedMs", 0);
                        if (statsLine == null) {
                            statsLine = Widgets.mono(c, "", Design.T_MONO_SM, 400,
                                    Design.MINT);
                            results.addView(statsLine);
                        }
                        statsLine.setText(String.format("deauth   %d sent · %.1fs",
                                sent, ms / 1000.0));
                        return;
                    }
                    case "deauthStopped": {
                        results.addView(Widgets.kvRow(c, "deauth",
                                "stopped · " + com.zerosploit.util.Json.i(data, "sent", 0)
                                        + " sent", Design.TEXT_2));
                        statsLine = null;
                        return;
                    }
                    case "deauthIdle": {
                        results.addView(Widgets.kvRow(c, "deauth",
                                com.zerosploit.util.Json.str(data, "msg", "idle"),
                                Design.ORANGE));
                        return;
                    }
                    case "error": {
                        results.addView(Widgets.kvRow(c, "error",
                                com.zerosploit.util.Json.str(data, "msg", "failed"),
                                Design.RED));
                        return;
                    }
                    case "warn": {
                        results.addView(Widgets.kvRow(c, "warn",
                                com.zerosploit.util.Json.str(data, "msg", ""),
                                Design.ORANGE));
                        return;
                    }
                    default:
                        results.addView(Widgets.kvRow(c, kind,
                                com.zerosploit.util.Json.str(data, "count", "·"), Design.MINT));
                }
                return;
            }
            default:
                results.addView(Widgets.kvRow(c, type,
                        com.zerosploit.util.Json.str(data, "count", "·"), Design.TEXT_2));
        }
    }

    /**
     * Renders the CVE list. The engine sorts it most-severe-first and already
     * decides which rows to include, so this only lays it out -- but it does
     * print the evidence and the remedy next to every finding, because a
     * severity badge with no version behind it is a claim the user cannot
     * check.
     */
    private void onFindings(Object data) {
        java.util.List<Object> list = com.zerosploit.util.Json.arr(
                com.zerosploit.util.Json.obj(data).get("findings"));
        if (list == null || list.isEmpty()) {
            int checked = com.zerosploit.util.Json.i(data, "checked", 0);
            results.addView(Widgets.kvRow(c, "findings",
                    "none · " + checked + " service(s) checked", Design.GREEN));
            return;
        }
        int shown = 0;
        for (Object o : list) {
            java.util.Map<String, Object> f = com.zerosploit.util.Json.obj(o);
            if (f == null) continue;
            String sev = com.zerosploit.util.Json.str(o, "severity", "INFO");
            String cve = com.zerosploit.util.Json.str(o, "cve", "-");
            String title = com.zerosploit.util.Json.str(o, "title", "");
            String evidence = com.zerosploit.util.Json.str(o, "evidence", "");
            String remedy = com.zerosploit.util.Json.str(o, "remedy", "");
            String cwe = com.zerosploit.util.Json.str(o, "cwe", "");
            if (cve.equals("-")) {
                // The engine's own "this run was cancelled" marker.
                results.addView(Widgets.kvRow(c, "incomplete", title, Design.ORANGE));
                continue;
            }
            results.addView(Widgets.badge(c, sev, Design.severity(sev)));
            results.addView(Widgets.kvRow(c, cve, title, Design.severity(sev)));
            String detail = evidence;
            if (!cwe.isEmpty() && !cwe.equals("-")) detail += "  ·  " + cwe;
            results.addView(Widgets.label(c, "      " + detail, 11, 400, Design.TEXT_2));
            if (!remedy.isEmpty() && !remedy.equals("-")) {
                results.addView(Widgets.label(c, "      fix: " + remedy, 11, 400,
                        Design.TEXT_2));
            }
            shown++;
        }
        results.addView(Widgets.kvRow(c, "findings", shown + " shown", Design.TEXT_2));
    }

    /**
     * Final service list. The per-port "service" events stream in as they are
     * probed, so this row is the summary that states how much was actually
     * covered -- and says so explicitly when the run was cancelled, because a
     * short list otherwise reads exactly like a host with nothing exposed.
     */
    private void onServices(Object data) {
        int probed = com.zerosploit.util.Json.i(data, "probed", 0);
        int of = com.zerosploit.util.Json.i(data, "of", probed);
        boolean partial = com.zerosploit.util.Json.b(data, "partial", false);
        if (partial) {
            results.addView(Widgets.kvRow(c, "coverage",
                    probed + " of " + of + " · incomplete", Design.ORANGE));
        } else {
            results.addView(Widgets.kvRow(c, "coverage",
                    probed + " of " + of + (of == 1 ? " service" : " services"),
                    Design.TEXT_2));
        }
    }

    @Override
    public View view() {
        return root;
    }

    @Override
    public void onShown() {
        Engine.get().addListener(this);
        // The soft-AP form is only known once the helper has answered, so the
        // very first thing the module does is ask which kind of interface the
        // default one is.
        if (key.equals("wifi")) requestStaList();
    }

    @Override
    public void onHidden() {
        Engine.get().removeListener(this);
        if (staJob > 0) Engine.get().cancel(c, staJob);
        staJob = -1;
        if (running && job > 0) Engine.get().cancel(c, job);
        stopRunning();
    }
}
