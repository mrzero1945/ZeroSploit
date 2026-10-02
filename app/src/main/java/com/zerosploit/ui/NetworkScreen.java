package com.zerosploit.ui;

import android.content.Context;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.zerosploit.core.Engine;
import com.zerosploit.core.State;
import com.zerosploit.core.Wifi;
import com.zerosploit.util.Json;

import java.util.List;
import java.util.Map;

/**
 * Network tab: interfaces, default gateway, root status, and the device
 * discovery sweep. Tapping a discovered device pushes the target screen.
 */
public class NetworkScreen implements MainActivity.Screen, Engine.Listener {

    private static final String TAG = "ZsNetwork";

    private final Context c;
    private final MainActivity act;
    private final LinearLayout page;
    /** page wrapped in a scroller; this is what view() hands out. */
    private final android.widget.ScrollView root;
    private final LinearLayout ifaceList;
    private final LinearLayout deviceList;
    /** Kernel interfaces stay hidden until asked for; this device has 38. */
    private boolean showAllIfaces;
    private TextView scanButton;
    private TextView devicesHeader;
    private int scanJob = -1;
    private double scanPct;
    private TextView scanLine;

    private static final int[] SCAN_PORTS = {22, 23, 53, 80, 443, 445, 554, 3306, 3389, 5000, 8080, 8443, 9100};

    public NetworkScreen(MainActivity act) {
        this.act = act;
        this.c = act;
        LinearLayout content = Widgets.column(c);
        page = content;
        root = Widgets.scroller(c, page);

        content.addView(Widgets.navBar(c, "Network", "", false, null));

        // Interfaces lead the screen: everything else on it used to be static
        // chrome that rendered as empty space. The device list below only
        // appears once a scan has actually found something.
        content.addView(Widgets.sectionHeader(c, "Interfaces"));
        ifaceList = Widgets.column(c);
        ifaceList.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        content.addView(ifaceList, lpMargin(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 16, 0, 0));

        scanButton = Widgets.button(c, "Scan", 0, Design.TINT);
        scanButton.setOnClickListener(v -> toggleScan());
        content.addView(scanButton, lpMargin(ViewGroup.LayoutParams.MATCH_PARENT,
                Widgets.dp(c, 50), 16, 10, 0));

        devicesHeader = Widgets.sectionHeader(c, "Devices");
        devicesHeader.setVisibility(View.GONE);
        content.addView(devicesHeader, lpMargin(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 0, 20, 0));
        deviceList = Widgets.column(c);
        deviceList.setVisibility(View.GONE);
        content.addView(deviceList, lpMargin(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 16, 0, 0));
    }

    // ---- scan control -----------------------------------------------------
    /**
     * The phone is usually the hotspot host, so its own radio interface often
     * has no address and cannot be swept. The button therefore adapts: a routed
     * interface means a host sweep over its CIDR, a wireless interface without
     * an address means a radio scan.
     */
    private State.Iface wifiIface() {
        for (State.Iface i : State.ifaces) if (i.isWifi) return i;
        return null;
    }

    private void renderScanButton() {
        if (scanJob > 0) {
            scanButton.setText("Cancel scan");
            scanButton.setEnabled(true);
            return;
        }
        boolean haveCidr = !State.primaryCidr.isEmpty();
        State.Iface w = wifiIface();
        // Once a sweep has produced rows the button becomes a re-run.
        boolean haveResults = !State.sorted().isEmpty();
        scanButton.setText(haveResults ? "Rescan" : "Scan");
        scanButton.setEnabled(haveCidr || w != null);
    }

    private void toggleScan() {
        if (scanJob > 0) {
            Engine.get().cancel(c, scanJob);
            scanJob = -1;
            renderScanButton();
            renderDevices();
            scanButton.setBackground(Widgets.round(Design.TINT, Widgets.dp(c, Design.R_CONTROL)));
            return;
        }
        startScan();
    }

    /**
     * Sweep the selected interface, or fall back to a radio scan when it has
     * no address. Both the Scan button and an interface tap land here.
     */
    private void startScan() {
        if (scanJob > 0) return;
        if (State.primaryCidr.isEmpty()) {
            State.Iface w = wifiIface();
            if (w != null) {
                scanRadio(w.name);
            } else {
                Toast2.show(c, "No usable interface found");
            }
            return;
        }
        // A /8 has sixteen million addresses; expandHostRange would sample an
        // arbitrary slice of it, which is worse than refusing.
        State.Iface tgt = State.iface(State.primaryIface);
        if (tgt != null && tgt.prefix < 16) {
            Toast2.show(c, State.primaryIface + " is a /" + tgt.prefix
                    + " — too large to sweep. Tap a narrower interface first.");
            return;
        }
        Log.i(TAG, "toggleScan: discover " + State.primaryCidr + " on " + State.primaryIface
                + " ports=" + SCAN_PORTS.length);
        int id = Engine.get().discover(State.primaryCidr, SCAN_PORTS, 350, 2);
        Log.i(TAG, "toggleScan: jobId=" + id);
        if (id < 0) {
            Toast2.show(c, Engine.get().isReady() ? "Engine busy" : Engine.get().loadError());
            return;
        }
        scanJob = id;
        State.beginDiscover(id);
        scanPct = 0;
        renderScanButton();
        renderDevices();
    }

    // ---- event handling ---------------------------------------------------
    @Override
    public void onEvent(int jobId, String type, Object data) {
        switch (type) {
            case "progress": {
                if (jobId != scanJob) return;
                double pct = Json.d(data, "pct", 0);
                Log.i(TAG, String.format("progress: %s %.0f%%", Json.str(data, "phase", ""),
                        Math.max(0, Math.min(100, pct))));
                scanPct = Math.max(0, Math.min(100, pct));
                renderScanLine();
                return;
            }
            case "devices": {
                if (jobId != scanJob) return;
                List<Object> items = Json.arr(Json.obj(data) == null ? null : Json.obj(data).get("devices"));
                if (items != null) {
                    for (Object o : items) State.addFound(State.Device.from(o));
                }
                State.endDiscover();
                scanJob = -1;
                Log.i(TAG, "scan done: " + State.devices.size() + " device(s)");
                renderAll();
                return;
            }
            case "device": {
                if (jobId != scanJob) return;
                State.Device d = State.Device.from(data);
                Log.i(TAG, "device: " + d.label() + " ip=" + d.ip + " mac=" + d.mac
                        + " via=" + d.source + " host=" + d.hostname);
                State.addFound(d);
                renderDevices();
                return;
            }
            case "network": {
                State.setRoot(data);
                State.setInterfaces(Engine.get().ifaceList(c));
                renderAll();
                return;
            }
            case "capabilities": {
                State.setRoot(data);
                renderAll();
                return;
            }
            default:
                break;
        }
    }

    // ---- rendering --------------------------------------------------------
    private void renderAll() {
        StringBuilder sb = new StringBuilder();
        for (State.Iface i : State.ifaces) {
            sb.append(i.name).append("(ip=").append(i.ip.isEmpty() ? "-" : i.ip)
              .append(",wifi=").append(i.isWifi)
              .append(",up=").append(i.isUp).append(") ");
        }
        Log.i(TAG, "renderAll: ifaces=" + State.ifaces.size() + " primary=" + State.primaryIface
                + " cidr=" + State.primaryCidr + " granted=" + State.rootGranted + " [" + sb + "]");
        renderCaps();
        renderIfaces();
        renderScanButton();
        renderDevices();
    }

    private void renderCaps() {
        Log.i(TAG, "renderCaps: root=" + (State.rootGranted ? "granted" : "none")
                + " manager=" + State.rootManager);
    }

    private void renderIfaces() {
        ifaceList.removeAllViews();
        if (State.ifaces.isEmpty()) {
            ifaceList.addView(Widgets.label(c, "No interfaces reported yet.",
                    Design.T_SUBHEAD, 400, Design.TEXT_3),
                    lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            return;
        }
        int shown = 0;
        int hidden = 0;
        for (int i = 0; i < State.ifaces.size(); i++) {
            State.Iface it = State.ifaces.get(i);
            if (!showAllIfaces && !State.worthShowing(it)) { hidden++; continue; }
            StringBuilder sub = new StringBuilder();
            if (!it.ip.isEmpty()) sub.append(it.ip);
            if (!it.cidr.isEmpty()) sub.append("  ").append(it.cidr);
            if (!it.gateway.isEmpty()) sub.append("\ngw ").append(it.gateway);
            if (!it.mac.isEmpty()) sub.append("\n").append(it.mac);
            int dot = it.isGateway ? Design.GREEN : (it.isUp ? Design.BLUE : Design.TEXT_3);
            TextView trailing = Widgets.chip(c, it.isWifi ? "WIFI" : (it.isGateway ? "GW" : "IP"), dot);
            if (!it.hasIp) trailing = Widgets.chip(c, "NO IP", Design.TEXT_3);
            LinearLayout r = Widgets.listRow(c, it.name.isEmpty() ? "?" : it.name, sub.toString(), dot, trailing);
            final State.Iface target = it;
            r.setOnClickListener(v -> onIfaceTapped(target));
            ifaceList.addView(r);
            shown++;
            if (shown < countShown()) ifaceList.addView(Widgets.insetDivider(c, 16));
        }
        if (hidden > 0) {
            TextView more = Widgets.button(c, "Show " + hidden + " kernel interfaces", 1,
                    Design.TEXT_2);
            more.setOnClickListener(v -> { showAllIfaces = !showAllIfaces; renderAll(); });
            ifaceList.addView(more, lpMargin(0, Widgets.dp(c, 40), 0, 8, 0));
        }
    }

    private int countShown() {
        int n = 0;
        for (State.Iface i : State.ifaces) if (showAllIfaces || State.worthShowing(i)) n++;
        return n;
    }

    /**
     * Tapping an interface makes it the sweep target. A wireless interface
     * with no address cannot be swept, but the radio scan still works, so that
     * is offered instead of a dead row.
     */
    private void onIfaceTapped(State.Iface it) {
        Log.i(TAG, "ifaceTapped: " + it.name + " ip=" + it.ip + " hasIp=" + it.hasIp
                + " isWifi=" + it.isWifi + " isUp=" + it.isUp);
        if (!State.selectIface(it.name)) {
            if (it.isWifi) {
                scanRadio(it.name);
            } else {
                Toast2.show(c, it.name + " has no IPv4 address, nothing to sweep");
            }
            renderAll();
            return;
        }
        // Picking an interface scans it right away; results render in the
        // device list below.
        renderAll();
        startScan();
    }

    /** Radio-level scan, i.e. the wlan0 path rather than a subnet sweep. */
    private void scanRadio(String iface) {
        if (!Wifi.hasPermission(c)) {
            act.requestPermissions(Wifi.requiredPermissions(), 4201);
            return;
        }
        Log.i(TAG, "scanRadio: start iface=" + iface + " wifiEnabled="
                + Wifi.isEnabled(c) + " perm=" + Wifi.hasPermission(c));
        Toast2.show(c, "Scanning " + iface + "…");
        Wifi.scan(c, new Wifi.Callback() {
            @Override
            public void onResult(List<Wifi.Ap> aps, String warning) {
                Log.i(TAG, "scanRadio: " + aps.size() + " APs, warning=" + warning);
                for (Wifi.Ap ap : aps) {
                    Log.i(TAG, "  ap " + ap.bssid + " ssid=" + ap.ssid + " ch=" + ap.channel
                            + " level=" + ap.level + " caps=" + ap.caps);
                }
                State.aps.clear();
                State.aps.addAll(aps);
                renderAll();
                if (aps.isEmpty()) {
                    Toast2.show(c, warning == null || warning.isEmpty()
                            ? "No access points returned" : warning);
                } else {
                    Toast2.show(c, aps.size() + " access points on " + iface);
                }
            }

            @Override
            public void onError(String message) {
                Log.w(TAG, "scanRadio: error " + message);
                Toast2.show(c, message);
            }
        });
    }

    private void renderDevices() {
        deviceList.removeAllViews();
        List<State.Device> all = State.sorted();
        // Nothing to show and nothing running: the section disappears instead of
        // leaving an empty block behind.
        if (all.isEmpty() && scanJob <= 0) {
            devicesHeader.setVisibility(View.GONE);
            deviceList.setVisibility(View.GONE);
            scanLine = null;
            return;
        }
        devicesHeader.setVisibility(View.VISIBLE);
        deviceList.setVisibility(View.VISIBLE);
        if (scanJob > 0) {
            scanLine = Widgets.label(c, "", Design.T_SUBHEAD, 400, Design.TEXT_3);
            scanLine.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 10),
                    Widgets.dp(c, 16), Widgets.dp(c, 10));
            deviceList.addView(scanLine,
                    lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            if (!all.isEmpty()) deviceList.addView(Widgets.insetDivider(c, 16));
            renderScanLine();
        } else {
            scanLine = null;
        }
        for (int i = 0; i < all.size(); i++) {
            State.Device d = all.get(i);
            deviceList.addView(deviceRow(d));
            if (i < all.size() - 1) deviceList.addView(Widgets.insetDivider(c, 16));
        }
    }

    /** Live "Scanning <cidr> - nn%" line; repainted on every progress event. */
    private void renderScanLine() {
        if (scanLine == null) return;
        scanLine.setText(String.format("Scanning %s - %.0f%%",
                State.primaryCidr.isEmpty() ? State.primaryIface : State.primaryCidr, scanPct));
    }

    /**
     * One row per device: glyph, Wi-Fi mark, name and MAC side by side. These
     * used to be split across a title line, a multi-line subtitle and a
     * trailing icon, which pushed the identity of a host across three rows.
     */
    private View deviceRow(State.Device d) {
        int color = kindColor(d.kind);
        LinearLayout row = Widgets.row(c);
        row.setBackgroundColor(0x00000000);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 12), Widgets.dp(c, 16), Widgets.dp(c, 12));

        row.addView(Widgets.icon(c, Design.moduleIcon("service"), color),
                lp(Widgets.dp(c, 22), Widgets.dp(c, 22)));

        // Identity: name, then IP, MAC and vendor on the second line.
        LinearLayout text = Widgets.column(c);
        LinearLayout.LayoutParams tp = lp(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        tp.leftMargin = Widgets.dp(c, 12);
        row.addView(text, tp);

        String name = d.label();
        if (name.isEmpty() || name.equals(d.ip)) {
            name = d.vendor.isEmpty() ? d.ip : d.vendor;
        }
        text.addView(Widgets.label(c, name, Design.T_SUBHEAD, 600, Design.TEXT),
                lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        StringBuilder meta = new StringBuilder();
        if (!d.ip.isEmpty() && !d.ip.equals(name)) meta.append(d.ip);
        if (!d.mac.isEmpty()) {
            if (meta.length() > 0) meta.append("  ·  ");
            meta.append(d.mac);
        }
        if (!d.vendor.isEmpty() && !d.vendor.equals(name)) {
            if (meta.length() > 0) meta.append("  ·  ");
            meta.append(d.vendor);
        }
        if (meta.length() > 0) {
            text.addView(Widgets.mono(c, meta.toString(), Design.T_MONO_SM, 400, Design.TEXT_3),
                    lpMargin(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0, 3, 0));
        }

        // Trailing marks, kept in one place on the same line.
        LinearLayout marks = Widgets.row(c);
        if (d.isWifi) marks.addView(Widgets.chip(c, "WIFI", Design.BLUE));
        if (!d.openPorts.isEmpty()) {
            marks.addView(Widgets.chip(c, d.openPorts.size() + "p", Design.GREEN));
        }
        if (d.isGateway) marks.addView(Widgets.chip(c, "GW", Design.GREEN));
        if (marks.getChildCount() > 0) {
            LinearLayout.LayoutParams mp = lp(ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            mp.leftMargin = Widgets.dp(c, 10);
            marks.setLayoutParams(mp);
            row.addView(marks);
        }
        row.setOnClickListener(v -> {
            Log.i(TAG, "deviceTapped: " + d.ip + " mac=" + d.mac
                    + " host=" + d.hostname + " ports=" + d.openPorts.size());
            State.target = d;
            Log.i(TAG, "target set -> " + (State.target == null ? "NULL" : State.target.ip));
            act.push(new TargetDetailScreen(act));
        });
        return row;
    }

    static int kindColor(String kind) {
        if (kind == null) return Design.TEXT_2;
        switch (kind) {
            case "router": return Design.GREEN;
            case "server": return Design.BLUE;
            case "phone": return Design.TEAL;
            case "laptop": return Design.INDIGO;
            case "printer": return Design.ORANGE;
            case "tv": return Design.PURPLE;
            case "camera": return Design.CYAN;
            case "iot": return Design.MINT;
            default: return Design.TEXT_2;
        }
    }

    static String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    @Override
    public View view() {
        return root;
    }

    @Override
    public void onShown() {
        Engine.get().addListener(this);
        State.setInterfaces(Engine.get().ifaceList(c));
        probeRoot(false);
        renderAll();
    }

    @Override
    public void onHidden() {
        Engine.get().removeListener(this);
    }

    @Override
    public void onTabSelected() {
        State.setInterfaces(Engine.get().ifaceList(c));
        renderAll();
    }

    // ---- layout helpers ---------------------------------------------------
    private LinearLayout.LayoutParams lp(int w, int h) {
        return new LinearLayout.LayoutParams(w, h);
    }

    private LinearLayout.LayoutParams lp(int w, int h, float weight) {
        return new LinearLayout.LayoutParams(w, h, weight);
    }

    private LinearLayout.LayoutParams lpWrap(int size) {
        return new LinearLayout.LayoutParams(size, size);
    }

    private LinearLayout.LayoutParams lpMargin(int w, int h, float side, float top, float bottom) {
        return Widgets.lpMargin(c, w, h, side, top, bottom);
    }
    private void probeRoot(boolean userInitiated) {
        Log.i(TAG, "probeRoot: start, userInitiated=" + userInitiated);
        Engine.get().refreshRoot(info -> {
            if (info != null) State.setRoot(info);
            Log.i(TAG, "probeRoot: granted=" + State.rootGranted + " manager=" + State.rootManager
                    + " detail=" + State.rootDetail);
            renderAll();
            if (State.rootGranted) {
                // Only meaningful with uid 0: the packet and monitor modules all
                // shell out through the helper.
                Engine.get().capabilities();
                if (scanJob <= 0) toggleScan();
            }
        });
    }}
