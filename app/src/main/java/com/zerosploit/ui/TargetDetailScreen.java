package com.zerosploit.ui;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.zerosploit.core.Engine;
import com.zerosploit.core.PortCache;
import com.zerosploit.core.State;

/**
 * Target detail, pushed from the Network device list: full identity, open ports
 * and inline launchers for each module.
 */
public class TargetDetailScreen implements MainActivity.Screen, Engine.Listener {

    private final Context c;
    private final MainActivity act;
    private final LinearLayout page;
    /** page wrapped in a scroller; this is what view() hands out. */
    private final android.widget.ScrollView root;
    private final LinearLayout body;
    private State.Device d;
    /** When the listed ports were observed; drives the "scanned 3m ago" note. */
    private long cachedAt;

    public TargetDetailScreen(MainActivity act) {
        this.act = act;
        this.c = act;
        this.d = State.target;
        // Restored before the first render(), so the "Open ports" list and the
        // module launchers below it are built from the last scan rather than
        // from an empty target that then fills in under the user's finger.
        if (d != null) {
            PortCache.load(c, d);
            cachedAt = PortCache.scannedAt(c, d.ip);
        }
        LinearLayout content = Widgets.column(c);
        page = content;
        root = Widgets.scroller(c, page);
        content.addView(Widgets.navBar(c, "Device", "", true, v -> act.pop()));
        body = Widgets.column(c);
        body.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 8), Widgets.dp(c, 16), Widgets.dp(c, 20));
        content.addView(body);
    }

    @Override
    public View view() {
        return root;
    }

    @Override
    public void onShown() {
        Engine.get().addListener(this);
        render();
    }

    @Override
    public void onHidden() {
        Engine.get().removeListener(this);
    }

    @Override
    public void onEvent(int jobId, String type, Object data) {
        if (d == null) return;
        if (type.equals("port") && jobId > 0) {
            int p = Json2.i(data, "port");
            if (p > 0 && !d.openPorts.contains(p)) {
                d.openPorts.add(p);
                d.services.put(p, Json2.s(data, "service", ""));
                // A scan started from this screen has to be cached too, otherwise
                // leaving and coming back loses exactly the run the user watched
                // here finish. See PortCache for why it is written per port.
                PortCache.save(c, d);
                cachedAt = PortCache.scannedAt(c, d.ip);
                render();
            }
        }
    }

    private void render() {
        body.removeAllViews();
        if (d == null) {
            body.addView(Widgets.emptyState(c, "◎", "Device gone", "Reselect a device."),
                    new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT));
            return;
        }

        LinearLayout card = Widgets.column(c);
        card.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        card.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 16), Widgets.dp(c, 16), Widgets.dp(c, 16));
        int color = NetworkScreen.kindColor(d.kind);
        card.addView(Widgets.label(c, d.ip, Design.T_TITLE_1, 700, Design.TEXT),
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
        TextView kind = Widgets.label(c, d.kind + (d.isGateway ? "  ·  gateway" : ""),
                Design.T_SUBHEAD, 400, color);
        LinearLayout.LayoutParams kp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        kp.topMargin = Widgets.dp(c, 2);
        card.addView(kind, kp);
        card.addView(Widgets.insetDivider(c, 0));
        card.addView(Widgets.kvRow("mac", d.mac.isEmpty() ? "—" : d.mac, Design.TEXT));
        card.addView(Widgets.kvRow("vendor", d.vendor.isEmpty() ? "—" : d.vendor, Design.TEXT));
        card.addView(Widgets.kvRow("hostname", d.hostname.isEmpty() ? "—" : d.hostname, Design.TEXT));
        card.addView(Widgets.kvRow("rtt", d.rttMs <= 0 ? "—"
                : String.format(java.util.Locale.US, "%.1f ms", d.rttMs), Design.TEXT));

        TextView scan = Widgets.button(c, "Full Port Scan", 1, Design.TINT);
        scan.setOnClickListener(v -> {
            Toast2.show(c, "Scanning 1-65535 on " + d.ip);
            Engine.get().portScan(d.ip, 1, 65535, 260, 96);
        });
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(0, Widgets.dp(c, 46));
        sp.topMargin = Widgets.dp(c, 14);
        card.addView(scan, sp);
        body.addView(card, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        body.addView(Widgets.sectionHeader(c, "Open ports (" + d.openPorts.size() + ")"));
        LinearLayout ports = Widgets.column(c);
        ports.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        if (d.openPorts.isEmpty()) {
            ports.addView(Widgets.label(c, "  none yet — run a scan",
                    Design.T_SUBHEAD, 400, Design.TEXT_3),
                    new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT));
        } else {
            Widgets.Flow flow = Widgets.flow(c);
            for (int p : d.openPorts) {
                flow.addView(Widgets.chip(c, p + " " + d.services.getOrDefault(p, ""), Design.GREEN));
            }
            ports.addView(flow, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            // Restored ports are not current by definition, and these are fed
            // straight into the exploit finder as live services downstream -- so
            // the age of the scan has to be on the same card as the list.
            if (cachedAt > 0) {
                ports.addView(Widgets.mono(c,
                        "scanned " + ModuleScreen.relativeAge(cachedAt),
                        Design.T_MONO_SM, 400, Design.TEXT_3),
                        new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                                ViewGroup.LayoutParams.WRAP_CONTENT));
            }
        }
        LinearLayout.LayoutParams pp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        pp.setMargins(0, 0, 0, Widgets.dp(c, 8));
        body.addView(ports, pp);

        body.addView(Widgets.sectionHeader(c, "Run a module"));
        for (String[] m : Design.MODULES) {
            final String key = m[0];
            LinearLayout r = Widgets.listRow(c, m[1], null, Design.moduleColor(key), null);
            r.addView(Widgets.label(c, "›", 22, 400, Design.TEXT_3),
                    new LinearLayout.LayoutParams(Widgets.dp(c, 12), ViewGroup.LayoutParams.WRAP_CONTENT));
            r.setOnClickListener(v -> {
                State.target = d;
                act.push(new ModuleScreen(act, key));
            });
            body.addView(r);
        }
    }

    /** Tiny indirection so the event handler reads cleanly. */
    static final class Json2 {
        static String s(Object o, String k, String dflt) {
            return com.zerosploit.util.Json.str(o, k, dflt);
        }

        static int i(Object o, String k) {
            return com.zerosploit.util.Json.i(o, k, 0);
        }
    }
}
