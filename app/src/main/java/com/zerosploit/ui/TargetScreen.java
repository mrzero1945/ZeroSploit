package com.zerosploit.ui;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.zerosploit.core.Engine;
import com.zerosploit.core.State;

/**
 * Target tab: the currently selected device plus the eight module shortcuts,
 * so a target can be chosen and acted on without leaving the tab bar.
 */
public class TargetScreen implements MainActivity.Screen {

    private final Context c;
    private final MainActivity act;
    private final LinearLayout page;
    /** page wrapped in a scroller; this is what view() hands out. */
    private final android.widget.ScrollView root;
    private final LinearLayout body;

    public TargetScreen(MainActivity act) {
        this.act = act;
        this.c = act;
        LinearLayout content = Widgets.column(c);
        page = content;
        root = Widgets.scroller(c, page);
        content.addView(Widgets.navBar(c, "Target", "selected device", false, null));
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
        render();
    }

    @Override
    public void onTabSelected() {
        render();
    }

    private void render() {
        body.removeAllViews();
        State.Device d = State.target;
        if (d == null) {
            LinearLayout empty = Widgets.emptyState(c, "◎", "No target selected",
                    "Choose a device on the Network tab, then come back here to run a module.");
            empty.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
            body.addView(empty, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            return;
        }

        // ---- identity card
        LinearLayout card = Widgets.column(c);
        card.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        card.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 16), Widgets.dp(c, 16), Widgets.dp(c, 16));
        int color = NetworkScreen.kindColor(d.kind);

        LinearLayout head = Widgets.row(c);
        int iconRes = Design.moduleIcon("service");
        if (iconRes != 0) {
            head.addView(Widgets.icon(c, iconRes, color),
                    new LinearLayout.LayoutParams(Widgets.dp(c, 34), Widgets.dp(c, 34)));
        }
        LinearLayout nameCol = Widgets.column(c);
        LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        nameLp.leftMargin = Widgets.dp(c, 12);
        nameCol.setLayoutParams(nameLp);
        nameCol.addView(Widgets.label(c, d.label(), Design.T_TITLE_3, 600, Design.TEXT),
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
        nameCol.addView(Widgets.mono(c, d.ip, Design.T_SUBHEAD, 400, Design.TEXT_2),
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
        head.addView(nameCol);
        head.addView(Widgets.badge(c, d.kind.toUpperCase(), color));
        card.addView(head);

        card.addView(Widgets.insetDivider(c, 0));
        card.addView(Widgets.kvRow("mac", d.mac.isEmpty() ? "—" : d.mac, Design.TEXT));
        card.addView(Widgets.kvRow("vendor", d.vendor.isEmpty() ? "—" : d.vendor, Design.TEXT));
        card.addView(Widgets.kvRow("hostname", d.hostname.isEmpty() ? "—" : d.hostname, Design.TEXT));
        card.addView(Widgets.kvRow("source", d.source.isEmpty() ? "—" : d.source, Design.TEXT_2));
        card.addView(Widgets.kvRow("gateway", d.isGateway ? "yes" : "no",
                d.isGateway ? Design.GREEN : Design.TEXT_2));
        card.addView(Widgets.kvRow("rtt", d.rttMs <= 0 ? "—"
                : String.format(java.util.Locale.US, "%.1f ms", d.rttMs), Design.TEXT));
        body.addView(card, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // ---- open ports
        body.addView(Widgets.sectionHeader(c, "Open ports"));
        LinearLayout ports = Widgets.column(c);
        ports.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        if (d.openPorts.isEmpty()) {
            ports.addView(Widgets.label(c, "  none detected yet",
                    Design.T_SUBHEAD, 400, Design.TEXT_3),
                    new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT));
        } else {
            Widgets.Flow flow = Widgets.flow(c);
            for (int p : d.openPorts) {
                String svc = d.services.get(p);
                flow.addView(Widgets.chip(c, svc == null ? String.valueOf(p) : p + " " + svc,
                        Design.GREEN));
            }
            ports.addView(flow, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        }
        body.addView(ports, margin(0, 0, 0, 8));

        // ---- module shortcuts
        body.addView(Widgets.sectionHeader(c, "Modules"));
        for (String[] m : Design.MODULES) {
            final String key = m[0];
            int accent = Design.moduleColor(key);
            LinearLayout r = Widgets.listRow(c, m[1], describe(key), accent, null);
            TextView go = Widgets.label(c, "›", 22, 400, Design.TEXT_3);
            r.addView(go, new LinearLayout.LayoutParams(Widgets.dp(c, 12),
                    ViewGroup.LayoutParams.WRAP_CONTENT));
            r.setOnClickListener(v -> act.push(new ModuleScreen(act, key)));
            body.addView(r);
        }
    }

    private String describe(String key) {
        switch (key) {
            case "portscan": return "TCP connect scan across all ports";
            case "service": return "Banner grab and fingerprint " + State.target.openPorts.size() + " port(s)";
            case "exploit": return "Match version against a local CVE table";
            case "login": return "Default-credential audit";
            case "sessions": return "Attempt an interactive session";
            case "mitm": return "ARP poisoning, needs root";
            case "forger": return "Craft and inject a raw frame, needs root";
            case "wifi": return "802.11 deauthentication, needs root";
            default: return "";
        }
    }

    private LinearLayout.LayoutParams margin(int side, int top, int side2, int bottom) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.setMargins(Widgets.dp(c, side), Widgets.dp(c, top), Widgets.dp(c, side2), Widgets.dp(c, bottom));
        return p;
    }
}
