package com.zerosploit.ui;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.zerosploit.core.Engine;
import com.zerosploit.util.Json;

import java.util.List;
import java.util.Map;

/** Sessions tab: live and closed interactive sessions, plus the log stream. */
public class SessionsScreen implements MainActivity.Screen, Engine.Listener {

    private final Context c;
    private final LinearLayout page;
    /** page wrapped in a scroller; this is what view() hands out. */
    private final android.widget.ScrollView root;
    private final LinearLayout list;
    private final TextView summary;

    public SessionsScreen(MainActivity act) {
        this.c = act;
        LinearLayout content = Widgets.column(c);
        page = content;
        root = Widgets.scroller(c, page);
        content.addView(Widgets.navBar(c, "Sessions", "live shells", false, null));

        LinearLayout hdr = Widgets.column(c);
        hdr.setPadding(Widgets.dp(c, 20), 0, Widgets.dp(c, 20), 0);
        summary = Widgets.label(c, "no sessions", Design.T_SUBHEAD, 400, Design.TEXT_2);
        hdr.addView(summary, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        content.addView(hdr);

        list = Widgets.column(c);
        content.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
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
        if (type.equals("session") || type.equals("sessionData") || type.equals("log")) {
            render();
        }
    }

    private void render() {
        list.removeAllViews();
        List<Map<String, Object>> sessions = readSessions();
        summary.setText(sessions.isEmpty() ? "no sessions yet"
                : sessions.size() + " session(s) recorded");

        if (sessions.isEmpty()) {
            LinearLayout empty = Widgets.emptyState(c, "▤", "No sessions",
                    "Open a session from the Sessions module on a selected target.");
            empty.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
            list.addView(empty, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        } else {
            for (int i = 0; i < sessions.size(); i++) {
                Map<String, Object> s = sessions.get(i);
                String target = Json.str(s, "target", "?");
                String proto = Json.str(s, "proto", "?");
                String user = Json.str(s, "user", "");
                String priv = Json.str(s, "priv", "");
                String state = Json.str(s, "state", "?");
                boolean live = "live".equals(state);
                String sub = proto + (user.isEmpty() ? "" : " · " + user)
                        + (priv.isEmpty() ? "" : " · " + priv);
                TextView badge = Widgets.badge(c, state, live ? Design.GREEN : Design.TEXT_3);
                LinearLayout r = Widgets.listRow(c, target, sub,
                        live ? Design.GREEN : Design.TEXT_3, badge);
                list.addView(r);
                if (i < sessions.size() - 1) list.addView(Widgets.insetDivider(c, 16));
            }
        }

        // Recent log tail, so the tab is useful even with no sessions.
        list.addView(Widgets.sectionHeader(c, "Recent activity"));
        LinearLayout logs = Widgets.column(c);
        logs.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        logs.setPadding(Widgets.dp(c, 12), Widgets.dp(c, 10), Widgets.dp(c, 12), Widgets.dp(c, 10));
        List<Map<String, Object>> tail = Engine.get().logs();
        int from = Math.max(0, tail.size() - 12);
        if (from == tail.size()) {
            logs.addView(Widgets.label(c, "  nothing logged yet",
                    Design.T_SUBHEAD, 400, Design.TEXT_3),
                    new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT));
        }
        for (int i = tail.size() - 1; i >= from; i--) {
            Map<String, Object> l = tail.get(i);
            String level = Json.str(l, "level", "info");
            int color = "error".equals(level) ? Design.RED
                    : "warn".equals(level) ? Design.ORANGE : Design.TEXT_2;
            logs.addView(Widgets.kvRow(c,
                    Json.str(l, "t", "") + " " + Json.str(l, "tag", ""),
                    Json.str(l, "msg", ""), color));
        }
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.setMargins(Widgets.dp(c, 16), 0, Widgets.dp(c, 16), Widgets.dp(c, 20));
        list.addView(logs, p);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> readSessions() {
        List<Map<String, Object>> out = new java.util.ArrayList<>();
        Object payload = Engine.get().sessionList(c);
        List<Object> items = Json.arr(payload);
        if (items == null) {
            List<Object> nested = Json.arr(Json.obj(payload) == null ? null
                    : Json.obj(payload).get("sessions"));
            items = nested;
        }
        if (items == null) return out;
        for (Object o : items) {
            if (o instanceof Map) out.add((Map<String, Object>) o);
        }
        return out;
    }
}
