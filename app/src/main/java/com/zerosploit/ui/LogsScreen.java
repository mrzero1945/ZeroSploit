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

/** Logs tab: the full event stream, filterable by level. */
public class LogsScreen implements MainActivity.Screen, Engine.Listener {

    private static final String[] FILTERS = {"ALL", "INFO", "WARN", "ERROR"};

    private final Context c;
    private final LinearLayout page;
    /** page wrapped in a scroller; this is what view() hands out. */
    private final android.widget.ScrollView root;
    private final LinearLayout stream;
    private final LinearLayout filterRow;
    private int filter = 0;
    private int rendered;

    public LogsScreen(MainActivity act) {
        this.c = act;
        LinearLayout content = Widgets.column(c);
        page = content;
        root = Widgets.scroller(c, page);
        content.addView(Widgets.navBar(c, "Logs", "engine event stream", false, null));

        filterRow = Widgets.row(c);
        filterRow.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 4), Widgets.dp(c, 16), Widgets.dp(c, 8));
        content.addView(filterRow);
        renderChips();

        stream = Widgets.column(c);
        stream.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        stream.setPadding(Widgets.dp(c, 12), Widgets.dp(c, 10), Widgets.dp(c, 12), Widgets.dp(c, 10));
        content.addView(stream, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        content.addView(Widgets.banner(c,
                "Authorized networks only. Activity is logged locally and never leaves this device.",
                Design.TEXT_3, false), new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    private void renderChips() {
        filterRow.removeAllViews();
        for (int i = 0; i < FILTERS.length; i++) {
            final int idx = i;
            boolean on = i == filter;
            TextView f = Widgets.chip(c, FILTERS[i], on ? Design.TINT : Design.TEXT_3);
            if (on) {
                f.setBackground(Widgets.round(Design.withAlpha(Design.TINT, 40), Widgets.dp(c, 7)));
            }
            f.setOnClickListener(v -> {
                filter = idx;
                rendered = 0;
                stream.removeAllViews();
                renderChips();
                render(true);
            });
            LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            p.rightMargin = Widgets.dp(c, 8);
            filterRow.addView(f, p);
        }
        TextView clear = Widgets.label(c, "Clear", Design.T_FOOTNOTE, 400, Design.RED);
        clear.setPadding(Widgets.dp(c, 8), 0, 0, 0);
        clear.setOnClickListener(v -> {
            Engine.get().clearLogs();
            rendered = 0;
            stream.removeAllViews();
            render(true);
        });
        filterRow.addView(clear);
    }

    @Override
    public View view() {
        return root;
    }

    @Override
    public void onShown() {
        Engine.get().addListener(this);
        render(false);
    }

    @Override
    public void onHidden() {
        Engine.get().removeListener(this);
    }

    @Override
    public void onEvent(int jobId, String type, Object data) {
        if (!"log".equals(type)) return;
        if (!matches(Json.str(data, "level", "info"))) return;
        appendLine(data);
        rendered++;
    }

    private boolean matches(String level) {
        switch (filter) {
            case 0: return true;
            case 1: return "info".equals(level);
            case 2: return "warn".equals(level);
            case 3: return "error".equals(level);
            default: return true;
        }
    }

    private void render(boolean force) {
        List<Map<String, Object>> all = Engine.get().logs();
        if (all.isEmpty()) {
            if (force) {
                stream.addView(Widgets.label(c, "  no log lines yet",
                        Design.T_SUBHEAD, 400, Design.TEXT_3),
                        new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                                ViewGroup.LayoutParams.WRAP_CONTENT));
            }
            return;
        }
        int shown = 0;
        for (int i = all.size() - 1; i >= 0 && shown < 200; i--) {
            Map<String, Object> l = all.get(i);
            if (!matches(Json.str(l, "level", "info"))) continue;
            appendLine(l);
            shown++;
        }
        rendered = shown;
    }

    private void appendLine(Object data) {
        if (stream.getChildCount() == 1 && stream.getChildAt(0) instanceof TextView
                && "  no log lines yet".contentEquals(((TextView) stream.getChildAt(0)).getText())) {
            stream.removeAllViews();
        }
        String level = Json.str(data, "level", "info");
        int color = "error".equals(level) ? Design.RED
                : "warn".equals(level) ? Design.ORANGE : Design.TEXT_2;
        stream.addView(Widgets.kvRow(c,
                Json.str(data, "t", "") + "  " + Json.str(data, "tag", ""),
                Json.str(data, "msg", ""), color));
    }
}
