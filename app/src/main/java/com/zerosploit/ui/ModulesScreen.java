package com.zerosploit.ui;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.zerosploit.core.Engine;
import com.zerosploit.core.State;

/**
 * Modules tab: the eight tool tiles. A tile is enabled only when a target has
 * been picked, mirroring the intended flow Network -> Target -> Module.
 */
public class ModulesScreen implements MainActivity.Screen {

    private final Context c;
    private final MainActivity act;
    private final LinearLayout page;
    /** page wrapped in a scroller; this is what view() hands out. */
    private final android.widget.ScrollView root;
    private final LinearLayout grid;
    private final TextView targetLine;

    public ModulesScreen(MainActivity act) {
        this.act = act;
        this.c = act;
        LinearLayout content = Widgets.column(c);
        page = content;
        root = Widgets.scroller(c, page);

        content.addView(Widgets.navBar(c, "Modules",
                Design.MODULES.length + " tools", false, null));

        LinearLayout hdr = Widgets.column(c);
        hdr.setPadding(Widgets.dp(c, 20), 0, Widgets.dp(c, 20), Widgets.dp(c, 4));
        targetLine = Widgets.label(c, "No target selected", Design.T_SUBHEAD, 400, Design.TEXT_2);
        hdr.addView(targetLine, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        content.addView(hdr);

        grid = Widgets.column(c);
        grid.setPadding(Widgets.dp(c, 16), Widgets.dp(c, 10), Widgets.dp(c, 16), Widgets.dp(c, 20));
        content.addView(grid);
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
        final boolean hasTarget = State.target != null;
        if (hasTarget) {
            targetLine.setText("Target  " + State.target.ip + "  ·  " + State.target.label());
            targetLine.setTextColor(Design.TEXT_2);
        } else {
            targetLine.setText("No target selected — pick a device on the Network tab");
            targetLine.setTextColor(Design.TEXT_3);
        }

        grid.removeAllViews();
        String[][] mods = Design.MODULES;
        for (int r = 0; r < mods.length; r += 2) {
            LinearLayout line = Widgets.row(c);
            line.setPadding(0, 0, 0, Widgets.dp(c, 10));
            for (int col = 0; col < 2 && r + col < mods.length; col++) {
                final String[] m = mods[r + col];
                View tile = tile(m, hasTarget);
                LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0,
                        ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                if (col == 0) p.rightMargin = Widgets.dp(c, 6);
                else p.leftMargin = Widgets.dp(c, 6);
                line.addView(tile, p);
            }
            grid.addView(line, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        }
    }

    private View tile(String[] m, boolean enabled) {
        final String key = m[0];
        final String label = m[1];
        int accent = Design.moduleColor(key);

        LinearLayout v = Widgets.column(c);
        v.setGravity(Gravity.CENTER_HORIZONTAL);
        v.setPadding(Widgets.dp(c, 14), Widgets.dp(c, 18), Widgets.dp(c, 14), Widgets.dp(c, 16));
        v.setBackground(Widgets.round(Design.BG_CARD, Widgets.dp(c, Design.R_CARD)));
        v.setAlpha(enabled ? 1f : 0.55f);

        int iconRes = Design.moduleIcon(key);
        if (iconRes != 0) {
            v.addView(Widgets.icon(c, iconRes, enabled ? accent : Design.TEXT_3),
                    new LinearLayout.LayoutParams(Widgets.dp(c, 34), Widgets.dp(c, 34)));
        }
        TextView title = Widgets.label(c, label, Design.T_FOOTNOTE, 600,
                enabled ? Design.TEXT : Design.TEXT_3);
        title.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        tp.topMargin = Widgets.dp(c, 10);
        v.addView(title, tp);

        TextView sub = Widgets.label(c, enabled ? "Run" : "Select target",
                Design.T_CAPTION_2, 400, enabled ? accent : Design.TEXT_3);
        sub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.topMargin = Widgets.dp(c, 2);
        v.addView(sub, sp);

        v.setOnClickListener(view -> {
            if (!enabled) {
                Toast2.show(c, "Select a target on the Network tab first");
                return;
            }
            act.push(new ModuleScreen(act, key));
        });
        return v;
    }
}
