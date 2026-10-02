package com.zerosploit.ui;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import android.widget.Toast;

/** iOS-style transient toast, replacing the stock Android toast. */
public final class Toast2 {

    private Toast2() {}

    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    public static void show(Context c, String message) {
        if (c == null || message == null || message.isEmpty()) return;
        MAIN.post(() -> {
            try {
                Toast toast = Toast.makeText(c, message, Toast.LENGTH_SHORT);
                ViewGroup root = (ViewGroup) toast.getView();
                if (root != null && root.getChildCount() > 0) {
                    TextView old = root.getChildAt(0) instanceof TextView ? (TextView) root.getChildAt(0) : null;
                    if (old != null) {
                        old.setTextColor(Design.TEXT);
                        old.setTextSize(13);
                        old.setTypeface(Design.sans(c));
                        old.setGravity(Gravity.CENTER);
                        old.setPadding(Widgets.dp(c, 18), Widgets.dp(c, 12), Widgets.dp(c, 18), Widgets.dp(c, 12));
                        old.setBackground(Widgets.round(Design.BG_ELEV_2, Widgets.dp(c, 14)));
                    }
                }
                toast.show();
            } catch (Throwable ignored) {
                // A missing toast is never worth crashing a scan over.
            }
        });
    }

    /** Convenience for building an inline inline message row. */
    public static LinearLayout inline(Context c, String message, int accent) {
        LinearLayout v = Widgets.banner(c, message, accent, true);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        return v;
    }
}
