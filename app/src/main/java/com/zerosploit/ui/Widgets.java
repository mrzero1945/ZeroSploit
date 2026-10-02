package com.zerosploit.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

/** iOS-flavoured view primitives used across every screen. */
public final class Widgets {

    private Widgets() {}

    // ---- small builders ---------------------------------------------------
    public static int dp(Context c, float v) {
        return Design.dp(c, v);
    }

    public static LinearLayout column(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    public static LinearLayout row(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        return l;
    }

    public static LinearLayout.LayoutParams lp(int w, int h) {
        return new LinearLayout.LayoutParams(w, h);
    }

    public static LinearLayout.LayoutParams lp(int w, int h, float weight) {
        return new LinearLayout.LayoutParams(w, h, weight);
    }

    public static LinearLayout.LayoutParams lpMargin(Context c, int w, int h, float sideDp, float topDp, float bottomDp) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h);
        int s = dp(c, sideDp);
        p.setMargins(s, dp(c, topDp), s, dp(c, bottomDp));
        return p;
    }

    public static TextView label(Context c, String text, int size, int weight, int color) {
        TextView t = new TextView(c);
        t.setText(text == null ? "" : text);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, size);
        t.setTextColor(color);
        t.setTypeface(weight >= 600 ? Design.face(c, weight) : Design.sans(c));
        t.setIncludeFontPadding(false);
        return t;
    }

    public static TextView mono(Context c, String text, int size, int weight, int color) {
        TextView t = label(c, text, size, weight, color);
        t.setTypeface(Design.monoFace(c, weight));
        t.setLetterSpacing(0.02f);
        return t;
    }

    public static TextView spacer(Context c) {
        TextView t = new TextView(c);
        t.setText(" ");
        t.setIncludeFontPadding(false);
        return t;
    }

    // ---- surfaces ---------------------------------------------------------
    public static GradientDrawable round(int fill, float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.RECTANGLE);
        d.setColor(fill);
        d.setCornerRadius(radius);
        return d;
    }

    public static GradientDrawable stroke(int fill, int strokeColor, float radius, int strokeWidth) {
        GradientDrawable d = round(fill, radius);
        if (strokeWidth > 0) d.setStroke(strokeWidth, strokeColor);
        return d;
    }

    /** A grouped-list style card. */
    public static LinearLayout card(Context c) {
        LinearLayout v = column(c);
        v.setBackground(round(Design.BG_CARD, dp(c, Design.R_CARD)));
        v.setPadding(dp(c, 16), dp(c, 14), dp(c, 16), dp(c, 14));
        return v;
    }

    /**
     * Adds a child only when it carries text. A blank row still occupies
     * padding, which is what made half the network screen look like empty
     * space, so nothing without content is added at all.
     */
    public static <T extends View> T addText(ViewGroup parent, T view, String text,
            ViewGroup.LayoutParams lp) {
        if (text == null || text.trim().isEmpty()) return view;
        parent.addView(view, lp);
        return view;
    }

    /** Same, for a list of chips where each entry may be empty. */
    public static void addNonEmpty(ViewGroup parent, View view, String text,
            ViewGroup.LayoutParams lp) {
        if (text == null || text.trim().isEmpty()) return;
        parent.addView(view, lp);
    }

    /** A horizontal card: content sits beside itself, not stacked under it. */
    public static LinearLayout cardRow(Context c) {
        LinearLayout v = row(c);
        v.setBackground(round(Design.BG_CARD, dp(c, Design.R_CARD)));
        v.setPadding(dp(c, 16), dp(c, 14), dp(c, 16), dp(c, 14));
        v.setGravity(Gravity.CENTER_VERTICAL);
        return v;
    }

    public static View divider(Context c) {
        View v = new View(c);
        v.setBackgroundColor(Design.SEPARATOR);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, dp(c, 0.5f))));
        return v;
    }

    public static View insetDivider(Context c, float insetDp) {
        LinearLayout holder = new LinearLayout(c);
        holder.setOrientation(LinearLayout.HORIZONTAL);
        View spacer = new View(c);
        holder.addView(spacer, lp(dp(c, insetDp), 1));
        holder.addView(divider(c), lp(0, Math.max(1, dp(c, 0.5f))));
        return holder;
    }

    public static TextView sectionHeader(Context c, String text) {
        TextView t = label(c, text.toUpperCase(), Design.T_CAPTION, 600, Design.TEXT_3);
        t.setLetterSpacing(0.08f);
        LinearLayout.LayoutParams p = lpMargin(c, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, 20, 20, 8);
        t.setLayoutParams(p);
        return t;
    }

    // ---- controls ---------------------------------------------------------
    /** Filled / tinted / gray iOS button. */
    public static TextView button(Context c, String text, int kind, int accent) {
        TextView t = label(c, text, Design.T_HEADLINE, 600, Design.TEXT);
        int h = dp(c, 50);
        int padH = dp(c, 20);
        t.setPadding(padH, 0, padH, 0);
        t.setGravity(Gravity.CENTER);
        t.setMinHeight(h);
        GradientDrawable bg;
        if (kind == 0) {           // filled accent
            bg = round(accent, dp(c, Design.R_CONTROL));
        } else if (kind == 1) {    // tinted
            bg = round(Design.withAlpha(accent, 38), dp(c, Design.R_CONTROL));
        } else {                   // gray fill
            bg = round(Design.FILL, dp(c, Design.R_CONTROL));
        }
        t.setBackground(pressable(bg, accent));
        t.setTextColor(kind == 0 ? (isLight(accent) ? Design.BG : Design.TEXT) : accent);
        return t;
    }

    private static boolean isLight(int c) {
        double l = 0.2126 * Color.red(c) + 0.7152 * Color.green(c) + 0.0722 * Color.blue(c);
        return l > 170;
    }

    private static StateListDrawable pressable(GradientDrawable normal, int accent) {
        StateListDrawable s = new StateListDrawable();
        GradientDrawable down = round(Design.darken(accent, 0.18f), normal.getCornerRadius());
        s.addState(new int[]{android.R.attr.state_pressed}, down);
        s.addState(new int[]{}, normal);
        return s;
    }

    /** Small capsule label, e.g. a port number or a state tag. */
    public static TextView chip(Context c, String text, int color) {
        TextView t = mono(c, text, Design.T_MONO_SM, 600, color);
        t.setBackground(round(Design.withAlpha(color, 34), dp(c, 7)));
        t.setPadding(dp(c, 7), dp(c, 3), dp(c, 7), dp(c, 3));
        t.setGravity(Gravity.CENTER);
        return t;
    }

    public static TextView badge(Context c, String text, int color) {
        TextView t = label(c, text, Design.T_CAPTION_2, 700, color);
        t.setBackground(round(Design.withAlpha(color, 30), dp(c, 6)));
        t.setPadding(dp(c, 6), dp(c, 2), dp(c, 6), dp(c, 2));
        return t;
    }

    /** Circular status indicator. */
    public static View dot(Context c, int color, int sizeDp) {
        View v = new View(c);
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.OVAL);
        d.setColor(color);
        v.setBackground(d);
        int s = dp(c, sizeDp);
        v.setLayoutParams(new LinearLayout.LayoutParams(s, s));
        return v;
    }

    // ---- rows -------------------------------------------------------------
    /**
     * Grouped-list row: optional leading dot/view, title, subtitle, trailing view.
     */
    public static LinearLayout listRow(Context c, String title, String subtitle, int dotColor,
                                       View trailing) {
        LinearLayout r = row(c);
        r.setPadding(dp(c, 16), dp(c, 12), dp(c, 16), dp(c, 12));
        r.setBackgroundColor(Color.TRANSPARENT);

        LinearLayout textCol = column(c);
        LinearLayout.LayoutParams textLp = lp(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        textCol.setLayoutParams(textLp);
        textCol.setPadding(dp(c, 10), 0, dp(c, 10), 0);

        TextView t = label(c, title, Design.T_BODY, 400, Design.TEXT);
        t.setMaxLines(1);
        t.setEllipsize(TextUtils.TruncateAt.END);
        textCol.addView(t, lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        if (subtitle != null && !subtitle.isEmpty()) {
            TextView s = label(c, subtitle, Design.T_FOOTNOTE, 400, Design.TEXT_2);
            s.setMaxLines(2);
            s.setEllipsize(TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams p = lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            p.topMargin = dp(c, 3);
            textCol.addView(s, p);
        }
        r.addView(textCol);

        if (dotColor != 0) r.addView(dot(c, dotColor, 8), lp(dp(c, 8), dp(c, 8)));
        if (trailing != null) {
            LinearLayout.LayoutParams tp = lp(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            tp.leftMargin = dp(c, 8);
            r.addView(trailing, tp);
        }
        return r;
    }

    /** Monospace key/value line used in detail sheets. */
    public static LinearLayout kv(Context c, String key, String value, int valueColor) {
        LinearLayout r = column(c);
        TextView k = mono(c, key, Design.T_MONO_SM, 400, Design.TEXT_3);
        TextView v = mono(c, value, Design.T_MONO, 500, valueColor);
        LinearLayout.LayoutParams p = lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(c, 8);
        v.setLayoutParams(p);
        v.setTextIsSelectable(true);
        r.addView(k);
        r.addView(v);
        return r;
    }

    public static LinearLayout kvRow(Context c, String key, String value, int valueColor) {
        LinearLayout r = row(c);
        r.setPadding(0, dp(c, 7), 0, dp(c, 7));
        TextView k = mono(c, key, Design.T_MONO_SM, 400, Design.TEXT_3);
        r.addView(k, lp(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        TextView v = mono(c, value, Design.T_MONO, 500, valueColor);
        v.setGravity(Gravity.END);
        v.setMaxLines(2);
        v.setEllipsize(TextUtils.TruncateAt.END);
        r.addView(v);
        return r;
    }

    // ---- progress ---------------------------------------------------------
    /**
     * Thin iOS-style determinate bar.
     *
     * <p>The onMeasure is not decoration. A plain {@link View} falls back to
     * {@code getDefaultSize}, which hands back the whole AT_MOST bound, so in a
     * vertical column this bar grew to swallow all the space left below it and
     * pushed the run button off the end of the scroller. It measured 1771px tall
     * on a 2426px page: the "Start Port Scan" button was still built and still
     * wired up, just never reachable.
     */
    public static class Bar extends View {
        private static final int THICKNESS_DP = 4;
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private float pct = 0f;
        private int accent = Design.TINT;

        public Bar(Context c) {
            super(c);
            setWillNotDraw(false);
        }

        @Override
        protected void onMeasure(int widthSpec, int heightSpec) {
            int h = dp(getContext(), THICKNESS_DP);
            setMeasuredDimension(
                    getDefaultSize(getSuggestedMinimumWidth(), widthSpec),
                    resolveSize(h, heightSpec));
        }

        public void setProgress(float p, int color) {
            this.pct = Math.max(0f, Math.min(1f, p));
            this.accent = color;
            invalidate();
        }

        public void setProgress(float p) {
            setProgress(p, accent);
        }

        @Override
        protected void onDraw(Canvas canvas) {
            int h = getHeight();
            float r = h / 2f;
            paint.setColor(Design.FILL);
            canvas.drawRoundRect(new RectF(0, 0, getWidth(), h), r, r, paint);
            if (pct <= 0) return;
            paint.setColor(accent);
            canvas.drawRoundRect(new RectF(0, 0, getWidth() * pct, h), r, r, paint);
        }
    }

    /** Circular progress ring with a percentage in the middle. */
    public static class Ring extends View {
        private final Paint track = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint arc = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint text = new Paint(Paint.ANTI_ALIAS_FLAG);
        private float pct = 0f;
        private int accent = Design.TINT;
        private String label = "";

        public Ring(Context c) {
            super(c);
            track.setStyle(Paint.Style.STROKE);
            arc.setStyle(Paint.Style.STROKE);
            arc.setStrokeCap(Paint.Cap.ROUND);
            text.setTextAlign(Paint.Align.CENTER);
        }

        public void setProgress(float p, int color, String labelText) {
            this.pct = Math.max(0f, Math.min(1f, p));
            this.accent = color;
            this.label = labelText == null ? "" : labelText;
            invalidate();
        }

        @Override
        protected void onDraw(Canvas canvas) {
            float size = Math.min(getWidth(), getHeight());
            float stroke = size * 0.09f;
            track.setStrokeWidth(stroke);
            arc.setStrokeWidth(stroke);
            track.setColor(Design.FILL);
            arc.setColor(accent);
            float inset = stroke / 2f + 2f;
            RectF box = new RectF(inset, inset, size - inset, size - inset);
            canvas.drawArc(box, 0, 360, false, track);
            canvas.drawArc(box, -90, 360 * pct, false, arc);
            text.setColor(Design.TEXT);
            text.setTextSize(size * 0.22f);
            text.setTypeface(Design.face(getContext(), 600));
            Paint.FontMetrics fm = text.getFontMetrics();
            float cy = size / 2f - (fm.ascent + fm.descent) / 2f;
            canvas.drawText(label.isEmpty() ? (int) (pct * 100) + "%" : label, size / 2f, cy, text);
        }
    }

    /** Circular activity indicator. */
    public static class Spinner extends View {
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private float angle = 0f;
        private final android.os.Handler h = new android.os.Handler(android.os.Looper.getMainLooper());
        private boolean running;

        public Spinner(Context c) {
            super(c);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeCap(Paint.Cap.ROUND);
            paint.setColor(Design.TINT);
        }

        public void start() {
            if (running) return;
            running = true;
            h.post(tick);
        }

        public void stop() {
            running = false;
            h.removeCallbacks(tick);
            invalidate();
        }

        private final Runnable tick = new Runnable() {
            @Override
            public void run() {
                if (!running) return;
                angle = (angle + 11f) % 360f;
                invalidate();
                h.postDelayed(this, 16);
            }
        };

        @Override
        protected void onDraw(Canvas canvas) {
            float size = Math.min(getWidth(), getHeight());
            paint.setStrokeWidth(size * 0.11f);
            RectF box = new RectF(size * 0.13f, size * 0.13f, size * 0.87f, size * 0.87f);
            for (int i = 0; i < 12; i++) {
                double a = Math.toRadians(angle + i * 30f);
                paint.setAlpha(30 + (int) (200 * (i / 11f)));
                canvas.drawArc(box, (float) Math.toDegrees(a), 26f, false, paint);
            }
        }
    }

    /** Wraps text in a flow layout; used for chips and tags. */
    public static Flow flow(Context c) {
        return new Flow(c);
    }

    public static class Flow extends ViewGroup {
        private final android.util.SparseIntArray positions = new android.util.SparseIntArray();

        public Flow(Context c) {
            super(c);
        }

        @Override
        public LayoutParams generateDefaultLayoutParams() {
            return new MarginLayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        }

        @Override
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = MeasureSpec.getSize(widthMeasureSpec);
            int avail = width - getPaddingLeft() - getPaddingRight();
            int x = 0, y = 0, lineH = 0;
            for (int i = 0; i < getChildCount(); i++) {
                View c = getChildAt(i);
                measureChild(c, widthMeasureSpec, heightMeasureSpec);
                MarginLayoutParams mp = (MarginLayoutParams) c.getLayoutParams();
                int cw = c.getMeasuredWidth() + mp.leftMargin + mp.rightMargin;
                if (x > 0 && x + cw > avail) {
                    positions.put(i, x);
                    x = 0;
                    y += lineH;
                    lineH = 0;
                }
                x += cw;
                lineH = Math.max(lineH, c.getMeasuredHeight() + mp.topMargin + mp.bottomMargin);
            }
            setMeasuredDimension(width, y + lineH + getPaddingTop() + getPaddingBottom());
        }

        @Override
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int avail = getWidth() - getPaddingLeft() - getPaddingRight();
            int x = 0, y = getPaddingTop(), lineH = 0;
            for (int i = 0; i < getChildCount(); i++) {
                View c = getChildAt(i);
                MarginLayoutParams mp = (MarginLayoutParams) c.getLayoutParams();
                int cw = c.getMeasuredWidth() + mp.leftMargin + mp.rightMargin;
                if (x > 0 && x + cw > avail) {
                    x = 0;
                    y += lineH;
                    lineH = 0;
                }
                c.layout(getPaddingLeft() + x + mp.leftMargin, y + mp.topMargin,
                        getPaddingLeft() + x + mp.leftMargin + c.getMeasuredWidth(),
                        y + mp.topMargin + c.getMeasuredHeight());
                x += cw;
                lineH = Math.max(lineH, c.getMeasuredHeight() + mp.topMargin + mp.bottomMargin);
            }
        }
    }

    // ---- context-free convenience wrappers --------------------------------
    // Design.bind() is called from MainActivity, so these can rely on the
    // application context and keep call sites short.
    /** Application context, bound once by MainActivity. */
    public static Context ctx() {
        return Design.context();
    }

    public static int dp(float v) {
        return Design.dp(ctx(), v);
    }

    public static LinearLayout kvRow(String key, String value, int color) {
        return kvRow(ctx(), key, value, color);
    }

    public static LinearLayout kv(String key, String value, int color) {
        return kv(ctx(), key, value, color);
    }

    public static LinearLayout listRow(String title, String subtitle, int dotColor, View trailing) {
        return listRow(ctx(), title, subtitle, dotColor, trailing);
    }

    public static TextView sectionHeader(String text) {
        return sectionHeader(ctx(), text);
    }

    public static View divider() {
        return divider(ctx());
    }

    public static View insetDivider(float insetDp) {
        return insetDivider(ctx(), insetDp);
    }

    public static LinearLayout emptyState(String glyph, String headline, String body) {
        return emptyState(ctx(), glyph, headline, body);
    }

    public static LinearLayout banner(String text, int accent, boolean solid) {
        return banner(ctx(), text, accent, solid);
    }

    public static TextView button(String text, int kind, int accent) {
        return button(ctx(), text, kind, accent);
    }

    public static TextView chip(String text, int color) {
        return chip(ctx(), text, color);
    }

    public static TextView badge(String text, int color) {
        return badge(ctx(), text, color);
    }

    public static TextView label(String text, int size, int weight, int color) {
        return label(ctx(), text, size, weight, color);
    }

    public static TextView mono(String text, int size, int weight, int color) {
        return mono(ctx(), text, size, weight, color);
    }

    public static LinearLayout card() {
        return card(ctx());
    }

    public static LinearLayout row() {
        return row(ctx());
    }

    public static LinearLayout column() {
        return column(ctx());
    }

    public static android.widget.ImageView icon(int res, int tint) {
        return icon(ctx(), res, tint);
    }

    public static LinearLayout.LayoutParams lpMargin(int w, int h, float side, float top, float bottom) {
        return lpMargin(ctx(), w, h, side, top, bottom);
    }

    // ---- screen chrome ----------------------------------------------------
    /** iOS navigation bar: large title, optional subtitle, optional back affordance. */
    public static LinearLayout navBar(Context c, String title, String subtitle, boolean back,
                                       View.OnClickListener onBack) {
        LinearLayout nav = column(c);
        nav.setPadding(dp(c, 16), dp(c, 4), dp(c, 16), dp(c, 10));

        if (back) {
            LinearLayout top = row(c);
            TextView b = label(c, "\u2039 Back", Design.T_BODY, 400, Design.TINT);
            b.setPadding(dp(c, 2), dp(c, 4), dp(c, 10), dp(c, 4));
            b.setOnClickListener(onBack);
            top.addView(b, lp(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            nav.addView(top, lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        }

        LinearLayout titles = column(c);
        TextView t = label(c, title, back ? Design.T_TITLE_3 : Design.T_LARGE_TITLE,
                back ? 600 : 700, Design.TEXT);
        t.setSingleLine(true);
        t.setEllipsize(TextUtils.TruncateAt.END);
        titles.addView(t, lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        if (subtitle != null && !subtitle.isEmpty()) {
            TextView s = label(c, subtitle, Design.T_FOOTNOTE, 400, Design.TEXT_2);
            s.setSingleLine(true);
            s.setEllipsize(TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams p = lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            p.topMargin = dp(c, 2);
            titles.addView(s, p);
        }
        nav.addView(titles, lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return nav;
    }

    /** Bottom tab bar. */
    public static LinearLayout tabBar(Context c, String[] labels, int[] icons, int selected, OnTabClick cb) {
        LinearLayout bar = new LinearLayout(c);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER);
        bar.setBackgroundColor(Design.withAlpha(Design.BG_SECTION, 235));
        bar.setPadding(dp(c, 4), dp(c, 6), dp(c, 4), dp(c, 4));
        for (int i = 0; i < labels.length; i++) {
            final int index = i;
            LinearLayout item = column(c);
            item.setGravity(Gravity.CENTER);
            int color = i == selected ? Design.TINT : Design.TEXT_3;
            item.addView(icon(c, icons[i], color), lp(dp(c, 24), dp(c, 24)));
            TextView lbl = label(c, labels[i], Design.T_CAPTION_2, i == selected ? 600 : 400, color);
            lbl.setPadding(0, dp(c, 3), 0, 0);
            item.addView(lbl, lp(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            item.setPadding(0, dp(c, 2), 0, dp(c, 2));
            item.setOnClickListener(v -> cb.onTab(index));
            bar.addView(item, lp(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        }
        return bar;
    }

    public interface OnTabClick {
        void onTab(int index);
    }

    /** Tinted SF-style icon. */
    public static android.widget.ImageView icon(Context c, int res, int tint) {
        android.widget.ImageView iv = new android.widget.ImageView(c);
        iv.setImageResource(res);
        iv.setColorFilter(tint, android.graphics.PorterDuff.Mode.SRC_IN);
        iv.setScaleType(android.widget.ImageView.ScaleType.FIT_CENTER);
        return iv;
    }

    /** Empty-state block: icon glyph, headline, supporting text. */
    /**
     * Placeholder for a list with nothing in it. The padding is deliberately
     * small: an empty list that reserves a tall block reads as a broken layout,
     * and the space is wasted once the first row arrives.
     */
    public static LinearLayout emptyState(Context c, String glyph, String headline, String body) {
        LinearLayout v = column(c);
        v.setGravity(Gravity.CENTER_HORIZONTAL);
        // No padding: an empty list should occupy only the lines it prints.
        v.setPadding(0, 0, 0, 0);
        TextView g = label(c, glyph, 40, 400, Design.TEXT_3);
        g.setGravity(Gravity.CENTER);
        v.addView(g, lp(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        TextView h = label(c, headline, Design.T_HEADLINE, 600, Design.TEXT_2);
        h.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams p = lp(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(c, 12);
        v.addView(h, p);
        TextView b = label(c, body, Design.T_SUBHEAD, 400, Design.TEXT_3);
        b.setGravity(Gravity.CENTER);
        b.setLineSpacing(dp(c, 3), 1f);
        LinearLayout.LayoutParams p2 = lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p2.topMargin = dp(c, 6);
        v.addView(b, p2);
        return v;
    }

    /** Rounded translucent container used for banners and warnings. */
    public static LinearLayout banner(Context c, String text, int accent, boolean solid) {
        LinearLayout v = column(c);
        v.setBackground(stroke(solid ? Design.withAlpha(accent, 30) : Color.TRANSPARENT,
                Design.withAlpha(accent, solid ? 60 : 90), dp(c, Design.R_CONTROL), dp(c, 1)));
        v.setPadding(dp(c, 13), dp(c, 11), dp(c, 13), dp(c, 11));
        TextView t = label(c, text, Design.T_FOOTNOTE, 400, accent);
        t.setLineSpacing(dp(c, 2), 1f);
        v.addView(t, lp(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return v;
    }

    /**
     * Wraps a screen column in a vertical scroller.
     *
     * <p>Every screen builds a plain LinearLayout, which the tab container
     * cannot scroll, so anything taller than the window was simply cut off.
     * The scrollbar and the glow overscroll are hidden to match the iOS look,
     * and a bottom inset keeps the last row clear of the tab bar.
     */
    public static android.widget.ScrollView scroller(Context c, View content) {
        android.widget.ScrollView sv = new android.widget.ScrollView(c);
        sv.setFillViewport(true);
        sv.setClipToPadding(false);
        sv.setVerticalScrollBarEnabled(false);
        sv.setHorizontalScrollBarEnabled(false);
        sv.setOverScrollMode(View.OVER_SCROLL_NEVER);
        sv.setBackgroundColor(Color.TRANSPARENT);
        sv.addView(content, new android.widget.ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return sv;
    }

    /** Convenience: a full-width scrollable page with vertical padding. */
    public static FrameLayout page(Context c, LinearLayout content) {
        FrameLayout f = new FrameLayout(c);
        android.widget.ScrollView sv = new android.widget.ScrollView(c);
        sv.setFillViewport(true);
        sv.setClipToPadding(false);
        content.setPadding(0, dp(c, 6), 0, dp(c, 24));
        sv.addView(content, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        f.addView(sv, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        return f;
    }
}
