package com.zerosploit.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.util.TypedValue;

/**
 * Design tokens, mirroring {@code design/theme.py} so the runtime UI and the
 * Inkscape screens stay in sync. Values are the same iOS metrics used in the
 * SVG: 393x852pt canvas, 44pt nav bar, 49pt tab bar, iOS dark system palette.
 */
public final class Design {

    private Design() {}

    /** Bound once from MainActivity so resource lookups have a context. */
    public static void bind(Context ctx) {
        c = ctx.getApplicationContext();
    }

    public static Context context() {
        return c;
    }

    // ---- canvas & chrome (iPhone 15/16 Pro logical points) -----------------
    public static final int W = 393;
    public static final int H = 852;
    public static final int SA_TOP = 59;
    public static final int SA_BOTTOM = 34;
    public static final int NAV_H = 44;
    public static final int TABBAR_H = 49;
    public static final int CONTENT_TOP = SA_TOP + NAV_H;                 // 103
    public static final int CONTENT_BOTTOM = H - TABBAR_H - SA_BOTTOM;    // 769

    // ---- corner radii ----------------------------------------------------
    public static final int R_CARD = 18;
    public static final int R_LARGE = 24;
    public static final int R_SHEET = 28;
    public static final int R_CONTROL = 12;

    // ---- system backgrounds ----------------------------------------------
    public static final int BG = 0xFF000000;
    public static final int BG_ELEV = 0xFF1C1C1E;
    public static final int BG_ELEV_2 = 0xFF2C2C2E;
    public static final int BG_CARD = 0xFF1C1C1E;
    public static final int BG_SECTION = 0xFF141416;
    public static final int FILL = 0x3E787880;
    public static final int FILL_2 = 0x2A787880;
    public static final int FILL_3 = 0x1F767880;
    public static final int SEPARATOR = 0xA6545454;
    public static final int HAIRLINE = 0x73545454;

    // ---- labels ----------------------------------------------------------
    public static final int TEXT = 0xFFFFFFFF;
    public static final int TEXT_2 = 0x99EBEBF5;
    public static final int TEXT_3 = 0x4DEBEBF5;
    public static final int TEXT_4 = 0x2EEBEBF5;

    // ---- system tints ----------------------------------------------------
    public static final int BLUE = 0xFF0A84FF;
    public static final int GREEN = 0xFF30D158;
    public static final int INDIGO = 0xFF5E5CE6;
    public static final int ORANGE = 0xFFFF9F0A;
    public static final int PINK = 0xFFFF375F;
    public static final int PURPLE = 0xFFBF5AF2;
    public static final int RED = 0xFFFF453A;
    public static final int TEAL = 0xFF40C8E0;
    public static final int YELLOW = 0xFFFFD60A;
    public static final int MINT = 0xFF63E6E2;
    public static final int CYAN = 0xFF64D2FF;
    public static final int TINT = BLUE;

    // ---- module catalogue (mirrors theme.MODULES) ------------------------
    public static final String[][] MODULES = {
        {"portscan", "Port Scanner", "0A84FF"},
        {"trace", "Traceroute", "5E5CE6"},
        {"service", "Service Inspect", "40C8E0"},
        {"exploit", "Exploit Finder", "FF453A"},
        {"login", "Login Auditor", "FF9F0A"},
        {"sessions", "Sessions", "BF5AF2"},
        {"mitm", "MITM", "FF375F"},
        {"sniffer", "Password Sniffer", "BF5AF2"},
        {"dns", "DNS Spoofing", "AC8E68"},
        {"hijack", "Hijacker", "64D2FF"},
        {"forger", "Packet Forger", "63E6E2"},
        {"wifi", "Wi-Fi Kill", "FFD60A"},
    };

    public static int moduleColor(String key) {
        for (String[] m : MODULES) {
            if (m[0].equals(key)) return Color.parseColor("#" + m[2]);
        }
        return TINT;
    }

    public static String moduleLabel(String key) {
        for (String[] m : MODULES) {
            if (m[0].equals(key)) return m[1];
        }
        return key;
    }

    public static int moduleIcon(String key) {
        // Glyphs are exported from design/icons/glyph_<key>.svg to gl_<key>.png.
        return getDrawable("gl_" + key);
    }

    public static int tabIcon(String key) {
        return getDrawable("gl_tab_" + key);
    }

    /** Drawable lookup by name, returning 0 when the asset is absent. */
    public static int getDrawable(String name) {
        try {
            return c.getResources().getIdentifier(name, "drawable", c.getPackageName());
        } catch (Throwable t) {
            return 0;
        }
    }

    private static Context c;

    // ---- type scale (size, weight) ---------------------------------------
    public static final int T_LARGE_TITLE = 34, W_LARGE_TITLE = 700;
    public static final int T_TITLE_1 = 28, W_TITLE_1 = 700;
    public static final int T_TITLE_2 = 22, W_TITLE_2 = 700;
    public static final int T_TITLE_3 = 20, W_TITLE_3 = 600;
    public static final int T_HEADLINE = 17, W_HEADLINE = 600;
    public static final int T_BODY = 17, W_BODY = 400;
    public static final int T_CALL_OUT = 16, W_CALL_OUT = 400;
    public static final int T_SUBHEAD = 15, W_SUBHEAD = 400;
    public static final int T_FOOTNOTE = 13, W_FOOTNOTE = 400;
    public static final int T_CAPTION = 12, W_CAPTION = 400;
    public static final int T_CAPTION_2 = 11, W_CAPTION_2 = 400;
    public static final int T_MONO = 13, W_MONO = 400;
    public static final int T_MONO_SM = 11, W_MONO_SM = 400;
    public static final int T_MONO_LG = 15, W_MONO_LG = 500;

    private static Typeface sans;
    private static Typeface mono;

    /** SF Pro if the device has it, else the platform default. */
    public static Typeface sans(Context ctx) {
        if (sans == null) {
            Typeface t = Typeface.create("sans-serif", Typeface.NORMAL);
            String[] candidates = {"SF Pro Text", "SF Pro Display", "Roboto", "sans-serif"};
            for (String name : candidates) {
                try {
                    Typeface f = Typeface.create(name, Typeface.NORMAL);
                    if (f != null) {
                        t = f;
                        break;
                    }
                } catch (Throwable ignored) {
                    // fall through to the next candidate
                }
            }
            sans = t;
        }
        return sans;
    }

    /** Monospace for all data and terminal output. */
    public static Typeface mono(Context ctx) {
        if (mono == null) {
            Typeface t = Typeface.MONOSPACE;
            String[] candidates = {"SF Mono", "Roboto Mono", "Droid Sans Mono", "monospace"};
            for (String name : candidates) {
                try {
                    Typeface f = Typeface.create(name, Typeface.NORMAL);
                    if (f != null) {
                        t = f;
                        break;
                    }
                } catch (Throwable ignored) {
                    // fall through
                }
            }
            mono = t;
        }
        return mono;
    }

    public static Typeface face(Context c, int weight) {
        Typeface base = sans(c);
        int style;
        switch (weight) {
            case 300: style = Typeface.BOLD; break;      // closest available mapping
            case 500: style = Typeface.NORMAL; break;
            case 600: style = Typeface.BOLD; break;
            case 700: style = Typeface.BOLD; break;
            case 800:
            case 900: style = Typeface.BOLD; break;
            default: style = Typeface.NORMAL;
        }
        return Typeface.create(base, style);
    }

    public static Typeface monoFace(Context c, int weight) {
        return Typeface.create(mono(c), weight >= 600 ? Typeface.BOLD : Typeface.NORMAL);
    }

    public static int sp(Context ctx, float v) {
        Context use = ctx != null ? ctx : c;
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, v, use.getResources().getDisplayMetrics()));
    }

    public static int dp(Context ctx, float v) {
        Context use = ctx != null ? ctx : c;
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, use.getResources().getDisplayMetrics()));
    }

    /** Severity colours used by findings, ports and log lines. */
    public static int severity(String s) {
        if (s == null) return TEXT_2;
        switch (s.toUpperCase()) {
            case "CRITICAL": return RED;
            case "HIGH": return ORANGE;
            case "MEDIUM": return YELLOW;
            case "LOW": return BLUE;
            case "INFO": return TEXT_2;
            case "CRITICAL RISK": return RED;
            case "HIGH RISK": return ORANGE;
            case "GUARDED": return GREEN;
            case "ROOT": return PURPLE;
            default: return TEXT_2;
        }
    }

    public static int withAlpha(int color, int alpha) {
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color));
    }

    /** Blends {@code color} toward black by {@code amount} (0..1). */
    public static int darken(int color, float amount) {
        float f = 1f - Math.max(0f, Math.min(1f, amount));
        return Color.rgb((int) (Color.red(color) * f), (int) (Color.green(color) * f),
                (int) (Color.blue(color) * f));
    }

    /** Blends {@code color} toward white by {@code amount} (0..1). */
    public static int lighten(int color, float amount) {
        float a = Math.max(0f, Math.min(1f, amount));
        return Color.rgb(
                (int) (Color.red(color) + (255 - Color.red(color)) * a),
                (int) (Color.green(color) + (255 - Color.green(color)) * a),
                (int) (Color.blue(color) + (255 - Color.blue(color)) * a));
    }
}
