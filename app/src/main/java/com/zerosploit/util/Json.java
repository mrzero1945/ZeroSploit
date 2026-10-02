package com.zerosploit.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal recursive-descent JSON reader.
 *
 * <p>Hand-rolled on purpose: the engine speaks line-delimited JSON, and pulling
 * in a full parsing library for a few small objects would add a dependency and
 * an allocation cost per event.
 *
 * <p>Values map to {@code Map<String,Object>}, {@code List<Object>},
 * {@code String}, {@code Double}, {@code Boolean} and {@code null}.
 */
public final class Json {

    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
        this.i = 0;
    }

    public static Object parse(String text) {
        if (text == null) return null;
        try {
            Json p = new Json(text);
            p.ws();
            Object v = p.value();
            p.ws();
            return v;
        } catch (RuntimeException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    public static List<Object> arr(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    /** True when the key is present, so a missing key never overwrites state. */
    public static boolean has(Object o, String key) {
        Map<String, Object> m = obj(o);
        return m != null && m.containsKey(key);
    }

    public static String str(Object o, String key) {
        Object v = obj(o) == null ? null : obj(o).get(key);
        return v == null ? null : String.valueOf(v);
    }

    public static String str(Object o, String key, String dflt) {
        String v = str(o, key);
        return v == null ? dflt : v;
    }

    public static int i(Object o, String key, int dflt) {
        String v = str(o, key);
        if (v == null) return dflt;
        try {
            return (int) Double.parseDouble(v);
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    public static long l(Object o, String key, long dflt) {
        String v = str(o, key);
        if (v == null) return dflt;
        try {
            return (long) Double.parseDouble(v);
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    public static double d(Object o, String key, double dflt) {
        String v = str(o, key);
        if (v == null) return dflt;
        try {
            return Double.parseDouble(v);
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    public static boolean b(Object o, String key, boolean dflt) {
        Object v = obj(o) == null ? null : obj(o).get(key);
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) {
            String s = (String) v;
            if (s.equals("true")) return true;
            if (s.equals("false")) return false;
        }
        return dflt;
    }

    // ---- scanner --------------------------------------------------------
    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
            else break;
        }
    }

    private Object value() {
        if (i >= s.length()) return null;
        char c = s.charAt(i);
        switch (c) {
            case '{':
                return object();
            case '[':
                return array();
            case '"':
                return string();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return number();
        }
    }

    private void expect(String word) {
        if (!s.startsWith(word, i)) throw new IllegalStateException("expected " + word);
        i += word.length();
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<>();
        i++; // {
        ws();
        if (i < s.length() && s.charAt(i) == '}') {
            i++;
            return m;
        }
        while (i < s.length()) {
            ws();
            String k = string();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') throw new IllegalStateException("expected :");
            i++;
            ws();
            m.put(k, value());
            ws();
            if (i >= s.length()) break;
            char c = s.charAt(i);
            if (c == ',') {
                i++;
                continue;
            }
            if (c == '}') {
                i++;
                break;
            }
            break;
        }
        return m;
    }

    private List<Object> array() {
        List<Object> l = new ArrayList<>();
        i++; // [
        ws();
        if (i < s.length() && s.charAt(i) == ']') {
            i++;
            return l;
        }
        while (i < s.length()) {
            ws();
            l.add(value());
            ws();
            if (i >= s.length()) break;
            char c = s.charAt(i);
            if (c == ',') {
                i++;
                continue;
            }
            if (c == ']') {
                i++;
                break;
            }
            break;
        }
        return l;
    }

    private String string() {
        if (i >= s.length() || s.charAt(i) != '"') throw new IllegalStateException("expected string");
        i++;
        StringBuilder b = new StringBuilder();
        while (i < s.length()) {
            char c = s.charAt(i++);
            if (c == '"') break;
            if (c != '\\') {
                b.append(c);
                continue;
            }
            if (i >= s.length()) break;
            char e = s.charAt(i++);
            switch (e) {
                case 'n': b.append('\n'); break;
                case 't': b.append('\t'); break;
                case 'r': b.append('\r'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case '/': b.append('/'); break;
                case '\\': b.append('\\'); break;
                case '"': b.append('"'); break;
                case 'u':
                    if (i + 4 > s.length()) throw new IllegalStateException("bad \\u");
                    b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                    break;
                default:
                    b.append(e);
            }
        }
        return b.toString();
    }

    private Double number() {
        int start = i;
        if (i < s.length() && (s.charAt(i) == '-' || s.charAt(i) == '+')) i++;
        while (i < s.length()) {
            char c = s.charAt(i);
            if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') i++;
            else break;
        }
        if (start == i) throw new IllegalStateException("expected value at " + i);
        try {
            return Double.parseDouble(s.substring(start, i));
        } catch (NumberFormatException e) {
            throw new IllegalStateException("bad number: " + s.substring(start, i));
        }
    }
}
