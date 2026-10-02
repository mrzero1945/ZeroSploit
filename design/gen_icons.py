"""ZEROSPLOIT — Apple-style icon set. Generates SVGs (Inkscape source)."""
import os
from theme import *
from kit import Svg
from sf import MODULE_ICON, draw_sf

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "icons")
os.makedirs(OUT, exist_ok=True)


def shade(hexc, f):
    h = hexc.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    if f < 1:
        r, g, b = int(r * f), int(g * f), int(b * f)
    else:
        r, g, b = [min(255, int(v + (255 - v) * (f - 1))) for v in (r, g, b)]
    return f"#{r:02X}{g:02X}{b:02X}"


def app_icon(name, glyph, tint, size=1024, plate=True):
    """iOS-style squircle plate with a gradient + white SF glyph."""
    sv = Svg(size, size, bg=None, namedview=False)
    r = size * 0.2237          # iOS corner approximation
    g = sv.grad([(0, shade(tint, 1.30), None),
                 (0.45, tint, None),
                 (1, shade(tint, 0.62), None)], gid=f"g_{name}")
    if plate:
        cid = sv.shadow(sv.uid("sh"), size * 0.030, size * 0.012, 0.42)
        sv.rect(0, 0, size, size, f"url(#{g})", r=r,
                extra=f' filter="url(#{cid})"')
    else:
        sv.rect(0, 0, size, size, f"url(#{g})", r=r)
    # gloss highlight
    hg = sv.grad([(0, "#FFFFFF", 0.30), (0.55, "#FFFFFF", 0.03), (1, "#FFFFFF", 0.0)],
                 gid=f"h_{name}")
    sv.rect(size * 0.02, size * 0.02, size * 0.96, size * 0.96, f"url(#{hg})", r=r)
    # glyph
    gsz = size * 0.50
    draw_sf(sv, glyph, size / 2, size / 2, gsz, "#FFFFFF", sw=size * 0.0405)
    p = f"{OUT}/app_{name}.svg"
    sv.save(p)
    return p


def glyph_only(name, glyph, size=256):
    """Transparent glyph, white fill -> Android can tint it."""
    sv = Svg(size, size, bg=None, namedview=False)
    draw_sf(sv, glyph, size / 2, size / 2, size * 0.80, "#FFFFFF", sw=size * 0.065)
    p = f"{OUT}/glyph_{name}.svg"
    sv.save(p)
    return p


# ---- tab bar glyphs ---------------------------------------------------------
# The tab bar is app chrome rather than part of the 13 designed screens, but it
# still comes from the same SF-style library so the weights match exactly.
TAB_ICONS = [
    ("tab_network", "network"),
    ("tab_target", "location"),
    ("tab_modules", "square_stack"),
    ("tab_sessions", "terminal"),
    ("tab_logs", "list"),
    ("tab_security", "shield"),
    ("tab_console", "doc"),
    ("tab_wifi", "antenna"),
]


def tab_glyphs(size=256):
    out = []
    for name, glyph in TAB_ICONS:
        out.append(glyph_only(name, glyph, size))
    return out


# ---- app launcher (Zerosploit "0" mark) --------------------------------------
def launcher(size=1024):
    sv = Svg(size, size, bg=None, namedview=False)
    import math
    r = size * 0.2237
    g = sv.grad([(0, "#3A3A3C", None), (0.5, "#101012", None), (1, "#000000", None)],
                gid="lg")
    cid = sv.shadow(sv.uid("sh"), size * 0.03, size * 0.012, 0.45)
    sv.rect(0, 0, size, size, f"url(#{g})", r=r, extra=f' filter="url(#{cid})"')
    c = size / 2
    # rings
    for rr, op, sw in [(0.355, 0.22, 0.018), (0.275, 0.42, 0.022)]:
        sv.circle(c, c, size * rr, "none", BLUE, size * sw, op=op)
    # tick marks around outer ring
    for k in range(36):
        a = math.radians(k * 10)
        r1, r2 = size * 0.385, size * 0.405
        sv.line(c + r1 * math.cos(a), c + r1 * math.sin(a),
                c + r2 * math.cos(a), c + r2 * math.sin(a),
                BLUE, size * 0.011, op=0.30)
    # crosshair ticks
    for dx, dy in ((0, -1), (0, 1), (-1, 0), (1, 0)):
        sv.line(c + dx * size * 0.425, c + dy * size * 0.425,
                c + dx * size * 0.30, c + dy * size * 0.30, BLUE, size * 0.014, op=0.5)
    # the "0"
    sv.circle(c, c, size * 0.175, "none", "#FFFFFF", size * 0.052)
    sv.rect(c - size * 0.026, c - size * 0.175, size * 0.052, size * 0.35, "#0B0B0D")
    # slash
    sw = size * 0.056
    sv.line(c - size * 0.20, c + size * 0.20, c + size * 0.20, c - size * 0.20,
            BLUE, sw + size * 0.022, op=0.9)
    sv.line(c - size * 0.20, c + size * 0.20, c + size * 0.20, c - size * 0.20,
            "#FFFFFF", sw)
    sv.save(f"{OUT}/launcher.svg")
    return f"{OUT}/launcher.svg"


def adaptive(size=432):
    """Android adaptive: background + foreground (safe zone 66/108)."""
    sv = Svg(size, size, bg=None, namedview=False)
    g = sv.grad([(0, "#2C2C2E", None), (1, "#000000", None)], gid="ab")
    sv.rect(0, 0, size, size, f"url(#{g})")
    sv.save(f"{OUT}/adaptive_bg.svg")

    sv = Svg(size, size, bg=None, namedview=False)
    import math
    s = size / 108.0
    c = size / 2
    for rr, op, sw in [(0.30, 0.30, 1.5), (0.20, 0.55, 1.8)]:
        sv.circle(c, c, s * rr * 2, "none", BLUE, sw, op=op)
    for k in range(24):
        a = math.radians(k * 15)
        r1, r2 = s * 33, s * 35.5
        sv.line(c + r1 * math.cos(a), c + r1 * math.sin(a),
                c + r2 * math.cos(a), c + r2 * math.sin(a), BLUE, 1.0, op=0.35)
    sv.circle(c, c, s * 26, "none", "#FFFFFF", 3.4)
    sv.rect(c - 1.6, c - 26, 3.2, 52, "#0B0B0D")
    sv.line(c - 21, c + 21, c + 21, c - 21, BLUE, 7.0, op=0.95)
    sv.line(c - 21, c + 21, c + 21, c - 21, "#FFFFFF", 4.6)
    sv.save(f"{OUT}/adaptive_fg.svg")
    return f"{OUT}/adaptive_fg.svg"


if __name__ == "__main__":
    for key, title, tint in MODULES:
        app_icon(key, MODULE_ICON[key], tint)
        glyph_only(key, MODULE_ICON[key])
    tab_glyphs()
    launcher()
    adaptive()
    print("icons ->", OUT)
    for f in sorted(os.listdir(OUT)):
        print("  ", f)
