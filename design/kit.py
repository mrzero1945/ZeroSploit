"""iOS-style component kit -> flat SVG that Inkscape renders 1:1."""
import html
from theme import *
from sf import draw_sf, MODULE_ICON, DEVICE_ICON, ICONS as SF_ICONS


class Svg:
    """Flat SVG document builder. Gradients/filters go into <defs> on save,
    which is what Inkscape expects (it keeps them out of the drawing tree)."""

    def __init__(self, w=W, h=H, bg=None, namedview=True, title="ZEROSPLOIT"):
        self.w, self.h = w, h
        self.p = []          # drawing content
        self.defs = []       # gradients / filters / clipPaths
        self._uid = 0
        self._head = (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" '
            f'xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd" '
            f'version="1.1" inkscape:version="1.4.2" '
            f'width="{w:g}pt" height="{h:g}pt" viewBox="0 0 {w:g} {h:g}">')
        self._nv = namedview
        self._title = title
        if bg:
            self.rect(0, 0, w, h, bg)

    # ---------------------------------------------------------- primitives
    def raw(self, s):
        self.p.append(s)

    def uid(self, p="g"):
        self._uid += 1
        return f"{p}{self._uid}"

    def grad(self, stops, x1=0, y1=0, x2=0, y2=1, gid=None):
        """stops = [(offset, color, opacity_or_None), ...]; vertical default."""
        gid = gid or self.uid("grad")
        s = "".join(
            f'<stop offset="{o}" stop-color="{c}"'
            + (f' stop-opacity="{a}"/>' if a is not None else '/>')
            for o, c, a in stops)
        self.defs.append(
            f'<linearGradient id="{gid}" x1="{x1:g}" y1="{y1:g}" '
            f'x2="{x2:g}" y2="{y2:g}">{s}</linearGradient>')
        return gid

    def rect(self, x, y, w, h, fill="none", r=0, stroke=None, sw=1,
             op=None, dash=None, extra=""):
        st = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        da = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.p.append(f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" '
                      f'rx="{r:g}" ry="{r:g}" fill="{fill}"{st}{da}{o}{extra}/>')

    def line(self, x1, y1, x2, y2, stroke=SEPARATOR, sw=0.5, cap="butt",
             dash=None, op=None):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.p.append(f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}" '
                      f'stroke="{stroke}" stroke-width="{sw:g}" '
                      f'stroke-linecap="{cap}"{da}{o}/>')

    def circle(self, cx, cy, r, fill="none", stroke=None, sw=1,
               op=None, dash=None):
        st = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        da = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.p.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="{r:g}" fill="{fill}"'
                      f'{st}{da}{o}/>')

    def ellipse(self, cx, cy, rx, ry, fill="none", stroke=None, sw=1, op=None):
        st = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.p.append(f'<ellipse cx="{cx:g}" cy="{cy:g}" rx="{rx:g}" ry="{ry:g}" '
                      f'fill="{fill}"{st}{o}/>')

    def path(self, d, fill="none", stroke=None, sw=2, cap="round",
             join="round", op=None, dash=None):
        st = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        da = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.p.append(f'<path d="{d}" fill="{fill}"{st} stroke-linecap="{cap}" '
                      f'stroke-linejoin="{join}"{da}{o}/>')

    def poly(self, pts, fill="none", stroke=None, sw=2, join="round",
             cap="round", op=None, close=True):
        p = " ".join(f"{x:g},{y:g}" for x, y in pts)
        tag = "polygon" if close else "polyline"
        st = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.p.append(f'<{tag} points="{p}" fill="{fill}"{st} '
                      f'stroke-linejoin="{join}" stroke-linecap="{cap}"{o}/>')

    def text(self, x, y, t, size=17, fill=TEXT, font=FONT, weight="400",
             anchor="start", ls=None, op=None, style=None):
        t = html.escape(str(t))
        tr = "" if ls is None else f' letter-spacing="{ls}"'
        o = f' opacity="{op}"' if op is not None else ""
        self.p.append(f'<text x="{x:g}" y="{y:g}" font-family="{font}" '
                      f'font-size="{size:g}" font-weight="{weight}" fill="{fill}" '
                      f'text-anchor="{anchor}"{tr}{o}{style or ""} '
                      f'xml:space="preserve">{t}</text>')

    def st(self, x, y, t, style, fill=None, anchor="start", font=None,
           weight=None, ls=None, op=None):
        """Text using one of the ST_* iOS text styles."""
        size, w, l = style
        return self.text(x, y, t, size=size, fill=fill or TEXT,
                         font=font or FONT, weight=weight or w,
                         anchor=anchor, ls=l if ls is None else ls, op=op)

    def mono(self, x, y, t, size=13, fill=TEXT, weight="400", anchor="start",
             ls=0.2, op=None):
        return self.text(x, y, t, size=size, fill=fill, font=FONT_MONO,
                         weight=weight, anchor=anchor, ls=ls, op=op)

    def g(self, tr):
        self.p.append(f'<g transform="{tr}">')
        return self

    def ge(self):
        self.p.append('</g>')
        return self

    def clip(self, d, cid=None):
        cid = cid or self.uid("clip")
        self.defs.append(f'<clipPath id="{cid}"><path d="{d}"/></clipPath>')
        return cid

    def shadow(self, cid=None, blur=18, dy=6, op=0.5, color="#000000", dx=0):
        """iOS-style soft drop shadow, built from explicit primitives so it
        renders identically in Inkscape 1.x, librsvg and Android."""
        cid = cid or self.uid("sh")
        b = max(blur, 0.01)
        self.defs.append(
            f'<filter id="{cid}" x="-60%" y="-60%" width="220%" height="220%" '
            f'color-interpolation-filters="sRGB">'
            f'<feGaussianBlur in="SourceAlpha" stdDeviation="{b:g}" result="b"/>'
            f'<feOffset in="b" dx="{dx:g}" dy="{dy:g}" result="o"/>'
            f'<feFlood flood-color="{color}" flood-opacity="{op}"/>'
            f'<feComposite in2="o" operator="in" result="s"/>'
            f'<feMerge><feMergeNode in="s"/><feMergeNode in="SourceGraphic"/>'
            f'</feMerge></filter>')
        return cid

    def save(self, path):
        out = [self._head, f'<title id="tt">{html.escape(self._title)}</title>']
        if self._nv:
            out.append('<sodipodi:namedview id="nv" inkscape:document-units="pt" '
                       'pagecolor="#000000" bordercolor="#666666" '
                       'inkscape:pagecheckerboard="false" '
                       'inkscape:zoom="0.5" inkscape:cx="196" inkscape:cy="426"/>')
        if self.defs:
            out.append('<defs id="zsdefs">' + "".join(self.defs) + '</defs>')
        out.extend(self.p)
        out.append('</svg>')
        with open(path, "w") as f:
            f.write("\n".join(out) + "\n")
        return path


# =============================================================================
#  iOS chrome
# =============================================================================
def status_bar(sv, time="9:41", dark=True):
    """Left time, Dynamic Island, right signal/wifi/battery."""
    c = TEXT if dark else "#000"
    sv.st(29, 35, time, ST_SUBHEAD, fill=c, weight="600", ls=0)
    # dynamic island
    sv.rect(126, 11, 141, 37, "#000" if dark else "#fff", r=19)
    if dark:
        sv.circle(213, 29.5, 4.5, "#1C1C1E")
    # cellular
    for i, hgt in enumerate([4, 6.5, 9, 11.5]):
        sv.rect(288 + i * 5, 35 - hgt, 3.4, hgt, c, r=1.1)
    # wifi
    for i, r in enumerate([3.2, 6.6, 10]):
        sv.path(f"M {329-r} {27.5 + i*0.2} A {r*2} {r*2} 0 0 1 {329+r} {27.5}",
                stroke=c, sw=1.7)
    sv.circle(329, 32.2, 1.5, c)
    # battery
    sv.rect(340, 24, 22, 11, "none", r=3.4, stroke=c, sw=1, op=0.4)
    sv.rect(342, 26, 14, 7, c, r=2)
    sv.rect(363.5, 27.4, 1.6, 4.2, c, r=0.8, op=0.4)


def tab_bar(sv, active=0, items=None):
    items = items or ["Scan", "Targets", "Sessions", "Logs", "Settings"]
    y0 = H - TABBAR_H - SA_BOTTOM
    sv.rect(0, y0 - 6, W, TABBAR_H + 6 + SA_BOTTOM, BG)
    g = sv.grad([(0, "#1C1C1E", 0.0), (0.5, "#1C1C1E", 0.92), (1, "#1C1C1E", 1.0)])
    sv.rect(0, y0, W, TABBAR_H, f"url(#{g})")
    sv.line(0, y0, W, y0, SEPARATOR, 0.5)
    n = len(items)
    for i, it in enumerate(items):
        cx = W * (i + 0.5) / n
        col = TINT if i == active else TEXT_3
        draw_tab_icon(sv, i, cx, y0 + 20, col, 22)
        sv.st(cx, y0 + 42, it, ST_CAPTION_2, fill=col, anchor="middle",
              weight="500", ls=0.1)
    # home indicator
    sv.rect(W / 2 - 67, H - 12, 134, 5, "#FFFFFF", r=2.5, op=0.92)


def draw_tab_icon(sv, i, cx, cy, col, s=22):
    h = s / 2
    if i == 0:      # radar / scan
        sv.circle(cx, cy, h * 0.78, "none", col, 1.6)
        sv.circle(cx, cy, h * 0.36, "none", col, 1.6, op=0.75)
        sv.line(cx, cy, cx + h * 0.56, cy - h * 0.56, col, 1.6)
    elif i == 1:    # devices
        sv.rect(cx - h * 0.85, cy - h * 0.75, h * 0.95, h * 1.05, "none", stroke=col, sw=1.6, r=2)
        sv.rect(cx + h * 0.15, cy - h * 0.3, h * 0.7, h * 1.2, "none", stroke=col, sw=1.6, r=2)
    elif i == 2:    # terminal
        sv.rect(cx - h * 0.9, cy - h * 0.75, h * 1.8, h * 1.5, "none", stroke=col, sw=1.6, r=2.6)
        sv.poly([(cx - h * 0.45, cy - h * 0.2), (cx - h * 0.05, cy + h * 0.08),
                 (cx - h * 0.45, cy + h * 0.36)], stroke=col, sw=1.6)
        sv.line(cx + h * 0.05, cy + h * 0.36, cx + h * 0.5, cy + h * 0.36, col, 1.6)
    elif i == 3:    # waveform / log
        for k, hh in enumerate([0.9, 0.5, 1.2, 0.65, 1.0]):
            sv.line(cx - h * 0.9 + k * h * 0.45, cy + h * 0.75, 
                    cx - h * 0.9 + k * h * 0.45, cy + h * 0.75 - h * hh * 1.5, col, 1.6)
    else:           # gear
        sv.circle(cx, cy, h * 0.42, "none", col, 1.7)
        for k in range(8):
            import math
            a = math.radians(k * 45)
            sv.line(cx + h * 0.62 * math.cos(a), cy + h * 0.62 * math.sin(a),
                    cx + h * 0.9 * math.cos(a), cy + h * 0.9 * math.sin(a), col, 1.5)


def nav_bar(sv, title, large=True, back=None, trailing=None, sub=None,
            large_color=None, tcolor=None):
    """Compact nav bar + optional large title. back=None -> no chevron."""
    tc = tcolor or TEXT
    if back is not None:
        # SF chevron + label
        bx = 8
        sv.path(f"M {bx+11} 22 L {bx+3} 30 L {bx+11} 38", stroke=TINT, sw=2.4)
        sv.st(bx + 17, 35, back, ST_BODY, fill=TINT)
    if trailing:
        sv.st(W - 20, 35, trailing, ST_BODY, fill=TINT, anchor="end")
    if title:
        if large:
            sv.st(20, 82, title, ST_LARGE_TITLE, fill=large_color or tc)
            if sub:
                sv.st(20, 100, sub, ST_FOOTNOTE, fill=TEXT_2)
        else:
            sv.st(W / 2, 33, title, ST_HEADLINE, fill=tc, anchor="middle")
    return CONTENT_TOP if large else STATUS_H + NAV_H


def home_indicator(sv, light=True):
    sv.rect(W / 2 - 67, H - 12, 134, 5, "#FFFFFF" if light else "#000", r=2.5,
            op=0.92 if light else 0.6)


# =============================================================================
#  iOS content blocks
# =============================================================================
def screen(w=W, h=H, bg=BG, grid=False):
    sv = Svg(w, h, bg=bg)
    return sv


def group(sv, x, y, w, rows, title=None, footer=None, r=R_CARD, fill=BG_CARD):
    """iOS inset grouped list.

    Row draw functions paint in *row-local* coordinates (y=0 at the row's top
    edge), so each one is translated to its absolute canvas position. The
    separator hairlines are drawn outside that transform, in canvas space.
    """
    if title:
        sv.st(x, y - 22, title.upper(), ST_CAPTION_2, fill=TEXT_2, ls=0.6)
        y += 8
    h = sum(rh for _, rh in rows) + (10 if rows else 0)
    sv.rect(x, y, w, h, fill, r=r)
    cy = y + 5
    for i, (draw, rh) in enumerate(rows):
        sv.g(f"translate({x:g},{cy:.2f})")
        draw(sv, 0, w, 0)
        sv.ge()
        if i < len(rows) - 1:
            sv.line(x + 16, cy + rh, x + w - 16, cy + rh, SEPARATOR, 0.5)
        cy += rh
    if footer:
        sv.st(x, y + h + 20, footer, ST_FOOTNOTE, fill=TEXT_2)
        y += h + 30
    else:
        y += h
    return y


def row(icon=None, tint=BLUE, title="", value=None, sub=None, h=44,
        accessory="chevron", on_tap=True, mono_value=False, value_color=None,
        badge=None, chev=True, leading_text=None, destructive=False):
    """Build a row draw fn + its height. accessory: chevron|none|switch|check"""
    def draw(sv, x=20, w=W - 40, y=0):
        tx = x
        if icon:
            sv.rect(x, y + (h - 30) / 2, 30, 30, tint, r=7.5, op=0.9)
            draw_sf(sv, icon, x + 15, y + h / 2, 19, "#FFFFFF")
            tx = x + 30 + 12
        elif leading_text:
            sv.st(x, y + h / 2 + 4, leading_text, ST_BODY,
                  fill=RED if destructive else TEXT_2)
            tx = x + 78
        right_edge = x + w
        if accessory == "switch":
            sw_ = draw_switch(sv, right_edge - 51, y + (h - 31) / 2, on=on_tap)
        if accessory == "chevron" and chev:
            sv.path(f"M {right_edge-8} {y+h/2-5} L {right_edge-1.5} {y+h/2} "
                    f"L {right_edge-8} {y+h/2+5}", stroke=TEXT_3, sw=2)
        if value:
            if mono_value:
                sv.mono(right_edge - (16 if (accessory == "chevron" and chev) else 0),
                        y + h / 2 + 4.5, value, 13,
                        fill=value_color or TEXT_2, anchor="end")
            else:
                sv.st(right_edge - (16 if (accessory == "chevron" and chev) else 0),
                      y + h / 2 + 5.5, value, ST_BODY,
                      fill=value_color or TEXT_2, anchor="end")
        if badge:
            bw = 20 + 7.5 * len(badge)
            bv = right_edge - 18 - bw
            sv.rect(bv, y + (h - 20) / 2, bw, 20, tint, r=10, op=0.22)
            sv.st(bv + bw / 2, y + h / 2 + 4, badge, ST_CAPTION_2, fill=tint,
                  anchor="middle", weight="600")
        tcol = RED if destructive else TEXT
        if title:
            sv.st(tx, y + h / 2 - (2 if sub else -4.5) + 1, title, ST_BODY, fill=tcol)
        if sub:
            sv.st(tx, y + h / 2 + (sub and 14 or 0), sub, ST_FOOTNOTE, fill=TEXT_2)
    return draw, h


def stat_row(sv, x, y, w, label, value, vcolor=TEXT, mono=True, size=15):
    sv.st(x, y, label, ST_SUBHEAD, fill=TEXT_2)
    if mono:
        sv.mono(x + w, y, value, size, fill=vcolor, anchor="end")
    else:
        sv.st(x + w, y, value, size, fill=vcolor, anchor="end", weight="500")
    return y + 22


def draw_switch(sv, x, y, on=True, w=51, h=31):
    if on:
        sv.rect(x, y, w, h, GREEN, r=h / 2)
        sv.circle(x + w - h / 2, y + h / 2, h / 2 - 2, "#FFFFFF")
    else:
        sv.rect(x, y, w, h, FILL, r=h / 2)
        sv.circle(x + h / 2, y + h / 2, h / 2 - 2, "#FFFFFF")
    return x + w


def segmented(sv, x, y, w, labels, sel=0, h=32, fs=13):
    sv.rect(x, y, w, h, FILL_3, r=R_CONTROL)
    cw = w / len(labels)
    r = sv.grad([(0, BG_ELEV_2, 0.95), (1, BG_ELEV_2, 0.75)])
    cid = sv.shadow(sv.uid("sh"), 3, 1, 0.35)
    sv.rect(x + sel * cw + 2, y + 2, cw - 4, h - 4, f"url(#{r})", r=9,
            extra=f' filter="url(#{cid})"')
    for i, l in enumerate(labels):
        sv.st(x + cw * (i + 0.5), y + h / 2 + 4.5, l, (fs, "600", 0),
              fill=TEXT if i == sel else TEXT_2, anchor="middle")
    return y + h


def search_field(sv, x, y, w, placeholder="Search", h=36):
    sv.rect(x, y, w, h, FILL_3, r=10)
    sv.circle(x + 16, y + h / 2 - 0.5, 5.6, "none", TEXT_2, 1.6)
    sv.line(x + 20, y + h / 2 + 4, x + 24, y + h / 2 + 8, TEXT_2, 1.6)
    sv.st(x + 30, y + h / 2 + 4.5, placeholder, (14, "400", -0.1), fill=TEXT_2)
    return y + h


def button(sv, x, y, w, h, label, kind="filled", tint=BLUE, icon=None):
    """kind: filled | tinted | plain | gray"""
    fs, fw, fl = (15, "600", 0.1)
    if kind == "filled":
        sv.rect(x, y, w, h, tint, r=13)
        col = "#FFFFFF"
    elif kind == "tinted":
        sv.rect(x, y, w, h, tint, r=13, op=0.18)
        col = tint
    elif kind == "gray":
        sv.rect(x, y, w, h, BG_ELEV_2, r=13)
        col = TEXT
    else:
        col = tint
    cx = x + w / 2
    if icon:
        tw = len(label) * fs * 0.55
        draw_sf(sv, icon, cx - tw / 2 - 9, y + h / 2, 17, col)
        sv.st(cx + 10, y + h / 2 + 5, label, (fs, fw, fl), fill=col)
    else:
        sv.st(cx, y + h / 2 + 5, label, (fs, fw, fl), fill=col, anchor="middle")
    return y + h


def progress(sv, x, y, w, pct, tint=BLUE, h=4):
    sv.rect(x, y, w, h, FILL, r=h / 2)
    if pct > 0:
        sv.rect(x, y, max(w * pct / 100, h), h, tint, r=h / 2)
    return y + h


def progress_ring(sv, cx, cy, r, pct, tint=BLUE, sw=6, label=None, sub=None):
    sv.circle(cx, cy, r, "none", FILL, sw)
    import math
    circ = 2 * math.pi * r
    on = circ * max(0, min(100, pct)) / 100
    if on > 0:
        sv.circle(cx, cy, r, "none", tint, sw, dash=f"{on:.2f} {circ:.2f}")
        sv.p[-1] = sv.p[-1].replace('<circle', f'<circle transform="rotate(-90 {cx} {cy})"')
    if label:
        sv.st(cx, cy + 1, label, (24, "700", -0.3), fill=TEXT, anchor="middle")
    if sub:
        sv.st(cx, cy + 16, sub, ST_CAPTION_2, fill=TEXT_2, anchor="middle")
    return cy + r


def badge(sv, x, y, label, tint, fs=11, h=19, solid=False, pad=8):
    w = len(label) * fs * 0.56 + pad * 2
    if solid:
        sv.rect(x, y, w, h, tint, r=h / 2)
        col = "#FFFFFF"
    else:
        sv.rect(x, y, w, h, tint, r=h / 2, op=0.2)
        col = tint
    sv.st(x + w / 2, y + h / 2 + 3.8, label, (fs, "600", 0.1), fill=col,
          anchor="middle")
    return w


def severity_badge(sv, x, y, sev):
    m = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": BLUE,
         "INFO": TEXT_2}
    return badge(sv, x, y, sev, m.get(sev, TEXT_2))


def sheet(sv, h=520, title=None, grabber=True, bg=BG_ELEV):
    """Bottom sheet over dimmed backdrop."""
    sv.rect(0, 0, W, H, "#000", op=0.45)
    y = H - h
    g = sv.grad([(0, BG_ELEV, 0.92), (1, BG_ELEV, 1.0)])
    cid = sv.shadow(sv.uid("sh"), 26, -6, 0.55)
    sv.rect(0, y, W, h + 40, f"url(#{g})", r=R_SHEET,
            extra=f' filter="url(#{cid})"')
    sv.rect(0, y, W, R_SHEET, f"url(#{g})", r=R_SHEET)
    if grabber:
        sv.rect(W / 2 - 18, y + 6, 36, 5, TEXT_3, r=2.5)
    if title:
        sv.st(W / 2, y + 40, title, ST_HEADLINE, fill=TEXT, anchor="middle")
    home_indicator(sv)
    return y + 56


def empty_state(sv, cx, cy, icon, title, sub, tint=TEXT_3):
    draw_sf(sv, icon, cx, cy - 26, 46, tint)
    sv.st(cx, cy + 30, title, ST_HEADLINE, fill=TEXT_2, anchor="middle")
    sv.st(cx, cy + 50, sub, ST_FOOTNOTE, fill=TEXT_3, anchor="middle")


def code_block(sv, x, y, w, lines, lh=17, fs=11.5, bg="#0B0B0D", r=12,
               pad=12, tint=None):
    h = pad * 2 + lh * len(lines)
    sv.rect(x, y, w, h, bg, r=r)
    sv.rect(x, y, w, h, "none", r=r, stroke=SEPARATOR, sw=0.5)
    for i, (t, c) in enumerate(lines):
        sv.mono(x + pad, y + pad + lh * i + fs, t, fs, fill=c or TEXT_2)
    return y + h


def mono_table(sv, x, y, w, header, rows, cols, fs=12, lh=22, rh=32,
               accent_col=None, accent=BLUE):
    """header: list[str]; rows: list[list[str]]; cols: list[float] width frac"""
    xs = [x]
    for c in cols[:-1]:
        xs.append(xs[-1] + w * c)
    for i, htx in enumerate(header):
        sv.st(xs[i] + (0 if i == 0 else 0), y, htx.upper(), ST_CAPTION_2,
              fill=TEXT_3, ls=0.4)
    yy = y + 8
    sv.line(x, yy, x + w, yy, SEPARATOR, 0.5)
    yy += 12
    for r_ in rows:
        for i, cell in enumerate(r_):
            c = TEXT if i == 0 else TEXT_2
            if accent_col is not None and i == accent_col:
                c = accent
            if i == 0:
                sv.mono(xs[i], yy, cell, fs, fill=c)
            else:
                sv.st(xs[i], yy, cell, (fs, "400", 0), fill=c)
        yy += lh
    return yy
