"""SF Symbols-style stroke icon set (normalised -1..1 grid, scaled at draw)."""
import math
from theme import *


def _pts(cx, cy, s, pts):
    return [(cx + x * s / 2, cy + y * s / 2) for x, y in pts]


def _path(sv, cx, cy, s, pts, col, sw=1.7, close=False, cap="round"):
    p = _pts(cx, cy, s, pts)
    d = "M " + " L ".join(f"{x:.2f} {y:.2f}" for x, y in p)
    if close:
        d += " Z"
    sv.path(d, stroke=col, sw=sw, cap=cap, join="round")


def _arc(sv, cx, cy, r, a0, a1, col, sw=1.7):
    """Arc from a0 to a1 degrees (0 = east, cw screen coords)."""
    x0 = cx + r * math.cos(math.radians(a0))
    y0 = cy + r * math.sin(math.radians(a0))
    x1 = cx + r * math.cos(math.radians(a1))
    y1 = cy + r * math.sin(math.radians(a1))
    large = 1 if abs(a1 - a0) > 180 else 0
    sweep = 1 if a1 > a0 else 0
    sv.path(f"M {x0:.2f} {y0:.2f} A {r:.2f} {r:.2f} 0 {large} {sweep} "
            f"{x1:.2f} {y1:.2f}", stroke=col, sw=sw)


# =============================================================================
def _radar(sv, cx, cy, s, c, sw):
    sv.circle(cx, cy, s * 0.40, "none", c, sw)
    sv.circle(cx, cy, s * 0.20, "none", c, sw, op=0.7)
    sv.line(cx, cy, cx + s * 0.28, cy - s * 0.28, c, sw)
    sv.circle(cx, cy, s * 0.045, c)


def _devices(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.45, cy - s * 0.34, s * 0.42, s * 0.50, "none", stroke=c, sw=sw, r=2.5)
    sv.line(cx - s * 0.36, cy + s * 0.22, cx - s * 0.14, cy + s * 0.22, c, sw * 0.8)
    sv.rect(cx + s * 0.08, cy - s * 0.12, s * 0.37, s * 0.56, "none", stroke=c, sw=sw, r=2.5)
    sv.circle(cx + s * 0.265, cy + s * 0.40, s * 0.022, c)


def _terminal(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.46, cy - s * 0.36, s * 0.92, s * 0.72, "none", stroke=c, sw=sw, r=4)
    _path(sv, cx, cy, s, [(-0.26, -0.10), (-0.10, 0.02), (-0.26, 0.14)], c, sw)
    sv.line(cx - 0.02 * s, cy + 0.15 * s, cx + 0.24 * s, cy + 0.15 * s, c, sw)


def _waveform(sv, cx, cy, s, c, sw):
    for k, hh in enumerate([0.34, 0.16, 0.42, 0.22, 0.36, 0.14, 0.30]):
        x = cx + (k - 3) * s * 0.13
        sv.line(x, cy + s * 0.36, x, cy + s * 0.36 - s * hh, c, sw)


def _gear(sv, cx, cy, s, c, sw):
    sv.circle(cx, cy, s * 0.20, "none", c, sw)
    for k in range(8):
        a = math.radians(k * 45)
        sv.line(cx + s * 0.30 * math.cos(a), cy + s * 0.30 * math.sin(a),
                cx + s * 0.44 * math.cos(a), cy + s * 0.44 * math.sin(a), c, sw)


def _doc_search(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.34, -0.44), (0.12, -0.44), (0.28, -0.28),
                          (0.28, 0.16), (-0.34, 0.16)], c, sw, close=True)
    sv.line(cx - 0.18 * s, cy - 0.26 * s, cx + 0.05 * s, cy - 0.26 * s, c, sw * 0.8)
    sv.line(cx - 0.18 * s, cy - 0.08 * s, cx + 0.05 * s, cy - 0.08 * s, c, sw * 0.8)
    sv.circle(cx + 0.16 * s, cy + 0.20 * s, s * 0.19, "none", c, sw)
    sv.line(cx + 0.30 * s, cy + 0.34 * s, cx + 0.44 * s, cy + 0.48 * s, c, sw * 1.1)


def _bug(sv, cx, cy, s, c, sw):
    sv.ellipse(cx, cy + s * 0.02, s * 0.22, s * 0.30, "none", c, sw)
    sv.circle(cx, cy - s * 0.30, s * 0.11, "none", c, sw)
    sv.line(cx, cy - s * 0.19, cx, cy - s * 0.16, c, sw)
    for dy in (-0.16, 0.04, 0.24):
        sv.line(cx - s * 0.22, cy + s * dy, cx - s * 0.44, cy + s * dy, c, sw * 0.85)
        sv.line(cx + s * 0.22, cy + s * dy, cx + s * 0.44, cy + s * dy, c, sw * 0.85)
    for k in (-1, 0, 1):
        sv.line(cx + k * s * 0.11, cy - s * 0.40, cx + k * s * 0.14,
                cy - s * 0.48, c, sw * 0.8)


def _key(sv, cx, cy, s, c, sw):
    sv.circle(cx - s * 0.20, cy, s * 0.22, "none", c, sw)
    sv.line(cx + 0.0 * s, cy, cx + 0.44 * s, cy, c, sw)
    sv.line(cx + 0.30 * s, cy, cx + 0.30 * s, cy + 0.14 * s, c, sw)
    sv.line(cx + 0.42 * s, cy, cx + 0.42 * s, cy + 0.14 * s, c, sw)


def _sniffer(sv, cx, cy, s, c, sw):
    """A funnel narrowing from many wire lines to one dot.

    Reading many flows down to the few that carry a credential is what the
    module does, so the glyph is the funnel rather than a key -- a key is
    already Login Auditor's, and reusing it would make the two tools that
    differ most look identical.
    """
    top = [(-0.34, -0.34), (-0.11, -0.34), (0.11, -0.34), (0.34, -0.34)]
    for dx, dy in top:
        sv.line(cx + dx * s, cy + dy * s, cx, cy + s * 0.10, c, sw * 0.75)
    sv.line(cx - s * 0.34, cy - s * 0.34, cx + s * 0.34, cy - s * 0.34, c, sw)
    sv.circle(cx, cy + s * 0.30, s * 0.11, c)


def _dns(sv, cx, cy, s, c, sw):
    """A spoofed answer: one query, two stacked answers, the lower one wrong.

    The second row is drawn offset and crossed through. DNS spoofing only
    means anything because more than one answer can exist for a name, and a
    glyph showing a single clean reply would describe a resolver instead.
    """
    sv.circle(cx - s * 0.34, cy + s * 0.02, s * 0.055, c)
    sv.line(cx - s * 0.28, cy + s * 0.04, cx - s * 0.04, cy + s * 0.04, c, sw * 0.8)
    sv.line(cx - s * 0.28, cy - s * 0.04, cx - s * 0.04, cy - s * 0.20, c, sw * 0.8)
    sv.line(cx - s * 0.04, cy - s * 0.20, cx + s * 0.30, cy - s * 0.20, c, sw * 0.8)
    sv.circle(cx + s * 0.30, cy - s * 0.20, s * 0.055, c)
    sv.line(cx - s * 0.04, cy + s * 0.04, cx + s * 0.30, cy + s * 0.04, c, sw * 0.8)
    sv.circle(cx + s * 0.30, cy + s * 0.04, s * 0.055, c)
    d = s * 0.075
    sv.line(cx + s * 0.30 - d, cy + s * 0.04 + d, cx + s * 0.30 + d, cy + s * 0.04 - d,
            c, sw * 0.9)


def _hijack(sv, cx, cy, s, c, sw):
    """A padlock whose shackle has been swapped for a broken arc.

    The gap in the shackle is the finding. A padlock drawn whole reads as
    "secure", which is the opposite of what this module reports.
    """
    sw2 = sw
    # Body, opened at the top edge where the shackle would seat.
    sv.path(f"M {cx - s*0.30} {cy - s*0.06} L {cx - s*0.30} {cy + s*0.30} "
            f"L {cx + s*0.30} {cy + s*0.30} L {cx + s*0.30} {cy - s*0.06} Z",
            stroke=c, sw=sw2, join="round")
    # Shackle: left leg seated, right leg lifted off and open.
    _arc(sv, cx, cy - s * 0.06, s * 0.20, 180, 300, c, sw2)
    sv.line(cx - s * 0.20, cy - s * 0.06, cx - s * 0.20, cy - s * 0.16, c, sw2)
    sv.line(cx + s * 0.30, cy - s * 0.06, cx + s * 0.42, cy - s * 0.22, c, sw2)
    sv.circle(cx, cy + s * 0.12, s * 0.055, c)


def _mitm(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.46, cy - s * 0.12, s * 0.24, s * 0.24, c, r=2.5)
    sv.rect(cx + s * 0.22, cy - s * 0.12, s * 0.24, s * 0.24, c, r=2.5)
    _path(sv, cx, cy, s, [(-0.22, 0.0), (0.0, 0.0)], c, sw)
    _path(sv, cx, cy, s, [(-0.02, -0.28), (-0.02, 0.28)], c, sw * 0.8)
    _arc(sv, cx, cy, s * 0.30, -90, 90, c, sw * 0.8)
    sv.circle(cx - 0.02 * s, cy, s * 0.05, c)


def _cube(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(0, -0.44), (0.44, -0.22), (0.44, 0.22), (0, 0.44),
                          (-0.44, 0.22), (-0.44, -0.22)], c, sw, close=True)
    _path(sv, cx, cy, s, [(-0.44, -0.22), (0, 0.0), (0.44, -0.22)], c, sw * 0.8)
    sv.line(cx, cy, cx, cy + 0.44 * s, c, sw * 0.8)


def _wifi_slash(sv, cx, cy, s, c, sw):
    _arc(sv, cx, cy + s * 0.22, s * 0.20, 210, 330, c, sw)
    _arc(sv, cx, cy + s * 0.22, s * 0.36, 210, 330, c, sw, )
    _arc(sv, cx, cy + s * 0.22, s * 0.52, 210, 330, c, sw)
    sv.circle(cx, cy + s * 0.26, s * 0.05, c)
    sv.line(cx - s * 0.42, cy - s * 0.42, cx + s * 0.42, cy + s * 0.42, c, sw * 1.25)


def _wifi(sv, cx, cy, s, c, sw):
    _arc(sv, cx, cy + s * 0.22, s * 0.20, 210, 330, c, sw)
    _arc(sv, cx, cy + s * 0.22, s * 0.36, 210, 330, c, sw)
    _arc(sv, cx, cy + s * 0.22, s * 0.52, 210, 330, c, sw)
    sv.circle(cx, cy + s * 0.26, s * 0.05, c)


def _lock(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.32, cy - s * 0.06, s * 0.64, s * 0.48, "none", stroke=c, sw=sw, r=4)
    sv.path(f"M {cx-s*0.19} {cy-s*0.06} L {cx-s*0.19} {cy-s*0.20} "
            f"A {s*0.19} {s*0.19} 0 0 1 {cx+s*0.19} {cy-s*0.20} "
            f"L {cx+s*0.19} {cy-s*0.06}", stroke=c, sw=sw)
    sv.circle(cx, cy + s * 0.18, s * 0.055, c)


def _lock_open(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.32, cy - s * 0.06, s * 0.64, s * 0.48, "none", stroke=c, sw=sw, r=4)
    sv.path(f"M {cx-s*0.19} {cy-s*0.06} L {cx-s*0.19} {cy-s*0.26} "
            f"A {s*0.19} {s*0.19} 0 0 1 {cx+s*0.19} {cy-s*0.26}",
            stroke=c, sw=sw)
    sv.circle(cx, cy + s * 0.18, s * 0.055, c)


def _shield(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(0, -0.44), (0.38, -0.28), (0.38, 0.06), (0, 0.44),
                          (-0.38, 0.06), (-0.38, -0.28)], c, sw, close=True)
    _path(sv, cx, cy, s, [(-0.15, 0.0), (-0.03, 0.13), (0.18, -0.12)], c, sw * 0.9)


def _shield_slash(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(0, -0.44), (0.38, -0.28), (0.38, 0.06), (0, 0.44),
                          (-0.38, 0.06), (-0.38, -0.28)], c, sw, close=True)
    sv.line(cx - 0.34 * s, cy + 0.30 * s, cx + 0.34 * s, cy - 0.30 * s, c, sw * 1.2)


def _cpu(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.26, cy - s * 0.26, s * 0.52, s * 0.52, "none", stroke=c, sw=sw, r=3)
    sv.rect(cx - s * 0.09, cy - s * 0.09, s * 0.18, s * 0.18, "none", stroke=c, sw=sw * 0.8, r=1.5)
    for k in (-1, 0, 1):
        sv.line(cx + k * s * 0.15, cy - s * 0.40, cx + k * s * 0.15, cy - s * 0.26, c, sw * 0.8)
        sv.line(cx + k * s * 0.15, cy + s * 0.26, cx + k * s * 0.15, cy + s * 0.40, c, sw * 0.8)
        sv.line(cx - s * 0.40, cy + k * s * 0.15, cx - s * 0.26, cy + k * s * 0.15, c, sw * 0.8)
        sv.line(cx + s * 0.26, cy + k * s * 0.15, cx + s * 0.40, cy + k * s * 0.15, c, sw * 0.8)


def _globe(sv, cx, cy, s, c, sw):
    sv.circle(cx, cy, s * 0.40, "none", c, sw)
    sv.ellipse(cx, cy, s * 0.17, s * 0.40, "none", c, sw * 0.8)
    sv.line(cx - s * 0.40, cy, cx + s * 0.40, cy, c, sw * 0.8)
    sv.path(f"M {cx-s*0.34} {cy-s*0.20} A {s*0.40} {s*0.40} 0 0 1 {cx+s*0.34} {cy-s*0.20}",
            stroke=c, sw=sw * 0.7)
    sv.path(f"M {cx-s*0.34} {cy+s*0.20} A {s*0.40} {s*0.40} 0 0 0 {cx+s*0.34} {cy+s*0.20}",
            stroke=c, sw=sw * 0.7)


def _router(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.44, cy - s * 0.20, s * 0.88, s * 0.42, "none", stroke=c, sw=sw, r=4)
    sv.circle(cx - s * 0.26, cy, s * 0.05, c)
    sv.circle(cx - s * 0.10, cy, s * 0.05, c)
    _arc(sv, cx + s * 0.20, cy + s * 0.12, s * 0.13, 200, 340, c, sw * 0.8)
    _arc(sv, cx + s * 0.20, cy + s * 0.12, s * 0.24, 200, 340, c, sw * 0.8)


def _server(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.40, cy - s * 0.40, s * 0.80, s * 0.34, "none", stroke=c, sw=sw, r=3)
    sv.rect(cx - s * 0.40, cy + s * 0.06, s * 0.80, s * 0.34, "none", stroke=c, sw=sw, r=3)
    sv.circle(cx - s * 0.26, cy - s * 0.23, s * 0.045, c)
    sv.circle(cx - s * 0.26, cy + s * 0.23, s * 0.045, c)


def _phone(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.24, cy - s * 0.42, s * 0.48, s * 0.84, "none", stroke=c, sw=sw, r=5)
    sv.line(cx - s * 0.08, cy + s * 0.32, cx + s * 0.08, cy + s * 0.32, c, sw * 0.9)


def _laptop(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.34, cy - s * 0.34, s * 0.68, s * 0.46, "none", stroke=c, sw=sw, r=3)
    _path(sv, cx, cy, s, [(-0.46, 0.12), (0.46, 0.12), (0.38, 0.26), (-0.38, 0.26)],
          c, sw, close=True)


def _printer(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.34, cy - s * 0.40, s * 0.68, s * 0.26, "none", stroke=c, sw=sw, r=2.5)
    sv.rect(cx - s * 0.42, cy - s * 0.14, s * 0.84, s * 0.40, "none", stroke=c, sw=sw, r=4)
    sv.rect(cx - s * 0.24, cy + s * 0.14, s * 0.48, s * 0.26, c, r=2, op=0.9)


def _tv(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.44, cy - s * 0.32, s * 0.88, s * 0.56, "none", stroke=c, sw=sw, r=4)
    sv.line(cx, cy + s * 0.24, cx, cy + s * 0.34, c, sw)
    sv.line(cx - s * 0.18, cy + s * 0.36, cx + s * 0.18, cy + s * 0.36, c, sw)


def _camera(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.42, cy - s * 0.24, s * 0.84, s * 0.54, "none", stroke=c, sw=sw, r=5)
    _path(sv, cx, cy, s, [(-0.20, -0.24), (-0.10, -0.36), (0.10, -0.36),
                          (0.20, -0.24)], c, sw)
    sv.circle(cx, cy + 0.03 * s, s * 0.15, "none", c, sw)


def _clock(sv, cx, cy, s, c, sw):
    sv.circle(cx, cy, s * 0.40, "none", c, sw)
    sv.line(cx, cy, cx, cy - s * 0.22, c, sw)
    sv.line(cx, cy, cx + s * 0.16, cy + s * 0.08, c, sw)


def _bolt(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(0.10, -0.44), (-0.26, 0.04), (-0.02, 0.04),
                          (-0.10, 0.44), (0.26, -0.06), (0.02, -0.06)], c, sw, close=True)


def _link(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.06, -0.20), (0.16, -0.20), (0.16, 0.20), (-0.06, 0.20)],
          c, sw, close=False)
    _path(sv, cx, cy, s, [(0.06, -0.20), (-0.16, -0.20), (-0.16, 0.20), (0.06, 0.20)],
          c, sw, close=False)
    sv.line(cx - 0.08 * s, cy, cx + 0.08 * s, cy, c, sw)


def _list(sv, cx, cy, s, c, sw):
    for k in range(3):
        y = cy + (k - 1) * s * 0.22
        sv.circle(cx - s * 0.30, y, s * 0.045, c)
        sv.line(cx - s * 0.18, y, cx + s * 0.34, y, c, sw)


def _exclamation(sv, cx, cy, s, c, sw):
    sv.circle(cx, cy, s * 0.40, "none", c, sw)
    sv.line(cx, cy - s * 0.20, cx, cy + s * 0.02, c, sw)
    sv.circle(cx, cy + s * 0.18, s * 0.045, c)


def _checkmark(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.24, 0.0), (-0.07, 0.18), (0.26, -0.20)], c, sw * 1.15)


def _xmark(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.22, -0.22), (0.22, 0.22)], c, sw)
    _path(sv, cx, cy, s, [(-0.22, 0.22), (0.22, -0.22)], c, sw)


def _play(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.16, -0.28), (0.28, 0.0), (-0.16, 0.28)], c, sw, close=True)


def _stop(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.24, cy - s * 0.24, s * 0.48, s * 0.48, c, r=4)


def _refresh(sv, cx, cy, s, c, sw):
    _arc(sv, cx, cy, s * 0.36, 40, 320, c, sw)
    _path(sv, cx, cy, s, [(0.24, -0.34), (0.40, -0.16), (0.20, -0.10)], c, sw * 0.9)


def _plus(sv, cx, cy, s, c, sw):
    sv.line(cx - s * 0.26, cy, cx + s * 0.26, cy, c, sw)
    sv.line(cx, cy - s * 0.26, cx, cy + s * 0.26, c, sw)


def _trash(sv, cx, cy, s, c, sw):
    sv.line(cx - s * 0.30, cy - s * 0.26, cx + s * 0.30, cy - s * 0.26, c, sw)
    sv.path(f"M {cx-s*0.22} {cy-s*0.26} L {cx-s*0.18} {cy+s*0.40} "
            f"L {cx+s*0.18} {cy+s*0.40} L {cx+s*0.22} {cy-s*0.26}",
            stroke=c, sw=sw)
    sv.path(f"M {cx-s*0.10} {cy-s*0.26} L {cx-s*0.10} {cy-s*0.36} "
            f"L {cx+s*0.10} {cy-s*0.36} L {cx+s*0.10} {cy-s*0.26}", stroke=c, sw=sw)


def _network(sv, cx, cy, s, c, sw):
    sv.circle(cx, cy - s * 0.32, s * 0.11, "none", c, sw)
    sv.circle(cx - s * 0.34, cy + s * 0.30, s * 0.11, "none", c, sw)
    sv.circle(cx + s * 0.34, cy + s * 0.30, s * 0.11, "none", c, sw)
    sv.line(cx, cy - s * 0.21, cx - s * 0.27, cy + s * 0.22, c, sw * 0.8)
    sv.line(cx, cy - s * 0.21, cx + s * 0.27, cy + s * 0.22, c, sw * 0.8)
    sv.line(cx - s * 0.23, cy + s * 0.30, cx + s * 0.23, cy + s * 0.30, c, sw * 0.8)


def _route_trace(sv, cx, cy, s, c, sw):
    """Hop path: three nodes, the leg between each pair dashed.

    The dashes are the point of the glyph rather than styling. A traceroute is
    a sequence of probes that only reveal a router when that router answers, so
    the path is known to have gaps in it, and a solid line would draw a route
    that is more certain than the thing being measured. The far node is filled
    to mark the destination, the two before it hollow to mark the routers.
    """
    a = (cx - s * 0.36, cy + s * 0.24)
    b = (cx, cy - s * 0.24)
    d = (cx + s * 0.36, cy + s * 0.24)
    r = s * 0.115
    dash = f"{s * 0.055:.2f} {s * 0.075:.2f}"
    sv.line(a[0], a[1], b[0], b[1], c, sw * 0.9, cap="round", dash=dash)
    sv.line(b[0], b[1], d[0], d[1], c, sw * 0.9, cap="round", dash=dash)
    sv.circle(a[0], a[1], r, "none", c, sw)
    sv.circle(b[0], b[1], r, "none", c, sw)
    sv.circle(d[0], d[1], r, c, c, sw)


def _location(sv, cx, cy, s, c, sw):
    sv.path(f"M {cx} {cy+s*0.40} C {cx-s*0.40} {cy+s*0.02} {cx-s*0.30} {cy-s*0.42} "
            f"{cx} {cy-s*0.42} C {cx+s*0.30} {cy-s*0.42} {cx+s*0.40} {cy+s*0.02} "
            f"{cx} {cy+s*0.40} Z", stroke=c, sw=sw)
    sv.circle(cx, cy - s * 0.16, s * 0.13, "none", c, sw * 0.9)


def _square_arrow_up(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.38, cy - s * 0.38, s * 0.76, s * 0.76, "none", stroke=c, sw=sw, r=5)
    sv.line(cx, cy + s * 0.16, cx, cy - s * 0.16, c, sw)
    _path(sv, cx, cy, s, [(-0.13, -0.02), (0, -0.16), (0.13, -0.02)], c, sw)


def _arrow_right(sv, cx, cy, s, c, sw):
    sv.line(cx - s * 0.24, cy, cx + s * 0.20, cy, c, sw)
    _path(sv, cx, cy, s, [(0.04, -0.16), (0.22, 0.0), (0.04, 0.16)], c, sw)


def _chevron_right(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.09, -0.20), (0.09, 0.0), (-0.09, 0.20)], c, sw)


def _eye(sv, cx, cy, s, c, sw):
    sv.path(f"M {cx-s*0.42} {cy} C {cx-s*0.20} {cy-s*0.26} {cx+s*0.20} {cy-s*0.26} "
            f"{cx+s*0.42} {cy} C {cx+s*0.20} {cy+s*0.26} {cx-s*0.20} {cy+s*0.26} "
            f"{cx-s*0.42} {cy} Z", stroke=c, sw=sw)
    sv.circle(cx, cy, s * 0.13, "none", c, sw)


def _doc(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.30, -0.42), (0.10, -0.42), (0.30, -0.22),
                          (0.30, 0.42), (-0.30, 0.42)], c, sw, close=True)
    _path(sv, cx, cy, s, [(0.10, -0.42), (0.10, -0.22), (0.30, -0.22)], c, sw * 0.8)
    for k in range(3):
        sv.line(cx - 0.16 * s, cy - 0.06 * s + k * s * 0.14,
                cx + 0.16 * s, cy - 0.06 * s + k * s * 0.14, c, sw * 0.75)


def _folder(sv, cx, cy, s, c, sw):
    _path(sv, cx, cy, s, [(-0.40, -0.30), (-0.10, -0.30), (0.0, -0.18),
                          (0.40, -0.18), (0.40, 0.30), (-0.40, 0.30)], c, sw, close=True)


def _person(sv, cx, cy, s, c, sw):
    sv.circle(cx, cy - s * 0.22, s * 0.17, "none", c, sw)
    _path(sv, cx, cy, s, [(-0.34, 0.36), (-0.34, 0.18), (0.34, 0.18), (0.34, 0.36)],
          c, sw)


def _bell(sv, cx, cy, s, c, sw):
    sv.path(f"M {cx-s*0.32} {cy+s*0.16} L {cx-s*0.22} {cy+s*0.04} "
            f"L {cx-s*0.22} {cy-s*0.08} A {s*0.22} {s*0.22} 0 0 1 {cx+s*0.22} {cy-s*0.08} "
            f"L {cx+s*0.22} {cy+s*0.04} L {cx+s*0.32} {cy+s*0.16} Z", stroke=c, sw=sw)
    sv.line(cx - s * 0.32, cy + s * 0.16, cx + s * 0.32, cy + s * 0.16, c, sw)
    sv.line(cx - s * 0.10, cy + s * 0.28, cx + s * 0.10, cy + s * 0.28, c, sw * 0.8)


def _antenna(sv, cx, cy, s, c, sw):
    sv.line(cx, cy + s * 0.40, cx, cy + s * 0.10, c, sw)
    _arc(sv, cx, cy + s * 0.10, s * 0.16, 200, 340, c, sw * 0.9)
    _arc(sv, cx, cy + s * 0.10, s * 0.30, 200, 340, c, sw * 0.9)
    _arc(sv, cx, cy + s * 0.10, s * 0.44, 200, 340, c, sw * 0.9)
    sv.circle(cx, cy + s * 0.12, s * 0.05, c)


def _battery(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.36, cy - s * 0.20, s * 0.72, s * 0.40, "none", stroke=c, sw=sw, r=4)
    sv.rect(cx - s * 0.26, cy - s * 0.10, s * 0.34, s * 0.20, c, r=2, op=0.9)


def _square_stack(sv, cx, cy, s, c, sw):
    sv.rect(cx - s * 0.42, cy - s * 0.42, s * 0.52, s * 0.52, "none", stroke=c, sw=sw, r=4)
    sv.rect(cx - s * 0.10, cy - s * 0.10, s * 0.52, s * 0.52, c, r=4, op=0.35)


ICONS = {
    "radar": _radar, "devices": _devices, "terminal": _terminal,
    "waveform": _waveform, "gear": _gear, "doc_search": _doc_search,
    "bug": _bug, "key": _key, "mitm": _mitm, "cube": _cube,
    "wifi_slash": _wifi_slash, "wifi": _wifi, "lock": _lock,
    "lock_open": _lock_open, "shield": _shield, "shield_slash": _shield_slash,
    "cpu": _cpu, "globe": _globe, "router": _router, "server": _server,
    "phone": _phone, "laptop": _laptop, "printer": _printer, "tv": _tv,
    "camera": _camera, "clock": _clock, "bolt": _bolt, "link": _link,
    "list": _list, "exclamation": _exclamation, "checkmark": _checkmark,
    "xmark": _xmark, "play": _play, "stop": _stop, "refresh": _refresh,
    "plus": _plus, "trash": _trash, "network": _network, "location": _location,
    "square_arrow_up": _square_arrow_up, "arrow_right": _arrow_right,
    "chevron_right": _chevron_right, "eye": _eye, "doc": _doc,
    "folder": _folder, "person": _person, "bell": _bell, "antenna": _antenna,
    "battery": _battery, "square_stack": _square_stack,
    "route_trace": _route_trace, "sniffer": _sniffer, "dns": _dns,
    "hijack": _hijack,
}

MODULE_ICON = {
    "portscan": "radar", "service": "doc_search", "exploit": "bug",
    "login": "key", "sessions": "terminal", "mitm": "mitm",
    "forger": "cube", "wifi": "wifi_slash", "trace": "route_trace",
    "sniffer": "sniffer", "dns": "dns", "hijack": "hijack",
}

DEVICE_ICON = {
    "router": "router", "server": "server", "phone": "phone",
    "laptop": "laptop", "printer": "printer", "tv": "tv",
    "camera": "camera", "iot": "cpu", "unknown": "square_stack",
}


def draw_sf(sv, name, cx, cy, size, color, sw=None):
    fn = ICONS.get(name, ICONS["square_stack"])
    sw = sw if sw is not None else max(1.35, size * 0.075)
    fn(sv, cx, cy, size, color, sw)
