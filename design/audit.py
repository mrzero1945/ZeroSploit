#!/usr/bin/env python3
"""Layout audit: estimate text extents and flag overflow / collisions.

This is the automated stand-in for eyeballing the design — it catches text
running off the canvas or past the right margin, which is the most common
defect in generated layouts.
"""
import glob
import os
import re
import xml.etree.ElementTree as ET

NS = "{http://www.w3.org/2000/svg}"
HERE = os.path.dirname(os.path.abspath(__file__))
W, H = 393, 852
SAFE_L, SAFE_R = 4, W - 4
TAB_TOP = H - 49 - 34          # tab bar top
NAV_TOP = 103

# average advance width as a fraction of font-size
W_SANS = 0.495
W_MONO = 0.602

issues = []
stats = []


def text_width(t, size, mono, ls):
    adv = (W_MONO if mono else W_SANS) * size
    return adv * len(t) + (ls or 0) * len(t)


def audit(path):
    root = ET.parse(path).getroot()
    vb = [float(v) for v in root.get("viewBox").split()]
    cw, ch = vb[2], vb[3]
    els = list(root.iter(NS + "text"))
    worst = []

    def walk(node, dx, dy):
        """Text coords are local; accumulate ancestor translate() offsets."""
        nonlocal els
        for e in node:
            tr = e.get("transform") or ""
            ndx, ndy = dx, dy
            m = re.search(r"translate\(\s*(-?[\d.]+)[ ,]+(-?[\d.]+)", tr)
            if m:
                ndx += float(m.group(1))
                ndy += float(m.group(2))
            if e.tag == NS + "text":
                t = "".join(e.itertext())
                if not t.strip():
                    continue
                size = float(e.get("font-size", 16))
                ls = float(e.get("letter-spacing", 0) or 0)
                mono = "Mono" in (e.get("font-family") or "")
                x = float(e.get("x", 0)) + ndx
                y = float(e.get("y", 0)) + ndy
                w = text_width(t, size, mono, ls)
                anchor = e.get("text-anchor", "start")
                x0, x1 = ((x - w / 2, x + w / 2) if anchor == "middle"
                          else (x - w, x) if anchor == "end" else (x, x + w))
                name = os.path.basename(path)
                if x0 < SAFE_L:
                    issues.append(f"{name}: '{t[:34]}' starts at {x0:.1f} "
                                  f"(< {SAFE_L})")
                if x1 > cw:
                    issues.append(f"{name}: '{t[:34]}' ends at {x1:.1f} "
                                  f"(> canvas {cw})")
                elif x1 > cw - 12:
                    worst.append((x1, t))
                if y > ch or y < 0:
                    issues.append(f"{name}: '{t[:34]}' baseline y={y:.1f} "
                                  f"off-canvas")
                if 763 < y < 800:
                    issues.append(f"{name}: '{t[:34]}' baseline y={y:.1f} hidden "
                                  f"behind the tab bar (content must end by 763)")
                if 44 < y < 70:
                    issues.append(f"{name}: '{t[:34]}' baseline y={y:.1f} collides "
                                  f"with the nav bar / large title")
            walk(e, ndx, ndy)

    walk(root, 0, 0)
    if worst:
        worst.sort(reverse=True)
        stats.append((os.path.basename(path), worst[:3]))
    return len(els)


if __name__ == "__main__":
    total = 0
    files = sorted(glob.glob(os.path.join(HERE, "screens", "*.svg"))) + \
        sorted(glob.glob(os.path.join(HERE, "icons", "*.svg")))
    for f in files:
        total += audit(f)
    print(f"audited {len(files)} files, {total} text runs\n")
    if issues:
        print(f"HARD ISSUES ({len(issues)}):")
        for i in issues:
            print("  ", i)
    else:
        print("HARD ISSUES: none (no text off-canvas)")
    if stats:
        print("\nRIGHT-EDGE CROWDING (check visually / may be intentional):")
        for n, w in stats:
            for x1, t in w:
                print(f"   {n:22s} {x1:7.1f}  '{t[:40]}'")
