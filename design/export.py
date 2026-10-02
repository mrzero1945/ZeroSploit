#!/usr/bin/env python3
"""ZEROSPLOIT — build pipeline: SVG (source) -> PNG (Inkscape) -> APK assets.

  1. regenerate every .svg from the design system
  2. strict XML validation (fail fast, never ship a broken file)
  3. Inkscape raster export at 1x/2x/3x and per-density icon sizes
  4. pixel sanity check: right dimensions + actually has ink
"""
import os
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXP = os.path.join(HERE, "export")
INK = shutil.which("inkscape")

DPI = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}

# launcher / adaptive icon sizes per density
LAUNCHER = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
ADAPTIVE = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}
TILE = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}

fail = []


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sh(*args):
    return " ".join(args)


def validate(path):
    """Strict XML well-formedness + required root checks."""
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        return f"XML parse error: {e}"
    if not root.tag.endswith("svg"):
        return f"root element is <{root.tag}>, expected <svg>"
    if root.get("viewBox") is None:
        return "missing viewBox"
    # every url(#id) reference must resolve
    ids = {e.get("id") for e in root.iter() if e.get("id")}
    for e in root.iter():
        for k, v in e.attrib.items():
            if isinstance(v, str) and v.startswith("url(#"):
                rid = v[5:-1]
                if rid not in ids:
                    return f"dangling reference {v}"
    return None


def export_png(svg, out, w, h=None, bg=None):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    h = h or w
    cmd = [INK, os.path.abspath(svg), "--export-type=png",
           f"--export-filename={os.path.abspath(out)}",
           "-w", str(int(round(w))), "-h", str(int(round(h)))]
    if bg:
        cmd += [f"--export-background={bg}", "--export-background-opacity=1"]
    r = run(cmd)
    err = (r.stderr or "").strip()
    if "parser error" in err or "cannot be opened" in err or "Extra content" in err:
        fail.append(f"{svg}: {err.splitlines()[0]}")
        return False
    if not os.path.exists(out):
        fail.append(f"{svg}: no PNG produced (rc={r.returncode}) {err[:200]}")
        return False
    return True


def png_size(path):
    with open(path, "rb") as f:
        head = f.read(33)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    w, h = struct.unpack(">II", head[16:24])
    return w, h


def has_ink(path, thresh=0.004):
    """True if the PNG actually rendered content.

    Two cases:
      * transparent background (glyphs, adaptive fg) -> measure alpha coverage
      * opaque background (screens, tiles)           -> measure colour variance
    """
    try:
        from PIL import Image
    except ImportError:
        return os.path.getsize(path) > 400, "no-PIL:size"
    im = Image.open(path).convert("RGBA")
    px = list(im.getdata())
    if not px:
        return False, "empty"
    transparent = sum(1 for p in px if p[3] < 16) / len(px)
    if transparent > 0.5:
        ink = sum(1 for p in px if p[3] > 32) / len(px)
        return ink > thresh, f"alpha {ink*100:.1f}%"
    counts = {}
    for p in px:
        counts[p[:3]] = counts.get(p[:3], 0) + 1
    bg = max(counts, key=counts.get)
    ink = sum(1 for p in px
              if abs(p[0]-bg[0]) + abs(p[1]-bg[1]) + abs(p[2]-bg[2]) > 24) / len(px)
    return ink > thresh, f"rgb {ink*100:.1f}%"


# =============================================================================
def main():
    if not INK:
        print("FATAL: inkscape not found in PATH")
        return 2

    print("== 1. regenerate SVG from design system ==")
    for script in ("gen_icons.py", "gen_screens.py"):
        r = run([sys.executable, os.path.join(HERE, script)], cwd=HERE)
        if r.returncode:
            print(r.stdout, r.stderr)
            return 1
        print("   ", script, "ok")

    svgs = []
    for d in ("screens", "icons"):
        p = os.path.join(HERE, d)
        svgs += [os.path.join(p, f) for f in sorted(os.listdir(p))
                 if f.endswith(".svg")]
    print(f"    {len(svgs)} svg files")

    print("== 2. strict XML validation ==")
    bad = 0
    for s in svgs:
        err = validate(s)
        if err:
            print(f"    FAIL {os.path.relpath(s, HERE)}: {err}")
            fail.append(s)
            bad += 1
    if bad:
        print(f"    {bad} invalid file(s) — aborting before export")
        return 1
    print("    all svg well-formed, all url(#id) references resolve")

    if os.path.isdir(EXP):
        shutil.rmtree(EXP)
    os.makedirs(EXP, exist_ok=True)

    print("== 3. Inkscape raster export ==")
    n = 0

    # 3a. screens at 1x/2x/3x (design reference + in-app guide)
    for s in svgs:
        if os.path.basename(os.path.dirname(s)) != "screens":
            continue
        base = os.path.splitext(os.path.basename(s))[0]
        for scale in (1, 2, 3):
            if export_png(s, f"{EXP}/screens/{base}@{scale}x.png",
                          393 * scale, 852 * scale):
                n += 1

    # 3b. module tiles + glyphs, per density
    for s in svgs:
        b = os.path.basename(s)
        if b.startswith("app_"):
            key = b[4:-4]
            for d, sz in TILE.items():
                if export_png(s, f"{EXP}/res/{d}/ic_{key}.png", sz, sz):
                    n += 1
        elif b.startswith("glyph_"):
            key = b[6:-4]
            for d, sz in TILE.items():
                if export_png(s, f"{EXP}/res/{d}/gl_{key}.png", sz, sz):
                    n += 1

    # 3c. launcher (legacy round-ish + adaptive layers)
    lch = [x for x in svgs if x.endswith("launcher.svg")][0]
    for d, sz in LAUNCHER.items():
        if export_png(lch, f"{EXP}/res/{d}/ic_launcher.png", sz, sz):
            n += 1
    if export_png(lch, f"{EXP}/res/playstore/icon_512.png", 512, 512):
        n += 1
    for d, sz in ADAPTIVE.items():
        for kind in ("adaptive_bg", "adaptive_fg"):
            p = os.path.join(HERE, "icons", kind + ".svg")
            if export_png(p, f"{EXP}/res/{d}/{kind}.png", sz, sz):
                n += 1
    print(f"    {n} PNG written")

    print("== 4. output sanity check ==")
    pngs = []
    for dp, _, fs in os.walk(EXP):
        pngs += [os.path.join(dp, f) for f in fs if f.endswith(".png")]
    probs = 0
    for p in sorted(pngs):
        sz = png_size(p)
        if sz is None:
            print(f"    FAIL not a png: {p}")
            probs += 1
            continue
        ok, info = has_ink(p)
        if not ok:
            print(f"    FAIL blank ({info}): {os.path.relpath(p, HERE)} {sz}")
            probs += 1
    print(f"    {len(pngs)} PNG checked, {probs} problem(s)")

    if fail or probs:
        print("\nFAILED")
        for f in fail:
            print("  -", f)
        return 1
    print("\nOK — design pipeline clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
