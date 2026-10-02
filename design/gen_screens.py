"""ZEROSPLOIT — iOS-style screen designs (Inkscape SVG sources)."""
import os
from theme import *
from kit import *
from sf import draw_sf, MODULE_ICON, DEVICE_ICON

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "screens")
os.makedirs(OUT, exist_ok=True)

M = 20                      # outer margin
CW = W - M * 2              # 353 content width
IN = 16                     # grouped-list inset


def frame(title=None, active_tab=0, back=None, large=True, trailing=None,
          sub=None, tab=True, bg=BG, status=True):
    sv = screen(bg=bg)
    if status:
        status_bar(sv)
    if title:
        nav_bar(sv, title, large=large, back=back, trailing=trailing, sub=sub)
    if tab:
        tab_bar(sv, active_tab)
    else:
        home_indicator(sv)
    return sv


# =============================================================================
def s01_splash():
    sv = screen()
    # ambient wash
    g = sv.grad([(0, "#0A1A3A", 0.85), (0.45, "#000000", 0.0), (1, "#000000", 0.0)],
                x1=0, y1=0, x2=0, y2=1, gid="wash")
    sv.rect(0, 0, W, 520, f"url(#{g})")
    status_bar(sv)
    cx, cy = W / 2, 330
    for rr, op, sw in [(92, 0.16, 1.2), (70, 0.30, 1.6), (48, 0.55, 2.0)]:
        sv.circle(cx, cy, rr, "none", BLUE, sw, op=op)
    for k in range(48):
        import math
        a = math.radians(k * 7.5)
        sv.line(cx + 100 * math.cos(a), cy + 100 * math.sin(a),
                cx + 108 * math.cos(a), cy + 108 * math.sin(a), BLUE, 1.2, op=0.25)
    sv.circle(cx, cy, 34, "none", "#FFFFFF", 5.0)
    sv.rect(cx - 5, cy - 34, 10, 68, "#000")
    sv.line(cx - 40, cy + 40, cx + 40, cy - 40, BLUE, 11, op=0.95)
    sv.line(cx - 40, cy + 40, cx + 40, cy - 40, "#FFFFFF", 7)

    sv.st(cx, 500, "ZeroSploit", ST_LARGE_TITLE, fill=TEXT, anchor="middle",
          weight="700")
    sv.st(cx, 524, "LAN SECURITY SUITE", ST_FOOTNOTE, fill=BLUE, anchor="middle",
          ls=2.4)
    sv.st(cx, 566, "Authorized networks only.", ST_SUBHEAD, fill=TEXT_2,
          anchor="middle")

    # boot log
    lines = [("$ zerosploit --init", TEXT_2),
             ("[ok]  native engine loaded", GREEN),
             ("[ok]  raw socket capability", YELLOW),
             ("[--]  awaiting authorization", TEXT_3)]
    y = 648
    code_block(sv, M, y, CW, lines, lh=18, fs=11.5)
    progress(sv, M, y + 100, CW, 100, BLUE, 3)
    sv.st(cx, H - 46, "v1.0.0  ·  C++ / JNI core", ST_CAPTION_2, fill=TEXT_3,
          anchor="middle")
    sv.save(f"{OUT}/01_splash.svg")


# =============================================================================
def s02_root():
    sv = frame("Capability", active_tab=4, large=True, tab=True)
    y = 118
    # big status card
    cid = sv.shadow(sv.uid("sh"), 20, 8, 0.5)
    g = sv.grad([(0, "#1C1C1E", None), (1, "#101012", None)], gid="rc")
    sv.rect(M, y, CW, 110, f"url(#{g})", r=R_LARGE,
            extra=f' filter="url(#{cid})"')
    sv.circle(M + 44, y + 44, 24, ORANGE, op=0.20)
    draw_sf(sv, "lock_open", M + 44, y + 44, 26, ORANGE, 2.0)
    sv.st(M + 80, y + 38, "Root not granted", ST_TITLE_3, fill=TEXT)
    sv.st(M + 80, y + 58, "su binary not available to app", ST_FOOTNOTE,
          fill=TEXT_2)
    x = M + CW - 62
    draw_switch(sv, x, y + 32, on=False)
    sv.st(M + CW - 20, y + 100, "TAP TO REQUEST", ST_CAPTION_2, fill=TEXT_3,
          ls=0.8, anchor="end")
    y += 130

    rows = []
    for ic, t, s_, v, ok in [
        ("network", "Subnet discovery", "ARP + TCP + UDP sweep", "READY", GREEN),
        ("radar", "TCP port scanner", "connect() based, no root", "READY", GREEN),
        ("doc_search", "Banner & service ID", "fingerprint database", "READY", GREEN),
        ("bug", "Exploit matcher", "CVE signature database", "READY", GREEN),
        ("key", "Login auditor", "protocol-aware checks", "READY", GREEN),
        ("mitm", "ARP spoof / MITM", "raw AF_PACKET socket", "ROOT", ORANGE),
        ("forger", "Packet forger", "AF_INET raw socket", "ROOT", ORANGE),
    ]:
        rows.append(row(icon=ic, tint=BLUE if ok == "READY" else ORANGE,
                        title=t, sub=s_, h=50, accessory="none", value=v,
                        value_color=ok, mono_value=True))
    y = group(sv, M, y, CW, rows, title="Engine capabilities")

    y += 8
    rows2 = [row(icon="doc", tint=TEXT_2, title="Authorization statement",
                 h=42, accessory="chevron", value="v1", value_color=TEXT_3),
             row(icon="trash", tint=RED, title="Reset all data", h=42,
                 accessory="none", destructive=True)]
    y = group(sv, M, y + 6, CW, rows2, title="General")
    sv.st(W / 2, y + 24, "ZEROSPLOIT 1.0.0  ·  build 20260929", ST_CAPTION_2,
          fill=TEXT_3, anchor="middle")
    sv.save(f"{OUT}/02_capability.svg")


# =============================================================================
DEVICES = [
    ("192.168.1.1",    "ASUS RT-AX56U",       "router", "router", GREEN, "GW"),
    ("192.168.1.131",  "galaxy-s24",          "phone",  "phone",  BLUE,  "3h"),
    ("192.168.1.104",  "HP LaserJet M428",    "printer","printer",PURPLE,"2d"),
    ("192.168.1.77",   "DESKTOP-7QK2F9",      "laptop", "laptop", INDIGO,"8m"),
    ("192.168.1.142",  "ESP32-DevKit-CAM",    "camera", "camera", PINK,  "1m"),
    ("192.168.1.19",   "NAS-Synology",        "server", "server", TEAL,  "12d"),
]


def device_row(ip, name, di, tint, seen, tag=None, tagc=BLUE, h=62, ports=None):
    """Row-local coordinates: the group() helper translates to absolute."""
    def draw(sv, x=0, w=CW, y=0):
        sv.rect(x + 8, y + (h - 38) / 2, 38, 38, tint, r=10, op=0.20)
        draw_sf(sv, DEVICE_ICON[di], x + 27, y + h / 2, 23, tint, 1.8)
        sv.mono(x + 58, y + 25, ip, 13.5, fill=TEXT)
        sv.st(x + 58, y + 44, name, ST_FOOTNOTE, fill=TEXT_2)
        rx = x + w
        sv.st(rx - 12, y + 25, seen, ST_CAPTION_2, fill=TEXT_3, anchor="end")
        if ports:
            sv.st(rx - 12, y + 45, f"{ports} open", ST_CAPTION_2, fill=GREEN,
                  anchor="end")
        if tag:
            bw = 10 * 0.56 * len(tag) + 16
            badge(sv, rx - 12 - bw - (46 if ports else 0), y + 15, tag, tagc,
                  10, 18)
        sv.path(f"M {rx-10} {y+h/2-5} L {rx-3} {y+h/2} L {rx-10} {y+h/2+5}",
                stroke=TEXT_3, sw=2)
    return draw, h


def s03_network():
    sv = frame("Network", active_tab=0, large=True, sub="wlan0 · 192.168.1.0/24",
               trailing="Edit")
    y = 126
    # gateway hero card
    g = sv.grad([(0, "#0A2A1E", None), (1, "#08110D", None)], gid="gw")
    sv.rect(M, y, CW, 128, f"url(#{g})", r=R_LARGE)
    sv.rect(M, y, CW, 128, "none", r=R_LARGE, stroke=GREEN, sw=1, op=0.45)
    sv.rect(M + 18, y + 20, 44, 44, GREEN, r=12, op=0.20)
    draw_sf(sv, "router", M + 40, y + 42, 27, GREEN, 2.0)
    sv.st(M + 74, y + 36, "GATEWAY", ST_CAPTION_2, fill=GREEN, ls=1.4)
    sv.mono(M + 74, y + 58, "192.168.1.1", 19, fill=TEXT)
    for i, (k, v) in enumerate([("MAC", "2C:30:33:8F:12:04"),
                                ("UPTIME", "6d 04h"),
                                ("HOSTS", "9")]):
        cx = M + 18 + i * ((CW - 36) / 3)
        sv.st(cx, y + 92, k, ST_CAPTION_2, fill=TEXT_3, ls=0.6)
        sv.mono(cx, y + 108, v, 11.5, fill=TEXT_2)
    y += 136

    # scan control
    rows = [row(icon="antenna", tint=BLUE, title="Interface", h=42,
                accessory="chevron", value="wlan0", mono_value=True),
            row(icon="network", tint=BLUE, title="CIDR", h=42,
                accessory="chevron", value="192.168.1.0/24", mono_value=True),
            row(icon="radar", tint=BLUE, title="Probes", h=42,
                accessory="none", value="TCP 80,445,22", mono_value=True)]
    y = group(sv, M, y, CW, rows, title="Scan scope")

    y += 16
    sv.st(M, y, "DISCOVERED  6", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 10
    dev = [device_row(*d[:4], d[5], "GW" if i == 0 else None, GREEN if i == 0
                      else BLUE, h=62) for i, d in enumerate(DEVICES[:4])]
    y = group(sv, M, y, CW, dev, fill=BG_CARD)

    # floating scan button
    cid = sv.shadow(sv.uid("sh"), 14, 6, 0.55)
    g2 = sv.grad([(0, "#3A9BFF", None), (1, BLUE, None)], gid="fb")
    sv.rect(M, y + 18, CW, 52, f"url(#{g2})", r=15,
            extra=f' filter="url(#{cid})"')
    draw_sf(sv, "radar", M + CW / 2 - 48, y + 44, 21, "#FFFFFF", 1.9)
    sv.st(M + CW / 2 + 12, y + 49, "Scan Network", (16, "600", 0.1),
          fill="#FFFFFF", anchor="middle")
    sv.save(f"{OUT}/03_network.svg")


# =============================================================================
def s04_target():
    sv = frame(active_tab=1, back="Network", large=True)
    y = 116
    # target hero
    g = sv.grad([(0, "#101A2E", None), (1, "#0A0C10", None)], gid="th")
    sv.rect(M, y, CW, 150, f"url(#{g})", r=R_LARGE)
    sv.rect(M + 18, y + 18, 52, 52, BLUE, r=14, op=0.20)
    draw_sf(sv, "router", M + 44, y + 44, 31, BLUE, 2.2)
    sv.st(M + 82, y + 38, "ASUS RT-AX56U", ST_TITLE_3, fill=TEXT)
    sv.mono(M + 82, y + 60, "192.168.1.1", 15, fill=TEXT_2)
    bx = M + 18
    for t, c in [("GATEWAY", GREEN), ("LINUX", BLUE), ("ARMv7", INDIGO)]:
        bx += badge(sv, bx, y + 76, t, c, 10, 19) + 6
    sv.line(M + 18, y + 112, M + CW - 18, y + 112, SEPARATOR, 0.5)
    for i, (k, v) in enumerate([("MAC", "2C:30:33:8F:12:04"),
                                ("VENDOR", "ASUSTek"),
                                ("OPEN", "12"),
                                ("OS", "OpenWrt 21.02")]):
        cx = M + 18 + i * ((CW - 36) / 4)
        sv.st(cx, y + 130, k, ST_CAPTION_2, fill=TEXT_3, ls=0.5)
        sv.mono(cx, y + 145, v, 10.5, fill=TEXT_2)
    y += 170

    sv.st(M, y, "ASSESSMENT MODULES", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    gap = 12
    cwid = (CW - gap) / 2
    for i, (key, title, tint) in enumerate(MODULES):
        cx = M + (i % 2) * (cwid + gap)
        cy = y + (i // 2) * 92
        sv.rect(cx, cy, cwid, 84, BG_CARD, r=R_CARD)
        sv.rect(cx, cy, cwid, 84, "none", r=R_CARD, stroke=SEPARATOR, sw=0.5)
        sv.rect(cx + 14, cy + 14, 34, 34, tint, r=9, op=0.20)
        draw_sf(sv, MODULE_ICON[key], cx + 31, cy + 31, 21, tint, 1.7)
        sv.st(cx + 14, cy + 68, title, ST_SUBHEAD, fill=TEXT, weight="600")
        sv.path(f"M {cx+cwid-22} {cy+38} L {cx+cwid-16} {cy+44} L {cx+cwid-22} {cy+50}",
                stroke=TEXT_3, sw=2)
    y += 4 * 92 + 4

    y2 = y
    sv.rect(M, y2, CW, 50, BG_ELEV_2, r=15)
    draw_sf(sv, "eye", M + 30, y2 + 25, 19, TEXT)
    sv.st(M + 50, y2 + 30, "Deep Scan All Modules", (15, "600", 0.1), fill=TEXT)
    sv.save(f"{OUT}/04_target.svg")


# =============================================================================
def s05_portscan():
    sv = frame("Port Scanner", active_tab=1, back="Target", large=True,
               sub="192.168.1.1 · 1-65535")
    y = 128
    # progress card
    sv.rect(M, y, CW, 104, BG_CARD, r=R_CARD)
    progress_ring(sv, M + 46, y + 52, 32, 68, BLUE, 5, "68", "TCP")
    sv.st(M + 94, y + 34, "SCANNING", ST_CAPTION_2, fill=BLUE, ls=1.0)
    sv.mono(M + 94, y + 54, "44,502 / 65,535", 14, fill=TEXT)
    sv.st(M + 94, y + 72, "1,284 threads · 32 ms avg", ST_FOOTNOTE, fill=TEXT_2)
    y += 118

    sv.st(M, y, "PROFILES", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 10
    y = segmented(sv, M, y, CW, ["Top 100", "Top 1000", "Full", "Custom"], sel=1) + 22

    rows = []
    ports = [("22", "open", "ssh", "OpenSSH 8.4p1 Raspbian", GREEN),
             ("23", "open", "telnet", "BusyBox v1.31.1 telnetd", GREEN),
             ("53", "open", "domain", "dnsmasq 2.86", GREEN),
             ("80", "open", "http", "lighttpd/1.4.53", GREEN),
             ("443", "open", "http", "lighttpd/1.4.53 (TLS)", GREEN),
             ("139", "open", "netbios", "Samba 4.11.12", GREEN),
             ("445", "open", "smb", "Samba 4.11.12", GREEN),
             ("548", "open", "afp", "Netatalk 3.1.13", GREEN),
             ("7547", "open", "tr-069", "CWMPd 1.1", GREEN),
             ("1900", "closed", "ssdp", "—", TEXT_3),
             ("23", "filtered", "telnet", "dropped", ORANGE)]
    for p_, stt, svc, ver, col in ports:
        def mk(p_=p_, stt=stt, svc=svc, ver=ver, col=col):
            def draw(sv, x=M, w=CW, y=0):
                sv.mono(x + 14, y + 22, p_, 13, fill=TEXT)
                sv.st(x + 58, y + 22, svc, ST_FOOTNOTE, fill=col)
                sv.st(x + 128, y + 22, ver, ST_FOOTNOTE, fill=TEXT_2)
                badge(sv, x + w - 14 - (10 * 0.56 * len(stt) + 16), y + 8, stt,
                      col, 10, 18)
                if stt == "open":
                    sv.circle(x + w - 14 - 58, y + 17, 3, GREEN)
            return draw
        rows.append((mk(), 40))
    y = group(sv, M, y, CW, rows[:6], title="Results  ·  9 open")
    y = group(sv, M, y + 14, CW, rows[6:8], title=None)
    sv.save(f"{OUT}/05_portscan.svg")


# =============================================================================
def s06_service():
    sv = frame("Service Inspector", active_tab=1, back="Target", large=True,
               sub="192.168.1.1:22")
    y = 128
    rows = [row(icon="server", tint=TEAL, title="Protocol", h=44,
                accessory="none", value="SSH-2.0-OpenSSH_8.4p1", mono_value=True,
                value_color=TEXT),
            row(icon="cpu", tint=TEAL, title="Firmware", h=44, accessory="chevron",
                value="OpenWrt 21.02.3", value_color=TEXT),
            row(icon="lock", tint=TEAL, title="Encryption", h=44,
                accessory="none", value="aes256-ctr / hmac", mono_value=True,
                value_color=GREEN),
            row(icon="person", tint=TEAL, title="Auth methods", h=44,
                accessory="chevron", value="publickey,password"),
            row(icon="doc", tint=TEAL, title="Full banner", h=44,
                accessory="chevron")]
    y = group(sv, M, y, CW, rows, title="Identification")

    y += 16
    sv.st(M, y, "RAW BANNER", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 10
    y = code_block(sv, M, y, CW, [
        ("SSH-2.0-OpenSSH_8.4p1 Raspbian-5", TEXT_2),
        ("SSH-2.0-OpenSSH_8.4p1", CYAN),
        ("debug1: kex_exchange_identification", TEXT_3),
        ("debug1: SSH2_MSG_KEXINIT received", TEXT_3),
        ("kex: algorithm: curve25519-sha256", GREEN),
        ("kex: host key: ssh-rsa SHA256:aB3...", GREEN),
        ("kex: server-sig-algs: rsa-sha2-512", GREEN),
        ("publickey,password", ORANGE),
    ], lh=17)

    y += 22
    sv.st(M, y, "TLS / CERTIFICATE", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    rows2 = [row(leading_text="Subject", title="CN=router.asus.local", h=42,
                 accessory="none"),
             row(leading_text="Issuer", title="CN=router.asus.local (self)", h=42,
                 accessory="none"),
             row(leading_text="Expires", title="2027-04-11 (418 d)", h=42,
                 accessory="none"),
             row(leading_text="SAN", title="router.asus.local",
                 h=42, accessory="none")]
    y = group(sv, M, y, CW, rows2)
    sv.save(f"{OUT}/06_service.svg")


# =============================================================================
def s07_exploit():
    sv = frame("Exploit Finder", active_tab=1, back="Target", large=True,
               sub="9 services · 2,418 signatures")
    y = 126
    tot = [("4", "CRITICAL", RED), ("9", "HIGH", ORANGE),
           ("16", "MEDIUM", YELLOW), ("31", "LOW", BLUE)]
    gap = 10
    bw = (CW - gap * 3) / 4
    for i, (n, t, c) in enumerate(tot):
        bx = M + i * (bw + gap)
        sv.rect(bx, y, bw, 62, BG_CARD, r=14)
        sv.st(bx + bw / 2, y + 30, n, (22, "700", -0.3), fill=c, anchor="middle")
        sv.st(bx + bw / 2, y + 48, t, (9, "600", 0.4), fill=TEXT_2,
              anchor="middle")
    y += 78
    y = segmented(sv, M, y, CW, ["Known CVE", "Misconfig", "Weak TLS", "Default"],
                  sel=0) + 24

    sv.st(M, y, "FINDINGS", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    findings = [
        ("CVE-2023-1389", "OpenSSH 8.4p1 pre-auth RCE", "SSH · 192.168.1.1:22",
         "CVSS 9.8", RED),
        ("CVE-2021-43565", "lighttpd 1.4.53 stack overflow", "HTTP · :80",
         "CVSS 8.1", RED),
        ("CVE-2020-8597", "dnsmasq 2.86 heap overflow", "DNS · :53", "CVSS 7.5", ORANGE),
        ("CVE-2019-10197", "Samba 4.11 remote exec", "SMB · :445", "CVSS 9.8", RED),
        ("CVE-2022-42889", "Text4Shell RCE", "HTTP · :8080", "CVSS 9.8", RED),
        ("WEAK-KEY", "RSA 1024-bit host key", "SSH · :22", "CVSS 5.9", BLUE),
    ]
    for f in findings:
        cve, desc, loc, cvss, col = f
        sv.rect(M, y, CW, 72, BG_CARD, r=R_CARD)
        sv.rect(M, y + 12, 3.5, 48, col, r=2)
        sv.mono(M + 16, y + 26, cve, 12, fill=col)
        sv.st(M + 16, y + 45, desc, ST_SUBHEAD, fill=TEXT)
        sv.st(M + 16, y + 62, loc, ST_CAPTION_2, fill=TEXT_2)
        sv.st(M + CW - 14, y + 26, cvss, ST_CAPTION_2, fill=TEXT_2, anchor="end")
        badge(sv, M + CW - 14 - (10 * 0.56 * 8 + 16), y + 38,
              "CRITICAL" if col is RED else "HIGH", col, 10, 18)
        sv.path(f"M {M+CW-20} {y+32} L {M+CW-14} {y+38} L {M+CW-20} {y+44}",
                stroke=TEXT_3, sw=2)
        y += 80
    sv.save(f"{OUT}/07_exploit.svg")


# =============================================================================
def s08_login():
    sv = frame("Login Auditor", active_tab=1, back="Target", large=True,
               sub="192.168.1.1")
    y = 126
    rows = [row(icon="server", tint=ORANGE, title="Target service", h=44,
                accessory="chevron", value="Telnet :23", value_color=TEXT),
            row(icon="list", tint=ORANGE, title="Profile", h=44,
                accessory="chevron", value="Router default", value_color=TEXT),
            row(icon="clock", tint=ORANGE, title="Rate limit", h=44,
                accessory="chevron", value="2 / sec", mono_value=True)]
    y = group(sv, M, y, CW, rows, title="Configuration")

    y += 20
    sv.st(M, y, "CREDENTIAL MATRIX", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    hdr = ["USER", "RESULT", "RTT"]
    data = [["root", "ACCEPTED", "18 ms"],
            ["admin", "ACCEPTED", "21 ms"],
            ["user", "REJECTED", "17 ms"],
            ["guest", "REJECTED", "16 ms"],
            ["support", "REJECTED", "19 ms"],
            ["default", "REJECTED", "15 ms"]]
    colx = [M + 14, M + 120, M + CW - 16]
    for i, h_ in enumerate(hdr):
        sv.st(colx[i], y, h_, ST_CAPTION_2, fill=TEXT_3, ls=0.5)
    y += 8
    sv.line(M + 6, y, M + CW - 6, y, SEPARATOR, 0.5)
    y += 18
    for u, r_, t in data:
        ok = r_ == "ACCEPTED"
        sv.mono(colx[0], y, u, 12.5, fill=TEXT)
        sv.st(colx[1], y, r_, (11, "600", 0.4),
              fill=GREEN if ok else TEXT_3)
        sv.mono(colx[2], y, t, 11, fill=TEXT_2, anchor="end")
        y += 26
    y += 8
    sv.rect(M, y, CW, 46, GREEN, r=13, op=0.16)
    sv.rect(M, y, CW, 46, "none", r=13, stroke=GREEN, sw=1, op=0.6)
    draw_sf(sv, "lock_open", M + 24, y + 23, 19, GREEN, 1.8)
    sv.st(M + 42, y + 28, "2 accounts recovered · admin session ready",
          ST_FOOTNOTE, fill=GREEN)
    y += 62

    sv.st(M, y, "SESSION", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    y = code_block(sv, M, y, CW, [
        ("$ telnet 192.168.1.1 23", TEXT_2),
        ("BusyBox v1.31.1 telnetd", TEXT_3),
        ("login: admin", CYAN),
        ("Password: ********", CYAN),
        ("~ # uname -a", GREEN),
        ("Linux router 4.14.180 #1 SMP", GREEN),
    ], lh=17)
    sv.save(f"{OUT}/08_login.svg")


# =============================================================================
def s09_sessions():
    sv = frame("Sessions", active_tab=2, large=True, sub="3 live · 1 escalated")
    y = 126
    g = sv.grad([(0, "#241436", None), (1, "#0C0810", None)], gid="ss")
    sv.rect(M, y, CW, 132, f"url(#{g})", r=R_LARGE)
    sv.rect(M, y, CW, 132, "none", r=R_LARGE, stroke=PURPLE, sw=1, op=0.5)
    draw_sf(sv, "terminal", M + 32, y + 32, 24, PURPLE, 1.9)
    sv.st(M + 56, y + 37, "LIVE SHELL", ST_CAPTION_2, fill=PURPLE, ls=1.2)
    sv.mono(M + 56, y + 58, "192.168.1.1:23", 16, fill=TEXT)
    badge(sv, M + 56, y + 70, "ROOT", PURPLE, 10, 19)
    badge(sv, M + 104, y + 70, "PERSISTENT", GREEN, 10, 19)
    sv.line(M + 18, y + 102, M + CW - 18, y + 102, SEPARATOR, 0.5)
    for i, (k, v) in enumerate([("PID", "1"), ("UPTIME", "00:12:48"),
                                ("IFACE", "ppp0")]):
        cx = M + 18 + i * ((CW - 36) / 3)
        sv.st(cx, y + 118, k, ST_CAPTION_2, fill=TEXT_3, ls=0.5)
        sv.mono(cx, y + 130, v, 10.5, fill=TEXT_2)
    y += 152

    sv.st(M, y, "ACTIVE", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    sess = [("192.168.1.1", "Telnet · admin", "root", "00:12:48", GREEN, "router"),
            ("192.168.1.77", "SMB · PSExec", "SYSTEM", "00:04:02", GREEN, "laptop"),
            ("192.168.1.142", "HTTP · CSRF", "guest", "00:00:51", ORANGE, "camera")]
    for ip, svc, user, up, col, di in sess:
        sv.rect(M, y, CW, 72, BG_CARD, r=R_CARD)
        sv.rect(M + 14, y + 18, 36, 36, PURPLE, r=10, op=0.18)
        draw_sf(sv, DEVICE_ICON[di], M + 32, y + 36, 22, PURPLE, 1.8)
        sv.mono(M + 62, y + 28, ip, 12.5, fill=TEXT)
        sv.st(M + 62, y + 46, svc, ST_FOOTNOTE, fill=TEXT_2)
        sv.st(M + 62, y + 62, user, ST_CAPTION_2, fill=col)
        sv.st(M + CW - 14, y + 28, up, ST_CAPTION_2, fill=TEXT_2,
              anchor="end", )
        sv.st(M + CW - 14, y + 50, "OPEN", (10, "600", 0.5), fill=col, anchor="end")
        sv.circle(M + CW - 14 - 26, y + 47, 3, col)
        y += 80
    y += 6
    button(sv, M, y, (CW - 10) / 2, 46, "New Session", "tinted", PURPLE, "plus")
    button(sv, M + (CW + 10) / 2, y, (CW - 10) / 2, 46, "Export", "gray", "doc")
    sv.save(f"{OUT}/09_sessions.svg")


# =============================================================================
def s10_mitm():
    sv = frame("MITM", active_tab=1, back="Target", large=True,
               sub="192.168.1.1 ↔ 192.168.1.77")
    y = 126
    if True:
        g = sv.grad([(0, "#2E1020", None), (1, "#100810", None)], gid="mm")
        sv.rect(M, y, CW, 116, f"url(#{g})", r=R_LARGE)
        sv.rect(M, y, CW, 116, "none", r=R_LARGE, stroke=PINK, sw=1, op=0.55)
        draw_sf(sv, "mitm", M + 38, y + 40, 28, PINK, 2.0)
        sv.st(M + 70, y + 36, "POISONING ACTIVE", (13, "600", 0.6), fill=PINK)
        sv.mono(M + 70, y + 56, "3 hosts poisoned", 15, fill=TEXT)
        sv.st(M + 20, y + 92, "ARP table refreshed every 5 s · restore on stop",
              ST_CAPTION_2, fill=TEXT_2)
        y += 132

    rows = [row(icon="antenna", tint=PINK, title="Interface", h=44,
                accessory="chevron", value="wlan0", mono_value=True),
            row(icon="refresh", tint=PINK, title="Poison interval", h=44,
                accessory="chevron", value="5 s", mono_value=True),
            row(icon="network", tint=PINK, title="Targets", h=44,
                accessory="chevron", value="3 hosts", mono_value=True),
            row(icon="lock_open", tint=PINK, title="TLS interception", h=44,
                accessory="switch", on_tap=True)]
    y = group(sv, M, y, CW, rows, title="Configuration")

    y += 18
    sv.st(M, y, "CAPTURED FLOWS", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    flows = [("192.168.1.77", "→", "192.168.1.1", "HTTP", "GET /admin", YELLOW),
             ("192.168.1.104", "→", "192.168.1.1", "HTTP", "POST /login", RED),
             ("192.168.1.131", "→", "192.168.1.1", "DNS", "A? nas.local", TEXT_2),
             ("192.168.1.77", "→", "192.168.1.1", "HTTP", "POST /cgi-bin/", RED),
             ]
    for a, arrow, b, proto, info, col in flows:
        sv.rect(M, y, CW, 44, BG_CARD, r=12)
        sv.mono(M + 14, y + 27, a, 11, fill=TEXT_2)
        sv.st(M + 86, y + 27, arrow, ST_FOOTNOTE, fill=PINK)
        sv.mono(M + 100, y + 27, b, 11, fill=TEXT_2)
        sv.st(M + 158, y + 27, proto, (10, "600", 0.4), fill=TEXT_2)
        sv.st(M + CW - 14, y + 27, info, ST_CAPTION_2, fill=col, anchor="end")
        y += 50
    y += 8
    button(sv, M, y + 6, CW, 48, "Stop & Restore", "filled", RED, "stop")
    sv.save(f"{OUT}/10_mitm.svg")


# =============================================================================
def s11_forger():
    sv = frame("Packet Forger", active_tab=1, back="Target", large=True)
    y = 126
    y = segmented(sv, M, y, CW, ["TCP", "UDP", "ICMP", "ARP", "802.11"], sel=4) + 22

    rows = [row(icon="wifi", tint=MINT, title="Source MAC", h=42,
                accessory="none", value="3A:F1:09:22:C4:DE", mono_value=True),
            row(icon="router", tint=MINT, title="BSSID", h=42, accessory="none",
                value="2C:30:33:8F:12:04", mono_value=True),
            row(icon="location", tint=MINT, title="Target MAC", h=42,
                accessory="none", value="A4:83:E7:1B:02:99", mono_value=True),
            row(icon="person", tint=MINT, title="Reason code", h=42,
                accessory="chevron", value="7 · invalid", value_color=TEXT),
            row(icon="list", tint=MINT, title="Frame count", h=42,
                accessory="chevron", value="64", mono_value=True),
            row(icon="clock", tint=MINT, title="Rate", h=42, accessory="chevron",
                value="100 pps", mono_value=True)]
    y = group(sv, M, y, CW, rows, title="Frame")

    y += 18
    sv.st(M, y, "RAW FRAME PREVIEW", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    y = code_block(sv, M, y, CW, [
        ("c0  00 0c 29 1b 02 99   dest  ff:ff:ff:ff:ff:ff", TEXT_3),
        ("c6  3a f1 09 22 c4 de   src   3a:f1:09:22:c4:de", TEXT_3),
        ("cc  00 00 00 00 00 00   bssid 2c:30:33:8f:12:04", TEXT_3),
        ("cc  a4 83 e7 1b 02 99   sa   a4:83:e7:1b:02:99", TEXT_3),
        ("d0  07 00 00 00 00 00 00 07  type  deauth(12)", CYAN),
        ("6c  00 00 00 00 00 00 00 00  seq  0x012c", CYAN),
        ("0c  00 00 00 00 00 00 00 00  reason 7", CYAN),
        ("00  00 00 00 00 00 00 00  pad", TEXT_3),
        ("len 64 bytes · FCS ok · 802.11 mgmt", GREEN),
    ], lh=16)

    y += 22
    half = (CW - 10) / 2
    button(sv, M, y, half, 48, "Inject 1", "tinted", MINT, "play")
    button(sv, M + half + 10, y, half, 48, "Flood", "filled", MINT, "bolt")
    y += 60
    button(sv, M, y - 4, CW, 48, "Save template to /sdcard/Packets", "gray", "folder")
    sv.save(f"{OUT}/11_forger.svg")


# =============================================================================
def s12_wifi():
    sv = frame("Wi-Fi Kill", active_tab=4, large=True, sub="monitor mode required")
    y = 126
    g = sv.grad([(0, "#2E2A0E", None), (1, "#0E0D08", None)], gid="wk")
    sv.rect(M, y, CW, 112, f"url(#{g})", r=R_LARGE)
    sv.rect(M, y, CW, 112, "none", r=R_LARGE, stroke=YELLOW, sw=1, op=0.5)
    draw_sf(sv, "wifi_slash", M + 40, y + 42, 30, YELLOW, 2.2)
    sv.st(M + 76, y + 38, "NOT IN MONITOR MODE", (12, "600", 0.5), fill=YELLOW)
    sv.st(M + 76, y + 58, "wlan0 · managed mode", ST_FOOTNOTE, fill=TEXT_2)
    button(sv, M + 20, y + 72, CW - 40, 30, "Switch to monitor mode", "tinted",
           YELLOW)
    y += 130

    rows = [row(icon="antenna", tint=YELLOW, title="Interface", h=42,
                accessory="chevron", value="wlan0", mono_value=True),
            row(icon="wifi", tint=YELLOW, title="Channel", h=42,
                accessory="chevron", value="auto hop", mono_value=True),
            row(icon="list", tint=YELLOW, title="Frame type", h=42,
                accessory="chevron", value="deauth + auth"),
            row(icon="clock", tint=YELLOW, title="Interval", h=42,
                accessory="chevron", value="10 ms", mono_value=True)]
    y = group(sv, M, y, CW, rows, title="Radio")

    y += 16
    sv.st(M, y, "NETWORKS IN RANGE", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    nets = [("FLOOR-5G", "a1:b2:c3:d4:e5:f6", 6, -52, "WPA2", GREEN),
            ("Rumah-2.4G", "00:11:22:33:44:55", 1, -67, "WPA2", GREEN),
            ("FreeWiFi_Guest", "9f:8e:7d:6c:5b:4a", 11, -78, "OPEN", ORANGE),
            ("H3C-Office", "de:ad:be:ef:00:11", 6, -60, "WPA3", BLUE)]
    for ssid, bssid, ch, rssi, enc, col in nets:
        sv.rect(M, y, CW, 54, BG_CARD, r=R_CARD)
        sv.rect(M + 14, y + 17, 20, 20, col, r=6, op=0.22)
        draw_sf(sv, "wifi", M + 24, y + 27, 13, col, 1.5)
        sv.st(M + 46, y + 25, ssid, ST_SUBHEAD, fill=TEXT)
        sv.mono(M + 46, y + 41, bssid, 10, fill=TEXT_3)
        bars = int((rssi + 90) / 18) + 1
        for b in range(4):
            hgt = 5 + b * 3.5
            col2 = col if b < bars else FILL
            sv.rect(M + CW - 116 + b * 7, y + 33 - hgt, 4.5, hgt, col2, r=1.5)
        sv.st(M + CW - 14, y + 25, enc, (10, "600", 0.4), fill=col, anchor="end")
        sv.st(M + CW - 14, y + 41, f"ch {ch}", ST_CAPTION_2, fill=TEXT_3,
              anchor="end")
        y += 60
    y += 6
    button(sv, M, y, CW, 50, "Deauth Selected", "filled", YELLOW, "wifi_slash")
    sv.save(f"{OUT}/12_wifi.svg")


# =============================================================================
def s13_logs():
    sv = frame("Activity Log", active_tab=3, large=True,
               trailing="Export", sub="buffered · 4,182 events")
    y = 126
    rows = [row(icon="check", tint=GREEN, title="Only", h=38, accessory="none"),
            row(icon="exclamation", tint=ORANGE, title="Warnings + errors", h=38,
                accessory="switch", on_tap=True),
            row(icon="list", tint=BLUE, title="Verbose", h=38, accessory="switch",
                on_tap=False)]
    y = group(sv, M, y, CW, rows, title="Filter")

    y += 20
    sv.st(M, y, "LIVE STREAM", ST_CAPTION_2, fill=TEXT_2, ls=0.8)
    y += 12
    logs = [("14:02:11.482", "SCAN", "swept 254 hosts · 9 alive", BLUE),
            ("14:02:11.509", "SCAN", "192.168.1.1 open ports 9", BLUE),
            ("14:02:11.610", "FINGER", "ssh → OpenSSH 8.4p1", TEAL),
            ("14:02:12.044", "CVE", "CVE-2023-1389 matched · CVSS 9.8", RED),
            ("14:02:12.301", "AUTH", "telnet admin → ACCEPTED", ORANGE),
            ("14:02:12.318", "AUTH", "telnet root → ACCEPTED", ORANGE),
            ("14:02:12.560", "MITM", "arp poison 3 hosts · 5s", PINK),
            ("14:02:13.001", "RAW", "AF_PACKET socket opened", PURPLE),
            ("14:02:14.220", "WARN", "channel 6 busy, retrying", ORANGE),
            ("14:02:15.730", "CVE", "CVE-2021-43565 matched · CVSS 8.1", RED),
            ("14:02:16.902", "SCAN", "192.168.1.77 open ports 4", BLUE),
            ("14:02:17.455", "FINGER", "smb → Samba 4.11.12", TEAL)]
    for t, tag, msg, col in logs:
        sv.mono(M + 2, y + 12, t, 10, fill=TEXT_3)
        sv.rect(M + 66, y + 3, 44, 15, col, r=7.5, op=0.20)
        sv.st(M + 88, y + 14, tag, (9, "700", 0.4), fill=col, anchor="middle")
        sv.st(M + 118, y + 14, msg, (11.5, "400", 0), fill=TEXT_2)
        y += 26
    y += 6
    sv.save(f"{OUT}/13_logs.svg")


if __name__ == "__main__":
    s01_splash(); s02_root(); s03_network(); s04_target(); s05_portscan()
    s06_service(); s07_exploit(); s08_login(); s09_sessions(); s10_mitm()
    s11_forger(); s12_wifi(); s13_logs()
    print("screens ->", OUT)
    for f in sorted(os.listdir(OUT)):
        print("  ", f)
