"""ZEROSPLOIT — Apple-style (iOS 17/18) design tokens.

Design canvas is authored in REAL iOS points (393 x 852 @ iPhone 15/16 Pro).
PNG export is done at 1x/2x/3x by Inkscape, so nothing is guessed.
"""

# ---- canvas (iPhone 15/16 Pro logical points) -------------------------------
W, H = 393, 852

# safe areas / chrome metrics (iOS HIG)
SA_TOP = 59          # dynamic island
SA_BOTTOM = 34       # home indicator
STATUS_H = SA_TOP
NAV_H = 44           # compact nav bar
TABBAR_H = 49        # standard tab bar
HOME_IND = 5         # home indicator pill width-ish

CONTENT_TOP = SA_TOP + NAV_H          # 103
CONTENT_BOTTOM = H - TABBAR_H - SA_BOTTOM  # 769

# ---- corner radii (continuous / squircle feel) -------------------------------
R_CARD = 18
R_LARGE = 24
R_SHEET = 28
R_CONTROL = 12
R_PILL = 999

# ---- iOS system colors (dark) -----------------------------------------------
BG              = "#000000"                 # systemBackground
BG_ELEV         = "#1C1C1E"                 # secondarySystemBackground
BG_ELEV_2       = "#2C2C2E"                 # tertiarySystemBackground
BG_CARD         = "#1C1C1E"                 # secondarySystemGroupedBackground
BG_SECTION      = "#141416"
FILL            = "rgba(120,120,128,0.24)"  # systemFill
FILL_2          = "rgba(120,120,128,0.16)"
FILL_3          = "rgba(118,118,128,0.12)"
SEPARATOR       = "rgba(84,84,88,0.65)"
HAIRLINE        = "rgba(84,84,88,0.45)"
HIGHLIGHT       = "rgba(120,120,128,0.16)"

TEXT            = "#FFFFFF"                 # label
TEXT_2          = "rgba(235,235,245,0.60)"  # secondaryLabel
TEXT_3          = "rgba(235,235,245,0.30)"  # tertiaryLabel
TEXT_4          = "rgba(235,235,245,0.18)"

# system tints
BLUE      = "#0A84FF"
GREEN     = "#30D158"
INDIGO    = "#5E5CE6"
ORANGE    = "#FF9F0A"
PINK      = "#FF375F"
PURPLE    = "#BF5AF2"
RED       = "#FF453A"
TEAL      = "#40C8E0"
YELLOW    = "#FFD60A"
MINT      = "#63E6E2"
CYAN      = "#64D2FF"
BROWN     = "#AC8E68"

TINT = BLUE

# ---- type --------------------------------------------------------------------
# SF Pro if present, else closest fallbacks. Monospace for all data/terminal.
FONT      = "'SF Pro Display','SF Pro Text',-apple-system,'Helvetica Neue',Inter,'Segoe UI',sans-serif"
FONT_MONO = "'SF Mono',ui-monospace,'SF Mono Text',Menlo,'Roboto Mono','DejaVu Sans Mono',monospace"

# iOS text styles: (size, weight, tracking)
ST_LARGE_TITLE = (34, "700", -0.4)
ST_TITLE_1     = (28, "700", -0.3)
ST_TITLE_2     = (22, "700", -0.26)
ST_TITLE_3     = (20, "600", -0.24)
ST_HEADLINE    = (17, "600", -0.41)
ST_BODY        = (17, "400", -0.41)
ST_CALL_OUT    = (16, "400", -0.32)
ST_SUBHEAD     = (15, "400", -0.24)
ST_FOOTNOTE    = (13, "400", -0.08)
ST_CAPTION_1   = (12, "400", 0)
ST_CAPTION_2   = (11, "400", 0.06)
ST_MONO        = (13, "400", 0)
ST_MONO_SM     = (11, "400", 0.2)
ST_MONO_LG     = (15, "500", 0.2)

# ---- modules -----------------------------------------------------------------
MODULES = [
    ("portscan", "Port Scanner",   BLUE),
    ("trace",     "Traceroute",     INDIGO),
    ("service",  "Service Inspect", TEAL),
    ("exploit",  "Exploit Finder", RED),
    ("login",    "Login Auditor",  ORANGE),
    ("sessions", "Sessions",       PURPLE),
    ("mitm",     "MITM",           PINK),
    ("sniffer",  "Password Sniffer", PURPLE),
    ("dns",      "DNS Spoofing",   BROWN),
    ("hijack",   "Hijacker",       CYAN),
    ("forger",   "Packet Forger",  MINT),
    ("wifi",     "Wi-Fi Kill",     YELLOW),
]
MODULE_MAP = {m[0]: m for m in MODULES}
