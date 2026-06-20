"""
apisec/term.py
Terminal-aware symbols -- uses Unicode on capable terminals,
falls back to ASCII on Windows codepages that don't support it.
"""

import sys

_UNICODE = bool(sys.stdout.encoding) and sys.stdout.encoding.upper() in (
    "UTF-8", "UTF8", "UTF-16", "UTF-32",
)


def _s(uni, asc):
    return uni if _UNICODE else asc


CHECK  = _s("\u2713", "v")
CROSS  = _s("\u2717", "X")
WARN   = _s("\u26a0", "!")
FLAG   = _s("\u2691", "*")
DASH   = _s("\u2500", "-")
ARROW  = _s("\u2192", "->")
BULLET = _s("\u25cf", "*")
EMDASH = _s("\u2014", "--")
ELLIPS = _s("\u2026", "...")
BOX_H  = _s("\u2500", "=")
BOX_V  = _s("\u2502", "|")
CORNER = _s("\u2514", "+")
