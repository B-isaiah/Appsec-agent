"""
apisec/screenshot.py
Screenshot capture using Playwright (headless Chromium).
Takes screenshots of endpoints during recon and findings during exploitation.
"""

import os
import sys
import hashlib
from datetime import datetime
from typing import Optional

from .term import CHECK, CROSS

DIM = "\033[2m"
RS = "\033[0m"

SCREENSHOT_DIR = "screenshots"


def _ensure_dir():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)


def _sanitize_filename(url: str, label: str = "") -> str:
    h = hashlib.md5(url.encode()).hexdigest()[:8]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = label.replace(" ", "_").replace("/", "_") if label else "shot"
    return f"{ts}_{name}_{h}.png"


def capture(
    url: str,
    label: str = "",
    timeout: int = 15000,
    full_page: bool = True,
) -> Optional[str]:
    """
    Take a screenshot of the given URL using Playwright.
    Returns the file path if successful, None otherwise.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(f"  {DIM}Install playwright: pip install playwright && playwright install chromium{RS}")
        return None

    _ensure_dir()
    filename = _sanitize_filename(url, label)
    filepath = os.path.join(SCREENSHOT_DIR, filename)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(
                viewport={"width": 1280, "height": 720},
                user_agent="APISec-Agent/1.0",
            )
            try:
                page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                page.screenshot(path=filepath, full_page=full_page)
                browser.close()
                return filepath
            except Exception as e:
                browser.close()
                # Try screenshot even if page timed out
                try:
                    with sync_playwright() as p2:
                        b2 = p2.chromium.launch(headless=True)
                        p2_page = b2.new_page(viewport={"width": 1280, "height": 720})
                        p2_page.goto(url, timeout=timeout, wait_until="commit")
                        p2_page.screenshot(path=filepath, full_page=False)
                        b2.close()
                        return filepath
                except Exception:
                    return None
    except Exception as e:
        print(f"  {DIM}Screenshot error: {e}{RS}")
        return None


def capture_endpoints(
    endpoints: list[dict],
    auth_headers: Optional[dict] = None,
    auth_cookies: Optional[dict] = None,
) -> list[str]:
    """Take screenshots of discovered endpoints."""
    paths = []
    for ep in endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        method = ep.get("method", "GET")
        path = ep.get("path", "/")
        print(f"  {DIM}Screenshotting {method} {path}...{RS}", end="", flush=True)
        fp = capture(url, label=f"{method}_{path.strip('/')}")
        if fp:
            print(f" {CHECK}")
            paths.append(fp)
        else:
            print(f" {CROSS}")
    return paths


def capture_findings(
    findings: list[dict],
    base_url: str,
) -> list[str]:
    """Take screenshots of URLs associated with findings."""
    paths = []
    seen = set()
    for f in findings:
        url = f.get("url", "")
        if not url or url in seen:
            continue
        seen.add(url)
        title = f.get("title") or f.get("finding", "finding")
        print(f"  {DIM}Screenshotting finding: {title[:50]}...{RS}", end="", flush=True)
        fp = capture(url, label=f"finding_{title[:30]}")
        if fp:
            print(f" {CHECK}")
            paths.append(fp)
        else:
            print(f" {CROSS}")
    return paths
