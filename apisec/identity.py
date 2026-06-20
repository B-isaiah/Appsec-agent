"""
apisec/identity.py
Handles ALL forms of authentication:
JWT Bearer, cookies, CSRF tokens, API keys, .NET Core sessions,
Basic auth, client credentials, custom headers -- anything.

Extracts automatically from Burp XML, or accepts manual paste.
"""

import re
import base64
import json
from urllib.parse import urlparse
from typing import Optional
from xml.etree import ElementTree as ET

from .term import CHECK, CROSS, ELLIPS


# -- Known auth-bearing header names ------------------------------
AUTH_HEADERS = {
    "authorization", "x-api-key", "api-key", "x-auth-token",
    "x-access-token", "x-csrf-token", "x-xsrf-token",
    "requestverificationtoken", "__requestverificationtoken",
    "x-client-id", "x-client-secret", "x-app-id", "x-app-key",
    "x-user-id", "x-tenant-id", "x-account-id",
    "x-amz-security-token", "x-amz-date",
}

# -- Known auth-bearing cookie names ------------------------------
AUTH_COOKIES = {
    ".aspnetcore.antiforgery", ".aspnetcore.session",
    ".aspnetcore.identity", "aspnet.applicationcookie",
    "session", "sessionid", "sess", "auth", "token",
    "access_token", "jwt", "remember_me", "jsessionid",
    "phpsessid", "connect.sid", "rack.session",
    "csrf_token", "xsrf-token",
}

# -- Headers that are never auth-related --------------------------
SKIP_HEADERS = {
    "host", "content-type", "accept", "user-agent",
    "accept-encoding", "accept-language", "connection",
    "content-length", "cache-control", "pragma",
    "upgrade-insecure-requests", "sec-fetch-site",
    "sec-fetch-mode", "sec-fetch-dest", "referer",
}


class Identity:
    """
    One account's complete auth material.
    Carries headers + cookies regardless of auth mechanism.
    """
    def __init__(self, label: str):
        self.label     = label
        self.headers   : dict[str, str] = {}
        self.cookies   : dict[str, str] = {}
        self.auth_type : str = "none"

    def is_authenticated(self) -> bool:
        return bool(self.headers or self.cookies)

    def merge_into(self, base_headers: dict) -> dict:
        """Merge identity headers on top of base headers."""
        merged = {**base_headers}
        merged.update(self.headers)
        return merged

    def summary(self) -> str:
        parts = []
        if self.headers:
            parts.append(f"headers={list(self.headers.keys())}")
        if self.cookies:
            parts.append(f"cookies={list(self.cookies.keys())}")
        return f"[{self.label}] {self.auth_type} | {', '.join(parts) or 'unauthenticated'}"


def _parse_raw_request(raw: str) -> tuple[dict, dict]:
    """Extract auth headers + cookies from raw HTTP request text."""
    headers, cookies = {}, {}
    lines = raw.replace("\r\n", "\n").split("\n")

    for line in lines[1:]:          # skip request line
        if line.strip() == "":
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name  = name.strip()
        value = value.strip()
        name_lower = name.lower()

        if name_lower in SKIP_HEADERS:
            continue

        if name_lower == "cookie":
            for part in value.split(";"):
                part = part.strip()
                if "=" not in part:
                    continue
                cn, _, cv = part.partition("=")
                cn_lower = cn.strip().lower()
                if cn_lower in AUTH_COOKIES:
                    cookies[cn.strip()] = cv.strip()
        elif name_lower in AUTH_HEADERS:
            headers[name] = value

    return headers, cookies


def _detect_auth_type(headers: dict, cookies: dict) -> str:
    types = []
    for k, v in headers.items():
        kl = k.lower()
        if kl == "authorization":
            types.append("JWT/Bearer" if v.lower().startswith("bearer") else "Basic" if v.lower().startswith("basic") else "Authorization")
        elif kl in ("x-api-key", "api-key"):
            types.append("API Key")
        elif "csrf" in kl or "xsrf" in kl or "verification" in kl:
            types.append("CSRF Token")
        elif kl.startswith("x-client"):
            types.append("Client Credentials")
        else:
            types.append(f"Custom({k})")
    for k in cookies:
        kl = k.lower()
        if "aspnetcore" in kl:
            types.append(".NET Core Cookie")
        elif "session" in kl or "sess" in kl:
            types.append("Session Cookie")
        elif "csrf" in kl or "xsrf" in kl:
            types.append("CSRF Cookie")
        elif "jwt" in kl or "token" in kl:
            types.append("Token Cookie")
        else:
            types.append(f"Cookie({k})")
    return " + ".join(dict.fromkeys(types)) if types else "none"


def from_burp(xml_path: str, label: str, base_url: str) -> Identity:
    """
    Extract the richest auth identity found in a Burp XML export.
    Scores each request by number of auth signals and picks the best.
    """
    identity    = Identity(label)
    best_score  = 0
    best_h, best_c = {}, {}
    base_host   = urlparse(base_url).netloc

    try:
        root = ET.parse(xml_path).getroot()
    except Exception as e:
        print(f"  [identity] Burp parse error: {e}")
        return identity

    for item in root.findall(".//item"):
        try:
            url_el = item.find("url")
            if url_el is None or not url_el.text:
                continue
            if base_host and urlparse(url_el.text.strip()).netloc != base_host:
                continue

            req_el = item.find("request")
            if req_el is None or not req_el.text:
                continue

            enc = req_el.get("base64", "false") == "true"
            raw = (base64.b64decode(req_el.text).decode("utf-8", errors="replace")
                   if enc else req_el.text)

            h, c  = _parse_raw_request(raw)
            score = len(h) * 2 + len(c)
            if score > best_score:
                best_score = score
                best_h, best_c = h, c
        except Exception:
            continue

    identity.headers   = best_h
    identity.cookies   = best_c
    identity.auth_type = _detect_auth_type(best_h, best_c)
    return identity


def from_manual(label: str, raw_input: str) -> Identity:
    """
    Parse identity from a manually pasted block. Accepts:
      - Raw HTTP headers  (paste from Burp Inspector)
      - JSON object       {"headers":{...}, "cookies":{...}}
      - curl -H style     'Authorization: Bearer eyJ...'
    """
    identity = Identity(label)
    raw = raw_input.strip()
    if not raw:
        return identity

    # Try JSON
    try:
        data = json.loads(raw)
        identity.headers   = data.get("headers", {})
        identity.cookies   = data.get("cookies", {})
        identity.auth_type = _detect_auth_type(identity.headers, identity.cookies)
        return identity
    except json.JSONDecodeError:
        pass

    # Try raw HTTP headers
    h, c = _parse_raw_request("GET / HTTP/1.1\n" + raw)

    # Also catch any non-skip header the user pasted
    for line in raw.split("\n"):
        line = line.strip().strip("'\"")
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name_l = name.strip().lower()
        if name_l not in SKIP_HEADERS and name_l != "cookie":
            h[name.strip()] = value.strip()

    identity.headers   = h
    identity.cookies   = c
    identity.auth_type = _detect_auth_type(h, c)
    return identity


def build(
    label: str,
    burp_path: Optional[str],
    base_url: str,
    manual: Optional[str] = None,
) -> Identity:
    """
    Build one identity. Burp is the base, manual overrides specific keys.
    Prints a summary to terminal.
    """
    identity = Identity(label)

    if burp_path:
        burp_id = from_burp(burp_path, label, base_url)
        if burp_id.is_authenticated():
            identity.headers.update(burp_id.headers)
            identity.cookies.update(burp_id.cookies)
            identity.auth_type = burp_id.auth_type

    if manual:
        manual_id = from_manual(label, manual)
        if manual_id.is_authenticated():
            identity.headers.update(manual_id.headers)   # manual overrides burp
            identity.cookies.update(manual_id.cookies)
            identity.auth_type = _detect_auth_type(identity.headers, identity.cookies)

    # Print what we found
    tag = CHECK if identity.is_authenticated() else CROSS
    print(f"  {tag} {label.upper():8} {identity.auth_type}")
    for k, v in identity.headers.items():
        print(f"           header  {k}: {v[:55]}{'...' if len(v) > 55 else ''}")
    for k, v in identity.cookies.items():
        print(f"           cookie  {k}={v[:40]}{'...' if len(v) > 40 else ''}")

    return identity
