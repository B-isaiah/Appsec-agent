"""
apisec/login.py
Browser-based login using Playwright.
Alternative to Burp XML exports -- just give it creds and it logs in like a human,
then feeds the full auth context (cookies, tokens, localStorage) into the Identity system.

Usage:
    python run.py scan https://target.com \\
      --login https://target.com/login \\
      --login-user admin@test.com \\
      --login-pass "secret123"
"""

import re
import json
from typing import Optional

from .identity import Identity

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


def browser_login(
    login_url: str,
    username: str,
    password: str,
    username_field: str = "input[name=email], input[name=username], input[name=login], input[type=email], input#email, input#username, input#login, input#user_login",
    password_field: str = "input[name=password], input[type=password], input#password, input#pass, input#user_pass",
    submit_field: str = "button[type=submit], input[type=submit], button:has-text('Login'), button:has-text('Sign in'), button:has-text('Log in')",
    otp: Optional[str] = None,
    otp_field: str = "input[name=otp], input[name=totp], input[name=code], input[name=mfa], input#otp, input#totp, input#mfa-code",
    timeout: int = 15000,
) -> Optional[Identity]:
    """
    Launch headless Chromium, log in, extract full auth context.

    Returns an Identity with cookies, headers, localStorage.
    Returns None on failure with details printed.
    """
    if not PLAYWRIGHT_AVAILABLE:
        print("  \033[91mX Playwright not installed. Run: pip install playwright && playwright install chromium\033[0m")
        return None

    identity = Identity("browser")
    print(f"\n  \033[1m[BROWSER LOGIN]\033[0m {login_url}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
            )
            page = context.new_page()

            # Monitor network requests for auth headers
            auth_headers = {}

            def on_request(request):
                headers = request.headers
                for h, v in headers.items():
                    hl = h.lower()
                    if hl.startswith("authorization") or hl.startswith("x-api-key") or hl.startswith("x-auth"):
                        auth_headers[h] = v
                    elif hl == "cookie":
                        # Capture any auth cookies set by the page
                        pass

            page.on("request", on_request)

            # Navigate to login
            print(f"  Navigating to {login_url}...")
            page.goto(login_url, wait_until="networkidle", timeout=timeout)

            # Detect and fill username
            username_el = page.query_selector(username_field)
            if not username_el:
                # Try finding any email/text input
                username_el = page.query_selector("input[type=email]") or page.query_selector("input[type=text]")
            if username_el:
                username_el.fill(username)
                print(f"  Filled username")
            else:
                print(f"  \033[93m! Could not find username field\033[0m")

            # Detect and fill password
            password_el = page.query_selector(password_field)
            if password_el:
                password_el.fill(password)
                print(f"  Filled password")
            else:
                print(f"  \033[93m! Could not find password field\033[0m")

            # Click submit
            submit_el = page.query_selector(submit_field)
            if submit_el:
                submit_el.click()
                print(f"  Submitted login form")
            else:
                # Maybe it's a div/button without type
                submit_el = page.query_selector("button:has-text('Log'), button:has-text('Sign'), button:has-text('Continue'), [type=submit]")
                if submit_el:
                    submit_el.click()
                    print(f"  Submitted login form (fallback)")
                else:
                    print(f"  \033[93m! Could not find submit button\033[0m")
                    page.screenshot(path="login_failed.png")
                    print(f"  Screenshot saved to login_failed.png")

            # Handle OTP if provided
            if otp:
                try:
                    page.wait_for_selector(otp_field, timeout=5000)
                    otp_el = page.query_selector(otp_field)
                    if otp_el:
                        otp_el.fill(otp)
                        print(f"  Filled OTP")
                        submit_el = page.query_selector(submit_field)
                        if submit_el:
                            submit_el.click()
                except Exception:
                    print(f"  No OTP prompt detected")

            # Wait for post-login page (dashboard redirect, or URL change)
            try:
                page.wait_for_url(lambda url: url != login_url, timeout=timeout)
                print(f"  Redirected to {page.url}")
            except Exception:
                print(f"  \033[93m! No redirect detected, trying to capture state anyway\033[0m")

            # Wait a moment for async auth to complete
            page.wait_for_timeout(2000)

            # -- Extract cookies --
            cookies = context.cookies()
            cookie_dict = {}
            for c in cookies:
                name = c.get("name", "")
                value = c.get("value", "")
                if name.lower() in ("session", "sessionid", "token", "jwt", "auth",
                                    "connect.sid", "phpsessid", "asp.net.sessionid",
                                    ".aspnetcore.session", ".aspnetcore.antiforgery"):
                    cookie_dict[name] = value
                elif any(k in name.lower() for k in ("auth", "token", "session", "jwt", "sess")):
                    cookie_dict[name] = value
            if cookie_dict:
                identity.cookies = cookie_dict
                print(f"  Extracted {len(cookie_dict)} auth cookies")

            # -- Extract localStorage --
            try:
                ls = page.evaluate("() => JSON.stringify(window.localStorage)")
                ls_data = json.loads(ls) if ls else {}
                for k, v in ls_data.items():
                    kl = k.lower()
                    if any(x in kl for x in ("token", "jwt", "auth", "session", "credential", "access", "refresh")):
                        identity.headers[f"X-LocalStorage-{k}"] = str(v)[:200]
                if ls_data:
                    print(f"  Scanned localStorage ({len(ls_data)} keys)")
            except Exception:
                pass

            # -- Extract sessionStorage --
            try:
                ss = page.evaluate("() => JSON.stringify(window.sessionStorage)")
                ss_data = json.loads(ss) if ss else {}
                for k, v in ss_data.items():
                    kl = k.lower()
                    if any(x in kl for x in ("token", "jwt", "auth", "session", "credential", "access", "refresh")):
                        identity.headers[f"X-SessionStorage-{k}"] = str(v)[:200]
            except Exception:
                pass

            # -- Extract auth headers captured from network --
            for h, v in auth_headers.items():
                identity.headers[h] = v
            if auth_headers:
                print(f"  Captured {len(auth_headers)} auth headers from network")

            # -- Try to read auth token from page context (common JS frameworks) --
            try:
                token = page.evaluate("() => window.__NEXT_DATA__?.props?.pageProps?.accessToken || ''")
                if token:
                    identity.headers["Authorization"] = f"Bearer {token}"
                    print(f"  Found Next.js auth token")
            except Exception:
                pass
            try:
                token = page.evaluate("() => window.__NUXT__?.state?.auth?.accessToken || window.__NUXT__?.state?.user?.token || ''")
                if token:
                    identity.headers["Authorization"] = f"Bearer {token}"
                    print(f"  Found Nuxt.js auth token")
            except Exception:
                pass

            # -- Take success screenshot for reference --
            try:
                page.screenshot(path="login_success.png")
                print(f"  Screenshot saved to login_success.png")
            except Exception:
                pass

            # -- Set auth_type --
            auth_types = []
            if identity.headers:
                for k in identity.headers:
                    kl = k.lower()
                    if "authorization" in kl:
                        auth_types.append("JWT/Bearer" if "bearer" in str(identity.headers[k]).lower() else "Authorization")
                    elif "api-key" in kl or "x-api-key" in kl:
                        auth_types.append("API Key")
                    elif "x-auth" in kl:
                        auth_types.append("Custom Auth Header")
            if identity.cookies:
                auth_types.append("Session Cookie")
            identity.auth_type = " + ".join(dict.fromkeys(auth_types)) if auth_types else "browser-login"

            browser.close()

            if identity.is_authenticated():
                print(f"  \033[92mv Login successful\033[0m")
                return identity
            else:
                print(f"  \033[93m! Page loaded but no auth tokens found.\033[0m")
                print(f"  \033[93m  The identity will be unauthenticated.\033[0m")
                return identity

    except Exception as e:
        print(f"  \033[91mX Browser login failed: {e}\033[0m")
        return None
