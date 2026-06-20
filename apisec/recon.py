"""
apisec/recon.py
Pre-scan reconnaissance. Discovers endpoints, technology stack,
subdomains, historical URLs, and configuration files.
Called automatically before the agent runs.
"""

import re
import json
import subprocess
import shutil
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .graphql import probe_graphql, format_schema_context, attack_guide as graphql_attack_guide, PING_QUERY
from .term import CHECK, CROSS, WARN, BULLET, DASH, BOX_H, EMDASH, ARROW


# -- Recon suggestions engine ---------------------------------------
def recon_suggestions(report: dict):
    """Print contextual suggestions based on recon findings."""
    tips = []

    if report.get("graphql") and report["graphql"].get("is_graphql"):
        g = report["graphql"]
        if g.get("introspection"):
            tips.append("GraphQL introspection is open. Dump the full schema, look for mutations without auth.")
        if g.get("suggestions"):
            tips.append("GraphQL suggestions mode is on (debug). Try field-name brute force to reconstruct schema.")
        if g.get("schema"):
            q = len(g["schema"].get("queries", []))
            m = len(g["schema"].get("mutations", []))
            if m == 0:
                tips.append("No mutations found by introspection -- test mutations anyway (some hide behind role checks).")
            tips.append(f"GraphQL has {q} queries and {m} mutations. Probe each for auth bypass and IDOR.")
        tips.append("Try batching: send multiple GraphQL queries in one request via [{\"query\":...},...]")
        tips.append("Test GET-based GraphQL: curl -G \"$URL\" --data-urlencode \"query={__typename}\"")

    tech = report.get("tech_stack", [])
    if "GraphQL" in tech:
        tips.append("GraphQL tech detected beyond /graphql path -- look for custom endpoints too.")

    leaks = report.get("data_leaks", [])
    leak_types = set(l["type"] for l in leaks)
    for lt in leak_types:
        if "Key" in lt or "Token" in lt or "Secret" in lt:
            tips.append(f"{lt} exposed! Try using it against discovered endpoints. Test permissions.")
        elif "JWT" in lt:
            tips.append("JWT found. Decode at jwt.io. Check 'none' algorithm, 'kid' injection, weak secret.")
        elif "Internal" in lt or "Stack" in lt:
            tips.append(f"{lt} visible. Use this info for deeper targeting (internal IPs, error details).")
        elif "Email" in lt:
            tips.append("Email addresses exposed. Try as user IDs for enumeration.")

    cors = report.get("cors_issues", [])
    if cors:
        tips.append(f"{len(cors)} CORS misconfigs allow null/wildcard origin. Craft a cross-origin PoC to test.")

    missing = report.get("missing_headers", [])
    if missing:
        names = set(h["header"] for h in missing)
        if "strict-transport-security" in names:
            tips.append("HSTS missing. The site is vulnerable to SSL stripping attacks.")
        if "content-security-policy" in names:
            tips.append("CSP missing. XSS mitigation is absent -- test for stored/reflected XSS.")
        if "x-frame-options" in names:
            tips.append("Clickjacking protection missing. Test with a <frame> PoC.")

    if report.get("cors_issues") or report.get("missing_headers"):
        tips.append("Run a full security headers scan: https://securityheaders.com")

    wb = report.get("wayback_urls", [])
    if wb:
        tips.append(f"{len(wb)} historical endpoints from Wayback Machine. Check deprecated versions (v1, old routes).")

    subs = report.get("subdomains", [])
    if subs:
        tips.append(f"{len(subs)} subdomains found. Scan each with: python run.py scan https://<sub>")

    openapi_paths = [e for e in report.get("endpoints", []) if any(k in e.lower() for k in ["swagger", "openapi", "api-docs"])]
    if openapi_paths:
        tips.append("OpenAPI spec exposed. Download it and replay all documented endpoints.")

    if report.get("forms"):
        tips.append(f"{len(report['forms'])} forms found. Test for CSRF, mass assignment, and input injection.")

    if tips:
        print(f"\n  \033[1m\033[93m[SUGGESTIONS]\033[0m")
        for t in tips:
            print(f"  {ARROW} {t}")



# -- Tech stack signatures -----------------------------------------
TECH_SIGNATURES = {
    "ASP.NET":         [r"x-powered-by.*ASP\.NET", r"__requestverificationtoken", r".aspnetcore"],
    "nginx":           [r"server: nginx", r"x-powered-by.*nginx"],
    "Cloudflare":      [r"cf-ray", r"__cfduid", r"cloudflare"],
    "AWS/CloudFront":  [r"x-amz-", r"cloudfront", r"awsalbtarget"],
    "AWS/S3":          [r"x-amz-request-id", r"x-amz-id-2", r"s3.amazonaws"],
    "AWS/Lambda":      [r"x-amzn-requestid", r"x-amz-invocation-type"],
    "Java/Spring":     [r"x-application-context", r"actuator", r"javax\.faces", r"jsessionid"],
    "Python/Django":   [r"csrftoken", r"sessionid", r"django"],
    "Python/Flask":    [r"flask", r"werkzeug"],
    "Node/Express":    [r"x-powered-by.*express", r"connect\.sid"],
    "Ruby/Rails":      [r"rails", r"ruby", r"_session_id"],
    "PHP/Laravel":     [r"laravel", r"php_session", r"x-powered-by.*php"],
    "GraphQL":         [r"graphql", r"__graphql"],
    "WordPress":       [r"wp-content", r"wp-json", r"wp-admin"],
    "Kubernetes":      [r"k8s", r"kubernetes", r"eks", r"kubespray"],
    "Docker":          [r"docker-desktop", r"docker"],
    "GitHub Pages":    [r"github\.com", r"pages\.github"],
    "Fastly":          [r"x-fastly", r"fastly"],
    "Akamai":          [r"akamai", r"x-akamai"],
    "Azure/AppSvc":    [r"x-aspnet-version", r"x-powered-by.*azure", r"azurewebsites"],
    "Firebase":        [r"firebase", r"firebaseio\.com", r"firestore"],
    "Cloudflare Workers": [r"cf-workers", r"workers\.dev"],
    "Vercel":          [r"vercel", r"now\.sh"],
    "Netlify":         [r"netlify", r"x-nf-request-id"],
    "Heroku":          [r"heroku", r"herokuapp\.com"],
    "DigitalOcean":    [r"digitalocean", r"do-"],
    "Algolia":         [r"algolia", r"x-algolia"],
    "Auth0":           [r"auth0", r"webtask\.io"],
    "Okta":            [r"okta", r"oktacdn\.com"],
    "Cognito":         [r"cognito", r"amazoncognito"],
    "Stripe":          [r"stripe\.com", r"stripe\.network"],
    "PayPal":          [r"paypal", r"paypalobjects"],
    "NewRelic":        [r"newrelic", r"nr-data\.net"],
    "Datadog":         [r"datadog", r"dd-trace"],
    "Sentry":          [r"sentry\.io", r"raven-js", r"@sentry"],
    "Segment":         [r"segment\.com", r"cdn\.segment"],
    "Google Analytics": [r"google-analytics", r"googletagmanager", r"ga\.js", r"gtag"],
    "Facebook/Tracking": [r"facebook\.com.*tr\/", r"fbq\(", r"connect\.facebook"],
    "Hotjar":          [r"hotjar", r"static\.hotjar"],
    "Intercom":        [r"intercom", r"widget\.intercom"],
    "Zendesk":         [r"zendesk", r"zopim"],
    "Cloudinary":      [r"cloudinary\.com", r"res\.cloudinary"],
    "imgix":           [r"imgix\.net", r"ix-"],
    "Twilio":          [r"twilio", r"twilio\.com"],
    "SendGrid":        [r"sendgrid", r"sendgrid\.net"],
    "Mailchimp":       [r"mailchimp", r"list-manage\.com"],
    "jQuery/CDN":      [r"jquery", r"code\.jquery"],
    "Bootstrap":       [r"bootstrap", r"maxcdn\.bootstrapcdn"],
    "React":           [r"react\.js", r"react\.min", r"_next\/static"],
    "Vue":             [r"vue\.js", r"vue\.min", r"vue-router"],
    "Angular":         [r"angular\.js", r"angular\.min", r"ng-app"],
    "Next.js":         [r"_next\/static", r"__NEXT_DATA__"],
    "Nuxt.js":         [r"_nuxt\/", r"__NUXT__"],
    "Gatsby":          [r"gatsby", r"__GATSBY"],
    "jQuery":          [r"jquery", r"\$\.ajax"],
    "HTMX":            [r"htmx", r"hx-get", r"hx-post"],
    "Alpine.js":       [r"alpinejs", r"x-data"],
}

# -- Supply chain / third-party domain signatures ------------------
SUPPLY_CHAIN_DOMAINS = {
    "Google Analytics/Tag Manager":   ["googletagmanager.com", "google-analytics.com", "analytics.google.com"],
    "Google Ads/DoubleClick":         ["doubleclick.net", "googleadservices.com", "googlesyndication.com"],
    "Google Fonts":                   ["fonts.googleapis.com", "fonts.gstatic.com"],
    "Google reCAPTCHA":               ["google.com/recaptcha", "gstatic.com/recaptcha", "hcaptcha.com"],
    "Facebook Pixel":                 ["facebook.com/tr", "connect.facebook.net", "fbcdn.net"],
    "Twitter/X Widget":               ["platform.twitter.com", "twimg.com"],
    "LinkedIn Widget":                ["linkedin.com/analytics", "licdn.com"],
    "TikTok Pixel":                   ["tiktok.com/analytics", "tiktokcdn.com"],
    "Cloudflare CDN":                 ["cdnjs.cloudflare.com", "ajax.cloudflare.com"],
    "jsDelivr CDN":                   ["cdn.jsdelivr.net", "jsdelivr.net"],
    "UNPKG CDN":                      ["unpkg.com"],
    "cdnJS":                          ["cdnjs.com"],
    "Stripe":                         ["js.stripe.com", "m.stripe.network", "stripe.com"],
    "PayPal":                         ["paypal.com", "paypalobjects.com"],
    "Shopify":                        ["shopify.com", "shopifycdn.com", "myshopify.com"],
    "Sentry Error Tracking":          ["sentry.io", "browser.sentry-cdn.com", "dsn.sentry"],
    "Datadog RUM":                    ["datadoghq.com", "dd-trace"],
    "NewRelic":                       ["newrelic.com", "nr-data.net"],
    "Hotjar Analytics":               ["hotjar.com", "static.hotjar.com"],
    "FullStory Recording":            ["fullstory.com", "fullstory.net"],
    "Intercom Chat":                  ["intercom.io", "widget.intercom.io"],
    "Zendesk Chat":                   ["zopim.com", "zendesk.com"],
    "Drift Chat":                     ["drift.com", "drift.net"],
    "LiveChat":                       ["livechat.com", "livechatinc.com"],
    "Auth0":                          ["auth0.com", "auth0.net"],
    "Okta SSO":                       ["okta.com", "oktacdn.com"],
    "Amazon S3":                      ["s3.amazonaws.com", "s3.us-east", "s3-us-west"],
    "CloudFront CDN":                 ["cloudfront.net"],
    "Akamai CDN":                     ["akamaihd.net", "akamaized.net"],
    "Fastly CDN":                     ["fastly.net", "fastlylb.net"],
    "KeyCDN":                         ["kxcdn.com", "keycdn.com"],
    "BunnyCDN":                       ["bunnycdn.com", "b-cdn.net"],
    "Algolia Search":                 ["algolia.net", "algolianet.com"],
    "Mapbox":                         ["mapbox.com", "mapbox.net", "tiles.mapbox"],
    "Google Maps":                    ["maps.googleapis.com", "maps.gstatic.com"],
    "YouTube Embed":                  ["youtube.com/embed", "youtube-nocookie.com"],
    "Vimeo Embed":                    ["player.vimeo.com", "vimeocdn.com"],
    "Wistia Video":                   ["wistia.com", "wistia.net"],
    "Vidyard":                        ["vidyard.com", "vidyard.net"],
    "Typekit/Adobe Fonts":           ["use.typekit.net", "p.typekit.net"],
    "Cloudinary CDN":                 ["cloudinary.com", "res.cloudinary.com"],
    "imgix":                          ["imgix.net"],
    "Twilio":                         ["twilio.com", "twiliocdn.com"],
    "SendGrid":                       ["sendgrid.net", "sendgrid.com"],
    "Mailchimp":                      ["mailchimp.com", "list-manage.com"],
    "Disqus Comments":                ["disqus.com", "disquscdn.com"],
    "Medium Widget":                  ["medium.com", "cdn.medium.com"],
    "GitHub Pages":                   ["github.io", "pages.github.com"],
    "Netlify":                        ["netlify.app", "netlify.com"],
    "Vercel":                         ["vercel.app", "vercel.com"],
    "Heroku":                         ["herokuapp.com", "herokucdn.com"],
    "Cloudflare":                     ["cloudflare.com"],
}

# -- Security headers to audit -------------------------------------
REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security":       "HSTS missing -- allows downgrade attacks",
    "content-security-policy":        "CSP missing -- XSS mitigation absent",
    "x-frame-options":                "Clickjacking protection missing",
    "x-content-type-options":         "MIME-sniffing protection missing",
    "x-xss-protection":              "XSS filter not enabled",
    "referrer-policy":               "Referrer leakage not controlled",
    "permissions-policy":            "Feature permissions not restricted",
    "access-control-allow-origin":   "CORS may be open (check value)",
}

# -- Data leakage patterns ------------------------------------------
LEAK_PATTERNS = {
    "AWS Access Key":        r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":        r"(?i)aws(.{0,20})?(secret|secret_access|secretkey)[\"\'].{0,5}[\"\'][\'\"][A-Za-z0-9\/+=]{40}[\"\']",
    "Google API Key":        r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Key":      r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Slack Token":           r"xox[baprs]-[0-9a-zA-Z\-]{10,72}",
    "GitHub Token":          r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "GitHub Old Token":      r"[0-9a-f]{40}",
    "JWT Token":             r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+",
    "Private Key (PEM)":     r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Stripe API Key":        r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "Twilio API Key":        r"SK[0-9a-fA-F]{32}",
    "Heroku API Key":        r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Slack Webhook":         r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}",
    "S3 Bucket URL":         r"s3\.amazonaws\.com/[/\w\-\.]{3,}",
    "Internal IP":           r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    "Internal Hostname":     r"(?:localhost|internal|intranet|corp|dev|staging|admin-internal)\.[\w\-\.]+",
    "Debug Path":            r"/(?:debug|trace|swagger|api-docs|actuator|\.env|administrator|phpinfo)\.?(?:php|json|html)?$",
    "Database Connection":   r"(?:postgresql|mysql|mongodb|redis|jdbc|mssql)://[\w\-\.]+:\d+",
    "Elasticsearch":         r"elasticsearch.*:\d+|(?:9200|9300)",
    "Email Leak":            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "External IP":           r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Admin Email":           r"admin@[\w\-\.]+",
    "API Endpoint in Body":  r"https://[a-z][\w\-\.]+\.(?:com|io|net|org|app)/api/[\w\-/]+",
    "Stack Trace":           r"(?:Traceback|at\s+[\w\.]+\(|Stack trace|Exception in thread)",
    "SQL Error":             r"(?:SQL syntax|mysql_fetch|ORA-[0-9]{5}|MYSQL_ERROR|PostgreSQL.*ERROR)",
    "Internal Path":         r"(?:C:\\Users|/var/www|/home/|/root/|/etc/|D:\\[A-Za-z])",
}


def detect_tech(headers: dict, body: str = "") -> list[str]:
    """Detect technology stack from response headers and body."""
    combined = json.dumps(dict(headers)).lower() + " " + body.lower()
    found = []
    for tech, patterns in TECH_SIGNATURES.items():
        for p in patterns:
            if re.search(p, combined, re.I):
                found.append(tech)
                break
    return found


# -- Robots & Sitemap ----------------------------------------------
ROBOTS_ENDPOINTS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/rss.xml", "/sitemap/",
]

COMMON_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/api-docs", "/api-docs.json", "/.well-known/openapi", "/graphql",
    "/api/v1/auth/login", "/api/v1/auth/register",
    "/api/v1/login", "/api/v1/register", "/login", "/register",
    "/api/v1/users", "/api/v1/users/me", "/api/v1/profile",
    "/api/v1/users/1", "/api/v1/users/2", "/api/v1/users/3",
    "/api/v1/admin", "/api/v1/admin/users",
    "/api/v1/products", "/api/v1/orders", "/api/v1/orders/1",
    "/api/v1/payments", "/api/v1/accounts", "/api/v1/accounts/1",
    "/api/v1/settings", "/api/v1/config",
    "/health", "/healthz", "/ping", "/status", "/metrics",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/debug", "/.env", "/version",
    "/admin", "/administrator", "/backup", "/config",
    "/console", "/dashboard", "/docs", "/info",
    "/internal", "/manage", "/portal", "/private",
    "/staging", "/test", "/tmp", "/logs",
    "/ws", "/wss", "/socket.io", "/webhook",
    "/callback", "/notify", "/hook",
]

SUB_DOMAINS = [
    "api", "admin", "dev", "staging", "test", "uat",
    "beta", "v2", "v3", "api-dev", "api-staging",
    "api-admin", "portal", "dashboard", "internal",
    "graphql", "api-graphql", "docs", "developer",
    "sandbox", "demo", "app", "api-app",
]


def parse_robots(text: str) -> list[str]:
    """Extract allowed/disallowed paths from robots.txt."""
    paths = []
    for line in text.split("\n"):
        line = line.strip()
        for prefix in ("Allow: ", "Disallow: "):
            if line.lower().startswith(prefix.lower()):
                path = line[len(prefix):].strip()
                if path and not path.startswith("/"):
                    path = "/" + path
                if path:
                    paths.append(path)
    return paths


def parse_sitemap(text: str) -> list[str]:
    """Extract URLs from sitemap XML."""
    urls = re.findall(r"<loc>(.*?)</loc>", text, re.I)
    return [u.strip() for u in urls]


# -- Crawler --------------------------------------------------------
def crawl_page(url: str, client: httpx.Client) -> dict:
    """Crawl a single page for endpoints, forms, and JS references."""
    result = {"links": [], "forms": [], "api_calls": [], "scripts": []}
    try:
        r = client.get(url, timeout=10, follow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")

        # All links
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                full = urljoin(url, href)
                result["links"].append(full)

        # Forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            inputs = []
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if name:
                    inputs.append({"name": name, "type": inp.get("type", "text")})
            result["forms"].append({
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs,
            })

        # Inline JS for API calls
        for script in soup.find_all("script"):
            if script.string:
                apis = re.findall(
                    r'(?:fetch|axios|XMLHttpRequest|ajax|getJSON|\.get|\.post|\.put|\.delete)\s*\(?\s*["\']([^"\']+)["\']',
                    script.string, re.I)
                result["api_calls"].extend(apis)
            if script.get("src"):
                result["scripts"].append(urljoin(url, script["src"]))

        # Look for JSON-LD / meta data
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string)
                result["json_ld"] = data
            except: pass

    except Exception:
        pass
    return result


# -- Wayback Machine ------------------------------------------------
def wayback_urls(domain: str, limit: int = 100) -> list[str]:
    """Fetch historical URLs from the Wayback Machine."""
    urls = []
    try:
        r = httpx.get(
            f"https://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{domain}/*", "output": "json", "limit": limit,
                    "fl": "original", "collapse": "urlkey"},
            timeout=15,
        )
        if r.status_code == 200 and len(r.json()) > 1:
            urls = [row[0] for row in r.json()[1:] if row]
    except Exception:
        pass
    return urls


# -- Supply chain detection -----------------------------------------
def detect_supply_chain(soup: BeautifulSoup, html: str) -> list[dict]:
    """Detect third-party scripts, iframes, images, and fonts."""
    found = {}
    html_lower = html.lower()

    for service, domains in SUPPLY_CHAIN_DOMAINS.items():
        for d in domains:
            if d.lower() in html_lower:
                found[service] = found.get(service, 0) + 1
                break

    # Also check for subresource integrity hints
    results = []
    for svc, count in sorted(found.items(), key=lambda x: -x[1]):
        results.append({"service": svc, "detections": count})

    return results


# -- Security headers audit -----------------------------------------
def audit_security_headers(headers: dict) -> list[dict]:
    """Check which security headers are missing or misconfigured."""
    issues = []
    h_lower = {k.lower(): v for k, v in headers.items()}
    for header, msg in REQUIRED_SECURITY_HEADERS.items():
        if header not in h_lower:
            issues.append({"header": header, "issue": msg, "severity": "LOW"})
        elif header == "access-control-allow-origin" and h_lower[header] == "*":
            issues.append({"header": header, "issue": "CORS allows all origins (*)", "severity": "MEDIUM"})
        elif header == "strict-transport-security":
            val = h_lower[header]
            if "max-age=" in val:
                age = re.search(r"max-age=(\d+)", val)
                if age and int(age.group(1)) < 31536000:
                    issues.append({"header": header, "issue": f"HSTS max-age too short ({age.group(1)}s)", "severity": "LOW"})
            else:
                issues.append({"header": header, "issue": "HSTS missing max-age directive", "severity": "LOW"})
        elif header == "content-security-policy":
            val = h_lower[header]
            if "'unsafe-inline'" in val:
                issues.append({"header": header, "issue": "CSP allows unsafe-inline scripts", "severity": "MEDIUM"})
            if "'unsafe-eval'" in val:
                issues.append({"header": header, "issue": "CSP allows unsafe-eval", "severity": "MEDIUM"})
            if "default-src 'none'" not in val and "default-src 'self'" not in val:
                if "default-src" not in val:
                    issues.append({"header": header, "issue": "CSP has no default-src directive", "severity": "LOW"})
    return issues


# -- Data leakage scan ----------------------------------------------
def scan_data_leakage(body: str, url: str) -> list[dict]:
    """Scan response body for sensitive data exposure patterns."""
    leaks = []
    for label, pattern in LEAK_PATTERNS.items():
        matches = re.findall(pattern, body)
        if matches:
            for m in matches[:5]:
                # Filter out false positives for IP detection from JS libraries
                if label == "External IP" and m.startswith("0."):
                    continue
                if label == "Email Leak" and any(
                    x in m for x in ["example.com", "domain.com", "test.com", "@localhost"]
                ):
                    continue
                leaks.append({
                    "type": label,
                    "match": m[:60],
                    "url": url,
                    "severity": "HIGH" if "Key" in label or "Secret" in label or "Token" in label
                               else "MEDIUM" if "Internal" in label or "Stack" in label or "SQL" in label
                               else "LOW",
                })
    return leaks


# -- CORS Preflight -------------------------------------------------
def cors_check(url: str, origin: str, client: httpx.Client) -> dict:
    """Check CORS configuration with a specific origin."""
    try:
        r = client.options(url, headers={"Origin": origin, "Access-Control-Request-Method": "GET"})
        h = r.headers
        return {
            "url": url,
            "status": r.status_code,
            "allow_origin": h.get("access-control-allow-origin", ""),
            "allow_methods": h.get("access-control-allow-methods", ""),
            "allow_credentials": h.get("access-control-allow-credentials", ""),
            "expose_headers": h.get("access-control-expose-headers", ""),
            "wildcard": h.get("access-control-allow-origin", "") == "*",
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


# -- External tool integration ----------------------------------------
TOOL_MAP = {
    "subfinder": "github.com/projectdiscovery/subfinder",
    "httpx":     "github.com/projectdiscovery/httpx",
    "nuclei":    "github.com/projectdiscovery/nuclei",
    "katana":    "github.com/projectdiscovery/katana",
    "gau":       "github.com/lc/gau",
    "ffuf":      "github.com/ffuf/ffuf",
    "sqlmap":    "sqlmap.org",
    "dalfox":    "github.com/hahwul/dalfox",
    "naabu":     "github.com/projectdiscovery/naabu",
}

def tool_available(name: str) -> bool:
    """Check if an external tool is on PATH."""
    return shutil.which(name) is not None

def _run_cmd(cmd: list, timeout: int = 60) -> str:
    """Run a command, return stdout, or empty on error."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""

def subfinder_scan(domain: str) -> list[str]:
    """Find subdomains using subfinder."""
    out = _run_cmd(["subfinder", "-d", domain, "-silent"])
    subs = [s.strip() for s in out.strip().split("\n") if s.strip()]
    return list(set(subs))

def httpx_probe(urls: list[str]) -> list[str]:
    """Probe which URLs are alive using httpx."""
    if not urls:
        return []
    input_str = "\n".join(urls)
    try:
        r = subprocess.run(
            ["httpx", "-silent", "-status-code", "-content-type", "-title"],
            input=input_str, capture_output=True, text=True, timeout=120
        )
        alive = []
        for line in r.stdout.strip().split("\n"):
            if line.strip():
                url_part = line.strip().split()[0] if " " in line else line.strip()
                if url_part.startswith("http"):
                    alive.append(url_part)
        return list(set(alive))
    except Exception:
        return []

def nuclei_scan(targets: list[str], severity: str = "medium") -> list[dict]:
    """Run nuclei templates on targets."""
    results = []
    for target in targets[:10]:
        out = _run_cmd(
            ["nuclei", "-u", target, "-severity", severity,
             "-silent", "-json", "-timeout", "5"],
            timeout=120
        )
        for line in out.strip().split("\n"):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return results

def katana_crawl(base_url: str) -> list[str]:
    """Deep crawl with katana to discover endpoints."""
    out = _run_cmd(["katana", "-u", base_url, "-silent", "-d", "2",
                     "-kf", "all", "-jc", "-aff"], timeout=120)
    urls = [u.strip() for u in out.strip().split("\n") if u.strip() and u.startswith("http")]
    return list(set(urls))

def gau_urls(domain: str) -> list[str]:
    """Fetch historical URLs from gau (wayback + otx + commoncrawl)."""
    out = _run_cmd(["gau", "--subs", domain], timeout=90)
    urls = [u.strip() for u in out.strip().split("\n") if u.strip() and u.startswith("http")]
    return list(set(urls))

def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> list[dict]:
    """Fuzz a URL with ffuf to find hidden paths."""
    if not shutil.which("ffuf"):
        return []
    out = _run_cmd(
        ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
         "-fc", "404", "-s", "-t", "50", "-timeout", "5"],
        timeout=120
    )
    found = []
    for line in out.strip().split("\n"):
        if line.strip():
            found.append({"path": line.strip(), "url": f"{url}/{line.strip()}"})
    return found

def sqlmap_check(url: str, method: str = "GET", body: str = None) -> list[dict]:
    """Run sqlmap to test for SQL injection."""
    if not shutil.which("sqlmap"):
        return []
    cmd = ["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
           "--time-sec", "5", "--random-agent", "--output-dir=/tmp/sqlmap_out"]
    if body:
        cmd += ["--data", body]
    out = _run_cmd(cmd, timeout=120)
    results = []
    if "Parameter:" in out and ("vulnerable" in out or "Banner:" in out):
        results.append({"url": url, "result": "SQL injection detected"})
    return results

def dalfox_scan(url: str) -> list[dict]:
    """Run dalfox for XSS detection."""
    if not shutil.which("dalfox"):
        return []
    out = _run_cmd(["dalfox", "url", url, "--silence", "--no-color",
                     "--only-poc", "--skip-mining-all"], timeout=120)
    results = []
    for line in out.strip().split("\n"):
        if "[POC]" in line or "[V]" in line:
            results.append({"url": url, "result": line.strip()})
    return results

def naabu_scan(domain: str, ports: str = "80,443,8080,8443,3000,5000,9000,9090,9443"):
    """Port scan using naabu."""
    if not shutil.which("naabu"):
        return []
    out = _run_cmd(["naabu", "-host", domain, "-p", ports,
                     "-silent", "-verify"], timeout=120)
    hosts = [h.strip() for h in out.strip().split("\n") if h.strip()]
    return hosts


# -- Main Discover --------------------------------------------------
def discover(base_url: str) -> dict:
    """
    Run full recon on a target.
    Returns a dict with all findings for the agent to use.
    """
    parsed = urlparse(base_url)
    domain = parsed.netloc
    hostname = parsed.hostname or domain
    print(f"\n  \033[96m{'='*60}\033[0m")
    print(f"  \033[1mRECONNAISSANCE\033[0m - {domain}")
    print(f"  \033[96m{'='*60}\033[0m")

    report = {
        "domain": domain,
        "tech_stack": [],
        "endpoints": set(),
        "forms": [],
        "sitemap_urls": [],
        "wayback_urls": [],
        "cors_issues": [],
        "subdomains_found": [],
        "supply_chain": [],
        "missing_headers": [],
        "data_leaks": [],
        "graphql": None,
    }

    with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
        hdrs = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, */*"}

        # -- 1. Homepage + tech detection --
        print(f"\n  \033[1m[1/6] Tech Detection\033[0m")
        try:
            r = client.get(base_url, headers=hdrs)
            tech = detect_tech(dict(r.headers), r.text)
            if tech:
                report["tech_stack"] = tech
                print(f"  Detected: {', '.join(tech)}")
            else:
                print(f"  No clear tech signatures")
        except Exception as e:
            print(f"  Failed: {e}")

        # -- 2. Common paths --
        print(f"\n  \033[1m[2/6] Probing Common Paths\033[0m")
        found_paths = []
        for path in COMMON_PATHS:
            try:
                r = client.get(base_url.rstrip("/") + path, headers=hdrs)
                if r.status_code not in (404, 410):
                    found_paths.append({"path": path, "status": r.status_code})
                    report["endpoints"].add(base_url.rstrip("/") + path)
                    # Try to detect OpenAPI specs live
                    ct = r.headers.get("content-type", "")
                    if "json" in ct and any(k in path for k in ["swagger", "openapi", "api-docs"]):
                        try:
                            spec = r.json()
                            for p, ms in spec.get("paths", {}).items():
                                for m in ms:
                                    if m.lower() in ("get","post","put","patch","delete"):
                                        report["endpoints"].add(base_url.rstrip("/") + p)
                        except: pass
            except: pass
        if found_paths:
            for fp in found_paths[:20]:
                print(f"  {fp['status']} {fp['path']}")
            if len(found_paths) > 20:
                print(f"  ... and {len(found_paths)-20} more")
        else:
            print(f"  None found")

        # -- 2b. GraphQL Introspection --
        print(f"\n  \033[1m[2b/10] GraphQL Introspection\033[0m")
        gql_checked = False
        for fp in found_paths:
            if "graphql" in fp["path"].lower():
                url = base_url.rstrip("/") + fp["path"]
                print(f"  Probing {fp['path']}...")
                gql = probe_graphql(url, client)
                if gql["is_graphql"]:
                    gql_checked = True
                    report["graphql"] = gql
                    print(f"  {CHECK} Confirmed GraphQL endpoint")
                    if gql.get("schema"):
                        q = len(gql["schema"].get("queries", []))
                        m = len(gql["schema"].get("mutations", []))
                        print(f"  Queries: {q}, Mutations: {m}")
                    if gql.get("introspection"):
                        print(f"  {WARN} Introspection ENABLED (full schema exposed)")
                    else:
                        print(f"  Introspection disabled")
                    if gql.get("suggestions"):
                        print(f"  {WARN} Suggestions mode ON (debug info leak)")
                    # Also try POST with GET-style query param
                    try:
                        r = client.get(url, params={"query": PING_QUERY},
                                       headers=hdrs)
                        if r.status_code == 200:
                            print(f"  GET-based queries work (query param)")
                    except: pass
                break
        if not gql_checked:
            # Check wayback/crawl endpoints too
            all_endpoints = list(report["endpoints"])
            for ep in all_endpoints:
                if "graphql" in ep.lower():
                    print(f"  Probing {ep[:70]}...")
                    gql = probe_graphql(ep, client)
                    if gql["is_graphql"]:
                        gql_checked = True
                        report["graphql"] = gql
                        print(f"  {CHECK} Confirmed GraphQL endpoint")
                        break
        if not gql_checked:
            print(f"  No GraphQL endpoints detected")

        # -- 3. Robots & Sitemap --
        print(f"\n  \033[1m[3/6] Robots & Sitemap\033[0m")
        for ep in ROBOTS_ENDPOINTS:
            try:
                r = client.get(base_url.rstrip("/") + ep, headers=hdrs)
                if r.status_code == 200:
                    print(f"  Found: {ep}")
                    if "robots" in ep:
                        paths = parse_robots(r.text)
                        for p in paths[:20]:
                            report["endpoints"].add(base_url.rstrip("/") + p)
                    elif "sitemap" in ep:
                        urls = parse_sitemap(r.text)
                        report["sitemap_urls"].extend(urls[:100])
                        for u in urls[:10]:
                            report["endpoints"].add(u)
                            print(f"  Sitemap: {u[:80]}")
                        if urls:
                            print(f"  {len(urls)} URLs in sitemap")
            except: pass

        # -- 4. Full crawl --
        print(f"\n  \033[1m[4/6] Crawling\033[0m")
        crawl = crawl_page(base_url, client)
        if crawl["links"]:
            print(f"  {len(crawl['links'])} links found")
        for form in crawl["forms"][:10]:
            report["forms"].append(form)
            report["endpoints"].add(form["action"])
            print(f"  Form: {form['method']} {form['action'][:80]}")
            if form["inputs"]:
                print(f"        inputs: {', '.join(i['name'] for i in form['inputs'][:5])}")
        if crawl["scripts"]:
            for src in crawl["scripts"][:10]:
                try:
                    js = client.get(src, headers=hdrs).text
                    refs = set(re.findall(r'["\'](/(?:api|v\d)[^"\'?\s]{2,60})["\']', js))
                    for ref in refs:
                        report["endpoints"].add(base_url.rstrip("/") + ref)
                        print(f"  JS ref: {ref}")
                except: pass
            print(f"  {len(crawl['scripts'])} scripts found")

        # -- 5. Wayback Machine --
        print(f"\n  \033[1m[5/10] Wayback Machine\033[0m")
        wb = wayback_urls(hostname)
        if wb:
            report["wayback_urls"] = wb
            for u in wb[:15]:
                report["endpoints"].add(u)
                print(f"  Archived: {u[:90]}")
            print(f"  {len(wb)} historical URLs")
        else:
            print(f"  None found")

        # -- 6. CORS preflight on discovered endpoints --
        if report["endpoints"]:
            print(f"\n  \033[1m[6/10] CORS Preflight\033[0m")
            malicious = ["https://evil.com", "null", "https://attacker.com"]
            for ep in list(report["endpoints"])[:10]:
                for origin in malicious:
                    result = cors_check(ep, origin, client)
                    if result.get("wildcard") or "null" in str(result.get("allow_origin", "")):
                        report["cors_issues"].append(result)
                        print(f"  CORS: {ep} allows {origin}")

        # -- 7. Supply chain detection --
        print(f"\n  \033[1m[7/10] Supply Chain Detection\033[0m")
        try:
            r = client.get(base_url, headers=hdrs)
            soup = BeautifulSoup(r.text, "html.parser")
            sc = detect_supply_chain(soup, r.text)
            if sc:
                report["supply_chain"] = sc
                for s in sc[:15]:
                    print(f"  {s['service']} ({s['detections']} refs)")
                if len(sc) > 15:
                    print(f"  ... and {len(sc)-15} more third-party services")
                print(f"  Total: {len(sc)} third-party services detected")
            else:
                print(f"  No third-party services detected")
        except Exception as e:
            print(f"  Failed: {e}")

        # -- 8. Security headers audit --
        print(f"\n  \033[1m[8/10] Security Headers Audit\033[0m")
        try:
            r = client.get(base_url, headers=hdrs)
            issues = audit_security_headers(dict(r.headers))
            if issues:
                report["missing_headers"] = issues
                for iss in issues:
                    icon = f"\033[93m{WARN}" if iss["severity"] == "MEDIUM" else f"\033[91m{CROSS}"
                    print(f"  {icon}\033[0m {iss['header']}: {iss['issue']}")
            else:
                print(f"  All security headers present")
        except Exception as e:
            print(f"  Failed: {e}")

        # -- 9. Data leakage scan --
        print(f"\n  \033[1m[9/10] Data Leakage Scan\033[0m")
        try:
            for ep in [base_url] + list(report["endpoints"])[:20]:
                try:
                    r = client.get(ep, headers=hdrs, timeout=8)
                    leaks = scan_data_leakage(r.text, ep)
                    if leaks:
                        report["data_leaks"].extend(leaks)
                        for l in leaks[:3]:
                            icon = {"HIGH": f"\033[91m{BULLET}", "MEDIUM": f"\033[93m{BULLET}", "LOW": f"\033[92m{BULLET}"}
                            print(f"  {icon[l['severity']]}\033[0m [{l['severity']}] {l['type']}: {l['match'][:50]}")
                except: pass
            if report["data_leaks"]:
                print(f"  Total leaks found: {len(report['data_leaks'])}")
            else:
                print(f"  No obvious data leaks detected")
        except Exception as e:
            print(f"  Failed: {e}")

        # -- 10. External tools --
        print(f"\n  \033[1m[10/10] External Tools\033[0m")
        tools = {
            "subfinder": tool_available("subfinder"),
            "httpx":     tool_available("httpx"),
            "nuclei":    tool_available("nuclei"),
            "katana":    tool_available("katana"),
            "gau":       tool_available("gau"),
            "ffuf":      tool_available("ffuf"),
            "sqlmap":    tool_available("sqlmap"),
            "dalfox":    tool_available("dalfox"),
            "naabu":     tool_available("naabu"),
        }
        found = [k for k, v in tools.items() if v]
        if found:
            print(f"  Tools found: {', '.join(found)}")

            raw_domain = hostname
            if ":" in raw_domain:
                raw_domain = raw_domain.split(":")[0]

            # -- subfinder --
            if tools["subfinder"]:
                print(f"  [subfinder] Scanning {raw_domain}...")
                subs = subfinder_scan(raw_domain)
                if subs:
                    report["subdomains"] = subs
                    print(f"  [subfinder] Found {len(subs)} subdomains")
                    for s in subs[:10]:
                        report["endpoints"].add(f"https://{s}")
                        report["endpoints"].add(f"http://{s}")
                        print(f"    https://{s}")
                    if len(subs) > 10:
                        print(f"    ... and {len(subs)-10} more")

            # -- gau --
            if tools["gau"]:
                print(f"  [gau] Fetching historical URLs for {raw_domain}...")
                gau = gau_urls(raw_domain)
                if gau:
                    report["gau_urls"] = gau
                    print(f"  [gau] Found {len(gau)} URLs")
                    for u in gau[:20]:
                        parsed = urlparse(u)
                        if parsed.path and parsed.path != "/":
                            report["endpoints"].add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
                        else:
                            report["endpoints"].add(u)
                        print(f"    {u[:90]}")
                    if len(gau) > 20:
                        print(f"    ... and {len(gau)-20} more")

            # -- httpx (probe all collected endpoints) --
            if tools["httpx"] and report["endpoints"]:
                print(f"  [httpx] Probing {len(report['endpoints'])} endpoints...")
                alive = httpx_probe(list(report["endpoints"]))
                if alive:
                    report["alive_endpoints"] = alive
                    report["endpoints"].update(alive)
                    print(f"  [httpx] {len(alive)} alive confirmed")

            # -- katana (deep crawl on base + subdomains) --
            if tools["katana"]:
                crawl_targets = [f"https://{raw_domain}"]
                for s in report.get("subdomains", [])[:5]:
                    crawl_targets.append(f"https://{s}")
                for ct in crawl_targets:
                    print(f"  [katana] Crawling {ct}...")
                    kt = katana_crawl(ct)
                    if kt:
                        report.setdefault("katana_urls", []).extend(kt)
                        for u in kt[:10]:
                            report["endpoints"].add(u)
                            print(f"    {u[:90]}")
                        if len(kt) > 10:
                            print(f"    ... and {len(kt)-10} more")

            # -- nuclei --
            if tools["nuclei"] and report["endpoints"]:
                targets = list(report["endpoints"])[:10]
                print(f"  [nuclei] Scanning {len(targets)} targets...")
                nuc = nuclei_scan(targets)
                if nuc:
                    report["nuclei_results"] = nuc
                    for nr in nuc[:10]:
                        sev = nr.get("info", {}).get("severity", "unknown").upper()
                        name = nr.get("info", {}).get("name", "unknown")
                        matched = nr.get("matched-at", "")
                        print(f"    [{sev}] {name}")
                        print(f"           {matched[:80]}")
                        report["endpoints"].add(matched)
                    if len(nuc) > 10:
                        print(f"    ... and {len(nuc)-10} more findings")
                    print(f"  [nuclei] {len(nuc)} findings")
                else:
                    print(f"  [nuclei] No findings")

            # -- naabu (port scan on main domain) --
            if tools["naabu"]:
                print(f"  [naabu] Port scanning {raw_domain}...")
                ports = naabu_scan(raw_domain)
                if ports:
                    report["open_ports"] = ports
                    for p in ports[:10]:
                        scheme = "https" if ":443" in p else "http"
                        report["endpoints"].add(f"{scheme}://{p}")
                        print(f"    {p}")
                    if len(ports) > 10:
                        print(f"    ... and {len(ports)-10} more")

            # -- ffuf (fuzz discovered paths) --
            if tools["ffuf"] and report["endpoints"]:
                fuzz_targets = list(report["endpoints"])[:3]
                for ft in fuzz_targets:
                    parsed = urlparse(ft)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    print(f"  [ffuf] Fuzzing {base}...")
                    found = ffuf_fuzz(base)
                    if found:
                        report.setdefault("ffuf_results", []).extend(found)
                        for f in found[:10]:
                            report["endpoints"].add(f["url"])
                            print(f"    {f['path']}")
                        if len(found) > 10:
                            print(f"    ... and {len(found)-10} more")

            # -- dalfox (XSS check on all endpoints) --
            if tools["dalfox"] and report["endpoints"]:
                print(f"  [dalfox] Scanning {len(report['endpoints'])} endpoints...")
                for ep in list(report["endpoints"])[:10]:
                    dx = dalfox_scan(ep)
                    if dx:
                        report.setdefault("dalfox_results", []).extend(dx)
                        for d in dx:
                            print(f"    [XSS] {ep}")

            # -- sqlmap (check endpoints with query params) --
            if tools["sqlmap"] and report["endpoints"]:
                print(f"  [sqlmap] Testing endpoints with params...")
                for ep in list(report["endpoints"])[:5]:
                    if "?" in ep:
                        sq = sqlmap_check(ep)
                        if sq:
                            report.setdefault("sqlmap_results", []).extend(sq)
                            for s in sq:
                                print(f"    [SQLi] {s['result']} - {ep[:60]}")
        else:
            print(f"  No external tools found on PATH")
            print(f"  Install guide:")

        # -- Summary --
        print(f"\n  \033[96m{'-'*60}\033[0m")
        print(f"  \033[1mRecon Complete\033[0m")
        print(f"  Tech stack: {', '.join(report['tech_stack']) or 'unknown'}")
        print(f"  Endpoints discovered: {len(report['endpoints'])}")
        print(f"  Forms: {len(report['forms'])}")
        print(f"  Sitemap URLs: {len(report['sitemap_urls'])}")
        print(f"  Wayback URLs: {len(report['wayback_urls'])}")
        print(f"  Third-party services: {len(report['supply_chain'])}")
        print(f"  Missing security headers: {len(report['missing_headers'])}")
        print(f"  Data leaks: {len(report['data_leaks'])}")
        print(f"  CORS issues: {len(report['cors_issues'])}")
        if report.get("subdomains"):
            print(f"  Subdomains: {len(report['subdomains'])}")
        if report.get("gau_urls"):
            print(f"  Historical URLs (gau): {len(report['gau_urls'])}")
        if report.get("katana_urls"):
            print(f"  Katana crawl: {len(report['katana_urls'])} URLs")
        if report.get("nuclei_results"):
            print(f"  Nuclei findings: {len(report['nuclei_results'])}")
        if report.get("open_ports"):
            print(f"  Open ports: {len(report['open_ports'])}")
        if report.get("ffuf_results"):
            print(f"  Ffuf discoveries: {len(report['ffuf_results'])}")
        if report.get("dalfox_results"):
            print(f"  Dalfox XSS: {len(report['dalfox_results'])}")
        if report.get("sqlmap_results"):
            print(f"  SQLMap findings: {len(report['sqlmap_results'])}")
        if report.get("graphql") and report["graphql"].get("is_graphql"):
            g = report["graphql"]
            print(f"  GraphQL: {'Yes' if g.get('schema') else 'Active (no schema)'}")
            if g.get("introspection"):
                print(f"  GraphQL introspection: OPEN")
            if g.get("suggestions"):
                print(f"  GraphQL suggestions: ON")
        recon_suggestions(report)
        report["endpoints"] = list(report["endpoints"])
        return report
