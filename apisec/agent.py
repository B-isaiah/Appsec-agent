"""
apisec/agent.py
The brain. Discovers endpoints, runs Claude agent loop,
collects findings. Uses identity.py for auth and knowledge.py for context.
"""

import re
import json
import base64
from urllib.parse import urljoin, urlparse
from typing import Optional
from xml.etree import ElementTree as ET

import httpx
from bs4 import BeautifulSoup
from .identity  import Identity
from .knowledge import context_for_scan
from .llm       import LLM


# ── Terminal colours ──────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def _sc(s):
    return {"CRITICAL":C.RED+C.BOLD,"HIGH":C.RED,
            "MEDIUM":C.YELLOW,"LOW":C.GREEN,"INFO":C.CYAN}.get(s, C.RESET)


# ── Operation log (replay system) ────────────────────────────────
operations : dict = {}
findings   : list = []
_op_n = 0

def _log(method, url, body, status, resp, label):
    global _op_n
    _op_n += 1
    oid = f"op_{_op_n:03d}"
    operations[oid] = {"op_id":oid,"identity":label,"method":method,
                        "url":url,"request_body":body,
                        "status":status,"response_body":resp}
    return oid


# ── Common paths for auto-discovery ──────────────────────────────
COMMON = [
    "/api","/api/v1","/api/v2","/api/v3","/v1","/v2","/v3",
    "/swagger.json","/swagger/v1/swagger.json","/openapi.json",
    "/api-docs","/api-docs.json","/.well-known/openapi","/graphql",
    "/api/v1/auth/login","/api/v1/auth/register",
    "/api/v1/login","/api/v1/register","/login","/register",
    "/api/v1/users","/api/v1/users/me","/api/v1/profile",
    "/api/v1/users/1","/api/v1/users/2","/api/v1/users/3",
    "/api/v1/admin","/api/v1/admin/users",
    "/api/v1/products","/api/v1/orders","/api/v1/orders/1",
    "/api/v1/payments","/api/v1/accounts","/api/v1/accounts/1",
    "/api/v1/settings","/api/v1/config",
    "/health","/healthz","/ping","/status","/metrics",
    "/actuator","/actuator/health","/actuator/env",
    "/actuator/beans","/actuator/mappings",
    "/debug","/.env","/version",
]


# ── Endpoint collection ───────────────────────────────────────────
def _base_hdrs(origin: str) -> dict:
    return {"User-Agent":"Mozilla/5.0","Accept":"application/json, */*",
            "Content-Type":"application/json","Origin":origin}


def collect_endpoints(
    base_url   : str,
    burp_path  : Optional[str]     = None,
    spec_path  : Optional[str]     = None,
    attacker   : Optional[Identity] = None,
) -> list[dict]:
    eps, seen = [], set()

    def _add(method, url, body=None, source="?", desc=""):
        k = f"{method}:{urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path}"
        if k not in seen:
            seen.add(k)
            eps.append({"method":method,"url":url,"body":body,
                        "source":source,"description":desc})

    # Burp XML
    if burp_path:
        print(f"\n{C.BOLD}[BURP]{C.RESET} {burp_path}")
        try:
            root = ET.parse(burp_path).getroot()
            bh = urlparse(base_url).netloc
            for item in root.findall(".//item"):
                try:
                    url_el = item.find("url")
                    if not url_el or not url_el.text: continue
                    url = url_el.text.strip()
                    if bh and urlparse(url).netloc != bh: continue
                    req_el = item.find("request")
                    body, method = None, "GET"
                    if req_el and req_el.text:
                        enc = req_el.get("base64","false") == "true"
                        raw = (base64.b64decode(req_el.text).decode("utf-8",errors="replace")
                               if enc else req_el.text)
                        parts = raw.split("\n")[0].strip().split(" ")
                        if parts: method = parts[0].upper()
                        in_body, blines = False, []
                        for line in raw.split("\n")[1:]:
                            if line.strip() == "" and not in_body: in_body=True; continue
                            if in_body: blines.append(line)
                        rb = "\n".join(blines).strip()
                        if rb:
                            try: body = json.loads(rb)
                            except: body = {"_raw":rb}
                    _add(method, url, body, "burp", "Burp observed")
                except Exception: continue
        except Exception as e:
            print(f"  {C.RED}Burp parse error: {e}{C.RESET}")
        print(f"  {C.CYAN}→ {len(eps)} from Burp{C.RESET}")

    # OpenAPI spec
    if spec_path:
        print(f"\n{C.BOLD}[SPEC]{C.RESET} {spec_path}")
        n_before = len(eps)
        try:
            spec = json.load(open(spec_path))
            base = spec.get("basePath","")
            for path, methods in spec.get("paths",{}).items():
                for m, d in methods.items():
                    if m.lower() in ("get","post","put","patch","delete","options"):
                        _add(m.upper(), base_url.rstrip("/")+base+path,
                             source="openapi", desc=d.get("summary",""))
        except Exception as e:
            print(f"  {C.RED}Spec error: {e}{C.RESET}")
        print(f"  {C.CYAN}→ {len(eps)-n_before} from spec{C.RESET}")

    # Auto-discovery
    print(f"\n{C.BOLD}[DISCOVERY]{C.RESET} Probing {base_url}...")
    n_before = len(eps)
    hdrs = _base_hdrs(base_url)
    if attacker:
        hdrs = attacker.merge_into(hdrs)

    with httpx.Client(timeout=8, follow_redirects=True, verify=False) as c:
        for path in COMMON:
            url = base_url.rstrip("/")+path
            try:
                r = c.get(url, headers=hdrs,
                          cookies=attacker.cookies if attacker else {})
                if r.status_code not in (404,410):
                    _add("GET", url, source="discovery",
                         desc=f"HTTP {r.status_code}")
                    ct = r.headers.get("content-type","")
                    if "json" in ct and any(k in path for k in ["swagger","openapi","api-docs"]):
                        try:
                            spec = r.json()
                            for p,ms in spec.get("paths",{}).items():
                                for m,d in ms.items():
                                    if m.lower() in ("get","post","put","patch","delete"):
                                        _add(m.upper(), base_url.rstrip("/")+p,
                                             source="openapi_live", desc=d.get("summary",""))
                        except: pass
            except: pass

        # JS crawl
        try:
            r = c.get(base_url, headers=hdrs,
                      cookies=attacker.cookies if attacker else {})
            soup = BeautifulSoup(r.text,"html.parser")
            for tag in soup.find_all("script",src=True)[:8]:
                try:
                    js = c.get(urljoin(base_url,tag["src"]),headers=hdrs).text
                    for ref in set(re.findall(r'["\'](/(?:api|v\d)[^"\'?\s]{2,60})["\']',js)):
                        _add("GET", base_url.rstrip("/")+ref, source="js", desc="JS ref")
                except: pass
        except: pass

    print(f"  {C.CYAN}→ {len(eps)-n_before} from discovery{C.RESET}")
    print(f"\n{C.BOLD}Total endpoints:{C.RESET} {len(eps)}")
    return eps


def _idor_variants(eps: list[dict]) -> list[str]:
    variants = []
    for e in eps:
        path = urlparse(e["url"]).path
        base = e["url"].replace(path,"")
        for m in re.finditer(r'/(\d+)(?=/|$)', path):
            orig = int(m.group(1))
            for c in [orig-1, orig+1, 1, 2, 3, 100, 9999, 0]:
                if c >= 0 and c != orig:
                    np = path[:m.start(1)]+str(c)+path[m.end(1):]
                    variants.append(base+np)
    return list(dict.fromkeys(variants))[:50]


def harvest_victim_ids(
    eps: list[dict],
    victim: Identity,
    base_url: str,
) -> dict:
    print(f"\n{C.BOLD}[VICTIM SETUP]{C.RESET} Harvesting resource IDs...")
    ctx = {"victim_ids":{}}
    hdrs = victim.merge_into(_base_hdrs(base_url))
    with httpx.Client(timeout=8,follow_redirects=True,verify=False) as c:
        for path in ["/api/v1/users/me","/api/v1/me","/api/v1/profile","/me","/profile"]:
            try:
                r = c.get(base_url.rstrip("/")+path, headers=hdrs, cookies=victim.cookies)
                if r.status_code == 200:
                    data = r.json()
                    for k in ("id","userId","user_id","_id","accountId","uuid"):
                        if k in data:
                            ctx["victim_ids"][k] = data[k]
                            print(f"  {C.GREEN}✓ victim.{k} = {data[k]}{C.RESET}")
                    break
            except: pass
    if not ctx["victim_ids"]:
        print(f"  {C.DIM}No IDs found — agent will use sequential guessing{C.RESET}")
    return ctx


# ── HTTP probe ────────────────────────────────────────────────────
def probe(
    method: str,
    url: str,
    body: Optional[dict],
    identity: Optional[Identity],
    base_url: str,
    extra_headers: Optional[dict] = None,
) -> dict:
    label = identity.label if identity else "none"
    hdrs  = _base_hdrs(base_url)
    if extra_headers: hdrs.update(extra_headers)
    if identity:      hdrs = identity.merge_into(hdrs)
    cookies = identity.cookies if identity else {}

    try:
        with httpx.Client(timeout=10,follow_redirects=True,verify=False) as c:
            r = c.request(method, url, json=body, headers=hdrs, cookies=cookies)
        try:    rb = r.json()
        except: rb = r.text[:1000]

        oid = _log(method, url, body, r.status_code, rb, label)
        rs  = json.dumps(rb) if isinstance(rb,(dict,list)) else str(rb)
        sigs = []
        if r.status_code == 200 and not identity:                         sigs.append("UNAUTH_200")
        if any(w in rs.lower() for w in ("password","secret","private_key")): sigs.append("SENSITIVE_FIELD")
        if any(w in rs.lower() for w in ("system.","traceback","at line",
                                          "exception","stack trace")):     sigs.append("STACK_TRACE")
        if r.status_code == 500:                                           sigs.append("SERVER_500")
        if r.headers.get("access-control-allow-origin","") == "*":        sigs.append("CORS_WILDCARD")
        if "x-powered-by" in r.headers:
            sigs.append(f"TECH:{r.headers['x-powered-by'][:30]}")

        sc = C.GREEN if r.status_code<300 else C.YELLOW if r.status_code<400 else C.DIM
        id_tag = f"{C.CYAN}[{label}]{C.RESET} " if label != "attacker" else ""
        sig    = f" {C.YELLOW}⚑ {'|'.join(sigs)}{C.RESET}" if sigs else ""
        print(f"  {C.DIM}[{oid}]{C.RESET} {id_tag}{method:6} {url[:65]} {sc}{r.status_code}{C.RESET}{sig}")

        return {"op_id":oid,"method":method,"url":url,"identity":label,
                "status":r.status_code,"response":rb,"signals":sigs,
                "resp_headers":dict(r.headers)}
    except Exception as e:
        oid = _log(method, url, body, 0, str(e), label)
        print(f"  {C.DIM}[{oid}]{C.RESET} {method:6} {url[:65]} {C.DIM}ERR: {e}{C.RESET}")
        return {"op_id":oid,"method":method,"url":url,"identity":label,
                "status":0,"response":str(e),"signals":["CONN_ERR"],"resp_headers":{}}


def report_finding(title,severity,owasp,description,op_ids,remediation):
    f = {"title":title,"severity":severity,"owasp":owasp,"description":description,
         "op_ids":op_ids,"remediation":remediation,
         "evidence":{k:operations.get(k) for k in op_ids if k in operations}}
    findings.append(f)
    col = _sc(severity)
    print(f"\n  {col}🚨 [{severity}] {title}{C.RESET}")
    print(f"     {C.DIM}{owasp}{C.RESET}")
    print(f"     {description[:140]}")
    print(f"     Proof: {', '.join(op_ids)}\n")


# ── Claude agent tools schema ─────────────────────────────────────
TOOLS = [
    {
        "name": "probe",
        "description": (
            "Send one HTTP request. identity = 'attacker' | 'victim' | 'none'. "
            "Auth (cookies, tokens, headers) is handled automatically per identity. "
            "Test each endpoint at least 3 ways: none → attacker → IDOR with victim IDs."
        ),
        "input_schema": {
            "type":"object",
            "properties": {
                "method":        {"type":"string","enum":["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]},
                "url":           {"type":"string"},
                "body":          {"type":"object"},
                "identity":      {"type":"string","enum":["attacker","victim","none"]},
                "extra_headers": {"type":"object"},
            },
            "required":["method","url","identity"],
        },
    },
    {
        "name": "report_finding",
        "description": (
            "Report a CONFIRMED vulnerability. "
            "Requires real proof — a 200 with another user's data, auth bypass, "
            "stack trace, or clear misconfiguration. "
            "Never report 401/403/404 or speculation."
        ),
        "input_schema": {
            "type":"object",
            "properties": {
                "title":          {"type":"string"},
                "severity":       {"type":"string","enum":["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},
                "owasp_category": {"type":"string","description":"e.g. API1:2023 BOLA"},
                "description":    {"type":"string"},
                "op_ids":         {"type":"array","items":{"type":"string"}},
                "remediation":    {"type":"string"},
            },
            "required":["title","severity","owasp_category","description","op_ids","remediation"],
        },
    },
    {
        "name": "testing_complete",
        "description": "Call ONLY when every endpoint has been tested.",
        "input_schema": {
            "type":"object",
            "properties": {
                "summary":     {"type":"string"},
                "tested_urls": {"type":"array","items":{"type":"string"}},
            },
            "required":["summary","tested_urls"],
        },
    },
]

SYSTEM = """You are an expert API security researcher. Find OWASP API Top 10 vulnerabilities.

## Auth is automatic
probe() applies cookies, tokens, headers automatically.
You only choose identity="attacker", "victim", or "none".

## Your Knowledge Base
Relevant techniques from blog posts, videos, and research have been injected
into the context below. Read them. Apply those techniques during testing.

## OWASP API Top 10 Protocol

API1  BOLA — Probe as victim → confirm 200 → replay as attacker with same ID. 200 = confirmed BOLA.
API2  Auth  — Probe with no auth. Try /login with no password, empty string, SQL chars.
API3  Mass Assignment — Add "role":"admin","isAdmin":true to every POST/PUT body.
API4  Consumption — No pagination on list endpoints? Huge response? Note it.
API5  Function Auth — Try /admin/* endpoints as attacker (non-admin).
API6  Business Logic — Try skipping workflow steps, bulk deletes, replaying tokens.
API7  SSRF — Any URL field? Point it at http://169.254.169.254/
API8  Misconfig — Debug endpoints, CORS *, stack traces, server banners, .NET System. errors.
API9  Inventory — Old /v1/ still alive? Docs publicly exposed?
API10 Unsafe Consumption — Inject payloads in fields passed to third parties.

## Severity
CRITICAL — Account takeover, mass data dump, RCE
HIGH     — IDOR with another user's PII, auth bypass
MEDIUM   — Sensitive fields, rate limiting bypassed
LOW      — Server banner, verbose error, CORS on non-sensitive endpoint
INFO     — Docs exposed, old version alive

## Rules
REPORT:  200 + other user's data | unauth 200 + data | admin accessible | stack trace in response
DO NOT:  401/403/404 | 500 alone | speculation | existence enumeration alone

Call testing_complete when ALL endpoints have been tested."""


def run(
    base_url    : str,
    eps         : list[dict],
    attacker    : Optional[Identity],
    victim      : Optional[Identity],
    victim_ctx  : dict,
    provider    : str = "groq",
):
    """Run the agent loop using the specified LLM provider."""
    llm = LLM(provider=provider)
    print(f"\n{C.BOLD}[AGENT]{C.RESET} Starting with {provider.upper()} — {len(eps)} endpoints\n")

    # Pull knowledge base context
    auth_type = attacker.auth_type if attacker else "none"
    kb = context_for_scan(urlparse(base_url).netloc, auth_type)
    if kb:
        n = kb.count("###")
        print(f"  {C.CYAN}→ {n} knowledge chunks loaded{C.RESET}")
    else:
        print(f"  {C.DIM}Knowledge base empty — add resources with: python3 run.py learn URL{C.RESET}")

    ep_list   = "\n".join(f"- [{e['method']}] {e['url']} [{e['source']}]" for e in eps)
    idor_list = "\n".join(_idor_variants(eps))

    auth_lines = []
    if attacker and attacker.is_authenticated():
        auth_lines.append(f"ATTACKER: {attacker.auth_type}")
    else:
        auth_lines.append("ATTACKER: unauthenticated")
    if victim and victim.is_authenticated():
        auth_lines.append(f"VICTIM:   {victim.auth_type}")
    else:
        auth_lines.append("VICTIM:   none — use sequential ID guessing")

    victim_ids = ""
    if victim_ctx.get("victim_ids"):
        victim_ids = "\nKnown victim IDs:\n" + json.dumps(victim_ctx["victim_ids"], indent=2)

    user_msg = f"""Target: {base_url}

Auth:
{chr(10).join(auth_lines)}
{victim_ids}

{"## Knowledge Base Context" + chr(10) + kb if kb else ""}

## Endpoints ({len(eps)}):
{ep_list}

## IDOR variants to test as attacker:
{idor_list}

Begin. Test every endpoint."""

    # First call
    resp = llm.send(system=SYSTEM, user_msg=user_msg, tools=TOOLS)

    done, iters = False, 0
    while not done and iters < 150:
        iters += 1

        # Print any text the model said
        if resp.text.strip():
            print(f"\n{C.DIM}[Agent] {resp.text[:160]}{C.RESET}")

        # No tool calls — model is done
        if not resp.tool_calls:
            break

        # Process tool calls
        tool_results = []
        for tc in resp.tool_calls:
            name = tc["name"]
            inp  = tc["input"]
            tid  = tc["id"]

            if name == "probe":
                label    = inp.get("identity", "attacker")
                identity = (attacker if label == "attacker"
                            else victim if label == "victim" else None)
                result   = probe(
                    inp["method"], inp["url"], inp.get("body"),
                    identity, base_url, inp.get("extra_headers")
                )
                tool_results.append({
                    "tool_use_id": tid,
                    "content":     json.dumps(result),
                })

            elif name == "report_finding":
                report_finding(
                    inp["title"], inp["severity"], inp["owasp_category"],
                    inp["description"], inp["op_ids"], inp["remediation"]
                )
                tool_results.append({"tool_use_id": tid, "content": "Logged."})

            elif name == "testing_complete":
                print(f"\n{C.BOLD}[DONE]{C.RESET} {inp['summary']}")
                print(f"  Tested: {len(inp.get('tested_urls',[]))} | Findings: {len(findings)}")
                tool_results.append({"tool_use_id": tid, "content": "Done."})
                done = True

        if tool_results and not done:
            resp = llm.reply(system=SYSTEM, tool_results=tool_results, tools=TOOLS)
        elif tool_results and done:
            # Send final ack even when done so history is clean
            llm.reply(system=SYSTEM, tool_results=tool_results, tools=TOOLS)
