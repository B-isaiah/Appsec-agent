#!/usr/bin/env python3
"""
run.py -- APISec Agent
The ONLY file you run. Everything else is internal.
Bee / EdiongTechnologies

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCANNING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Basic scan (auto-discovers endpoints)
python3 run.py scan https://target.com

# With Burp export (real observed traffic -- best results)
python3 run.py scan https://target.com --burp traffic.xml

# With attacker + victim accounts (full IDOR testing)
python3 run.py scan https://target.com \
  --attacker-burp attacker.xml \
  --victim-burp   victim.xml

# Manual auth (paste headers directly -- any format)
python3 run.py scan https://target.com \
  --attacker-headers "Authorization: Bearer eyJ...
X-CSRF-Token: abc123
Cookie: .AspNetCore.Session=xyz"

# Burp as base + manual header override
python3 run.py scan https://target.com \
  --attacker-burp attacker.xml \
  --attacker-headers "X-Extra-Token: override"

# Everything at once
python3 run.py scan https://target.com \
  --burp traffic.xml \
  --attacker-burp attacker.xml \
  --victim-burp victim.xml \
  --spec openapi.json

# HACKBOT MODE: Auth testing sub-agent (JWT, MFA, cred stuffing, etc.)
python3 run.py scan https://target.com \
  --attacker-headers "Authorization: Bearer eyJ..." \
  --auth-only --model deepseek --breach-key YOUR_KEY

# Full hackbot: API scanning + auth testing with DeepSeek
python3 run.py scan https://target.com \
  --attacker-headers "Authorization: Bearer eyJ..." \
  --model deepseek --breach-key YOUR_KEY --wordlist ./common.txt

# EXPLOIT MODE: SQLi, XSS, SSRF, IDOR, mass assignment (no LLM needed)
python3 run.py scan https://target.com \
  --attacker-headers "Authorization: Bearer eyJ..." \
  --exploit-only

# Exploitation alongside normal scan
python3 run.py scan https://target.com \
  --attacker-headers "Authorization: Bearer eyJ..." \
  --model groq --exploit

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KNOWLEDGE BASE  (grows permanently, used in every scan)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python3 run.py learn https://brutecat.com/articles/hacking-google
python3 run.py learn https://www.youtube.com/watch?v=VIDEO_ID
python3 run.py learn https://linkedin.com/pulse/some-article

python3 run.py learn --text "NET Core uses X-CSRF-Token. Session in .AspNetCore.Session cookie."

python3 run.py kb list
python3 run.py kb search "NET Core CSRF bypass"
python3 run.py kb stats
python3 run.py kb delete 3
"""

import sys
import os
import json
import argparse

# Colour helpers (no imports needed -- just ANSI)
R  = "\033[91m"
Y  = "\033[93m"
G  = "\033[92m"
CY = "\033[96m"
B  = "\033[1m"
D  = "\033[2m"
RS = "\033[0m"

def _sev(s):
    return {
        "CRITICAL": R+B, "HIGH": R, "MEDIUM": Y, "LOW": G, "INFO": CY
    }.get(s, RS)

def banner():
    print(f"{CY}{B}  APISec  --  OWASP API Top 10 Agent{RS}")
    print(f"{D}  Author:Ediongs Technologies{RS}\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SCAN COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def cmd_scan(args):
    from urllib.parse import urlparse
    import urllib3; urllib3.disable_warnings()

    from apisec.identity import build as build_identity
    from apisec         import agent, knowledge as kb
    from apisec.recon   import discover as recon_discover
    from apisec.login   import browser_login

    base_url = args.url.rstrip("/")
    if not urlparse(base_url).scheme:
        print(f"{R}Error: include https:// in the URL{RS}"); sys.exit(1)

    # Ingest knowledge before scan if --learn-url or --learn-text provided
    if args.learn_url:
        print(f"\n{B}[LEARN BEFORE SCAN]{RS} {args.learn_url}")
        try:
            r = kb.add_url(args.learn_url)
            if r["status"] == "ok":
                print(f"  {G}v{RS} {r['message']}")
            else:
                print(f"  {Y}!{RS} {r['message']}")
        except Exception as e:
            print(f"  {R}X Failed: {e}{RS}")

    if args.learn_text:
        print(f"\n{B}[LEARN BEFORE SCAN]{RS} Ingesting text...")
        r = kb.add_text(args.learn_text, title=args.learn_title or "Pre-scan note")
        print(f"  {G}v{RS} {r['message']}")

    # -- RECONNAISSANCE --
    recon_report = recon_discover(base_url)
    print(f"{B}Target:{RS}  {base_url}")

    # -- IDENTITY SETUP --
    print(f"\n{B}[IDENTITY SETUP]{RS}")

    # Browser login (alternative to Burp -- just needs creds)
    if args.login:
        print(f"  Using browser login instead of Burp XML")
        attacker = browser_login(
            login_url  = args.login,
            username   = args.login_user or "admin@test.com",
            password   = args.login_pass or "password",
            otp        = args.login_otp,
        )
        # Browser login covers attacker. Victim is still from Burp/manual if provided.
        victim = build_identity(
            label    = "victim",
            burp_path= args.victim_burp,
            base_url = base_url,
            manual   = args.victim_headers,
        )
    else:
        # Build attacker identity (Burp base + manual override)
        attacker = build_identity(
            label    = "attacker",
            burp_path= args.attacker_burp or args.burp,
            base_url = base_url,
            manual   = args.attacker_headers,
        )

        # Build victim identity
        victim = build_identity(
            label    = "victim",
            burp_path= args.victim_burp,
            base_url = base_url,
            manual   = args.victim_headers,
        )

    # Collect endpoints from all sources (recon endpoints included)
    eps = agent.collect_endpoints(
        base_url  = base_url,
        burp_path = args.burp,
        spec_path = args.spec,
        attacker  = attacker if attacker.is_authenticated() else None,
        recon_eps = recon_report.get("endpoints", []) if recon_report else None,
    )

    if not eps:
        print(f"{Y}No endpoints found. Try --burp or --spec.{RS}")
        sys.exit(0)

    # Harvest victim resource IDs for IDOR testing
    victim_ctx = {}
    if victim.is_authenticated():
        victim_ctx = agent.harvest_victim_ids(eps, victim, base_url)

    # Load knowledge base context + run agent with recon context
    print(f"\n{B}[KNOWLEDGE BASE]{RS}")
    breach_key = args.breach_key or os.environ.get("BREACHCOLLECTION_API_KEY", "")

    exploit_findings = []
    if args.exploit_only or args.exploit:
        mode = "exploit-only" if args.exploit_only else "exploit"
        print(f"{CY}  {mode} mode -- running exploitation tests (SQLi, XSS, SSRF, ...){RS}")
        from apisec.exploit import run_all as run_exploits
        auth_headers = {}
        auth_cookies = {}
        victim_headers = {}
        victim_cookies = {}
        if attacker and attacker.is_authenticated():
            auth_headers.update(attacker.headers)
            auth_cookies.update(attacker.cookies)
        if victim and victim.is_authenticated():
            victim_headers.update(victim.headers)
            victim_cookies.update(victim.cookies)
        exploit_findings = run_exploits(
            base_url=base_url, endpoints=eps,
            attacker_headers=auth_headers, attacker_cookies=auth_cookies,
            victim_headers=victim_headers, victim_cookies=victim_cookies,
        )

    if args.exploit_only:
        agent.findings = exploit_findings
    elif args.auth_only:
        # Auth-only mode: skip main LLM agent, run auth sub-agent directly
        print(f"{CY}  Auth-only mode -- running auth tester without LLM{RS}")
        from apisec.orchestrator import Orchestrator
        auth_headers = {}
        auth_cookies = {}
        if attacker and attacker.is_authenticated():
            auth_headers.update(attacker.headers)
            auth_cookies.update(attacker.cookies)
        orch = Orchestrator(base_url=base_url, provider=args.model,
                            attacker=attacker, victim=victim,
                            breach_api_key=breach_key,
                            wordlist=args.wordlist or "")
        orch.run_auth_agent(auth_headers, auth_cookies)
        orch.report_summary()
        agent.findings = orch.all_findings
    else:
        try:
            agent.run(base_url, eps, attacker, victim, victim_ctx,
                      provider=args.model, recon_report=recon_report,
                      auth_only=False, breach_key=breach_key,
                      wordlist=args.wordlist or "", sub_agents=not args.no_sub_agents)
        except RuntimeError as e:
            if "API_KEY" in str(e) or "api key" in str(e).lower():
                print(f"{R}No LLM API key set.{RS}")
                print(f"  Set GROQ_API_KEY, ANTHROPIC_API_KEY, or DEEPSEEK_API_KEY")
                print(f"  Or use --auth-only to run auth tests without LLM")
                sys.exit(1)
            raise
        if args.exploit:
            agent.findings.extend(exploit_findings)

    # Print final report
    _print_report(base_url, agent.findings, agent.operations, agent._op_n, recon_report)


def _print_report(base_url, findings, operations, total_ops, recon_report=None):
    print(f"\n{'='*66}")
    print(f"{B}  REPORT -- {base_url}{RS}")
    print(f"{'='*66}")
    print(f"  Total probes : {total_ops}")
    print(f"  Findings     : {len(findings)}")

    if not findings:
        print(f"\n  {G}No confirmed vulnerabilities.{RS}")
        print(f"  {D}Tip: add --attacker-burp and --victim-burp for deeper IDOR testing.{RS}")
    else:
        print()
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            bucket = [f for f in findings if f["severity"]==sev]
            if not bucket: continue
            col = _sev(sev)
            print(f"{col}  -- {sev} ({len(bucket)}) --{RS}")
            for f in bucket:
                title = f.get("title") or f.get("finding", "?")
                print(f"  {col}*{RS} {title}")
                owasp = f.get("owasp", f.get("owasp_category", ""))
                if owasp:
                    print(f"    {D}{owasp}{RS}")
                desc = f.get("description") or f.get("detail", "")
                print(f"    {desc[:120]}")
                fix = f.get("remediation") or f.get("fix", "")
                if fix:
                    print(f"    Fix: {fix[:100]}")
                ops = f.get("op_ids", [])
                if ops:
                    print(f"    Proof ops: {', '.join(ops)}")
                print()

    _print_recommendations(findings, recon_report)

    out = "findings.json"
    with open(out,"w") as fh:
        json.dump({"target":base_url,"findings":findings,"operations":operations},fh,indent=2)
    print(f"  {CY}Evidence saved -> {out}{RS}")
    print(f"  {D}Each op_id has the full request + response. Verify manually before reporting.{RS}\n")


def _print_recommendations(findings, recon_report=None):
    """Generate actionable next steps based on findings."""
    tips = []

    owasp_map = {
        "API1": "BOLA/IDOR",
        "API2": "Broken Auth",
        "API3": "Mass Assignment",
        "API4": "Resource Exhaustion",
        "API5": "Function Auth",
        "API6": "Business Logic",
        "API7": "SSRF",
        "API8": "Misconfiguration",
        "API9": "Inventory",
        "API10": "Unsafe Consumption",
    }

    severity_order = {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "INFO":4}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.get("severity","INFO"), 9))

    for f in findings_sorted:
        sev = f.get("severity", "INFO")
        title = f.get("title", "")
        owasp = f.get("owasp", "")
        desc = f.get("description", "")
        remediation = f.get("remediation", "")

        cat = ""
        for code, name in owasp_map.items():
            if code in owasp:
                cat = name
                break

        if sev in ("CRITICAL", "HIGH"):
            if "IDOR" in title or "BOLA" in title or "access" in title.lower():
                tips.append(f"[{sev}] {title} -- Check if other users' data is accessible via the same pattern. Test sequential IDs.")
            if "auth" in title.lower() or "bypass" in title.lower():
                tips.append(f"[{sev}] {title} -- Try horizontal escalation with other known users. Check if rate limiting is missing.")
            if "mass" in title.lower() or "assignment" in title.lower():
                tips.append(f"[{sev}] {title} -- Look for other endpoints that accept similar input structures. Test isAdmin/role fields.")

        if "exposed" in title.lower() or "leak" in title.lower():
            tips.append(f"[{sev}] {title} -- Verify if exposed data contains actionable credentials. Try against other endpoints.")

        if remediation:
            tips.append(f"[ACTION] {remediation[:120]}")

    if recon_report:
        gql = recon_report.get("graphql")
        if gql and gql.get("is_graphql") and not any("graphql" in str(f).lower() for f in findings):
            tips.append("[INFO] GraphQL endpoint found but not tested by agent. Run again with --model claude for better coverage.")
        if gql and gql.get("introspection") and not any("introspection" in str(f).lower() for f in findings):
            tips.append("[MEDIUM] GraphQL introspection is open. Report this as an information disclosure.")
        subs = recon_report.get("subdomains", [])
        if subs:
            tips.append(f"[INFO] {len(subs)} subdomains found. Extend the scan: python run.py scan https://<subdomain>")

    if not tips:
        tips.append("[INFO] No specific findings to act on. Try with --attacker-burp and --victim-burp for IDOR coverage.")
    else:
        # Deduplicate
        seen = set()
        unique = []
        for t in tips:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        tips = unique

    print(f"\n{D}{'='*66}{RS}")
    print(f"{B}{Y}  RECOMMENDED NEXT STEPS{RS}")
    print(f"{D}{'='*66}{RS}")
    for t in tips[:15]:
        print(f"  >{RS} {t}")
    if len(tips) > 15:
        print(f"  {D}... and {len(tips)-15} more suggestions{RS}")
    print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LEARN COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def cmd_learn(args):
    from apisec import knowledge as kb

    if args.text:
        print(f"\n{B}[LEARN]{RS} Ingesting text...")
        r = kb.add_text(args.text, title=args.title or "Manual note")
        print(f"  {G}v{RS} {r['message']}")
        if r.get("tags"):
            print(f"  Tags: {', '.join(r['tags'])}")
        return

    if not args.source:
        print(f"{R}Error: provide a URL or use --text{RS}"); sys.exit(1)

    print(f"\n{B}[LEARN]{RS} {args.source}")
    try:
        r = kb.add_url(args.source)
        if r["status"] == "ok":
            print(f"  {G}v{RS} {r['message']}")
            if r.get("tags"):
                print(f"  Tags: {', '.join(r['tags'])}")
        else:
            print(f"  {Y}!{RS} {r['message']}")
    except Exception as e:
        print(f"  {R}X Failed: {e}{RS}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# KB MANAGEMENT COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def cmd_kb(args):
    from apisec import knowledge as kb

    if args.kb_cmd == "list":
        sources = kb.list_all()
        if not sources:
            print(f"\n  {Y}Knowledge base is empty.{RS}")
            print(f"  Add resources: python3 run.py learn https://url.com")
            return
        print(f"\n{B}Knowledge Base -- {len(sources)} sources{RS}\n")
        for s in sources:
            print(f"  {CY}[{s['id']}]{RS} {s['title'][:65]}")
            print(f"       {D}{s['source_type']} | {s['chunks']} chunks | {s['added_at'][:10]}{RS}")
            if s.get("url"):
                print(f"       {s['url'][:70]}")
            print()

    elif args.kb_cmd == "search":
        if not args.query:
            print(f"{R}Provide a search query{RS}"); sys.exit(1)
        print(f"\n{B}Search:{RS} '{args.query}'\n")
        results = kb.search(args.query, top_k=5)
        if not results:
            print(f"  {Y}No results.{RS}")
            return
        for i,r in enumerate(results,1):
            print(f"{CY}[{i}] {r['title']}{RS}")
            print(f"    {D}Type: {r['source_type']} | Tags: {r['tags']} | Score: {r['score']}{RS}")
            print(f"    {r['text'][:250].replace(chr(10),' ')}...")
            print()

    elif args.kb_cmd == "stats":
        s = kb.stats()
        print(f"\n{B}Knowledge Base Stats{RS}")
        print(f"  Sources : {s['sources']}")
        print(f"  Chunks  : {s['chunks']}")
        for t,n in s["by_type"].items():
            print(f"  {t:12} {n}")

    elif args.kb_cmd == "delete":
        if not args.id:
            print(f"{R}Provide --id{RS}"); sys.exit(1)
        kb.delete(args.id)
        print(f"  {G}v Deleted source {args.id}{RS}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    banner()

    p = argparse.ArgumentParser(
        prog="run.py",
        description="APISec -- OWASP API Top 10 Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command")

    # -- scan --
    sc = sub.add_parser("scan", help="Scan a target for API vulnerabilities")
    sc.add_argument("url",                  help="Target base URL e.g. https://api.target.com")
    sc.add_argument("--burp",               help="Burp XML export (endpoint discovery + traffic)", default=None)
    sc.add_argument("--attacker-burp",      help="Burp XML to extract ATTACKER identity from", default=None)
    sc.add_argument("--victim-burp",        help="Burp XML to extract VICTIM identity from", default=None)
    sc.add_argument("--attacker-headers",
                    help="Attacker auth headers (raw HTTP format, JSON, or curl -H style). "
                         "Example: 'Authorization: Bearer eyJ...\\nX-CSRF-Token: abc'",
                    default=None)
    sc.add_argument("--victim-headers",     help="Victim auth headers (same formats)", default=None)
    sc.add_argument("--spec",               help="OpenAPI/Swagger JSON spec file", default=None)
    sc.add_argument("--learn-url",   help="Ingest a URL (blog, writeup, video) before scanning", default=None)
    sc.add_argument("--learn-text",  help="Ingest raw text/notes before scanning", default=None)
    sc.add_argument("--learn-title", help="Title for --learn-text entries", default=None)
    sc.add_argument("--login",        help="Browser login URL (alternative to Burp XML)", default=None)
    sc.add_argument("--login-user",   help="Username for browser login", default=None)
    sc.add_argument("--login-pass",   help="Password for browser login", default=None)
    sc.add_argument("--login-otp",    help="OTP/2FA code for browser login", default=None)
    sc.add_argument("--auth-only",
                    help="Skip API scanning, only run auth testing sub-agent",
                    action="store_true", default=False)
    sc.add_argument("--no-sub-agents",
                    help="Disable sub-agent architecture (run only main agent)",
                    action="store_true", default=False)
    sc.add_argument("--breach-key",
                    help="BreachCollection API key for credential stuffing",
                    default=None)
    sc.add_argument("--wordlist",
                    help="Path to wordlist for path brute-force",
                    default=None)
    sc.add_argument("--model",
                    help="LLM provider (default: groq). Options: groq, claude, deepseek",
                    default="groq", choices=["groq","claude","deepseek"])
    sc.add_argument("--exploit-only",
                    help="Skip main agent, only run exploitation tests (SQLi, XSS, SSRF, etc.)",
                    action="store_true", default=False)
    sc.add_argument("--exploit",
                    help="Run exploitation tests alongside main scan",
                    action="store_true", default=False)

    # -- learn --
    lc = sub.add_parser("learn", help="Add knowledge to the knowledge base")
    lc.add_argument("source",  nargs="?",   help="URL to ingest (blog, YouTube, LinkedIn, any)")
    lc.add_argument("--text",               help="Raw text or notes to ingest", default=None)
    lc.add_argument("--title",              help="Title for --text entries", default=None)

    # -- kb --
    kc = sub.add_parser("kb", help="Manage the knowledge base")
    kb_sub = kc.add_subparsers(dest="kb_cmd")
    kb_sub.add_parser("list",   help="List all sources")
    ks = kb_sub.add_parser("search", help="Search the knowledge base")
    ks.add_argument("query", help="Search query")
    kb_sub.add_parser("stats",  help="Show stats")
    kd = kb_sub.add_parser("delete", help="Delete a source by ID")
    kd.add_argument("--id", type=int, help="Source ID to delete")

    args = p.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "learn":
        cmd_learn(args)
    elif args.command == "kb":
        if not args.kb_cmd:
            kc.print_help()
        else:
            cmd_kb(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
