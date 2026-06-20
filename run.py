#!/usr/bin/env python3
"""
run.py — APISec Agent
The ONLY file you run. Everything else is internal.
Bee / EdiongTechnologies

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCANNING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Basic scan (auto-discovers endpoints)
python3 run.py scan https://target.com

# With Burp export (real observed traffic — best results)
python3 run.py scan https://target.com --burp traffic.xml

# With attacker + victim accounts (full IDOR testing)
python3 run.py scan https://target.com \
  --attacker-burp attacker.xml \
  --victim-burp   victim.xml

# Manual auth (paste headers directly — any format)
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

# Colour helpers (no imports needed — just ANSI)
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
    print(f"""
{CY}{B}
 █████╗ ██████╗ ██╗███████╗███████╗ ██████╗
██╔══██╗██╔══██╗██║██╔════╝██╔════╝██╔════╝
███████║██████╔╝██║███████╗█████╗  ██║
██╔══██║██╔═══╝ ██║╚════██║██╔══╝  ██║
██║  ██║██║     ██║███████║███████╗╚██████╗
╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝
{RS}{D}  OWASP API Top 10 Agent — Bee / EdiongTechnologies{RS}
""")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SCAN COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def cmd_scan(args):
    from urllib.parse import urlparse
    import urllib3; urllib3.disable_warnings()

    from apisec.identity import build as build_identity
    from apisec         import agent

    base_url = args.url.rstrip("/")
    if not urlparse(base_url).scheme:
        print(f"{R}Error: include https:// in the URL{RS}"); sys.exit(1)

    print(f"{B}Target:{RS}  {base_url}")
    print(f"\n{B}[IDENTITY SETUP]{RS}")

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

    # Collect endpoints from all sources
    eps = agent.collect_endpoints(
        base_url  = base_url,
        burp_path = args.burp,
        spec_path = args.spec,
        attacker  = attacker if attacker.is_authenticated() else None,
    )

    if not eps:
        print(f"{Y}No endpoints found. Try --burp or --spec.{RS}")
        sys.exit(0)

    # Harvest victim resource IDs for IDOR testing
    victim_ctx = {}
    if victim.is_authenticated():
        victim_ctx = agent.harvest_victim_ids(eps, victim, base_url)

    # Load knowledge base context + run agent
    print(f"\n{B}[KNOWLEDGE BASE]{RS}")
    agent.run(base_url, eps, attacker, victim, victim_ctx, provider=args.model)

    # Print final report
    _print_report(base_url, agent.findings, agent.operations, agent._op_n)


def _print_report(base_url, findings, operations, total_ops):
    print(f"\n{'═'*66}")
    print(f"{B}  REPORT — {base_url}{RS}")
    print(f"{'═'*66}")
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
            print(f"{col}  ── {sev} ({len(bucket)}) ──{RS}")
            for f in bucket:
                print(f"  {col}●{RS} {f['title']}")
                print(f"    {D}{f['owasp']}{RS}")
                print(f"    {f['description'][:120]}")
                print(f"    Fix: {f['remediation'][:100]}")
                print(f"    Proof ops: {', '.join(f['op_ids'])}")
                print()

    out = "findings.json"
    with open(out,"w") as fh:
        json.dump({"target":base_url,"findings":findings,"operations":operations},fh,indent=2)
    print(f"  {CY}Evidence saved → {out}{RS}")
    print(f"  {D}Each op_id has the full request + response. Verify manually before reporting.{RS}\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LEARN COMMAND
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def cmd_learn(args):
    from apisec import knowledge as kb

    if args.text:
        print(f"\n{B}[LEARN]{RS} Ingesting text...")
        r = kb.add_text(args.text, title=args.title or "Manual note")
        print(f"  {G}✓{RS} {r['message']}")
        if r.get("tags"):
            print(f"  Tags: {', '.join(r['tags'])}")
        return

    if not args.source:
        print(f"{R}Error: provide a URL or use --text{RS}"); sys.exit(1)

    print(f"\n{B}[LEARN]{RS} {args.source}")
    try:
        r = kb.add_url(args.source)
        if r["status"] == "ok":
            print(f"  {G}✓{RS} {r['message']}")
            if r.get("tags"):
                print(f"  Tags: {', '.join(r['tags'])}")
        else:
            print(f"  {Y}⚠{RS} {r['message']}")
    except Exception as e:
        print(f"  {R}✗ Failed: {e}{RS}")


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
        print(f"\n{B}Knowledge Base — {len(sources)} sources{RS}\n")
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
        print(f"  {G}✓ Deleted source {args.id}{RS}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    banner()

    p = argparse.ArgumentParser(
        prog="run.py",
        description="APISec — OWASP API Top 10 Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command")

    # ── scan ──
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
    sc.add_argument("--model",
                    help="LLM provider to use (default: groq). Options: groq, claude",
                    default="groq", choices=["groq","claude"])

    # ── learn ──
    lc = sub.add_parser("learn", help="Add knowledge to the knowledge base")
    lc.add_argument("source",  nargs="?",   help="URL to ingest (blog, YouTube, LinkedIn, any)")
    lc.add_argument("--text",               help="Raw text or notes to ingest", default=None)
    lc.add_argument("--title",              help="Title for --text entries", default=None)

    # ── kb ──
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
