"""
apisec/orchestrator.py
Sub-agent orchestrator. Manages multiple specialized LLM agents with memory.
Each sub-agent focuses on a specific testing domain with its own context/tools.
"""

import json
import time
import sqlite3
import os
from urllib.parse import urlparse
from typing import Optional

import httpx

from .llm import LLM, LLMResponse
from .identity import Identity
from .knowledge import context_for_scan, add_text, search
from .term import CHECK, CROSS, WARN, FLAG, ARROW, BULLET
from . import authtest


DB_PATH = os.path.join(os.path.dirname(__file__), "agent_memory.db")


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


# ---------------------------------------------------------------------------
# Agent Memory (persistent SQLite across runs)
# ---------------------------------------------------------------------------

class AgentMemory:
    def __init__(self, agent_name: str, target_domain: str):
        self.agent_name = agent_name
        self.target_domain = target_domain
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_name TEXT,
                    target_domain TEXT,
                    key TEXT,
                    value TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_lookup
                ON agent_memory(agent_name, target_domain, key)
            """)

    def remember(self, key: str, value: str):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO agent_memory (agent_name, target_domain, key, value) "
                "VALUES (?, ?, ?, ?)",
                (self.agent_name, self.target_domain, key, value)
            )

    def recall(self, key: str) -> Optional[str]:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute(
                "SELECT value FROM agent_memory WHERE agent_name=? AND target_domain=? AND key=?",
                (self.agent_name, self.target_domain, key)
            )
            row = cur.fetchone()
            return row[0] if row else None

    def recall_all(self) -> dict:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute(
                "SELECT key, value FROM agent_memory WHERE agent_name=? AND target_domain=?",
                (self.agent_name, self.target_domain)
            )
            return {row[0]: row[1] for row in cur.fetchall()}

    def forget(self, key: str):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "DELETE FROM agent_memory WHERE agent_name=? AND target_domain=? AND key=?",
                (self.agent_name, self.target_domain, key)
            )

    def context_prompt(self) -> str:
        data = self.recall_all()
        if not data:
            return ""
        lines = [f"## {self.agent_name} Memory"]
        for k, v in data.items():
            lines.append(f"- {k}: {v[:200]}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Base Sub-Agent
# ---------------------------------------------------------------------------

class SubAgent:
    def __init__(self, name: str, provider: str, system_prompt: str,
                 target_domain: str = "", memory: bool = True):
        self.name = name
        self.llm = LLM(provider=provider)
        self.system = system_prompt
        self.memory = AgentMemory(name, target_domain) if memory and target_domain else None
        self.findings = []

    def run(self, user_msg: str, tools: list, max_iters: int = 50) -> list[dict]:
        local_findings = []

        mem_context = self.memory.context_prompt() if self.memory else ""
        full_system = self.system
        if mem_context:
            full_system += "\n\n" + mem_context

        resp = self.llm.send(system=full_system, user_msg=user_msg, tools=tools)

        done, iters = False, 0
        while not done and iters < max_iters:
            iters += 1
            if resp.text.strip():
                print(f"  {C.DIM}[{self.name}] {resp.text[:160]}{C.RESET}")

            if not resp.tool_calls:
                break

            tool_results = []
            for tc in resp.tool_calls:
                name = tc["name"]
                inp = tc["input"]
                tid = tc["id"]

                if name == "report_finding":
                    local_findings.append({
                        "title": inp["title"],
                        "severity": inp["severity"],
                        "owasp": inp.get("owasp_category", ""),
                        "description": inp["description"],
                        "remediation": inp.get("remediation", ""),
                        "agent": self.name,
                    })
                    tool_results.append({"tool_use_id": tid, "content": "Logged."})

                elif name == "testing_complete":
                    tool_results.append({"tool_use_id": tid, "content": "Done."})
                    done = True

                elif name == "remember":
                    if self.memory:
                        self.memory.remember(inp["key"], inp["value"])
                    tool_results.append({"tool_use_id": tid, "content": "Remembered."})

                else:
                    tool_results.append({
                        "tool_use_id": tid,
                        "content": json.dumps({"error": f"Unknown tool: {name}"}),
                    })

            if tool_results and not done:
                resp = self.llm.reply(system=full_system, tool_results=tool_results, tools=tools)

        self.findings = local_findings
        return local_findings


# ---------------------------------------------------------------------------
# Specialized Sub-Agents
# ---------------------------------------------------------------------------

def _make_api_agent_system(base_url: str, recon_context: str, kb_context: str) -> str:
    return f"""You are an API security testing agent called "api-scanner". Your ONLY job is to probe REST API endpoints for OWASP API Top 10 vulnerabilities. You have the probe() tool to send HTTP requests.

Target: {base_url}

{recon_context}

{kb_context}

## Your Tools
- probe(method, url, body, identity, extra_headers) - Send HTTP requests
- report_finding(title, severity, owasp_category, description, op_ids, remediation) - Report confirmed vulns
- testing_complete(summary, tested_urls) - Call when done
- remember(key, value) - Save knowledge for future runs

## Protocol
Test every endpoint 3 ways: no auth -> attacker auth -> IDOR with other user IDs.
Report only CONFIRMED vulnerabilities with clear proof.
Do NOT report 401/403/404 responses.
Call testing_complete when ALL endpoints have been tested."""


def _make_auth_agent_system() -> str:
    return """You are an authentication security testing agent called "auth-tester". Your ONLY job is to test authentication mechanisms.

You have Python-based auth testing tools available:
- test_jwt: Analyze JWT tokens for none alg, weak secrets, kid injection
- test_default_credentials: Try common default usernames/passwords
- test_mfa_bypass: Bypass MFA via direct navigation, response manipulation
- test_password_reset: Check reset flow for user enumeration, token leaks
- test_session_management: Check fixation, leakage, entropy
- test_rate_limiting: Check for missing rate limiting on login endpoints
- test_account_lockout: Check lockout mechanisms

Also available:
- breach_stuff: Credential stuffing via BreachCollection API
- path_bruteforce: Discover hidden admin endpoints

Run ALL applicable tests, then report findings.
Call testing_complete when done."""


AGENT_TOOLS = [
    {
        "name": "report_finding",
        "description": "Report a confirmed vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                "owasp_category": {"type": "string"},
                "description": {"type": "string"},
                "op_ids": {"type": "array", "items": {"type": "string"}},
                "remediation": {"type": "string"},
            },
            "required": ["title", "severity", "owasp_category", "description", "op_ids", "remediation"],
        },
    },
    {
        "name": "testing_complete",
        "description": "Call when ALL testing for this agent is done.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "tested_urls": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary", "tested_urls"],
        },
    },
    {
        "name": "remember",
        "description": "Save key information for future runs (e.g. endpoints, credentials, patterns).",
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
        },
    },
]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(
        self,
        base_url: str,
        provider: str = "groq",
        attacker: Optional[Identity] = None,
        victim: Optional[Identity] = None,
        breach_api_key: str = "",
        wordlist: str = "",
    ):
        self.base_url = base_url
        self.provider = provider
        self.attacker = attacker
        self.victim = victim
        self.breach_api_key = breach_api_key
        self.wordlist = wordlist
        self.domain = urlparse(base_url).netloc
        self.all_findings = []

    def run_api_agent(self, eps: list, recon_report: dict = None,
                      victim_ctx: dict = None) -> list[dict]:
        print(f"\n{C.BOLD}[SUB-AGENT] API Scanner{C.RESET}")
        agent = SubAgent("api-scanner", self.provider, "", self.domain)

        recon_lines = ""
        if recon_report:
            parts = []
            if recon_report.get("tech_stack"):
                parts.append(f"Tech Stack: {', '.join(recon_report['tech_stack'])}")
            if recon_report.get("forms"):
                parts.append(f"Forms: {len(recon_report['forms'])} endpoints accepting user input")
            if recon_report.get("supply_chain"):
                services = [s["service"] for s in recon_report["supply_chain"][:10]]
                parts.append(f"Third-party services: {', '.join(services)}")
            if recon_report.get("missing_headers"):
                missing = [h["header"] for h in recon_report["missing_headers"]]
                parts.append(f"Missing security headers: {', '.join(missing)}")
            if recon_report.get("data_leaks"):
                leak_types = set(l["type"] for l in recon_report["data_leaks"])
                parts.append(f"Potential data leaks: {', '.join(leak_types)}")
            if recon_report.get("cors_issues"):
                parts.append(f"CORS Misconfigs: {len(recon_report['cors_issues'])} endpoints")
            if recon_report.get("wayback_urls"):
                parts.append(f"Historical endpoints: {len(recon_report['wayback_urls'])} from Wayback")
            if recon_report.get("graphql") and recon_report["graphql"].get("is_graphql"):
                parts.append("GraphQL endpoint detected")
                if recon_report["graphql"].get("introspection"):
                    parts.append("GraphQL introspection is OPEN")
            if parts:
                recon_lines = "## Recon\n" + "\n".join(f"- {p}" for p in parts)

        kb = context_for_scan(self.domain, self.attacker.auth_type if self.attacker else "none")

        agent.system = _make_api_agent_system(self.base_url, recon_lines, kb)

        ep_list = "\n".join(f"- [{e['method']}] {e['url']} [{e['source']}]" for e in eps[:50])

        auth_lines = []
        if self.attacker and self.attacker.is_authenticated():
            auth_lines.append(f"ATTACKER: {self.attacker.auth_type}")
        else:
            auth_lines.append("ATTACKER: unauthenticated")
        if self.victim and self.victim.is_authenticated():
            auth_lines.append(f"VICTIM:   {self.victim.auth_type}")
        else:
            auth_lines.append("VICTIM:   none")

        victim_ids = ""
        if victim_ctx and victim_ctx.get("victim_ids"):
            victim_ids = "\nKnown victim IDs:\n" + json.dumps(victim_ctx["victim_ids"], indent=2)

        user_msg = f"""Target: {self.base_url}

Auth:
{chr(10).join(auth_lines)}
{victim_ids}

## Endpoints ({len(eps)}):
{ep_list}

Begin. Test every endpoint."""

        api_tools = AGENT_TOOLS + [
            {
                "name": "probe",
                "description": "Send one HTTP request with automatic auth.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]},
                        "url": {"type": "string"},
                        "body": {"type": "object"},
                        "identity": {"type": "string", "enum": ["attacker", "victim", "none"]},
                        "extra_headers": {"type": "object"},
                    },
                    "required": ["method", "url", "identity"],
                },
            },
        ]

        findings = agent.run(user_msg, api_tools)
        self.all_findings.extend(findings)
        return findings

    def run_auth_agent(self, headers: dict, cookies: dict) -> list[dict]:
        print(f"\n{C.BOLD}[SUB-AGENT] Auth Tester{C.RESET}")

        agent = SubAgent("auth-tester", self.provider, _make_auth_agent_system(), self.domain)
        user_msg = f"Run ALL auth tests against {self.base_url}. Auth headers: {list(headers.keys()) if headers else 'none'}, Cookies: {list(cookies.keys()) if cookies else 'none'}"

        auth_tools = AGENT_TOOLS + [
            {
                "name": "run_auth_tests",
                "description": "Run all auth tests (JWT, default creds, MFA bypass, password reset, session mgmt, rate limiting, account lockout). Optionally BreachCollection stuffing and path brute-force.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "jwt": {"type": "boolean", "description": "Test JWT tokens"},
                        "default_creds": {"type": "boolean", "description": "Test default credentials"},
                        "mfa_bypass": {"type": "boolean"},
                        "password_reset": {"type": "boolean"},
                        "session_mgmt": {"type": "boolean"},
                        "rate_limiting": {"type": "boolean"},
                        "breach_stuffing": {"type": "boolean", "description": "Credential stuffing via BreachCollection"},
                        "path_bruteforce": {"type": "boolean", "description": "Brute-force admin paths"},
                    },
                    "required": ["jwt", "default_creds", "mfa_bypass", "password_reset", "session_mgmt", "rate_limiting"],
                },
            },
        ]

        findings = agent.run(user_msg, auth_tools)

        # Also run the Python auth tests directly (deterministic, no LLM cost)
        print(f"\n  {C.CYAN}{ARROW} Running direct auth tests...{C.RESET}")
        try:
            with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
                py_findings = authtest.run_all(
                    client=client,
                    base_url=self.base_url,
                    headers=headers,
                    cookies=cookies,
                    domain=self.domain,
                    breach_api_key=self.breach_api_key,
                    wordlist=self.wordlist,
                )
                for f in py_findings:
                    f["agent"] = "auth-tester"
                findings.extend(py_findings)
        except Exception as e:
            print(f"  {C.RED}{CROSS} Auth test error: {e}{C.RESET}")

        self.all_findings.extend(findings)
        return findings

    def report_summary(self):
        if not self.all_findings:
            return

        print(f"\n{C.BOLD}{'='*60}{C.RESET}")
        print(f"{C.BOLD}  COMBINED FINDINGS ({len(self.all_findings)}){C.RESET}")
        print(f"{C.BOLD}{'='*60}{C.RESET}")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            bucket = [f for f in self.all_findings if f.get("severity") == sev]
            if not bucket:
                continue
            col = _sc(sev)
            print(f"\n{col}  -- {sev} ({len(bucket)}) --{C.RESET}")
            for f in bucket:
                agent_tag = f"{C.DIM}[{f.get('agent','?')}]{C.RESET}" if f.get("agent") else ""
                print(f"  {col}{BULLET}{C.RESET} {agent_tag} {f['title']}")
                print(f"    {C.DIM}{f.get('description','')[:120]}{C.RESET}")
                if f.get("remediation"):
                    print(f"    Fix: {C.DIM}{f['remediation'][:100]}{C.RESET}")
                print()

        self._save_findings()

    def _save_findings(self):
        path = "findings.json"
        try:
            existing = []
            try:
                with open(path, "r") as f:
                    existing = json.load(f).get("findings", [])
            except (json.JSONDecodeError, FileNotFoundError):
                pass

            seen_titles = set(f["title"] for f in existing)
            for f in self.all_findings:
                if f["title"] not in seen_titles:
                    existing.append(f)
                    seen_titles.add(f["title"])

            with open(path, "w") as f:
                json.dump({"target": self.base_url, "findings": existing}, f, indent=2)
            print(f"  {C.CYAN}Findings saved -> {path}{C.RESET}")
        except Exception as e:
            print(f"  {C.RED}Error saving findings: {e}{C.RESET}")
