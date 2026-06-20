# APISec — OWASP API Top 10 Agent

An AI-powered autonomous API security scanner. Discovers endpoints, dumps GraphQL schemas, checks 30+ leak patterns, runs 9 external recon tools, then deploys an LLM agent (Groq/Claude) to probe for OWASP API Top 10 vulnerabilities.

Gets smarter over time — feed it blog posts, YouTube videos, and writeups via `--learn-url`.

---

## What It Does

### Reconnaissance (10 phases)

| Phase | What |
|-------|------|
| Tech Detection | 70+ signatures — React, Next.js, AWS, Cloudflare, GraphQL, Django, etc. |
| Common Paths | 60+ API endpoints (/api/v1, /graphql, /swagger.json, /actuator, /health...) |
| GraphQL Introspection | Pings /graphql endpoints, runs full introspection, parses schema (queries, mutations, input types, enums) |
| Robots & Sitemap | Extracts paths from robots.txt, sitemap.xml, security.txt |
| Full Crawl | Crawls homepage for links, forms, inline JS API calls, JSON-LD |
| Wayback Machine | Fetches 100 historical endpoints from web.archive.org |
| CORS Preflight | Tests 3 malicious origins (evil.com, null, attacker.com) on every endpoint |
| Supply Chain Audit | Detects 50+ third-party services (Google Analytics, Stripe, Sentry, Auth0...) |
| Security Headers | Checks 8 headers — HSTS, CSP, XFO, CORS, Referrer-Policy, etc. |
| Data Leakage | Scans for 30+ patterns — AWS keys, JWTs, private keys, internal IPs, stack traces, emails |
| External Tools (step 10) | Auto-runs subfinder, httpx, katana, nuclei, naabu, ffuf, gau, dalfox, sqlmap if on PATH |

### Agent Loop (LLM-powered)

After recon, the agent (Groq by default, Claude optional) autonomously:

- Probes every discovered endpoint 3 ways: **unauthenticated → attacker → victim (IDOR)**
- Tests all OWASP API Top 10 categories via structured prompts
- Reports confirmed vulnerabilities with full request/response evidence
- Suggests next steps when fishy things are found

### GraphQL Attack Surface

When a GraphQL endpoint is found, the agent gets schema context + targeted attack guidance:

- Introspection leak detection
- Mutations to test without auth
- Batch/N+1 attack vectors
- Mass assignment in mutation inputs
- Alias/field-duplication abuse

### Knowledge Base (Grows Forever)

Ingest any URL (blog, YouTube, LinkedIn, writeup) before a scan and the extracted techniques are injected into the agent's context automatically.

---

## Setup

### Prerequisites

- Python 3.10+
- `pip install -r requirements.txt`

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/apisec.git
cd apisec
pip install -r requirements.txt
```

### 2. LLM Provider

**Groq (default — free tier):**

```bash
export GROQ_API_KEY=gsk_your_key_here
```

Get a key at https://console.groq.com (free — 100K tokens/day, enough for small-to-medium targets).

**Claude (optional — no rate limits):**

```bash
export ANTHROPIC_API_KEY=sk-ant-your_key_here
# Then pass --model claude on scan
```

### 3. Optional — External Tools (Kali/Linux)

Tools auto-run during step 10 if found on PATH:

```bash
# Install projectdiscovery tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest

# sqlmap
apt install sqlmap
```

### 4. Optional — Playwright Browser Login

```bash
pip install playwright
playwright install chromium
```

Then use `--login` flag instead of Burp XML.

### Windows Notes

- Works on Windows with cp1252 terminal — Unicode symbols have ASCII fallbacks
- External tools (step 10) require WSL or manual install — skip if not present
- `playwright install chromium` works on Windows too

---

## Usage

### Scan

```bash
# Basic — auto-discovers endpoints
python3 run.py scan https://target.com

# With Burp export (real observed traffic — best coverage)
python3 run.py scan https://target.com --burp traffic.xml

# Full IDOR testing — two accounts
python3 run.py scan https://target.com \
  --attacker-burp attacker.xml \
  --victim-burp   victim.xml

# Manual auth headers (JWT, cookies, API keys)
python3 run.py scan https://target.com \
  --attacker-headers "Authorization: Bearer eyJ...
X-CSRF-Token: abc123
Cookie: session=xyz"

# Use Claude instead of Groq
python3 run.py scan https://target.com --model claude

# Browser login (alternative to Burp XML)
python3 run.py scan https://target.com \
  --login https://target.com/login \
  --login-user admin@test.com \
  --login-pass SuperSecurePass123

# Pre-load knowledge before scan
python3 run.py scan https://target.com \
  --learn-url https://example.com/graphql-security-writeup

# Maximum coverage
python3 run.py scan https://target.com \
  --burp traffic.xml \
  --attacker-burp attacker.xml \
  --victim-burp victim.xml \
  --spec openapi.json \
  --model claude
```

### Learn (Knowledge Base)

```bash
# Blog post or writeup
python3 run.py learn https://example.com/api-security-article

# YouTube security talk
python3 run.py learn https://www.youtube.com/watch?v=VIDEO_ID

# Raw text
python3 run.py learn --text "NET Core uses X-CSRF-Token + .AspNetCore.Antiforgery"

# Manage
python3 run.py kb list
python3 run.py kb search "JWT bypass"
python3 run.py kb stats
python3 run.py kb delete --id 3
```

---

## Deployment

| Where | Best for | Notes |
|-------|----------|-------|
| **Kali VPS** | Full external tool support (step 10) | Install all Go tools + sqlmap |
| **Docker (Linux)** | CI/CD / staging envs | Python slim + pip install |
| **GitLab CI / GitHub Actions** | Scan staging before release | Active scanning — don't target prod |
| **Local dev machine** | Testing your own APIs | Skips step 10 without Kali tools |
| **Windows** | Dev testing | Works, step 10 needs WSL |

### Production Considerations

- **Groq free tier** hits 100K token/day limit mid-scan on medium targets — use `--model claude` for serious work
- **Do not** run against production without explicit approval (active scanning triggers WAFs/IDP)
- Best for **bug bounty recon** after manual target scope review

---

## Architecture

```
run.py
  scan → apisec/recon.py     10-phase recon + GraphQL introspection
       → apisec/identity.py   Auth extraction (Burp XML, manual, browser)
       → apisec/agent.py      LLM agent loop + endpoint probing
         ├── apisec/graphql.py  Schema parser + attack guide
         ├── apisec/knowledge.py SQLite KB (persistent)
         ├── apisec/login.py    Playwright browser login
         └── apisec/llm.py      Groq/Claude adapter
  learn/kb → apisec/knowledge.py
```

### Key Files

| File | Purpose |
|------|---------|
| `run.py` | Single entry point — scan, learn, kb subcommands |
| `apisec/recon.py` | 10-phase reconnaissance + external tool integration |
| `apisec/agent.py` | Agent loop — calls LLM, probes endpoints, reports findings |
| `apisec/graphql.py` | GraphQL introspection, schema parser, fuzzing payloads |
| `apisec/identity.py` | Auth extraction from Burp XML or manual headers |
| `apisec/login.py` | Playwright browser login — alternative to Burp |
| `apisec/llm.py` | Unified Groq/Claude adapter |
| `apisec/knowledge.py` | Persistent SQLite knowledge base |
| `apisec/term.py` | Terminal-aware Unicode/ASCII symbols (cross-platform) |

---

## Output

Results print to terminal in real time with color-coded severity.

```
  [op_001] GET    https://api.target.com/api/v1/users/me  200  [UNAUTH_200]
  [op_002] POST   https://api.target.com/api/v1/users     403

  * [HIGH] IDOR in /api/v1/users/1
     API1:2023 BOLA
     Attacker can access victim profile by changing user ID
     Fix: Implement proper authorization checks
     Proof ops: op_003, op_004

  > [SUGGESTIONS]
  > GraphQL introspection is open. Dump the full schema.
  > 2 subdomains found. Scan each with run.py.
```

Full evidence (every request + response) saved to `findings.json`. Each finding links to `op_ids` for manual verification before reporting.

---

## Bug Bounty Guidelines

Only scan programs that explicitly allow automated testing:

| Platform | Check |
|----------|-------|
| HackerOne | Policy tab → "Testing Policy" |
| Bugcrowd | Program brief → Allowed Testing Methods |
| YesWeHack | Rules of Engagement |
| Immunefi | Scope tab → automation notes |

Look for: *"automated scanning allowed"* or *"active testing permitted"*.
Avoid: *"no automated tools"* or *"no scanners"*.

---

## License

MIT
