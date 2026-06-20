# APISec — OWASP API Top 10 Agent
**Bee / EdiongTechnologies**

An AI-powered API security scanner that hunts for OWASP API Top 10 vulnerabilities.
Gets smarter over time as you feed it blog posts, YouTube videos, and research.

---

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/apisec.git
cd apisec
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here
```

---

## Scanning

```bash
# Basic — auto-discovers endpoints
python3 run.py scan https://target.com

# With Burp export (real observed traffic — best results)
python3 run.py scan https://target.com --burp traffic.xml

# Full IDOR testing — two accounts
python3 run.py scan https://target.com \
  --attacker-burp attacker.xml \
  --victim-burp   victim.xml

# Manual auth headers (JWT, cookies, CSRF, API keys — any format)
python3 run.py scan https://target.com \
  --attacker-headers "Authorization: Bearer eyJ...
X-CSRF-Token: abc123
Cookie: .AspNetCore.Session=xyz; .AspNetCore.Antiforgery=tok"

# Burp + spec + two accounts (maximum coverage)
python3 run.py scan https://target.com \
  --burp traffic.xml \
  --attacker-burp attacker.xml \
  --victim-burp victim.xml \
  --spec openapi.json
```

---

## Knowledge Base (gets smarter over time)

```bash
# Add a blog post or writeup
python3 run.py learn https://brutecat.com/articles/hacking-google

# Add a YouTube security talk (auto-transcribes)
python3 run.py learn https://www.youtube.com/watch?v=VIDEO_ID

# Add a LinkedIn article
python3 run.py learn https://linkedin.com/pulse/article

# Add your own notes
python3 run.py learn --text "NET Core uses X-CSRF-Token + .AspNetCore.Antiforgery cookie together"

# Manage
python3 run.py kb list
python3 run.py kb search "NET Core auth bypass"
python3 run.py kb stats
python3 run.py kb delete --id 3
```

---

## How It Works

```
run.py
  ├── scan → apisec/identity.py   (extracts auth from Burp / manual paste)
  ├── scan → apisec/agent.py      (discovers endpoints, runs Claude agent loop)
  │            └── apisec/knowledge.py  (searches KB, injects relevant techniques)
  └── learn / kb → apisec/knowledge.py (ingest + manage knowledge)
```

Every scan:
1. Extracts your full auth identity from Burp XML (cookies, JWT, CSRF, anything)
2. Searches the knowledge base for relevant attack techniques
3. Injects that knowledge into the Claude agent's context
4. Agent probes every endpoint three ways: unauthenticated, attacker, IDOR variants
5. Saves all evidence to `findings.json` for manual verification

---

## Bug Bounty Programs That Allow Automated Scanning

Only scan programs that **explicitly allow it** in their policy:

| Platform   | Where to check                          |
|------------|------------------------------------------|
| HackerOne  | Policy tab → "Testing Policy" section   |
| Bugcrowd   | Program brief → Allowed Testing Methods |
| YesWeHack  | Rules of Engagement in each program     |
| Immunefi   | Scope tab → check for automation notes  |

Look for: *"automated scanning allowed"* or *"active testing permitted"*.
Avoid: programs that say *"no automated tools"* or *"no scanners"*.

---

## Output

Results print to terminal in real time.
Full evidence (every request + response) saved to `findings.json`.
Each finding links to `op_ids` — replay any request to verify before reporting.

---

## Project Structure

```
apisec/
  __init__.py     Package marker
  identity.py     Auth extraction (JWT, cookies, CSRF, .NET, anything)
  knowledge.py    Persistent knowledge base (SQLite)
  agent.py        Claude agent loop + endpoint discovery
  knowledge.db    Auto-created on first learn command
run.py            ← The only file you run
requirements.txt
README.md
.gitignore
```
