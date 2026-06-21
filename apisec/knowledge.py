"""
apisec/knowledge.py
Persistent knowledge base. Grows forever on disk.
Ingests: blog posts, YouTube videos, LinkedIn, raw text, any URL.
Searched automatically before every scan.
"""

import os
import re
import json
import sqlite3
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import Optional

import httpx
from bs4 import BeautifulSoup

try:
    from youtube_transcript_api import YouTubeTranscriptApi
    YOUTUBE_OK = True
except ImportError:
    YOUTUBE_OK = False


# -- Config --------------------------------------------------------
DB_PATH    = os.path.join(os.path.dirname(__file__), "knowledge.db")
CHUNK_SIZE = 800
OVERLAP    = 100

# -- Security topic detector ---------------------------------------
TOPICS = {
    "BOLA/IDOR":        r'\b(idor|bola|object.level|insecure.direct|broken.object)\b',
    "Auth":             r'\b(auth|jwt|token|bearer|session|cookie|login|oauth|saml|sso)\b',
    "Mass Assignment":  r'\b(mass.?assign|parameter.?pollut|over.?post|binding)\b',
    "SSRF":             r'\b(ssrf|server.side.request|internal.request|metadata.aws)\b',
    "Injection":        r'\b(inject|sqli|sql.injection|nosql|ldap|xss|template)\b',
    "CSRF":             r'\b(csrf|xsrf|antiforgery|cross.site.request|samesite)\b',
    "Misconfiguration": r'\b(misconfigur|debug|actuator|swagger|cors|server.banner)\b',
    "Rate Limiting":    r'\b(rate.?limit|throttl|brute.?force|lockout)\b',
    "dotNET":           r'\b(asp\.?net|dotnet|\.net.core|c#|csharp|iis|kestrel)\b',
    "GraphQL":          r'\b(graphql|introspect|mutation|resolver)\b',
    "API Key":          r'\b(api.?key|secret.key|client.secret|credential)\b',
    "Business Logic":   r'\b(business.logic|workflow|race.condition|price|discount)\b',
}

def _tags(text: str) -> list[str]:
    tl = text.lower()
    return [t for t, p in TOPICS.items() if re.search(p, tl, re.I)]


# -- Database ------------------------------------------------------
def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT, title TEXT, source_type TEXT,
        added_at TEXT, content_hash TEXT UNIQUE)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS chunks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_id INTEGER, chunk_idx INTEGER,
        text TEXT, tags TEXT,
        FOREIGN KEY(source_id) REFERENCES sources(id))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_src ON chunks(source_id)")
    conn.commit()
    return conn


def _chunk(text: str) -> list[str]:
    text = re.sub(r'\n{3,}', '\n\n', text.strip())
    out, start = [], 0
    while start < len(text):
        c = text[start:start + CHUNK_SIZE].strip()
        if c:
            out.append(c)
        start += CHUNK_SIZE - OVERLAP
    return out


# -- Extractors ----------------------------------------------------
def _youtube(url: str) -> tuple[str, str]:
    if not YOUTUBE_OK:
        raise RuntimeError("pip install youtube-transcript-api")
    parsed = urlparse(url)
    vid = (parsed.path.lstrip("/") if parsed.hostname in ("youtu.be",)
           else parse_qs(parsed.query).get("v", [None])[0])
    if not vid:
        raise ValueError(f"Cannot parse video ID: {url}")
    title = f"YouTube: {vid}"
    try:
        r = httpx.get(f"https://www.youtube.com/oembed?url={url}&format=json", timeout=10)
        if r.status_code == 200:
            title = r.json().get("title", title)
    except Exception:
        pass
    items = YouTubeTranscriptApi().fetch(vid)
    text  = re.sub(r'\[.*?\]', '', " ".join(i.text for i in items))
    return title, re.sub(r'\s+', ' ', text).strip()


def _webpage(url: str) -> tuple[str, str]:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    r = httpx.get(url, headers=headers, timeout=15, follow_redirects=True)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    for t in soup(["script","style","nav","footer","header","aside","iframe","noscript"]):
        t.decompose()
    title = (soup.find("title") or soup).get_text(strip=True)[:120]
    content = None
    for sel in ["article","main",'[role="main"]',".post-content",".article-body",".entry-content"]:
        el = soup.select_one(sel)
        if el and len(el.get_text()) > 400:
            content = el; break
    text = (content or soup.find("body") or soup).get_text(separator="\n", strip=True)
    text = re.sub(r'\n{3,}', '\n\n', re.sub(r'[ \t]{2,}', ' ', text))
    return title, text.strip()


def _source_type(url: str) -> str:
    if not url: return "raw"
    h = urlparse(url).hostname or ""
    if "youtube.com" in h or "youtu.be" in h: return "youtube"
    if "linkedin.com" in h:                    return "linkedin"
    if any(x in h for x in ["medium.com","dev.to","substack.com"]): return "blog"
    if "hackerone.com" in h or "bugcrowd.com" in h: return "bug_report"
    return "web"


# -- Public API ----------------------------------------------------
def add_url(url: str) -> dict:
    """Ingest any URL. Auto-detects YouTube, blog posts, LinkedIn."""
    st = _source_type(url)
    title, text = (_youtube(url) if st == "youtube" else _webpage(url))
    return _store(url=url, title=title, source_type=st, text=text)


def add_text(text: str, title: str = "Manual note") -> dict:
    """Ingest raw text or notes."""
    return _store(url="", title=title, source_type="raw", text=text)


def _store(url, title, source_type, text) -> dict:
    h = hashlib.sha256(text.encode()).hexdigest()
    db = _db()
    ex = db.execute("SELECT id,title FROM sources WHERE content_hash=?", (h,)).fetchone()
    if ex:
        db.close()
        return {"status":"duplicate", "message":f"Already stored: '{ex['title']}'", "tags":[]}

    cur = db.execute(
        "INSERT INTO sources (url,title,source_type,added_at,content_hash) VALUES (?,?,?,?,?)",
        (url, title, source_type, datetime.utcnow().isoformat(), h))
    sid = cur.lastrowid
    chunks = _chunk(text)
    all_tags = set()
    for i, c in enumerate(chunks):
        t = _tags(c)
        all_tags.update(t)
        db.execute("INSERT INTO chunks (source_id,chunk_idx,text,tags) VALUES (?,?,?,?)",
                   (sid, i, c, ",".join(t)))
    db.commit(); db.close()
    return {"status":"ok","title":title,"chunks":len(chunks),
            "tags":list(all_tags),"message":f"Ingested '{title}' -> {len(chunks)} chunks"}


def search(query: str, top_k: int = 5) -> list[dict]:
    """Keyword + tag search. Returns ranked chunks."""
    db   = _db()
    terms = [t.lower() for t in re.split(r'\s+', query) if len(t) > 2]
    qtags = _tags(query)
    rows  = db.execute(
        "SELECT c.*,s.title,s.url,s.source_type FROM chunks c JOIN sources s ON s.id=c.source_id"
    ).fetchall()
    db.close()

    scored = []
    for row in rows:
        tl = row["text"].lower()
        ct = [x.strip() for x in (row["tags"] or "").split(",") if x.strip()]
        kw = sum(1 for t in terms if t in tl)
        tg = sum(2 for t in qtags if t in ct)
        if kw + tg > 0:
            scored.append((kw + tg, dict(row)))
    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:top_k]]


def context_for_scan(target_host: str, auth_type: str) -> str:
    """
    Called automatically at scan start.
    Returns formatted knowledge chunks ready to inject into agent context.
    """
    db = _db()
    total = db.execute("SELECT COUNT(*) as n FROM chunks").fetchone()["n"]
    db.close()
    if total == 0:
        return ""

    queries = [
        "API authentication bypass IDOR broken access control",
        "OWASP API Top 10 attack techniques",
        target_host,
        auth_type,
    ]
    seen, parts = set(), []
    for q in queries:
        if not q.strip():
            continue
        for r in search(q, top_k=3):
            key = r["text"][:80]
            if key not in seen:
                seen.add(key)
                src = f"[{r['source_type'].upper()}] {r['title']}"
                if r.get("url"):
                    src += f" -- {r['url'][:60]}"
                parts.append(f"### {src}\n{r['text']}")

    return "\n\n".join(parts) if parts else ""


def stats() -> dict:
    db = _db()
    s  = db.execute("SELECT COUNT(*) as n FROM sources").fetchone()["n"]
    c  = db.execute("SELECT COUNT(*) as n FROM chunks").fetchone()["n"]
    ty = db.execute("SELECT source_type,COUNT(*) as n FROM sources GROUP BY source_type").fetchall()
    db.close()
    return {"sources": s, "chunks": c, "by_type": {r["source_type"]:r["n"] for r in ty}}


def list_all() -> list[dict]:
    db = _db()
    rows = db.execute("""
        SELECT s.*,COUNT(c.id) as chunks
        FROM sources s LEFT JOIN chunks c ON c.source_id=s.id
        GROUP BY s.id ORDER BY s.added_at DESC""").fetchall()
    db.close()
    return [dict(r) for r in rows]


def delete(source_id: int):
    db = _db()
    db.execute("DELETE FROM chunks WHERE source_id=?", (source_id,))
    db.execute("DELETE FROM sources WHERE id=?", (source_id,))
    db.commit(); db.close()
