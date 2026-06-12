#!/usr/bin/env python3
"""Metier — Find your calling, screen out the noise. AI-powered recruiter legitimacy check for career professionals."""

import hashlib
import json
import os
import re
import socket
import sqlite3
from datetime import datetime, timezone
from typing import Literal

import anthropic
import requests as http_requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_from_directory
from pydantic import BaseModel, Field

load_dotenv()

app = Flask(__name__)

# ── LLM provider config ─────────────────────────────────────────────────────────
# Claude is the default. Set LLM_PROVIDER=openai or =grok in .env to switch.

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic").strip().lower()
LLM_MODELS = {
    "anthropic": os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-7"),
    "openai":    os.environ.get("OPENAI_MODEL",    "gpt-4o"),
    "grok":      os.environ.get("GROK_MODEL",      "grok-2-latest"),
}
PROVIDER_LABEL = {"anthropic": "Claude", "openai": "OpenAI", "grok": "Grok"}
_PROVIDER_KEY_ENV = {"anthropic": ("ANTHROPIC_API_KEY",), "openai": ("OPENAI_API_KEY",),
                     "grok": ("XAI_API_KEY", "GROK_API_KEY")}

def llm_available() -> bool:
    """True if an API key is configured for the selected provider. When False,
    Métier runs fully on the deterministic rules engine — no API needed."""
    prov = LLM_PROVIDER if LLM_PROVIDER in LLM_MODELS else "anthropic"
    return any(os.environ.get(k) for k in _PROVIDER_KEY_ENV[prov])

def call_llm(system_prompt: str, user_text: str):
    """Single entry point for the model call. Returns (text, usage_dict).
    Dispatches to Claude (default), OpenAI, or Grok (xAI) based on LLM_PROVIDER."""
    provider = LLM_PROVIDER if LLM_PROVIDER in LLM_MODELS else "anthropic"
    model    = LLM_MODELS[provider]

    if provider == "anthropic":
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=model, max_tokens=6000, thinking={"type": "adaptive"},
            system=[{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": [{"type": "text", "text": user_text}]}],
        )
        text = next(b.text for b in resp.content if b.type == "text")
        u = resp.usage
        usage = {"input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
                 "cache_read_input_tokens": u.cache_read_input_tokens or 0,
                 "cache_creation_input_tokens": u.cache_creation_input_tokens or 0}
        return text, usage

    # OpenAI-compatible path (OpenAI and Grok/xAI both use the OpenAI SDK)
    from openai import OpenAI
    if provider == "grok":
        client = OpenAI(api_key=os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY"),
                        base_url="https://api.x.ai/v1")
    else:
        client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    resp = client.chat.completions.create(
        model=model, max_tokens=6000,
        response_format={"type": "json_object"},
        messages=[{"role": "system", "content": system_prompt},
                  {"role": "user",   "content": user_text}],
    )
    text = resp.choices[0].message.content
    u = getattr(resp, "usage", None)
    usage = {"input_tokens": getattr(u, "prompt_tokens", 0) if u else 0,
             "output_tokens": getattr(u, "completion_tokens", 0) if u else 0,
             "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    return text, usage

# ── Database ───────────────────────────────────────────────────────────────────

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "metier.db")

def get_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Pipeline statuses (what the seeker is doing). The risk read lives in the score badge.
VALID_STATUSES = ["Interested", "Applied", "Interviewing", "Offered",
                  "Rejected", "Ghosted", "Passed"]

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS analyses (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT    NOT NULL,
            msg_hash    TEXT    NOT NULL,
            message     TEXT    NOT NULL,
            channel     TEXT    NOT NULL DEFAULT 'unknown',
            score       INTEGER NOT NULL,
            label       TEXT    NOT NULL,
            result_json TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS identifiers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
            type        TEXT    NOT NULL,
            value       TEXT    NOT NULL,
            normalized  TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ident_normalized ON identifiers(normalized);
        CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
        CREATE TABLE IF NOT EXISTS scam_patterns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            category    TEXT    NOT NULL,
            match_type  TEXT    NOT NULL DEFAULT 'keyword',  -- 'keyword' | 'regex'
            pattern     TEXT    NOT NULL,
            weight      INTEGER NOT NULL DEFAULT 10,
            severity    TEXT    NOT NULL DEFAULT 'medium',
            polarity    TEXT    NOT NULL DEFAULT 'risk',      -- 'risk' | 'trust'
            title       TEXT    NOT NULL DEFAULT '',
            explanation TEXT    NOT NULL DEFAULT '',
            active      INTEGER NOT NULL DEFAULT 1,
            source      TEXT    NOT NULL DEFAULT 'seed',      -- 'seed' (from json) | 'manual'
            added_at    TEXT    NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_pattern_uniq ON scam_patterns(category, pattern);
    """)
    # ── Migration: tracker columns (safe to run repeatedly) ──
    existing = {row[1] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()}
    migrations = {
        "status":         "TEXT NOT NULL DEFAULT 'Interested'",
        "entry_type":     "TEXT NOT NULL DEFAULT 'vetted'",   # 'vetted' or 'manual'
        "manual_title":   "TEXT",
        "manual_company": "TEXT",
        "manual_source":  "TEXT",
        "manual_url":     "TEXT",
        "notes":          "TEXT",
        "personal_rating":"INTEGER NOT NULL DEFAULT 0",  # 1-5 stars, 0 = unset
        "manual_legit":   "TEXT",                        # manual legitimacy pick for self-added jobs
        "salary":         "TEXT",                        # free-text salary / comp
    }
    for col, ddl in migrations.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE analyses ADD COLUMN {col} {ddl}")
    conn.commit()
    conn.close()

# ── Normalisation helpers ──────────────────────────────────────────────────────

def _norm(v): return v.lower().strip()
def _norm_phone(v): return re.sub(r"\D", "", v)

PERSONAL_DOMAINS = {"gmail.com","yahoo.com","hotmail.com","outlook.com",
                    "icloud.com","aol.com","protonmail.com","me.com","live.com"}

# Disposable/temporary inboxes — near-certain scam when used for recruiting outreach
DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","temp-mail.org","tempmail.com",
    "throwawaymail.com","yopmail.com","getnada.com","maildrop.cc","sharklasers.com",
    "trashmail.com","mohmal.com","emailondeck.com","mintemail.com","dispostable.com",
    "fakeinbox.com","mailnesia.com","tempinbox.com","spamgourmet.com","mytemp.email",
}

# Link intelligence — shorteners hide destinations; form services are not hiring portals
URL_SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
                  "rebrand.ly","cutt.ly","shorturl.at","rb.gy","tiny.cc"}
FORM_SERVICES  = {"forms.gle","forms.office.com","typeform.com","jotform.com","tally.so",
                  "surveymonkey.com","wufoo.com","cognitoforms.com","formstack.com","airtable.com"}
# Hosts we never run age checks on (well-known infrastructure, not evidence either way)
SKIP_LINK_HOSTS = {"linkedin.com","lnkd.in","calendly.com","zoom.us","google.com",
                   "docs.google.com","meet.google.com","teams.microsoft.com","github.com",
                   "x.com","twitter.com","youtube.com","indeed.com","ziprecruiter.com","glassdoor.com"}

def _host_matches(host, ref):
    return host == ref or host.endswith("." + ref)

def _ats_info(host, path):
    """Identify a real ATS link and pull the company slug so it can be checked
    against the claimed employer. Returns (ats_name, slug) or None."""
    seg = lambda: (path.strip("/").split("/") or [""])[0]
    if _host_matches(host, "greenhouse.io")        and seg(): return ("Greenhouse", seg())
    if _host_matches(host, "jobs.lever.co")        and seg(): return ("Lever", seg())
    if _host_matches(host, "jobs.ashbyhq.com")     and seg(): return ("Ashby", seg())
    if _host_matches(host, "apply.workable.com")   and seg(): return ("Workable", seg())
    if _host_matches(host, "jobs.smartrecruiters.com") and seg(): return ("SmartRecruiters", seg())
    first = host.split(".")[0]
    if host.endswith(".myworkdayjobs.com"): return ("Workday", first)
    if host.endswith(".recruitee.com"):     return ("Recruitee", first)
    if host.endswith(".breezy.hr"):         return ("Breezy", first)
    if host.endswith(".bamboohr.com"):      return ("BambooHR", first)
    if host.endswith(".icims.com"):         return ("iCIMS", first)
    return None

_URL_RE = re.compile(r"""https?://[^\s<>"')\]]+|\bwww\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s<>"')\]]*""")

def _extract_urls(text):
    return list(dict.fromkeys(u.rstrip(".,;:!?") for u in _URL_RE.findall(text or "")))

def _url_host_path(url):
    if url.startswith("www."): url = "http://" + url
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (p.hostname or "").lower(), p.path or ""
    except Exception:
        return "", ""

_LEET = str.maketrans("0135478", "oleastb")
_HIRING_WORDS = r"(careers?|jobs?|hiring|recruit(?:ing|ment)?|talent|apply|hr)"

def _lookalike_notes(host, message):
    """Deterministic lookalike tells for a domain: punycode, hiring-word bolt-ons,
    and digit-substitution of a brand named in plain letters elsewhere in the message."""
    notes = []
    if "xn--" in host:
        notes.append("⚠ PUNYCODE/HOMOGLYPH DOMAIN — characters disguised to imitate another domain")
    labels = host.split(".")
    label = labels[-2] if len(labels) >= 2 else labels[0]
    if "-" in label and re.search(rf"(^|-){_HIRING_WORDS}(-|$)", label):
        notes.append("⚠ hiring word bolted onto the domain — real companies host careers on their main domain")
    _LEET_I = str.maketrans("0135478", "oieastb")   # leet "1" reads as both "l" and "i"
    for part in label.split("-"):
        if not any(ch.isdigit() for ch in part): continue
        for plain in {part.translate(_LEET), part.translate(_LEET_I)}:
            if plain != part and len(plain) > 3 and re.search(rf"\b{re.escape(plain)}\b", (message or ""), re.IGNORECASE):
                notes.append(f"⚠ DIGIT-SUBSTITUTION LOOKALIKE of “{plain}” — classic impersonation registration")
                break
    return notes

def _sig(category, title, weight, severity, polarity, explanation, matched=""):
    """Build a uniform signal dict (same shape match_patterns emits)."""
    return {"category": category, "title": title, "weight": weight, "severity": severity,
            "polarity": polarity, "explanation": explanation, "matched": matched}

def _lookalike_signals(host, message):
    sigs = []
    for note in _lookalike_notes(host, message):
        crit = "PUNYCODE" in note or "DIGIT-SUBSTITUTION" in note
        sigs.append(_sig("identity", "Lookalike / disguised domain", 35 if crit else 20,
                         "critical" if crit else "high", "risk", note, host))
    return sigs

def run_url_checks(message: str, signals=None) -> str:
    """Deterministic link intelligence on every URL in the message body —
    shorteners, form-service 'portals', ATS slugs, lookalikes, and age checks
    on unfamiliar linked domains. Appends structured signals if a list is given;
    always returns the text block for the LLM prompt."""
    urls = _extract_urls(message)
    if not urls: return ""
    sig = signals if signals is not None else []
    lines, seen, aged = ["\n## Link & URL Checks (automated)"], set(), 0
    for url in urls[:8]:
        host, path = _url_host_path(url)
        if not host or host in seen: continue
        seen.add(host)
        notes = []
        if any(_host_matches(host, s) for s in URL_SHORTENERS):
            notes.append("⚠ URL SHORTENER — destination hidden; legitimate recruiters link directly")
            sig.append(_sig("link", "Link shortener hides the destination", 22, "high", "risk",
                            "Legitimate recruiters link directly; shorteners conceal where you actually land.", host))
        if any(_host_matches(host, s) for s in FORM_SERVICES):
            notes.append("⚠ generic form service used as an application path — real companies use their ATS or careers site")
            sig.append(_sig("link", "Generic form used as an application portal", 24, "high", "risk",
                            "Real companies collect applications through their ATS or careers site, not a survey form.", host))
        ats = _ats_info(host, path)
        if ats:
            notes.append(f"ATS link ({ats[0]}), company slug “{ats[1]}” — verify the slug matches the claimed employer")
        notes += _lookalike_notes(host, message)
        sig.extend(_lookalike_signals(host, message))
        skip = (any(_host_matches(host, s) for s in SKIP_LINK_HOSTS) or host in PERSONAL_DOMAINS
                or any(_host_matches(host, s) for s in URL_SHORTENERS)
                or any(_host_matches(host, s) for s in FORM_SERVICES))
        if not ats and not skip and aged < 3:
            reg = ".".join(host.split(".")[-2:])
            info = check_domain(reg)
            aged += 1
            if info["age_days"] is not None and info["age_days"] < 180:
                notes.append(f"⚠ linked domain registered only {info['age_days']} days ago ({info['reg_date']})")
                crit = info["age_days"] < 30
                sig.append(_sig("link", "Freshly-registered linked domain", 35 if crit else 20,
                                "critical" if crit else "high", "risk",
                                f"The linked domain was registered only {info['age_days']} days ago — created right before this outreach.", host))
            if not info["resolves"]:
                notes.append("⚠ linked domain does not resolve")
                sig.append(_sig("link", "Linked domain does not resolve", 18, "medium", "risk",
                                "The destination domain doesn't resolve — it may not exist.", host))
        if notes:
            lines.append(f"- {host}: " + "; ".join(notes))
    return "\n".join(lines) if len(lines) > 1 else ""

def check_email_dns(domain: str) -> dict:
    """MX/SPF/DMARC presence — real corporate domains have mail infrastructure."""
    out = {"mx": None, "spf": None, "dmarc": None}
    try:
        import dns.resolver
    except ImportError:
        return out
    res = dns.resolver.Resolver(); res.timeout = res.lifetime = 4
    try: out["mx"] = bool(res.resolve(domain, "MX"))
    except Exception: out["mx"] = False
    try:
        txts = [b"".join(r.strings).decode(errors="replace") for r in res.resolve(domain, "TXT")]
        out["spf"] = any(t.lower().startswith("v=spf1") for t in txts)
    except Exception: out["spf"] = False
    try:
        txts = [b"".join(r.strings).decode(errors="replace") for r in res.resolve(f"_dmarc.{domain}", "TXT")]
        out["dmarc"] = any("v=dmarc1" in t.lower() for t in txts)
    except Exception: out["dmarc"] = False
    return out

def parse_email_headers(raw: str, signals=None):
    """Parse raw email headers the user pastes from 'Show original'.
    Returns (findings_text, reply_to_email) and appends signals if a list is given —
    the strongest spoof evidence available."""
    if not raw or not raw.strip(): return "", None
    from email.parser import HeaderParser
    try:
        h = HeaderParser().parsestr(raw.strip())
    except Exception:
        return "", None
    sig = signals if signals is not None else []
    addr = lambda s: (re.search(r"[\w.+-]+@[\w.-]+", s or "") or [None]) and \
                     (re.search(r"[\w.+-]+@[\w.-]+", s or "").group(0).lower()
                      if re.search(r"[\w.+-]+@[\w.-]+", s or "") else None)
    frm, rep, rp = addr(h.get("From")), addr(h.get("Reply-To")), addr(h.get("Return-Path"))
    dom = lambda a: a.split("@")[1] if a and "@" in a else ""
    lines = ["\n## Email Header Analysis (automated, from raw headers)"]
    if frm: lines.append(f"From: {frm}")
    if rep and frm and dom(rep) != dom(frm):
        lines.append(f"⚠ REPLY-TO MISMATCH: From is @{dom(frm)} but replies are routed to {rep} — classic spoof/impersonation pattern")
        sig.append(_sig("header", "Reply-To address doesn't match the sender", 45, "critical", "risk",
                        f"The email is From @{dom(frm)} but replies route to {rep} — a classic spoofing/impersonation pattern.", rep))
    elif rep:
        lines.append(f"Reply-To: {rep} (matches From domain)")
    if rp and frm and dom(rp) != dom(frm):
        lines.append(f"⚠ Return-Path domain (@{dom(rp)}) differs from From domain (@{dom(frm)})")
        sig.append(_sig("header", "Return-Path domain differs from sender", 20, "medium", "risk",
                        f"The Return-Path (@{dom(rp)}) differs from the From domain (@{dom(frm)}).", rp))
    auth = h.get("Authentication-Results", "")
    if auth:
        for mech, w in (("spf", 20), ("dkim", 20), ("dmarc", 30)):
            m = re.search(rf"{mech}=(\w+)", auth, re.IGNORECASE)
            if m:
                r = m.group(1).lower()
                if r == "pass":
                    lines.append(f"{mech.upper()}: pass ✓")
                    if mech == "dmarc":
                        sig.append(_sig("header", "Email authentication passed (DMARC)", 10, "low", "trust",
                                        "The message passed DMARC — the sending domain is authenticated.", "dmarc=pass"))
                else:
                    lines.append(f"{mech.upper()}: ⚠ {r.upper()} — sender authentication failed or missing")
                    sig.append(_sig("header", f"{mech.upper()} authentication failed", w, "high", "risk",
                                    f"{mech.upper()} is '{r}' — the sender's domain is not properly authenticated, a strong spoof signal.", f"{mech}={r}"))
    else:
        lines.append("No Authentication-Results header found in the pasted headers")
    bulk = h.get("X-Mailer", "") + " " + (h.get("List-Unsubscribe") or "")
    if re.search(r"sendgrid|mailgun|mailchimp|brevo|sendinblue|campaign", bulk, re.IGNORECASE) or h.get("List-Unsubscribe"):
        lines.append("Sent via bulk-mail infrastructure (mass outreach, not a personal note)")
        sig.append(_sig("ai_template", "Sent via bulk-mail infrastructure", 8, "low", "risk",
                        "Delivered through mass-mailing infrastructure — outreach blast, not a personal note.", "bulk-mailer"))
    return ("\n".join(lines) if len(lines) > 1 else ""), rep

# ── Keyword pre-screening ──────────────────────────────────────────────────────
# Runs instantly before the Claude call — catches obvious patterns for free.

_FEE_KW      = ["resume writing fee","background check fee","training fee","placement fee",
                "equipment deposit","certification fee","pay to apply","administration fee",
                "processing fee","membership fee","starter kit","onboarding fee","insurance fee",
                "bond fee","security deposit","software license fee","pay for access",
                "refundable deposit","purchase equipment","buy your own equipment"]
_PII_KW      = ["social security","ssn","bank account","routing number","direct deposit setup",
                "passport number","driver's license","date of birth","mother's maiden",
                "send id","copy of id","government id","verify your identity","identity verification",
                "w-9","w9 form","i-9","credit check","background check form"]
_URGENCY_KW  = ["respond within 24 hours","limited positions","act now","don't miss out",
                "positions are filling fast","today only","expires soon","respond immediately",
                "time sensitive","last chance","closing soon","respond by end of day"]
_OFFCHANNEL_KW = ["whatsapp","telegram","text me at","call this number","signal app",
                  "google hangouts","facebook messenger","instagram dm","move to text"]

def detect_keyword_flags(message: str) -> dict:
    """Fast local keyword scan — runs before the Claude call at zero cost."""
    m = message.lower()
    flags = {
        "fee":        [k for k in _FEE_KW        if k in m],
        "pii":        [k for k in _PII_KW        if k in m],
        "urgency":    [k for k in _URGENCY_KW    if k in m],
        "off_channel":[k for k in _OFFCHANNEL_KW if k in m],
    }
    flags["any"] = any(v for v in flags.values() if isinstance(v, list) and v)
    return flags

# ── Scam-pattern store (the updatable "techniques database") ─────────────────────
PATTERNS_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scam_patterns.json")

def sync_patterns_from_json():
    """Load scam_patterns.json into the DB. Seed rows are upserted (so edits to the
    file propagate on restart); 'manual' rows added at runtime are never touched."""
    try:
        with open(PATTERNS_JSON, encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0
    rows = data.get("patterns", [])
    conn = get_db()
    try:
        for p in rows:
            conn.execute(
                "INSERT INTO scam_patterns (category,match_type,pattern,weight,severity,polarity,title,explanation,active,source,added_at) "
                "VALUES(?,?,?,?,?,?,?,?,1,'seed',?) "
                "ON CONFLICT(category,pattern) DO UPDATE SET "
                "match_type=excluded.match_type,weight=excluded.weight,severity=excluded.severity,"
                "polarity=excluded.polarity,title=excluded.title,explanation=excluded.explanation "
                "WHERE scam_patterns.source='seed'",
                (p["category"], p.get("match_type", "keyword"), p["pattern"], int(p.get("weight", 10)),
                 p.get("severity", "medium"), p.get("polarity", "risk"), p.get("title", ""),
                 p.get("explanation", ""), datetime.now(timezone.utc).isoformat()))
        conn.commit()
        return len(rows)
    finally:
        conn.close()

def load_active_patterns():
    conn = get_db()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT category,match_type,pattern,weight,severity,polarity,title,explanation "
            "FROM scam_patterns WHERE active=1").fetchall()]
    finally:
        conn.close()

def match_patterns(message: str, patterns=None):
    """Return the scam-technique signals present in the message. Each signal:
    {category,title,explanation,weight,severity,polarity,matched}."""
    m = (message or "").lower()
    out, seen = [], set()
    for p in (patterns if patterns is not None else load_active_patterns()):
        hit = None
        if p["match_type"] == "regex":
            mo = re.search(p["pattern"], m, re.IGNORECASE)
            if mo: hit = mo.group(0)
        else:
            if p["pattern"].lower() in m: hit = p["pattern"]
        if not hit: continue
        key = (p["title"], p["category"])           # dedupe repeated titles within a category
        if key in seen: continue
        seen.add(key)
        out.append({"category": p["category"], "title": p["title"], "explanation": p["explanation"],
                    "weight": p["weight"], "severity": p["severity"], "polarity": p["polarity"],
                    "matched": hit})
    return out

# ── Deterministic scoring engine (rules-based verdict, runs with NO API key) ─────
def score_signals(signals):
    """Combine risk/trust signal weights into a 0–100 scam_likelihood_score
    (higher = more scammy). Without any positive verification, a clean message
    can't reach a confident 'Legit' — it caps at Dubious (honest 'unverified')."""
    risk  = sum(s["weight"] for s in signals if s["polarity"] == "risk")
    trust = sum(s["weight"] for s in signals if s["polarity"] == "trust")
    score = max(0, min(100, risk - trust))
    if not any(s["polarity"] == "trust" for s in signals):
        score = max(score, 26)          # nothing verified → at most Dubious, never confident Legit
    return score

def _verdict_label(score):
    return "Low" if score <= 25 else "Medium" if score <= 60 else "High" if score <= 80 else "Very High"

_CLASS_BY_CAT = {"fee": "advance_fee", "pii": "data_harvesting", "ghost_job": "ghost_job",
                 "identity": "impersonation", "header": "impersonation", "link": "impersonation",
                 "off_channel": "unknown", "urgency": "unknown", "too_good": "unknown",
                 "ai_template": "data_harvesting"}
_CLASS_LABEL = {"advance_fee": "Upfront-payment / advance-fee scam", "data_harvesting": "Data / resume harvesting",
                "ghost_job": "Likely ghost job", "impersonation": "Impersonation",
                "legitimate": "No scam type detected", "unknown": "Unclear — proceed with caution"}

def _classify(signals):
    risks = [s for s in signals if s["polarity"] == "risk"]
    if not risks: return "legitimate"
    by = {}
    for s in risks: by[s["category"]] = by.get(s["category"], 0) + s["weight"]
    return _CLASS_BY_CAT.get(max(by, key=by.get), "unknown")

class _RulesIdent:
    def __init__(self, emails, domains, names):
        self.emails, self.domains, self.recruiter_names = emails, domains, names
        self.phone_numbers, self.company_names, self.linkedin_urls = [], [], []
        self.recruiter_company = self.job_title = self.job_company = ""
    def dump(self):
        return {"emails": self.emails, "phone_numbers": self.phone_numbers,
                "recruiter_names": self.recruiter_names, "recruiter_company": self.recruiter_company,
                "job_title": self.job_title, "job_company": self.job_company,
                "company_names": self.company_names, "domains": self.domains,
                "linkedin_urls": self.linkedin_urls}

class RulesAnalysis:
    """Deterministic, RecruiterAnalysis-compatible result built purely from signals —
    no LLM. The route can mutate score/label/red_flags (e.g. the known-scam floor)."""
    def __init__(self, signals, quick, reply_to=None):
        self.signals = signals
        emails = list(quick.get("emails", []))
        if reply_to and reply_to not in emails: emails.append(reply_to)
        self.identifiers = _RulesIdent(emails, list(quick.get("domains", [])), list(quick.get("names", [])))
        self.scam_likelihood_score = score_signals(signals)
        self.scam_likelihood_label = _verdict_label(self.scam_likelihood_score)
        risks  = sorted([s for s in signals if s["polarity"] == "risk"],  key=lambda x: -x["weight"])
        trusts = [s for s in signals if s["polarity"] == "trust"]
        self.red_flags = list(dict.fromkeys(s["title"] for s in risks))
        self.legitimate_signals = list(dict.fromkeys(s["title"] for s in trusts))
        self._ptype = _classify(signals)
        self._risks, self._trusts = risks, trusts

    def _tier(self):
        legit = 100 - self.scam_likelihood_score
        return "go" if legit >= 75 else "watch" if legit >= 50 else "away"

    def model_dump(self):
        tier = self._tier()
        rec = {"away": "Do not engage — multiple scam signals detected. Don't share personal information, documents, or money.",
               "watch": "Proceed carefully — verify the recruiter and role before sharing anything. Send the verification questions first.",
               "go": "No red flags found and the sender's domain checks out — reasonable to proceed, but still confirm the role on the company's own careers page."}[tier]
        detail = "; ".join(f"{s['title']} ({s['explanation']})" for s in self._risks[:4])
        reasoning = (f"Rules-based read: {detail}." if self._risks else
                     "No scam patterns matched and the sender's technical signals look consistent with a real company.")
        if not self._trusts and not self._risks:
            reasoning += " Nothing could be positively verified, so treat as unconfirmed."
        fee = min(100, sum(s["weight"] for s in self._risks if s["category"] == "fee"))
        return {
            "scam_likelihood_score": self.scam_likelihood_score,
            "scam_likelihood_label": self.scam_likelihood_label,
            "red_flags": self.red_flags,
            "legitimate_signals": self.legitimate_signals,
            "recommendation": rec,
            "reasoning": reasoning,
            "scam_classification": {"primary_type": self._ptype,
                "type_label": _CLASS_LABEL.get(self._ptype, ""),
                "confidence": "High" if (self.scam_likelihood_score >= 70 or (self._trusts and not self._risks)) else "Medium",
                "reasoning": f"Dominant signal category: {self._ptype}." if self._risks else "No scam category detected."},
            "company_intel": {"named_company": "", "likely_identity":
                ("Sender domain not verified as a real company." if not self._trusts else "Sender domain is consistent with an established company."),
                "confidence": "Low", "clues": [], "identity_concerns": [s["title"] for s in self._risks if s["category"] == "identity"]},
            "pay_to_play": {"score": fee, "label": _verdict_label(fee),
                "signals": [s["title"] for s in self._risks if s["category"] == "fee"], "likely_tactics": []},
            "web_presence": {"summary": "", "legitimate_findings": [], "red_flags": []},
            "follow_up_questions": ["Can you email me from your company domain?",
                "Who is the hiring manager for this role?",
                "Can you send the careers-page link for this role?"],
            "identifiers": self.identifiers.dump(),
        }

def run_rules_analysis(signals, quick, reply_to=None):
    return RulesAnalysis(signals, quick, reply_to)

def _identifier_rows(analysis_id, ids):
    rows = []
    for e in ids.emails:        rows.append((analysis_id,"email",e,_norm(e)))
    for p in ids.phone_numbers:
        n = _norm_phone(p)
        if len(n)>=7: rows.append((analysis_id,"phone",p,n))
    for n in ids.recruiter_names:  rows.append((analysis_id,"name",n,_norm(n)))
    for c in ids.company_names:    rows.append((analysis_id,"company",c,_norm(c)))
    for d in ids.domains:          rows.append((analysis_id,"domain",d,_norm(d)))
    for u in ids.linkedin_urls:    rows.append((analysis_id,"linkedin",u,_norm(u).rstrip("/")))
    return rows

def save_analysis(message, channel, analysis, usage):
    result = analysis.model_dump()
    result["usage"] = dict(usage)  # usage is already a normalized dict
    # Default pipeline status from the legitimacy score (the risk itself shows in
    # the score badge). Worth pursuing → Interested; flagged → Pass.
    legit = 100 - analysis.scam_likelihood_score
    initial_status = "Passed" if legit < 34 else "Interested"  # Scam tier → Passed
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO analyses (created_at,msg_hash,message,channel,score,label,result_json,status) VALUES(?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), hashlib.sha256(message.encode()).hexdigest(),
             message, channel, analysis.scam_likelihood_score, analysis.scam_likelihood_label,
             json.dumps(result), initial_status),
        )
        aid = cur.lastrowid
        rows = _identifier_rows(aid, analysis.identifiers)
        if rows:
            conn.executemany("INSERT INTO identifiers (analysis_id,type,value,normalized) VALUES(?,?,?,?)", rows)
        conn.commit()
        return aid
    finally:
        conn.close()

def add_manual_job(title, company, source, url, status, notes, salary=""):
    """Insert a self-found job (no AI analysis) into the tracker."""
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO analyses "
            "(created_at,msg_hash,message,channel,score,label,result_json,"
            " status,entry_type,manual_title,manual_company,manual_source,manual_url,notes,salary,manual_legit) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), "", "", source or "manual", 0, "",
             "{}", status, "manual", title, company, source, url, notes, salary, "Legit"),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def update_status(entry_id, status):
    conn = get_db()
    try:
        conn.execute("UPDATE analyses SET status=? WHERE id=?", (status, entry_id))
        conn.commit()
    finally:
        conn.close()

def update_notes(entry_id, notes):
    conn = get_db()
    try:
        conn.execute("UPDATE analyses SET notes=? WHERE id=?", (notes, entry_id))
        conn.commit()
    finally:
        conn.close()

# Columns the user can edit on any entry. For vetted entries the manual_* values
# act as display overrides over the AI-extracted fields (the analysis is untouched).
# (key -> (column, type))
_EDITABLE = {
    "title":        ("manual_title",   "str"),
    "company":      ("manual_company", "str"),
    "source":       ("manual_source",  "str"),
    "url":          ("manual_url",     "str"),
    "notes":        ("notes",          "str"),
    "status":       ("status",         "str"),
    "manual_legit": ("manual_legit",   "str"),  # self-set legitimacy for manual jobs
    "rating":       ("personal_rating","int"),  # 1-5 stars, 0 = unset
    "salary":       ("salary",         "str"),  # free-text salary / comp
}

def update_entry(entry_id, fields: dict):
    sets, vals = [], []
    for key, (col, kind) in _EDITABLE.items():
        if key not in fields:
            continue
        if kind == "int":
            try:    v = max(0, min(5, int(fields[key] or 0)))
            except (TypeError, ValueError): v = 0
        else:
            v = (fields[key] or "").strip()
        sets.append(f"{col}=?"); vals.append(v)
    if not sets:
        return
    vals.append(entry_id)
    conn = get_db()
    try:
        conn.execute(f"UPDATE analyses SET {', '.join(sets)} WHERE id=?", vals)
        conn.commit()
    finally:
        conn.close()

def delete_entry(entry_id):
    conn = get_db()
    try:
        conn.execute("DELETE FROM identifiers WHERE analysis_id=?", (entry_id,))
        conn.execute("DELETE FROM analyses WHERE id=?", (entry_id,))
        conn.commit()
    finally:
        conn.close()

def find_cross_references(analysis, exclude_id):
    ids = analysis.identifiers
    normed = set()
    for e in ids.emails:        normed.add(_norm(e))
    for p in ids.phone_numbers:
        n = _norm_phone(p)
        if len(n)>=7: normed.add(n)
    for d in ids.domains:       normed.add(_norm(d))
    for u in ids.linkedin_urls: normed.add(_norm(u).rstrip("/"))
    for n in ids.recruiter_names: normed.add(_norm(n))
    for c in ids.company_names:   normed.add(_norm(c))
    if not normed: return []
    ph = ",".join("?"*len(normed))
    conn = get_db()
    try:
        rows = conn.execute(
            f"SELECT DISTINCT a.id,a.created_at,a.score,a.label,i.type AS match_type,i.value AS match_value,a.result_json "
            f"FROM analyses a JOIN identifiers i ON i.analysis_id=a.id "
            f"WHERE i.normalized IN ({ph}) AND a.id!=? ORDER BY a.score DESC,a.created_at DESC LIMIT 20",
            list(normed)+[exclude_id],
        ).fetchall()
        seen, refs = set(), []
        for row in rows:
            if row["id"] in seen: continue
            seen.add(row["id"])
            prev = json.loads(row["result_json"])
            pi = prev.get("identifiers",{})
            refs.append({"id":row["id"],"created_at":row["created_at"],"score":row["score"],
                         "label":row["label"],"match_type":row["match_type"],"match_value":row["match_value"],
                         "prev_names":pi.get("recruiter_names",[]),"prev_companies":pi.get("company_names",[])})
        return refs
    finally:
        conn.close()

# ── Known/repeat-contact correlation ────────────────────────────────────────────
_STRONG_MATCH_TYPES = {"email", "phone", "domain", "linkedin"}  # weak: name, company (collide)
# Free/public email providers — the domain is shared by millions, so it is NOT a unique
# identifier. Match these only on the full email address, never on the bare domain.
FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "tutanota.com", "fastmail.com",
}

def _verdict_word(score):
    legit = 100 - (score or 0)
    return "Scam" if legit < 50 else "Dubious" if legit < 75 else "Legit"

def _prior_matches(normed, exclude_id=-1):
    """Prior analyses sharing any normalized identifier in `normed` (pre-call regex lookup)."""
    normed = {n for n in normed if n}
    if not normed: return []
    ph = ",".join("?" * len(normed))
    conn = get_db()
    try:
        rows = conn.execute(
            f"SELECT DISTINCT a.id,a.created_at,a.score,i.type AS match_type,i.value AS match_value "
            f"FROM analyses a JOIN identifiers i ON i.analysis_id=a.id "
            f"WHERE i.normalized IN ({ph}) AND a.id!=? ORDER BY a.score DESC,a.created_at DESC LIMIT 10",
            list(normed) + [exclude_id],
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def prior_history_block(matches):
    """Context block injected into the prompt so the model knows this is a repeat contact."""
    flagged = [m for m in matches if (100 - (m["score"] or 0)) < 75]  # prior Scam or Dubious
    if not flagged: return ""
    lines = ["\n## ⚠ PRIOR HISTORY — this contact matches earlier entries in the user's own records"]
    for m in flagged[:5]:
        lines.append(f"- {m['match_type']} {m['match_value']} was already scored "
                     f"**{_verdict_word(m['score'])}** on {str(m['created_at'])[:10]}.")
    lines.append("This is a KNOWN/REPEAT contact the user previously flagged. Carry that suspicion "
                 "forward — a polite follow-up does NOT clear it. Do NOT score this message Legit.")
    return "\n".join(lines)

def apply_known_scam_floor(analysis, cross_refs):
    """Hard rule: a strong-identifier match to a prior Scam-tier entry forces a Scam verdict."""
    for ref in cross_refs:
        mt, mv = ref.get("match_type"), (ref.get("match_value") or "")
        # A shared free-email domain (gmail.com, etc.) is NOT a unique contact — skip it.
        if mt == "domain" and _norm(mv) in FREE_EMAIL_DOMAINS:
            continue
        if mt in _STRONG_MATCH_TYPES and (100 - (ref.get("score") or 0)) < 50:
            if analysis.scam_likelihood_score < 90:
                analysis.scam_likelihood_score = 90
                analysis.scam_likelihood_label = "Very High"
            note = (f"Known scammer: this {ref.get('match_type')} ({ref.get('match_value')}) "
                    f"matches a prior entry you flagged as Scam.")
            if note not in analysis.red_flags:
                analysis.red_flags.insert(0, note)
            return True
    return False

# ── Auto-checks ────────────────────────────────────────────────────────────────

def check_domain(domain: str) -> dict:
    """DNS + RDAP age check for a domain. Returns dict with resolves/age_days/reg_date."""
    result = {"domain": domain, "resolves": False, "age_days": None, "reg_date": None, "error": None}
    if domain in PERSONAL_DOMAINS:
        result["resolves"] = True
        result["note"] = "Personal email provider"
        return result
    # DNS
    try:
        socket.setdefaulttimeout(4)
        socket.gethostbyname(domain)
        result["resolves"] = True
    except Exception:
        result["resolves"] = False
    # RDAP age
    try:
        r = http_requests.get(f"https://rdap.org/domain/{domain}", timeout=8, allow_redirects=True,
                              headers={"User-Agent": "Metier/1.0"})
        if r.ok:
            data = r.json()
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    raw = event["eventDate"]
                    try:
                        reg = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        result["age_days"] = (datetime.now(timezone.utc) - reg).days
                        result["reg_date"] = raw[:10]
                    except Exception:
                        pass
    except Exception as e:
        result["error"] = str(e)
    return result

def run_domain_checks(domains: list[str], message: str = "", signals=None) -> str:
    """Automated domain intel (age via RDAP, DNS/MX/SPF/DMARC, lookalike tells) —
    runs BEFORE Claude. Appends structured signals if a list is given."""
    sig = signals if signals is not None else []
    lines = []
    for domain in domains[:3]:
        if not domain: continue
        if domain in DISPOSABLE_DOMAINS:
            lines.append(f"{domain}: ⚠ DISPOSABLE/TEMPORARY EMAIL DOMAIN — burner inbox, near-certain scam")
            sig.append(_sig("identity", "Disposable/burner email domain", 50, "critical", "risk",
                            "The sender uses a throwaway email provider — near-certain scam for recruiting outreach.", domain))
            continue
        if domain in PERSONAL_DOMAINS:
            lines.append(f"{domain}: personal email provider (gmail/yahoo/etc) — not a company domain")
            continue
        info = check_domain(domain)
        established = False
        bits = [f"{domain}:"]
        if info["age_days"] is not None:
            if info["age_days"] < 30:
                bits.append(f"⚠ REGISTERED ONLY {info['age_days']} DAYS AGO ({info['reg_date']}) — created right before this outreach")
                sig.append(_sig("identity", "Sender domain registered days ago", 40, "critical", "risk",
                                f"The sender's domain was registered only {info['age_days']} days ago ({info['reg_date']}) — created right before this outreach.", domain))
            elif info["age_days"] < 180:
                bits.append(f"young domain, {info['age_days']} days old ({info['reg_date']})")
                sig.append(_sig("identity", "Young sender domain", 20, "medium", "risk",
                                f"The sender's domain is only {info['age_days']} days old.", domain))
            else:
                bits.append(f"established, registered {info['reg_date']} ({info['age_days']} days old)")
                established = True
        else:
            bits.append("registration date unknown")
        if info["resolves"]:
            bits.append("resolves (live)")
        else:
            bits.append("⚠ DOES NOT RESOLVE — domain may not exist")
            sig.append(_sig("identity", "Sender domain does not resolve", 28, "high", "risk",
                            "The sender's domain doesn't resolve in DNS — it may not exist.", domain))
        mail = check_email_dns(domain)
        good_mail = False
        if mail["mx"] is not None:
            if not mail["mx"]:
                bits.append("⚠ NO MX RECORDS — this domain cannot receive email; a 'corporate' sender here is spoofed")
                sig.append(_sig("identity", "Sender domain can't receive email (no MX)", 40, "critical", "risk",
                                "The 'corporate' domain has no MX records — it cannot receive mail, so the sender is almost certainly spoofed.", domain))
            else:
                missing = [k.upper() for k in ("spf", "dmarc") if mail[k] is False]
                if missing:
                    bits.append("mail infra: MX ✓ ⚠ missing " + "/".join(missing) + " — unusual for a real company domain")
                    sig.append(_sig("identity", "Sender domain missing " + "/".join(missing), 12, "medium", "risk",
                                    "Established company domains normally publish SPF and DMARC; their absence is unusual.", domain))
                else:
                    bits.append("mail infra: MX ✓ SPF/DMARC ✓")
                    good_mail = True
        if good_mail and info["resolves"]:
            w = 18 if established else 12
            note = (f"{domain} is an established domain ({info['reg_date']}) with proper MX/SPF/DMARC — consistent with a real company."
                    if established else f"{domain} has proper MX/SPF/DMARC mail infrastructure — consistent with a real company.")
            sig.append(_sig("identity", "Corporate domain with valid mail setup", w, "medium", "trust", note, domain))
        for n in _lookalike_notes(domain, message):
            bits.append(n)
        sig.extend(_lookalike_signals(domain, message))
        lines.append(" ".join(bits))
    return "\n".join(lines) if lines else "No company domains to check."

# ── Web research ───────────────────────────────────────────────────────────────

def _quick_extract(message, sender_email):
    emails = list(dict.fromkeys(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", message)))
    if sender_email and sender_email not in emails: emails.insert(0, sender_email)
    domains = list(dict.fromkeys(e.split("@")[1].lower() for e in emails if "@" in e))
    name_re = [
        r"(?:Regards|Best|Cheers|Thanks|Sincerely),?\s*\n\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",
        r"(?:I'm|I am|this is|name is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)(?:\s|,|\.)",
    ]
    names = []
    for pat in name_re: names += re.findall(pat, message, re.MULTILINE)
    names = list(dict.fromkeys(n.strip() for n in names if len(n.strip())>3))
    return {"emails": emails[:3], "domains": domains[:3], "names": names[:2]}

def _linkedin_name_from_url(url):
    """Pull a best-guess name from a LinkedIn /in/ slug, e.g. /in/fred-meindl-1a2b → 'fred meindl'."""
    m = re.search(r"/in/([A-Za-z0-9\-]+)", url or "")
    if not m: return ""
    slug = m.group(1)
    # Drop trailing hash segments (numbers/short alnum) LinkedIn appends
    parts = [p for p in slug.split("-") if not re.fullmatch(r"[0-9a-f]{2,}", p) and not p.isdigit()]
    return " ".join(parts).strip()

def run_web_research(message, sender_email, channel=None, contact_info=None):
    ids = _quick_extract(message, sender_email)
    lines = []
    try:
        from ddgs import DDGS
        with DDGS() as ddgs:
            def _search(query, n=4):
                try:
                    results = list(ddgs.text(query, max_results=n))
                    lines.append(f'\nSearch: {query}')
                    for r in results:
                        lines.append(f'  [{r["title"]}] {r["href"]}\n  {r.get("body","")[:200]}')
                    if not results: lines.append("  → No results")
                except:
                    lines.append(f"  → Search failed")

            # ── Channel-specific scans ──────────────────────────────────────────
            if channel == "linkedin" and contact_info:
                lines.append(f"\n## LinkedIn source: {contact_info}")
                _search(f'{contact_info}', n=3)                      # the profile itself
                ln_name = _linkedin_name_from_url(contact_info)
                if ln_name:
                    lines.append(f"(name guessed from profile URL: {ln_name})")
                    _search(f'"{ln_name}" recruiter LinkedIn', n=3)
                    _search(f'"{ln_name}" scam OR fake OR fraud', n=3)
                    if ln_name not in ids["names"]:
                        ids["names"].insert(0, ln_name)

            elif channel == "sms" and contact_info:
                digits = re.sub(r"\D", "", contact_info)
                lines.append(f"\n## Phone source: {contact_info}")
                _search(f'"{contact_info}" scam OR spam OR robocall OR complaint', n=4)
                if digits:
                    _search(f'{digits} who called OR scam report', n=3)

            elif channel == "other" and contact_info:
                lines.append(f"\n## Platform source: {contact_info}")
                _search(f'"{contact_info}" recruiter scam OR fake job', n=3)
                for nm in ids["names"][:1]:
                    _search(f'"{nm}" {contact_info} scam OR fraud', n=3)

            # ── Standard scans (names, domains) ─────────────────────────────────
            for name in ids["names"][:2]:
                _search(f'"{name}" recruiter')

            for domain in ids["domains"][:3]:  # up to 3 domains — catches signature mismatches
                if domain in PERSONAL_DOMAINS:
                    lines.append(f'\nDomain {domain} → Personal email provider'); continue
                _search(f'"{domain}" company', n=3)
                _search(f'"{domain}" scam OR fraud OR complaint', n=3)

            for cname in ids.get("names", [])[:1]:
                _search(f'"{cname}" recruiter scam OR fraud', n=3)

            # ── Careers-page scan — does the company's own site list jobs at all? ──
            for domain in ids["domains"][:3]:
                if domain not in PERSONAL_DOMAINS and domain not in DISPOSABLE_DOMAINS:
                    lines.append(f"\n## Careers page scan: {domain}")
                    _search(f"site:{domain} careers OR jobs", n=3)
                    break

    except ImportError: return "Web research unavailable."
    except Exception as e: return f"Web research error: {e}"
    return "\n".join(lines) or "No identifiers found."

# ── System prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a trusted advisor for job seekers navigating a difficult market. \
Your job is to give them the intelligence and confidence to make smart decisions — not to \
frighten them. Analyze every recruiter message through the lens of: is this worth the job \
seeker's time, energy, and trust? Help them proceed with courage when things look legitimate, \
and help them walk away without regret when they don't.

The job market is hard. Candidates are under pressure. Unscrupulous recruiters exploit that \
fear and desperation. Your role is to give the job seeker their power back.

## SCOPE
This tool weeds out sketchy or fake corporate and executive recruiters — NOT everyday consumer \
scams. It applies to any career-track job, but skews toward tech and white-collar roles: software \
engineering, SRE / DevOps / infrastructure, data, security, product, design, IT, plus finance, \
consulting, marketing, sales, and operations. Weight the scam patterns common in those markets \
(e.g. fake "we saw your GitHub/LinkedIn profile" hooks, bogus application portals, mass-blast \
outreach for senior roles).

Output style: BRIEF. Every field should be the shortest possible version that is still useful.
- `recommendation`: ONE sentence. The single most important action to take.
- `red_flags` and `legitimate_signals`: 4–6 words each. No full sentences.
- `reasoning`: 2–3 short sentences max. No essays.
- `company_intel.likely_identity`: one sentence.
- `web_presence.summary`: one sentence.
- `checklist.task`: one short imperative. `checklist.detail`: one short sentence.
- `follow_up_questions`: short, natural questions only.

Never pad. Never explain what you're about to say. Just say it.

---
## SCORING — direction matters, read carefully
`scam_likelihood_score` runs 0–100 where **HIGHER = MORE likely a scam** (0–25 Low, 26–60 Medium, \
61–80 High, 81–100 Very High). The user sees the INVERSE as a legitimacy verdict: legitimacy = \
100 − scam_likelihood_score, so a HIGH score → "Scam", a LOW score → "Legit". Never invert this.

Catching scams is the priority. Missing a real scam hurts the job seeker far more than over-flagging \
a legitimate recruiter. So when you are uncertain, err toward a HIGHER scam_likelihood_score (more \
suspicious) — protect the user first.
- If signals are mixed or you can't verify the company/recruiter, do NOT default to legitimate. \
  Treat unverifiable as suspicious and RAISE the score.
- A genuinely clean, fully verifiable opportunity can score LOW — don't over-flag the obvious good ones.
- Any real red flag (upfront money, early PII requests, domain/identity mismatch, off-channel push, \
  pressure, no web presence, template/placeholder fakes) should push the score UP hard.
- Reserve a LOW (clearly-legitimate) score only for contacts you could actually verify as real.
Resulting legitimacy bands: 0–49 legitimacy = Scam, 50–74 = Dubious, 75–100 = Legit. When torn \
between two bands, pick the more cautious one (the HIGHER scam_likelihood_score).

### Follow-up messages — judge them in context, not in isolation
A short follow-up ("just circling back," "any update?") usually won't repeat the original red flags. \
Do NOT score it Legit just because the follow-up text itself reads polite and harmless. An \
unsolicited follow-up from an unverifiable sender, or one that keeps pushing for information or \
action, stays suspicious — carry over the suspicion from the thread it belongs to. If the original \
message isn't included, note that and lean cautious (higher score).

---
## CLASSIFICATION — what kind of contact is this?
- **legitimate** — genuine recruiter, verifiable company, standard process
- **ghost_job** — posting exists to collect resumes/data; no real open role
- **data_harvesting** — goal is personal info: SSN, bank account, passport, ID, DOB
- **pay_to_play** — will ask for upfront payment (resume services, coaching, fees, deposits)
- **advance_fee** — asks for money before access to jobs, interviews, or first paycheck
- **impersonation** — using a real company's name/brand without affiliation, OR posing as a known executive-search firm
- **unknown** — suspicious but type unclear

---
## WHAT TO LOOK FOR

### Green lights — these signal a real opportunity
- Corporate email matching a verifiable, established domain (not gmail/yahoo/hotmail)
- Company has a real LinkedIn page with employee count, history, and active employees
- Job appears on the company's official careers page
- Recruiter has a real LinkedIn profile with work history and connections
- Salary range matches the market rate for the role
- Structured interview process described (screen → interviews → offer)
- Recruiter can describe the team, the problem they're solving, and what the role looks like day-to-day

### Ghost job signals — no real role exists
- Extremely vague description that could match anyone
- No specific team, manager, or department
- Role not listed on the company's official careers page
- "We keep resumes on file for future openings" language
- Recruiter can't describe what the role actually does
- No other current job openings at the company
- Listing has been active for months with no change

### Data harvesting signals — protecting personal information
Legitimate employers never ask for sensitive information before a signed offer.
- Asking for SSN, bank account, routing number, or direct deposit info before hire paperwork
- Requesting a passport, driver's license, or government ID before a formal offer
- W-9 or I-9 requests before employment is confirmed
- "Background check" forms asking for financial information
- Moving communication off professional channels before collecting information

### Upfront payment signals — they get paid, you get nothing
Legitimate recruiters are paid by employers. Candidates never pay.
- Resume writing, LinkedIn optimisation, or coaching fees tied to placement
- Placement fee or finder's fee charged to the candidate
- Equipment, software, or training material deposits
- Background check fee charged to the candidate
- "Serious candidates only" paired with any cost
- Onboarding, admin, or processing fees
- Refundable deposits

### Executive / retained-search red flags — vetting corporate & exec recruiters
This tool's purpose is weeding out sketchy or fake corporate and executive recruiters — not everyday consumer scams. Focus on whether the recruiter and firm are real.
- **Search-firm impersonation**: claims to be from a known firm (Korn Ferry, Heidrick & Struggles, \
  Russell Reynolds, Spencer Stuart, Egon Zehnder, etc.) but the email domain or LinkedIn doesn't \
  match that firm — or uses a free/lookalike domain.
- **Not on the firm's roster**: the named consultant can't be found on the search firm's own \
  team/bios page or the firm's LinkedIn employee list.
- **"Confidential client" as a dodge**: uses client confidentiality to refuse ALL verification \
  (won't confirm the firm, their role there, or any checkable detail). Real retained search explains \
  confidentiality without becoming unverifiable themselves.
- **Pattern mismatch for the level**: a vague, rushed, generic cold message for a senior/executive \
  role. Genuine retained recruiters lead with specifics (mandate, scope, comp band) and move deliberately.

### AI-generated, mass-blast & resume-harvesting signals
Many fake or low-quality recruiter contacts are automated pipelines whose real goal is to harvest \
resumes and personal data, not to fill a role. Detect and weight these:
- **AI-generated / templated text**: generic, polished-but-hollow phrasing with no real \
  personalization; boilerplate openers ("I hope this message finds you well," "I came across your \
  impressive profile"); praise that names no specific project, employer, or detail from the \
  candidate's actual background; uniform machine-written structure; leftover or wrong template \
  fields ([First Name], wrong role, wrong tech stack, wrong seniority).
- **Scraped flattery (do NOT mistake for genuine interest)**: word-for-word details lifted from the \
  candidate's PUBLIC LinkedIn — job titles, employers, posts, skills — used as "personalized" praise. \
  This is trivially automated, so quoting the candidate's own profile back at them is NOT a green \
  light and must not lower the scam_likelihood_score. Real interest shows specific knowledge of the ROLE \
  and COMPANY and a coherent reason for the outreach — not flattery that echoes the candidate's bio.
- **Resume / data harvesting as the real goal**: the immediate ask is the candidate's resume, full \
  contact details, or to "complete your profile" on an external portal — before any real \
  conversation about the role. A vague role used as bait to collect candidates.
- **Automated drip follow-ups**: scripted, suspiciously regular follow-ups ("just bumping this," \
  "circling back," "last chance") on an automated cadence, each escalating the request for \
  information — a sign of a bulk pipeline, not a human recruiter who knows the candidate's situation.
- **Link-to-form / portal**: pushed to a third-party form or unfamiliar "application portal" that \
  collects data, instead of the company's real careers site.

IMPORTANT — avoid false positives: legitimate recruiters DO use templates and AI assistance now. \
AI-sounding text ALONE is a yellow flag, not proof of a scam. It becomes a strong (red) signal only \
when combined with vagueness, immediate data-collection, automated cadence, or unverifiable \
identity. When AI-generated text + immediate data-collection + automated follow-ups appear together, \
treat it as a likely data_harvesting / ghost_job operation and raise the scam_likelihood_score hard.

### Template, placeholder & self-contradiction tells — lazy fakes give themselves away
These are some of the strongest, easiest-to-verify scam signals. Flag them by name and raise the scam_likelihood_score hard.
- **Leftover template/placeholder artifacts**: a Canva default website like **reallygreatsite.com**, \
  plus example.com, yourname@email.com, "[First Name]", lorem-ipsum text, or stock placeholder \
  imagery — proof the signature/message was built from a template and never finished.
- **Senior title at a named company + free personal email**: e.g. "VP Talent Acquisition at \
  Brightwave Insurance" writing from @gmail.com / @yahoo.com / @outlook.com. A real corporate executive uses \
  the company domain. This combination is almost never legitimate.
- **Company name stuffed into a free-email address**: addresses like allstate.recruiting@gmail.com, \
  careers.stripe@outlook.com, or hr-google@yahoo.com put the company name in the LOCAL part (before \
  the @) to look official. The actual domain is still gmail/yahoo/outlook, so it is NOT a corporate \
  address — this is a common impersonation tactic. Judge legitimacy by the DOMAIN after the @, never \
  by words before it. Treat company-name-in-a-free-inbox as a red flag, not a corporate green light.
- **Self-contradicting identity**: the title/header claims a senior role at a big company, but the \
  bio or body says something incompatible (e.g. "VP at Brightwave Insurance" up top, "independent contract \
  recruiter" in the bio). Inconsistent identity = treat as impersonation.

### Communication concerns
- Pushing immediately to WhatsApp, Telegram, or personal text
- No real phone or video interview — only text/chat
- Offer made without a real interview process
- Extreme urgency ("respond today", "positions filling fast")
- Recruiter deflects specific questions about the company or role

### LinkedIn profile red flags — even when the profile looks real
Even a seemingly legitimate LinkedIn profile can be fake, planted, or stolen. Look for:

**Identity mismatch:**
- "Open to Work" banner — they are job searching, not placing candidates
- Background has no recruiting, staffing, or executive search experience
- Current industry has nothing to do with the role or company they're pitching
- Email domain doesn't match any employer in their LinkedIn history
- Listed employer doesn't exist on LinkedIn or was just recently created

**Thin or planted profile:**
- Under 150 connections — active recruiters typically have 500+
- No recommendations from named individuals (easy to fake, hard to fake well)
- No endorsements for recruiting-specific skills
- Generic bio language: "passionate about connecting talent with opportunities" — \
  real recruiters name industries, clients, and specialisations
- No posts, no comments, no activity for months or years
- Profile URL still has the auto-generated number string (e.g. /in/name-4b8a9c2) \
  rather than a clean customised URL — indicates minimal profile investment
- Recently joined LinkedIn relative to their claimed years of experience

**AI-generated or stolen profile photo:**
- AI-generated: perfect skin with no pores, overly symmetrical face, blurred or \
  gradient background, slightly unnatural hair edges, jewellery that looks off
- Stolen: running the photo through Google Images or TinEye (reverse image search) \
  reveals it belongs to someone else
- Stock photo: professional headshot style with no personal context clues

**Company page signals:**
- The company they claim to work for has no LinkedIn page
- Or the company page was created recently with only 1–2 employees
- Or the company page employee count doesn't match the size they're claiming

---
## PAY-TO-PLAY ASSESSMENT
Score 0–100. Legitimate staffing firms are always paid by employers, never candidates. Flag:
- Coaching, resume, or LinkedIn service pitch embedded in the outreach
- "Exclusive access" to job listings for a fee
- "Guaranteed placement" for an upfront investment
- Any language that makes the candidate feel they need to pay to compete

---
## COMPANY IDENTIFICATION
Extract every clue: industry, size, tech stack, location, email domain, accidental details. \
Name specific likely companies. Watch for impersonation of well-known brands. \
Give the job seeker 2–3 concrete things they can do right now to verify.

---
## WEB PRESENCE ASSESSMENT
Use provided search results to assess the recruiter's and company's web presence. \
Flag any scam reports, fraud complaints, or mismatches found in search results. \
The search results may include channel-specific scans, labeled with headers like \
"## Phone source", "## LinkedIn source", or "## Platform source":
- **Phone source**: if the number appears on scam/spam/robocall-report sites (e.g. who-called \
  databases), treat that as a strong red flag and raise the score.
- **LinkedIn source**: compare the profile URL/name against the claims in the message. A name \
  guessed from the profile URL that doesn't match the sender, or scam mentions, is a red flag.
- **Platform source**: factor in known scam patterns for that platform (e.g. unsolicited \
  recruiter DMs on Indeed/ZipRecruiter that push off-platform).
Always name the specific finding in `web_presence.red_flags` so the job seeker sees the evidence.

---
## AUTOMATED TECHNICAL EVIDENCE — how to weight it
Each message arrives with automated technical blocks: domain age + DNS/MX/SPF/DMARC results, \
Link & URL checks, an optional Email Header Analysis, and a careers-page scan. Treat these as \
hard evidence, stronger than tone or wording:
- **REPLY-TO MISMATCH, failed SPF/DKIM/DMARC, or a disposable email domain** → near-certain \
  spoof or scam. Score very high and say exactly which check failed.
- **A claimed corporate domain with no MX records or missing SPF/DMARC** → strong red flag; \
  real companies have mail infrastructure.
- **URL shorteners or generic form services (Google Forms, Typeform, etc.) as the application \
  path** → strong red flag; nobody hires through a survey form.
- **Punycode, digit-substitution lookalikes, or hiring words bolted onto a domain \
  (acme-careers.net)** → treat as impersonation.
- **Young domains (<180 days) — sender or linked — claiming an established company** → strong red flag.
- **ATS links (Greenhouse/Lever/Workday/Ashby…)**: if the company slug matches the claimed \
  employer, that supports legitimacy; a slug for a different company is a red flag.
- **Careers-page scan hits showing the role on the company's own site** → genuine legitimacy support.
Cite the specific technical finding by name in `red_flags` or `legitimate_signals` so the job \
seeker sees the evidence, not just a conclusion.

---
## DO THE WORK YOURSELF — DON'T HAND OUT HOMEWORK
You are given automated intelligence with each message: live web search results, domain-age \
and DNS checks, scam-report scans, and channel-specific lookups (phone/LinkedIn/platform). \
USE these to reach a conclusive verdict yourself. Do NOT tell the job seeker to "go check" \
things — they came here so they wouldn't have to. Draw the conclusions for them.

When the automated research reveals something, state it as a finding in `red_flags` or \
`legitimate_signals`, e.g.:
- "Domain registered 11 days ago — created right before this outreach"
- "Phone number appears on multiple scam-report sites"
- "No web presence found for this recruiter or company"
- "LinkedIn name from the profile URL doesn't match the sender's claimed name"

Where you genuinely cannot verify something automatically (e.g. whether a LinkedIn profile \
shows "Open to Work", connection count, or whether a photo is AI-generated), do NOT punt it \
to the user as a task. Instead, reason from what you DO have, and if it matters, note it \
briefly inside `reasoning` as a limitation — not as an action item for them.

---
## FOLLOW-UP QUESTIONS
Generate 3–4 questions the job seeker can send to the recruiter. Frame them as natural, \
professional questions any confident candidate would ask. These should smoke out ghost jobs \
and identity theft without tipping them off — legitimate recruiters answer these easily, \
scammers deflect or disappear. Good examples:
- "Can you share the direct link to this role on your careers page?"
- "Who would I be reporting to in this role, and what does their team look like?"
- "What ATS are you using — I'd like to apply through the official system."
- "How long have you been in executive search — I'd love to know more about your background?"""

# ── Structured output schema ───────────────────────────────────────────────────

class ExtractedIdentifiers(BaseModel):
    emails: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    recruiter_names: list[str] = Field(default_factory=list)
    recruiter_company: str = Field(default="", description="The staffing/search firm the recruiter works for")
    job_title: str = Field(default="", description="The job title or role being pitched")
    job_company: str = Field(default="", description="The company where the job opening is (the employer, not the recruiter's firm)")
    company_names: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    linkedin_urls: list[str] = Field(default_factory=list)

class CompanyIntel(BaseModel):
    named_company: str
    likely_identity: str
    confidence: str  # Low / Medium / High
    clues: list[str]
    identity_concerns: list[str]

class PayToPlayAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    label: str  # Unlikely / Possible / Likely / Very Likely
    signals: list[str]
    likely_tactics: list[str]

class WebPresenceAssessment(BaseModel):
    summary: str
    legitimate_findings: list[str]
    red_flags: list[str]

class PhotoAssessment(BaseModel):
    photo_provided: bool
    likely_ai_generated: bool = False
    likely_stock_photo: bool = False
    confidence: str = "Low"  # Low / Medium / High
    observations: list[str] = Field(default_factory=list)

class ScamTypeClassification(BaseModel):
    primary_type: str  # legitimate / ghost_job / data_harvesting / pay_to_play / advance_fee / impersonation / unknown
    type_label: str = Field(description="Human-readable label, e.g. 'Ghost job — resume data harvesting'")
    confidence: str  # Low / Medium / High
    reasoning: str = Field(description="One or two sentences explaining the classification")

class RecruiterAnalysis(BaseModel):
    scam_likelihood_score: int = Field(ge=0, le=100,
        description="0–25=Low, 26–60=Medium, 61–80=High, 81–100=Very High")
    scam_likelihood_label: Literal["Low","Medium","High","Very High"]
    red_flags: list[str]
    legitimate_signals: list[str]
    recommendation: str
    reasoning: str
    scam_classification: ScamTypeClassification
    company_intel: CompanyIntel
    pay_to_play: PayToPlayAssessment
    web_presence: WebPresenceAssessment
    photo_assessment: PhotoAssessment
    identifiers: ExtractedIdentifiers
    follow_up_questions: list[str]

# ── Schema hints (exact field names for free-form JSON output) ─────────────────

_ANALYSIS_SCHEMA = """\
{
  "scam_likelihood_score": <0-100>,
  "scam_likelihood_label": "Low|Medium|High|Very High",
  "red_flags": ["..."],
  "legitimate_signals": ["..."],
  "recommendation": "...",
  "reasoning": "...",
  "scam_classification": {
    "primary_type": "legitimate|ghost_job|data_harvesting|pay_to_play|advance_fee|impersonation|unknown",
    "type_label": "...", "confidence": "Low|Medium|High", "reasoning": "..."
  },
  "company_intel": {
    "named_company": "...", "likely_identity": "...", "confidence": "Low|Medium|High",
    "clues": ["..."], "identity_concerns": ["..."]
  },
  "pay_to_play": {
    "score": <0-100>, "label": "Unlikely|Possible|Likely|Very Likely",
    "signals": ["..."], "likely_tactics": ["..."]
  },
  "web_presence": {"summary": "...", "legitimate_findings": ["..."], "red_flags": ["..."]},
  "photo_assessment": {
    "photo_provided": true|false, "likely_ai_generated": false, "likely_stock_photo": false,
    "confidence": "Low|Medium|High", "observations": ["..."]
  },
  "identifiers": {
    "emails": ["..."], "phone_numbers": ["..."],
    "recruiter_names": ["..."],
    "recruiter_company": "the staffing/search firm they work for",
    "job_title": "the role being pitched e.g. Senior Software Engineer",
    "job_company": "the employer company where the job is (not the recruiter's firm)",
    "company_names": ["..."], "domains": ["..."], "linkedin_urls": ["..."]
  },
  "follow_up_questions": ["..."]
}"""

# ── Analysis ───────────────────────────────────────────────────────────────────

def build_content(message, channel, sender_email, web_results, domain_findings, keyword_flags=None, prior_block="", rules_baseline=""):
    kf_text = ""
    if keyword_flags and keyword_flags.get("any"):
        kf_text = "\n## ⚠ Pre-screening Keyword Alerts (auto-detected)\n"
        if keyword_flags.get("fee"):
            kf_text += f"UPFRONT FEE LANGUAGE: {', '.join(keyword_flags['fee'])}\n"
        if keyword_flags.get("pii"):
            kf_text += f"PERSONAL INFO REQUESTED: {', '.join(keyword_flags['pii'])}\n"
        if keyword_flags.get("urgency"):
            kf_text += f"PRESSURE/URGENCY: {', '.join(keyword_flags['urgency'])}\n"
        if keyword_flags.get("off_channel"):
            kf_text += f"OFF-CHANNEL PUSH: {', '.join(keyword_flags['off_channel'])}\n"

    text = (
        f"Channel: {channel}\n"
        + (f"Sender email: {sender_email}\n" if sender_email else "")
        + (prior_block + "\n" if prior_block else "")
        + (rules_baseline + "\n" if rules_baseline else "")
        + kf_text
        + f"\n## Automated Technical Checks (domain age, DNS/MX/SPF/DMARC, links, email headers)\n{domain_findings}\n"
        + f"\n## Web Research\n{web_results}\n"
        + "\n## Recruiter Message\n---\n" + message + "\n---\n"
        + "\nUsing the automated checks and web research above, reach a conclusive verdict. "
        + "Draw the conclusions yourself — do not hand the job seeker tasks to verify."
        + f"\n\nRespond with ONLY a valid JSON object using EXACTLY these field names:\n{_ANALYSIS_SCHEMA}"
        + "\n\nNo preamble, no explanation, no markdown fences. JSON only."
    )
    return text

def _rules_baseline_block(rules):
    """Compact summary of the deterministic engine's read, injected so the LLM
    enriches it rather than starting blind. The LLM may override with justification."""
    if rules is None: return ""
    d = rules.model_dump()
    lines = [f"\n## Deterministic baseline (Métier's rule engine already scored this)",
             f"Baseline scam_likelihood_score: {d['scam_likelihood_score']} ({d['scam_likelihood_label']}); "
             f"suspected type: {d['scam_classification']['primary_type']}."]
    if d["red_flags"]:           lines.append("Rule-matched red flags: " + "; ".join(d["red_flags"][:8]))
    if d["legitimate_signals"]:  lines.append("Rule-matched trust signals: " + "; ".join(d["legitimate_signals"]))
    lines.append("Use this as your floor: do not score SAFER than the baseline without a concrete, stated reason. "
                 "You may add nuance from the message wording the rules can't see.")
    return "\n".join(lines)

def _extract_json(text: str) -> str:
    """Strip any preamble/postamble and return the raw JSON object."""
    text = text.strip()
    start = text.find("{")
    end   = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON object found in response: {text[:300]}")
    return text[start:end+1]

def analyze(message, channel, sender_email, web_results, domain_findings, keyword_flags=None, prior_block="", rules_baseline=""):
    user_text = build_content(message, channel, sender_email, web_results, domain_findings, keyword_flags, prior_block, rules_baseline)
    text, usage = call_llm(SYSTEM_PROMPT, user_text)
    return RecruiterAnalysis.model_validate_json(_extract_json(text)), usage

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index(): return render_template("index.html", llm=llm_available())

@app.route("/history")
def history(): return render_template("history.html")

@app.route("/questions")
def questions(): return render_template("questions.html")

@app.route("/redflags")
def redflags(): return render_template("redflags.html")

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

@app.route("/assets/<path:filename>")
def assets_file(filename): return send_from_directory(ASSETS_DIR, filename)

@app.route("/favicon.ico")
def favicon(): return send_from_directory(ASSETS_DIR, "metier-icon-small.svg", mimetype="image/svg+xml")

@app.route("/analyze", methods=["POST"])
def analyze_route():
    data         = request.get_json(silent=True) or {}
    message      = (data.get("message")      or "").strip()
    channel      = (data.get("channel")      or "unknown").strip()
    contact_info = (data.get("contact_info") or data.get("sender_email") or "").strip() or None

    if not message: return jsonify({"error":"Message is empty."}), 400

    # Build augmented message and extract sender_email based on channel
    augmented    = message
    sender_email = None

    if channel == "email" and contact_info:
        # Comma-separated email addresses
        all_emails = list(dict.fromkeys(
            e.strip() for e in contact_info.replace(";", ",").split(",") if e.strip()
        ))
        sender_email = all_emails[0] if all_emails else None
        extra = [e for e in all_emails if e.lower() not in message.lower()]
        if extra:
            augmented = "Known email addresses: " + ", ".join(extra) + "\n\n" + message

    elif channel == "linkedin" and contact_info:
        augmented = f"Recruiter LinkedIn profile URL: {contact_info}\n\n" + message

    elif channel == "sms" and contact_info:
        augmented = f"Recruiter phone number: {contact_info}\n\n" + message

    elif channel == "other" and contact_info:
        augmented = f"Source platform: {contact_info}\n\n" + message

    keyword_flags = detect_keyword_flags(augmented)
    quick         = _quick_extract(augmented, sender_email)

    # ── Deterministic technical + pattern signals (NO API key needed) ──
    signals = []
    domain_findings = run_domain_checks(quick["domains"], augmented, signals)
    url_findings    = run_url_checks(augmented, signals)
    header_findings, reply_to = parse_email_headers(data.get("email_headers") or "", signals)
    if reply_to and reply_to not in quick["emails"]:        # Reply-To is the real destination
        quick["emails"].append(reply_to)
        rd = reply_to.split("@")[1]
        if rd not in quick["domains"]:
            quick["domains"].append(rd)
            run_domain_checks([rd], augmented, signals)     # vet the real reply-to domain too
    signals += match_patterns(augmented)
    tech_findings = "\n".join(b for b in (domain_findings, url_findings, header_findings) if b)

    # Web research only feeds the LLM layer — skip its latency in rules-only mode
    use_llm     = llm_available()
    web_results = run_web_research(augmented, sender_email, channel, contact_info) if use_llm \
                  else "Not run (rules-only mode)."

    # Cross-reference this sender against the user's prior entries (known/repeat contacts)
    prior_norm = {_norm(e) for e in quick["emails"]} \
               | {_norm(d) for d in quick["domains"] if _norm(d) not in FREE_EMAIL_DOMAINS}
    if channel == "sms" and contact_info:
        pn = _norm_phone(contact_info)
        if len(pn) >= 7: prior_norm.add(pn)
    elif channel == "linkedin" and contact_info:
        prior_norm.add(_norm(contact_info).rstrip("/"))
    prior_block = prior_history_block(_prior_matches(prior_norm))

    # ── Hybrid verdict: rules engine is the baseline; the LLM layers on top if a key exists ──
    rules = run_rules_analysis(signals, quick, reply_to)
    analysis, usage, provider_label = None, {}, "Rules engine (no AI)"
    if use_llm:
        try:
            analysis, usage = analyze(augmented, channel, sender_email, web_results, tech_findings,
                                      keyword_flags, prior_block, _rules_baseline_block(rules))
            provider_label = f"{PROVIDER_LABEL.get(LLM_PROVIDER, 'Claude')} + rules"
        except ImportError:
            return jsonify({"error": "The 'openai' package is required for OpenAI/Grok. Run: pip install openai"}), 500
        except Exception:
            analysis = None     # any LLM failure → fall back to the deterministic engine, never error out
    if analysis is None:
        analysis = rules                # rules engine IS the verdict (free, no key)

    # Correlate against prior entries; a strong match to a known Scam forces a Scam verdict.
    cross_refs = find_cross_references(analysis, -1)
    apply_known_scam_floor(analysis, cross_refs)
    analysis_id = save_analysis(augmented, channel, analysis, usage)

    result = analysis.model_dump()
    result["analysis_id"]       = analysis_id
    result["cross_references"]  = cross_refs
    result["web_research_ran"]  = bool(use_llm and web_results and "unavailable" not in web_results)
    result["keyword_flags"]     = keyword_flags
    result["provider"]          = provider_label
    result["usage"]             = dict(usage) if usage else {}
    return jsonify(result)

@app.route("/api/history")
def api_history():
    limit  = min(int(request.args.get("limit",200)),500)
    offset = int(request.args.get("offset",0))
    conn   = get_db()
    try:
        rows  = conn.execute(
            "SELECT id,created_at,channel,score,label,result_json,status,entry_type,"
            "manual_title,manual_company,manual_source,manual_url,notes,personal_rating,manual_legit,salary "
            "FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit,offset)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        items = []
        for row in rows:
            if (row["entry_type"] or "vetted") == "manual":
                items.append({
                    "id":row["id"],"created_at":row["created_at"],"entry_type":"manual",
                    "status":row["status"] or "Interested",
                    "score":None,"label":None,
                    "recruiter_name":"","recruiter_company":"",
                    "job_title":row["manual_title"] or "","job_company":row["manual_company"] or "",
                    "source":row["manual_source"] or "","url":row["manual_url"] or "",
                    "notes":row["notes"] or "",
                    "rating":row["personal_rating"] or 0,"manual_legit":row["manual_legit"] or "",
                    "salary":row["salary"] or "",
                    "emails":[],"domains":[],"recommendation":row["notes"] or "","red_flags":[]})
            else:
                r   = json.loads(row["result_json"] or "{}")
                ids = r.get("identifiers",{})
                # manual_* columns act as user overrides for the extracted fields
                items.append({
                    "id":row["id"],"created_at":row["created_at"],"entry_type":"vetted",
                    "status":row["status"] or "Interested",
                    "channel":row["channel"],"score":row["score"],"label":row["label"],
                    "recruiter_name":  (ids.get("recruiter_names") or [""])[0],
                    "recruiter_company": ids.get("recruiter_company",""),
                    "job_title":       row["manual_title"]   or ids.get("job_title",""),
                    "job_company":     row["manual_company"] or ids.get("job_company",""),
                    "source":          row["manual_source"]  or "",
                    "url":             row["manual_url"]     or "",
                    "emails":ids.get("emails",[]),"domains":ids.get("domains",[]),
                    "notes":row["notes"] or "",
                    "rating":row["personal_rating"] or 0,"manual_legit":"",
                    "salary":row["salary"] or "",
                    "recommendation":r.get("recommendation",""),
                    "red_flags":r.get("red_flags",[])})
        return jsonify({"total":total,"items":items,"statuses":VALID_STATUSES})
    finally:
        conn.close()

@app.route("/api/application", methods=["POST"])
def api_add_application():
    data    = request.get_json(silent=True) or {}
    title   = (data.get("title")   or "").strip()
    company = (data.get("company") or "").strip()
    source  = (data.get("source")  or "").strip()
    url     = (data.get("url")     or "").strip()
    status  = (data.get("status")  or "Interested").strip()
    notes   = (data.get("notes")   or "").strip()
    salary  = (data.get("salary")  or "").strip()
    if not title and not company:
        return jsonify({"error":"Add at least a job title or company."}), 400
    if status not in VALID_STATUSES:
        status = "Interested"
    new_id = add_manual_job(title, company, source, url, status, notes, salary)
    return jsonify({"id":new_id, "ok":True})

@app.route("/api/status", methods=["POST"])
def api_update_status():
    data   = request.get_json(silent=True) or {}
    entry_id = data.get("id")
    status   = (data.get("status") or "").strip()
    if not entry_id or status not in VALID_STATUSES:
        return jsonify({"error":"Valid id and status required."}), 400
    update_status(entry_id, status)
    return jsonify({"ok":True})

@app.route("/api/notes", methods=["POST"])
def api_update_notes():
    data     = request.get_json(silent=True) or {}
    entry_id = data.get("id")
    notes    = (data.get("notes") or "").strip()
    if not entry_id:
        return jsonify({"error":"id required"}), 400
    update_notes(entry_id, notes)
    return jsonify({"ok":True})

LEGIT_WORDS = {"", "Legit", "Dubious", "Scam"}

@app.route("/api/entry/<int:entry_id>", methods=["POST"])
def api_update_entry(entry_id):
    data = request.get_json(silent=True) or {}
    if "status" in data and data["status"] and data["status"] not in VALID_STATUSES:
        return jsonify({"error": "Invalid status."}), 400
    if "manual_legit" in data and (data["manual_legit"] or "") not in LEGIT_WORDS:
        return jsonify({"error": "Invalid legitimacy value."}), 400
    update_entry(entry_id, data)
    return jsonify({"ok": True})

@app.route("/api/entry/<int:entry_id>", methods=["DELETE"])
def api_delete_entry(entry_id):
    delete_entry(entry_id)
    return jsonify({"ok":True})

@app.route("/api/analysis/<int:analysis_id>")
def api_analysis(analysis_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT result_json FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        if not row: return jsonify({"error":"Not found"}), 404
        return jsonify(json.loads(row["result_json"]))
    finally:
        conn.close()

# ── Startup ────────────────────────────────────────────────────────────────────

init_db()
sync_patterns_from_json()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
