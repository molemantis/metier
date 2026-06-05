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
VALID_STATUSES = ["Interested", "Applied", "Interviewing", "Offer",
                  "Rejected", "Ghosted", "Not Pursuing"]

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
    # the score badge). Worth pursuing → Interested; flagged → Not Pursuing.
    legit = 100 - analysis.scam_likelihood_score
    initial_status = "Interested" if legit >= 50 else "Not Pursuing"
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

def add_manual_job(title, company, source, url, status, notes):
    """Insert a self-found job (no AI analysis) into the tracker."""
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO analyses "
            "(created_at,msg_hash,message,channel,score,label,result_json,"
            " status,entry_type,manual_title,manual_company,manual_source,manual_url,notes) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), "", "", source or "manual", 0, "",
             "{}", status, "manual", title, company, source, url, notes),
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
_EDITABLE = {
    "title":   "manual_title",
    "company": "manual_company",
    "source":  "manual_source",
    "url":     "manual_url",
    "notes":   "notes",
    "status":  "status",
}

def update_entry(entry_id, fields: dict):
    sets, vals = [], []
    for key, col in _EDITABLE.items():
        if key in fields:
            sets.append(f"{col}=?")
            vals.append((fields[key] or "").strip())
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

def run_domain_checks(domains: list[str]) -> str:
    """Automated domain intel (age via RDAP, DNS resolution) — runs BEFORE Claude
    so the model factors it straight into the verdict. Returns a text block."""
    lines = []
    for domain in domains[:3]:
        if not domain or domain in PERSONAL_DOMAINS:
            if domain in PERSONAL_DOMAINS:
                lines.append(f"{domain}: personal email provider (gmail/yahoo/etc) — not a company domain")
            continue
        info = check_domain(domain)
        bits = [f"{domain}:"]
        if info["age_days"] is not None:
            if info["age_days"] < 30:
                bits.append(f"⚠ REGISTERED ONLY {info['age_days']} DAYS AGO ({info['reg_date']}) — created right before this outreach")
            elif info["age_days"] < 180:
                bits.append(f"young domain, {info['age_days']} days old ({info['reg_date']})")
            else:
                bits.append(f"established, registered {info['reg_date']} ({info['age_days']} days old)")
        else:
            bits.append("registration date unknown")
        bits.append("resolves (live)" if info["resolves"] else "⚠ DOES NOT RESOLVE — domain may not exist")
        lines.append(" ".join(bits))
    return "\n".join(lines) if lines else "No company domains to check."
    return checklist

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
## CLASSIFICATION — what kind of contact is this?
- **legitimate** — genuine recruiter, verifiable company, standard process
- **ghost_job** — posting exists to collect resumes/data; no real open role
- **data_harvesting** — goal is personal info: SSN, bank account, passport, ID, DOB
- **pay_to_play** — will ask for upfront payment (resume services, coaching, fees, deposits)
- **advance_fee** — asks for money before access to jobs, interviews, or first paycheck
- **impersonation** — using a real company's name/brand without affiliation
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

def build_content(message, channel, sender_email, web_results, domain_findings, keyword_flags=None):
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
        + kf_text
        + f"\n## Automated Domain Checks (RDAP age + DNS)\n{domain_findings}\n"
        + f"\n## Web Research\n{web_results}\n"
        + "\n## Recruiter Message\n---\n" + message + "\n---\n"
        + "\nUsing the automated checks and web research above, reach a conclusive verdict. "
        + "Draw the conclusions yourself — do not hand the job seeker tasks to verify."
        + f"\n\nRespond with ONLY a valid JSON object using EXACTLY these field names:\n{_ANALYSIS_SCHEMA}"
        + "\n\nNo preamble, no explanation, no markdown fences. JSON only."
    )
    return text

def _extract_json(text: str) -> str:
    """Strip any preamble/postamble and return the raw JSON object."""
    text = text.strip()
    start = text.find("{")
    end   = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON object found in response: {text[:300]}")
    return text[start:end+1]

def analyze(message, channel, sender_email, web_results, domain_findings, keyword_flags=None):
    user_text = build_content(message, channel, sender_email, web_results, domain_findings, keyword_flags)
    text, usage = call_llm(SYSTEM_PROMPT, user_text)
    return RecruiterAnalysis.model_validate_json(_extract_json(text)), usage

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index(): return render_template("index.html")

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

    keyword_flags   = detect_keyword_flags(augmented)
    web_results     = run_web_research(augmented, sender_email, channel, contact_info)
    # Automated domain intel (RDAP age + DNS) — done up front so Claude factors it in
    quick           = _quick_extract(augmented, sender_email)
    domain_findings = run_domain_checks(quick["domains"])

    try:
        analysis, usage = analyze(augmented, channel, sender_email, web_results, domain_findings, keyword_flags)
    except ImportError:
        return jsonify({"error": "The 'openai' package is required for OpenAI/Grok. Run: pip install openai"}), 500
    except Exception as exc:
        low = str(exc).lower()
        prov = PROVIDER_LABEL.get(LLM_PROVIDER, "Claude")
        if any(k in low for k in ("api key", "api_key", "authentication", "unauthorized", "401")):
            return jsonify({"error": f"Invalid or missing API key for {prov}. Check your .env file."}), 401
        return jsonify({"error": f"{prov} API error: {exc}"}), 502

    analysis_id = save_analysis(augmented, channel, analysis, usage)
    cross_refs  = find_cross_references(analysis, analysis_id)

    result = analysis.model_dump()
    result["analysis_id"]       = analysis_id
    result["cross_references"]  = cross_refs
    result["web_research_ran"]  = bool(web_results and "unavailable" not in web_results)
    result["keyword_flags"]     = keyword_flags
    result["provider"]          = PROVIDER_LABEL.get(LLM_PROVIDER, "Claude")
    result["usage"]             = dict(usage)
    return jsonify(result)

@app.route("/api/history")
def api_history():
    limit  = min(int(request.args.get("limit",200)),500)
    offset = int(request.args.get("offset",0))
    conn   = get_db()
    try:
        rows  = conn.execute(
            "SELECT id,created_at,channel,score,label,result_json,status,entry_type,"
            "manual_title,manual_company,manual_source,manual_url,notes "
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
    if not title and not company:
        return jsonify({"error":"Add at least a job title or company."}), 400
    if status not in VALID_STATUSES:
        status = "Interested"
    new_id = add_manual_job(title, company, source, url, status, notes)
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

@app.route("/api/entry/<int:entry_id>", methods=["POST"])
def api_update_entry(entry_id):
    data = request.get_json(silent=True) or {}
    if "status" in data and data["status"] and data["status"] not in VALID_STATUSES:
        return jsonify({"error": "Invalid status."}), 400
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
