<p align="center">
  <img src="assets/metier-logo.svg" alt="Metier" width="320" />
</p>

# Metier

**Find your calling. Screen out the noise.** Metier is the recruiter legitimacy check for career professionals. Paste any recruiter email, LinkedIn DM, or outreach message and get an AI-powered read on whether it's worth your time — plus a tracker for every job you're pursuing.

*Pronounced "met-yay" — from* métier*, your calling, your craft, your vocation.*

- 🎯 **Legitimacy Score** (0–100) with a color-coded verdict
- 🔍 **LinkedIn identity check** — does their background actually match who they claim to be?
- 🏢 **Company intelligence** — who the company likely *actually* is
- 💬 **Questions to send them** — tailored follow-ups that smoke out ghost jobs
- ✅ **Verification checklist** — auto-checks domain age, DNS, and more
- 🔗 **Cross-reference** — flags if the same identity appeared in a previous analysis
- 🌐 **Live web research** — searches for scam reports automatically
- 📋 **Job tracker** — every vetted contact and self-found role in one pipeline, with status tracking

---

## Quick start

### 1. Get an API key

Sign up at **[console.anthropic.com](https://console.anthropic.com)** and create an API key.

### 2. Clone and install

```bash
git clone https://github.com/your-username/metier.git
cd metier
pip install -r requirements.txt
```

### 3. Add your API key

```bash
cp .env.example .env
# Open .env and add your key
```

### 4. Run

```bash
python app.py
```

---

## Choosing a model provider

Métier runs on **Claude by default**, but supports **OpenAI** and **Grok (xAI)** too. Pick one in `.env`:

```bash
# Claude (default)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=...

# OpenAI
LLM_PROVIDER=openai
OPENAI_API_KEY=...

# Grok / xAI
LLM_PROVIDER=grok
XAI_API_KEY=...
```

Only the key for your chosen provider is required. OpenAI and Grok need the `openai` package (already in `requirements.txt`). The prompts are tuned for Claude, so other models may score a little differently. The footer under each result shows which provider produced the read.

Open **[http://localhost:5000](http://localhost:5000)**

---

## Running as a service (Linux / systemd)

To keep Metier running in the background on any systemd-based Linux host, a unit
file is included. Edit the paths in `metier.service` to match where you cloned it,
then:

```bash
sudo cp metier.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable metier
sudo systemctl start metier
```

You can also deploy it anywhere that runs Python — a VPS, a home server, or a
platform like Railway, Render, or Fly.io.

---

## Project structure

```
metier/
├── app.py                  # Flask server + LLM providers (Claude / OpenAI / Grok)
├── templates/
│   ├── index.html          # Analyzer
│   ├── history.html        # Job Tracker
│   ├── questions.html      # Questions to Ask
│   └── redflags.html       # Common Red Flags
├── assets/                 # Logos & app icons (SVG)
│   ├── metier-logo.svg
│   ├── metier-logo-dark.svg
│   ├── metier-app-icon.svg
│   └── metier-icon-small.svg
├── data/                   # SQLite database (git-ignored)
├── requirements.txt
├── .env.example
└── metier.service          # systemd unit (optional, for Linux hosts)
```

---

## License

MIT
