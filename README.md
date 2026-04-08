<div align="center">

# 🛡️ AEGIS-G4
### Autonomous Edge-based Global Intelligence Swarm — v3.0

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Powered by Gemma 4](https://img.shields.io/badge/Powered%20by-Gemma%204-orange.svg)](https://ai.google.dev/gemma)
[![Hackathon: Gemma 4 Good](https://img.shields.io/badge/Hackathon-Gemma%204%20Good-green.svg)](https://www.kaggle.com/competitions/gemma-4-good)
[![Edge Computing](https://img.shields.io/badge/Edge-Ollama%20%7C%20llama.cpp-purple.svg)](https://ollama.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red.svg)](https://attack.mitre.org)
[![Author](https://img.shields.io/badge/Author-mootoo-blue.svg)](https://github.com/mootoo)

**A fully local, privacy-first cybersecurity intelligence swarm that discovers exposed API credentials on the internet, traces full attack chains to their GitHub source, and prepares responsible disclosure reports — powered entirely by Gemma 4's multimodal, function-calling, and chain-of-thought capabilities.**

*Submitted to the [Gemma 4 Good Hackathon](https://www.kaggle.com/competitions/gemma-4-good) — Google DeepMind × Kaggle*

---

```
╔══════════════════════════════════════════════════════════════════════╗
║  AGENT INTELLIGENCE FEED   │  THREAT FINDINGS  │  LIVE STATS        ║
║  👑 COMMANDER  Initiating..│  🔴 192.x.x.x:80  │  🌍 DE:12  US:9    ║
║  🔭 SCOUT  ZoomEye query.. │  🟠 45.x.x.x:8080 │  🎯 CRIT:3 HIGH:7  ║
║  🛡  SENTINEL  Analyzing.. │  🟡 103.x.x.x:443 │  🔑 TELEGRAM:8     ║
║  ⚖️  CRITIC  Reviewing...  │  ⛓  CHAIN: github │  ⛓  Chains:5      ║
╠════════════════════════════╧═══════════════════╧════════════════════╣
║  🔎 EVIDENCE │ ⚔️ T1552.001 Credential Access │ ⛓ ATTACK CHAIN     ║
╠══════════════════════════════════════════════════════════════════════╣
║  ▶ LAUNCH  ✓ APPROVE  ↺ REFRESH  ✗ DISMISS  ⊘ ABORT  ● SCANNING   ║
╚══════════════════════════════════════════════════════════════════════╝
```

</div>

---

## 📖 Table of Contents

- [The Problem](#-the-problem)
- [The Solution: AEGIS-G4](#-the-solution-aegis-g4)
- [Architecture](#️-architecture)
- [What's New in v3.0](#-whats-new-in-v30)
- [Gemma 4 Features Used](#-gemma-4-features-used)
- [Tech Stack](#️-tech-stack)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [War Room Dashboard](#-war-room-dashboard)
- [Ethical Framework](#️-ethical-framework)
- [Project Structure](#-project-structure)
- [Hackathon Tracks](#-hackathon-tracks)
- [License](#-license)

---

## 🚨 The Problem

Every day, developers accidentally push **exposed API tokens** to public-facing web applications — embedded in debug pages, admin dashboards, and staging environments. These aren't hypothetical risks:

- 🔑 **Millions of credentials** are exposed on internet-facing services indexed by ZoomEye and Shodan
- ⚡ **Automated harvesters** (run by malicious actors) steal these tokens within **minutes** of exposure
- 🤖 **Hijacked bots** become Command-and-Control (C2) infrastructure for phishing and malware campaigns
- 💳 **Stripe keys** allow direct financial fraud — charging real cards without a trace
- 💸 **Existing solutions** are manual, legally questionable, or require expensive cloud infrastructure

**The gap:** No open-source, local-first, AI-powered tool can *discover*, *trace full attack chains*, and *responsibly report* these exposures in a legally compliant, fully automated way.

---

## 💡 The Solution: AEGIS-G4

AEGIS-G4 is a **True Multi-Agent Cybersecurity Swarm** running entirely on a standard laptop. It:

1. **Discovers** exposed credential endpoints using 40+ battle-tested ZoomEye dorks from `dorks_library.py`
2. **Validates** targets with a 3-second HEAD pre-check (Circuit Breaker) — skips dead URLs instantly
3. **Analyzes** each target multimodally — screenshot + HTML — to determine malicious intent
4. **Traces Attack Chains** via GitHub Code Search — links live credentials to their original repository/commit
5. **Scores** every finding with a 5-factor Risk Algorithm (0–100) mapped to MITRE ATT&CK
6. **Reviews** findings through an adversarial Critic Agent to eliminate false positives
7. **Attributes** findings to named Threat Campaigns for cross-target correlation
8. **Drafts** professional disclosure reports following ISO/IEC 29147:2018
9. **Requires** explicit human approval before any action — zero autonomous dispatching

> ⚠️ **AEGIS-G4 is a defensive tool.** Read-only. No token validation against external APIs. Human-in-the-Loop required for all actions.

---

## 🏗️ Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │          COMMANDER  (Gemma 4 27B)            │
                    │    Orchestrator · Risk Scorer · CoT Active   │
                    │    Campaign Correlation · Final Decision      │
                    └──────────┬───────────┬────────────┬──────────┘
                               │           │            │
             ┌─────────────────▼──┐  ┌─────▼──────┐  ┌─▼──────────────┐
             │  SCOUT  (Gemma E4B) │  │  SENTINEL  │  │  CRITIC  (E2B) │
             │  ZoomEye Dork Query │  │  (E4B+Vision│  │  Adversarial   │
             │  40+ Strategic Dorks│  │  Screenshot │  │  Review        │
             │  GitHub Code Search │  │  + Code Scan│  │  Safety Gate   │
             │  Circuit Breaker    │  │  Intent AI  │  │  False Positive │
             └────────────────────┘  └────────────┘  └────────────────┘
                                            │
                      ┌─────────────────────▼──────────────────────┐
                      │          WAR ROOM TUI (4 Panels)            │
                      │  Agent Feed │ Findings Table │ Live Stats   │
                      │  Evidence Panel + MITRE + Attack Chain      │
                      │  ✓ APPROVE (human)  ✗ DISMISS  ⊘ ABORT    │
                      └────────────────────────────────────────────┘
```

### Full Intelligence Pipeline

```
dorks_library.py (40+ dorks)
       │
       ▼
ZoomEye Search ──→ IP List ──→ [Circuit Breaker HEAD check 3s]
                                    │                    │
                              ✅ ALIVE            ❌ DEAD (skipped)
                                    │
                              Playwright Capture
                              (screenshot + HTML)
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
              Regex Token Scan              Vision AI Analysis
              (5 credential types)         (Gemma 4 multimodal)
              MITRE ATT&CK mapping
                    │
              GitHub Code Search ──→ Source Repo/Commit Attribution
                    │
              AbuseIPDB Reputation ──→ Abuse Score (0-100)
                    │
              Risk Score Algorithm (5 factors → 0-100)
                    │
              Campaign Attribution ──→ Threat Actor Clustering
                    │
              Critic Review ──→ False Positive Filter
                    │
              Commander Decision ──→ Structured Report
                    │
              [ HUMAN APPROVAL ] ──→ ISO 29147 Disclosure
```

---

## 🆕 What's New in v3.0

### `dorks_library.py` — Strategic Intelligence Library
- **40+ battle-tested ZoomEye dorks** organized by credential type and impact priority
- Each dork annotated with: MITRE technique, expected yield (HIGH/MEDIUM/LOW), target credential type
- Categories: Telegram (×10), Discord (×6), GitHub PAT (×5), Stripe (×5), Slack (×4), General (×10)
- Helper functions: `get_top_dorks()`, `get_high_yield_dorks()`, `get_dorks_for_session()`

### Circuit Breaker + Smart URL Validation
- **Phase 1:** 3-second HEAD request validates URL before Playwright spends 30s on a dead page
- **Phase 2:** Full Playwright capture (only for live targets)
- **Phase 3:** httpx fallback (for non-browser pages)
- Dead domains are cached for **120 seconds** — never retried within the same session
- **Result:** 70–90% reduction in wasted time on unreachable targets

### 4-Panel War Room Dashboard
- **Agent Feed:** Live Chain-of-Thought stream from all 4 agents with timestamps and icons
- **Findings Table:** Scrollable table with risk bar, country flag, credential type, chain indicator
- **Live Stats Panel (right sidebar):**
  - 🌍 Country distribution with flag emojis + histogram bars (32 countries)
  - 🎯 Risk level overview with percentage breakdown
  - 🔑 Credential type breakdown with icons
  - ⛓ Attack chains confirmed + GitHub-attributed count
  - 🏕 Campaign names with alert badges
  - 🏢 Top ISPs / infrastructure
  - 🔌 Port distribution
  - ⚡ Performance metrics (rate/min, elapsed, skipped)
- **Evidence Panel:** XAI breakdown, MITRE techniques, attack chain, AbuseIPDB score
- **JSON Export:** `Ctrl+E` exports all findings with full statistics

### Enhanced Data Model (`SwarmResult`)
- `targets_skipped` — dead URLs bypassed by circuit breaker
- `attack_chains_confirmed` — GitHub-attributed full chains
- `country_stats` — per-country finding counts
- `credential_stats` — per-type credential counts
- `campaign_ids` — named threat campaigns

---

## ✨ Gemma 4 Features Used

| Feature | Agent | Implementation |
|---------|-------|---------------|
| **🔮 Multimodal Vision** | Sentinel | Screenshot + HTML analyzed simultaneously — detects phishing UI even without token text |
| **⚡ Native Function Calling** | All Agents | `@tool` decorated functions: ZoomEye search, GitHub search, AbuseIPDB check, report drafting |
| **🧠 Chain-of-Thought** | Commander + Critic | Explicit reasoning streamed live to War Room; every decision is explainable |
| **📟 Edge Models (E2B/E4B)** | Scout + Sentinel + Critic | Gemma 4 E4B/E2B on Ollama — no cloud, no data leaves the device |
| **🖥️ Large Model (27B)** | Commander | Maximum reasoning quality for orchestration, risk scoring, and campaign attribution |
| **📊 Structured Output** | Commander | Pydantic-validated `AbuseReport` schema — no hallucinated field names |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Agent Framework** | `smolagents` (HuggingFace) | Multi-agent swarm, native function calling, managed agents |
| **Local Inference** | `Ollama` + `llama.cpp` | Edge-first Gemma 4 — works offline, no API costs |
| **Web Intelligence** | `Playwright` (async) | Headless Chromium; blocks images/media for speed |
| **Fast Validation** | `httpx` + Circuit Breaker | 3s HEAD pre-check; smart retry suppression |
| **HTML Parsing** | `BeautifulSoup4` + `lxml` | Fast script extraction from captured pages |
| **Threat Intel** | `AbuseIPDB` API | Free-tier IP reputation (1000/day) |
| **Data Validation** | `Pydantic v2` | Typed, structured report schemas |
| **Terminal UI** | `Textual` | 4-panel interactive War Room dashboard |
| **Configuration** | `python-dotenv` | Zero hardcoded secrets — `.env` only |

---

## 🚀 Getting Started

### Prerequisites

- Python **3.11+**
- [Ollama](https://ollama.com) installed and running (`ollama serve`)
- A [ZoomEye API key](https://www.zoomeye.ai) (free tier: 10,000 results/month)
- Optional: [AbuseIPDB API key](https://www.abuseipdb.com) (free: 1,000 checks/day)
- Optional: [GitHub Token](https://github.com/settings/tokens) (for Code Search correlation — free)

### 1. Clone & Install

```bash
git clone https://github.com/mootoo/AEGIS-G4.git
cd AEGIS-G4

pip install -r requirements.txt
playwright install chromium
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and configure your keys:

```env
# Required
ZOOMEYE_API_KEY=your_zoomeye_key_here
DEMO_MODE=true                  # Safe demo mode (targets honeypot only)

# Recommended (free tiers)
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
GITHUB_TOKEN=ghp_your_token_here   # Enables attack chain tracing

# Models (adjust to your hardware)
COMMANDER_MODEL=gemma4:27b         # Requires ~32GB RAM or GPU
SENTINEL_MODEL=gemma4:4b           # Requires ~6GB RAM
CRITIC_MODEL=gemma4:2b             # Requires ~3GB RAM
```

### 3. Pull Gemma 4 Models

```bash
# Lightweight edge models (fits in 8GB RAM total)
ollama pull gemma4:2b
ollama pull gemma4:4b

# Commander (requires 32GB RAM or good GPU)
ollama pull gemma4:27b

# Start Ollama server (keep running in background)
ollama serve
```

### 4. Launch

```bash
# Interactive War Room — 4-panel dashboard (recommended)
python main.py ui --with-honeypot

# Headless mode — JSON output to stdout
python main.py headless

# Demo-safe mode — honeypot only, no external requests
python main.py ui --with-honeypot --honeypot-port 8888
```

---

## 🎮 Usage

### War Room Dashboard (4 Panels)

| Panel | Description |
|-------|-------------|
| **🧠 Agent Intelligence Feed** (left) | Real-time CoT stream from all 4 agents with timestamps and icons |
| **🛰 Threat Intelligence Findings** (center) | Live table: IP, port, country flag, risk bar, credential type, chain indicator |
| **📊 Live Statistics Dashboard** (right) | Countries, risk levels, credential types, attack chains, campaigns, ISPs, ports |
| **🔎 Evidence Panel** (bottom) | MITRE techniques, XAI decision, attack chain, AbuseIPDB score, commander reasoning |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+L` | Launch swarm mission |
| `Ctrl+A` | Approve selected report |
| `Ctrl+E` | Export all findings to JSON |
| `Escape` | Dismiss current finding |
| `R` | Refresh stats dashboard |
| `Ctrl+Q` | Quit |

### Demo Mode (Safe for Video Recording)

With `DEMO_MODE=true`, the swarm targets only your local honeypot server. The built-in honeypot serves a fake "Bot Manager" page containing a structurally-valid but completely non-functional Telegram token — demonstrates the full pipeline safely on camera.

```bash
python main.py ui --with-honeypot --honeypot-port 8888
```

### Intelligence Dork Library

The `dorks_library.py` module contains **40+ strategic ZoomEye dorks**. To preview them:

```bash
python dorks_library.py
```

Output:
```
📚 AEGIS-G4 Dork Library — 40 dorks loaded
   HIGH yield: 28 | Categories: ['TELEGRAM', 'DISCORD', 'GITHUB', 'STRIPE', 'SLACK', 'GENERAL']

🎯 Top 5 Priority Dorks:
   1. [TELEGRAM] http.body:"api.telegram.org/bot" http.status:200
   2. [TELEGRAM] http.body:"sendMessage" http.body:"chat_id" http.body:"token"
   3. [GITHUB]   http.body:"ghp_" http.status:200
   4. [STRIPE]   http.body:"sk_live_" http.status:200
   5. [SLACK]    http.body:"xoxb-" http.status:200
```

---

## ⚖️ Ethical Framework

AEGIS-G4 is designed with **legal compliance as a hard architectural constraint**, not an afterthought:

### What AEGIS-G4 DOES ✅
- Scans **publicly accessible** URLs indexed by ZoomEye
- Detects token patterns using **local regex only** — no external API token validation
- Analyzes **publicly visible** HTML/screenshots (read-only, no authentication)
- Traces token origins via GitHub's **public** Code Search API
- Checks IP reputation via **AbuseIPDB** (public threat intelligence)
- Drafts reports following **ISO/IEC 29147:2018** responsible disclosure standard
- Requires **explicit human approval** for every report before any action

### What AEGIS-G4 NEVER DOES ❌
- ❌ Call `api.telegram.org`, Discord, Slack, GitHub, or Stripe APIs with a discovered token
- ❌ Send any report, email, or submission autonomously
- ❌ Access, modify, or delete data on any target system
- ❌ Display full credential values (always shown as `XXXXXXXX...[REDACTED]`)
- ❌ Operate without Human-in-the-Loop oversight at every decision point

### Human-in-the-Loop Pipeline

Every finding passes through this chain before any external action:

```
Scout → Sentinel → Critic → Commander → [ WAR ROOM ] → [ HUMAN ✓ ] → ISO Report
         (vision)  (safety)  (XAI+score)  (TUI review)   (explicit)
```

---

## 📂 Project Structure

```
AEGIS-G4/
├── main.py                 # CLI entry point — ui / headless / honeypot modes
├── swarm_orchestrator.py   # Multi-agent swarm (Commander + Scout + Sentinel + Critic)
├── aegis_tools.py          # @tool library: ZoomEye, Playwright, Regex, AbuseIPDB, GitHub
│                           #   → Circuit Breaker + Fast URL Validation (v3.0)
│                           #   → Multi-credential detection (5 types, regex-only)
│                           #   → MITRE ATT&CK mapping + Risk scoring (0-100)
│                           #   → Attack chain tracing via GitHub Code Search
│                           #   → Campaign correlation engine
├── dorks_library.py        # 40+ strategic ZoomEye dorks (NEW in v3.0)
│                           #   → Organized by: credential type, yield, MITRE ID
│                           #   → get_top_dorks(), get_dorks_for_session()
├── war_room_ui.py          # Textual TUI — 4-panel War Room dashboard (v3.0 rewrite)
│                           #   → Live stats: countries, risk, creds, chains, campaigns
│                           #   → Evidence panel with XAI + MITRE + attack chain
│                           #   → JSON export (Ctrl+E)
├── requirements.txt        # Python dependencies (lxml added in v3.0)
├── .env.example            # Environment config template (copy to .env)
├── .gitignore              # Prevents .env and secrets from being committed
└── README.md               # This file
```

---

## 🔑 Credential Detection Coverage

| Credential Type | Pattern | MITRE Technique | Severity |
|----------------|---------|----------------|---------|
| **Telegram Bot Token** | `\d{8,10}:[A-Za-z0-9_-]{35,}` | T1552.001 + T1102 (C2) | 🔴 CRITICAL |
| **GitHub PAT** | `ghp_[A-Za-z0-9]{36}` | T1195.001 (Supply Chain) | 🔴 CRITICAL |
| **Discord Bot Token** | `[MN][A-Za-z\d]{23}\.[...]{6}\.[...]{27}` | T1078.004 (Cloud Acct) | 🟠 HIGH |
| **Stripe Secret Key** | `sk_live_[A-Za-z0-9]{24,}` | T1657 (Financial Theft) | 🔴 CRITICAL |
| **Slack Token** | `xox[baprs]-[0-9]{12}-...` | T1552.001 + T1213.003 | 🟠 HIGH |

---

## 🏆 Hackathon Tracks

AEGIS-G4 targets **three prize categories simultaneously**:

| Track | Prize | Qualification |
|-------|-------|--------------|
| **🥇 Main Track** | $100,000 | Novel multi-agent swarm solving a real global threat; measurable impact via disclosed vulnerabilities |
| **🛡️ Safety & Reliability** | $10,000 | Critic Agent adversarial review, Human-in-the-Loop enforcement, ISO 29147 compliance, zero autonomous actions |
| **⚡ Edge Computing** | $10,000 | Gemma 4 E2B/E4B running locally via Ollama + llama.cpp — complete offline operation on a standard laptop |

---

## 📄 License

Released under the **Creative Commons Attribution 4.0 International (CC BY 4.0)** license, as required by the Gemma 4 Good Hackathon rules.

You are free to use, share, and adapt this work — provided you give appropriate credit to **mootoo**.

[creativecommons.org/licenses/by/4.0](https://creativecommons.org/licenses/by/4.0/)

---

<div align="center">

**Built with ❤️ by [mootoo](https://github.com/mootoo) for the [Gemma 4 Good Hackathon](https://www.kaggle.com/competitions/gemma-4-good)**

*Google DeepMind × Kaggle · 2026*

`AEGIS-G4 v3.0` · `40+ Dorks` · `5 Credential Types` · `MITRE ATT&CK` · `Circuit Breaker` · `Attack Chain Tracing`

</div>
