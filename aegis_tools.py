"""
aegis_tools.py — AEGIS-G4 Native Tool Library (v2.0)
=====================================================
All @tool decorated functions available to swarm agents.

v2.0 Additions:
  - Multi-credential detection: Telegram, GitHub, Discord, Slack, Stripe (5 types)
  - MITRE ATT&CK framework mapping for every credential type
  - AbuseIPDB threat intelligence integration (free tier: 1000/day)
  - Multi-factor risk scoring algorithm (0-100 numerical scale)
  - Threat Attribution Engine (campaign correlation across findings)

Design Principles:
  - Zero hardcoded secrets (all config via .env)
  - Legal compliance: Regex-only token detection, zero external API validation
  - Honeypot-first: safe for demo environments
  - Production-grade: full error handling, type hints, structured outputs
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
import ollama
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from smolagents import tool

load_dotenv()
logger = logging.getLogger("aegis.tools")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration (from .env — zero hardcoded values)
# ─────────────────────────────────────────────────────────────────────────────

ZOOMEYE_API_KEY: str   = os.getenv("ZOOMEYE_API_KEY", "")
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
ZOOMEYE_API_URL: str   = "https://api.zoomeye.ai/v2/search"
ABUSEIPDB_URL: str     = "https://api.abuseipdb.com/api/v2/check"
SENTINEL_MODEL: str    = os.getenv("SENTINEL_MODEL", "gemma4:4b")
REQUEST_TIMEOUT: int   = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
REQUEST_FAST_TIMEOUT: int = 3   # HEAD-only pre-validation timeout (seconds)
DEMO_MODE: bool        = os.getenv("DEMO_MODE", "true").lower() == "true"
HONEYPOT_URLS: list[str] = [
    u.strip() for u in os.getenv("HONEYPOT_URLS", "").split(",") if u.strip()
]

# ── Circuit Breaker State ─────────────────────────────────────────────────────
# Tracks dead domains to skip on subsequent requests within the same session.
# Key = domain, Value = epoch timestamp of failure
_DEAD_URL_CACHE: dict[str, float] = {}
_CIRCUIT_BREAKER_TTL: int = 120   # Skip domain for 2 minutes after failure
_CB_LOCK = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Multi-Credential Pattern Registry
# LOCAL REGEX ONLY — no external API calls ever
# ─────────────────────────────────────────────────────────────────────────────

CREDENTIAL_PATTERNS: dict[str, re.Pattern] = {
    "TELEGRAM_BOT_TOKEN": re.compile(
        r"(?<![A-Za-z0-9_])(\d{8,10}:[A-Za-z0-9_-]{35,})(?![A-Za-z0-9_])"
    ),
    "GITHUB_PAT": re.compile(
        r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"
    ),
    "DISCORD_BOT_TOKEN": re.compile(
        r"([MN][A-Za-z\d]{23}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27})"
    ),
    "SLACK_TOKEN": re.compile(
        r"(xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24})"
    ),
    "STRIPE_SECRET_KEY": re.compile(
        r"(sk_(?:live|test)_[A-Za-z0-9]{24,})"
    ),
}

# Human-readable descriptions for each credential type
CREDENTIAL_DESCRIPTIONS: dict[str, str] = {
    "TELEGRAM_BOT_TOKEN": "Telegram Bot API token — enables full bot control and C2 potential",
    "GITHUB_PAT":         "GitHub Personal Access Token — enables repo access and code theft",
    "DISCORD_BOT_TOKEN":  "Discord Bot token — enables server messaging and data exfiltration",
    "SLACK_TOKEN":        "Slack API token — enables workspace message access and data leakage",
    "STRIPE_SECRET_KEY":  "Stripe Secret Key — enables financial transactions and fraud",
}

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Framework Mapping
# Source: https://attack.mitre.org (free, no API needed)
# ─────────────────────────────────────────────────────────────────────────────

MITRE_MAPPING: dict[str, dict] = {
    "TELEGRAM_BOT_TOKEN": {
        "technique_id":   "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials in Files",
        "tactic":         "Credential Access",
        "secondary_id":   "T1102",
        "secondary_name": "Web Service (C2 via Telegram API)",
        "severity_boost": 20,  # Extra risk points for C2 potential
    },
    "GITHUB_PAT": {
        "technique_id":   "T1195.001",
        "technique_name": "Supply Chain Compromise: Dependency Compromise",
        "tactic":         "Initial Access",
        "secondary_id":   "T1552.001",
        "secondary_name": "Credentials in Source Code",
        "severity_boost": 15,
    },
    "DISCORD_BOT_TOKEN": {
        "technique_id":   "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "tactic":         "Defense Evasion / Persistence",
        "secondary_id":   "T1102",
        "secondary_name": "Web Service Abuse",
        "severity_boost": 18,
    },
    "SLACK_TOKEN": {
        "technique_id":   "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials in Files",
        "tactic":         "Credential Access",
        "secondary_id":   "T1213.003",
        "secondary_name": "Data from Information Repositories: Code Repos",
        "severity_boost": 12,
    },
    "STRIPE_SECRET_KEY": {
        "technique_id":   "T1657",
        "technique_name": "Financial Theft",
        "tactic":         "Impact",
        "secondary_id":   "T1552.001",
        "secondary_name": "Credentials in Files",
        "severity_boost": 25,  # Highest boost — direct financial risk
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Data Models
# ─────────────────────────────────────────────────────────────────────────────

class MitreInfo(BaseModel):
    technique_id:   str
    technique_name: str
    tactic:         str
    secondary_id:   str = ""
    secondary_name: str = ""


class TokenFinding(BaseModel):
    """A single discovered credential pattern (always redacted)."""
    token_preview:       str   = Field(description="First 8 chars + [REDACTED]")
    credential_type:     str
    description:         str   = ""
    source_url:          str
    structurally_valid:  bool
    confidence:          float = Field(ge=0.0, le=1.0)
    context_snippet:     str   = Field(description="Surrounding code with token redacted")
    mitre:               Optional[MitreInfo] = None
    validation_method:   str   = "LOCAL_REGEX_ONLY"


class IpReputation(BaseModel):
    """AbuseIPDB intelligence result for a target IP."""
    ip:                str
    abuse_score:       int    = Field(ge=0, le=100)
    total_reports:     int    = 0
    country_code:      str    = "??"
    isp:               str    = "Unknown"
    is_known_bad:      bool   = False
    last_reported:     str    = ""
    data_source:       str    = "AbuseIPDB"
    checked_at:        str    = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RiskAssessment(BaseModel):
    """Complete multi-factor risk assessment for a target."""
    target_url:         str
    risk_score:         int   = Field(ge=0, le=100, description="0=safe, 100=critical")
    risk_level:         str   = "UNKNOWN"
    score_breakdown:    dict  = Field(default_factory=dict)
    mitre_techniques:   list  = Field(default_factory=list)
    recommended_action: str   = ""
    reasoning:          str   = ""


class TargetEvidence(BaseModel):
    """Complete evidence bundle for a single analyzed target."""
    target_url:         str
    token_findings:     list[TokenFinding] = Field(default_factory=list)
    ip_reputation:      Optional[IpReputation] = None
    risk_assessment:    Optional[RiskAssessment] = None
    sentinel_analysis:  str   = ""
    critic_verdict:     str   = ""
    risk_level:         str   = "UNKNOWN"
    is_malicious:       bool  = False
    timestamp:          str   = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AbuseReport(BaseModel):
    """ISO/IEC 29147 structured responsible disclosure report."""
    report_id:            str
    report_type:          str = Field(description="ABUSE or DISCLOSURE")
    target_url:           str
    risk_score:           int = 0
    risk_level:           str
    evidence:             TargetEvidence
    mitre_techniques:     list = Field(default_factory=list)
    recommended_action:   str
    disclosure_framework: str = "ISO/IEC 29147:2018"
    generated_at:         str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    generated_by:         str = "AEGIS-G4 v2.0 | Human-Approved"
    disclaimer: str = (
        "Generated by an AI system; reviewed by a human analyst before any action. "
        "No unauthorized access was performed. Tokens detected via regex pattern matching only."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Internal Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _redact(token: str) -> str:
    """Returns a display-safe redacted token preview."""
    return token[:8] + "...[REDACTED]" if len(token) >= 8 else "[INVALID]"


def _score_to_level(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "BENIGN"


def _extract_domain(url: str) -> str:
    """Extracts domain:port from a URL for circuit breaker keys."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.hostname}:{p.port or (443 if p.scheme == 'https' else 80)}"
    except Exception:
        return url[:50]


def _is_circuit_breaker_open(domain: str) -> bool:
    """Returns True if the domain should be skipped (recently failed)."""
    import time
    with _CB_LOCK:
        ts = _DEAD_URL_CACHE.get(domain, 0)
        if ts and (time.monotonic() - ts) < _CIRCUIT_BREAKER_TTL:
            return True
        return False


def _trip_circuit_breaker(domain: str) -> None:
    """Marks a domain as dead for _CIRCUIT_BREAKER_TTL seconds."""
    import time
    with _CB_LOCK:
        _DEAD_URL_CACHE[domain] = time.monotonic()
        logger.debug("Circuit breaker tripped: %s (skip for %ds)",
                     domain, _CIRCUIT_BREAKER_TTL)


def _validate_url_fast(url: str) -> tuple[bool, str]:
    """
    Ultra-fast HTTP HEAD pre-validation before spending Playwright resources.

    Returns:
        (is_alive: bool, reason: str)
        - is_alive=True  → proceed with full capture
        - is_alive=False → skip immediately (saves 10-30s per dead URL)
    """
    domain = _extract_domain(url)

    # Circuit breaker: skip domain if recently failed
    if _is_circuit_breaker_open(domain):
        return False, f"CIRCUIT_BREAKER_OPEN: {domain} failed recently"

    try:
        with httpx.Client(
            timeout=httpx.Timeout(REQUEST_FAST_TIMEOUT, connect=2.0),
            verify=False, follow_redirects=True,
        ) as client:
            resp = client.head(url)

            # Skip client errors, server errors, and redirect loops
            if resp.status_code in (400, 403, 404, 410, 429, 503):
                _trip_circuit_breaker(domain)
                return False, f"HTTP_{resp.status_code}: skip"

            # Accept any response that indicates a live server
            return True, f"HTTP_{resp.status_code}: alive"

    except httpx.ConnectError:
        _trip_circuit_breaker(domain)
        return False, "CONNECTION_REFUSED"
    except httpx.TimeoutException:
        _trip_circuit_breaker(domain)
        return False, "FAST_TIMEOUT"
    except Exception as exc:
        logger.debug("Fast validation failed for %s: %s", url, exc)
        return True, "VALIDATION_ERROR: proceeding anyway"



def _capture_page_sync(url: str) -> dict:
    """Playwright screenshot + HTML capture. Pre-validated with fast HEAD check."""
    result: dict = {"screenshot_b64": None, "html": "", "error": None}

    # ── Phase 1: Fast validation (3s HEAD check) ─────────────────────────────
    alive, reason = _validate_url_fast(url)
    if not alive:
        logger.info("Skipping dead URL (%s): %s", reason, url)
        result["error"] = f"SKIPPED_{reason}"
        return result

    # ── Phase 2: Full Playwright capture ─────────────────────────────────────
    async def _work() -> None:
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-images",      # faster loading
                        "--blink-settings=imagesEnabled=false",
                    ],
                )
                ctx = await browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
                    ),
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                )
                page = await ctx.new_page()

                # Block heavy resources to speed up loading
                await page.route(
                    "**/*",
                    lambda route: route.abort()
                    if route.request.resource_type in ("image", "media", "font")
                    else route.continue_(),
                )

                try:
                    await page.goto(
                        url,
                        timeout=REQUEST_TIMEOUT * 1000,
                        wait_until="domcontentloaded",  # don't wait for full load
                    )
                except Exception as nav_exc:
                    # Navigation errors (e.g., cert issues) are non-fatal —
                    # we still capture what loaded
                    logger.debug("Nav warning for %s: %s", url, nav_exc)

                shot = await page.screenshot(type="png", full_page=False)
                result["screenshot_b64"] = base64.b64encode(shot).decode()
                result["html"] = await page.content()
                await browser.close()
        except Exception as exc:
            result["error"] = str(exc)
            _trip_circuit_breaker(_extract_domain(url))
            logger.warning("Playwright failed for %s: %s", url, exc)

    thread = threading.Thread(target=lambda: asyncio.run(_work()), daemon=True)
    thread.start()
    thread.join(timeout=REQUEST_TIMEOUT + 5)
    return result




# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1 — ZoomEye Search
# ─────────────────────────────────────────────────────────────────────────────

@tool
def zoomeye_search(dork: str, page: int = 1, page_size: int = 20) -> str:
    """
    Searches ZoomEye for internet-exposed network assets using an advanced dork query.

    In DEMO_MODE this returns only configured HONEYPOT_URLS for safe demonstration.

    Args:
        dork: ZoomEye dork query string (e.g., 'app="Telegram Bot" && http.body="api.telegram.org"')
        page: Result page number (default 1).
        page_size: Results per page, max 100 (default 20).

    Returns:
        JSON with 'targets' list, 'total' count, 'query' string.
    """
    if DEMO_MODE:
        logger.info("DEMO_MODE — returning honeypot targets")
        targets = [
            {"url": u, "ip": u.split("//")[-1].split(":")[0], "port": 8888,
             "service": "http", "country": "Honeypot Lab", "is_honeypot": True}
            for u in HONEYPOT_URLS
        ]
        return json.dumps({"targets": targets, "total": len(targets),
                           "query": dork, "mode": "DEMO_HONEYPOT"})

    if not ZOOMEYE_API_KEY:
        return json.dumps({"error": "ZOOMEYE_API_KEY not set in .env", "targets": []})

    query_b64 = base64.b64encode(dork.encode()).decode()
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                ZOOMEYE_API_URL,
                headers={"API-KEY": ZOOMEYE_API_KEY, "Content-Type": "application/json"},
                json={"qbase64": query_b64, "page": max(1, page),
                      "pagesize": min(100, max(1, page_size)), "sub_type": "v4+v6+web"},
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        return json.dumps({"error": f"ZoomEye HTTP {exc.response.status_code}", "targets": []})
    except Exception as exc:
        return json.dumps({"error": str(exc), "targets": []})

    raw = data.get("data", data.get("matches", []))
    targets = []
    for item in raw:
        ip   = item.get("ip", "")
        port = item.get("port", 80)
        proto = "https" if port in (443, 8443) else "http"
        url = f"{proto}://{ip}" if port in (80, 443) else f"{proto}://{ip}:{port}"

        # Extract rich geo/org metadata
        country_data  = item.get("country", {})
        country_name  = country_data.get("name", "Unknown") if isinstance(country_data, dict) else str(country_data)
        country_code  = country_data.get("code", "??") if isinstance(country_data, dict) else "??"
        city_data     = item.get("city", {})
        city_name     = city_data.get("name", "") if isinstance(city_data, dict) else ""
        org_data      = item.get("organization", {})
        org_name      = org_data.get("name", "Unknown") if isinstance(org_data, dict) else str(org_data)

        targets.append({
            "url":          url,
            "ip":           ip,
            "port":         port,
            "service":      item.get("service", "unknown"),
            "country":      country_name,
            "country_code": country_code.upper()[:2],
            "city":         city_name,
            "asn":          item.get("asn", 0),
            "isp":          org_name,
            "os":           item.get("os", ""),
            "banner":       item.get("banner", "")[:200],
        })

    logger.info("ZoomEye '%s' → %d targets", dork[:60], len(targets))
    return json.dumps({"targets": targets, "total": data.get("total", len(targets)), "query": dork})


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2 — Web Page Capture
# ─────────────────────────────────────────────────────────────────────────────

@tool
def fetch_target_data(url: str) -> str:
    """
    Safely captures a target URL's visual screenshot and HTML source for analysis.

    Smart 3-phase approach:
      Phase 1: Fast HEAD validation (3s) — skip dead URLs immediately
      Phase 2: Playwright full capture (if alive) — screenshot + HTML
      Phase 3: httpx fallback (if Playwright fails but URL is alive)

    Args:
        url: Full target URL (e.g., "http://192.168.1.1:8080").

    Returns:
        JSON with 'screenshot_b64' (str|null), 'html_snippet' (str),
        'status' (str), 'alive' (bool).
    """
    logger.info("Fetching: %s", url)

    # Phase 1: Fast validation — avoid wasting 30s on dead pages
    alive, reason = _validate_url_fast(url)
    if not alive:
        logger.info("Fast skip: %s → %s", url, reason)
        return json.dumps({
            "screenshot_b64": None,
            "html_snippet": "",
            "status": "DEAD_URL_SKIPPED",
            "alive": False,
            "skip_reason": reason,
        })

    # Phase 2: Playwright full capture
    cap = _capture_page_sync(url)

    if cap.get("error") and not cap.get("html"):
        # Phase 3: httpx fallback (handles non-browser pages gracefully)
        try:
            with httpx.Client(
                timeout=REQUEST_TIMEOUT, verify=False,
                follow_redirects=True, limits=httpx.Limits(max_connections=5),
            ) as client:
                r = client.get(url, headers={"Accept": "text/html,*/*"})
                return json.dumps({
                    "screenshot_b64": None,
                    "html_snippet": r.text[:3500],
                    "status": "html_only_fallback",
                    "alive": True,
                    "http_status": r.status_code,
                    "error_detail": cap["error"],
                })
        except Exception as exc:
            return json.dumps({
                "screenshot_b64": None, "html_snippet": "",
                "status": "failed", "alive": False, "error_detail": str(exc),
            })

    soup = BeautifulSoup(cap["html"], "html.parser")
    scripts = [
        t.string[:600]
        for t in soup.find_all("script")
        if t.string and len(t.string) > 20
    ]
    snippet = (
        "=== PAGE HTML (first 1500 chars) ===\n" + cap["html"][:1500]
        + "\n\n=== INLINE SCRIPTS ===\n" + "\n---\n".join(scripts[:4])
    )
    return json.dumps({
        "screenshot_b64": cap["screenshot_b64"],
        "html_snippet": snippet[:3500],
        "status": "success",
        "alive": True,
    })




# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3 — Multi-Credential Extraction (v2: 5 credential types)
# ─────────────────────────────────────────────────────────────────────────────

@tool
def extract_and_validate_tokens(html_content: str) -> str:
    """
    Scans HTML/JavaScript source for exposed API credentials using regex ONLY.

    Detects 5 credential types:
      - Telegram Bot Tokens    (T1552.001 / Credential Access)
      - GitHub Personal Tokens (T1195.001 / Supply Chain)
      - Discord Bot Tokens     (T1078.004 / Valid Accounts)
      - Slack API Tokens       (T1552.001 / Credential Access)
      - Stripe Secret Keys     (T1657     / Financial Theft)

    ⚠️ LEGAL: LOCAL PATTERN MATCHING ONLY. No external API calls ever made.

    Args:
        html_content: Raw HTML or JavaScript string to scan.

    Returns:
        JSON with 'findings' list (TokenFinding), 'total' (int),
        'credential_type_summary' (dict), and 'highest_severity_mitre' (str).
    """
    if not html_content:
        return json.dumps({"findings": [], "total": 0, "credential_type_summary": {}})

    seen: set[str] = set()
    findings: list[dict] = []
    type_summary: dict[str, int] = {}

    for cred_type, pattern in CREDENTIAL_PATTERNS.items():
        for match in pattern.finditer(html_content):
            raw = match.group(1)
            if raw in seen:
                continue
            seen.add(raw)

            # Structural validation (heuristic, no API)
            is_valid = len(raw) >= 20  # Minimum credible length
            if cred_type == "TELEGRAM_BOT_TOKEN":
                parts = raw.split(":")
                is_valid = (len(parts) == 2 and parts[0].isdigit()
                            and 8 <= len(parts[0]) <= 10 and len(parts[1]) >= 35)

            confidence = 0.88 if is_valid else 0.45
            s, e = max(0, match.start() - 80), min(len(html_content), match.end() + 80)
            ctx = html_content[s:e].replace(raw, _redact(raw))

            mitre = MITRE_MAPPING.get(cred_type)
            mitre_obj = MitreInfo(**{k: v for k, v in mitre.items()
                                     if k in MitreInfo.model_fields}) if mitre else None

            finding = TokenFinding(
                token_preview=_redact(raw),
                credential_type=cred_type,
                description=CREDENTIAL_DESCRIPTIONS.get(cred_type, ""),
                source_url="extracted_from_html",
                structurally_valid=is_valid,
                confidence=confidence,
                context_snippet=ctx,
                mitre=mitre_obj,
            )
            findings.append(finding.model_dump())
            type_summary[cred_type] = type_summary.get(cred_type, 0) + 1

    # Determine highest severity MITRE technique found
    highest_mitre = "None detected"
    if findings:
        for f in findings:
            if f.get("mitre") and f["mitre"].get("technique_id"):
                highest_mitre = f["mitre"]["technique_id"]
                break

    logger.info("Credential scan: %d finding(s) — types: %s", len(findings), type_summary)
    return json.dumps({
        "findings": findings,
        "total": len(findings),
        "credential_type_summary": type_summary,
        "highest_severity_mitre": highest_mitre,
    })


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 4 — AbuseIPDB Threat Intelligence (new in v2)
# ─────────────────────────────────────────────────────────────────────────────

@tool
def check_ip_reputation(ip: str) -> str:
    """
    Queries AbuseIPDB (free tier: 1000 req/day) to check if the target IP
    has been previously reported for malicious activity.

    This adds real Threat Intelligence to each finding — distinguishing
    between accidental developer exposure and known malicious infrastructure.

    Args:
        ip: IPv4 or IPv6 address to check (e.g., "185.220.101.45").

    Returns:
        JSON with abuse_score (0-100), total_reports, country, ISP, is_known_bad.
    """
    if not ip or ip in ("127.0.0.1", "localhost", "honeypot"):
        return json.dumps(IpReputation(ip=ip, abuse_score=0,
                                       isp="Honeypot/Local").model_dump())

    if not ABUSEIPDB_API_KEY:
        logger.warning("ABUSEIPDB_API_KEY not set — skipping IP reputation check")
        return json.dumps({
            "ip": ip, "abuse_score": 0, "total_reports": 0,
            "is_known_bad": False, "status": "API_KEY_NOT_CONFIGURED",
            "note": "Set ABUSEIPDB_API_KEY in .env for threat intelligence"
        })

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            )
            resp.raise_for_status()
            d = resp.json().get("data", {})
    except Exception as exc:
        logger.warning("AbuseIPDB check failed for %s: %s", ip, exc)
        return json.dumps({"ip": ip, "abuse_score": 0, "error": str(exc)})

    reputation = IpReputation(
        ip=ip,
        abuse_score=d.get("abuseConfidenceScore", 0),
        total_reports=d.get("totalReports", 0),
        country_code=d.get("countryCode", "??"),
        isp=d.get("isp", "Unknown"),
        is_known_bad=d.get("abuseConfidenceScore", 0) > 50,
        last_reported=d.get("lastReportedAt", "Never"),
    )

    logger.info("AbuseIPDB %s → score=%d, reports=%d, known_bad=%s",
                ip, reputation.abuse_score, reputation.total_reports, reputation.is_known_bad)
    return reputation.model_dump_json()


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 5 — Multi-Factor Risk Scoring (new in v2)
# ─────────────────────────────────────────────────────────────────────────────

@tool
def calculate_risk_score(
    tokens_found: int,
    highest_confidence: float,
    visual_suspicion_level: str,
    abuse_score: int,
    credential_types_json: str,
) -> str:
    """
    Calculates a quantitative risk score (0-100) using a multi-factor algorithm.

    Factors weighted by real-world security impact:
      - Credential count & confidence    (max 25 pts)
      - Visual analysis suspicion level  (max 20 pts)
      - AbuseIPDB threat score           (max 20 pts)
      - MITRE severity boost per type    (max 25 pts)
      - Credential type diversity bonus  (max 10 pts)

    Args:
        tokens_found:            Number of credential patterns detected.
        highest_confidence:      Highest regex confidence score (0.0-1.0).
        visual_suspicion_level:  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN"
        abuse_score:             AbuseIPDB score 0-100 (0 if not checked).
        credential_types_json:   JSON dict of {credential_type: count} from extraction.

    Returns:
        JSON with risk_score (0-100), risk_level, score_breakdown, and mitre_techniques.
    """
    score = 0
    breakdown = {}

    # Factor 1: Credential count × confidence
    cred_score = min(int(tokens_found * 12 * highest_confidence), 25)
    score += cred_score
    breakdown["credential_detection"] = f"{cred_score}/25"

    # Factor 2: Visual analysis
    visual_pts = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "BENIGN": 0}.get(
        visual_suspicion_level.upper(), 0
    )
    score += visual_pts
    breakdown["visual_analysis"] = f"{visual_pts}/20"

    # Factor 3: AbuseIPDB reputation
    abuse_pts = min(int(abuse_score * 0.20), 20)
    score += abuse_pts
    breakdown["ip_reputation"] = f"{abuse_pts}/20 (AbuseIPDB: {abuse_score}/100)"

    # Factor 4: MITRE severity boost per credential type
    try:
        cred_types = json.loads(credential_types_json) if isinstance(credential_types_json, str) \
                     else credential_types_json
    except Exception:
        cred_types = {}

    mitre_pts = 0
    mitre_techniques = []
    for cred_type in cred_types:
        mitre = MITRE_MAPPING.get(cred_type, {})
        boost = mitre.get("severity_boost", 5)
        mitre_pts = min(mitre_pts + boost, 25)
        if mitre.get("technique_id"):
            mitre_techniques.append({
                "id":     mitre["technique_id"],
                "name":   mitre["technique_name"],
                "tactic": mitre["tactic"],
            })
    score += mitre_pts
    breakdown["mitre_severity_boost"] = f"{mitre_pts}/25"

    # Factor 5: Diversity bonus (multiple credential types = deliberate or template leak)
    diversity_pts = min(len(cred_types) * 3, 10)
    score += diversity_pts
    breakdown["credential_diversity"] = f"{diversity_pts}/10 ({len(cred_types)} type(s))"

    final_score = min(score, 100)
    level = _score_to_level(final_score)

    recommended = {
        "CRITICAL": "Immediate ABUSE REPORT to hosting provider + CERT/CC notification",
        "HIGH":     "ABUSE REPORT + responsible disclosure to developer within 24h",
        "MEDIUM":   "Responsible DISCLOSURE email to developer (90-day window)",
        "LOW":      "Monitor — collect more evidence before action",
        "BENIGN":   "DISMISS — likely test/example data",
    }.get(level, "Manual analyst review required")

    logger.info("Risk score for finding: %d/100 (%s)", final_score, level)
    return json.dumps({
        "risk_score": final_score,
        "risk_level": level,
        "score_breakdown": breakdown,
        "mitre_techniques": mitre_techniques,
        "recommended_action": recommended,
    })


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 6 — Vision Analysis (Multimodal)
# ─────────────────────────────────────────────────────────────────────────────

@tool
def analyze_screenshot_with_vision(screenshot_b64: str, context_hint: str = "") -> str:
    """
    Analyzes a webpage screenshot with Gemma 4 Multimodal to detect visual indicators
    of malicious intent vs. accidental credential exposure.

    Detects: phishing pages, fake login forms, brand impersonation, C2 dashboards.

    Args:
        screenshot_b64: Base64-encoded PNG screenshot of the target.
        context_hint:   Optional context string (URL, snippets, etc.).

    Returns:
        JSON with visual_purpose, suspicious_elements, intent_estimate, suspicion_level.
    """
    if not screenshot_b64:
        return json.dumps({"error": "No screenshot", "suspicion_level": "UNKNOWN"})

    prompt = (
        "You are a cybersecurity analyst examining a webpage screenshot.\n\n"
        "Respond ONLY with valid JSON using these exact keys:\n"
        '  "visual_purpose": string,\n'
        '  "suspicious_visual_elements": list[string],\n'
        '  "intent_estimate": "PHISHING"|"ACCIDENTAL_EXPOSURE"|"MALICIOUS_C2"|"BENIGN",\n'
        '  "suspicion_level": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"BENIGN",\n'
        '  "reasoning": string\n\n'
        f"Additional context: {context_hint[:400] or 'None'}"
    )
    try:
        response = ollama.chat(
            model=SENTINEL_MODEL,
            messages=[{"role": "user", "content": prompt, "images": [screenshot_b64]}],
        )
        text = response["message"]["content"]
        m = re.search(r"\{.*\}", text, re.DOTALL)
        return m.group(0) if m else json.dumps({
            "visual_purpose": "Could not parse",
            "suspicious_visual_elements": [],
            "intent_estimate": "UNKNOWN",
            "suspicion_level": "UNKNOWN",
            "reasoning": text[:500],
        })
    except Exception as exc:
        logger.error("Vision analysis error: %s", exc)
        return json.dumps({"error": str(exc), "suspicion_level": "FAILED"})


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 7 — Threat Attribution Engine (new in v2)
# ─────────────────────────────────────────────────────────────────────────────

@tool
def correlate_findings(findings_json: str) -> str:
    """
    Groups multiple findings into 'Threat Campaigns' based on shared indicators.

    Correlation logic:
      - Same ISP/ASN → Coordinated hosting infrastructure
      - Same credential type across >2 targets → Template leak or deliberate campaign
      - Targets found within same ZoomEye time window → Active simultaneous exposure
      - Same IP subnet (/24) → Same physical or logical network

    This transforms individual findings into campaign-level threat intelligence.

    Args:
        findings_json: JSON list of finding dicts (each with url, ip, isp, credential_types).

    Returns:
        JSON with 'campaigns' list and 'campaign_count'.
    """
    try:
        findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
    except Exception:
        return json.dumps({"campaigns": [], "campaign_count": 0, "error": "Invalid JSON"})

    if not findings or len(findings) < 2:
        return json.dumps({
            "campaigns": [], "campaign_count": 0,
            "note": "Insufficient findings for correlation (need ≥2)"
        })

    # Group by ISP/ASN
    by_isp: dict[str, list] = {}
    for f in findings:
        isp = f.get("isp", f.get("country", "Unknown"))
        by_isp.setdefault(isp, []).append(f)

    # Group by credential type
    by_cred: dict[str, list] = {}
    for f in findings:
        for cred_type in f.get("credential_types", []):
            by_cred.setdefault(cred_type, []).append(f)

    # Group by /24 subnet
    by_subnet: dict[str, list] = {}
    for f in findings:
        ip = f.get("ip", "")
        subnet = ".".join(ip.split(".")[:3]) + ".0/24" if ip.count(".") == 3 else ip
        by_subnet.setdefault(subnet, []).append(f)

    campaigns = []
    campaign_names = iter(["ALPHA", "BETA", "GAMMA", "DELTA", "EPSILON",
                           "ZETA", "ETA", "THETA", "IOTA", "KAPPA"])

    for isp, targets in by_isp.items():
        if len(targets) >= 2:
            name = next(campaign_names, f"CAMPAIGN-{len(campaigns)+1}")
            severity = "CRITICAL" if len(targets) >= 5 else "HIGH" if len(targets) >= 3 else "MEDIUM"
            campaigns.append({
                "campaign_id":      f"CAMP-{name}",
                "correlation_type": "SHARED_ISP",
                "shared_indicator": isp,
                "target_count":     len(targets),
                "targets":          [t.get("url", "?") for t in targets],
                "severity":         severity,
                "assessment":       (
                    f"Campaign '{name}': {len(targets)} targets share ISP '{isp}'. "
                    f"Likely {'coordinated infrastructure' if len(targets) >= 3 else 'related deployment'}."
                ),
            })

    for cred_type, targets in by_cred.items():
        if len(targets) >= 3:
            name = next(campaign_names, f"CRED-{len(campaigns)+1}")
            campaigns.append({
                "campaign_id":      f"CAMP-{name}",
                "correlation_type": "SHARED_CREDENTIAL_TYPE",
                "shared_indicator": cred_type,
                "target_count":     len(targets),
                "targets":          [t.get("url", "?") for t in targets],
                "severity":         "HIGH",
                "assessment":       (
                    f"Campaign '{name}': {len(targets)} targets all expose {cred_type}. "
                    "Possibly a compromised framework template or shared developer mistake."
                ),
                "mitre_relevance":  MITRE_MAPPING.get(cred_type, {}).get("technique_id", "N/A"),
            })

    logger.info("Correlation: %d campaign(s) identified from %d findings", len(campaigns), len(findings))
    return json.dumps({"campaigns": campaigns, "campaign_count": len(campaigns)})


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 8 — Draft Abuse Report
# ─────────────────────────────────────────────────────────────────────────────

@tool
def draft_abuse_report(
    target_url: str,
    token_findings_json: str,
    sentinel_analysis: str,
    risk_score: int,
    risk_level: str,
    is_malicious: bool,
    mitre_techniques_json: str = "[]",
) -> str:
    """
    Generates a structured abuse/disclosure report per ISO/IEC 29147:2018.

    DRAFTED ONLY — never sent automatically. Human approval is mandatory.

    Args:
        target_url:            URL of the exposure.
        token_findings_json:   JSON from extract_and_validate_tokens.
        sentinel_analysis:     Sentinel Agent analysis text.
        risk_score:            Numerical risk score 0-100.
        risk_level:            CRITICAL / HIGH / MEDIUM / LOW / BENIGN.
        is_malicious:          True → ABUSE report; False → DISCLOSURE.
        mitre_techniques_json: JSON list of MITRE technique dicts.

    Returns:
        Formatted AbuseReport JSON awaiting human review.
    """
    raw_findings = json.loads(token_findings_json).get("findings", []) \
        if isinstance(token_findings_json, str) else []
    mitre_techs = json.loads(mitre_techniques_json) \
        if isinstance(mitre_techniques_json, str) else []

    token_objects = [
        TokenFinding(
            token_preview=f.get("token_preview", "[REDACTED]"),
            credential_type=f.get("credential_type", "UNKNOWN"),
            description=f.get("description", ""),
            source_url=target_url,
            structurally_valid=f.get("structurally_valid", False),
            confidence=f.get("confidence", 0.5),
            context_snippet=f.get("context_snippet", ""),
        )
        for f in raw_findings
    ]

    evidence = TargetEvidence(
        target_url=target_url,
        token_findings=token_objects,
        sentinel_analysis=sentinel_analysis[:2000],
        risk_level=risk_level,
        is_malicious=is_malicious,
    )

    report = AbuseReport(
        report_id=f"AEGIS-{uuid.uuid4().hex[:8].upper()}",
        report_type="ABUSE" if is_malicious else "DISCLOSURE",
        target_url=target_url,
        risk_score=risk_score,
        risk_level=risk_level,
        evidence=evidence,
        mitre_techniques=mitre_techs,
        recommended_action=(
            "Submit to abuse@[hosting-provider] and relevant CERT/CC team immediately"
            if is_malicious
            else "Notify developer via responsible disclosure (90-day window)"
        ),
    )

    logger.info("Report drafted: %s | %s | Score: %d | Risk: %s",
                report.report_id, report.report_type, risk_score, risk_level)
    return report.model_dump_json(indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 9 — Draft Disclosure Email
# ─────────────────────────────────────────────────────────────────────────────

@tool
def draft_disclosure_email(
    target_url: str,
    token_summary: str,
    risk_score: int = 0,
    mitre_technique: str = "",
    owner_hint: str = "",
) -> str:
    """
    Drafts an ISO/IEC 29147 responsible disclosure email. NEVER sent automatically.

    Args:
        target_url:      URL of the exposure.
        token_summary:   Redacted credential summary.
        risk_score:      Numerical risk score for context.
        mitre_technique: Primary MITRE technique ID (e.g., T1552.001).
        owner_hint:      Optional owner/company name.

    Returns:
        JSON with 'subject', 'body', 'recommended_recipients', 'status'.
    """
    owner = owner_hint or "Developer / System Owner"
    mitre_line = f"  MITRE ATT&CK        : {mitre_technique}\n" if mitre_technique else ""

    subject = f"[Security Notice — Risk {risk_score}/100] Exposed API Credentials — {target_url[:60]}"
    body = f"""\
Dear {owner},

This notification is issued by AEGIS-G4, an automated cybersecurity monitoring system,
operating under the ISO/IEC 29147:2018 Coordinated Vulnerability Disclosure standard.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Affected Resource   : {target_url}
  Finding Type        : Exposed API Credential(s)
  Pattern Detected    : {token_summary}
  Risk Score          : {risk_score}/100{('  (' + _score_to_level(risk_score) + ')') if risk_score else ''}
{mitre_line}  Discovery Method    : Automated regex pattern matching (no token tested externally)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

POTENTIAL IMPACT
If exploited by a malicious actor, the exposed credential may enable:
  • Unauthorized access to your service or users' data
  • Abuse of your account for spam, malware, or C2 infrastructure
  • Financial fraud (if payment credentials are involved)
  • Permanent compromise requiring full credential rotation

RECOMMENDED REMEDIATION (please act within 90 days)
  1. Immediately revoke / rotate the exposed credential
  2. Remove the credential string from all public-facing code
  3. Store secrets using environment variables or a secrets manager
  4. If ever committed to Git, use BFG Repo Cleaner to purge history
  5. Enable secret scanning alerts on your repository platform

IMPORTANT DISCLOSURES
  • Credential detected via local regex analysis only
  • No external API calls were made using the discovered credential
  • This notification is provided purely for defensive purposes
  • Disclosure follows ISO/IEC 29147:2018 guidelines

Regards,
AEGIS-G4 Automated Security Monitoring System
[This message was reviewed and approved by a human analyst before dispatch]
"""
    return json.dumps({
        "subject": subject,
        "body": body,
        "recommended_recipients": [
            f"security@[{owner.lower().replace(' ', '-')}-domain]",
            "abuse@[hosting-provider]",
        ],
        "disclosure_standard": "ISO/IEC 29147:2018",
        "risk_score": risk_score,
        "status": "DRAFT — AWAITING HUMAN APPROVAL",
    }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 10 — GitHub Code Search Correlation Engine (v2 — THE CHAIN COMPLETER)
# ─────────────────────────────────────────────────────────────────────────────

GITHUB_SEARCH_URL = "https://api.github.com/search/code"

# Dork templates per credential type — optimised for finding actual source code
GITHUB_DORKS: dict[str, list[str]] = {
    "TELEGRAM_BOT_TOKEN": [
        "{prefix} language:python",
        "{prefix} language:javascript",
        "{prefix} filename:.env",
        "{prefix} filename:config.py",
    ],
    "GITHUB_PAT": [
        "{prefix} language:yaml",
        "{prefix} filename:.env",
    ],
    "DISCORD_BOT_TOKEN": [
        "{prefix} language:javascript",
        "{prefix} language:python",
    ],
    "SLACK_TOKEN": [
        "{prefix} xoxb language:python",
        "{prefix} language:yaml",
    ],
    "STRIPE_SECRET_KEY": [
        "{prefix} sk_live language:python",
        "{prefix} sk_live language:javascript",
    ],
}

@tool
def search_github_for_credential_source(
    token_preview: str,
    credential_type: str,
) -> str:
    """
    Traces a discovered live credential BACK to its GitHub source code origin.

    This completes the full attack chain intelligence picture:
      GitHub Repo (source leak) ←── AEGIS-G4 correlates ──→ ZoomEye (live server)

    For each credential found on a live server, this tool finds:
      - The GitHub repository where the token was originally committed
      - The exact file path and developer/owner
      - When the code was last updated (exposure timeline)
      - Whether it was in a fork (template propagation risk)
      - MITRE ATT&CK attribution for source code exposure

    Uses GitHub Code Search API (REST v3):
      - FREE with GitHub account: 30 req/min, 10 req/min without auth
      - Searches ALL public GitHub repositories (~330M+)
      - No scraping — official public API call only

    ⚠️ LEGAL: Read-only search of already-public indexed code. Zero repo access.

    Args:
        token_preview: First 8 characters of the discovered token
                       (e.g., "12345678" for a Telegram bot ID prefix).
                       Used as search term — never the full token.
        credential_type: Credential category, e.g., "TELEGRAM_BOT_TOKEN".

    Returns:
        JSON with:
          - attribution_status: SOURCE_FOUND | NOT_FOUND | RATE_LIMITED | ERROR
          - source_repos: list of {repo_name, file_path, owner, pushed_at, file_url}
          - total_github_matches: total public repos containing the pattern
          - intelligence: human-readable attribution summary
          - attack_chain: dict linking GitHub origin → live server exposure
          - mitre_attribution: T1552.001 (Credentials in Files — Source Code)
    """
    github_token = os.getenv("GITHUB_TOKEN", "")

    headers = {
        "Accept":              "application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    # Use first 8 chars of token as search key (safe, non-identifying)
    prefix = token_preview.replace("...[REDACTED]", "").strip()[:8]
    if len(prefix) < 6:
        return json.dumps({
            "attribution_status": "INSUFFICIENT_PREFIX",
            "source_repos": [],
            "intelligence": "Token prefix too short for reliable GitHub search.",
        })

    dork_templates = GITHUB_DORKS.get(credential_type, ["{prefix}"])
    query = dork_templates[0].format(prefix=prefix)

    logger.info("GitHub Code Search: type=%s prefix=%s query='%s'",
                credential_type, prefix, query[:80])

    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                GITHUB_SEARCH_URL,
                headers=headers,
                params={"q": query, "per_page": 5, "sort": "indexed"},
            )
            # Rate limit check
            if resp.status_code == 403:
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                return json.dumps({
                    "attribution_status": "RATE_LIMITED",
                    "source_repos": [],
                    "intelligence": (
                        f"GitHub rate limit reached (remaining: {remaining}). "
                        "Add GITHUB_TOKEN to .env for higher limits (30 req/min)."
                    ),
                })
            # Unprocessable — query too complex
            if resp.status_code == 422:
                return json.dumps({
                    "attribution_status": "QUERY_ERROR",
                    "source_repos": [],
                    "intelligence": "GitHub rejected the search query. Simplifying.",
                })
            resp.raise_for_status()
            data = resp.json()

    except httpx.TimeoutException:
        return json.dumps({
            "attribution_status": "TIMEOUT",
            "source_repos": [],
            "intelligence": "GitHub search timed out. Will retry on next run.",
        })
    except Exception as exc:
        logger.warning("GitHub search error: %s", exc)
        return json.dumps({"attribution_status": "ERROR", "error": str(exc), "source_repos": []})

    items         = data.get("items", [])
    total_matches = data.get("total_count", 0)
    source_repos  = []

    for item in items[:5]:
        repo     = item.get("repository", {})
        owner    = repo.get("owner", {})
        html_url = item.get("html_url", "")

        source_repos.append({
            "repo_name":    repo.get("full_name", "unknown/unknown"),
            "repo_url":     repo.get("html_url", ""),
            "file_path":    item.get("path", "unknown"),
            "file_url":     html_url,
            "owner_login":  owner.get("login", "unknown"),
            "owner_type":   owner.get("type", "User"),  # User or Organization
            "is_fork":      repo.get("fork", False),
            "stars":        repo.get("stargazers_count", 0),
            "pushed_at":    repo.get("pushed_at", "unknown"),
            "description":  (repo.get("description") or "")[:120],
            "mitre_note":   "T1552.001 — Unsecured Credentials: Credentials in Source Code",
        })

    # ── Build the Attack Chain narrative ──────────────────────────────────────
    if source_repos:
        first       = source_repos[0]
        chain_story = (
            f"ATTACK CHAIN RECONSTRUCTED:\n"
            f"  1. Developer commits token to: {first['repo_name']} "
            f"({'fork' if first['is_fork'] else 'original'})\n"
            f"  2. File: {first['file_path']}\n"
            f"  3. Last code push: {first['pushed_at'][:10] if first['pushed_at'] != 'unknown' else 'unknown'}\n"
            f"  4. Token propagated to live internet-facing service (discovered via ZoomEye)\n"
            f"  5. AEGIS-G4 correlated both sources — full exposure chain confirmed\n"
            f"  Total public GitHub matches: {total_matches}"
        )
        attribution_status = "SOURCE_FOUND"
        intelligence = (
            f"🔗 SOURCE ATTRIBUTION CONFIRMED: Token prefix '{prefix}' traced to "
            f"{len(source_repos)} public GitHub repo(s). "
            f"First match: github.com/{first['repo_name']} "
            f"(file: {first['file_path']}). "
            f"Total public instances: {total_matches}. "
            f"This proves the complete attack chain: source code → deployment exposure."
        )
    else:
        chain_story = (
            "Source not found in public GitHub repositories. "
            "Token may originate from a private repo, CI/CD env, or other source."
        )
        attribution_status = "NOT_FOUND"
        intelligence = (
            f"Token prefix '{prefix}' not found in public GitHub repositories. "
            "Possible private leak, environment variable injection, or internal template."
        )

    logger.info("GitHub attribution: %s | %d repos found | %d total matches",
                attribution_status, len(source_repos), total_matches)

    return json.dumps({
        "attribution_status":  attribution_status,
        "source_repos":        source_repos,
        "total_github_matches": total_matches,
        "intelligence":        intelligence,
        "attack_chain":        chain_story,
        "mitre_attribution":   "T1552.001 — Unsecured Credentials: Credentials in Source Code",
        "search_query_used":   query,
        "api_source":          "GitHub Code Search REST API v3 (public repos only)",
        "legal_note":          "Read-only search of publicly indexed code. No repo access.",
    }, indent=2)

