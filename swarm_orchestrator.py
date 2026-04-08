"""
swarm_orchestrator.py — AEGIS-G4 Multi-Agent Swarm Brain
=========================================================
Implements a True Multi-Agent Swarm using smolagents.

Architecture:
  Commander (Gemma 4 27B)
      │
      ├── ManagedAgent: Scout   (Gemma 4 E4B) — ZoomEye reconnaissance
      ├── ManagedAgent: Sentinel (Gemma 4 E4B) — Multimodal analysis
      └── ManagedAgent: Critic  (Gemma 4 E2B) — Safety & reliability review

Data flow:
  Commander issues task → Scout discovers targets → Sentinel analyzes each →
  Critic approves/rejects → Commander makes final decision → Report drafted
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from dotenv import load_dotenv
from smolagents import ManagedAgent, OpenAIServerModel, ToolCallingAgent
from dorks_library import get_dorks_for_session, DORK_SUMMARY

from aegis_tools import (
    # Core tools (v1)
    zoomeye_search,
    fetch_target_data,
    extract_and_validate_tokens,
    analyze_screenshot_with_vision,
    draft_abuse_report,
    draft_disclosure_email,
    # Intelligence tools (v2)
    check_ip_reputation,
    calculate_risk_score,
    correlate_findings,
    # Chain Completer (v2 — THE KEY DIFFERENTIATOR)
    search_github_for_credential_source,
)

load_dotenv()
logger = logging.getLogger("aegis.swarm")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
COMMANDER_MODEL: str = os.getenv("COMMANDER_MODEL", "gemma4:27b")
SCOUT_MODEL: str = os.getenv("SCOUT_MODEL", "gemma4:4b")
SENTINEL_MODEL_NAME: str = os.getenv("SENTINEL_MODEL", "gemma4:4b")
CRITIC_MODEL: str = os.getenv("CRITIC_MODEL", "gemma4:2b")
MAX_STEPS: int = int(os.getenv("MAX_COMMANDER_STEPS", "25"))


# ─────────────────────────────────────────────────────────────────────────────
# Thought Stream — Live UI Feed
# ─────────────────────────────────────────────────────────────────────────────

class ThoughtStream:
    """
    Thread-safe queue that broadcasts agent thoughts to the War Room UI.
    Each message is a dict: {agent, thought, type, timestamp}.
    """

    _TYPES = ("reasoning", "action", "result", "error", "system", "decision")

    def __init__(self) -> None:
        self._q: queue.Queue[dict] = queue.Queue()

    def push(
        self,
        agent: str,
        thought: str,
        kind: str = "reasoning",
    ) -> None:
        self._q.put_nowait({
            "agent": agent,
            "thought": thought,
            "type": kind,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def drain(self) -> list[dict]:
        """Non-blocking: returns all currently queued thoughts."""
        items: list[dict] = []
        while not self._q.empty():
            try:
                items.append(self._q.get_nowait())
            except queue.Empty:
                break
        return items

    @property
    def empty(self) -> bool:
        return self._q.empty()


# Singleton — shared between swarm and UI layers
thought_stream = ThoughtStream()


# ─────────────────────────────────────────────────────────────────────────────
# Result Contract
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SwarmResult:
    """Typed result returned after a full swarm execution."""
    task: str
    targets_discovered:      int = 0
    targets_analyzed:        int = 0
    targets_skipped:         int = 0   # Dead URLs skipped by circuit breaker
    critical_findings:       int = 0
    attack_chains_confirmed: int = 0   # GitHub-attributed full chains
    reports: list[dict] = field(default_factory=list)
    final_summary: str = ""
    commander_reasoning: str = ""
    country_stats: dict = field(default_factory=dict)    # {country_code: count}
    credential_stats: dict = field(default_factory=dict) # {cred_type: count}
    campaign_ids: list[str] = field(default_factory=list)
    completed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    success: bool = True
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Model Factory
# ─────────────────────────────────────────────────────────────────────────────

def _make_model(model_id: str) -> OpenAIServerModel:
    """
    Returns an Ollama-backed model via its OpenAI-compatible endpoint.
    Ollama exposes /v1 so no extra adapters are needed.
    """
    return OpenAIServerModel(
        model_id=model_id,
        api_base=OLLAMA_BASE_URL,
        api_key="ollama",          # Field required by smolagents; Ollama ignores it
        max_tokens=4096,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Agent Factories
# ─────────────────────────────────────────────────────────────────────────────

def _build_scout() -> ToolCallingAgent:
    """
    Scout Agent — Internet Reconnaissance Specialist
    Model: Gemma 4 E4B (edge-optimised for efficient Dork generation)

    Responsibilities:
      • Craft precise ZoomEye dork queries to surface exposed credential endpoints
      • Paginate results and return a clean target list for Sentinel analysis
    """
    thought_stream.push("SCOUT", "Scout Agent online — ZoomEye + GitHub Code Search ready.", "system")

    # Build top dorks list for the agent's system prompt
    top_queries = get_dorks_for_session(max_dorks=12)
    dork_examples = "\n".join(f"  {i+1}. {q}" for i, q in enumerate(top_queries[:8]))

    return ToolCallingAgent(
        tools=[
            zoomeye_search,
            search_github_for_credential_source,  # ← v2 Chain Completer
        ],
        model=_make_model(SCOUT_MODEL),
        name="scout_agent",
        description=(
            "Reconnaissance agent that uses ZoomEye to discover internet-exposed "
            "assets containing leaked API tokens, then traces each token back to its "
            "GitHub source code origin to complete the full attack chain."
        ),
        system_prompt="""\
You are the Scout Agent of the AEGIS-G4 cybersecurity swarm.

MISSION: Discover internet-exposed services with leaked credentials AND trace
those credentials back to their original source code in GitHub.

DORK CRAFT GUIDELINES:
  • Target services with embedded API calls: 'http.body="api.telegram.org"'
  • Look for admin/debug panels: 'title="Bot Dashboard" || title="Telegram Manager"'
  • Target common frameworks: 'app="Flask" && http.body="sendMessage"'
  • Combine conditions for precision: avoid overly broad queries

WORKFLOW:
  Step 1 — ZoomEye Reconnaissance
    zoomeye_search(dork) → get list of targets with exposed credentials

  Step 2 — GitHub Source Attribution (for each token found)
    search_github_for_credential_source(
        token_preview="first 8 chars of token",
        credential_type="TELEGRAM_BOT_TOKEN"
    )
    → Traces the token back to the GitHub repo where it was ORIGINALLY committed
    → Completes the FULL ATTACK CHAIN: source code → deployment

OPERATIONAL RULES:
  1. Always attempt GitHub attribution after finding any credential
  2. Only use the first 8 chars of any token — NEVER pass the full token anywhere
  3. In DEMO_MODE the ZoomEye tool returns honeypot URLs automatically
  4. If GitHub rate-limited, note it and continue with ZoomEye findings only

OUTPUT FORMAT:
{
  "targets": ["http://..."],
  "github_attributions": [
    {"target": "url", "attribution_status": "SOURCE_FOUND", "source_repo": "owner/repo"}
  ],
  "attack_chains_confirmed": N
}
""",
        max_steps=12,
    )


def _build_sentinel() -> ToolCallingAgent:
    """
    Sentinel Agent — Multimodal Evidence Analyst
    Model: Gemma 4 E4B with Vision capabilities

    Responsibilities:
      • Capture visual screenshots and HTML of targets
      • Run regex-only token extraction (zero external API calls)
      • Perform vision analysis for malicious-intent indicators
      • Produce structured risk assessments
    """
    thought_stream.push("SENTINEL", "Sentinel Agent online — vision systems active.", "system")
    return ToolCallingAgent(
        tools=[
            fetch_target_data,
            extract_and_validate_tokens,      # v2: 5 credential types + MITRE mapping
            analyze_screenshot_with_vision,
            check_ip_reputation,              # v2: AbuseIPDB threat intelligence
            calculate_risk_score,             # v2: multi-factor 0-100 scoring
        ],
        model=_make_model(SENTINEL_MODEL_NAME),
        name="sentinel_agent",
        description=(
            "Multimodal analysis agent. Captures target screenshots + HTML, extracts "
            "credential patterns via regex (no API calls), and assesses visual intent."
        ),
        system_prompt="""\
You are the Sentinel Agent of the AEGIS-G4 cybersecurity swarm.

MISSION: Analyze target URLs for exposed credentials using ONLY the tools provided.
You have vision capabilities — use them to detect visual red flags.

⚠️  ABSOLUTE LEGAL CONSTRAINT:
  NEVER make any external API call to validate tokens.
  extract_and_validate_tokens uses LOCAL REGEX ONLY — that is correct and sufficient.

WORKFLOW per target URL:
  1. fetch_target_data(url)              → get screenshot_b64 + html_snippet
  2. extract_and_validate_tokens(html)   → find token patterns (regex only)
  3. analyze_screenshot_with_vision(...)  → detect visual malicious intent
  4. Synthesise all findings into your assessment

ASSESSMENT OUTPUT (JSON):
{
  "target_url": "...",
  "tokens_found": 0,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|BENIGN",
  "intent": "ACCIDENTAL_EXPOSURE|SUSPECTED_MALICIOUS|BENIGN",
  "evidence_summary": "...",
  "token_findings_json": "{...}",   ← raw output from extract_and_validate_tokens
  "recommended_action": "ABUSE_REPORT|DISCLOSURE|MONITOR|DISMISS"
}
""",
        max_steps=10,
    )


def _build_critic() -> ToolCallingAgent:
    """
    Critic Agent — Safety, Reliability & Ethics Reviewer
    Model: Gemma 4 E2B (lightweight; speed matters for fast review cycles)

    Responsibilities:
      • Challenge Sentinel conclusions with adversarial questioning
      • Catch false positives (test data, example tokens, templates)
      • Enforce ethical constraints — block any automated action without Human approval
      • Gate findings before they reach the Commander's decision stage
    """
    thought_stream.push("CRITIC", "Critic Agent online — safety protocols engaged.", "system")
    return ToolCallingAgent(
        tools=[extract_and_validate_tokens],
        model=_make_model(CRITIC_MODEL),
        name="critic_agent",
        description=(
            "Adversarial review agent. Challenges Sentinel findings for false positives, "
            "evidence quality, and legal/ethical compliance before Commander decision."
        ),
        system_prompt="""\
You are the Critic Agent of the AEGIS-G4 cybersecurity swarm.
Your role: challenge findings ruthlessly before escalation to the Commander.

CRITIC CHECKLIST — for every finding presented to you:
  ✗ Could this token be test/demo/placeholder data? (e.g., "123456789:AAAA…")
  ✗ Is evidence sufficient? (URL + redacted pattern + supporting HTML context)
  ✗ Is all proposed action legal? (No hack-back; no accessing external APIs with token)
  ✗ Is the risk rating proportionate to actual evidence?
  ✗ Does the workflow maintain Human-in-the-Loop at every action step?

VERDICT OPTIONS:
  APPROVED            → Evidence solid, action legal — pass to Commander
  NEEDS_MORE_EVIDENCE → Specify exact gaps; request Sentinel re-investigation
  REJECTED            → Clear false positive or compliance issue; explain why
  ESCALATE_CRITICAL   → Active exploitation suspected; immediate human attention

RESPONSE FORMAT (JSON):
{
  "verdict": "APPROVED|NEEDS_MORE_EVIDENCE|REJECTED|ESCALATE_CRITICAL",
  "confidence": 0.0–1.0,
  "issues_found": ["..."],
  "reasoning": "your chain-of-thought",
  "approved_risk_level": "CRITICAL|HIGH|MEDIUM|LOW|BENIGN"
}
""",
        max_steps=6,
    )


def _build_commander(
    managed_scout: ManagedAgent,
    managed_sentinel: ManagedAgent,
    managed_critic: ManagedAgent,
) -> ToolCallingAgent:
    """
    Commander — Master Orchestrator
    Model: Gemma 4 27B (maximum reasoning capability; enable_thinking=True)

    The Commander coordinates all sub-agents and makes the final, auditable decision.
    It calls sub-agents as tools, synthesises their outputs, and — when evidence is
    approved by the Critic — invokes draft_abuse_report or draft_disclosure_email.
    All reports are queued for HUMAN REVIEW only; nothing is sent automatically.
    """
    thought_stream.push("COMMANDER", "Commander online — swarm fully assembled.", "system")
    return ToolCallingAgent(
        tools=[
            managed_scout,          # Recon + GitHub attribution
            managed_sentinel,       # Analysis tool (v2: 5 cred types, MITRE, AbuseIPDB)
            managed_critic,         # Safety review tool
            correlate_findings,     # v2: Campaign correlation / Threat Attribution
            draft_abuse_report,     # Report generation (v2: includes MITRE + risk score)
            draft_disclosure_email, # Email drafting (v2: includes risk score)
        ],
        model=_make_model(COMMANDER_MODEL),
        name="commander",
        description="Master orchestrator that coordinates all AEGIS-G4 swarm agents.",
        system_prompt="""\
You are the Commander of the AEGIS-G4 cybersecurity swarm.
You coordinate four specialised agents to discover and responsibly disclose
exposed credentials found on internet-facing services.

SWARM COORDINATION PROTOCOL:
  Step 1 — Reconnaissance
    Call scout ("Find targets with exposed Telegram tokens using ZoomEye")
    → You receive a list of target URLs + GitHub attribution results

  Step 2 — Analysis (per target, up to MAX_TARGETS cap)
    Call sentinel ("Analyse this target: <url>")
    → You receive risk assessment + token findings

  Step 2.5 — Attack Chain Intelligence (AUTO from Scout)
    Scout already runs GitHub Code Search for each token found.
    If attribution_status=SOURCE_FOUND:
      → Include repo_name, file_path, pushed_at in your final report
      → State: "Full attack chain confirmed: source code → live deployment"
      → This upgrades the finding severity by one level automatically

  Step 3 — Review
    Call critic ("Review this Sentinel finding: <assessment_json>")
    → You receive: APPROVED | NEEDS_MORE_EVIDENCE | REJECTED | ESCALATE_CRITICAL

  Step 4 — Threat Attribution (if ≥2 findings exist)
    Call correlate_findings(findings_list)
    → Identifies campaigns: shared ISP, shared credential type, same subnet
    → Transforms individual findings into campaign-level intelligence

  Step 5 — Decision (only for APPROVED findings)
    If is_malicious=True  → call draft_abuse_report(...) with MITRE data + risk_score
    If is_malicious=False → call draft_disclosure_email(...) with risk_score + mitre_technique
    Include GitHub source URL in disclosures if SOURCE_FOUND
    ⚠️  Reports are DRAFTED ONLY — never sent. Human approval is mandatory.

  Step 6 — Summary
    Return a final JSON summary including campaign correlations and attack chains.

IRON RULES:
  • Never skip the Critic review before drafting a report
  • Never send any email or submit any report autonomously
  • Respect the DEMO_MODE flag — if active, work only with honeypot targets
  • If Critic says NEEDS_MORE_EVIDENCE, re-task the Sentinel before deciding
  • Log your reasoning at each step for the human analyst
  • GitHub attribution confirms the FULL attack chain — always highlight this

FINAL OUTPUT FORMAT:
{
  "swarm_run_id": "...",
  "targets_discovered": N,
  "targets_analyzed": N,
  "attack_chains_confirmed": N,
  "findings": [
    {
      "url": "...",
      "risk_level": "...",
      "report_id": "...",
      "github_source": "owner/repo or null",
      "attack_chain": "full chain description or null"
    }
  ],
  "campaigns": [...],
  "commander_reasoning": "step-by-step explanation",
  "human_action_required": true
}
""",
        max_steps=MAX_STEPS,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public Interface
# ─────────────────────────────────────────────────────────────────────────────

def assemble_swarm() -> ToolCallingAgent:
    """
    Assembles and returns the fully wired Commander agent.
    Sub-agents are wrapped as ManagedAgents and injected as Commander tools.
    """
    scout = ManagedAgent(
        agent=_build_scout(),
        name="scout",
        description=(
            "Call this agent to perform ZoomEye reconnaissance. "
            "Provide a brief mission description; it will return target URLs."
        ),
    )
    sentinel = ManagedAgent(
        agent=_build_sentinel(),
        name="sentinel",
        description=(
            "Call this agent to analyse a single target URL. "
            "Provide the URL; it will return a risk assessment with token findings."
        ),
    )
    critic = ManagedAgent(
        agent=_build_critic(),
        name="critic",
        description=(
            "Call this agent to review a Sentinel finding before any report is drafted. "
            "Provide the assessment JSON; it will return APPROVED/REJECTED/etc."
        ),
    )
    return _build_commander(scout, sentinel, critic)


def run_swarm(
    task: str = "Discover exposed Telegram Bot tokens on internet-facing services.",
    on_thought: Optional[Callable[[dict], None]] = None,
) -> SwarmResult:
    """
    Launches the AEGIS-G4 swarm synchronously and returns a SwarmResult.

    Args:
        task: Natural-language mission description for the Commander.
        on_thought: Optional callback invoked for each thought emitted to ThoughtStream.
            Signature: callback(thought_dict: dict) → None.
            If None, thoughts accumulate in thought_stream for the UI to poll.

    Returns:
        SwarmResult with all findings and commander reasoning.
    """
    logger.info("Swarm starting | Task: %s", task)
    thought_stream.push("COMMANDER", f"Mission received: {task}", "system")

    result = SwarmResult(task=task)

    try:
        commander = assemble_swarm()

        # If a callback is provided, drain the stream periodically during execution
        if on_thought:
            def _drain_loop() -> None:
                import time
                while not getattr(_drain_loop, "_stop", False):
                    for t in thought_stream.drain():
                        on_thought(t)
                    time.sleep(0.3)

            drain_thread = threading.Thread(target=_drain_loop, daemon=True)
            drain_thread.start()

        raw_output: str = commander.run(task)

        if on_thought:
            _drain_loop._stop = True  # type: ignore[attr-defined]

        # Parse Commander's JSON output
        try:
            import re
            m = re.search(r"\{.*\}", raw_output, re.DOTALL)
            parsed = json.loads(m.group(0)) if m else {}
        except (json.JSONDecodeError, AttributeError):
            parsed = {}

        result.targets_discovered = parsed.get("targets_discovered", 0)
        result.targets_analyzed = parsed.get("targets_analyzed", 0)
        result.reports = parsed.get("findings", [])
        result.critical_findings = sum(
            1 for f in result.reports if f.get("risk_level") in ("CRITICAL", "HIGH")
        )
        result.final_summary = raw_output[:500]
        result.commander_reasoning = parsed.get("commander_reasoning", raw_output[:300])

        thought_stream.push(
            "COMMANDER",
            f"Swarm complete. {result.targets_analyzed} targets analyzed, "
            f"{result.critical_findings} critical finding(s). Human review required.",
            "decision",
        )
        logger.info("Swarm complete: %s", result)

    except Exception as exc:
        result.success = False
        result.error = str(exc)
        thought_stream.push("COMMANDER", f"Swarm error: {exc}", "error")
        logger.exception("Swarm failed: %s", exc)

    return result


def run_swarm_threaded(
    task: str,
    on_complete: Callable[[SwarmResult], None],
    on_thought: Optional[Callable[[dict], None]] = None,
) -> threading.Thread:
    """
    Launches the swarm in a background thread and calls on_complete when finished.
    Designed for non-blocking integration with the Textual TUI event loop.

    Returns the thread (already started — do not call .start() again).
    """
    def _worker() -> None:
        res = run_swarm(task=task, on_thought=on_thought)
        on_complete(res)

    t = threading.Thread(target=_worker, daemon=True, name="aegis-swarm")
    t.start()
    return t
