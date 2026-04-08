"""
war_room_ui.py — AEGIS-G4 War Room Intelligence Dashboard (v3.0)
================================================================
A cinematic, 4-panel TUI combining real-time agent activity,
comprehensive findings analysis, and live threat statistics.

Layout (4 panels):
  ┌─ HEADER ──────────────────────────────────────────────────────────────────┐
  │  ⚡ AEGIS-G4 WAR ROOM  │ Status  │ Elapsed │ Mode                         │
  ├─ AGENT FEED ──────────┬─ FINDINGS TABLE ─────────┬─ LIVE STATS ───────────┤
  │  Live CoT stream      │  All discoveries          │  🌍 Countries          │
  │  from all 4 agents    │  with full metadata       │  🎯 Risk Levels        │
  │                       │                           │  🔑 Credentials        │
  │                       │                           │  ⛓ Attack Chains      │
  │                       │                           │  🏕 Campaigns          │
  ├───────────────────────┴───────────────────────────┴────────────────────────┤
  │  EVIDENCE PANEL — Selected target XAI + MITRE breakdown                    │
  ├─────────────────────────────────────────────────────────────────────────────┤
  │  CONTROLS: ▶ Launch  ✓ Approve  ✗ Dismiss  ⊘ Abort  │ COUNTERS           │
  └─────────────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import ClassVar

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive, var
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    RichLog,
    Static,
)

from swarm_orchestrator import SwarmResult, run_swarm_threaded, thought_stream
from dorks_library import get_dorks_for_session

# ─────────────────────────────────────────────────────────────────────────────
# Country Flag Map (most common in exposed-service datasets)
# ─────────────────────────────────────────────────────────────────────────────

COUNTRY_FLAGS: dict[str, str] = {
    "US": "🇺🇸", "DE": "🇩🇪", "RU": "🇷🇺", "NL": "🇳🇱",
    "FR": "🇫🇷", "GB": "🇬🇧", "CN": "🇨🇳", "HK": "🇭🇰",
    "SG": "🇸🇬", "IN": "🇮🇳", "BR": "🇧🇷", "CA": "🇨🇦",
    "JP": "🇯🇵", "KR": "🇰🇷", "UA": "🇺🇦", "TR": "🇹🇷",
    "IR": "🇮🇷", "AU": "🇦🇺", "SE": "🇸🇪", "FI": "🇫🇮",
    "PL": "🇵🇱", "IT": "🇮🇹", "ES": "🇪🇸", "CH": "🇨🇭",
    "VN": "🇻🇳", "TH": "🇹🇭", "ID": "🇮🇩", "PK": "🇵🇰",
    "EG": "🇪🇬", "ZA": "🇿🇦", "MX": "🇲🇽", "AR": "🇦🇷",
    "RO": "🇷🇴", "CZ": "🇨🇿", "HU": "🇭🇺", "BG": "🇧🇬",
}

RISK_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "BENIGN":   "dim green",
    "UNKNOWN":  "dim white",
}

RISK_ICONS: dict[str, str] = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
    "LOW": "🔵",      "BENIGN": "🟢", "UNKNOWN": "⚪",
}

AGENT_COLORS: dict[str, str] = {
    "COMMANDER": "bold cyan",
    "SCOUT":     "bold blue",
    "SENTINEL":  "bold magenta",
    "CRITIC":    "bold yellow",
    "SYSTEM":    "dim white",
}

AGENT_ICONS: dict[str, str] = {
    "COMMANDER": "👑", "SCOUT": "🔭", "SENTINEL": "🛡",
    "CRITIC": "⚖️",    "SYSTEM": "⚙️",
}

CRED_ICONS: dict[str, str] = {
    "TELEGRAM_BOT_TOKEN": "📱",
    "GITHUB_PAT":         "🐙",
    "DISCORD_BOT_TOKEN":  "💬",
    "SLACK_TOKEN":        "🔔",
    "STRIPE_SECRET_KEY":  "💳",
    "MULTIPLE":           "🎁",
    "UNKNOWN":            "🔑",
}


# ─────────────────────────────────────────────────────────────────────────────
# Statistics State (singleton, updated by swarm callbacks)
# ─────────────────────────────────────────────────────────────────────────────

class SwarmStats:
    """Live statistics tracked in real-time as the swarm produces findings."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.targets_scanned:     int = 0
        self.targets_found:       int = 0
        self.targets_skipped:     int = 0
        self.critical_count:      int = 0
        self.high_count:          int = 0
        self.medium_count:        int = 0
        self.low_count:           int = 0
        self.attack_chains:       int = 0
        self.campaign_count:      int = 0
        self.github_attributed:   int = 0
        self.scan_start_time:     float = time.monotonic()

        self.countries:    Counter = Counter()    # {country_code: count}
        self.cred_types:   Counter = Counter()    # {cred_type: count}
        self.isps:         Counter = Counter()    # {isp: count}
        self.ports:        Counter = Counter()    # {port: count}
        self.campaigns:    list[str] = []

    def add_finding(self, report: dict) -> None:
        risk = report.get("risk_level", "UNKNOWN").upper()
        self.targets_found += 1
        if risk == "CRITICAL":   self.critical_count += 1
        elif risk == "HIGH":     self.high_count += 1
        elif risk == "MEDIUM":   self.medium_count += 1
        elif risk == "LOW":      self.low_count += 1

        # Geo
        cc = report.get("country_code", report.get("country", "??"))[:2].upper()
        if cc and cc not in ("??", ""):
            self.countries[cc] += 1

        # Credentials
        for ct in report.get("credential_types", []):
            self.cred_types[ct] += 1

        # Infrastructure
        isp = report.get("isp", "")
        if isp and isp != "Unknown":
            self.isps[isp] += 1
        port = report.get("port", 0)
        if port:
            self.ports[str(port)] += 1

        # Attack chain
        if report.get("github_source") or report.get("attack_chain"):
            self.attack_chains += 1

    @property
    def scan_elapsed(self) -> str:
        secs = int(time.monotonic() - self.scan_start_time)
        h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

    @property
    def scan_rate(self) -> str:
        elapsed = max(1, time.monotonic() - self.scan_start_time)
        rate = self.targets_scanned / elapsed * 60
        return f"{rate:.1f}/min"


STATS = SwarmStats()


# ─────────────────────────────────────────────────────────────────────────────
# Custom Widgets
# ─────────────────────────────────────────────────────────────────────────────

class StatsPanel(Static):
    """
    Live intelligence statistics panel — right sidebar.
    Shows: Countries, Risk levels, Credential types, Chains, Campaigns.
    """

    DEFAULT_CSS = """
    StatsPanel {
        background: #080c14;
        color: #a8c4e0;
        padding: 0 1;
        height: 1fr;
        overflow-y: auto;
    }
    """

    def render(self) -> str:
        lines: list[str] = []

        # ── Country distribution ───────────────────────────────────────────
        lines.append("[bold #00d4ff]🌍 COUNTRY DISTRIBUTION[/bold #00d4ff]")
        top_countries = STATS.countries.most_common(10)
        if top_countries:
            max_count = top_countries[0][1] if top_countries else 1
            for cc, cnt in top_countries:
                flag = COUNTRY_FLAGS.get(cc, "🏳")
                bar_len = max(1, int(cnt / max_count * 12))
                bar = "█" * bar_len + "░" * (12 - bar_len)
                lines.append(f" {flag} [bold white]{cc}[/bold white] [#4488bb]{bar}[/#4488bb] [bold]{cnt}[/bold]")
        else:
            lines.append(" [dim]Waiting for data...[/dim]")

        # ── Risk level overview ─────────────────────────────────────────────
        lines.append("")
        lines.append("[bold #ff6b6b]🎯 RISK OVERVIEW[/bold #ff6b6b]")
        risk_data = [
            ("CRITICAL", STATS.critical_count,  "#ff2222"),
            ("HIGH",     STATS.high_count,       "#ff8800"),
            ("MEDIUM",   STATS.medium_count,     "#ffdd00"),
            ("LOW",      STATS.low_count,         "#00bbdd"),
        ]
        total_risk = sum(c for _, c, _ in risk_data) or 1
        for level, count, color in risk_data:
            icon   = RISK_ICONS.get(level, "•")
            bar_l  = max(0, int(count / total_risk * 10))
            bar    = "█" * bar_l + "░" * (10 - bar_l)
            pct    = int(count / total_risk * 100) if total_risk > 0 else 0
            lines.append(f" {icon} [{color}]{level:<8}[/{color}] [{color}]{bar}[/{color}] [bold]{count}[/bold] [dim]({pct}%)[/dim]")

        # ── Credential type breakdown ───────────────────────────────────────
        lines.append("")
        lines.append("[bold #c792ea]🔑 CREDENTIAL TYPES[/bold #c792ea]")
        if STATS.cred_types:
            for ctype, cnt in STATS.cred_types.most_common(6):
                icon = CRED_ICONS.get(ctype, "🔑")
                short = ctype.replace("_TOKEN", "").replace("_SECRET_KEY", "").replace("_BOT", "")
                lines.append(f" {icon} [#b0c4de]{short:<12}[/#b0c4de] [bold white]{cnt}[/bold white]")
        else:
            lines.append(" [dim]No credentials detected yet[/dim]")

        # ── Attack chains ───────────────────────────────────────────────────
        lines.append("")
        lines.append("[bold #7fff7f]⛓  ATTACK CHAINS[/bold #7fff7f]")
        chain_icon = "🔗" if STATS.attack_chains > 0 else "○"
        lines.append(f" {chain_icon} Confirmed  [bold #7fff7f]{STATS.attack_chains}[/bold #7fff7f]")
        lines.append(f" 🐙 GitHub Src  [bold white]{STATS.github_attributed}[/bold white]")

        # ── Campaigns ──────────────────────────────────────────────────────
        lines.append("")
        lines.append("[bold #ffd700]🏕  CAMPAIGNS DETECTED[/bold #ffd700]")
        if STATS.campaigns:
            for camp in STATS.campaigns[:5]:
                lines.append(f" ⚡ [bold #ffd700]{camp}[/bold #ffd700]")
        else:
            lines.append(f" [dim]{STATS.campaign_count} campaign(s)[/dim]")

        # ── Top ISPs / Infrastructure ───────────────────────────────────────
        lines.append("")
        lines.append("[bold #87ceeb]🏢 TOP ISPs[/bold #87ceeb]")
        for isp, cnt in STATS.isps.most_common(4):
            short_isp = isp[:18]
            lines.append(f" [#87ceeb]{short_isp:<18}[/#87ceeb] [bold]{cnt}[/bold]")
        if not STATS.isps:
            lines.append(" [dim]No data yet[/dim]")

        # ── Port distribution ───────────────────────────────────────────────
        lines.append("")
        lines.append("[bold #98c379]🔌 TOP PORTS[/bold #98c379]")
        for port, cnt in STATS.ports.most_common(5):
            lines.append(f" :{port:<6} [bold]{cnt}[/bold]")
        if not STATS.ports:
            lines.append(" [dim]No data yet[/dim]")

        # ── Scan performance ────────────────────────────────────────────────
        lines.append("")
        lines.append("[bold #aaaaaa]⚡ PERFORMANCE[/bold #aaaaaa]")
        lines.append(f" ⏱  Elapsed   [bold]{STATS.scan_elapsed}[/bold]")
        lines.append(f" 🚀 Rate      [bold]{STATS.scan_rate}[/bold]")
        lines.append(f" ⏭  Skipped   [bold]{STATS.targets_skipped}[/bold] [dim](dead URLs)[/dim]")

        return "\n".join(lines)


class EvidencePanel(Static):
    """Full evidence breakdown for a selected finding — XAI + MITRE."""

    DEFAULT_CSS = """
    EvidencePanel {
        height: 9;
        border: none;
        padding: 0 2;
        background: #080c14;
        color: #c9d1d9;
        overflow-y: auto;
    }
    """

    content: reactive[str] = reactive(
        "[dim]▷ Select a finding in the table above to inspect evidence, "
        "MITRE mapping, and commander reasoning.[/dim]"
    )

    def render(self) -> str:
        return self.content

    def update_evidence(self, target_data: dict) -> None:
        url        = target_data.get("url", "N/A")
        risk       = target_data.get("risk_level", "UNKNOWN").upper()
        risk_score = target_data.get("risk_score", 0)
        tokens     = target_data.get("tokens_found", 0)
        intent     = target_data.get("intent", "UNKNOWN")
        cred_types = target_data.get("credential_types", [])
        mitre      = target_data.get("mitre_techniques", [])
        breakdown  = target_data.get("score_breakdown", {})
        ip_rep     = target_data.get("ip_reputation", {})
        reasoning  = target_data.get("commander_reasoning", "Pending...")
        country    = target_data.get("country", "")
        country_code = target_data.get("country_code", "??")
        isp        = target_data.get("isp", "")
        github_src = target_data.get("github_source", "")
        attack_chain = target_data.get("attack_chain", "")

        # Score bar
        filled = int(risk_score / 5)
        bar    = "█" * filled + "░" * (20 - filled)
        sc     = "red" if risk_score >= 80 else "yellow" if risk_score >= 40 else "green"
        flag   = COUNTRY_FLAGS.get(country_code, "🏳")
        icon   = RISK_ICONS.get(risk, "•")

        # MITRE
        mitre_str = "  " + " | ".join(
            f"{t.get('id','?')} ({t.get('tactic','?')})"
            for t in (mitre if isinstance(mitre, list) else [])
        ) or "  None detected"

        # GitHub attack chain
        chain_str = ""
        if github_src:
            chain_str = f"\n⛓  [bold #7fff7f]ATTACK CHAIN:[/bold #7fff7f] github.com/{github_src} → live at {url[:45]}"

        abuse = ip_rep.get("abuse_score", 0) if isinstance(ip_rep, dict) else 0
        known_bad = ip_rep.get("is_known_bad", False) if isinstance(ip_rep, dict) else False

        self.content = (
            f"{icon} [bold]{url[:60]}[/bold]    "
            f"Risk [{sc}]{risk}[/{sc}]  [{sc}]{bar}[/{sc}] {risk_score}/100    "
            f"{flag} {country} [{isp[:25]}]    "
            f"AbuseIPDB: [{'red' if known_bad else 'green'}]{abuse}/100[/{'red' if known_bad else 'green'}]\n"
            f"🔑 Found: {tokens} credential(s)  Types: {', '.join(cred_types) or '—'}    "
            f"Intent: {intent}\n"
            f"⚔️  MITRE: {mitre_str}"
            f"{chain_str}\n"
            f"🧠 [dim]{reasoning[:200]}[/dim]"
        )


class StatusCounters(Static):
    """Bottom status bar with live counters."""

    DEFAULT_CSS = """
    StatusCounters {
        background: #0d1520;
        color: #7aa2cc;
        height: 1;
        padding: 0 2;
        text-style: bold;
    }
    """

    def render(self) -> str:
        return (
            f"[#00d4ff]SCANNED:[/#00d4ff] {STATS.targets_scanned}  "
            f"[#ff8800]FOUND:[/#ff8800] {STATS.targets_found}  "
            f"[#ff2222]CRITICAL:[/#ff2222] {STATS.critical_count}  "
            f"[#ff8800]HIGH:[/#ff8800] {STATS.high_count}  "
            f"[#ffdd00]MEDIUM:[/#ffdd00] {STATS.medium_count}  "
            f"[#7fff7f]CHAINS:[/#7fff7f] {STATS.attack_chains}  "
            f"[#ffd700]CAMPS:[/#ffd700] {STATS.campaign_count}  "
            f"[#aaaaaa]SKIPPED:[/#aaaaaa] {STATS.targets_skipped}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────────────


class AegisWarRoom(App[None]):
    """
    AEGIS-G4 War Room — Comprehensive Threat Intelligence Dashboard.

    4-panel layout: Agent Feed │ Findings Table │ Live Statistics
    with Evidence Panel below and Control Bar at the bottom.
    """

    TITLE = "AEGIS-G4 | Autonomous Edge-based Global Intelligence Swarm"
    SUB_TITLE = "Gemma 4 Good Hackathon 2024 — Google DeepMind × Kaggle"

    CSS = """
    /* ── Global ─────────────────────────────────────────────────────────── */
    Screen {
        background: #050a12;
        color: #c0cfe0;
        layout: vertical;
    }

    Header {
        background: #0d1a2e;
        color: #00d4ff;
        text-style: bold;
    }

    /* ── Body ────────────────────────────────────────────────────────────── */
    #body {
        layout: horizontal;
        height: 1fr;
        min-height: 20;
    }

    /* ── Agent Feed Panel (left, 28%) ─────────────────────────────────────── */
    #agent-feed-panel {
        width: 28%;
        border: solid #1e3a5a;
        background: #060c18;
        min-width: 30;
    }

    #agent-feed-panel .panel-title {
        background: #163050;
        color: #00d4ff;
        text-style: bold;
        padding: 0 1;
        width: 100%;
        height: 1;
    }

    #cot-log {
        height: 1fr;
        background: #060c18;
        border: none;
        padding: 0 1;
        scrollbar-color: #1e3a5a;
    }

    /* ── Findings Table Panel (center, 47%) ──────────────────────────────── */
    #findings-panel {
        width: 47%;
        border: solid #1e3a5a;
        background: #060c18;
    }

    #findings-panel .panel-title {
        background: #1a2a1a;
        color: #7fff7f;
        text-style: bold;
        padding: 0 1;
        width: 100%;
        height: 1;
    }

    DataTable {
        height: 1fr;
        background: #070d1a;
        border: none;
    }

    DataTable > .datatable--header {
        background: #0f1f35;
        color: #58a6ff;
        text-style: bold;
    }

    DataTable > .datatable--cursor {
        background: #163050;
    }

    DataTable > .datatable--hover {
        background: #0d1a2e;
    }

    /* ── Stats Panel (right, 25%) ─────────────────────────────────────────── */
    #stats-panel {
        width: 25%;
        border: solid #1e3a5a;
        background: #060c18;
        min-width: 28;
    }

    #stats-panel .panel-title {
        background: #1a1535;
        color: #c792ea;
        text-style: bold;
        padding: 0 1;
        width: 100%;
        height: 1;
    }

    StatsPanel {
        height: 1fr;
        overflow-y: scroll;
        scrollbar-color: #1e3a5a;
    }

    /* ── Evidence Panel ──────────────────────────────────────────────────── */
    #evidence-wrapper {
        border: solid #1e5a3a;
        background: #060c18;
        height: 11;
        min-height: 9;
    }

    #evidence-wrapper .panel-title {
        background: #0a2a1a;
        color: #7fff7f;
        text-style: bold;
        padding: 0 1;
        width: 100%;
        height: 1;
    }

    EvidencePanel {
        height: 1fr;
        padding: 0 2;
        background: #060c18;
    }

    /* ── Control Bar ──────────────────────────────────────────────────────── */
    #controls {
        height: 4;
        layout: horizontal;
        background: #0d1520;
        border-top: solid #1e3a5a;
        align: center middle;
        padding: 0 2;
    }

    Button {
        margin: 0 1;
        min-width: 18;
        height: 3;
    }

    #btn-launch  { background: #1a4a9e; color: white; border: none; }
    #btn-launch:hover  { background: #2060c0; }
    #btn-approve { background: #1a6e2e; color: white; border: none; }
    #btn-approve:hover { background: #228b3c; }
    #btn-refresh { background: #2d4a6a; color: white; border: none; }
    #btn-refresh:hover { background: #3a5f87; }
    #btn-dismiss { background: #3a3a4a; color: white; border: none; }
    #btn-abort   { background: #7a1515; color: white; border: none; }
    #btn-abort:hover { background: #9e1e1e; }

    #status-label {
        color: #3fb950;
        text-style: bold;
        margin-left: 2;
        padding: 0 1;
    }

    StatusCounters {
        dock: bottom;
        height: 1;
    }

    Footer {
        background: #0d1520;
        color: #4a7a9b;
    }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+l", "launch_swarm", "Launch"),
        Binding("ctrl+a", "approve_report", "Approve"),
        Binding("ctrl+e", "export_findings", "Export"),
        Binding("escape", "dismiss_finding", "Dismiss"),
        Binding("r", "refresh_stats", "Refresh"),
    ]

    # ── Reactive State ─────────────────────────────────────────────────────
    swarm_running:       var[bool]      = var(False)
    pending_reports:     var[list[dict]]= var([])
    selected_report_idx: var[int]       = var(-1)
    _start_ts: float = 0.0

    # ───────────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header()

        # ── 3-column main body ─────────────────────────────────────────────
        with Horizontal(id="body"):

            # ── Left: Agent Feed ──────────────────────────────────────────
            with Vertical(id="agent-feed-panel"):
                yield Label("  🧠 AGENT INTELLIGENCE FEED", classes="panel-title")
                yield RichLog(id="cot-log", highlight=True, markup=True, wrap=True)

            # ── Center: Findings Table ────────────────────────────────────
            with Vertical(id="findings-panel"):
                yield Label("  🛰  THREAT INTELLIGENCE FINDINGS", classes="panel-title")
                yield DataTable(id="targets-table", cursor_type="row", zebra_stripes=True)

            # ── Right: Stats Dashboard ────────────────────────────────────
            with Vertical(id="stats-panel"):
                yield Label("  📊 LIVE STATISTICS DASHBOARD", classes="panel-title")
                yield StatsPanel(id="stats-widget")

        # ── Evidence Panel ─────────────────────────────────────────────────
        with Vertical(id="evidence-wrapper"):
            yield Label(
                "  🔎 EVIDENCE  │  ⚔️  MITRE ATT&CK  │  📊 XAI DECISION  │  ⛓ ATTACK CHAIN",
                classes="panel-title",
            )
            yield EvidencePanel(id="evidence-panel")

        # ── Control Bar + Counters ────────────────────────────────────────
        with Horizontal(id="controls"):
            yield Button("▶  LAUNCH SWARM",  id="btn-launch",  variant="primary")
            yield Button("✓  APPROVE",       id="btn-approve", variant="success")
            yield Button("↺  REFRESH",       id="btn-refresh")
            yield Button("✗  DISMISS",       id="btn-dismiss")
            yield Button("⊘  ABORT",        id="btn-abort",   variant="error")
            yield Label("● IDLE", id="status-label")

        yield StatusCounters(id="counters")
        yield Footer()

    # ───────────────────────────────────────────────────────────────────────
    def on_mount(self) -> None:
        """Initialize table, write welcome message, start polling."""
        table = self.query_one("#targets-table", DataTable)
        table.add_columns(
            " #", " IP / URL", " Port", " Country", " Risk", " Cred Type", " Score", " Chain", " Status"
        )
        table.cursor_type = "row"

        log = self.query_one("#cot-log", RichLog)
        log.write(
            "[bold #00d4ff]╔══════════════════════════════════════════════╗[/bold #00d4ff]\n"
            "[bold #00d4ff]║    AEGIS-G4 WAR ROOM — ONLINE                ║[/bold #00d4ff]\n"
            "[bold #00d4ff]╚══════════════════════════════════════════════╝[/bold #00d4ff]\n"
            "[dim]  Gemma 4 Good Hackathon — Google DeepMind[/dim]\n"
            "[dim]  Press [bold]Ctrl+L[/bold] or [bold]▶ LAUNCH SWARM[/bold] to begin.[/dim]\n"
            f"[dim]  Available dorks: {len(get_dorks_for_session())} strategic queries loaded.[/dim]\n"
        )

        # Poll thought_stream every 300ms + refresh stats every 1s
        self.set_interval(0.3, self._poll_thought_stream)
        self.set_interval(1.0, self._refresh_live_stats)

    # ── Polls ──────────────────────────────────────────────────────────────

    def _poll_thought_stream(self) -> None:
        log = self.query_one("#cot-log", RichLog)
        for msg in thought_stream.drain():
            agent  = msg.get("agent", "SYSTEM").upper()
            kind   = msg.get("type", "reasoning")
            thought = msg.get("thought", "")
            ts     = msg.get("timestamp", "")[:19].replace("T", " ")

            color = AGENT_COLORS.get(agent, "white")
            icon  = AGENT_ICONS.get(agent, "•")
            kind_icon = {
                "reasoning": "💭", "action":   "⚡", "result":   "✅",
                "error":     "❌", "system":   "⚙️", "decision": "⚖️",
            }.get(kind, "•")

            log.write(
                f"[dim]{ts}[/dim] {icon} [{color}]{agent:<9}[/{color}] "
                f"{kind_icon} {thought}"
            )

    def _refresh_live_stats(self) -> None:
        """Refresh the stats panel + counter bar every second."""
        try:
            self.query_one("#stats-widget", StatsPanel).refresh()
            self.query_one("#counters", StatusCounters).refresh()
        except Exception:
            pass

    # ── Button Actions ─────────────────────────────────────────────────────

    @on(Button.Pressed, "#btn-launch")
    def action_launch_swarm(self) -> None:
        if self.swarm_running:
            self._log_cot("SYSTEM", "⚠ Swarm already running. Wait for completion.", "system")
            return
        STATS.reset()
        self._start_swarm()

    @on(Button.Pressed, "#btn-approve")
    def action_approve_report(self) -> None:
        if not self.pending_reports:
            self._log_cot("SYSTEM", "No pending reports to approve.", "system")
            return
        if self.selected_report_idx < 0:
            self._log_cot("SYSTEM", "Select a finding row first.", "system")
            return
        self._approve_report(self.pending_reports[self.selected_report_idx])

    @on(Button.Pressed, "#btn-refresh")
    def action_refresh_stats(self) -> None:
        self.query_one("#stats-widget", StatsPanel).refresh()
        self.query_one("#counters", StatusCounters).refresh()
        self._log_cot("SYSTEM", "Dashboard refreshed.", "system")

    @on(Button.Pressed, "#btn-dismiss")
    def action_dismiss_finding(self) -> None:
        if self.selected_report_idx >= 0 and self.pending_reports:
            dismissed = self.pending_reports.pop(self.selected_report_idx)
            self.selected_report_idx = -1
            self._log_cot(
                "COMMANDER",
                f"Finding dismissed: {dismissed.get('url', 'unknown')[:50]}",
                "decision",
            )
            self.query_one("#evidence-panel", EvidencePanel).content = (
                "[dim]Finding dismissed. Select another target.[/dim]"
            )

    @on(Button.Pressed, "#btn-abort")
    def action_abort(self) -> None:
        self._log_cot("SYSTEM", "⊘ ABORT requested. Swarm will halt after current step.", "system")
        self.swarm_running = False
        self._set_status("● ABORTED", "#da3633")

    def action_export_findings(self) -> None:
        """Export all findings to a JSON file."""
        import os
        ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(os.getcwd(), f"aegis_findings_{ts}.json")
        export   = {
            "exported_at": ts,
            "stats": {
                "targets_scanned":   STATS.targets_scanned,
                "targets_found":     STATS.targets_found,
                "critical":          STATS.critical_count,
                "high":              STATS.high_count,
                "attack_chains":     STATS.attack_chains,
                "campaigns":         STATS.campaign_count,
                "countries":         dict(STATS.countries.most_common()),
                "credential_types":  dict(STATS.cred_types.most_common()),
            },
            "findings": self.pending_reports,
        }
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(export, f, indent=2, default=str)
            self._log_cot("SYSTEM", f"✅ Exported {len(self.pending_reports)} findings → {out_path}", "result")
        except Exception as exc:
            self._log_cot("SYSTEM", f"❌ Export failed: {exc}", "error")

    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self.pending_reports):
            self.selected_report_idx = idx
            self.query_one("#evidence-panel", EvidencePanel).update_evidence(
                self.pending_reports[idx]
            )

    # ── Swarm Lifecycle ────────────────────────────────────────────────────

    @work(thread=True)
    def _start_swarm(self) -> None:
        self.swarm_running = True
        self._start_ts = time.monotonic()
        self._set_status("● SCANNING", "#1f6feb")
        self._log_cot("COMMANDER", "🚀 Swarm mission initiated. Assembling agents...", "system")
        self._log_cot("SYSTEM", f"📚 {len(get_dorks_for_session())} strategic dorks loaded from library.", "system")

        def _on_complete(result: SwarmResult) -> None:
            self.swarm_running = False
            self._on_swarm_complete(result)

        # Build enriched task string using top dorks
        top_queries = get_dorks_for_session(max_dorks=5)
        dork_list   = " | ".join(f'"{q[:40]}"' for q in top_queries[:3])
        task = (
            "Discover internet-exposed secrets and API tokens on public-facing services. "
            f"Priority ZoomEye queries: {dork_list}. "
            "For each target: extract credentials, check IP reputation, "
            "trace GitHub source, calculate risk score, correlate campaigns. "
            "Prepare structured disclosure reports for all APPROVED findings."
        )

        run_swarm_threaded(task=task, on_complete=_on_complete)

    def _on_swarm_complete(self, result: SwarmResult) -> None:
        if result.success:
            self._set_status(
                f"● COMPLETE  ■ {result.critical_findings} CRITICAL", "#3fb950"
            )
            for r in result.reports:
                STATS.add_finding(r)
                STATS.targets_scanned += 1
                self.pending_reports.append(r)
                self._add_finding_row(r)

            # Extract campaign names from result
            if hasattr(result, "commander_reasoning"):
                import re
                camps = re.findall(r"CAMP-([A-Z]+)", result.commander_reasoning or "")
                for c in camps:
                    if c not in STATS.campaigns:
                        STATS.campaigns.append(c)
            STATS.campaign_count = len(STATS.campaigns)

            self._log_cot(
                "COMMANDER",
                f"✅ Mission complete │ {result.targets_analyzed} analyzed │ "
                f"{result.critical_findings} critical │ {STATS.attack_chains} chains │ "
                f"Human review required.",
                "decision",
            )
        else:
            self._set_status("● ERROR", "#da3633")
            self._log_cot("COMMANDER", f"❌ Swarm error: {result.error}", "error")

    def _add_finding_row(self, report: dict) -> None:
        table = self.query_one("#targets-table", DataTable)
        idx   = len(self.pending_reports)
        risk  = report.get("risk_level", "UNKNOWN").upper()
        score = report.get("risk_score", 0)
        color = RISK_COLORS.get(risk, "white")
        icon  = RISK_ICONS.get(risk, "•")

        # Score bar (10 chars)
        filled = int(score / 10)
        bar    = "█" * filled + "░" * (10 - filled)

        # Geo
        cc   = report.get("country_code", "??")[:2].upper()
        flag = COUNTRY_FLAGS.get(cc, "🏳")
        country_display = f"{flag} {cc}"

        # Credential type
        cred_types = report.get("credential_types", [])
        cred_icon  = CRED_ICONS.get(cred_types[0] if cred_types else "UNKNOWN", "🔑")
        cred_str   = (cred_types[0].replace("_TOKEN", "").replace("_SECRET_KEY", "")[:8]
                      if cred_types else "—")

        # Attack chain indicator
        chain_ind = "🔗" if (report.get("github_source") or report.get("attack_chain")) else "·"

        # IP extract
        ip = report.get("ip", report.get("url", "N/A"))[:15]
        port_str = str(report.get("port", ""))

        table.add_row(
            str(idx),
            ip,
            port_str,
            country_display,
            f"{icon} {risk[:4]}",
            f"{cred_icon} {cred_str}",
            f"[{color}]{bar}[/{color}] {score}",
            chain_ind,
            "⏳",
            key=str(idx),
        )

    def _approve_report(self, report: dict) -> None:
        url       = report.get("url", "N/A")
        report_id = report.get("report_id", "UNKNOWN")
        approved_at = datetime.now(timezone.utc).isoformat()

        try:
            # Mark as approved in table
            table = self.query_one("#targets-table", DataTable)
            row_key = str(self.selected_report_idx)
            table.update_cell(row_key, " Status", "✅")
        except Exception:
            pass

        self._log_cot(
            "COMMANDER",
            f"✅ HUMAN APPROVED │ {report_id} │ {url[:45]} │ {approved_at[:19]}",
            "decision",
        )
        self._log_cot(
            "SYSTEM",
            "📨 Report queued for dispatch. No autonomous action taken. Human supervised.",
            "system",
        )
        self.pending_reports.remove(report)
        self.selected_report_idx = -1

    # ── Helpers ────────────────────────────────────────────────────────────

    def _log_cot(self, agent: str, message: str, kind: str = "reasoning") -> None:
        log   = self.query_one("#cot-log", RichLog)
        color = AGENT_COLORS.get(agent.upper(), "white")
        icon  = AGENT_ICONS.get(agent.upper(), "•")
        ts    = datetime.now(timezone.utc).isoformat()[:19].replace("T", " ")
        log.write(f"[dim]{ts}[/dim] {icon} [{color}]{agent:<9}[/{color}] {message}")

    def _set_status(self, text: str, color: str = "#3fb950") -> None:
        try:
            label = self.query_one("#status-label", Label)
            label.update(f"[bold {color}]{text}[/bold {color}]")
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = AegisWarRoom()
    app.run()
