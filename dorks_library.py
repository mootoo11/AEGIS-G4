"""
dorks_library.py — AEGIS-G4 Strategic Intelligence Dork Library
================================================================
40+ battle-tested ZoomEye dorks organized by credential type, priority,
and expected yield. Each dork is annotated with MITRE ATT&CK context.

ZoomEye Query Syntax Reference:
  app:"Name"          → application/service name
  title:"text"        → page title
  http.body:"text"    → HTTP response body contains text
  http.status:200     → HTTP response status code
  port:8080           → specific port
  country:"US"        → country filter
  ip:"1.2.3.4"        → specific IP

Run: from dorks_library import get_top_dorks, PRIORITY_DORKS
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Dork:
    query: str
    category: str
    target_credential: str
    expected_yield: Literal["HIGH", "MEDIUM", "LOW"]
    mitre_technique: str
    description: str
    priority: int          # 1 = highest. 10 = lowest
    tags: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"[{self.category}/{self.expected_yield}] {self.query[:70]}"


# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM BOT TOKENS  (T1552.001 — Unsecured Credentials in Files)
# HIGH IMPACT: Telegram bots can control millions of users; common in phishing C2
# ─────────────────────────────────────────────────────────────────────────────

TELEGRAM_DORKS: list[Dork] = [
    Dork(
        query='http.body:"api.telegram.org/bot" http.status:200',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Active Telegram Bot API calls — highest confidence live bots",
        tags=["live-bot", "api-call", "active"],
    ),
    Dork(
        query='http.body:"api.telegram.org" http.body:"bot_token"',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Telegram API with bot_token variable explicitly named",
        tags=["token-var", "explicit"],
    ),
    Dork(
        query='http.body:"TELEGRAM_BOT_TOKEN" http.status:200',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Exposed env variable TELEGRAM_BOT_TOKEN in response",
        tags=["env-var", "exposed-config"],
    ),
    Dork(
        query='http.body:"sendMessage" http.body:"chat_id" http.body:"token"',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Telegram sendMessage API with token and chat_id exposed",
        tags=["api-call", "send-message", "chat-id"],
    ),
    Dork(
        query='http.body:"getUpdates" http.body:"api.telegram.org" http.status:200',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Polling getUpdates endpoints — live active bot exposure",
        tags=["polling", "live", "getUpdates"],
    ),
    Dork(
        query='http.body:"telebot" http.body:"TOKEN=" app:"Python"',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1552.001", priority=2,
        description="Python pyTelegramBotAPI (telebot) with exposed TOKEN",
        tags=["python", "telebot", "library"],
    ),
    Dork(
        query='http.body:"python-telegram-bot" http.body:"token="',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1552.001", priority=2,
        description="python-telegram-bot library with hardcoded token",
        tags=["ptb", "library", "python"],
    ),
    Dork(
        query='app:"Flask" http.body:"telegram" http.body:"token" http.status:200',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1552.001", priority=2,
        description="Flask webhook apps with telegram token in responses",
        tags=["flask", "webhook"],
    ),
    Dork(
        query='title:"Bot" http.body:"TELEGRAM" http.body:"token" http.status:200',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1552.001", priority=3,
        description="Bot-titled admin panels with exposed TELEGRAM tokens",
        tags=["admin-panel", "title-match"],
    ),
    Dork(
        query='http.body:"setWebhook" http.body:"telegram" http.status:200',
        category="TELEGRAM", target_credential="TELEGRAM_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Telegram webhook setup pages often expose full bot tokens",
        tags=["webhook", "setup", "live"],
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# DISCORD BOT TOKENS  (T1078.004 — Cloud Accounts)
# HIGH IMPACT: Full server control, mass DM capability for phishing
# ─────────────────────────────────────────────────────────────────────────────

DISCORD_DORKS: list[Dork] = [
    Dork(
        query='http.body:"discord.com/api" http.body:"Authorization" http.status:200',
        category="DISCORD", target_credential="DISCORD_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1078.004", priority=1,
        description="Discord API calls with Authorization token header in response",
        tags=["api-call", "auth-header"],
    ),
    Dork(
        query='http.body:"DISCORD_BOT_TOKEN" http.status:200',
        category="DISCORD", target_credential="DISCORD_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1078.004", priority=1,
        description="Exposed DISCORD_BOT_TOKEN env variable in page content",
        tags=["env-var", "critical"],
    ),
    Dork(
        query='http.body:"discordapp.com/api" http.body:"token" http.status:200',
        category="DISCORD", target_credential="DISCORD_BOT_TOKEN",
        expected_yield="HIGH", mitre_technique="T1078.004", priority=1,
        description="Discord legacy API endpoint with token parameter",
        tags=["legacy-api"],
    ),
    Dork(
        query='app:"Python" http.body:"discord" http.body:"TOKEN=" http.status:200',
        category="DISCORD", target_credential="DISCORD_BOT_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1078.004", priority=2,
        description="Python discord.py bots with exposed TOKEN variable",
        tags=["python", "discord-py"],
    ),
    Dork(
        query='http.body:"discord.gg" http.body:"bot_token" http.status:200',
        category="DISCORD", target_credential="DISCORD_BOT_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1078.004", priority=2,
        description="Discord invite/community pages with exposed bot tokens",
        tags=["invite", "community"],
    ),
    Dork(
        query='http.body:"discord.js" http.body:"client.login" http.status:200',
        category="DISCORD", target_credential="DISCORD_BOT_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1078.004", priority=2,
        description="Discord.js bot login pages — sometimes expose token in source",
        tags=["discord-js", "javascript"],
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# GITHUB PERSONAL ACCESS TOKENS  (T1195.001 — Supply Chain via Source Code)
# CRITICAL IMPACT: Full repo access, code injection, CI/CD poisoning
# ─────────────────────────────────────────────────────────────────────────────

GITHUB_DORKS: list[Dork] = [
    Dork(
        query='http.body:"ghp_" http.status:200',
        category="GITHUB", target_credential="GITHUB_PAT",
        expected_yield="HIGH", mitre_technique="T1195.001", priority=1,
        description="Classic GitHub PAT (ghp_ prefix) exposed in HTTP response",
        tags=["pat", "classic", "prefix-match"],
    ),
    Dork(
        query='http.body:"github_pat_" http.status:200',
        category="GITHUB", target_credential="GITHUB_PAT",
        expected_yield="HIGH", mitre_technique="T1195.001", priority=1,
        description="Fine-grained GitHub PAT (github_pat_ prefix) exposed",
        tags=["fine-grained-pat", "new-format"],
    ),
    Dork(
        query='http.body:"GITHUB_TOKEN" http.body:"ghp_" http.status:200',
        category="GITHUB", target_credential="GITHUB_PAT",
        expected_yield="HIGH", mitre_technique="T1195.001", priority=1,
        description="GITHUB_TOKEN env variable with actual ghp_ value visible",
        tags=["env-var", "explicit"],
    ),
    Dork(
        query='title:"GitHub" http.body:"access_token" http.body:"Bearer"',
        category="GITHUB", target_credential="GITHUB_PAT",
        expected_yield="MEDIUM", mitre_technique="T1195.001", priority=2,
        description="GitHub-related pages with Bearer token in response",
        tags=["bearer", "oauth"],
    ),
    Dork(
        query='http.body:"api.github.com" http.body:"Authorization" http.status:200',
        category="GITHUB", target_credential="GITHUB_PAT",
        expected_yield="MEDIUM", mitre_technique="T1195.001", priority=2,
        description="GitHub API calls with Authorization header visible",
        tags=["api-call", "auth-header"],
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# STRIPE SECRET KEYS  (T1657 — Financial Theft)
# CRITICAL IMPACT: Direct financial fraud, charge cards, access customer data
# ─────────────────────────────────────────────────────────────────────────────

STRIPE_DORKS: list[Dork] = [
    Dork(
        query='http.body:"sk_live_" http.status:200',
        category="STRIPE", target_credential="STRIPE_SECRET_KEY",
        expected_yield="HIGH", mitre_technique="T1657", priority=1,
        description="Stripe LIVE secret key (sk_live_) exposed — CRITICAL financial risk",
        tags=["live-key", "financial", "critical"],
    ),
    Dork(
        query='http.body:"STRIPE_SECRET_KEY" http.status:200',
        category="STRIPE", target_credential="STRIPE_SECRET_KEY",
        expected_yield="HIGH", mitre_technique="T1657", priority=1,
        description="STRIPE_SECRET_KEY env variable visible in HTTP response",
        tags=["env-var", "financial"],
    ),
    Dork(
        query='http.body:"stripe.com" http.body:"sk_live" http.status:200',
        category="STRIPE", target_credential="STRIPE_SECRET_KEY",
        expected_yield="HIGH", mitre_technique="T1657", priority=1,
        description="Stripe integration pages with live key exposed",
        tags=["stripe-integration"],
    ),
    Dork(
        query='app:"PHP" http.body:"stripe_secret" http.status:200',
        category="STRIPE", target_credential="STRIPE_SECRET_KEY",
        expected_yield="MEDIUM", mitre_technique="T1657", priority=2,
        description="PHP e-commerce apps with stripe_secret variable",
        tags=["php", "e-commerce"],
    ),
    Dork(
        query='http.body:"Stripe-Signature" http.body:"secret" http.status:200',
        category="STRIPE", target_credential="STRIPE_SECRET_KEY",
        expected_yield="MEDIUM", mitre_technique="T1657", priority=2,
        description="Stripe webhook signature pages with exposed secret",
        tags=["webhook", "signature"],
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# SLACK API TOKENS  (T1552.001 — Credential Exposure)
# HIGH IMPACT: Workspace enumeration, DM exfiltration, channel access
# ─────────────────────────────────────────────────────────────────────────────

SLACK_DORKS: list[Dork] = [
    Dork(
        query='http.body:"xoxb-" http.status:200',
        category="SLACK", target_credential="SLACK_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Slack bot token (xoxb- prefix) exposed in HTTP response",
        tags=["bot-token", "xoxb"],
    ),
    Dork(
        query='http.body:"xoxp-" http.status:200',
        category="SLACK", target_credential="SLACK_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Slack user token (xoxp- prefix) — even more privileged",
        tags=["user-token", "xoxp", "high-privilege"],
    ),
    Dork(
        query='http.body:"SLACK_TOKEN" http.body:"xox" http.status:200',
        category="SLACK", target_credential="SLACK_TOKEN",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="SLACK_TOKEN env variable with actual xox* value",
        tags=["env-var"],
    ),
    Dork(
        query='http.body:"slack.com/api" http.body:"token=" http.status:200',
        category="SLACK", target_credential="SLACK_TOKEN",
        expected_yield="MEDIUM", mitre_technique="T1552.001", priority=2,
        description="Slack API calls with token parameter visible",
        tags=["api-call"],
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# HIGH-VALUE GENERAL / MULTI-CREDENTIAL TARGETS
# ─────────────────────────────────────────────────────────────────────────────

GENERAL_DORKS: list[Dork] = [
    Dork(
        query='http.body:"SECRET_KEY" http.body:"DEBUG" http.body:"True" http.status:200',
        category="GENERAL", target_credential="DJANGO_SECRET",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Django/Flask debug mode pages with SECRET_KEY exposed",
        tags=["django", "flask", "debug-mode", "critical"],
    ),
    Dork(
        query='app:"Jupyter Notebook" port:8888 http.status:200',
        category="GENERAL", target_credential="MULTIPLE",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Unprotected Jupyter Notebooks — dev environments with all secrets",
        tags=["jupyter", "dev-env", "no-auth"],
    ),
    Dork(
        query='title:"phpinfo()" http.body:"SECRET" http.status:200',
        category="GENERAL", target_credential="MULTIPLE",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="PHP info pages dump all environment variables including secrets",
        tags=["phpinfo", "env-dump"],
    ),
    Dork(
        query='http.body:"AWS_ACCESS_KEY_ID" http.body:"AWS_SECRET_ACCESS_KEY"',
        category="GENERAL", target_credential="AWS_CREDENTIAL",
        expected_yield="HIGH", mitre_technique="T1552.005", priority=1,
        description="Exposed AWS credentials — highest-impact cloud credential type",
        tags=["aws", "cloud", "critical"],
    ),
    Dork(
        query='http.body:"database.yml" http.body:"password" http.status:200',
        category="GENERAL", target_credential="DB_CREDENTIAL",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Exposed Rails database.yml with database passwords",
        tags=["rails", "database", "credentials"],
    ),
    Dork(
        query='http.body:".env" http.body:"TOKEN" http.body:"KEY" http.status:200',
        category="GENERAL", target_credential="MULTIPLE",
        expected_yield="HIGH", mitre_technique="T1552.001", priority=1,
        description="Exposed .env files with multiple credential types — jackpot",
        tags=["env-file", "multi-cred"],
    ),
    Dork(
        query='http.body:"ACCESS_TOKEN" http.body:"REFRESH_TOKEN" http.status:200',
        category="GENERAL", target_credential="OAUTH_TOKEN",
        expected_yield="HIGH", mitre_technique="T1528", priority=1,
        description="OAuth token pairs exposed — enables impersonation attacks",
        tags=["oauth", "access-token", "refresh-token"],
    ),
    Dork(
        query='app:"FastAPI" http.body:"/docs" http.body:"Bearer" http.status:200',
        category="GENERAL", target_credential="API_KEY",
        expected_yield="MEDIUM", mitre_technique="T1552.001", priority=2,
        description="FastAPI Swagger UI with live Bearer token examples",
        tags=["fastapi", "swagger", "api-docs"],
    ),
    Dork(
        query='http.body:"private_key" http.body:"-----BEGIN" http.status:200',
        category="GENERAL", target_credential="PRIVATE_KEY",
        expected_yield="HIGH", mitre_technique="T1552.004", priority=1,
        description="Exposed private keys (RSA/EC) — enables certificate attacks",
        tags=["private-key", "rsa", "pem"],
    ),
    Dork(
        query='http.body:"mongodb" http.body:"password" http.body:"27017" http.status:200',
        category="GENERAL", target_credential="DB_CREDENTIAL",
        expected_yield="MEDIUM", mitre_technique="T1552.001", priority=2,
        description="MongoDB connection strings with passwords exposed",
        tags=["mongodb", "nosql", "connection-string"],
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Master Registry
# ─────────────────────────────────────────────────────────────────────────────

ALL_DORKS: list[Dork] = (
    TELEGRAM_DORKS
    + DISCORD_DORKS
    + GITHUB_DORKS
    + STRIPE_DORKS
    + SLACK_DORKS
    + GENERAL_DORKS
)

# Pre-sorted: priority ASC, then yield (HIGH=0, MEDIUM=1, LOW=2)
PRIORITY_DORKS: list[Dork] = sorted(
    ALL_DORKS,
    key=lambda d: (d.priority, {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[d.expected_yield]),
)

# ── Query Functions ───────────────────────────────────────────────────────────

def get_top_dorks(n: int = 15) -> list[Dork]:
    """Returns top N dorks sorted by impact priority."""
    return PRIORITY_DORKS[:n]


def get_dorks_by_category(category: str) -> list[Dork]:
    return [d for d in ALL_DORKS if d.category == category.upper()]


def get_high_yield_dorks() -> list[Dork]:
    return [d for d in ALL_DORKS if d.expected_yield == "HIGH"]


def get_dorks_for_session(max_dorks: int = 20) -> list[str]:
    """Returns a ready-to-use list of ZoomEye query strings for a scan session."""
    return [d.query for d in get_top_dorks(max_dorks)]


def get_dork_by_credential(cred_type: str) -> list[Dork]:
    return [d for d in ALL_DORKS if d.target_credential == cred_type]


# ── Summary ───────────────────────────────────────────────────────────────────
DORK_SUMMARY = {
    "total_dorks": len(ALL_DORKS),
    "high_yield":  sum(1 for d in ALL_DORKS if d.expected_yield == "HIGH"),
    "categories":  list({d.category for d in ALL_DORKS}),
    "top_5_queries": [d.query[:60] for d in PRIORITY_DORKS[:5]],
}

if __name__ == "__main__":
    print(f"\n📚 AEGIS-G4 Dork Library — {DORK_SUMMARY['total_dorks']} dorks loaded")
    print(f"   HIGH yield: {DORK_SUMMARY['high_yield']} | Categories: {DORK_SUMMARY['categories']}")
    print("\n🎯 Top 5 Priority Dorks:")
    for i, d in enumerate(PRIORITY_DORKS[:5], 1):
        print(f"   {i}. [{d.category}] {d.query[:65]}")
