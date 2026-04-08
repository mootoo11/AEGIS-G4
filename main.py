"""
main.py — AEGIS-G4 Entry Point
================================
CLI interface supporting three operation modes:
  ui       → Launch the interactive War Room TUI (default)
  headless → Run swarm without UI and print JSON report
  honeypot → Start a local honeypot web server for safe demos
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from dotenv import load_dotenv

load_dotenv()

# Configure logging before any imports that use it
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.getenv("LOG_FILE", "aegis_g4.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("aegis.main")


# ─────────────────────────────────────────────────────────────────────────────
# Honeypot Server — Safe Demo Target
# ─────────────────────────────────────────────────────────────────────────────

HONEYPOT_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bot Manager v2.1 — Dashboard</title>
  <style>
    body {{ font-family: monospace; background: #1a1a2e; color: #e0e0ff; padding: 40px; }}
    h1 {{ color: #00ff88; }}
    .config {{ background: #16213e; padding: 20px; border-radius: 8px; }}
    .warning {{ color: #ff6b6b; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>🤖 Telegram Bot Manager</h1>
  <div class="config">
    <h2>Active Configuration</h2>
    <p>Environment: <strong>DEVELOPMENT</strong></p>
    <pre>
# config.py — DO NOT COMMIT
BOT_TOKEN = "987654321:AAHoneypotTokenForAEGIS-G4DemoOnly123"
CHAT_ID = "-1001234567890"
WEBHOOK_URL = "https://example.com/webhook"
    </pre>
    <p class="warning">
      ⚠️ This is a HONEYPOT server for AEGIS-G4 demo purposes only.
      The token above is intentionally fake and non-functional.
    </p>
  </div>
  <script>
    // Simulated bot initialisation
    const config = {{
      bot_token: "987654321:AAHoneypotTokenForAEGIS-G4DemoOnly123",
      chat_id: "-1001234567890"
    }};
    console.log("Bot config loaded:", config);
  </script>
</body>
</html>
"""


class HoneypotHandler(BaseHTTPRequestHandler):
    """Serves a fake Bot Manager page containing a structurally-valid-looking token."""

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HONEYPOT_HTML.encode())

    def log_message(self, fmt: str, *args: object) -> None:
        logger.debug("Honeypot: " + fmt, *args)


def start_honeypot(host: str = "127.0.0.1", port: int = 8888) -> HTTPServer:
    """Starts the honeypot server in a daemon thread. Returns the server instance."""
    server = HTTPServer((host, port), HoneypotHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Honeypot serving at http://%s:%d", host, port)
    return server


# ─────────────────────────────────────────────────────────────────────────────
# CLI Modes
# ─────────────────────────────────────────────────────────────────────────────

def mode_ui(args: argparse.Namespace) -> None:
    """Launches the interactive War Room TUI."""
    if args.with_honeypot:
        hp = start_honeypot(port=args.honeypot_port)
        print(f"[HONEYPOT] Serving at http://127.0.0.1:{args.honeypot_port}")

    from war_room_ui import AegisWarRoom
    app = AegisWarRoom()
    app.run()


def mode_headless(args: argparse.Namespace) -> None:
    """Runs the swarm without UI and prints the JSON result to stdout."""
    from swarm_orchestrator import run_swarm, thought_stream

    if args.with_honeypot:
        start_honeypot(port=args.honeypot_port)

    print("[AEGIS-G4] Headless swarm starting...\n")

    def _on_thought(t: dict) -> None:
        print(f"  [{t['agent']:10s}] {t['thought'][:120]}")

    result = run_swarm(
        task=args.task or (
            "Discover exposed Telegram Bot tokens on internet-facing services "
            "and prepare responsible disclosure reports."
        ),
        on_thought=_on_thought,
    )

    print("\n" + "=" * 70)
    print("SWARM RESULT")
    print("=" * 70)
    print(json.dumps(
        {
            "task": result.task,
            "success": result.success,
            "targets_discovered": result.targets_discovered,
            "targets_analyzed": result.targets_analyzed,
            "critical_findings": result.critical_findings,
            "reports": result.reports,
            "final_summary": result.final_summary[:500],
            "completed_at": result.completed_at,
        },
        indent=2,
    ))


def mode_honeypot(args: argparse.Namespace) -> None:
    """Starts only the honeypot server (for testing fetch_target_data)."""
    import time
    hp = start_honeypot(port=args.honeypot_port)
    print(f"[HONEYPOT] Running at http://127.0.0.1:{args.honeypot_port}")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hp.shutdown()
        print("\n[HONEYPOT] Stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# Argument Parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis-g4",
        description="AEGIS-G4 — Autonomous Edge-based Global Intelligence Swarm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python main.py ui                    # Launch War Room TUI
  python main.py ui --with-honeypot   # TUI + auto-start honeypot demo server
  python main.py headless             # Run swarm, print JSON report
  python main.py honeypot             # Start honeypot server only (port 8888)
""",
    )
    sub = p.add_subparsers(dest="mode", required=False)

    # ── ui ──────────────────────────────────────────────────────────────────
    ui_p = sub.add_parser("ui", help="Launch interactive War Room TUI (default)")
    ui_p.add_argument("--with-honeypot", action="store_true",
                      help="Also start the honeypot demo server")
    ui_p.add_argument("--honeypot-port", type=int, default=8888)

    # ── headless ────────────────────────────────────────────────────────────
    hl_p = sub.add_parser("headless", help="Run swarm without TUI; print JSON report")
    hl_p.add_argument("--task", type=str, default=None,
                      help="Custom mission task for the Commander agent")
    hl_p.add_argument("--with-honeypot", action="store_true")
    hl_p.add_argument("--honeypot-port", type=int, default=8888)

    # ── honeypot ─────────────────────────────────────────────────────────────
    hp_p = sub.add_parser("honeypot", help="Start the demo honeypot server only")
    hp_p.add_argument("--honeypot-port", type=int, default=8888)

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Entry
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    # Default to UI mode if no sub-command given
    if not args.mode:
        args.mode = "ui"
        args.with_honeypot = False
        args.honeypot_port = 8888

    dispatch = {"ui": mode_ui, "headless": mode_headless, "honeypot": mode_honeypot}
    dispatch[args.mode](args)
