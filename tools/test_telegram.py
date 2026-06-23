#!/usr/bin/env python3
"""test_telegram — send 3 test messages to the configured Telegram bot.

This is a real-network test: it hits ``api.telegram.org``. The script
honors the project convention of NEVER sending when ``telegram.enabled``
is false in ``config.yml`` UNLESS you pass ``--force``.

What it sends (in this order, with a 1-second gap so the chat is readable):

  1. A plain ``notify()`` smoke-test message ("✅ telegram works")
  2. A ``notify_finding()`` CRITICAL message (template-id, URL, matcher)
  3. A ``notify_stage_result()`` summary (severity breakdown + counts)

Usage:
  python3 tools/test_telegram.py             # honors config.yml enabled flag
  python3 tools/test_telegram.py --force    # ignore enabled=false in config
  python3 tools/test_telegram.py --dry-run  # build messages, do not POST
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Allow ``python3 tools/test_telegram.py`` from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from modules import telegram as tg  # noqa: E402


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _load_cfg(config_path: Path, force: bool) -> dict:
    """Load ``config.yml`` and (optionally) force-enable the telegram block.

    Without ``--force`` the function returns the config as-is so the
    project-wide convention (do not spam when disabled) is respected.
    """
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    tg_cfg = dict(cfg.get("telegram") or {})
    if force and not tg_cfg.get("enabled"):
        tg_cfg["enabled"] = True
        print("[!] --force given: overriding telegram.enabled = true")
    return tg_cfg


def _print_config(tg_cfg: dict) -> None:
    print("Telegram config from config.yml:")
    print(f"  enabled              = {tg_cfg.get('enabled')}")
    print(f"  bot_token            = {(tg_cfg.get('bot_token') or '')[:10]}…"
          f"{'(empty)' if not tg_cfg.get('bot_token') else ''}")
    print(f"  chat_id              = {tg_cfg.get('chat_id')}")
    print(f"  notify_high_critical = {tg_cfg.get('notify_high_critical')}")
    print(f"  notify_summary       = {tg_cfg.get('notify_summary')}")
    print()


# ----------------------------------------------------------------------
# Test messages
# ----------------------------------------------------------------------
def _smoke_test(tg_cfg: dict) -> bool:
    """Message 1 — plain notify() smoke test."""
    msg = (
        "✅ *telegram smoke test* — `recon-agent` can reach you.\n"
        f"Sent from `{Path.cwd()}`."
    )
    print(f"[1/3] Sending smoke test…\n      → {msg!r}")
    return tg.notify(msg, tg_cfg, silent=False)


def _finding_test(tg_cfg: dict) -> bool:
    """Message 2 — High/Critical nuclei finding."""
    finding = {
        "info": {
            "name": "SQL Error Detected",
            "severity": "critical",
        },
        "matched-at": "https://example.com/api/v1/users?id=1'",
        "template-id": "sqli-error-based",
        "matcher-name": "sql-error",
    }
    print("[2/3] Sending nuclei CRITICAL finding notification…")
    return tg.notify_finding(finding, stage="nuclei_dynamic", cfg=tg_cfg)


def _stage_result_test(tg_cfg: dict) -> bool:
    """Message 3 — stage-complete summary with severity breakdown."""
    result = {
        "stage": "nuclei_dynamic",
        "status": "success",
        "count": 7,
        "extra": {
            "severity_count": {
                "critical": 1, "high": 2, "medium": 1, "low": 2, "info": 1,
            }
        },
    }
    print("[3/3] Sending stage-complete summary…")
    return tg.notify_stage_result("nuclei_dynamic", result, tg_cfg)


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(
        prog="test_telegram",
        description="Send 3 test messages to the Telegram bot in config.yml",
    )
    p.add_argument("--config", default="config.yml", help="path to config.yml")
    p.add_argument("--force", action="store_true",
                   help="override telegram.enabled=false in config")
    p.add_argument("--dry-run", action="store_true",
                   help="print the messages but do not POST")
    args = p.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"[!] config not found: {cfg_path}", file=sys.stderr)
        return 2

    tg_cfg = _load_cfg(cfg_path, args.force)
    _print_config(tg_cfg)

    if not tg_cfg.get("enabled"):
        print("[!] telegram.enabled = false — nothing to do.")
        print("    Re-run with --force to send anyway, or set enabled: true in config.yml.")
        return 1

    if not (tg_cfg.get("bot_token") and tg_cfg.get("chat_id")):
        print("[!] bot_token or chat_id is empty — fix config.yml first.", file=sys.stderr)
        return 2

    if args.dry_run:
        print("DRY-RUN — no HTTP requests will be made.")
        print()
        print("Messages that WOULD be sent:")
        print("  1. plain smoke-test message via notify()")
        print("  2. nuclei CRITICAL finding via notify_finding()")
        print("  3. stage-complete summary via notify_stage_result()")
        return 0

    print("Sending 3 test messages (1s between each so the chat stays readable)…\n")
    r1 = _smoke_test(tg_cfg);        time.sleep(1)
    r2 = _finding_test(tg_cfg);      time.sleep(1)
    r3 = _stage_result_test(tg_cfg)

    print()
    print("=" * 50)
    print("RESULTS")
    print("=" * 50)
    print(f"  [1/3] smoke-test        : {'✓ sent' if r1 else '✗ FAILED'}")
    print(f"  [2/3] critical finding  : {'✓ sent' if r2 else '✗ FAILED'}")
    print(f"  [3/3] stage summary     : {'✓ sent' if r3 else '✗ FAILED'}")

    if r1 and r2 and r3:
        print()
        print("[+] All 3 messages delivered. Check your Telegram chat.")
        return 0
    print()
    print("[!] One or more sends failed. Verify the bot token with @BotFather,")
    print("    and the chat_id by sending /start to the bot first.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
