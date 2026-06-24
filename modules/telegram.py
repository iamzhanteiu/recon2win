"""telegram — outbound notifications.

We try to be a good citizen:
  * no exception bubbles if the bot is unconfigured
  * no exception bubbles if the HTTP request fails (the hunt must continue)
  * messages are escaped for Telegram's HTML parser, which is far more
    forgiving than Markdown for user-supplied content (URLs, finding
    names, matcher evidence, …).
"""
from __future__ import annotations

import json
import time
from html import escape
from pathlib import Path
from typing import Optional

import requests

from .utils import now_iso

API_BASE = "https://api.telegram.org/bot{token}/sendMessage"


def _enabled(cfg: dict) -> bool:
    return bool(cfg and cfg.get("enabled") and cfg.get("bot_token") and cfg.get("chat_id"))


def _post(token: str, chat_id: str, html_text: str) -> bool:
    """POST an HTML-formatted message. Returns True on HTTP 200."""
    try:
        r = requests.post(
            API_BASE.format(token=token),
            data={"chat_id": chat_id, "text": html_text, "parse_mode": "HTML"},
            timeout=15,
        )
        return r.status_code == 200
    except requests.RequestException:
        return False


def _h(text: str) -> str:
    """Escape user-supplied text for Telegram HTML parse mode."""
    # Telegram HTML parser requires escaping &, <, >. Quotes are fine.
    return escape(str(text), quote=False)


def _relative(path_str: str, output_dir) -> str:
    """Return ``path_str`` relative to ``output_dir`` if possible."""
    if not output_dir:
        return path_str
    try:
        return str(Path(path_str).relative_to(output_dir))
    except (ValueError, TypeError):
        return path_str


def notify(message: str, cfg: Optional[dict], *, silent: bool = True) -> bool:
    """Send a generic message. If silent=True, no console echo on failure."""
    if not _enabled(cfg):
        if not silent:
            print(f"[telegram] skipped (not configured) :: {message[:80]}…")
        return False
    text = f"<code>{_h(now_iso())}</code>\n{_h(message)}"
    ok = _post(cfg["bot_token"], cfg["chat_id"], text)
    if not ok and not silent:
        print("[telegram] send failed")
    return ok


def notify_finding(
    finding: dict, stage: str, cfg: Optional[dict], *, severity_threshold: str = "high"
) -> bool:
    """Notify immediately for findings at or above `severity_threshold`."""
    if not _enabled(cfg):
        return False
    if not cfg.get("notify_high_critical", True):
        return False
    severity = (finding.get("info", {}) or {}).get("severity", "unknown").lower()
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": -1}
    if order.get(severity, -1) < order.get(severity_threshold, 3):
        return False
    name = (finding.get("info", {}) or {}).get("name", "n/a")
    matched = finding.get("matched-at") or finding.get("host", "")
    tmpl = finding.get("template-id", "?")
    msg = (
        f"🚨 <b>{_h(severity.upper())}</b> — <code>{_h(name)}</code>\n"
        f"stage: <code>{_h(stage)}</code>\n"
        f"target: <code>{_h(matched)}</code>\n"
        f"template: <code>{_h(tmpl)}</code>"
    )
    return _post(cfg["bot_token"], cfg["chat_id"], msg)


def notify_phase_complete(
    stage: str, result: dict, cfg: Optional[dict], output_dir=None
) -> bool:
    """Per-phase completion notification with count + output paths.

    Fires for every stage that finishes — not just nuclei / content
    discovery like ``notify_stage_result``. Operator opt-in via the
    ``telegram.per_phase`` config flag (default ``false`` because the
    default scan produces ~13 messages).

    Rules:
      * Telegram must be enabled and fully configured.
      * ``telegram.per_phase`` must be ``true``.
      * ``status`` must be ``"success"`` — we don't notify on failed/
        skipped stages (the milestone summary covers those).
      * ``count`` must be > 0 — empty runs don't get a message.

    The message looks like::

        ✅ <b>subdomain</b> — <code>343</code> result(s)
          • processed/subdomains.txt
          • raw/subdomain/subfinder.txt
          • raw/subdomain/amass.txt
          • raw/subdomain/chaos.txt
    """
    if not _enabled(cfg):
        return False
    if not isinstance(result, dict):
        return False
    if not cfg.get("per_phase", False):
        return False
    if result.get("status") != "success":
        return False
    try:
        count = int(result.get("count", 0) or 0)
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        return False

    outputs = result.get("outputs") or []
    # Render up to 5 paths inline; truncate with "and N more" if more.
    output_lines: list[str] = []
    for o in outputs[:5]:
        output_lines.append(f"  • <code>{_h(_relative(str(o), output_dir))}</code>")
    if len(outputs) > 5:
        output_lines.append(f"  • <i>…and {len(outputs) - 5} more</i>")

    msg = f"✅ <b>{_h(stage)}</b> — <code>{count}</code> result(s)"
    if output_lines:
        msg += "\n" + "\n".join(output_lines)
    return _post(cfg["bot_token"], cfg["chat_id"], msg)


def notify_stage_result(
    stage: str, result: dict, cfg: Optional[dict]
) -> bool:
    """Send a per-stage completion notification when a stage finishes with results.

    Rules (matching the spec: "khi scan xong và có result"):
      * Telegram must be enabled and fully configured (bot_token + chat_id).
      * ``result['status']`` must be ``"success"``.
      * ``result['count']`` must be > 0 — we do NOT notify on empty runs.

    The message is stage-aware:
      * ``nuclei_default`` / ``nuclei_dynamic``  → breakdown by severity.
      * ``content_discovery``                     → URL count + JS count.
      * anything else                             → generic "stage done — N".
    """
    if not _enabled(cfg):
        return False
    if not isinstance(result, dict):
        return False
    if result.get("status") != "success":
        return False
    try:
        count = int(result.get("count", 0) or 0)
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        return False

    extra = result.get("extra") or {}

    if stage in ("nuclei_default", "nuclei_dynamic"):
        sev = extra.get("severity_count") or {}
        msg = (
            f"🔬 <b>{_h(stage)}</b> finished — <code>{count}</code> finding(s)\n"
            f"• critical: <code>{sev.get('critical', 0)}</code>\n"
            f"• high:     <code>{sev.get('high', 0)}</code>\n"
            f"• medium:   <code>{sev.get('medium', 0)}</code>\n"
            f"• low:      <code>{sev.get('low', 0)}</code>\n"
            f"• info:     <code>{sev.get('info', 0)}</code>"
        )
    elif stage == "content_discovery":
        js = extra.get("js_urls", 0)
        msg = (
            f"🕷️ <b>content_discovery</b> finished — <code>{count}</code> URL(s)\n"
            f"• JS files: <code>{js}</code>"
        )
    else:
        msg = f"✅ <b>{_h(stage)}</b> finished — <code>{count}</code> result(s)"

    return _post(cfg["bot_token"], cfg["chat_id"], msg)


def rate_limit_send(messages: list[str], cfg: Optional[dict], delay: float = 0.5) -> int:
    """Send a batch of messages, respecting Telegram's ~30 msg/sec limit."""
    if not _enabled(cfg):
        return 0
    sent = 0
    for m in messages:
        if _post(cfg["bot_token"], cfg["chat_id"], m):
            sent += 1
        time.sleep(delay)
    return sent
