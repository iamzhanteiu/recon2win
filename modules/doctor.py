"""doctor — preflight check for tools, API keys and wordlists.

The acronis.com run burned hours before it surfaced that chaos, waymore,
xnlinkfinder, arjun and gau had all silently skipped (wrong binary name /
PATH). ``--doctor`` reports what's installed, what's configured and what
will be skipped BEFORE a scan starts, so you fix it up front instead of
reading logs afterwards.

Exit code: 1 if any REQUIRED tool is missing (the scan would be crippled),
else 0. Missing optional tools / keys are warnings, not failures.
"""
from __future__ import annotations

import os
from pathlib import Path

from . import console
from .runner import which


# (binary, required?, what it powers / what skips without it)
# ``required`` = the pipeline is crippled without it; everything else just
# skips its own stage. chaos-client is the Homebrew alias for chaos.
_TOOLS: list[tuple[str, bool, str]] = [
    ("subfinder",    True,  "subdomain enumeration"),
    ("dnsx",         True,  "DNS resolution"),
    ("httpx",        True,  "alive check — every later stage needs it"),
    ("katana",       True,  "content discovery (crawl)"),
    ("nuclei",       True,  "vulnerability scanning"),
    ("amass",        False, "extra passive subdomains"),
    ("chaos",        False, "chaos subdomains (also needs PDCP_API_KEY)"),
    ("urlfinder",    False, "passive URL discovery"),
    ("gau",          False, "archived URLs (wayback/commoncrawl)"),
    ("waymore",      False, "archived URLs + JS"),
    ("dirsearch",    False, "directory/file brute-force"),
    ("ffuf",         False, "directory fuzzing"),
    ("xnlinkfinder", False, "endpoint mining from JS"),
    ("jsluice",      False, "AST JS analysis + secrets"),
    ("arjun",        False, "parameter discovery"),
]


# Tools installable under more than one binary name — satisfied if ANY
# alias resolves (subdomain.py already tries both chaos names).
_ALIASES: dict[str, list[str]] = {"chaos": ["chaos", "chaos-client"]}


def _resolve_tool(name: str) -> str | None:
    for candidate in _ALIASES.get(name, [name]):
        path = which(candidate)
        if path:
            return path
    return None


def _check_tools() -> tuple[list, list]:
    """Return (rows, missing_required) where rows are
    (name, ok, required, path_or_note)."""
    rows = []
    missing_required = []
    for name, required, note in _TOOLS:
        path = _resolve_tool(name)
        ok = path is not None
        if not ok and required:
            missing_required.append(name)
        rows.append((name, ok, required, path or note))
    return rows, missing_required


def _check_keys(cfg: dict) -> list:
    """Return rows (label, configured, env_hint, note). ``cfg`` is already
    env-resolved, so a set value means it resolved from env or config."""
    sub = cfg.get("subdomain", {}) if isinstance(cfg, dict) else {}
    tg = cfg.get("telegram", {}) if isinstance(cfg, dict) else {}
    h1 = cfg.get("hackerone", {}) if isinstance(cfg, dict) else {}

    def _set(v) -> bool:
        return bool(str(v or "").strip())

    return [
        ("chaos API key", _set(sub.get("chaos_api_key")), "$PDCP_API_KEY",
         "chaos subdomains skip without it"),
        ("Telegram", _set(tg.get("bot_token")) and _set(tg.get("chat_id")),
         "$TELEGRAM_BOT_TOKEN + $TELEGRAM_CHAT_ID",
         "notifications off without it" + ("" if tg.get("enabled") else " (also enabled:false)")),
        ("HackerOne API", _set(h1.get("api_username")) and _set(h1.get("api_token")),
         "$H1_API_USERNAME + $H1_API_TOKEN",
         "--h1-list / --h1-program unavailable without it"),
    ]


def _resolve_wordlist(p: str) -> Path:
    return Path(os.path.expanduser(str(p)))


def _check_wordlists(cfg: dict) -> list:
    """Return rows (path, exists) for every configured ffuf/dirsearch wordlist."""
    rows = []
    seen = set()
    for stage in ("ffuf", "dirsearch"):
        s = cfg.get(stage, {}) if isinstance(cfg, dict) else {}
        for wl in s.get("wordlists", []) or []:
            if wl in seen:
                continue
            seen.add(wl)
            p = _resolve_wordlist(wl)
            rows.append((str(wl), p.exists()))
    return rows


def run(cfg: dict, *, added_paths: list[str] | None = None) -> int:
    """Print the preflight report and return an exit code (1 if a required
    tool is missing, else 0)."""
    tool_rows, missing_required = _check_tools()
    key_rows = _check_keys(cfg)
    wl_rows = _check_wordlists(cfg)

    ok = lambda b: console.c("✓", "green") if b else console.c("✗", "red")
    warn = console.c("⚠", "yellow")

    print(console.phase_header("doctor — preflight check"))

    if added_paths:
        print(console.phase_info_line(
            "PATH augmented with: " + ", ".join(added_paths)))

    # Tools
    print(console.c("\nTools", "bright_white"))
    for name, is_ok, required, detail in tool_rows:
        if is_ok:
            mark = ok(True)
        else:
            mark = ok(False) if required else warn
        tag = console.c("required", "red") if required else console.c("optional", "white")
        print(f"  {mark} {name:<14} [{tag}]  {detail}")

    # API keys
    print(console.c("\nAPI keys / secrets", "bright_white"))
    for label, configured, env_hint, note in key_rows:
        mark = ok(True) if configured else warn
        state = "set" if configured else f"unset — {note}"
        print(f"  {mark} {label:<14} {state}")
        if not configured:
            print(f"      set via {env_hint}")

    # Wordlists
    print(console.c("\nWordlists", "bright_white"))
    if not wl_rows:
        print("  (none configured)")
    for path, exists in wl_rows:
        print(f"  {ok(exists)} {path}")

    # Summary
    missing_opt = [n for n, is_ok, req, _ in tool_rows if not is_ok and not req]
    print(console.c("\nSummary", "bright_white"))
    if missing_required:
        print(f"  {ok(False)} required tools missing: {', '.join(missing_required)} "
              f"— the scan will be crippled; install them first.")
    else:
        print(f"  {ok(True)} all required tools present.")
    if missing_opt:
        print(f"  {warn} optional tools missing (their stages will skip): "
              f"{', '.join(missing_opt)}")
    missing_wl = [p for p, e in wl_rows if not e]
    if missing_wl:
        print(f"  {warn} wordlists missing: {', '.join(missing_wl)}")

    return 1 if missing_required else 0


def summarise(cfg: dict) -> dict:
    """Non-printing variant for an auto-preflight line: returns counts."""
    tool_rows, missing_required = _check_tools()
    missing_opt = [n for n, is_ok, req, _ in tool_rows if not is_ok and not req]
    return {
        "missing_required": missing_required,
        "missing_optional": missing_opt,
        "wordlists_missing": [p for p, e in _check_wordlists(cfg) if not e],
    }
