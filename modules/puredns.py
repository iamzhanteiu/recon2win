"""puredns — stage 1.5: validate subdomains via brute-force + trickest resolvers.

puredns is the missing link between passive enumeration (subfinder /
amass / chaos) and active resolution (dnsx):

  * subfinder/amass pull ~45k candidates from certificate-transparency
    logs. Most are noise (``applebot.apple.com``, ``sandbox.*``,
    wildcard subdomains that don't actually resolve).
  * puredns queries each candidate against a curated list of public
    resolvers — the **trickest** list at
    https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt.
    Hosts that don't resolve are dropped. Hosts that DO resolve but
    match a wildcard pattern are also dropped (puredns detects
    wildcards automatically).
  * The output is a deduplicated, validated, wildcard-free list of
    subdomains. ``dnsx`` then takes this and adds the structured
    per-record data (A/AAAA/CNAME/ASN) on the next stage.

Why a separate module (not bolted onto dnsx): puredns has its own
flags (``--resolvers``, ``--wildcard-tests``, ``--rate-limit``)
and a different runtime profile (it brute-forces common subdomains
too if you pass a wordlist). Keeping it separate means dnsx stays
simple and puredns failures don't poison the dnsx stage.
"""
from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Iterable

from . import runner
from .utils import (
    make_result,
    read_lines,
    write_lines,
)


# URL of the trickest curated resolver list — public, no auth, ~5k
# resolvers (Cloudflare, Quad9, AdGuard, custom public ones, etc.).
# We pull a snapshot per scan so the list stays current — they're
# rotated regularly.
TRICKEST_RESOLVERS_URL = (
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
)


def fetch_trickest_resolvers(cache_path: Path) -> Path:
    """Download the trickest resolver list to *cache_path*.

    Falls back to the cached file if the network is unavailable —
    puredns without resolvers is useless, so we'd rather use a
    slightly-stale list than fail the whole stage.

    Returns the path to the resolvers file (always non-empty on
    success).
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(TRICKEST_RESOLVERS_URL, timeout=15) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
        # Strip comments and blanks — puredns doesn't handle those.
        clean = "\n".join(
            ln.strip() for ln in data.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ) + "\n"
        cache_path.write_text(clean, encoding="utf-8")
    except (OSError, urllib.error.URLError, TimeoutError):
        # Network failure — use cache if we have one.
        if not cache_path.exists() or cache_path.stat().st_size == 0:
            raise
    return cache_path


def collect(
    domain: str,
    subdomains_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    """Run puredns to validate the candidate subdomain list.

    Input  : ``subdomains_file`` — flat list of candidates from
             subfinder/amass/chaos.
    Output : ``raw/puredns/valid.txt`` — deduplicated, wildcard-free
             list of subdomains that actually resolve.

    The output is also written to the standard
    ``processed/subdomains.txt`` location so the rest of the
    pipeline (dnsx, httpx_alive, …) sees the FILTERED list — not
    the raw 45k candidate spam.
    """
    stage = "puredns"
    raw = output_dir / "raw"
    proc = output_dir / "processed"
    raw.mkdir(parents=True, exist_ok=True)
    proc.mkdir(parents=True, exist_ok=True)

    raw_out = raw / "puredns" / "valid.txt"
    proc_out = proc / "subdomains.txt"
    resolvers_path = raw / "puredns" / "resolvers.txt"

    if dry_run:
        return make_result(
            stage, "skipped", input_path=subdomains_file,
            outputs=[raw_out, proc_out], count=0, error="dry-run",
        )

    if not runner.tool_available("puredns"):
        return make_result(
            stage, "skipped", input_path=subdomains_file,
            outputs=[raw_out, proc_out], count=0,
            error="puredns binary not found (optional, skipped)",
        )

    if resume and raw_out.exists() and raw_out.stat().st_size > 0:
        # Cached — just re-merge into processed/subdomains.txt.
        valid = read_lines(raw_out)
        write_lines(proc_out, valid)
        return make_result(
            stage, "success", input_path=subdomains_file,
            outputs=[raw_out, proc_out], count=len(valid),
        )

    # Fetch the trickest resolver list (cached on disk for re-runs
    # and offline fallback).
    try:
        resolvers = fetch_trickest_resolvers(resolvers_path)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return make_result(
            stage, "failed", input_path=subdomains_file,
            outputs=[raw_out, proc_out], count=0,
            error=f"could not fetch resolvers: {exc}",
        )

    p_cfg = cfg.get("puredns", {}) if isinstance(cfg, dict) else {}
    rate_limit = int(p_cfg.get("rate_limit", 200))    # queries / sec
    wildcard_tests = int(p_cfg.get("wildcard_tests", 3))  # how many to confirm
    bruteforce = bool(p_cfg.get("bruteforce", False))
    timeout = int(p_cfg.get("timeout", 1800))

    # Build the puredns cmd. ``-r`` accepts a file of public resolvers
    # (one per line). ``-w`` is an OPTIONAL wordlist to brute-force
    # common subdomains — we leave it off by default (the candidate
    # list from subfinder/amass/chaos is already comprehensive).
    cmd = [
        "puredns", "resolve",
        "-d", domain,
        "-r", str(resolvers),
        "-l", str(subdomains_file),
        "--rate-limit", str(rate_limit),
        "-q",
        "--wildcard-tests", str(wildcard_tests),
        "--write", str(raw_out),
    ]
    if bruteforce:
        cmd.extend(["-w", str(puredns_wordlist_path(cfg))])

    r = runner.run(
        cmd, stage=stage, output_dir=output_dir, timeout=timeout,
    )
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=subdomains_file,
            outputs=[raw_out, proc_out], count=0,
            error=(r["stderr"] or "")[:300],
        )

    # puredns writes valid subdomains to --write. Read them back and
    # overwrite the canonical processed/subdomains.txt so downstream
    # stages (dnsx, httpx_alive) see the FILTERED list — not the
    # 45k raw candidates.
    valid = read_lines(raw_out) if raw_out.exists() else []
    write_lines(proc_out, valid)
    return make_result(
        stage, "success", input_path=subdomains_file,
        outputs=[raw_out, proc_out],
        count=len(valid),
        extra={"resolvers_path": str(resolvers),
               "input_count": _count_lines(subdomains_file)},
    )


def puredns_wordlist_path(cfg: dict) -> Path:
    """Return the path to the puredns wordlist (used for bruteforce).

    Default to a SecLists path if configured, otherwise the standard
    puredns-bundled wordlist. Operators who don't run --bruteforce
    don't need this — we still resolve it to keep the cmd shape
    stable, but puredns won't read it without ``-w``.
    """
    p_cfg = cfg.get("puredns", {}) if isinstance(cfg, dict) else {}
    explicit = p_cfg.get("wordlist")
    if explicit:
        return Path(explicit)
    return Path("wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt")


def _count_lines(path: Path) -> int:
    """Cheap line counter — used to surface how many candidates
    puredns filtered down to. Returns 0 on any I/O error."""
    try:
        with path.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0