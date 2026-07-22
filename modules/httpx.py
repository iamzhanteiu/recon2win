"""httpx — stage 3 (alive check) and stage 6.1 (URL check).

httpx is called twice for two different jobs:
  1. alive-check subdomains → alive.txt + alive_detail.json
  2. check the merged URL list → alive_urls.txt + alive_urls_detail.json

The earlier ``alive_detail.csv`` was dropped in v2 — JSON is the
canonical machine-readable form and any downstream tool that wants CSV
can convert from JSON trivially.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import runner
from .utils import (
    load_json,
    make_result,
    raw_dir,
    read_lines,
    write_json,
    write_lines,
)


# High-value markers used to prioritise which URLs survive the
# ``httpx.max_url_check`` cap. Parameterised + auth/api paths first so a
# capped run still probes the URLs most likely to yield a finding.
_URL_HINTS = (
    "?", "id=", "token=", "key=", "/api/", "/v1/", "/v2/", "/v3/",
    "/graphql", "/admin", "/login", "/account", "/user", "/auth",
    "/oauth", "/upload", "/download", "/file", "/redirect",
)


def _score_url(url: str) -> int:
    """Higher = keep first when capping. Ties break on shorter URL."""
    lo = url.lower()
    score = sum(1 for h in _URL_HINTS if h in lo)
    if "web.archive.org" in lo or "webcache.googleusercontent" in lo:
        score -= 3
    return score


def _cap_urls(urls_file: Path, output_dir: Path, max_urls: int) -> tuple[Path, int, int]:
    """Cap the URL list to ``max_urls``, keeping the highest-value URLs.

    Returns ``(file_to_scan, total, kept)``. When the list already fits
    (or ``max_urls <= 0``) the original file is returned untouched so the
    common small-target case stays a no-op.
    """
    urls = read_lines(urls_file)
    total = len(urls)
    if max_urls <= 0 or total <= max_urls:
        return urls_file, total, total
    ranked = sorted(urls, key=lambda u: (-_score_url(u), len(u), u))[:max_urls]
    subset = raw_dir(output_dir, "httpx_urls") / "input_subset.txt"
    write_lines(subset, ranked)
    return subset, total, len(ranked)


def _write_alive_from_detail(detail_json: Path, alive_txt: Path) -> int:
    """Parse the httpx JSONL output and write the de-duped alive URL list.

    Shared by the success and salvaged-timeout paths so a partial run
    still leaves ``alive_urls.txt`` populated for the downstream
    nuclei_endpoints stage.
    """
    rows = _parse_httpx_jsonl(detail_json)
    seen: set[str] = set()
    dedup: list[dict] = []
    for row in rows:
        u = row.get("url", "")
        if not u or u in seen:
            continue
        seen.add(u)
        dedup.append(row)
    write_json(detail_json, dedup)
    write_lines(alive_txt, [r["url"] for r in dedup if r.get("url")])
    return len(dedup)


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _parse_httpx_jsonl(jsonl_path: Path) -> list[dict]:
    if not jsonl_path.exists():
        return []
    out: list[dict] = []
    for ln in jsonl_path.read_text(errors="ignore").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


# ----------------------------------------------------------------------
# stage 3 — alive check
# ----------------------------------------------------------------------
def alive_check(
    hosts_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    stage = "httpx_alive"
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    alive_txt = proc / "alive.txt"
    detail_json = proc / "alive_detail.json"

    if resume and alive_txt.exists() and alive_txt.stat().st_size > 0:
        existing = load_json(detail_json) or []
        return make_result(
            stage, "success", input_path=hosts_file,
            outputs=[alive_txt, detail_json], count=len(existing),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=hosts_file,
            outputs=[alive_txt, detail_json], count=0, error="dry-run",
        )

    if not runner.tool_available("httpx"):
        return make_result(
            stage, "failed", input_path=hosts_file,
            outputs=[alive_txt, detail_json], count=0,
            error="httpx binary not found (required stage)",
        )

    threads = int(cfg.get("httpx", {}).get("threads", 50))
    timeout = int(cfg.get("httpx", {}).get("timeout", 600))
    follow = bool(cfg.get("httpx", {}).get("follow_redirects", True))

    cmd = [
        "httpx", "-l", str(hosts_file),
        "-json", "-silent",
        "-threads", str(threads),
        "-timeout", "10",
        "-retries", "2",
        "-follow-redirects" if follow else "-no-follow-redirects",
        "-o", str(detail_json),
    ]
    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=hosts_file,
            outputs=[alive_txt, detail_json], count=0,
            error=(r["stderr"] or "")[:300],
        )

    rows = _parse_httpx_jsonl(detail_json)
    # de-dup by URL
    seen: set[str] = set()
    dedup: list[dict] = []
    for row in rows:
        u = row.get("url", "")
        if not u or u in seen:
            continue
        seen.add(u)
        dedup.append(row)
    write_json(detail_json, dedup)
    write_lines(alive_txt, [r["url"] for r in dedup if r.get("url")])

    return make_result(
        stage, "success", input_path=hosts_file,
        outputs=[alive_txt, detail_json], count=len(dedup),
    )


# ----------------------------------------------------------------------
# stage 6.1 — URL check
# ----------------------------------------------------------------------
def check_urls(
    urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    stage = "httpx_urls"
    proc = output_dir / "processed"
    alive_txt = proc / "alive_urls.txt"
    detail_json = proc / "alive_urls_detail.json"

    if resume and alive_txt.exists() and alive_txt.stat().st_size > 0:
        existing = load_json(detail_json) or []
        return make_result(
            stage, "success", input_path=urls_file,
            outputs=[alive_txt, detail_json], count=len(existing),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=urls_file,
            outputs=[alive_txt, detail_json], count=0, error="dry-run",
        )

    if not runner.tool_available("httpx"):
        return make_result(
            stage, "failed", input_path=urls_file,
            outputs=[alive_txt, detail_json], count=0,
            error="httpx binary not found (required stage)",
        )

    threads = int(cfg.get("httpx", {}).get("threads", 50))
    timeout = int(cfg.get("httpx", {}).get("timeout", 600))
    max_url_check = int(cfg.get("httpx", {}).get("max_url_check", 60000))

    scan_file, total, kept = _cap_urls(urls_file, output_dir, max_url_check)

    cmd = [
        "httpx", "-l", str(scan_file),
        "-json", "-silent",
        "-threads", str(threads),
        "-timeout", "10",
        "-retries", "2",
        "-o", str(detail_json),
    ]
    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)
    # A hard failure (binary error, not a timeout) leaves nothing to
    # salvage. A timeout is different: httpx streams results to ``-o`` as
    # it goes, so the partial JSONL on disk is real, live-verified data.
    # Salvaging it keeps alive_urls.txt populated so nuclei_endpoints
    # isn't starved — we just flag the stage so the operator knows the
    # probe didn't finish the full list.
    timed_out = r.get("timed_out", False)
    if not r["success"] and not r["missing_binary"] and not timed_out:
        return make_result(
            stage, "failed", input_path=urls_file,
            outputs=[alive_txt, detail_json], count=0,
            error=(r["stderr"] or "")[:300],
        )

    count = _write_alive_from_detail(detail_json, alive_txt)
    extra = {"input_urls": total, "probed_urls": kept}

    if timed_out:
        return make_result(
            stage, "failed", input_path=urls_file,
            outputs=[alive_txt, detail_json], count=count,
            error=(f"timeout after {timeout}s — salvaged {count} alive URLs "
                   f"from partial output ({kept}/{total} probed)"),
            extra=extra,
        )

    return make_result(
        stage, "success", input_path=urls_file,
        outputs=[alive_txt, detail_json], count=count,
        extra=extra,
    )
