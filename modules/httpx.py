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
    write_json,
    write_lines,
)


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

    cmd = [
        "httpx", "-l", str(urls_file),
        "-json", "-silent",
        "-threads", str(threads),
        "-timeout", "10",
        "-retries", "2",
        "-o", str(detail_json),
    ]
    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=urls_file,
            outputs=[alive_txt, detail_json], count=0,
            error=(r["stderr"] or "")[:300],
        )

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

    return make_result(
        stage, "success", input_path=urls_file,
        outputs=[alive_txt, detail_json], count=len(dedup),
    )
