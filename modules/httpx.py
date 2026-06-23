"""httpx — stage 3 (alive check) and stage 6.1 (URL check).

httpx is called twice for two different jobs:
  1. alive-check subdomains → alive.txt / alive_detail.{json,csv}
  2. check the merged URL list → alive_urls.txt / alive_urls_detail.json
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from . import runner
from .utils import (
    load_json,
    make_result,
    read_lines,
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


def _write_csv(csv_path: Path, rows: Iterable[dict]) -> None:
    rows = list(rows)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        csv_path.write_text("", encoding="utf-8")
        return
    # fixed column order so the CSV is consumable downstream
    cols = ["url", "input", "status_code", "title", "content_length",
            "content_type", "webserver", "tech", "host"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


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
    detail_csv = proc / "alive_detail.csv"

    if resume and alive_txt.exists() and alive_txt.stat().st_size > 0:
        existing = load_json(detail_json) or []
        return make_result(
            stage, "success", input_path=hosts_file,
            outputs=[alive_txt, detail_json, detail_csv], count=len(existing),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=hosts_file,
            outputs=[alive_txt, detail_json, detail_csv], count=0, error="dry-run",
        )

    if not runner.tool_available("httpx"):
        return make_result(
            stage, "failed", input_path=hosts_file,
            outputs=[alive_txt, detail_json, detail_csv], count=0,
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
            outputs=[alive_txt, detail_json, detail_csv], count=0,
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
    _write_csv(detail_csv, dedup)
    write_lines(alive_txt, [r["url"] for r in dedup if r.get("url")])

    return make_result(
        stage, "success", input_path=hosts_file,
        outputs=[alive_txt, detail_json, detail_csv], count=len(dedup),
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
