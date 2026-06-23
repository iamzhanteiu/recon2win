"""dnsx — stage 2: DNS resolution.

Runs dnsx in JSON mode, parses out (subdomain, ip, asn, cname) and writes
both a flat list and a structured detail file.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import runner
from .utils import (
    load_json,
    make_result,
    read_lines,
    write_json,
    write_lines,
)


def _outputs_exist(out_dir: Path) -> bool:
    r = out_dir / "processed" / "resolved.txt"
    j = out_dir / "processed" / "resolved_detail.json"
    return r.exists() and r.stat().st_size > 0 and j.exists()


def resolve(
    subdomains_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    stage = "dnsx"
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    resolved_txt = proc / "resolved.txt"
    detail_json = proc / "resolved_detail.json"

    if resume and _outputs_exist(output_dir):
        existing = load_json(detail_json) or []
        return make_result(
            stage, "success", input_path=subdomains_file,
            outputs=[resolved_txt, detail_json], count=len(existing),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=subdomains_file,
            outputs=[resolved_txt, detail_json], count=0, error="dry-run",
        )

    if not runner.tool_available("dnsx"):
        return make_result(
            stage, "failed", input_path=subdomains_file,
            outputs=[resolved_txt, detail_json], count=0,
            error="dnsx binary not found (required stage)",
        )

    threads = int(cfg.get("dnsx", {}).get("threads", 100))
    retries = int(cfg.get("dnsx", {}).get("retries", 3))
    timeout = int(cfg.get("dnsx", {}).get("timeout", 600))

    r = runner.run(
        [
            "dnsx", "-l", str(subdomains_file),
            "-json", "-resp", "-silent",
            "-retry", str(retries),
            "-t", str(threads),
            "-o", str(detail_json),
        ],
        stage=stage, output_dir=output_dir, timeout=timeout,
    )
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=subdomains_file,
            outputs=[resolved_txt, detail_json], count=0,
            error=(r["stderr"] or "")[:300],
        )

    # Parse JSON-lines output from dnsx (or fall back to JSON array)
    raw = detail_json.read_text(errors="ignore") if detail_json.exists() else ""
    rows: list[dict[str, Any]] = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(json.loads(ln))
        except json.JSONDecodeError:
            continue

    # de-dup by host, keep first occurrence
    seen: set[str] = set()
    detail: list[dict[str, Any]] = []
    for row in rows:
        host = (row.get("host") or "").lower().rstrip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        detail.append({
            "subdomain": host,
            "ip": ",".join(row.get("a", []) or []) or None,
            "aaaa": ",".join(row.get("aaaa", []) or []) or None,
            "cname": ",".join(row.get("cname", []) or []) or None,
            "asn": row.get("asn", {}) or {},
            "resolver": row.get("resolver", [None])[0] if row.get("resolver") else None,
        })
    write_json(detail_json, detail)
    write_lines(resolved_txt, [d["subdomain"] for d in detail])

    return make_result(
        stage, "success", input_path=subdomains_file,
        outputs=[resolved_txt, detail_json], count=len(detail),
    )
