"""dnsx — stage 2: DNS resolution.

Runs dnsx in JSON mode, parses out (subdomain, ip, asn, cname) and writes
both a flat list and a structured detail file.

After resolving, the host list is **prioritised and capped** so that
downstream stages (httpx_alive, nuclei, dirsearch) get the *interesting*
hosts first — not the bot/push/sandbox noise that cert-transparency
logs inflate the count with. See ``prioritize_subdomains`` in
``modules/utils.py`` for the scoring rules.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import console, layout, runner
from .utils import (
    load_json,
    make_result,
    prioritize_subdomains,
    write_json,
    write_lines,
)


def _outputs_exist(out_dir: Path) -> bool:
    r = layout.path(out_dir, "resolved.txt")
    j = layout.path(out_dir, "resolved_detail.json")
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
    layout.ensure_tree(output_dir)
    resolved_txt = layout.path(output_dir, "resolved.txt")
    detail_json = layout.path(output_dir, "resolved_detail.json")

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
        stage=stage, output_dir=output_dir, timeout=timeout, capture_stdout=False,
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

    # ------------------------------------------------------------------
    # Prioritise + cap before writing the flat host list.
    # Without this, ``apple.com`` style cert-transparency dumps (45k+
    # hosts, mostly applebot/courier.push/sandbox noise) feed the full
    # list into httpx_alive, which then blows its timeout and never
    # writes ``alive.txt`` — every downstream stage skips with
    # "no alive hosts". Cap defaults to 5000 (configurable via
    # ``dnsx.max_resolved``); the FULL list is preserved in the
    # structured detail file for reference.
    # ------------------------------------------------------------------
    dnsx_cfg = cfg.get("dnsx", {}) if isinstance(cfg, dict) else {}
    max_resolved = int(dnsx_cfg.get("max_resolved", 10000))
    full_hosts = [d["subdomain"] for d in detail]
    keep_hosts = prioritize_subdomains(full_hosts, max_count=max_resolved)

    write_json(detail_json, detail, compact=True)
    write_lines(resolved_txt, keep_hosts)

    # Cắt cụt ở đây là quyết định LẶNG LẼ nhất trong cả pipeline: mọi stage
    # sau chỉ nhìn thấy ``resolved.txt`` nên không cách nào biết nó là bản
    # rút gọn, và stage vẫn báo "success". Với một target 10k+ host thì
    # ``max_resolved`` mới là thứ quyết định coverage, không phải ngân sách
    # của nuclei — nên nó phải hiện lên console chứ không chỉ nằm trong
    # stages.json.
    dropped = len(full_hosts) - len(keep_hosts)
    extra = {
        "kept_for_downstream": len(keep_hosts),  # prioritised count
        "total_resolved": len(detail),
        "max_resolved": max_resolved,
    }
    if dropped > 0:
        extra["truncated"] = dropped
        print(console.phase_warn_line(
            f"[{stage}] cắt cụt: {len(full_hosts)} host resolve được → giữ "
            f"{len(keep_hosts)} (dnsx.max_resolved={max_resolved}), bỏ "
            f"{dropped}. Mọi stage sau chỉ thấy phần giữ lại; "
            f"danh sách đầy đủ ở {detail_json.name}."))

    return make_result(
        stage, "success", input_path=subdomains_file,
        outputs=[resolved_txt, detail_json],
        count=len(detail),                       # raw resolved count
        extra=extra,
    )
