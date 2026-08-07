"""httpx — stage 3 (alive check) and stage 6.1 (URL check).

httpx is called twice for two different jobs:
  1. alive-check subdomains → alive.txt + alive_detail.json + alive_table.txt
  2. check the merged URL list → alive_urls.txt + alive_urls_detail.json
     + alive_urls_table.txt

Each stage also writes a ``*_table.txt`` companion — a human-readable
``status | length | content-type | url`` view of the same rows for quick
eyeballing/grep. The ``*.txt`` list stays URL-only for downstream stages.

The earlier ``alive_detail.csv`` was dropped in v2 — JSON is the
canonical machine-readable form and any downstream tool that wants CSV
can convert from JSON trivially.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import console, layout, runner
from .sensitive_ext import is_static_asset
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


def _cap_urls(urls_file: Path, output_dir: Path, max_urls: int,
              *, drop_static: bool = False) -> tuple[Path, int, int, int]:
    """Prepare the URL list to probe: optionally drop static assets, then
    cap to ``max_urls`` keeping the highest-value URLs.

    ``drop_static`` removes image/font/css/media/source-map URLs BEFORE the
    cap — so the cap budget is spent on real endpoints, not dead-weight
    assets that were pushing genuine URLs out of the 60k window. ``.js`` is
    never dropped (JS analysis needs it).

    Returns ``(file_to_scan, total, kept, dropped_static)``. When nothing
    changes (no static dropped and list fits) the original file is returned
    untouched so the common small-target case stays a no-op.
    """
    urls = read_lines(urls_file)
    total = len(urls)

    dropped_static = 0
    if drop_static:
        kept_urls = [u for u in urls if not is_static_asset(u)]
        dropped_static = total - len(kept_urls)
        urls = kept_urls

    if max_urls > 0 and len(urls) > max_urls:
        urls = sorted(urls, key=lambda u: (-_score_url(u), len(u), u))[:max_urls]

    # No-op only when nothing was removed at all.
    if dropped_static == 0 and len(urls) == total:
        return urls_file, total, total, 0

    subset = raw_dir(output_dir, "httpx_urls") / "input_subset.txt"
    write_lines(subset, urls)
    return subset, total, len(urls), dropped_static


def _write_alive_from_detail(detail_json: Path, alive_txt: Path) -> int:
    """Parse the httpx JSONL output and write the de-duped alive URL list.

    Shared by the success and salvaged-timeout paths so a partial run
    still leaves ``alive_urls.txt`` populated for the report and the
    priority ranking downstream.
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
    write_json(detail_json, dedup, compact=True)
    write_lines(alive_txt, [r["url"] for r in dedup if r.get("url")])
    _write_alive_table(dedup, _table_path(alive_txt))
    return len(dedup)


def _table_path(alive_txt: Path) -> Path:
    """``alive_urls.txt`` → ``alive_urls_table.txt`` (companion table)."""
    return alive_txt.with_name(alive_txt.stem + "_table.txt")


def _write_alive_table(rows: list[dict], table_path: Path) -> int:
    """Write a human-readable ``status | length | content-type | url`` table
    from the httpx detail rows — the quick eyeball view of the probed surface
    (spot the odd-sized 200, the lone application/json API, the 401 admin).

    The plain ``alive*.txt`` stays URL-only for downstream consumers; this is
    a companion view, greppable by column (``awk '$1==200'`` / ``grep json``).
    Sorted by (status, -length) so unusual sizes within a status class
    cluster together. Written directly (not via ``write_lines``, which strips
    leading pad and would wreck the column alignment).
    """
    def _int(v) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    entries: list[tuple[int, int, str, str]] = []
    for r in rows:
        url = r.get("url") or ""
        if not url:
            continue
        ctype = (r.get("content_type") or "-").split(";")[0].strip() or "-"
        entries.append((_int(r.get("status_code")),
                        _int(r.get("content_length")), ctype, url))
    entries.sort(key=lambda e: (e[0], -e[1]))

    lines = [f"{'ST':>3}  {'LENGTH':>9}  {'CONTENT-TYPE':<24}  URL"]
    lines += [f"{st:>3}  {ln:>9}  {ct[:24]:<24}  {url}"
              for st, ln, ct, url in entries]
    table_path.parent.mkdir(parents=True, exist_ok=True)
    table_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(entries)


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
    layout.ensure_tree(output_dir)
    alive_txt = layout.path(output_dir, "alive.txt")
    detail_json = layout.path(output_dir, "alive_detail.json")

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
        # -td: passive tech-detection (Wappalyzer-style fingerprint of the
        # SAME response, no extra request) — feeds fuzz_depth's tech-based
        # tiering. Same cost profile as -cdn, already on by default.
        "-td",
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
    write_json(detail_json, dedup, compact=True)
    write_lines(alive_txt, [r["url"] for r in dedup if r.get("url")])
    table_txt = _table_path(alive_txt)
    _write_alive_table(dedup, table_txt)

    return make_result(
        stage, "success", input_path=hosts_file,
        outputs=[alive_txt, detail_json, table_txt], count=len(dedup),
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
    alive_txt = layout.path(output_dir, "alive_urls.txt")
    detail_json = layout.path(output_dir, "alive_urls_detail.json")

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
    drop_static = bool(cfg.get("httpx", {}).get("drop_static", True))

    scan_file, total, kept, n_static = _cap_urls(
        urls_file, output_dir, max_url_check, drop_static=drop_static)
    if n_static:
        print(console.phase_info_line(
            f"[{stage}] dropped {n_static} static asset URL(s) "
            f"(jpg/png/css/woff/…) before probing"))

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
    # Salvaging it keeps alive_urls.txt populated so the downstream
    # ranking isn't starved — we flag the stage so the operator knows the
    # probe didn't finish the full list.
    timed_out = r.get("timed_out", False)
    if not r["success"] and not r["missing_binary"] and not timed_out:
        return make_result(
            stage, "failed", input_path=urls_file,
            outputs=[alive_txt, detail_json], count=0,
            error=(r["stderr"] or "")[:300],
        )

    count = _write_alive_from_detail(detail_json, alive_txt)
    table_txt = _table_path(alive_txt)
    extra = {"input_urls": total, "probed_urls": kept,
             "static_dropped": n_static}

    if timed_out:
        return make_result(
            stage, "failed", input_path=urls_file,
            outputs=[alive_txt, detail_json, table_txt], count=count,
            error=(f"timeout after {timeout}s — salvaged {count} alive URLs "
                   f"from partial output ({kept}/{total} probed)"),
            extra=extra,
        )

    return make_result(
        stage, "success", input_path=urls_file,
        outputs=[alive_txt, detail_json, table_txt], count=count,
        extra=extra,
    )


# ----------------------------------------------------------------------
# stage 3.post — screenshots (optional, off by default: needs a headless
# browser). asm_report.py's own "Coverage Gaps" section names this as a
# known-missing capability with the exact fix — httpx already ships it.
#
# Visual triage beats reading a status-code table: a 200 on /admin could be
# a real login form or a landing page that catch-alls every path, and the
# only way to tell without opening a browser tab per host is a screenshot.
# ----------------------------------------------------------------------
def _outputs_exist(index_json: Path) -> bool:
    return index_json.exists() and index_json.stat().st_size > 0


def capture_screenshots(
    hosts_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    """Screenshot every alive host with ``httpx -screenshot``.

    Off by default (``httpx.screenshot.enabled: false``) — it needs Chrome
    installed, is far slower per-host than a plain probe, and most CI/VPS
    boxes don't have a browser sitting around. When enabled, caps to
    ``max_hosts`` (screenshotting a 5,000-host run would dwarf every other
    stage) and never treats a missing browser as a hard failure — this is
    coverage on top of the run, not something downstream depends on.

    The index only ever records a ``screenshot_path`` when httpx itself
    reported one in its JSON (recent versions add ``screenshot_path`` per
    row when ``-screenshot`` + ``-srd`` are combined). Older httpx builds
    don't emit that field — rather than guess a filename convention that
    may not match, those runs still get ``screenshots_written`` (a real
    file count from the store directory) and the directory itself, with
    ``screenshot_path: null`` per row so nothing is fabricated.
    """
    stage = "httpx_screenshot"
    layout.ensure_tree(output_dir)
    index_json = layout.path(output_dir, "screenshots_index.json")
    shot_dir = raw_dir(output_dir, "httpx_screenshot") / "screenshots"
    outputs = [index_json]

    s_cfg = ((cfg.get("httpx") or {}).get("screenshot") or {})

    if not s_cfg.get("enabled", False):
        return make_result(stage, "skipped", input_path=hosts_file,
                           outputs=outputs, count=0,
                           error="disabled in config (httpx.screenshot.enabled)")
    if resume and _outputs_exist(index_json):
        existing = load_json(index_json) or []
        return make_result(stage, "success", input_path=hosts_file,
                           outputs=outputs, count=len(existing))
    if dry_run:
        return make_result(stage, "skipped", input_path=hosts_file,
                           outputs=outputs, count=0, error="dry-run")
    if not runner.tool_available("httpx"):
        return make_result(stage, "skipped", input_path=hosts_file,
                           outputs=outputs, count=0,
                           error="httpx binary not found")

    hosts = read_lines(hosts_file)
    max_hosts = int(s_cfg.get("max_hosts", 200) or 0)
    capped = 0
    if max_hosts and len(hosts) > max_hosts:
        capped = len(hosts) - max_hosts
        hosts = hosts[:max_hosts]
    if not hosts:
        return make_result(stage, "success", input_path=hosts_file,
                           outputs=outputs, count=0,
                           error="no alive hosts to screenshot")

    scan_file = raw_dir(output_dir, "httpx_screenshot") / "hosts_subset.txt"
    write_lines(scan_file, hosts)
    detail_jsonl = raw_dir(output_dir, "httpx_screenshot") / "detail.jsonl"
    shot_dir.mkdir(parents=True, exist_ok=True)

    timeout = int(s_cfg.get("timeout", 1800))
    per_host_timeout = int(s_cfg.get("screenshot_timeout", 10))
    cmd = [
        "httpx", "-l", str(scan_file),
        "-json", "-silent",
        "-screenshot", "-srd", str(shot_dir),
        "-screenshot-timeout", str(per_host_timeout),
        "-threads", str(int(s_cfg.get("threads", 10))),
        "-timeout", "10", "-retries", "1",
        "-o", str(detail_jsonl),
    ]
    if s_cfg.get("system_chrome", True):
        cmd.append("-system-chrome")
    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)

    rows = _parse_httpx_jsonl(detail_jsonl)
    written = sum(1 for _ in shot_dir.rglob("*.png")) if shot_dir.exists() else 0

    if not rows and not written:
        # A hard failure (no chrome, no network) is coverage lost, not a
        # pipeline blocker — every other stage's output stands on its own.
        err = (r.get("stderr") or "")[:300] or "no screenshots captured"
        return make_result(stage, "skipped", input_path=hosts_file,
                           outputs=outputs, count=0, error=err,
                           extra={"hosts_capped": capped})

    index: list[dict] = []
    for row in rows:
        shot = row.get("screenshot_path")
        index.append({
            "url": row.get("url") or "",
            "status_code": row.get("status_code"),
            "title": row.get("title") or "",
            "screenshot_path": (str(shot_dir / shot) if shot else None),
        })
    write_json(index_json, index)

    print(console.phase_info_line(
        f"[{stage}] {written} screenshot(s) written → "
        f"{shot_dir.relative_to(output_dir)}/"))

    return make_result(
        stage, "success", input_path=hosts_file,
        outputs=[index_json], count=len(index),
        extra={"hosts_capped": capped, "screenshots_written": written,
               "screenshot_dir": str(shot_dir)},
    )
