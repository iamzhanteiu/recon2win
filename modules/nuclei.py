"""nuclei — stages 4.5 and 8.

Used twice:
  1. default_scan(alive_file)            — full template set against alive hosts
  2. dynamic_scan(parameterized_urls_file) — focused tags on parameterised URLs

Findings are persisted as both plain text (one matched URL per line) and JSON.
High/Critical findings fire an immediate Telegram alert (if configured).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from . import console, fuzz_targets, runner
from .utils import (
    findings_dir,
    load_json,
    make_result,
    raw_dir,
    read_lines,
    write_json,
    write_lines,
)
from .telegram import notify_finding, notify_stage_result


SEV_ORDER = ["info", "low", "medium", "high", "critical"]

# Don't start a batch with less than this left of the stage budget. nuclei
# spends ~10-30s loading templates before its first request, so a 30s slice
# buys nothing but a guaranteed timeout and a misleading "batch run" count.
_MIN_BATCH_BUDGET = 60


def update_templates(
    output_dir: Path,
    cfg: dict,
    *,
    skip: bool = False,
    dry_run: bool = False,
) -> dict:
    """Refresh the nuclei template store before scanning.

    Stale templates miss recently-published CVEs — the single biggest
    silent quality drain on a scanner. Runs ``nuclei -update-templates``
    once at the start of a run (fast no-op when already current).

    Opt-out via ``nuclei.update_templates: false`` (e.g. air-gapped hosts
    or when you pin a template version). Skipped on ``--skip-nuclei``,
    ``--dry-run``, missing binary, or when disabled.
    """
    stage = "nuclei_update"
    n_cfg = cfg.get("nuclei") or {}
    if skip:
        return make_result(stage, "skipped", count=0, error="--skip-nuclei")
    if dry_run:
        return make_result(stage, "skipped", count=0, error="dry-run")
    if not n_cfg.get("update_templates", True):
        return make_result(stage, "skipped", count=0, error="disabled in config")
    if not runner.tool_available("nuclei"):
        return make_result(stage, "skipped", count=0,
                           error="nuclei binary not found (optional, skipped)")

    r = runner.run(
        ["nuclei", "-update-templates", "-silent"],
        stage=stage, output_dir=output_dir,
        timeout=int(n_cfg.get("update_timeout", 600)),
    )
    if not r["success"] and not r["missing_binary"]:
        # A failed update is non-fatal — scan proceeds with existing templates.
        return make_result(stage, "failed", count=0,
                           error=(r["stderr"] or "")[:200])
    return make_result(stage, "success", count=0)


def _has_param(url: str) -> bool:
    """True when the URL carries at least one query parameter (``?name=``).

    The dynamic scan is meant to fuzz *parameterised* endpoints only, so a
    bare ``https://x.com/api`` with no ``?...=`` is nothing to fuzz. We
    require both a ``?`` and a ``name=`` pair so a trailing ``?`` with an
    empty query string doesn't slip through.
    """
    q = url.split("?", 1)
    return len(q) == 2 and "=" in q[1]


# High-value markers used to rank parameterised URLs before the
# ``nuclei.dynamic.max_urls`` cap — keep the URLs most likely to yield a
# fuzzing hit (auth / api / write paths, id-like params) over archive noise.
_DYN_HINTS = (
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/query", "/search",
    "/login", "/admin", "/user", "/account", "/auth", "/oauth",
    "/upload", "/download", "/file", "/redirect", "/proxy",
    "id=", "url=", "path=", "file=", "redirect=", "next=", "cmd=", "q=",
)


def _score_dynamic(url: str) -> int:
    """Higher = keep first when capping. Ties break on shorter URL."""
    lo = url.lower()
    score = sum(1 for h in _DYN_HINTS if h in lo)
    if "web.archive.org" in lo or "webcache.googleusercontent" in lo:
        score -= 3
    return score


def _param_signature(url: str) -> tuple:
    """Collapse near-identical URLs to one representative.

    ``?id=1`` and ``?id=2`` fuzz identically, so we key on
    scheme+host+path+*param names* (values ignored). A crawl of a large
    target is mostly the same handful of endpoints with different ids;
    this is what turns 100k+ URLs into a few thousand distinct shapes.
    """
    from urllib.parse import parse_qsl, urlsplit
    s = urlsplit(url)
    # ``set`` folds a repeated param name (``?p=a&p=b`` == ``?p=a``) so those
    # collapse to one shape too — not just distinct-name value variants.
    names = tuple(sorted({k for k, _ in parse_qsl(s.query, keep_blank_values=True)}))
    return (s.scheme, s.netloc, s.path, names)


def _filter_param_urls(
    input_file: Path, output_dir: Path, max_urls: int = 0,
) -> tuple[Path, dict]:
    """Prepare the dynamic-scan input: keep only parameterised URLs, dedup
    near-identical param shapes, then cap to ``max_urls`` highest-value.

    Returns ``(file_to_scan, stats)``. When nothing needs changing we
    return the original file untouched so the common case stays a no-op.
    ``max_urls <= 0`` disables the cap.
    """
    urls = read_lines(input_file)
    total = len(urls)
    kept = [u for u in urls if _has_param(u)]
    dropped = total - len(kept)

    # Dedup by param signature, preserving first-seen order for stable runs.
    seen: set[tuple] = set()
    unique: list[str] = []
    for u in kept:
        sig = _param_signature(u)
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(u)
    deduped = len(kept) - len(unique)

    selected = unique
    capped = 0
    if max_urls and max_urls > 0 and len(unique) > max_urls:
        selected = sorted(unique, key=lambda u: (-_score_dynamic(u), len(u), u))[:max_urls]
        capped = len(unique) - len(selected)

    stats = {
        "input": total, "dropped_no_param": dropped,
        "deduped": deduped, "capped": capped, "selected": len(selected),
    }
    if dropped == 0 and deduped == 0 and capped == 0:
        return input_file, stats
    filtered = raw_dir(output_dir, "nuclei_dynamic") / "param_urls.txt"
    write_lines(filtered, selected)
    return filtered, stats


# Status codes that mean "the edge refused us", as opposed to a status
# that tells us something about the origin. Deliberately EXCLUDES 401: an
# auth-protected endpoint is a real, informative answer from the app and
# worth scanning. 403/406/429 in bulk are what a CDN/WAF returns when it
# never forwarded the request at all.
_BLOCKED_STATUS = {403, 406, 429}
# Below this many probed URLs a host has too small a sample to call it
# blanket-blocked — three 403s could just be three protected paths.
_WAF_MIN_SAMPLE = 10
# Fraction of a host's URLs that must carry a blocked status before we
# treat the whole host as answered-by-the-edge.
_WAF_RATIO = 0.95


def _load_status_map(output_dir: Path) -> dict[str, int]:
    """``{url: status_code}`` from the httpx probe, or ``{}`` if absent.

    ``processed/alive_urls_detail.json`` is written by ``httpx.check_urls``
    as a JSON array of probe rows. Missing/malformed is not an error: the
    caller degrades to "no host is known-blocked", which only costs scan
    time, never coverage.
    """
    detail = output_dir / "processed" / "alive_urls_detail.json"
    rows = load_json(detail)
    if not isinstance(rows, list):
        return {}
    out: dict[str, int] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        url, sc = r.get("url"), r.get("status_code")
        if not url:
            continue
        try:
            out[str(url)] = int(sc)
        except (TypeError, ValueError):
            continue
    return out


def _blanket_blocked_hosts(
    urls: list[str], status: dict[str, int],
) -> set[str]:
    """Hosts where the CDN/WAF answers every path identically.

    Measured on a real discover.com run: ``apps.discover.com`` returned the
    Akamai ``errors.edgesuite.net`` "Access Denied" page for EVERY path,
    including paths that do not exist (``/zzz-random-9931``). 1907 of the
    2000 selected URLs sat on that one host. From nuclei's point of view
    those are not 1907 targets — they are one target scanned 1907 times,
    because exposure/misconfig templates match on the response at a given
    path and the response here does not depend on the path.

    Note the bodies are NOT byte-identical (Akamai echoes the requested URL
    and a per-request reference nonce), so response-hash dedup does not
    catch this. The status distribution does.

    Such a host is capped hard rather than dropped — see the caller. Some
    path may still reach the origin, and that is not a bet worth losing for
    a scan that now has budget to spare.
    """
    from urllib.parse import urlsplit

    per_host: dict[str, list[str]] = {}
    for u in urls:
        h = urlsplit(u).netloc
        if h:
            per_host.setdefault(h, []).append(u)

    blocked: set[str] = set()
    for host, hurls in per_host.items():
        known = [status[u] for u in hurls if u in status]
        if len(known) < _WAF_MIN_SAMPLE:
            continue
        hits = sum(1 for s in known if s in _BLOCKED_STATUS)
        if hits / len(known) > _WAF_RATIO:
            blocked.add(host)
    return blocked


def _filter_endpoint_urls(
    input_file: Path, output_dir: Path, max_urls: int = 0,
    *, max_per_host: int = 0, waf_host_max: int = 0,
) -> tuple[Path, dict]:
    """Prepare the endpoints-scan input: dedup URLs that share (scheme,
    host, path) — query-string noise aside they hit the same nuclei
    templates — then spread the budget across hosts and cap to
    ``max_urls`` highest-value.

    Unlike ``_filter_param_urls`` this does NOT require a query param:
    endpoints_scan targets every discovered live URL, not just the
    parameterised ones, so most inputs here have no ``?`` at all.

    THE PER-HOST CAP IS THE POINT, not a refinement of the global one. A
    ``max_urls`` cut ranks every URL against every other, so one host with
    a huge crawled surface takes the whole list: on a real discover.com run
    the top-2000 selection gave 1907 slots (95%) to a single WAF-blocked
    host and left 44 other hosts with 0-24 URLs between them. That
    selection contained 13 URLs that returned 200. Capping at 100/host over
    the same input yields 634 URLs containing 176 that return 200 — a list
    three times smaller with 13x more reachable content, because what it
    drops are near-copies of one "Access Denied" page. Cost falls with it:
    2000 URLs ≈ 6.9M requests ≈ 4.8h at rate_limit 400, versus ≈ 1.5h.

    Hosts whose every answer comes from the edge (see
    ``_blanket_blocked_hosts``) get the tighter ``waf_host_max`` instead,
    keeping a sample in case some path reaches the origin.

    Returns ``(file_to_scan, stats)``. When nothing needs changing we
    return the original file untouched so the common case stays a no-op.
    ``max_urls`` / ``max_per_host`` ``<= 0`` disable their cap.
    """
    from urllib.parse import urlsplit

    urls = read_lines(input_file)
    total = len(urls)

    seen: set[tuple] = set()
    unique: list[str] = []
    for u in urls:
        s = urlsplit(u)
        sig = (s.scheme, s.netloc, s.path)
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(u)
    deduped = total - len(unique)

    # Per-host cap. Rank globally FIRST so each host contributes its own
    # highest-value URLs, then walk that order handing out per-host slots.
    selected = unique
    per_host_capped = 0
    blocked: set[str] = set()
    if max_per_host and max_per_host > 0:
        status = _load_status_map(output_dir)
        blocked = _blanket_blocked_hosts(unique, status) if status else set()
        ranked = sorted(unique, key=lambda u: (-_score_dynamic(u), len(u), u))
        used: dict[str, int] = {}
        kept: list[str] = []
        for u in ranked:
            host = urlsplit(u).netloc
            cap = waf_host_max if host in blocked else max_per_host
            if cap <= 0:
                continue
            if used.get(host, 0) >= cap:
                continue
            used[host] = used.get(host, 0) + 1
            kept.append(u)
        per_host_capped = len(unique) - len(kept)
        selected = kept

    capped = 0
    if max_urls and max_urls > 0 and len(selected) > max_urls:
        ranked = sorted(selected, key=lambda u: (-_score_dynamic(u), len(u), u))
        capped = len(selected) - max_urls
        selected = ranked[:max_urls]

    stats = {
        "input": total, "deduped": deduped, "per_host_capped": per_host_capped,
        "capped": capped, "selected": len(selected),
    }
    if blocked:
        stats["waf_hosts"] = sorted(blocked)
    if deduped == 0 and capped == 0 and per_host_capped == 0:
        return input_file, stats
    filtered = raw_dir(output_dir, "nuclei_endpoints") / "endpoint_urls.txt"
    write_lines(filtered, selected)
    return filtered, stats


def _outputs_exist(out_dir: Path, kind: str) -> bool:
    """True only when a PREVIOUS run of this scan finished cleanly.

    ``--resume`` skips a stage when this returns True, so "the file is
    non-empty" is the wrong test: a timed-out or skipped scan still writes
    a well-formed ``{"findings": [], "severity_count": {...}}`` (~126
    bytes), and resuming after the 6-batch acronis.com run that timed out
    would silently report ``nuclei_default success | 0 findings`` without
    scanning anything — the failure looking exactly like a clean result.

    ``_run`` stamps ``"complete": true`` only after every batch has run
    without a timeout or a hard failure, so we key on that instead. An
    output dir written before this flag existed has no ``complete`` key
    and is therefore re-scanned, which is the safe direction to fail.
    """
    j = findings_dir(out_dir, kind) / "nuclei.json"
    if not j.exists() or j.stat().st_size == 0:
        return False
    try:
        data = json.loads(j.read_text(errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return False
    return isinstance(data, dict) and data.get("complete") is True


def _parse_findings(json_out: Path) -> list[dict]:
    """Parse a nuclei findings file into a list of finding dicts.

    Normally reads the incremental ``-jsonl -o`` stream (one object per
    line), but still accepts a single JSON array so older ``-json-export``
    files left in an output dir keep parsing. A JSONL stream from a killed
    run can end mid-line; that trailing fragment simply fails to decode
    and is skipped, along with any other malformed / non-dict entry, so a
    stray line never blows up the whole stage.
    """
    findings: list[dict] = []
    if not json_out.exists():
        return findings
    raw = json_out.read_text(errors="ignore").strip()
    if not raw:
        return findings
    if raw.startswith("["):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = []
        if isinstance(data, list):
            findings.extend(o for o in data if isinstance(o, dict))
    else:
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                findings.append(obj)
    return findings


def _build_nuclei_cmd(
    input_file: Path, jsonl_out: Path, *,
    severity: list[str], tags: Optional[list[str]], n_cfg: dict,
) -> list[str]:
    """Assemble the nuclei argv shared by the single-run and batch paths."""
    rate = int(n_cfg.get("rate_limit", 100))
    bulk = int(n_cfg.get("bulk_size", 25))
    conc = int(n_cfg.get("concurrency", 25))
    cmd = [
        "nuclei", "-l", str(input_file),
        "-severity", ",".join(severity),
        "-silent",
        # ``-o`` is the ONLY nuclei output written incrementally — flushed
        # per finding, the moment it is discovered. Both ``-json-export``
        # and ``-jsonl-export`` buffer everything in memory and write once
        # at exit, so a run we kill at its timeout leaves them EMPTY (or
        # never creates them at all). Verified against nuclei v3.11.0.
        #
        # That is precisely how real findings were lost: a run would time
        # out, ``-json-export`` had written nothing, and the stage reported
        # "salvaged 0 partial findings" even though nuclei HAD found real
        # issues and streamed them to the text ``-o`` file we ignored.
        #
        # ``-jsonl`` turns that incremental ``-o`` stream into one JSON
        # object per line, so we get structured findings that survive a
        # SIGKILL. Batching still matters (it bounds each run), but
        # correctness no longer depends on any batch finishing.
        "-jsonl", "-o", str(jsonl_out),
        "-rate-limit", str(rate),
        "-bulk-size", str(bulk),
        "-c", str(conc),
    ]
    # DAST (fuzzing) templates are gated behind an explicit flag: without
    # ``-dast`` nuclei will not load them at all — pointing it at nothing
    # but ``dast/`` without the flag fails outright with "no templates
    # provided for scan". They carry ordinary tags (``sqli,error,dast``),
    # so a tags filter alone LOOKS like it selects them while the engine
    # silently drops every one. That made the dynamic scan — the stage
    # whose whole job is fuzzing parameterised URLs — run only the
    # non-fuzzing sqli/xss/... templates. Off by default; the dynamic scan
    # turns it on (see nuclei.dynamic.dast in config.yml).
    #
    # NOTE ON ``-tags`` WITH ``-dast``: ``-dast`` is already the filter.
    # It restricts the run to the fuzzing corpus (54 loadable templates in
    # nuclei-templates v10.4.6 — the ``dast/`` tree is 249 files but 192
    # are ``flow: headless`` CSP-bypass checks that need ``-headless``).
    # Layering a tags filter on top only SUBTRACTS: the tag set we used to
    # ship (fuzz,fuzzing,sqli,xss,lfi,rce,ssrf,ssti,idor) cut 54 → 41,
    # silently dropping cmdi, crlf, open-redirect, rfi, xinclude, csv
    # injection and the DAST CVE templates — measured, not guessed, with
    # ``nuclei -u ... -dast [-tags ...]`` and reading "Templates loaded
    # for current scan". So the dynamic scan ships with NO tags now.
    if n_cfg.get("dast", False):
        cmd.append("-dast")
        # -fuzz-aggression controls how many payloads each fuzz point gets.
        # nuclei's default is "low", which is a detection-rate choice, not
        # a speed one: measured against a local 2-param target with the
        # full dast corpus, one URL costs 191 requests at low, 236 at
        # medium (+24%), 289 at high (+51%). A quarter more traffic for a
        # materially wider payload set is a good trade on a stage that
        # already finishes in a fraction of its budget — so the dynamic
        # scan ships at medium (see nuclei.dynamic.fuzz_aggression).
        aggression = str(n_cfg.get("fuzz_aggression", "") or "").strip()
        if aggression:
            cmd.extend(["-fuzz-aggression", aggression])
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    exclude_tags = n_cfg.get("exclude_tags") or []
    clean_excludes = [str(t).strip() for t in exclude_tags if str(t).strip()]
    if clean_excludes:
        cmd.extend(["-etags", ",".join(clean_excludes)])
    return cmd


def _write_outputs(
    txt_out: Path, json_out: Path, findings: list[dict],
    *, complete: bool = False,
) -> dict:
    """Persist accumulated findings to the canonical nuclei.txt/json pair
    and return the severity-count dict. Called after every batch so the
    on-disk result is always current even if a later batch is killed.

    ``complete`` marks the scan as having covered its whole input — only
    the final write after the batch loop passes True. ``_outputs_exist``
    (i.e. ``--resume``) keys on it so a partial result is never mistaken
    for a finished scan."""
    sev_count: dict[str, int] = {s: 0 for s in SEV_ORDER}
    for obj in findings:
        sev = ((obj.get("info") or {}).get("severity") or "info").lower()
        sev_count[sev] = sev_count.get(sev, 0) + 1
    matched = [
        f.get("matched-at") or f.get("host", "")
        for f in findings if isinstance(f, dict)
    ]
    write_lines(txt_out, [m for m in matched if m])
    write_json(json_out, {
        "findings": findings, "severity_count": sev_count,
        "complete": complete,
    })
    return sev_count


def _run(
    input_file: Path,
    kind: str,
    cfg: dict,
    output_dir: Path,
    *,
    severity: list[str],
    tags: Optional[list[str]] = None,
    timeout: int = 7200,
    skip: bool = False,
) -> dict:
    stage = f"nuclei_{kind}"
    fdir = findings_dir(output_dir, kind)
    txt_out = fdir / "nuclei.txt"
    json_out = fdir / "nuclei.json"

    if skip:
        txt_out.write_text("")
        write_json(json_out, {"findings": [], "severity_count": {}})
        return make_result(
            stage, "skipped", input_path=input_file,
            outputs=[txt_out, json_out], count=0, error="--skip-nuclei",
        )

    if not runner.tool_available("nuclei"):
        txt_out.write_text("")
        write_json(json_out, {"findings": [], "severity_count": {}})
        return make_result(
            stage, "skipped", input_path=input_file,
            outputs=[txt_out, json_out], count=0,
            error="nuclei binary not found (optional, skipped)",
        )

    if not input_file.exists() or input_file.stat().st_size == 0:
        txt_out.write_text("")
        write_json(json_out, {"findings": [], "severity_count": {}})
        return make_result(
            stage, "skipped", input_path=input_file,
            outputs=[txt_out, json_out], count=0,
            error="input file empty or missing",
        )

    # Per-scan sub-config (``nuclei.default`` / ``.endpoints`` / ``.dynamic``)
    # overrides the shared ``nuclei.*`` defaults, so each scan can tune its
    # own batch_size / batch_timeout / rate_limit without touching the
    # others. This is what lets the default scan (562 root hosts) batch at a
    # smaller size than the global 1000 — otherwise it stays a single run and
    # a timeout wipes every finding.
    global_cfg = cfg.get("nuclei", {})
    scan_cfg = global_cfg.get(kind)
    scan_cfg = scan_cfg if isinstance(scan_cfg, dict) else {}
    n_cfg = {**global_cfg, **scan_cfg}
    tg_cfg = cfg.get("telegram") or {}

    # ------------------------------------------------------------------
    # Batching. ``-json-export`` is written once at exit (see the note in
    # _build_nuclei_cmd), so a single huge run that walls at its timeout
    # persists NOTHING — the exact "salvaged 0 partial findings" failure a
    # real acronis.com run hit on all three scans. Splitting the input into
    # bounded batches makes each batch run to completion and persist its
    # findings BEFORE the next starts, so a later timeout never wipes the
    # earlier results.
    #
    # ``batch_size <= 0`` (or an input already under one batch) keeps the
    # original single-run behaviour untouched.
    # ------------------------------------------------------------------
    all_urls = read_lines(input_file)
    batch_size = int(n_cfg.get("batch_size", 0) or 0)
    batch_timeout = int(n_cfg.get("batch_timeout", timeout) or timeout)
    on_timeout = str(n_cfg.get("batch_on_timeout", "continue")).strip().lower()
    min_batch = max(1, int(n_cfg.get("batch_min_size", 25) or 1))

    batched = batch_size > 0 and len(all_urls) > batch_size
    single = not batched
    planned_batches = (
        -(-len(all_urls) // batch_size) if batched else 1
    )

    findings: list[dict] = []
    sev_count: dict[str, int] = {s: 0 for s in SEV_ORDER}
    seen_keys: set[tuple] = set()      # dedup findings across batches
    any_timeout = False
    stopped_early = False
    deadline_hit = False
    batches_run = 0
    hard_failed_batches = 0
    resized = False
    # nuclei always streams into its own raw JSONL file (even for a single
    # run) and we derive the canonical nuclei.txt/json from what we parse
    # back. Letting nuclei write the canonical files directly would put
    # JSONL into nuclei.txt, which is meant to be one matched URL per line.
    bdir = raw_dir(output_dir, stage)

    started = time.monotonic()
    pending = list(all_urls)
    cur_size = batch_size if batched else 0     # 0 → take everything
    idx = 0

    while pending:
        chunk = pending[:cur_size] if cur_size > 0 else pending
        pending = pending[len(chunk):]

        if single:
            batch_input = input_file
            b_jsonl = bdir / "scan.jsonl"
        else:
            batch_input = bdir / f"batch_{idx:03d}.txt"
            write_lines(batch_input, chunk)
            b_jsonl = bdir / f"batch_{idx:03d}.jsonl"
        idx += 1

        # Start from an empty stream. We now READ this file back, so a
        # leftover from an earlier run against the same output dir (very
        # likely — the previous attempt is what timed out) would otherwise
        # be re-reported as if this run had found it.
        b_jsonl.parent.mkdir(parents=True, exist_ok=True)
        b_jsonl.write_text("")

        # ``timeout`` is the ceiling for the WHOLE stage, batched or not.
        # It used to bound only the single-run path, so a batched scan ran
        # for batches × batch_timeout with nothing capping it — a real
        # discover.com run spent 4h in nuclei_endpoints under a nominal
        # 3h ``timeout``. Each batch now gets whatever is left of the
        # stage budget, and we stop rather than start a batch too short to
        # get past nuclei's template load.
        if single:
            per_timeout = timeout
        else:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= _MIN_BATCH_BUDGET:
                deadline_hit = True
                pending = chunk + pending      # un-consume, it never ran
                break
            per_timeout = int(min(batch_timeout, remaining))

        cmd = _build_nuclei_cmd(
            batch_input, b_jsonl,
            severity=severity, tags=tags, n_cfg=n_cfg,
        )
        r = runner.run(cmd, stage=stage, log_name=stage,
                       output_dir=output_dir, timeout=per_timeout)
        batches_run += 1
        timed_out = r.get("timed_out", False)

        hard_fail = (
            not r["success"] and not r["missing_binary"] and not timed_out
        )

        # Merge this batch's findings, de-duplicating by (template, match)
        # so a URL that appears in two batches isn't double-counted. We
        # parse even on a hard failure / timeout: the JSONL stream is
        # incremental, so whatever nuclei found before it died is real and
        # already on disk. Nothing is discarded on the way out.
        for f in _parse_findings(b_jsonl):
            key = (f.get("template-id") or f.get("templateID"),
                   f.get("matched-at") or f.get("host"))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(f)

        # Persist after every batch so a later kill never loses this one.
        sev_count = _write_outputs(txt_out, json_out, findings)

        # A hard failure (not a timeout, not a missing binary) is fatal for
        # a single run — but only after the salvage above, so any findings
        # nuclei streamed before dying are still reported. Across batches
        # one bad batch shouldn't sink the rest, so record and move on.
        if hard_fail:
            if single:
                return make_result(
                    stage, "failed", input_path=input_file,
                    outputs=[txt_out, json_out], count=len(findings),
                    error=(r["stderr"] or "")[:300],
                    extra={"severity_count": sev_count},
                )
            hard_failed_batches += 1
            continue

        if timed_out:
            any_timeout = True
            if not single:
                if on_timeout == "stop":
                    stopped_early = True
                    break
                # Halve the batch for what's left. A timed-out batch is
                # NOT "the last 17% of its URLs went unscanned": nuclei
                # walks template-by-template across every target, so a
                # kill truncates the TEMPLATE list for every URL in the
                # batch — and template order isn't random, so the same
                # tail is lost every time. Smaller batches each get
                # through the full template set. Total request cost is
                # unchanged; what improves is per-URL coverage, paid for
                # with one extra template load per batch (~10-30s).
                if cur_size > min_batch:
                    cur_size = max(min_batch, cur_size // 2)
                    resized = True

    # Final write. Identical content to the last per-batch write except for
    # the ``complete`` stamp, which only holds when the scan actually got
    # through its whole input: every batch ran, none timed out, none failed
    # hard, and nothing was left unscanned. That is what ``--resume``
    # checks before skipping this stage.
    complete = (
        not any_timeout
        and not stopped_early
        and not deadline_hit
        and hard_failed_batches == 0
        and not pending
    )
    sev_count = _write_outputs(txt_out, json_out, findings, complete=complete)

    # Notify once at the end over the full (deduped) finding set, matching
    # the previous single-run behaviour (no per-batch alert spam).
    for f in findings:
        if isinstance(f, dict):
            notify_finding(f, stage=stage, cfg=tg_cfg, severity_threshold="high")

    # With adaptive resizing the batch count isn't known up front, so
    # report what actually happened: batches run, plus what the leftover
    # would still need at the size we ended on.
    left = (-(-len(pending) // cur_size) if pending and cur_size else
            (1 if pending else 0))
    extra: dict = {"severity_count": sev_count}
    if not single:
        extra["batches"] = {
            "total": batches_run + left, "run": batches_run,
            "planned": planned_batches,
            "size": cur_size, "initial_size": batch_size,
            "resized": resized, "stopped_early": stopped_early,
            "failed": hard_failed_batches,
            "unscanned_urls": len(pending),
        }
    status = "success"
    error = None
    if any_timeout or deadline_hit:
        # A timed-out batch is a partial result, not a dead stage: with
        # batching the finished batches are real, persisted findings.
        status = "failed" if single else "success"
        if any_timeout:
            extra["timed_out"] = True
        if deadline_hit:
            extra["deadline_hit"] = True
        if single:
            error = (f"timeout after {timeout}s — salvaged {len(findings)} "
                     f"partial findings")
        else:
            if deadline_hit:
                note = (f"hit the {timeout}s stage budget with "
                        f"{len(pending)} URL(s) unscanned")
            elif stopped_early:
                note = "stopped after first timeout"
            else:
                note = "continued past timed-out batch(es)"
            if resized:
                note += f"; batch resized {batch_size}→{cur_size}"
            error = (f"{batches_run}/{batches_run + left} batches run, "
                     f"{note}; {len(findings)} findings kept")

    result = make_result(
        stage, status, input_path=input_file,
        outputs=[txt_out, json_out], count=len(findings),
        error=error, extra=extra,
    )

    # stage-complete summary — only fires when findings > 0
    notify_stage_result(stage, result, tg_cfg)

    return result


def default_scan(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    n_cfg = (cfg.get("nuclei") or {}).get("default") or {}
    fdir = findings_dir(output_dir, "default")
    outputs = [fdir / "nuclei.txt", fdir / "nuclei.json"]
    if resume and _outputs_exist(output_dir, "default"):
        return make_result(
            "nuclei_default", "success", input_path=alive_file,
            outputs=outputs,
            count=len(read_lines(fdir / "nuclei.txt")),
        )
    if dry_run:
        return make_result(
            "nuclei_default", "skipped", input_path=alive_file,
            outputs=outputs, count=0, error="dry-run",
        )
    if not n_cfg.get("enabled", True):
        return make_result(
            "nuclei_default", "skipped", input_path=alive_file,
            outputs=outputs, count=0, error="disabled in config",
        )
    # Gom host trùng response giống hai stage fuzzing — nhưng MẶC ĐỊNH TẮT.
    # Với fuzzing, bỏ qua bản sao chỉ mất thời gian; với quét lỗ hổng thì đó
    # là đánh đổi coverage: hai host có cùng trang chủ vẫn có thể khác nhau ở
    # tầng sâu hơn, và bỏ sót một finding thật đắt hơn nhiều so với vài phút
    # quét thừa. Operator tự bật khi biết chắc mình đang nhìn wildcard.
    if n_cfg.get("dedup_targets", False):
        targets, sel_stats = fuzz_targets.load_targets(
            alive_file, output_dir,
            max_hosts=int(n_cfg.get("max_hosts", 0)),
            dedup=True,
        )
        if targets and sel_stats.get("deduped"):
            alive_file = fuzz_targets.write_target_file(
                targets, fdir / "targets.txt")
            print(console.phase_info_line(
                f"[nuclei_default] {fuzz_targets.summary_line(sel_stats)}"))

    return _run(
        alive_file, "default", cfg, output_dir,
        severity=n_cfg.get("severity", SEV_ORDER),
        tags=n_cfg.get("tags"),
        timeout=int(n_cfg.get("timeout", 7200)),
        skip=skip,
    )


def endpoints_scan(
    alive_urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    """Scan the discovered live endpoints (alive_urls.txt) with nuclei.

    Fills the biggest coverage gap in the pipeline: ``default_scan`` only
    sees ``alive.txt`` (the root hosts), because it runs in parallel with
    content discovery. The thousands of endpoints that crawling + dirsearch
    + jsluice + waymore surface — the whole point of discovery — otherwise
    never get a nuclei pass. This scan runs *after* discovery on the
    live-verified URL list.

    Defaults to ``critical,high,medium`` (skips info/low): 1000+ endpoints
    at all-severity would bury real findings under detection noise.
    """
    n_cfg = (cfg.get("nuclei") or {}).get("endpoints") or {}
    fdir = findings_dir(output_dir, "endpoints")
    outputs = [fdir / "nuclei.txt", fdir / "nuclei.json"]
    if resume and _outputs_exist(output_dir, "endpoints"):
        return make_result(
            "nuclei_endpoints", "success", input_path=alive_urls_file,
            outputs=outputs,
            count=len(read_lines(fdir / "nuclei.txt")),
        )
    if dry_run:
        return make_result(
            "nuclei_endpoints", "skipped", input_path=alive_urls_file,
            outputs=outputs, count=0, error="dry-run",
        )
    if not n_cfg.get("enabled", True):
        return make_result(
            "nuclei_endpoints", "skipped", input_path=alive_urls_file,
            outputs=outputs, count=0, error="disabled in config",
        )

    # Same lesson dynamic_scan already learned: an uncapped URL list from
    # a large crawl (10k+) cannot finish inside the timeout and the scan
    # walls with 0 findings — see logs/stages.json from a real run where
    # this happened. Dedup near-identical URLs, spread the budget across
    # hosts, then keep the top ``max_urls`` highest-value ones.
    max_urls = int(n_cfg.get("max_urls", 5000))
    scan_file, stats = _filter_endpoint_urls(
        alive_urls_file, output_dir, max_urls,
        max_per_host=int(n_cfg.get("max_per_host", 100)),
        waf_host_max=int(n_cfg.get("waf_host_max", 25)),
    )

    result = _run(
        scan_file, "endpoints", cfg, output_dir,
        severity=n_cfg.get("severity", ["critical", "high", "medium"]),
        tags=n_cfg.get("tags"),
        timeout=int(n_cfg.get("timeout", 7200)),
        skip=skip,
    )
    if (stats.get("deduped") or stats.get("capped")
            or stats.get("per_host_capped")):
        (result.setdefault("extra", {}))["url_filter"] = stats
    return result


def dynamic_scan(
    parameterized_urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    n_cfg = (cfg.get("nuclei") or {}).get("dynamic") or {}
    fdir = findings_dir(output_dir, "dynamic")
    outputs = [fdir / "nuclei.txt", fdir / "nuclei.json"]
    if resume and _outputs_exist(output_dir, "dynamic"):
        return make_result(
            "nuclei_dynamic", "success", input_path=parameterized_urls_file,
            outputs=outputs,
            count=len(read_lines(fdir / "nuclei.txt")),
        )
    if dry_run:
        return make_result(
            "nuclei_dynamic", "skipped", input_path=parameterized_urls_file,
            outputs=outputs, count=0, error="dry-run",
        )
    if not n_cfg.get("enabled", True):
        return make_result(
            "nuclei_dynamic", "skipped", input_path=parameterized_urls_file,
            outputs=outputs, count=0, error="disabled in config",
        )

    # Enforce "parameterised endpoints only" at the scan boundary and keep
    # the list to a size nuclei can actually finish. Upstream (arjun +
    # jsluice) already produce ``?p=&q=`` URLs, but a large crawl can leak
    # 100k+ of them; without a cap the fuzzing scan walls at its timeout
    # with 0 findings. Dedup near-identical param shapes, then keep the
    # top ``max_urls`` highest-value URLs.
    max_urls = int(n_cfg.get("max_urls", 3000))
    scan_file, stats = _filter_param_urls(
        parameterized_urls_file, output_dir, max_urls
    )

    result = _run(
        scan_file, "dynamic", cfg, output_dir,
        severity=n_cfg.get("severity", ["critical", "high", "medium", "low","info"]),
        tags=n_cfg.get("tags"),
        timeout=int(n_cfg.get("timeout", 7200)),
        skip=skip,
    )
    if stats.get("dropped_no_param") or stats.get("deduped") or stats.get("capped"):
        (result.setdefault("extra", {}))["param_filter"] = stats
    return result
