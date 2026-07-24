"""nuclei — stages 4.5 and 8.

Used twice:
  1. default_scan(alive_file)            — full template set against alive hosts
  2. dynamic_scan(parameterized_urls_file) — focused tags on parameterised URLs

Findings are persisted as both plain text (one matched URL per line) and JSON.
High/Critical findings fire an immediate Telegram alert (if configured).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from . import console, fuzz_targets, runner
from .utils import (
    findings_dir,
    make_result,
    raw_dir,
    read_lines,
    write_json,
    write_lines,
)
from .telegram import notify_finding, notify_stage_result


SEV_ORDER = ["info", "low", "medium", "high", "critical"]


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


def _filter_endpoint_urls(
    input_file: Path, output_dir: Path, max_urls: int = 0,
) -> tuple[Path, dict]:
    """Prepare the endpoints-scan input: dedup URLs that share (scheme,
    host, path) — query-string noise aside they hit the same nuclei
    templates — then cap to ``max_urls`` highest-value.

    Unlike ``_filter_param_urls`` this does NOT require a query param:
    endpoints_scan targets every discovered live URL, not just the
    parameterised ones, so most inputs here have no ``?`` at all. Mirrors
    the same dedup+cap shape (and reuses ``_score_dynamic`` for ranking)
    so a 10k+ crawl doesn't wall the scan at its timeout with 0 findings,
    the same failure mode ``nuclei.dynamic.max_urls`` was added to fix.

    Returns ``(file_to_scan, stats)``. When nothing needs changing we
    return the original file untouched so the common case stays a no-op.
    ``max_urls <= 0`` disables the cap.
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

    selected = unique
    capped = 0
    if max_urls and max_urls > 0 and len(unique) > max_urls:
        selected = sorted(unique, key=lambda u: (-_score_dynamic(u), len(u), u))[:max_urls]
        capped = len(unique) - len(selected)

    stats = {
        "input": total, "deduped": deduped,
        "capped": capped, "selected": len(selected),
    }
    if deduped == 0 and capped == 0:
        return input_file, stats
    filtered = raw_dir(output_dir, "nuclei_endpoints") / "endpoint_urls.txt"
    write_lines(filtered, selected)
    return filtered, stats


def _outputs_exist(out_dir: Path, kind: str) -> bool:
    j = findings_dir(out_dir, kind) / "nuclei.json"
    return j.exists() and j.stat().st_size > 0


def _parse_findings(json_out: Path) -> list[dict]:
    """Parse a nuclei ``-json-export`` file into a list of finding dicts.

    Handles both shapes nuclei v3.x emits: a single JSON array, or JSONL
    (one object per line). Skips non-dict / malformed entries defensively
    so a stray line never blows up the whole stage.
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
    input_file: Path, txt_out: Path, json_out: Path, *,
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
        # See the long note in the git history: in nuclei v3.x, ``-o`` is
        # always text even with a .json extension; ``-json-export`` is the
        # flag that actually writes JSON. IMPORTANT: ``-json-export`` is
        # NOT incremental — nuclei writes the whole file once at exit, so a
        # killed run leaves it empty. That is exactly why we batch: each
        # batch runs to completion and its findings are persisted before
        # the next batch starts, so a later timeout never wipes them.
        "-o", str(txt_out),
        "-json-export", str(json_out),
        "-rate-limit", str(rate),
        "-bulk-size", str(bulk),
        "-c", str(conc),
    ]
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    exclude_tags = n_cfg.get("exclude_tags") or []
    clean_excludes = [str(t).strip() for t in exclude_tags if str(t).strip()]
    if clean_excludes:
        cmd.extend(["-etags", ",".join(clean_excludes)])
    return cmd


def _write_outputs(txt_out: Path, json_out: Path, findings: list[dict]) -> dict:
    """Persist accumulated findings to the canonical nuclei.txt/json pair
    and return the severity-count dict. Called after every batch so the
    on-disk result is always current even if a later batch is killed."""
    sev_count: dict[str, int] = {s: 0 for s in SEV_ORDER}
    for obj in findings:
        sev = ((obj.get("info") or {}).get("severity") or "info").lower()
        sev_count[sev] = sev_count.get(sev, 0) + 1
    matched = [
        f.get("matched-at") or f.get("host", "")
        for f in findings if isinstance(f, dict)
    ]
    write_lines(txt_out, [m for m in matched if m])
    write_json(json_out, {"findings": findings, "severity_count": sev_count})
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

    n_cfg = cfg.get("nuclei", {})
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

    if batch_size > 0 and len(all_urls) > batch_size:
        batches = [all_urls[i:i + batch_size]
                   for i in range(0, len(all_urls), batch_size)]
    else:
        batches = [all_urls]
    single = len(batches) == 1

    findings: list[dict] = []
    sev_count: dict[str, int] = {s: 0 for s in SEV_ORDER}
    seen_keys: set[tuple] = set()      # dedup findings across batches
    any_timeout = False
    stopped_early = False
    batches_run = 0
    bdir = raw_dir(output_dir, stage) if not single else None

    for idx, chunk in enumerate(batches):
        if single:
            batch_input, b_txt, b_json = input_file, txt_out, json_out
        else:
            batch_input = bdir / f"batch_{idx:03d}.txt"
            write_lines(batch_input, chunk)
            b_txt = bdir / f"batch_{idx:03d}.out.txt"
            b_json = bdir / f"batch_{idx:03d}.json"

        per_timeout = timeout if single else batch_timeout
        cmd = _build_nuclei_cmd(
            batch_input, b_txt, b_json,
            severity=severity, tags=tags, n_cfg=n_cfg,
        )
        r = runner.run(cmd, stage=stage, log_name=stage,
                       output_dir=output_dir, timeout=per_timeout)
        batches_run += 1
        timed_out = r.get("timed_out", False)

        # A hard failure (not a timeout, not a missing binary) has nothing
        # to salvage. With a single run we bail as before; across batches
        # one bad batch shouldn't sink the rest, so record and move on.
        if not r["success"] and not r["missing_binary"] and not timed_out:
            if single:
                return make_result(
                    stage, "failed", input_path=input_file,
                    outputs=[txt_out, json_out], count=0,
                    error=(r["stderr"] or "")[:300],
                )
            continue

        # Merge this batch's findings, de-duplicating by (template, match)
        # so a URL that appears in two batches isn't double-counted.
        for f in _parse_findings(b_json):
            key = (f.get("template-id") or f.get("templateID"),
                   f.get("matched-at") or f.get("host"))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(f)

        # Persist after every batch so a later kill never loses this one.
        sev_count = _write_outputs(txt_out, json_out, findings)

        if timed_out:
            any_timeout = True
            if not single and on_timeout == "stop":
                stopped_early = True
                break

    # Notify once at the end over the full (deduped) finding set, matching
    # the previous single-run behaviour (no per-batch alert spam).
    for f in findings:
        if isinstance(f, dict):
            notify_finding(f, stage=stage, cfg=tg_cfg, severity_threshold="high")

    extra: dict = {"severity_count": sev_count}
    if not single:
        extra["batches"] = {
            "total": len(batches), "run": batches_run,
            "size": batch_size, "stopped_early": stopped_early,
        }
    status = "success"
    error = None
    if any_timeout:
        # A timed-out batch is a partial result, not a dead stage: with
        # batching the finished batches are real, persisted findings.
        status = "failed" if single else "success"
        extra["timed_out"] = True
        if single:
            error = (f"timeout after {timeout}s — salvaged {len(findings)} "
                     f"partial findings")
        else:
            note = "stopped after first timeout" if stopped_early else \
                   "continued past timed-out batch(es)"
            error = (f"{batches_run}/{len(batches)} batches run, "
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
    # this happened. Dedup near-identical URLs, then keep the top
    # ``max_urls`` highest-value ones.
    max_urls = int(n_cfg.get("max_urls", 5000))
    scan_file, stats = _filter_endpoint_urls(
        alive_urls_file, output_dir, max_urls
    )

    result = _run(
        scan_file, "endpoints", cfg, output_dir,
        severity=n_cfg.get("severity", ["critical", "high", "medium"]),
        tags=n_cfg.get("tags"),
        timeout=int(n_cfg.get("timeout", 7200)),
        skip=skip,
    )
    if stats.get("deduped") or stats.get("capped"):
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
