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


def _outputs_exist(out_dir: Path, kind: str) -> bool:
    j = findings_dir(out_dir, kind) / "nuclei.json"
    return j.exists() and j.stat().st_size > 0


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
    rate = int(n_cfg.get("rate_limit", 100))
    bulk = int(n_cfg.get("bulk_size", 25))
    conc = int(n_cfg.get("concurrency", 25))

    cmd = [
        "nuclei", "-l", str(input_file),
        "-severity", ",".join(severity),
        "-silent",
        # nuclei v3.x has THREE different output formats and the flag
        # depends on which one you want:
        #   -o foo.txt              → text (default; what we don't want)
        #   -o foo.json             → STILL text in v3.x (extension
        #                              inference is NOT honoured; this
        #                              was the bug we just hit)
        #   -json-export foo.json   → JSON, written directly to file ←
        #   -jsonl                 → JSONL, written to stdout
        # nuclei v2.x only accepts ``-json`` which writes to stdout, so
        # for full v2.x support we'd need to also parse stdout. For v3.x
        # (the version that ships on current Ubuntu/Debian releases),
        # ``-json-export`` is the right flag.
        "-o", str(txt_out),
        "-json-export", str(json_out),
        "-rate-limit", str(rate),
        "-bulk-size", str(bulk),
        "-c", str(conc),
    ]
    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    # ``-etags`` (exclude-tags) — nuclei v3.x-only flag that skips
    # templates whose tags match the list. Useful for cutting noise
    # from templates that don't apply to a web target (e.g.
    # ``interaction`` requires user interaction; ``smtp/dns/ftp/...``
    # are non-HTTP protocols). Whitespace-only entries are stripped.
    exclude_tags = n_cfg.get("exclude_tags") or []
    clean_excludes = [str(t).strip() for t in exclude_tags if str(t).strip()]
    if clean_excludes:
        cmd.extend(["-etags", ",".join(clean_excludes)])

    r = runner.run(cmd, stage=stage, log_name=stage,
                   output_dir=output_dir, timeout=timeout)
    # nuclei streams findings to ``-json-export`` as it matches, so on a
    # timeout the partial file on disk holds real findings. Fall through
    # and parse them (salvage) instead of throwing the run away — a scan
    # that walls at 7200s with 3 confirmed highs is far more useful than
    # a "failed, 0 findings". A hard failure (not a timeout) has nothing
    # worth salvaging, so bail there as before.
    timed_out = r.get("timed_out", False)
    if not r["success"] and not r["missing_binary"] and not timed_out:
        return make_result(
            stage, "failed", input_path=input_file,
            outputs=[txt_out, json_out], count=0,
            error=(r["stderr"] or "")[:300],
        )

    # parse output — handle both JSONL (one object per line) AND a
    # single JSON array (some nuclei v3.x builds write the whole
    # findings as one array instead of one object per line). Skip any
    # non-dict entries defensively (a stray ``[1,2,3]`` line shouldn't
    # blow up the whole stage).
    findings: list[dict] = []
    sev_count: dict[str, int] = {s: 0 for s in SEV_ORDER}
    if json_out.exists():
        raw = json_out.read_text(errors="ignore").strip()
        if raw.startswith("["):
            # Single JSON array — parse as one document, then iterate.
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = []
            if isinstance(data, list):
                for obj in data:
                    if isinstance(obj, dict):
                        findings.append(obj)
        else:
            # JSONL — one object per line.
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
        # Aggregate severity counts once we have the parsed findings.
        for obj in findings:
            sev = ((obj.get("info") or {}).get("severity") or "info").lower()
            sev_count[sev] = sev_count.get(sev, 0) + 1

    matched = [
        f.get("matched-at") or f.get("host", "")
        for f in findings if isinstance(f, dict)
    ]
    write_lines(txt_out, [m for m in matched if m])
    write_json(json_out, {"findings": findings, "severity_count": sev_count})

    # immediate notification for High/Critical
    tg_cfg = cfg.get("telegram") or {}
    for f in findings:
        if isinstance(f, dict):
            notify_finding(f, stage=stage, cfg=tg_cfg, severity_threshold="high")

    extra: dict = {"severity_count": sev_count}
    status = "success"
    error = None
    if timed_out:
        status = "failed"
        error = (f"timeout after {timeout}s — salvaged {len(findings)} "
                 f"partial findings")
        extra["timed_out"] = True

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
    return _run(
        alive_urls_file, "endpoints", cfg, output_dir,
        severity=n_cfg.get("severity", ["critical", "high", "medium"]),
        tags=n_cfg.get("tags"),
        timeout=int(n_cfg.get("timeout", 7200)),
        skip=skip,
    )


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
