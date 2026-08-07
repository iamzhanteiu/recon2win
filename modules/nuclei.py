"""nuclei — stage 9, the last scan in the pipeline.

One entry point: ``default_scan(alive_file)`` — the full template set against
the alive hosts. It runs on its own at the end of the run rather than beside
content discovery, so it never shares its rate budget with the crawlers.

Findings are persisted as both plain text (one matched URL per line) and JSON.
High/Critical findings fire an immediate Telegram alert (if configured).
"""
from __future__ import annotations

import json
import subprocess
import time
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


# Every severity nuclei can emit, lowest first. ``unknown`` is what nuclei
# gives a template that declares no severity — it is a real filter value
# (`-severity unknown`), so leaving it out of a "run everything" list drops
# those templates silently.
SEV_ORDER = ["unknown", "info", "low", "medium", "high", "critical"]

# Don't start a batch with less than this left of the stage budget. nuclei
# spends ~10-30s loading templates before its first request, so a 30s slice
# buys nothing but a guaranteed timeout and a misleading "batch run" count.
_MIN_BATCH_BUDGET = 60

# Phần ngân sách batch mà một batch được phép ăn theo tính toán. Chừa 30%
# vì rps THẬT tụt dần khi target bóp lại (đo được 194 → 113 trong 2 phút
# trên discover.com), nên tính sát 100% là bảo đảm timeout.
_BATCH_BUDGET_FACTOR = 0.7

# Số request nuclei thực sự bắn cho mỗi (template × target). KHÔNG phải 1:
# redirect, retry và matcher nhiều bước làm nó nhân lên. Hai số đo thật
# (số thứ hai từ stage endpoints thời còn tồn tại, giữ lại làm cận trên):
#   host — 1.162.000 req / (100 host × 5.095 template) = 2,28
#   URL  — 34.510 req / (10 URL × 1.078 template)      = 3,20
# Ghi đè bằng ``nuclei.default.req_per_template`` sau khi đo lại `-stats`.
_REQ_PER_TEMPLATE = 2.3

_TL_CACHE: dict[tuple, Optional[int]] = {}


def _template_count(
    severity: list[str], tags: Optional[list[str]],
    exclude_tags: Optional[list[str]] = None,
    exclude_ids: Optional[list[str]] = None,
) -> Optional[int]:
    """Đếm template mà bộ lọc severity+tags+exclude này thực sự nạp.

    Các bộ loại trừ PHẢI có mặt ở đây. Thiếu chúng thì phép đo đếm cả
    template sẽ không bao giờ chạy, batch_size được tính từ một corpus to
    hơn thực tế — đúng cái bẫy mà chính config.yml cảnh báo ("sửa tags một
    dòng là corpus đổi kích thước còn batch_size đứng yên").

    Dùng ``nuclei -tl``, tức đúng thứ mà config bảo operator chạy tay khi
    retune. Trả ``None`` khi không đo được (nuclei thiếu, lệnh lỗi) — người
    gọi phải coi đó là "không biết" và giữ nguyên batch_size đã cấu hình,
    chứ không được đoán.

    KHÔNG dùng được cho scan ``-dast``: ``-tl`` lờ đi ``-dast`` và đếm cả
    13k template non-fuzzing, sai hai bậc độ lớn (xem nuclei.default.dast
    trong config.yml). Người gọi phải tự loại trường hợp đó.
    """
    key = (tuple(severity or ()), tuple(tags or ()),
           tuple(exclude_tags or ()), tuple(exclude_ids or ()))
    if key in _TL_CACHE:
        return _TL_CACHE[key]

    result: Optional[int] = None
    if runner.tool_available("nuclei"):
        # Cố tình KHÔNG qua ``runner.run``: đây là truy vấn metadata, không
        # phải một bước quét. Đẩy nó vào commands.log/stage log sẽ làm bẩn
        # đúng thứ dùng để dựng lại một run.
        cmd = ["nuclei", "-tl", "-severity", ",".join(severity)]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if exclude_tags:
            cmd += ["-etags", ",".join(exclude_tags)]
        if exclude_ids:
            cmd += ["-exclude-id", ",".join(exclude_ids)]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            lines = [ln for ln in (p.stdout or "").splitlines() if ln.strip()]
            if lines:
                result = len(lines)
        except (OSError, ValueError, subprocess.SubprocessError):
            result = None

    _TL_CACHE[key] = result
    return result


def _safe_batch_size(
    templates: int, n_cfg: dict, batch_timeout: int,
) -> int:
    """batch_size lớn nhất còn chạy hết được trong ``batch_timeout``.

    Chính là công thức đã ghi trong config.yml, chỉ khác là code tự tính
    thay vì bắt người sửa config nhớ tính lại:

        batch_size × req_per_template × templates / rate_limit
            ≤ 0,7 × batch_timeout
    """
    rate = int(n_cfg.get("rate_limit", 100)) or 1
    rpt = float(n_cfg.get("req_per_template", _REQ_PER_TEMPLATE)) or _REQ_PER_TEMPLATE
    budget = _BATCH_BUDGET_FACTOR * batch_timeout * rate
    return max(1, int(budget / (rpt * max(1, templates))))


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
    # silently drops every one — a fuzzing scan configured by tags alone
    # runs only the non-fuzzing sqli/xss/... templates. Off by default;
    # turn it on with ``nuclei.default.dast`` in config.yml.
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
    # for current scan". So: with ``dast`` on, ship NO tags.
    if n_cfg.get("dast", False):
        cmd.append("-dast")
        # -fuzz-aggression controls how many payloads each fuzz point gets.
        # nuclei's default is "low", which is a detection-rate choice, not
        # a speed one: measured against a local 2-param target with the
        # full dast corpus, one URL costs 191 requests at low, 236 at
        # medium (+24%), 289 at high (+51%). A quarter more traffic for a
        # materially wider payload set is a good trade whenever the scan
        # finishes well inside its budget (see nuclei.default.fuzz_aggression).
        aggression = str(n_cfg.get("fuzz_aggression", "") or "").strip()
        if aggression:
            cmd.extend(["-fuzz-aggression", aggression])
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    exclude_tags = n_cfg.get("exclude_tags") or []
    clean_excludes = [str(t).strip() for t in exclude_tags if str(t).strip()]
    if clean_excludes:
        cmd.extend(["-etags", ",".join(clean_excludes)])
    # ``-eid`` excludes by TEMPLATE ID, which is a different axis from
    # ``-etags``. The hygiene templates that dominate a report
    # (http-missing-security-headers, cookies-without-httponly, …) share no
    # single tag worth excluding — dropping their tags would take real
    # findings with them — so they have to be named individually.
    # Measured on the discover.com run: 329 of 343 findings were `info`,
    # and the top six template IDs alone accounted for 296 of them.
    exclude_ids = n_cfg.get("exclude_ids") or []
    clean_ids = [str(t).strip() for t in exclude_ids if str(t).strip()]
    if clean_ids:
        cmd.extend(["-exclude-id", ",".join(clean_ids)])
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

    # The per-scan sub-config (``nuclei.default``) overrides the shared
    # ``nuclei.*`` defaults, so the scan can tune its own batch_size /
    # batch_timeout / rate_limit without touching the shared block. This is
    # what lets the default scan (562 root hosts) batch at a smaller size
    # than the global 1000 — otherwise it stays a single run and a timeout
    # wipes every finding.
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

    # ------------------------------------------------------------------
    # Kiểm bất biến batch_size TRƯỚC khi quét.
    #
    # config.yml ghi rõ công thức và các số đo, nhưng không có gì kiểm nó:
    # sửa ``tags``, ``severity`` hay ``rate_limit`` là corpus đổi kích thước
    # trong khi ``batch_size`` đứng yên, và cách duy nhất phát hiện là mất
    # vài giờ xem 6/6 batch chết ở 1800s với 0 finding — đúng lịch sử đã
    # xảy ra. Đo corpus một lần (~1-3s, có cache) rồi so với công thức.
    #
    # CHỈ THU NHỎ, không tự phóng to: batch nhỏ hơn mức tối ưu chỉ tốn thêm
    # vài lượt load template, còn batch to hơn thì mất coverage phần đuôi
    # danh sách template cho MỌI URL trong batch.
    # ------------------------------------------------------------------
    configured_size = batch_size
    autotune = bool(n_cfg.get("batch_autotune", True))
    tune: dict = {}
    # ``-dast`` loại trừ: ``-tl`` lờ đi flag đó nên số đếm sẽ sai hai bậc.
    if autotune and batch_size > 0 and not n_cfg.get("dast", False):
        tmpl_count = _template_count(
            severity, tags,
            [str(t).strip() for t in (n_cfg.get("exclude_tags") or [])
             if str(t).strip()],
            [str(t).strip() for t in (n_cfg.get("exclude_ids") or [])
             if str(t).strip()],
        )
        if tmpl_count:
            safe = _safe_batch_size(tmpl_count, n_cfg, batch_timeout)
            tune = {"templates": tmpl_count, "safe_size": safe}
            # Sàn ``batch_min_size`` có thể nâng mức "an toàn" lên CAO HƠN
            # batch_size đang cấu hình (safe=1, sàn=25, cấu hình=4). Khi đó
            # phải im lặng bỏ qua: cơ chế này chỉ được thu nhỏ. Phóng to
            # batch — kể cả "về đúng sàn" — là đổi hành vi quét theo hướng
            # mất đuôi danh sách template, đúng thứ nó sinh ra để tránh.
            applied = max(min_batch, safe)
            if batch_size > safe and applied < batch_size:
                rate = max(1, int(n_cfg.get("rate_limit", 100)))
                rpt = float(n_cfg.get("req_per_template", _REQ_PER_TEMPLATE))
                need = batch_size * tmpl_count * rpt / rate
                msg = (
                    f"[{stage}] batch_size {batch_size} vượt ngân sách — "
                    f"{tmpl_count} template × {rpt:g} req/target @rate {rate} "
                    f"≈ {need:.0f}s/batch, quá {_BATCH_BUDGET_FACTOR:.0%} × "
                    f"batch_timeout {batch_timeout}s. Hạ xuống {applied}"
                )
                if applied > safe:
                    msg += (f" (sàn batch_min_size {min_batch}; vẫn có thể "
                            f"timeout — nới batch_timeout hoặc rate_limit)")
                print(console.phase_warn_line(msg + "."))
                batch_size = applied
                tune["applied_size"] = applied

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
        # discover.com run spent 4h in a nuclei stage under a nominal
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
            "configured_size": configured_size,
            "resized": resized, "stopped_early": stopped_early,
            "failed": hard_failed_batches,
            "unscanned_urls": len(pending),
        }
        if tune:
            extra["batches"]["autotune"] = tune
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
