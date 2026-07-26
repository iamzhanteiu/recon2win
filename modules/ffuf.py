"""ffuf — stage 4.3: recursive content fuzzing with auto-calibration.

Runs alongside dirsearch (stage 4.2) rather than replacing it: the two
tools disagree often enough that the union is worth the extra wall clock.
dirsearch is thorough per-word; ffuf is fast and — with ``-ac``/``-ach`` —
much better at surviving hosts that answer 200 to everything (soft-404
catch-alls, SPA fallbacks, WAF landing pages).

Unlike dirsearch, ffuf takes **one URL per process** (``-u <base>/FUZZ``),
not a host list. So this stage fans out over ``processed/alive.txt``,
capped by ``ffuf.max_hosts`` and run ``ffuf.concurrency`` processes at a
time, then merges every hit into one URL list.

Key flags (see ``_build_cmd``):

  * ``-ac``   auto-calibration — ffuf sends a batch of random paths first
              and auto-derives filters from the responses, so a host that
              returns ``200 <same body>`` for everything yields 0 hits
              instead of the whole wordlist.
  * ``-ach``  the same calibration, recomputed **per host**. Implies
              ``-ac`` in ffuf itself; we still emit both so the argv in
              ``commands.log`` says what it does.
  * ``-recursion`` / ``-recursion-depth`` — every matched directory is
              queued and fuzzed again, up to N levels deep.

Recursion caveat: ffuf detects a directory from the redirect that a
matched response points at, so ``follow_redirects`` (``-r``) defeats it —
the redirect is consumed before ffuf can look at it, and 30x codes must
stay in ``match_status`` for a directory to be queued at all. Hence the
defaults: ``recursion: true``, ``follow_redirects: false``, and 301/302
kept in the match list.

Outputs:
    raw/ffuf/<host>.json      — one ffuf JSON report per target
    raw/ffuf/ffuf_raw.txt     — "<status> <length> <url>" union, human-readable
    processed/ffuf_urls.txt   — URL-only, deduped (feeds url_merge)
"""
from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from . import console, fuzz_targets, runner
from .dirsearch import _merge_wordlists, _resolve_wordlists
from .sensitive_ext import SENSITIVE_EXT, to_wordlist_lines
from .utils import make_result, raw_dir, read_lines, write_lines


# Anything outside this set becomes "_" in a raw report filename, so a
# target like ``https://api.example.com:8443`` lands in ``api.example.com_8443.json``.
_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


# ----------------------------------------------------------------------
# Pure helpers — no I/O, fully unit-testable.
# ----------------------------------------------------------------------
def normalize_targets(lines: Iterable[str]) -> list[str]:
    """Reduce httpx's alive output to unique fuzzable base URLs.

    Keeps the scheme and port (``https://host:8443``) because ffuf needs a
    complete URL, drops any path/query (we always fuzz from the web root),
    and drops the trailing slash so ``base + "/FUZZ"`` never doubles up.
    """
    seen: set[str] = set()
    out: list[str] = []
    for ln in lines:
        s = (ln or "").strip()
        if not s:
            continue
        if "://" not in s:
            s = "https://" + s
        try:
            sp = urlsplit(s)
        except ValueError:
            continue
        if not sp.hostname:
            continue
        base = f"{(sp.scheme or 'https').lower()}://{sp.netloc.lower()}"
        if base not in seen:
            seen.add(base)
            out.append(base)
    return out


def report_name(target: str) -> str:
    """Filename for a target's per-host JSON report (no directory part)."""
    stripped = re.sub(r"^https?://", "", target.strip())
    return _UNSAFE_RE.sub("_", stripped).strip("_") + ".json"


def parse_report(text: str) -> list[tuple[int, int, str]]:
    """Extract ``(status, length, url)`` triples from one ffuf JSON report.

    ffuf writes ``{"results": [{"url": ..., "status": ..., "length": ...,
    "input": {...}}]}``. ``length`` is the response body size in bytes — the
    signal you scan for to spot the odd-sized hit among a wall of same-size
    soft-404s. A report can be missing, empty, or truncated when ffuf is
    killed by the per-host timeout — every one of those yields ``[]`` rather
    than raising, because one dead host must not fail the stage for the rest.
    """
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []
    out: list[tuple[int, int, str]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url.startswith("http"):
            continue
        try:
            status = int(item.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        try:
            length = int(item.get("length") or 0)
        except (TypeError, ValueError):
            length = 0
        out.append((status, length, url))
    return out


def _fmt_ext(extensions: list[str]) -> str:
    """ffuf's ``-e`` wants dot-prefixed, comma-separated: ``.bak,.old``.

    ``sensitive_ext`` stores bare extensions (``bak``), and operators may
    write either form in config — normalise both to the dotted spelling.
    """
    clean: list[str] = []
    for ext in extensions:
        s = str(ext).strip().lstrip(".")
        if s:
            clean.append("." + s)
    return ",".join(clean)


def _build_cmd(
    target: str,
    report_path: Path,
    wordlist: Path | None,
    *,
    threads: int,
    autocalibration: bool = True,
    autocalibration_per_host: bool = True,
    autocalibration_strategy: str = "",
    recursion: bool = True,
    recursion_depth: int = 2,
    recursion_strategy: str = "",
    follow_redirects: bool = False,
    rate: int = 0,
    match_status: list[str] | None = None,
    filter_status: list[str] | None = None,
    filter_regex: str = "",
    extensions: list[str] | None = None,
) -> list[str]:
    """Build the ffuf argv for a single target.

    ``-noninteractive`` matters: without it ffuf grabs the terminal to
    offer its interactive prompt, which mangles the progress bar when
    four stages are printing concurrently.
    """
    cmd = [
        "ffuf",
        "-u", f"{target.rstrip('/')}/FUZZ",
        "-t", str(threads),
        "-o", str(report_path),
        "-of", "json",
        "-noninteractive",
        "-s",
    ]
    if wordlist:
        cmd.extend(["-w", str(wordlist)])
    if extensions:
        formatted = _fmt_ext(extensions)
        if formatted:
            cmd.extend(["-e", formatted])

    # Auto-calibration. -ach already turns -ac on inside ffuf; we emit
    # both so the logged argv is self-documenting.
    if autocalibration or autocalibration_per_host:
        cmd.append("-ac")
    if autocalibration_per_host:
        cmd.append("-ach")
    if autocalibration_strategy:
        cmd.extend(["-acs", str(autocalibration_strategy)])

    if recursion:
        cmd.append("-recursion")
        cmd.extend(["-recursion-depth", str(int(recursion_depth))])
        if recursion_strategy:
            cmd.extend(["-recursion-strategy", str(recursion_strategy)])

    if follow_redirects:
        cmd.append("-r")
    if rate and int(rate) > 0:
        cmd.extend(["-rate", str(int(rate))])

    if match_status:
        clean = [str(s).strip() for s in match_status if str(s).strip()]
        if clean:
            cmd.extend(["-mc", ",".join(clean)])
    if filter_status:
        clean = [str(s).strip() for s in filter_status if str(s).strip()]
        if clean:
            cmd.extend(["-fc", ",".join(clean)])
    # -fr lọc theo NỘI DUNG body, không theo kích thước. Cần cho API soft-404
    # kiểu {"error":"not found","path":"/<đã-thử>"}: body echo lại path nên độ
    # dài đổi theo từng request, -ac (lọc theo size) không gom được và chính
    # chuỗi thăm dò của calibration bị báo thành hit.
    if filter_regex:
        cmd.extend(["-fr", str(filter_regex)])

    return cmd


# ----------------------------------------------------------------------
# Resume / dry-run helpers
# ----------------------------------------------------------------------
def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "ffuf_urls.txt"
    return p.exists() and p.stat().st_size > 0


def _cfg_wordlist(
    f_cfg: dict,
    merged_path: Path,
    *,
    merge: bool = True,
) -> tuple[Path | None, list[Path], dict | None]:
    """Resolve ``ffuf.wordlists`` down to the single file ffuf will use.

    ffuf *can* take several ``-w`` flags, but only with distinct keywords
    (``-w a.txt:FUZZ1 -w b.txt:FUZZ2``) which changes the fuzzing mode —
    so we merge into one deduped file exactly like the dirsearch stage.
    ``merge=False`` (dry-run) reports the planned path without writing.

    Returns ``(wordlist, resolved_paths, merge_stats)``.
    """
    paths = _resolve_wordlists(
        f_cfg.get("wordlists", []) or [], missing_callback=print,
    )
    if not paths:
        return None, [], None
    if len(paths) == 1:
        return paths[0], paths, None
    if not merge:
        return merged_path, paths, {"files": len(paths), "path": str(merged_path)}
    path, lines_in, lines_out = _merge_wordlists(paths, merged_path)
    stats = {
        "files": len(paths),
        "lines_in": lines_in,
        "lines_out": lines_out,
        "path": str(path),
    }
    print(
        console.phase_info_line(
            f"[ffuf] merged {len(paths)} wordlists "
            f"({lines_in} lines → {lines_out} unique) into {path}"
        )
    )
    return path, paths, stats


# ----------------------------------------------------------------------
# Stage entrypoint
# ----------------------------------------------------------------------
def scan(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "ffuf"
    raw_ff = raw_dir(output_dir, "ffuf")
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    raw_out = raw_ff / "ffuf_raw.txt"
    merged_wl_path = raw_ff / "merged_wordlists.txt"
    proc_out = proc / "ffuf_urls.txt"

    f_cfg = cfg.get("ffuf", {}) if isinstance(cfg, dict) else {}

    # ffuf is the most expensive stage in the parallel block (recursion ×
    # N hosts), so ``enabled: false`` turns it off for good without needing
    # ``--skip-ffuf`` on every invocation.
    if skip or not f_cfg.get("enabled", True):
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="--skip-ffuf" if skip else "disabled in config",
        )

    if resume and _outputs_exist(output_dir):
        existing = read_lines(proc_out)
        return make_result(
            stage, "success", input_path=alive_file,
            outputs=[raw_out, proc_out], count=len(existing),
        )

    threads = int(f_cfg.get("threads", 40))
    timeout = int(f_cfg.get("timeout", 1800))
    max_hosts = int(f_cfg.get("max_hosts", 50))
    concurrency = max(1, int(f_cfg.get("concurrency", 3)))
    extensions = f_cfg.get("extensions") or []

    # Gom nhóm host trả về cùng một response (wildcard DNS → 200 host, 1 app)
    # rồi mới xếp hạng + cap. Làm ngược lại thì cap có thể bị 50 bản sao của
    # cùng một trang chiếm sạch.
    selected, sel_stats = fuzz_targets.load_targets(
        alive_file, output_dir,
        max_hosts=max_hosts,
        dedup=bool(f_cfg.get("dedup_targets", True)),
        skip_waf=bool(f_cfg.get("skip_waf", False)),
    )
    targets = normalize_targets(read_lines(alive_file))
    capped = normalize_targets(selected)
    if sel_stats.get("deduped") or sel_stats.get("capped"):
        print(console.phase_info_line(f"[ffuf] {fuzz_targets.summary_line(sel_stats)}"))

    def _build(target: str, wordlist: Path | None) -> list[str]:
        return _build_cmd(
            target, raw_ff / report_name(target), wordlist,
            threads=threads,
            autocalibration=bool(f_cfg.get("autocalibration", True)),
            autocalibration_per_host=bool(
                f_cfg.get("autocalibration_per_host", True)),
            autocalibration_strategy=f_cfg.get("autocalibration_strategy") or "",
            recursion=bool(f_cfg.get("recursion", True)),
            recursion_depth=int(f_cfg.get("recursion_depth", 2)),
            recursion_strategy=f_cfg.get("recursion_strategy") or "",
            follow_redirects=bool(f_cfg.get("follow_redirects", False)),
            rate=int(f_cfg.get("rate", 0) or 0),
            match_status=f_cfg.get("match_status") or [],
            filter_status=f_cfg.get("filter_status") or [],
            filter_regex=f_cfg.get("filter_regex") or "",
            extensions=extensions,
        )

    if dry_run:
        wordlist, wl_paths, merge_stats = _cfg_wordlist(
            f_cfg, merged_wl_path, merge=False,
        )
        sel_stats = {}
        sample = capped[0] if capped else "https://example.com"
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0, error="dry-run",
            extra={
                "planned_cmd": _build(sample, wordlist),
                "targets": len(capped),
                "selection": sel_stats,
                "wordlists": [str(p) for p in wl_paths],
                "merge": merge_stats,
            },
        )

    if not runner.tool_available("ffuf"):
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="ffuf binary not found (optional, skipped)",
        )

    if not capped:
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="no alive hosts to scan",
        )

    wordlist, wl_paths, merge_stats = _cfg_wordlist(f_cfg, merged_wl_path)
    # ffuf không có chế độ chỉ-extension (không có gì để nối extension vào
    # nếu thiếu wordlist), nên khi chưa cấu hình wordlist ta tự dựng một cái
    # từ SENSITIVE_FILES — đó là các path thật (``.env``, ``.git/config``),
    # nối thẳng vào base URL. SENSITIVE_EXT đi kèm qua ``-e`` để phủ thêm
    # ``<từ>.bak`` / ``<từ>.sql``.
    if wordlist is None and not extensions:
        wordlist = merged_wl_path
        write_lines(merged_wl_path, to_wordlist_lines())
        extensions = SENSITIVE_EXT
        merge_stats = {"files": 0, "path": str(merged_wl_path),
                       "source": "sensitive_files fallback"}

    results: dict[str, list[tuple[int, int, str]]] = {}
    failures: list[str] = []
    skipped_over_budget: list[str] = []

    # ``timeout`` là ngân sách MỖI HOST. Không có trần tổng thì worst case là
    # ``max_hosts / concurrency × timeout`` — với mặc định 50/3×1800 là 8.5
    # giờ, trong khi 3 stage còn lại của phase 4 đã xong từ lâu và cả pipeline
    # ngồi chờ. ``budget_seconds`` chặn việc khởi động target mới khi đã hết
    # giờ; target đang chạy vẫn được để chạy nốt.
    budget = int(f_cfg.get("budget_seconds", 3600) or 0)
    deadline = time.monotonic() + budget if budget > 0 else None

    def _run_one(target: str) -> None:
        if deadline is not None and time.monotonic() >= deadline:
            skipped_over_budget.append(target)
            return
        report_path = raw_ff / report_name(target)
        # Không để một host đơn lẻ vượt quá phần ngân sách còn lại.
        host_timeout = timeout
        budget_capped = False
        if deadline is not None:
            # Trước đây chỗ này là ``max(30, min(timeout, remaining))``: khi
            # ngân sách chỉ còn vài giây, host vẫn được cấp trọn 30s — vượt
            # luôn trần mà chính nó tồn tại để bảo vệ, và chắc chắn chết vì
            # ffuf cần hàng phút cho một wordlist. Run thật 2026-07-25 có 3
            # host dính đúng kiểu này (``TimeoutExpired after 30s``). Cấp
            # đúng phần còn lại, không hơn.
            host_timeout = min(timeout, max(1, int(deadline - time.monotonic())))
            budget_capped = host_timeout < timeout
        r = runner.run(
            _build(target, wordlist), stage=stage, output_dir=output_dir,
            timeout=host_timeout, log_name=stage,
        )
        # ffuf exits non-zero on a timeout or a dead host. That is one
        # target's problem — record it and keep the other hits.
        if not r["success"] and not report_path.exists():
            # Host bị cắt ngắn vì hết ngân sách rồi chết đúng ở cái timeout
            # đã bị cắt đó không phải lỗi của target — đó là hệ quả của
            # quyết định ngân sách, cùng bản chất với nhánh skip ở trên.
            # Đếm nó vào ``failures`` chỉ làm nhiễu báo cáo.
            if budget_capped and r.get("timed_out"):
                skipped_over_budget.append(target)
            else:
                failures.append(f"{target}: {(r['stderr'] or 'failed').strip()[:120]}")
            return
        text = report_path.read_text(errors="ignore") if report_path.exists() else ""
        results[target] = parse_report(text)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(_run_one, capped))

    raw_lines: list[str] = []
    urls: list[str] = []
    seen: set[str] = set()
    for target in capped:
        for status, length, url in results.get(target, []):
            # "<status> <length> <url>" — length (response bytes) lets you eyeball
            # the odd-sized hit among a block of identical soft-404s.
            raw_lines.append(f"{status} {length} {url}")
            if url not in seen:
                seen.add(url)
                urls.append(url)

    write_lines(raw_out, raw_lines)
    n = write_lines(proc_out, urls)

    if skipped_over_budget:
        print(console.phase_info_line(
            f"[ffuf] hết ngân sách {budget}s — bỏ qua "
            f"{len(skipped_over_budget)} target còn lại"))

    # Mọi target đều lỗi nghĩa là có gì đó hệ thống (wordlist hỏng, mất
    # mạng) — báo failed thay vì im lặng trả 0 hit. Target bị bỏ vì hết
    # ngân sách KHÔNG tính là lỗi: đó là quyết định có chủ ý.
    attempted = len(capped) - len(skipped_over_budget)
    status = "failed" if attempted and len(failures) == attempted else "success"
    return make_result(
        stage, status, input_path=alive_file,
        outputs=[raw_out, proc_out], count=n,
        error="; ".join(failures)[:300] if status == "failed" else None,
        extra={
            "targets": len(capped),
            "targets_total": len(targets),
            "failed_targets": len(failures),
            "skipped_over_budget": len(skipped_over_budget),
            "budget_seconds": budget,
            "selection": sel_stats,
            "wordlists": [str(p) for p in wl_paths],
            "merge": merge_stats,
        },
    )
