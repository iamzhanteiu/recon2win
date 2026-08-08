"""fuzz_recurse — fuzz UNDER the directories the run already discovered.

The stage-4 fuzzers (dirsearch 4.2 + ffuf 4.3) fuzz from the ROOT of each
host. ffuf's ``-recursion`` extends that, but only along directories it
discovers *itself*, from a redirect — the ``/api/``, ``/admin/``,
``/internal/`` that katana / gau / waymore / jsluice / dirsearch turned up
are never used as fuzz roots. So a wordlist that would have found
``/api/v2/keys`` never gets the chance, because ``/api/`` was learned by a
different tool after root fuzzing had already finished.

This stage closes that loop. It runs AFTER the merge (stage 5/6.post), when
``processed/corpus/all_urls.txt`` holds everything every tool found, and:

  1. extracts the distinct directory prefixes of every in-corpus URL, per
     host, down to ``max_depth`` segments;
  2. collapses wildcard-duplicate hosts to one representative (reusing
     ``fuzz_targets.select_targets`` — the same "what is the same app"
     decision the other fuzzers make);
  3. ranks the directories (an ``/api/`` or ``/admin/`` is worth more than a
     ``/static/``), caps them, and fuzzes ``<host><dir>FUZZ`` with a small
     wordlist + auto-calibration, reusing ffuf's command builder, report
     parser and behavioural screen so nothing about hit handling is
     re-implemented here.

Hits are written to ``processed/sources/fuzz_recurse_urls.txt`` and merged
back into ``all_urls.txt`` by the caller (main.py), exactly like the other
post-merge probes. Read-only, same risk class as the stage-4 fuzzers.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from . import behavior, console, ffuf, fuzz_depth, fuzz_targets, layout, runner
from .dirsearch import _resolve_wordlists
from .utils import load_json, make_result, raw_dir, read_lines, write_lines

# Directory name → interest weight. A hit under ``/api/`` is worth far more
# than one under ``/static/``; when ``max_dirs_per_host`` forces a cut, the
# interesting roots must survive it.
_DIR_INTEREST: dict[str, int] = {
    "api": 100, "v1": 60, "v2": 60, "v3": 60, "graphql": 90,
    "admin": 90, "internal": 90, "private": 80, "secure": 70,
    "user": 50, "users": 50, "account": 50, "auth": 60, "oauth": 60,
    "upload": 70, "uploads": 70, "files": 50, "download": 50,
    "backup": 80, "config": 70, "settings": 50, "debug": 70,
    "actuator": 90, "manage": 60, "management": 60, "console": 70,
    "dashboard": 60, "rest": 70, "service": 50, "services": 50,
}
# Never worth fuzzing under — static asset trees are large and dead.
_DIR_SKIP = {"static", "assets", "img", "images", "css", "js", "fonts",
             "media", "vendor", "node_modules", "dist", "build"}


# ----------------------------------------------------------------------
# Pure helpers — no I/O, fully unit-testable.
# ----------------------------------------------------------------------
def dir_prefixes(path: str, max_depth: int) -> list[str]:
    """Ancestor directory paths of *path*, each ending in ``/``.

    ``/a/b/c.php`` → ``["/a/", "/a/b/"]``; ``/a/b/`` → ``["/a/", "/a/b/"]``.
    The root ``/`` is never returned — it is what stage-4 already fuzzed.
    ``max_depth`` caps the number of path segments considered.
    """
    if not path or not path.startswith("/"):
        return []
    if not path.endswith("/"):
        # drop the last segment: with no trailing slash it is a file, and
        # its own directory is its parent.
        path = path.rsplit("/", 1)[0] + "/"
    segs = [s for s in path.split("/") if s]
    out: list[str] = []
    for i in range(1, min(len(segs), max_depth) + 1):
        out.append("/" + "/".join(segs[:i]) + "/")
    return out


def _origin(url: str) -> str:
    s = urlsplit(url.strip() if "://" in url else "https://" + url.strip())
    return f"{s.scheme}://{s.netloc}" if s.scheme and s.netloc else ""


def dir_interest(directory: str) -> int:
    """Interest score for a directory path: sum of its segments' weights.

    Higher = more worth fuzzing under. A directory containing a skip segment
    (``/static/…``) scores below zero so it sorts to the bottom / can be
    filtered out entirely.
    """
    segs = [s.lower() for s in directory.split("/") if s]
    if any(s in _DIR_SKIP for s in segs):
        return -1
    # deeper dirs are marginally less valuable than their parents, all else
    # equal, so a shallow /api/ beats a deep /x/y/api/.
    return sum(_DIR_INTEREST.get(s, 5) for s in segs) - (len(segs) - 1)


def collect_dir_targets(
    urls: list[str], *, max_depth: int = 3,
) -> dict[str, list[str]]:
    """``{origin: [dir, …]}`` — the distinct directories seen per host.

    Directories under a skip tree (``/static/`` …) are dropped. Order within
    each host is by descending interest so a later ``max_dirs_per_host`` cut
    keeps the most promising roots.
    """
    by_host: dict[str, dict[str, int]] = {}
    for u in urls:
        u = (u or "").strip()
        if not u:
            continue
        origin = _origin(u)
        if not origin:
            continue
        path = urlsplit(u if "://" in u else "https://" + u).path
        for d in dir_prefixes(path, max_depth):
            score = dir_interest(d)
            if score < 0:
                continue
            by_host.setdefault(origin, {})[d] = score
    out: dict[str, list[str]] = {}
    for host, dirs in by_host.items():
        out[host] = [d for d, _ in sorted(
            dirs.items(), key=lambda kv: (-kv[1], kv[0]))]
    return out


# ----------------------------------------------------------------------
# Stage entry point
# ----------------------------------------------------------------------
def _outputs_exist(output_dir: Path) -> bool:
    p = layout.path(output_dir, "fuzz_recurse_urls.txt")
    return p.exists() and p.stat().st_size > 0


def _plan(output_dir: Path, cfg: dict) -> tuple[list[tuple[str, str]], dict]:
    """Compute the ``(host, dir)`` work list from the merged corpus.

    Split out so the dry-run and the real run agree on exactly what would be
    fuzzed. Returns ``(targets, stats)`` where each target is a
    ``(host, dir)`` pair.
    """
    r_cfg = (cfg.get("fuzz_recurse") or {}) if isinstance(cfg, dict) else {}
    max_depth = int(r_cfg.get("max_depth", 3))
    max_hosts = int(r_cfg.get("max_hosts", 30) or 0)
    max_dirs_per_host = int(r_cfg.get("max_dirs_per_host", 30) or 0)
    max_total = int(r_cfg.get("max_total_dirs", 300) or 0)

    corpus = read_lines(layout.path(output_dir, "all_urls.txt"))
    by_host = collect_dir_targets(corpus, max_depth=max_depth)
    stats: dict = {
        "corpus_urls": len(corpus),
        "hosts_with_dirs": len(by_host),
        "dirs_found": sum(len(v) for v in by_host.values()),
    }
    if not by_host:
        return [], stats

    # Collapse wildcard-duplicate hosts to one representative, then cap.
    detail = load_json(layout.path(output_dir, "alive_detail.json"))
    detail_rows = detail if isinstance(detail, list) else []
    selected, sel_stats = fuzz_targets.select_targets(
        list(by_host.keys()), detail_rows, max_hosts=max_hosts, dedup=True)
    stats["selection"] = sel_stats

    work: list[tuple[str, str]] = []
    for host in selected:
        dirs = by_host.get(host, [])
        if max_dirs_per_host:
            dirs = dirs[:max_dirs_per_host]
        for d in dirs:
            work.append((host, d))
    if max_total and len(work) > max_total:
        stats["dirs_capped"] = len(work) - max_total
        work = work[:max_total]
    stats["hosts_selected"] = len(selected)
    stats["dirs_selected"] = len(work)
    return work, stats


def scan(
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "fuzz_recurse"
    layout.ensure_tree(output_dir)
    raw_fr = raw_dir(output_dir, "fuzz_recurse")
    proc_out = layout.path(output_dir, "fuzz_recurse_urls.txt")
    outputs = [proc_out]

    r_cfg = (cfg.get("fuzz_recurse") or {}) if isinstance(cfg, dict) else {}

    if skip or not r_cfg.get("enabled", True):
        write_lines(proc_out, [])
        return make_result(
            stage, "skipped", input_path=layout.path(output_dir, "all_urls.txt"),
            outputs=outputs, count=0,
            error="--skip-fuzz-recurse" if skip else "disabled in config")
    if resume and _outputs_exist(output_dir):
        return make_result(stage, "success", outputs=outputs,
                           count=len(read_lines(proc_out)))

    # Resolve the wordlist (single file, or first of a list). Small on
    # purpose: this stage multiplies it by every discovered directory.
    wl_cfg = r_cfg.get("wordlist") or r_cfg.get("wordlists") or [
        "wordlists/SecLists/Discovery/Web-Content/common.txt"]
    if isinstance(wl_cfg, str):
        wl_cfg = [wl_cfg]
    wl_paths = _resolve_wordlists(wl_cfg, missing_callback=print)
    wordlist = wl_paths[0] if wl_paths else None

    work, stats = _plan(output_dir, cfg)

    if dry_run:
        sample = work[0] if work else ("https://example.com", "/api/")
        planned = ffuf._build_cmd(
            sample[0].rstrip("/") + sample[1].rstrip("/"),
            raw_fr / "sample.json", wordlist,
            threads=int(r_cfg.get("threads", 40)),
            recursion=False,
            match_status=[str(s) for s in (r_cfg.get("match_status") or [])],
            filter_status=[str(s) for s in (r_cfg.get("filter_status") or [])],
        )
        return make_result(
            stage, "skipped", outputs=outputs, count=0, error="dry-run",
            extra={"planned_cmd": planned, "targets": len(work),
                   "wordlist": str(wordlist) if wordlist else None, **stats})

    if not runner.tool_available("ffuf"):
        write_lines(proc_out, [])
        return make_result(stage, "skipped", outputs=outputs, count=0,
                           error="ffuf binary not found (optional, skipped)")
    if wordlist is None:
        write_lines(proc_out, [])
        return make_result(stage, "skipped", outputs=outputs, count=0,
                           error="no wordlist resolved (SecLists missing?)")
    if not work:
        write_lines(proc_out, [])
        return make_result(stage, "success", outputs=outputs, count=0,
                           error="no discovered directories to recurse into",
                           extra=stats)

    if stats.get("selection", {}).get("deduped") or stats.get("dirs_capped"):
        print(console.phase_info_line(
            f"[{stage}] {stats['dirs_found']} dir(s) trên "
            f"{stats['hosts_with_dirs']} host → fuzz {stats['dirs_selected']} "
            f"dir trên {stats.get('hosts_selected', 0)} host đại diện"))

    threads = int(r_cfg.get("threads", 40))
    per_target_timeout = int(r_cfg.get("timeout", 600))
    concurrency = max(1, int(r_cfg.get("concurrency", 3)))
    rate = int(r_cfg.get("rate", 0) or 0)
    match_status = [str(s) for s in (r_cfg.get("match_status")
                                     or [200, 204, 301, 302, 307, 401, 403])]
    filter_status = [str(s) for s in (r_cfg.get("filter_status") or [404, 429])]
    filter_regex = str(r_cfg.get("filter_regex") or "")
    extensions = list(r_cfg.get("extensions") or [])

    # Tech-aware extensions per host (B2), same signal as the stage-4 fuzzers.
    detail = load_json(layout.path(output_dir, "alive_detail.json"))
    by_url = {r["url"].strip(): r for r in (detail if isinstance(detail, list) else [])
              if isinstance(r, dict) and r.get("url")}
    ext_aware = bool(r_cfg.get("tech_aware_extensions", True))

    budget = int(r_cfg.get("budget_seconds", 1800) or 0)
    deadline = time.monotonic() + budget if budget > 0 else None

    results: dict[str, list[behavior.Behavior]] = {}
    failures: list[str] = []
    skipped_over_budget: list[str] = []

    def _run_one(item: tuple[str, str]) -> None:
        host, directory = item
        key = host.rstrip("/") + directory
        if deadline is not None and time.monotonic() >= deadline:
            skipped_over_budget.append(key)
            return
        exts = list(extensions)
        if ext_aware:
            for e in fuzz_depth.tech_exts_for(fuzz_depth._matched_ext_keys(by_url.get(host, {}))):
                if e not in exts:
                    exts.append(e)
        report_path = raw_fr / ffuf.report_name(key)
        host_timeout = per_target_timeout
        if deadline is not None:
            host_timeout = min(per_target_timeout,
                               max(1, int(deadline - time.monotonic())))
        cmd = ffuf._build_cmd(
            key.rstrip("/"), report_path, wordlist,
            threads=threads,
            autocalibration=True, autocalibration_per_host=True,
            recursion=False,          # we already enumerate the roots ourselves
            follow_redirects=False,
            rate=rate,
            match_status=match_status, filter_status=filter_status,
            filter_regex=filter_regex, extensions=exts,
        )
        r = runner.run(cmd, stage=stage, output_dir=output_dir,
                       timeout=host_timeout, log_name=stage)
        if not r["success"] and not report_path.exists():
            failures.append(f"{key}: {(r['stderr'] or 'failed').strip()[:100]}")
            return
        text = report_path.read_text(errors="ignore") if report_path.exists() else ""
        results[key] = ffuf.parse_report(text)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(_run_one, work))

    # Behavioural screen per target — same guard ffuf uses against a root
    # that answers every path identically.
    scr_cfg = r_cfg.get("screen") or {}
    screen_on = bool(scr_cfg.get("enabled", True))
    urls: list[str] = []
    seen: set[str] = set()
    raw_lines: list[str] = []
    dropped_total = 0
    for key, hits in results.items():
        if screen_on and hits:
            v = behavior.screen(
                hits,
                min_cluster=int(scr_cfg.get("min_cluster", 25)),
                min_share=float(scr_cfg.get("min_share", 0.5)),
                length_tolerance=int(scr_cfg.get("length_tolerance", 16)))
            kept = v.kept
            dropped_total += v.n_dropped
        else:
            kept = hits
        for b in kept:
            raw_lines.append(f"{b.status} {b.length} {b.url}")
            if b.url not in seen:
                seen.add(b.url)
                urls.append(b.url)

    write_lines(raw_fr / "fuzz_recurse_raw.txt", raw_lines)
    n = write_lines(proc_out, urls)

    if n:
        print(console.phase_info_line(
            f"[{stage}] +{n} URL dưới directory đã biết "
            f"(bỏ {dropped_total} hit lặp response)"))
    if skipped_over_budget:
        print(console.phase_info_line(
            f"[{stage}] hết ngân sách {budget}s — bỏ qua "
            f"{len(skipped_over_budget)} target còn lại"))

    attempted = len(work) - len(skipped_over_budget)
    status = "failed" if attempted and len(failures) == attempted else "success"
    return make_result(
        stage, status, outputs=outputs, count=n,
        error="; ".join(failures)[:300] if status == "failed" else None,
        extra={
            **stats,
            "wordlist": str(wordlist),
            "failed_targets": len(failures),
            "skipped_over_budget": len(skipped_over_budget),
            "budget_seconds": budget,
            "screen": {"enabled": screen_on, "dropped": dropped_total, "kept": n},
        },
    )
