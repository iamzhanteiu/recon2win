#!/usr/bin/env python3
"""recon-agent — automated recon framework.

Usage:
  python3 main.py -d example.com --config config.yml
  python3 main.py -d example.com --resume
  python3 main.py -d example.com --dry-run
  python3 main.py -d example.com --skip-nuclei --skip-dirsearch --skip-waymore --skip-arjun
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from modules import (
    arjun as arjun_mod,
    content_discovery as cd_mod,
    console,
    dirsearch as dirsearch_mod,
    dnsx as dnsx_mod,
    httpx as httpx_mod,
    nuclei as nuclei_mod,
    progress as progress_mod,
    report as report_mod,
    subdomain as sub_mod,
    telegram,
    url_merge as url_merge_mod,
    waymore as waymore_mod,
    xnlinkfinder as xnlinkfinder_mod,
)
from modules.utils import (
    create_output_structure,
    load_json,
    make_result,
    read_lines,
    validate_domain,
)


# Noun used by ``phase_status_line`` — most stages count "results",
# but a few are more meaningful with a domain-specific noun.
_STAGE_NOUN: dict[str, str] = {
    "subdomain":         "subdomains",
    "dnsx":              "resolved",
    "httpx_alive":       "alive hosts",
    "content_discovery": "urls",
    "dirsearch":         "urls",
    "waymore":           "urls",
    "nuclei_default":    "findings",
    "url_merge":         "urls",
    "url_merge_append":  "urls",
    "httpx_urls":        "alive urls",
    "xnlinkfinder":      "endpoints+urls",
    "arjun":             "parameterized urls",
    "nuclei_dynamic":    "findings",
    "report":            "artifacts",
}


# ----------------------------------------------------------------------
# Stage runner with consistent logging
# ----------------------------------------------------------------------
def _run_stage(name: str, fn, *args, **kwargs) -> dict:
    """Run a single stage, render its result, and notify (console + telegram).

    Stage call convention: positional args are typically
    ``(input_path, output_dir, cfg, ...)``. We pull ``output_dir`` and
    ``cfg`` out by position so we can:
      * print where the artefacts were saved (relative paths),
      * send a per-stage Telegram notification if configured.
    """
    # Pull metadata out of the positional args by convention. Most stage
    # functions receive ``(input_path, output_dir, cfg, ...)``; the
    # exceptions (e.g. ``_build_final_summary``) have output_dir in
    # ``extra["output_folder"]`` so we fall back to that.
    output_dir: Path | None = None
    cfg: dict = {}
    if len(args) >= 2 and isinstance(args[1], Path):
        output_dir = args[1]
    if len(args) >= 3 and isinstance(args[2], dict):
        cfg = args[2]

    print(console.phase_header(name), flush=True)
    t0 = time.time()
    try:
        res = fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        res = make_result(name, "failed", error=f"exception: {exc}")
    dt = round(time.time() - t0, 2)
    res.setdefault("extra", {})["elapsed_seconds"] = dt
    noun = _STAGE_NOUN.get(name, "results")
    # ``success`` stages: green ✓ + result line.
    # ``failed`` stages: red ✗ + result line + the error message below.
    # ``skipped`` stages: yellow ⊘ + brief status — we fold the error
    # message into the noun so the output stays one short line.
    print(
        console.phase_status_line(name, res["status"], res["count"], dt, noun=noun),
        flush=True,
    )
    err = res.get("error")
    if err and res["status"] != "skipped":
        print(console.phase_error_line(err), flush=True)
    elif err and res["status"] == "skipped":
        # Skip the separate "!" line for skipped stages; the error is
        # already informative (e.g. "no alive hosts to scan").
        print(console.phase_info_line(err), flush=True)

    # Show where the artefacts landed (relative paths, one per line).
    # The operator can scroll back to see "what did this stage produce?".
    if output_dir is not None:
        for line in console.phase_outputs(res, output_dir):
            print(line, flush=True)

    # Per-stage Telegram notification (opt-in via telegram.per_phase).
    telegram.notify_phase_complete(
        name, res, cfg.get("telegram") or {}, output_dir=output_dir,
    )

    # In dry-run, every stage that built a planned command attaches it
    # to ``extra['planned_cmd']`` (see modules/dirsearch.py and friends).
    # Print it so the operator can sanity-check the argv without grepping
    # through Python.
    planned = (res.get("extra") or {}).get("planned_cmd")
    if planned:
        print(console.cmd_echo(name, planned), flush=True)
    return res


# ----------------------------------------------------------------------
# Main orchestration
# ----------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(
        prog="recon-agent",
        description="Automated recon framework — follow the recon diagram.",
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("--config", default="config.yml", help="Path to YAML config")
    p.add_argument("--resume", action="store_true",
                   help="Skip stages whose expected outputs already exist")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the plan and exit; never invoke external tools")
    p.add_argument("--skip-nuclei", action="store_true")
    p.add_argument("--skip-dirsearch", action="store_true")
    p.add_argument("--skip-waymore", action="store_true")
    p.add_argument("--skip-arjun", action="store_true")
    p.add_argument("--skip-xnlinkfinder", action="store_true")
    p.add_argument("--color", dest="color", action="store_true", default=None,
                   help="Force ANSI colors even when stdout is not a TTY")
    p.add_argument("--no-color", dest="color", action="store_false",
                   help="Disable ANSI colors (overrides $FORCE_COLOR)")
    args = p.parse_args()

    # ---- 0. validate input + create structure ----
    if args.color is True:
        console.set_enabled(True)
    elif args.color is False:
        console.set_enabled(False)
    # else: leave auto-detection alone (TTY / $NO_COLOR / $FORCE_COLOR)

    try:
        domain = validate_domain(args.domain)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"[!] config not found: {cfg_path}", file=sys.stderr)
        return 2
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    output_dir = create_output_structure(
        domain, root=cfg.get("output_root", "outputs"),
    )
    print(console.banner(f"target: {domain}", "bright_cyan"))
    print(console.banner(f"output: {output_dir}", "bright_cyan"))

    if args.dry_run:
        _print_plan(domain, output_dir, cfg, args)
        return 0

    # Capture scan timing + tool versions up-front so the final report has
    # accurate metadata even if a later stage crashes.
    scan_start = datetime.now(timezone.utc)
    tool_versions = report_mod.capture_tool_versions()

    # Total phases for the progress bar. Counts every distinct step the
    # operator sees in the workflow — sequential phases plus each parallel
    # group counted as one (the sub-stages are reported as rows within
    # the parallel() context manager).
    prog = progress_mod.ReconProgress(n_phases=11)

    results: list[dict] = []

    with prog:
        # ---- 1. subdomain collection ----
        prog.start_phase("subdomain", num=1)
        r = _run_stage("subdomain", sub_mod.collect,
                       domain, output_dir, cfg,
                       resume=args.resume, dry_run=False)
        results.append(r)
        prog.finish_phase(r, num=1)

        # ---- 2. DNS resolution ----
        prog.start_phase("dnsx", num=2)
        sub_file = output_dir / "processed" / "subdomains.txt"
        r = _run_stage("dnsx", dnsx_mod.resolve,
                       sub_file, output_dir, cfg,
                       resume=args.resume, dry_run=False)
        results.append(r)
        prog.finish_phase(r, num=2)

        # ---- 3. HTTP alive ----
        prog.start_phase("httpx_alive", num=3)
        resolved_file = output_dir / "processed" / "resolved.txt"
        r = _run_stage("httpx_alive", httpx_mod.alive_check,
                       resolved_file, output_dir, cfg,
                       resume=args.resume, dry_run=False)
        results.append(r)
        prog.finish_phase(r, num=3)

        alive_file = output_dir / "processed" / "alive.txt"

        # ------------------------------------------------------------------
        # 2-PASS FALLBACK — if httpx_alive produced 0 alive hosts on the
        # first try (e.g. because the cap of 5000/10000 was too tight
        # and the cap-prioritiser dropped something important), retry
        # the dnsx→httpx_alive chain with a larger cap. Only happens
        # once, only when the user opted in via dnsx.max_resolved_expanded,
        # and only when ``resume=False`` (otherwise we'd be fighting
        # cached results).
        # ------------------------------------------------------------------
        dnsx_cfg = cfg.get("dnsx", {}) if isinstance(cfg, dict) else {}
        first_cap = int(dnsx_cfg.get("max_resolved", 10000))
        expanded_cap = int(dnsx_cfg.get("max_resolved_expanded", 25000))
        if (
            expanded_cap > first_cap
            and not args.resume
            and r.get("status") != "success"
            and (not alive_file.exists() or alive_file.stat().st_size == 0)
        ):
            retry_cfg = {
                **cfg,
                "dnsx": {**dnsx_cfg, "max_resolved": expanded_cap},
            }
            print(
                f"[!] alive.txt empty after first pass (cap={first_cap}). "
                f"Retrying with cap={expanded_cap}…"
            )
            prog.start_phase("dnsx (retry)", num=3)
            r_retry = _run_stage("dnsx", dnsx_mod.resolve,
                                 sub_file, output_dir, retry_cfg,
                                 resume=False, dry_run=False)
            prog.finish_phase(r_retry, num=3)
            results.append(r_retry)
            prog.start_phase("httpx_alive (retry)", num=3)
            r = _run_stage("httpx_alive", httpx_mod.alive_check,
                           resolved_file, output_dir, retry_cfg,
                           resume=False, dry_run=False)
            prog.finish_phase(r, num=3)
            results.append(r)

        # ---- 4. parallel: katana/urlfinder + dirsearch + waymore + nuclei default ----
        prog.start_phase("content_discovery (and 3 others)", num=4)
        from concurrent.futures import ThreadPoolExecutor
        par_results: dict[str, dict] = {}
        with prog.parallel(
            ["content_discovery", "dirsearch", "waymore", "nuclei_default"], num=4,
        ):
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {
                    pool.submit(_run_stage, "content_discovery", cd_mod.crawl,
                                alive_file, output_dir, cfg,
                                resume=args.resume, dry_run=False): "content_discovery",
                    pool.submit(_run_stage, "dirsearch", dirsearch_mod.scan,
                                alive_file, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_dirsearch): "dirsearch",
                    pool.submit(_run_stage, "waymore", waymore_mod.collect,
                                domain, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_waymore): "waymore",
                    pool.submit(_run_stage, "nuclei_default", nuclei_mod.default_scan,
                                alive_file, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_nuclei): "nuclei_default",
                }
                for fut in futures:
                    name = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        res = make_result(name, "failed",
                                          error=f"exception: {exc}")
                    par_results[name] = res
                    prog.subphase_done(name, res)
        results.extend(par_results.values())
        prog.finish_parallel(num=4)

        # ---- 5. merge ----
        prog.start_phase("url_merge", num=5)
        r = _run_stage("url_merge", url_merge_mod.merge,
                       output_dir, resume=args.resume, dry_run=False)
        results.append(r)
        prog.finish_phase(r, num=5)

        # ---- 6. parallel: httpx URL check + xnLinkFinder ----
        prog.start_phase("httpx_urls (and 1 other)", num=6)
        all_urls_file = output_dir / "processed" / "all_urls.txt"
        js_urls_file = output_dir / "processed" / "js_urls.txt"
        par6: dict[str, dict] = {}
        with prog.parallel(["httpx_urls", "xnlinkfinder"], num=6):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = {
                    pool.submit(_run_stage, "httpx_urls", httpx_mod.check_urls,
                                all_urls_file, output_dir, cfg,
                                resume=args.resume, dry_run=False): "httpx_urls",
                    pool.submit(_run_stage, "xnlinkfinder", xnlinkfinder_mod.scan,
                                js_urls_file, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_xnlinkfinder): "xnlinkfinder",
                }
                for fut in futures:
                    name = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        res = make_result(name, "failed",
                                          error=f"exception: {exc}")
                    par6[name] = res
                    prog.subphase_done(name, res)
        results.extend(par6.values())
        prog.finish_parallel(num=6)

        # ---- 6.post: merge xnlinkfinder URLs back into all_urls.txt ----
        prog.start_phase("url_merge_append", num=7)
        ep_file = output_dir / "processed" / "xnlinkfinder_endpoints.txt"
        url_file = output_dir / "processed" / "xnlinkfinder_urls.txt"
        extras = [p for p in (ep_file, url_file) if p.exists() and p.stat().st_size > 0]
        if extras:
            r = _run_stage(
                "url_merge_append", url_merge_mod.append_urls,
                output_dir, extras,
            )
            results.append(r)
            prog.finish_phase(r, num=7)
        else:
            prog.finish_phase(
                make_result("url_merge_append", "skipped", count=0,
                            error="no xnlinkfinder output to merge"),
                num=7,
            )

        # Telegram summary after stage 6
        _send_summary("stage-6", domain, results, cfg, output_dir)

        # ---- 7. arjun on dynamic URLs ----
        prog.start_phase("arjun", num=8)
        dyn_urls_file = output_dir / "processed" / "dynamic_urls.txt"
        r = _run_stage(
            "arjun", arjun_mod.discover,
            dyn_urls_file, output_dir, cfg,
            resume=args.resume, dry_run=False, skip=args.skip_arjun,
        )
        results.append(r)
        prog.finish_phase(r, num=8)

        # ---- 8. nuclei dynamic ----
        prog.start_phase("nuclei_dynamic", num=9)
        param_urls_file = output_dir / "processed" / "parameterized_urls.txt"
        r = _run_stage(
            "nuclei_dynamic", nuclei_mod.dynamic_scan,
            param_urls_file, output_dir, cfg,
            resume=args.resume, dry_run=False, skip=args.skip_nuclei,
        )
        results.append(r)
        prog.finish_phase(r, num=9)

        # ---- 9. final summary (no _run_stage wrapper — synthesised) ----
        prog.start_phase("summary", num=10)
        summary = _build_final_summary(domain, output_dir)
        results.append(summary)
        prog.finish_phase(summary, num=10)

        # ---- 10. generate the final report (HTML + MD + JSON) ----
        prog.start_phase("report", num=11)
        scan_end = datetime.now(timezone.utc)
        cfg_text = ""
        try:
            cfg_text = cfg_path.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            cfg_text = ""

        report_info = report_mod.build_report(
            output_dir, domain, cfg,
            cfg_path=str(cfg_path),
            cfg_text=cfg_text,
            scan_start=scan_start,
            scan_end=scan_end,
            tool_versions=tool_versions,
            stage_results=results,
            scan_mode="active",
        )
        report_result = make_result(
            "report", "success", input_path=output_dir,
            outputs=[report_info["html"], report_info["md"], report_info["json"]],
            count=3, extra=report_info,
        )
        results.append(report_result)
        prog.finish_phase(report_result, num=11)

    # Final Telegram message includes the HTML report path
    _send_summary("final", domain, results, cfg, output_dir, report_info=report_info)

    # persist full stage log
    log_path = output_dir / "logs" / "stages.json"
    log_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print()
    print(console.phase_header("report"))
    print(console.kv("stage log   ", str(log_path), value_color="bright_cyan"))
    print(console.kv("HTML report ", str(report_info["html"]), value_color="bright_cyan"))
    print(console.kv("Markdown    ", str(report_info["md"]), value_color="bright_cyan"))
    print(console.kv("JSON summary", str(report_info["json"]), value_color="bright_cyan"))
    print(console.kv("output dir  ", str(output_dir), value_color="bright_cyan"))
    return 0


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _print_plan(domain: str, output_dir: Path, cfg: dict, args: argparse.Namespace) -> None:
    print(console.phase_header("dry-run plan"))
    for k, v in [
        ("target        ", domain),
        ("output        ", str(output_dir)),
        ("config        ", args.config),
        ("resume        ", args.resume),
        ("skip-nuclei   ", args.skip_nuclei),
        ("skip-dirsearch", args.skip_dirsearch),
        ("skip-waymore  ", args.skip_waymore),
        ("skip-arjun    ", args.skip_arjun),
        ("color enabled ", console.is_enabled()),
    ]:
        print(console.kv(k, v))
    print()
    print(console.c("workflow:", "bright_white", bold=True))
    for step in [
        "  0  validate domain & create output structure",
        "  1  subdomain collection (subfinder + amass + chaos)",
        "  2  dnsx resolve",
        "  3  httpx alive check",
        "  4  PARALLEL: katana/urlfinder + dirsearch + waymore + nuclei-default",
        "  5  url_merge (crawler + dirsearch + waymore -> all_urls / js_urls / dynamic_urls)",
        "  6  PARALLEL: httpx url check + xnLinkFinder -> re-merge",
        "  7  arjun on dynamic_urls",
        "  8  nuclei dynamic on parameterized_urls",
        "  9  final telegram summary",
    ]:
        print(console.c(step, "white"))


def _send_summary(
    tag: str, domain: str, results: list[dict], cfg: dict, output_dir: Path,
    *,
    report_info: dict | None = None,
) -> None:
    tg = cfg.get("telegram") or {}
    if not tg.get("enabled"):
        return
    counts = {r["stage"]: r["count"] for r in results}
    msg = (
        f"📊 *recon-agent [{tag}]* — `{domain}`\n"
        f"• subdomains: `{counts.get('subdomain', 0)}`\n"
        f"• resolved: `{counts.get('dnsx', 0)}`\n"
        f"• alive: `{counts.get('httpx_alive', 0)}`\n"
        f"• crawler URLs: `{counts.get('content_discovery', 0)}`\n"
        f"• dirsearch: `{counts.get('dirsearch', 0)}`\n"
        f"• waymore: `{counts.get('waymore', 0)}`\n"
        f"• all URLs: `{counts.get('url_merge', 0)}`\n"
        f"• httpx urls: `{counts.get('httpx_urls', 0)}`\n"
        f"• xnlinkfinder: `{counts.get('xnlinkfinder', 0)}`\n"
        f"• arjun: `{counts.get('arjun', 0)}`\n"
        f"• nuclei default: `{counts.get('nuclei_default', 0)}`\n"
        f"• nuclei dynamic: `{counts.get('nuclei_dynamic', 0)}`\n"
        f"• output: `{output_dir}`"
    )
    if tag == "final" and report_info:
        msg += f"\n📄 *Final report*: `{report_info.get('html','')}`"
    telegram.notify(msg, tg)


def _build_final_summary(domain: str, output_dir: Path) -> dict:
    findings_default = load_json(output_dir / "findings" / "nuclei_default.json") or {}
    findings_dynamic = load_json(output_dir / "findings" / "nuclei_dynamic.json") or {}
    return make_result(
        "summary", "success", input_path=domain,
        outputs=[output_dir],
        count=0,
        extra={
            "total_subdomains": len(read_lines(output_dir / "processed" / "subdomains.txt")),
            "total_resolved": len(read_lines(output_dir / "processed" / "resolved.txt")),
            "total_alive_hosts": len(read_lines(output_dir / "processed" / "alive.txt")),
            "total_collected_urls": len(read_lines(output_dir / "processed" / "all_urls.txt")),
            "total_js_urls": len(read_lines(output_dir / "processed" / "js_urls.txt")),
            "total_dynamic_urls": len(read_lines(output_dir / "processed" / "dynamic_urls.txt")),
            "total_parameters_discovered": len(
                read_lines(output_dir / "processed" / "parameterized_urls.txt")
            ),
            "nuclei_default_findings_by_severity":
                findings_default.get("severity_count", {}),
            "nuclei_dynamic_findings_by_severity":
                findings_dynamic.get("severity_count", {}),
            "output_folder": str(output_dir),
        },
    )


if __name__ == "__main__":
    sys.exit(main())
