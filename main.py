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
    dirsearch as dirsearch_mod,
    dnsx as dnsx_mod,
    httpx as httpx_mod,
    nuclei as nuclei_mod,
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


# ----------------------------------------------------------------------
# Stage runner with consistent logging
# ----------------------------------------------------------------------
def _run_stage(name: str, fn, *args, **kwargs) -> dict:
    print(f"\n=== {name} ===", flush=True)
    t0 = time.time()
    try:
        res = fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        res = make_result(name, "failed", error=f"exception: {exc}")
    dt = round(time.time() - t0, 2)
    res.setdefault("extra", {})["elapsed_seconds"] = dt
    print(f"    -> {res['status']} (count={res['count']}, {dt}s)", flush=True)
    if res.get("error"):
        print(f"    ! {res['error']}", flush=True)
    # In dry-run, every stage that built a planned command attaches it
    # to ``extra['planned_cmd']`` (see modules/dirsearch.py and friends).
    # Print it so the operator can sanity-check the argv without grepping
    # through Python.
    planned = (res.get("extra") or {}).get("planned_cmd")
    if planned:
        print(f"    $ {' '.join(str(c) for c in planned)}", flush=True)
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
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Echo every external command + its exit code, "
                        "duration, stderr, and the first 20 lines of stdout")
    args = p.parse_args()

    # Toggle the runner's verbose mode once at startup. Every stage that
    # goes through modules.runner.run() will then echo its commands.
    from modules import runner as runner_mod
    runner_mod.set_verbose(args.verbose)

    # ---- 0. validate input + create structure ----
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
    print(f"[+] target: {domain}")
    print(f"[+] output: {output_dir}")

    if args.dry_run:
        _print_plan(domain, output_dir, cfg, args)
        return 0

    # Capture scan timing + tool versions up-front so the final report has
    # accurate metadata even if a later stage crashes.
    scan_start = datetime.now(timezone.utc)
    tool_versions = report_mod.capture_tool_versions()

    results: list[dict] = []

    # ---- 1. subdomain collection ----
    results.append(_run_stage(
        "subdomain", sub_mod.collect,
        domain, output_dir, cfg,
        resume=args.resume, dry_run=False,
    ))

    # ---- 2. DNS resolution ----
    sub_file = output_dir / "processed" / "subdomains.txt"
    results.append(_run_stage(
        "dnsx", dnsx_mod.resolve,
        sub_file, output_dir, cfg,
        resume=args.resume, dry_run=False,
    ))

    # ---- 3. HTTP alive ----
    resolved_file = output_dir / "processed" / "resolved.txt"
    results.append(_run_stage(
        "httpx_alive", httpx_mod.alive_check,
        resolved_file, output_dir, cfg,
        resume=args.resume, dry_run=False,
    ))

    alive_file = output_dir / "processed" / "alive.txt"

    # ---- 4. parallel: katana/urlfinder + dirsearch + waymore + nuclei default ----
    from concurrent.futures import ThreadPoolExecutor
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
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                results.append(make_result(futures[fut], "failed",
                                            error=f"exception: {exc}"))

    # ---- 5. merge ----
    results.append(_run_stage("url_merge", url_merge_mod.merge,
                              output_dir, resume=args.resume, dry_run=False))

    # ---- 6. parallel: httpx URL check + xnLinkFinder ----
    all_urls_file = output_dir / "processed" / "all_urls.txt"
    js_urls_file = output_dir / "processed" / "js_urls.txt"
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
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                results.append(make_result(futures[fut], "failed",
                                            error=f"exception: {exc}"))

    # ---- 6.post: merge xnlinkfinder URLs back into all_urls.txt ----
    ep_file = output_dir / "processed" / "xnlinkfinder_endpoints.txt"
    url_file = output_dir / "processed" / "xnlinkfinder_urls.txt"
    extras = [p for p in (ep_file, url_file) if p.exists() and p.stat().st_size > 0]
    if extras:
        results.append(_run_stage(
            "url_merge_append", url_merge_mod.append_urls,
            output_dir, extras,
        ))

    # Telegram summary after stage 6
    _send_summary("stage-6", domain, results, cfg, output_dir)

    # ---- 7. arjun on dynamic URLs ----
    dyn_urls_file = output_dir / "processed" / "dynamic_urls.txt"
    results.append(_run_stage(
        "arjun", arjun_mod.discover,
        dyn_urls_file, output_dir, cfg,
        resume=args.resume, dry_run=False, skip=args.skip_arjun,
    ))

    # ---- 8. nuclei dynamic ----
    param_urls_file = output_dir / "processed" / "parameterized_urls.txt"
    results.append(_run_stage(
        "nuclei_dynamic", nuclei_mod.dynamic_scan,
        param_urls_file, output_dir, cfg,
        resume=args.resume, dry_run=False, skip=args.skip_nuclei,
    ))

    # ---- 9. final summary ----
    summary = _build_final_summary(domain, output_dir)
    results.append(summary)

    # ---- 10. generate the final report (HTML + MD + JSON) ----
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
    results.append(make_result(
        "report", "success", input_path=output_dir,
        outputs=[report_info["html"], report_info["md"], report_info["json"]],
        count=3, extra=report_info,
    ))

    # Final Telegram message includes the HTML report path
    _send_summary("final", domain, results, cfg, output_dir, report_info=report_info)

    # persist full stage log
    log_path = output_dir / "logs" / "stages.json"
    log_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] stage log    : {log_path}")
    print(f"[+] HTML report  : {report_info['html']}")
    print(f"[+] Markdown     : {report_info['md']}")
    print(f"[+] JSON summary : {report_info['json']}")
    print(f"[+] output dir   : {output_dir}")
    return 0


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _print_plan(domain: str, output_dir: Path, cfg: dict, args: argparse.Namespace) -> None:
    print("\n--- DRY-RUN plan ---")
    print(f"  target         : {domain}")
    print(f"  output         : {output_dir}")
    print(f"  config         : {args.config}")
    print(f"  resume         : {args.resume}")
    print(f"  skip-nuclei    : {args.skip_nuclei}")
    print(f"  skip-dirsearch : {args.skip_dirsearch}")
    print(f"  skip-waymore   : {args.skip_waymore}")
    print(f"  skip-arjun     : {args.skip_arjun}")
    print("  workflow:")
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
        print(step)


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
