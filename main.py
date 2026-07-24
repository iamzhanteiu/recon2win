#!/usr/bin/env python3
"""recon-agent — automated recon framework.

Usage:
  python3 main.py -d example.com --config config.yml
  python3 main.py -d example.com --resume
  python3 main.py -d example.com --dry-run
  python3 main.py -d example.com --skip-nuclei --skip-dirsearch --skip-ffuf --skip-waymore
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from modules import (
    arjun as arjun_mod,
    audit as audit_mod,
    content_discovery as cd_mod,
    console,
    dirsearch as dirsearch_mod,
    doctor as doctor_mod,
    dnsx as dnsx_mod,
    ffuf as ffuf_mod,
    graphgen as graphgen_mod,
    httpx as httpx_mod,
    jsluice as jsluice_mod,
    nuclei as nuclei_mod,
    priority as priority_mod,
    progress as progress_mod,
    responses as responses_mod,
    scandiff as scandiff_mod,
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
    "ffuf":              "urls",
    "waymore":           "urls",
    "nuclei_default":    "findings",
    "url_merge":         "urls",
    "url_merge_append":  "urls",
    "httpx_urls":        "alive urls",
    "xnlinkfinder":      "endpoints+urls",
    "jsluice":           "endpoints+urls",
    "arjun":             "parameterized urls",
    "nuclei_endpoints":  "findings",
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
    p.add_argument("-d", "--domain",
                   help="Target domain (e.g. example.com). Optional when using "
                        "--h1-program (the target comes from the chosen H1 scope).")
    p.add_argument("--config", default="config.yml", help="Path to YAML config")
    p.add_argument("--h1-list", action="store_true",
                   help="Browse your HackerOne programs, pick one, then pick an "
                        "in-scope root and recon it (lists & exits when piped)")
    p.add_argument("--h1-program", metavar="HANDLE",
                   help="Skip the program picker: pull in-scope roots for this "
                        "handle, pick one, and recon it")
    p.add_argument("--resume", action="store_true",
                   help="Skip stages whose expected outputs already exist")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the plan and exit; never invoke external tools")
    p.add_argument("--doctor", action="store_true",
                   help="Preflight check: report installed tools, configured "
                        "API keys and wordlists, then exit (no scan).")
    p.add_argument("--skip-nuclei", action="store_true")
    p.add_argument("--skip-dirsearch", action="store_true")
    p.add_argument("--skip-ffuf", action="store_true")
    p.add_argument("--skip-waymore", action="store_true")
    p.add_argument("--skip-arjun", action="store_true")
    p.add_argument("--skip-xnlinkfinder", action="store_true")
    p.add_argument("--skip-jsluice", action="store_true")
    p.add_argument("--skip-responses", action="store_true",
                   help="Skip capturing full responses for ffuf/dirsearch hits.")
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

    # Make user-installed tools (~/.local/bin, ~/go/bin, ~/.pdtm/go/bin)
    # reachable before anything shells out — see _augment_path.
    _added_paths = _augment_path()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"[!] config not found: {cfg_path}", file=sys.stderr)
        return 2
    cfg = _load_config(cfg_path)

    # ---- preflight doctor (--doctor: full report + exit) ----
    if args.doctor:
        return doctor_mod.run(cfg, added_paths=_added_paths)

    # Brief auto-preflight: one warning line if something's missing, so a
    # crippled run is obvious up front instead of only in the logs. Never
    # blocks — run `--doctor` for the full report.
    if not args.dry_run:
        _pf = doctor_mod.summarise(cfg)
        if _pf["missing_required"]:
            print(console.phase_info_line(
                "⚠ REQUIRED tools missing: "
                + ", ".join(_pf["missing_required"])
                + " — run `--doctor`. Scan will be crippled."))
        if _pf["missing_optional"]:
            print(console.phase_info_line(
                "optional tools missing (stages will skip): "
                + ", ".join(_pf["missing_optional"])))

    # ---- HackerOne integration (optional) ----
    # One seamless flow: --h1-list lists your programs, lets you pick one,
    # then picks an in-scope root and drops straight into recon. --h1-program
    # skips the program picker (you already know the handle). Either way the
    # chosen root becomes the recon target, exactly like -d DOMAIN.
    handle: str | None = args.h1_program
    if args.h1_list:
        handle, rc = _h1_choose_program(cfg)
        # No handle chosen: either an error (rc=2) or a benign list-and-quit
        # / non-interactive listing (rc=0). Nothing to recon → exit.
        if handle is None:
            return rc

    if handle:
        raw_domain = _h1_pick_root(cfg, handle)
        if raw_domain is None:
            return 2
    elif args.domain:
        raw_domain = args.domain
    else:
        print("[!] no target: pass -d DOMAIN, or --h1-program HANDLE, "
              "or --h1-list to browse and pick a HackerOne program",
              file=sys.stderr)
        return 2

    try:
        domain = validate_domain(raw_domain)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

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

    # Refresh nuclei templates once, before any nuclei scan runs (stale
    # templates miss recent CVEs). Non-fatal; opt-out via config / --skip-nuclei.
    tpl = nuclei_mod.update_templates(output_dir, cfg, skip=args.skip_nuclei)
    if tpl["status"] == "success":
        print(console.phase_info_line("nuclei: templates updated"))
    elif tpl.get("error") and tpl["status"] == "failed":
        print(console.phase_info_line(f"nuclei: template update failed — {tpl['error']}"))

    # Total phases for the progress bar. Counts every distinct step the
    # operator sees in the workflow — sequential phases plus each parallel
    # group counted as one (the sub-stages are reported as rows within
    # the parallel() context manager).
    prog = progress_mod.ReconProgress(n_phases=12)

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

        # ---- 4. parallel: katana/urlfinder + dirsearch + ffuf + waymore + nuclei default ----
        prog.start_phase("content_discovery (and 4 others)", num=4)
        from concurrent.futures import ThreadPoolExecutor
        par_results: dict[str, dict] = {}
        with prog.parallel(
            ["content_discovery", "dirsearch", "ffuf", "waymore", "nuclei_default"],
            num=4,
        ):
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = {
                    pool.submit(_run_stage, "content_discovery", cd_mod.crawl,
                                alive_file, output_dir, cfg,
                                resume=args.resume, dry_run=False): "content_discovery",
                    pool.submit(_run_stage, "dirsearch", dirsearch_mod.scan,
                                alive_file, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_dirsearch): "dirsearch",
                    pool.submit(_run_stage, "ffuf", ffuf_mod.scan,
                                alive_file, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_ffuf): "ffuf",
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
                       output_dir, domain, cfg,
                       resume=args.resume, dry_run=False)
        results.append(r)
        _sd = (r.get("extra") or {}).get("scope_dropped")
        if _sd:
            print(console.phase_info_line(
                f"scope filter: dropped {_sd} out-of-scope URL(s) from "
                f"all_urls.txt (out-of-scope .js kept for JS analysis)"
            ))
        _pc = (r.get("extra") or {}).get("param_collapsed")
        if _pc:
            print(console.phase_info_line(
                f"param collapse: folded {_pc} value-only URL variant(s) "
                f"(kept keyword values like ?action=delete distinct)"
            ))
        prog.finish_phase(r, num=5)

        # ---- 5.post: body preview for ffuf/dirsearch hits ----
        # ffuf/dirsearch only record status+URL; re-request each hit with
        # httpx -bp to grab a short body preview (no full bodies stored) →
        # responses/index.md. Runs before the report so the preview can be
        # surfaced there. Skips cleanly when there are no hits.
        rr = _run_stage(
            "responses", responses_mod.collect, output_dir, cfg,
            resume=args.resume, dry_run=False, skip=args.skip_responses,
        )
        results.append(rr)
        _rc = rr.get("extra") or {}
        if _rc.get("fetched"):
            print(console.phase_info_line(
                f"previewed {_rc['fetched']} hit(s) → responses/index.md"
                + (f"; {_rc['capped']} skipped by cap" if _rc.get("capped") else "")
            ))

        # ---- 6. parallel: httpx URL check + xnLinkFinder + jsluice ----
        prog.start_phase("httpx_urls (and 2 others)", num=6)
        all_urls_file = output_dir / "processed" / "all_urls.txt"
        js_urls_file = output_dir / "processed" / "js_urls.txt"
        par6: dict[str, dict] = {}
        with prog.parallel(["httpx_urls", "xnlinkfinder", "jsluice"], num=6):
            with ThreadPoolExecutor(max_workers=3) as pool:
                futures = {
                    pool.submit(_run_stage, "httpx_urls", httpx_mod.check_urls,
                                all_urls_file, output_dir, cfg,
                                resume=args.resume, dry_run=False): "httpx_urls",
                    pool.submit(_run_stage, "xnlinkfinder", xnlinkfinder_mod.scan,
                                js_urls_file, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_xnlinkfinder): "xnlinkfinder",
                    pool.submit(_run_stage, "jsluice", jsluice_mod.scan,
                                js_urls_file, output_dir, cfg,
                                resume=args.resume, dry_run=False,
                                skip=args.skip_jsluice): "jsluice",
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

        # ---- 6.post: merge xnlinkfinder + jsluice URLs back into all_urls.txt ----
        # Both JS tools (regex + AST) feed their endpoints/urls here so they
        # get httpx-probed + nuclei-scanned, and any parameterised ones flow
        # on to arjun (stage 7) via the re-derived dynamic_urls.txt.
        prog.start_phase("url_merge_append", num=7)
        merge_candidates = [
            output_dir / "processed" / "xnlinkfinder_endpoints.txt",
            output_dir / "processed" / "xnlinkfinder_urls.txt",
            output_dir / "processed" / "jsluice_endpoints.txt",
            output_dir / "processed" / "jsluice_urls.txt",
        ]
        extras = [p for p in merge_candidates if p.exists() and p.stat().st_size > 0]
        if extras:
            r = _run_stage(
                "url_merge_append", url_merge_mod.append_urls,
                output_dir, extras, domain, cfg,
            )
            results.append(r)
            prog.finish_phase(r, num=7)
        else:
            prog.finish_phase(
                make_result("url_merge_append", "skipped", count=0,
                            error="no xnlinkfinder/jsluice output to merge"),
                num=7,
            )

        # ---- 6.post.b: mine new in-scope subdomains from collected URLs ----
        # Archived/crawled URLs often reference hosts passive enum missed.
        subs = url_merge_mod.derive_subdomains_from_urls(output_dir, domain)
        results.append(subs)
        if subs["count"]:
            print(console.phase_info_line(
                f"url-derived: +{subs['count']} new in-scope subdomain(s) "
                f"→ processed/url_derived_subdomains.txt"
            ))

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

        # ---- 7.post: enrich nuclei_dynamic input with jsluice's param intel ----
        # jsluice extracted {url, method, queryParams, bodyParams} via AST.
        # Feed those param-rich URLs (incl. POST/JSON params arjun never sees,
        # and anything past arjun's cap) straight into parameterized_urls.txt.
        # Safe/additive even when arjun was skipped or found nothing.
        merged = jsluice_mod.merge_params_into_nuclei_input(output_dir)
        results.append(merged)
        if merged["count"]:
            print(console.phase_info_line(
                f"jsluice: +{merged['count']} param URL(s) → nuclei_dynamic "
                f"(now {merged['extra']['total']} total)"
            ))

        # ---- 7.post.b: seed already-parameterized URLs (arjun-independent) ----
        # URLs that already carry ?a=1 in the crawl/waymore output are prime
        # injection targets; without this they only reach nuclei_dynamic if
        # arjun re-discovers them (so --skip-arjun / cap / failure = no scan).
        seeded = url_merge_mod.seed_parameterized_urls(output_dir)
        results.append(seeded)
        if seeded["count"]:
            print(console.phase_info_line(
                f"seed: +{seeded['count']} already-param URL(s) → nuclei_dynamic "
                f"(now {seeded['extra']['total']} total)"
            ))

        # ---- 8. nuclei on discovered endpoints (alive_urls.txt) ----
        # Closes the coverage gap: default_scan only saw the root hosts
        # (it ran in parallel with discovery). Scan the live-verified
        # discovered URLs so crawled/dirsearch/jsluice endpoints get a pass.
        prog.start_phase("nuclei_endpoints", num=9)
        alive_urls_file = output_dir / "processed" / "alive_urls.txt"
        r = _run_stage(
            "nuclei_endpoints", nuclei_mod.endpoints_scan,
            alive_urls_file, output_dir, cfg,
            resume=args.resume, dry_run=False, skip=args.skip_nuclei,
        )
        results.append(r)
        prog.finish_phase(r, num=9)

        # ---- 9. nuclei dynamic ----
        prog.start_phase("nuclei_dynamic", num=10)
        param_urls_file = output_dir / "processed" / "parameterized_urls.txt"
        r = _run_stage(
            "nuclei_dynamic", nuclei_mod.dynamic_scan,
            param_urls_file, output_dir, cfg,
            resume=args.resume, dry_run=False, skip=args.skip_nuclei,
        )
        results.append(r)
        pf = (r.get("extra") or {}).get("param_filter")
        if pf and (pf.get("dropped_no_param") or pf.get("deduped") or pf.get("capped")):
            print(console.phase_info_line(
                f"nuclei_dynamic: {pf.get('input', 0)} URL(s) → "
                f"-{pf.get('dropped_no_param', 0)} non-param "
                f"-{pf.get('deduped', 0)} dup-shape "
                f"-{pf.get('capped', 0)} over-cap → "
                f"{pf.get('selected', 0)} scanned"
            ))
        prog.finish_phase(r, num=10)

        # ---- 10. final summary (no _run_stage wrapper — synthesised) ----
        prog.start_phase("summary", num=11)
        summary = _build_final_summary(domain, output_dir)
        results.append(summary)
        prog.finish_phase(summary, num=11)

        # ---- 11. generate the final report (HTML + MD + JSON) ----
        prog.start_phase("report", num=12)
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
        prog.finish_phase(report_result, num=12)

        # ---- 10.post: distil everything into a ranked priority list ----
        # One file the operator opens first: report/priority_targets.txt.
        prio = priority_mod.build_priority_targets(output_dir, domain)
        results.append(prio)

        # ---- 10.post.b: diff vs the previous scan → report/delta.md ----
        # "What's new since last time" — the point of repeated recon.
        delta = scandiff_mod.build_scan_diff(output_dir, domain)
        results.append(delta)

        # ---- 10.post.c: provenance graph → report/graph.mmd + SVG in HTML ----
        # One picture of the whole funnel with real counts on every node.
        graph = graphgen_mod.build_output_graph(output_dir, domain)
        results.append(graph)

        # ---- 10.post.d: reviewer's map → INDEX.md ----
        # Groups every artefact into review / intermediate / raw / empty so
        # opening outputs/<domain>/ makes it obvious what to read first. The
        # processed/ tree is mostly derived slices of all_urls.txt; INDEX
        # spells that out. Deep overlap on demand: python3 -m modules.audit.
        index = audit_mod.build_index(output_dir, domain)
        results.append(index)

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
    print(console.kv("priority    ", str(output_dir / "report" / "priority_targets.txt"),
                     value_color="bright_cyan"))
    print(console.kv("delta       ", str(output_dir / "report" / "delta.md"),
                     value_color="bright_cyan"))
    print(console.kv("graph       ", str(output_dir / "report" / "graph.mmd"),
                     value_color="bright_cyan"))
    print(console.kv("index       ", str(output_dir / "INDEX.md"),
                     value_color="bright_cyan"))
    print(console.kv("output dir  ", str(output_dir), value_color="bright_cyan"))

    # One-line "what changed since last scan" summary.
    dx = delta.get("extra") or {}
    if dx.get("first_run"):
        print(console.phase_info_line("delta: first scan — baseline established"))
    else:
        n = dx.get("new") or {}
        print(console.phase_info_line(
            f"delta since last scan: +{n.get('findings', 0)} findings, "
            f"+{n.get('subdomains', 0)} subdomains, "
            f"+{n.get('alive', 0)} alive, +{n.get('urls', 0)} urls"
        ))

    # Echo the top priority targets so the operator sees "test these first"
    # without opening a file. Full ranked list is in priority_targets.txt.
    top = (prio.get("extra") or {}).get("top") or []
    if top:
        print()
        print(console.phase_header("top priority targets"))
        for t in top:
            reasons = "; ".join(t["reasons"][:3])
            print(console.c(f"  [{t['score']:>5}] ", "bright_yellow")
                  + console.c(t["url"], "bright_white")
                  + console.c(f"  — {reasons}", "bright_black"))
    return 0


# ----------------------------------------------------------------------
# Config loading (config.yml + optional config.local.yml overlay)
# ----------------------------------------------------------------------
def _augment_path() -> list[str]:
    """Prepend common user tool dirs to ``$PATH`` so subprocesses find tools
    installed via ``go install`` (~/go/bin), pip --user / pipx (~/.local/bin)
    and the ProjectDiscovery tool manager (~/.pdtm/go/bin) — even when the
    scan runs from cron / an IDE with a minimal PATH. This is the root cause
    fix for waymore/arjun/xnlinkfinder/gau silently skipping as "binary not
    found" despite being installed. Returns the dirs actually added.
    """
    import os
    home = Path.home()
    candidates = [home / ".local" / "bin", home / "go" / "bin",
                  home / ".pdtm" / "go" / "bin"]
    gopath = os.environ.get("GOPATH")
    if gopath:
        candidates.append(Path(gopath) / "bin")
    gobin = os.environ.get("GOBIN")
    if gobin:
        candidates.append(Path(gobin))

    current = os.environ.get("PATH", "").split(os.pathsep)
    seen = set(current)
    added: list[str] = []
    for c in candidates:
        cs = str(c)
        if cs not in seen and c.is_dir():
            added.append(cs)
            seen.add(cs)
    if added:
        os.environ["PATH"] = os.pathsep.join(added + current)
    return added


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge ``overlay`` over ``base`` (overlay wins)."""
    out = dict(base)
    for k, v in (overlay or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _resolve_env_vars(val):
    import os
    import re
    if isinstance(val, dict):
        return {k: _resolve_env_vars(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_resolve_env_vars(v) for v in val]
    elif isinstance(val, str):
        # Resolve ${VAR_NAME} or ${VAR_NAME:-default}
        pattern = re.compile(r'\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}')
        def repl(match):
            name = match.group('name')
            default = match.group('default')
            if default is None:
                default = ""
            return os.environ.get(name, default)
        
        # Also support bare $VAR_NAME if it constitutes the entire string
        if val.startswith("$") and not val.startswith("${"):
            bare_name = val[1:]
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', bare_name):
                return os.environ.get(bare_name, "")
                
        return pattern.sub(repl, val)
    return val


def _load_config(cfg_path: Path) -> dict:
    """Load ``config.yml`` and overlay a sibling ``config.local.yml`` if present.

    ``config.local.yml`` is git-ignored — the right place for secrets like
    the HackerOne API token or a real Telegram bot token.
    """
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    local = cfg_path.with_name("config.local.yml")
    if local.exists():
        overlay = yaml.safe_load(local.read_text(encoding="utf-8")) or {}
        if isinstance(overlay, dict):
            cfg = _deep_merge(cfg, overlay)
    return _resolve_env_vars(cfg)


# ----------------------------------------------------------------------
# HackerOne helpers
# ----------------------------------------------------------------------
def _prompt_index(count: int, prompt: str, *, default: int | None) -> int | None:
    """Read a 1-based selection from stdin and return the 0-based index.

    ``default`` is returned for empty input / EOF (pass ``None`` to make an
    empty answer mean "abort", or ``0`` to default to the first item).
    Returns ``None`` on an invalid or out-of-range answer.
    """
    try:
        choice = input(prompt).strip()
    except EOFError:
        choice = ""
    if not choice:
        return default
    try:
        idx = int(choice) - 1
    except ValueError:
        print(f"[!] invalid choice: {choice!r}", file=sys.stderr)
        return None
    if not (0 <= idx < count):
        print(f"[!] choice out of range: {choice}", file=sys.stderr)
        return None
    return idx


def _h1_choose_program(cfg: dict) -> tuple[str | None, int]:
    """List the operator's HackerOne programs and (in a TTY) pick one to recon.

    Returns ``(handle, exit_code)``:
      * ``(handle, 0)``  — a program was chosen; recon it.
      * ``(None, 0)``    — nothing to recon on purpose: listed & quit, or a
                           non-interactive shell (piped) so we just print the
                           list + hint and let the caller exit cleanly.
      * ``(None, 2)``    — an error (bad credentials / API failure).
    """
    from modules import hackerone as h1
    try:
        user, token = h1.get_credentials(cfg)
        programs = h1.list_programs(user, token)
    except h1.H1Error as e:
        print(f"[!] {e}", file=sys.stderr)
        return None, 2
    if not programs:
        print("[!] no programs returned (check your API token / program access).")
        return None, 0
    print(console.phase_header("hackerone programs"))
    for i, pr in enumerate(programs, 1):
        print(f"  {i:>2}. {pr['handle']:<32} {pr['name']}")

    # Piped / non-interactive: keep the classic list-and-exit behaviour so
    # scripts can still enumerate programs without blocking on input().
    if not sys.stdin.isatty():
        print(f"\n{len(programs)} program(s). Recon one with: "
              f"python3 main.py --h1-program <handle>")
        return None, 0

    idx = _prompt_index(
        len(programs),
        f"\nPick a program to recon [1-{len(programs)}] (Enter to quit): ",
        default=None,
    )
    if idx is None:
        return None, 0
    return programs[idx]["handle"], 0


def _h1_pick_root(cfg: dict, handle: str) -> str | None:
    """Fetch in-scope roots for ``handle`` and let the operator pick one.

    Returns the chosen domain string, or ``None`` on error / no selection.
    """
    from modules import hackerone as h1
    try:
        user, token = h1.get_credentials(cfg)
        roots = h1.roots_for_program(user, token, handle)
    except h1.H1Error as e:
        print(f"[!] {e}", file=sys.stderr)
        return None
    if not roots:
        print(f"[!] no in-scope URL/WILDCARD assets found for '{handle}'.",
              file=sys.stderr)
        return None
    print(console.phase_header(f"in-scope roots — {handle}"))
    for i, d in enumerate(roots, 1):
        print(f"  {i:>2}. {d}")
    # A single in-scope root needs no prompt — just recon it.
    if len(roots) == 1:
        return roots[0]
    idx = _prompt_index(
        len(roots),
        f"\nPick a target [1-{len(roots)}] (default 1): ",
        default=0,
    )
    if idx is None:
        return None
    return roots[idx]


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
        ("skip-ffuf     ", args.skip_ffuf),
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
        "  4  PARALLEL: katana/urlfinder + dirsearch + ffuf + waymore + nuclei-default",
        "  5  url_merge (crawler + dirsearch + ffuf + waymore -> all_urls / js_urls / dynamic_urls)",
        "  6  PARALLEL: httpx url check + xnLinkFinder + jsluice -> re-merge",
        "  7  arjun on dynamic_urls (+ seed already-param + jsluice params)",
        "  8  nuclei endpoints on alive_urls (discovered)",
        "  9  nuclei dynamic on parameterized_urls",
        " 10  final telegram summary + report + priority + delta",
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
        f"• ffuf: `{counts.get('ffuf', 0)}`\n"
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
    findings_default = load_json(output_dir / "findings" / "default" / "nuclei.json") or {}
    findings_endpoints = load_json(output_dir / "findings" / "endpoints" / "nuclei.json") or {}
    findings_dynamic = load_json(output_dir / "findings" / "dynamic" / "nuclei.json") or {}
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
            "nuclei_endpoints_findings_by_severity":
                findings_endpoints.get("severity_count", {}),
            "nuclei_dynamic_findings_by_severity":
                findings_dynamic.get("severity_count", {}),
            "output_folder": str(output_dir),
        },
    )


if __name__ == "__main__":
    sys.exit(main())
