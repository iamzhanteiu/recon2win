#!/usr/bin/env python3
"""jsvh — JavaScript Vulnerability Hunter CLI (analysis layer over recon2win).

This tool NEVER performs reconnaissance. It consumes recon2win's
``outputs/<domain>/`` datasets and produces ranked, verifiable JS
vulnerability candidates.

Commands:
    jsvh.py validate <target>     check the recon2win input contract
    jsvh.py ingest   <target>     build the JS inventory (no analysis)
    jsvh.py run      <target>     full pipeline → candidates + reports
    jsvh.py top      <target>     print the top candidates from last run
    jsvh.py plan     <target> <candidate-id>   print a verification plan

Examples:
    python3 jsvh.py validate omnicell.com
    python3 jsvh.py run omnicell.com --max-assets 100
    python3 jsvh.py run omnicell.com --no-acquire      # analyze already-downloaded
    python3 jsvh.py top omnicell.com
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jsvh import pipeline, verification  # noqa: E402
from jsvh.config import Config, DEFAULT_OUTPUTS  # noqa: E402


def _cfg(args) -> Config:
    cfg = Config(
        target=args.target,
        outputs_dir=Path(args.outputs) if args.outputs else DEFAULT_OUTPUTS,
        project=getattr(args, "project", None),
        acquire=not getattr(args, "no_acquire", False),
        net=getattr(args, "net", False),
        max_assets=getattr(args, "max_assets", 0) or 0,
        workers=getattr(args, "workers", 12),
    )
    if getattr(args, "max_parse", 0):
        cfg.max_parse_bytes = args.max_parse
    return cfg


def cmd_validate(args) -> int:
    cfg = _cfg(args)
    _rd, vr, assets = pipeline.ingest(cfg)
    print(vr.render())
    print(f"\nnormalized JS assets: {len(assets)}")
    return 0 if vr.ok else 2


def cmd_ingest(args) -> int:
    cfg = _cfg(args)
    cfg.ensure_dirs()
    _rd, vr, assets = pipeline.ingest(cfg)
    if not vr.ok:
        print(vr.render()); return 2
    out = cfg.output_dir / "javascript_inventory.json"
    out.write_text(json.dumps({"assets": [a.to_dict() for a in assets]}, indent=2))
    print(f"[+] {len(assets)} JS assets → {out}")
    return 0


def cmd_run(args) -> int:
    cfg = _cfg(args)
    print(f"[*] target={cfg.target}  recon2win outputs={cfg.outputs_dir}", flush=True)
    res = pipeline.run(cfg, do_acquire=cfg.acquire)
    if not res.ok:
        print(res.validation.render())
        print("\n[!] Missing upstream data — recon2win must provide the JS surface first.")
        return 2
    s = res.stats
    print(f"[+] assets={s['assets_total']} acquired={s['assets_acquired']} "
          f"parsed={s['assets_parsed']} (parse-fail={s['assets_parse_failed']})")
    print(f"[+] candidates={s['candidates_total']}  P1={s['p1']} P2={s['p2']} P3={s['p3']}")
    print(f"[+] artifacts → {cfg.output_dir}")
    print()
    print(pipeline.report.top_candidates_text(res.candidates))
    return 0


def cmd_top(args) -> int:
    cfg = _cfg(args)
    p = cfg.output_dir / "TOP_CANDIDATES.txt"
    if not p.exists():
        print("[!] no run found; run `jsvh.py run` first"); return 2
    print(p.read_text())
    return 0


def cmd_plan(args) -> int:
    cfg = _cfg(args)
    p = cfg.output_dir / "vulnerability_candidates.json"
    if not p.exists():
        print("[!] run the pipeline first"); return 2
    data = json.loads(p.read_text())
    from jsvh.models import Candidate
    for cd in data["candidates"]:
        if cd["id"] == args.candidate_id:
            print(verification.plan_for(Candidate(**cd)))
            return 0
    print(f"[!] candidate {args.candidate_id} not found"); return 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="jsvh", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outputs", help="recon2win outputs/ dir (default: ../outputs)")
    ap.add_argument("--project", help="recon2win -p project grouping")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, fn, extra in [
        ("validate", cmd_validate, False),
        ("ingest", cmd_ingest, False),
        ("run", cmd_run, True),
        ("top", cmd_top, False),
    ]:
        sp = sub.add_parser(name)
        sp.add_argument("target")
        if extra:
            sp.add_argument("--no-acquire", action="store_true",
                            help="skip acquisition; analyze already-acquired JS")
            sp.add_argument("--net", action="store_true",
                            help="network-fetch JS not cached by recon2win "
                                 "(default: use recon2win's cached bodies only)")
            sp.add_argument("--max-assets", type=int, default=0)
            sp.add_argument("--max-parse", type=int, default=0,
                            help="AST-parse cap in bytes (default 150000); "
                                 "larger files use the regex fallback")
            sp.add_argument("--workers", type=int, default=12)
        sp.set_defaults(func=fn)

    sp = sub.add_parser("plan")
    sp.add_argument("target")
    sp.add_argument("candidate_id")
    sp.set_defaults(func=cmd_plan)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
