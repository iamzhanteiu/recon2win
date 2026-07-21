"""tools/test_subdomain_alive.py — focused smoke test for subdomain
collection + alive check.

Skips content_discovery / dirsearch / waymore / nuclei / arjun /
xnlinkfinder / report — only exercises the first 3 stages
(subdomain, dnsx, httpx_alive). Useful for verifying the fix
in isolation on a local machine before running the full scan on a
VPS.

Usage::

    python3 tools/test_subdomain_alive.py example.com
    python3 tools/test_subdomain_alive.py example.com --max-resolved 200
    python3 tools/test_subdomain_alive.py example.com --no-resume

What it does:
  1. Checks which of {subfinder, amass, chaos, dnsx, httpx} are
     installed and prints the version for each found one. Missing
     tools are reported but do NOT abort — the framework gracefully
     skips missing tools.
  2. Runs subdomain.collect on the target.
  3. Runs dnsx.resolve on the discovered hosts.
  4. Runs httpx.alive_check on the prioritized resolved hosts.
  5. Prints a summary: discovered / resolved / alive counts + the
     output file paths so you can inspect them.

Default target is ``example.com`` (small, safe, has a handful of
known subdomains). Use a bigger target like ``microsoft.com`` to
stress-test the prioritiser, or ``apple.com`` to see the cap kick
in.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Make sure the project root is on sys.path so ``modules.*`` imports work.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import (  # noqa: E402
    console,
    dnsx as dnsx_mod,
    httpx as httpx_mod,
    runner,
    subdomain as sub_mod,
)
from modules.utils import (  # noqa: E402
    create_output_structure,
    read_lines,
)


# ----------------------------------------------------------------------
# Tool detection
# ----------------------------------------------------------------------
TOOLS = ["subfinder", "amass", "chaos", "dnsx", "httpx"]


def print_tool_status() -> dict[str, str]:
    """Print which recon tools are on PATH and return their binary paths.

    Missing tools are reported but do NOT abort — subdomain.collect
    will just skip the missing ones.
    """
    print("=== Tool availability ===")
    found: dict[str, str] = {}
    for t in TOOLS:
        path = runner.which(t)
        if path:
            print(f"  {t:<10} {path}")
            found[t] = path
        else:
            print(f"  {t:<10} NOT FOUND (will skip)")
    print()
    return found


# ----------------------------------------------------------------------
# Stage runners
# ----------------------------------------------------------------------
def run_subdomain(domain: str, output_dir: Path, cfg: dict,
                  *, resume: bool, timeout: int = 900) -> dict:
    """Stage 1 — subdomain enumeration."""
    print("=== Stage 1: subdomain ===")
    t0 = time.time()
    r = sub_mod.collect(
        domain, output_dir, cfg,
        resume=resume, dry_run=False,
    )
    dt = round(time.time() - t0, 2)
    print(f"  → {r['status']} · {r['count']} subdomains · {dt}s")
    if r.get("error"):
        print(f"  ! {r['error']}")
    print(f"  outputs: {r.get('outputs', [])}")
    print()
    return r


def run_dnsx(subdomains_file: Path, output_dir: Path, cfg: dict,
              *, resume: bool) -> dict:
    """Stage 2 — DNS resolution + prioritise."""
    print("=== Stage 2: dnsx ===")
    t0 = time.time()
    r = dnsx_mod.resolve(
        subdomains_file, output_dir, cfg,
        resume=resume, dry_run=False,
    )
    dt = round(time.time() - t0, 2)
    print(f"  → {r['status']} · {r['count']} resolved (raw) · {dt}s")
    kept = (r.get("extra") or {}).get("kept_for_downstream")
    if kept is not None:
        print(f"  → kept for downstream: {kept}")
    if r.get("error"):
        print(f"  ! {r['error']}")
    print(f"  outputs: {r.get('outputs', [])}")
    print()
    return r


def run_httpx_alive(resolved_file: Path, output_dir: Path, cfg: dict,
                     *, resume: bool) -> dict:
    """Stage 3 — httpx alive check."""
    print("=== Stage 3: httpx_alive ===")
    t0 = time.time()
    r = httpx_mod.alive_check(
        resolved_file, output_dir, cfg,
        resume=resume, dry_run=False,
    )
    dt = round(time.time() - t0, 2)
    print(f"  → {r['status']} · {r['count']} alive · {dt}s")
    if r.get("error"):
        print(f"  ! {r['error']}")
    print(f"  outputs: {r.get('outputs', [])}")
    print()
    return r


# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------
def print_summary(domain: str, output_dir: Path,
                  sub_result: dict, dnsx_result: dict, alive_result: dict) -> None:
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  domain        : {domain}")
    print(f"  output dir    : {output_dir}")
    print()
    print(f"  subdomains    : {sub_result['count']}")
    print(f"  resolved      : {dnsx_result['count']}")
    kept = (dnsx_result.get("extra") or {}).get("kept_for_downstream")
    if kept is not None and kept != dnsx_result["count"]:
        print(f"  prioritised   : {kept}  (cap kicked in)")
    print(f"  alive         : {alive_result['count']}")
    print()

    # Show the first few entries of each file for sanity-checking.
    sub_txt = output_dir / "processed" / "subdomains.txt"
    res_txt = output_dir / "processed" / "resolved.txt"
    alive_txt = output_dir / "processed" / "alive.txt"
    for label, path in [
        ("subdomains.txt (first 5)", sub_txt),
        ("resolved.txt   (first 5)", res_txt),
        ("alive.txt      (first 5)", alive_txt),
    ]:
        if path.exists():
            lines = read_lines(path)[:5]
            print(f"  {label}:")
            for ln in lines:
                print(f"    {ln}")
        else:
            print(f"  {label}: <missing>")
        print()

    print("=" * 70)
    if alive_result["count"] == 0:
        print("⚠  0 alive hosts. Common causes:")
        print("   - dnsx failed (check DNS / firewall)")
        print("   - httpx couldn't reach any host (CDN blocking, network issue)")
        print("   - dnsx.max_resolved cap too small (raise in config.yml)")
        print()
        print("Debug:")
        print(f"   cat {output_dir}/logs/dnsx.log")
        print(f"   cat {output_dir}/logs/httpx_alive.log")
    else:
        print(f"✓  {alive_result['count']} alive hosts — subdomain + alive OK")


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(
        prog="test-subdomain-alive",
        description="Focused smoke test for subdomain + dnsx + httpx_alive stages",
    )
    p.add_argument("domain", nargs="?", default="example.com",
                   help="Target domain (default: example.com)")
    p.add_argument("--output-root", default="outputs",
                   help="Where to write outputs (default: outputs/)")
    p.add_argument("--config", default="config.yml",
                   help="Path to config.yml (default: config.yml)")
    p.add_argument("--max-resolved", type=int, default=None,
                   help="Override dnsx.max_resolved for this run only")
    p.add_argument("--no-resume", action="store_true",
                   help="Don't reuse existing outputs (force re-run)")
    p.add_argument("--no-color", action="store_false", dest="color",
                   help="Disable ANSI colors in the output")
    args = p.parse_args()

    # Disable colors for cleaner test output if requested.
    if args.color is False:
        console.set_enabled(False)

    # Load config + apply override.
    import yaml
    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {}
    if args.max_resolved is not None:
        cfg.setdefault("dnsx", {})["max_resolved"] = args.max_resolved

    print_tool_status()

    output_dir = create_output_structure(args.domain, root=args.output_root)
    resume = not args.no_resume

    sub_result = run_subdomain(args.domain, output_dir, cfg, resume=resume)
    if sub_result["count"] == 0:
        print("⚠  0 subdomains — nothing to resolve. Aborting.")
        return 1

    subdomains_file = output_dir / "processed" / "subdomains.txt"
    dnsx_result = run_dnsx(subdomains_file, output_dir, cfg, resume=resume)
    if dnsx_result["count"] == 0:
        print("⚠  0 resolved — nothing to probe. Aborting.")
        return 1

    resolved_file = output_dir / "processed" / "resolved.txt"
    alive_result = run_httpx_alive(resolved_file, output_dir, cfg, resume=resume)

    print_summary(args.domain, output_dir, sub_result, dnsx_result, alive_result)
    return 0


if __name__ == "__main__":
    sys.exit(main())