"""subdomain — stage 1: subfinder + amass + chaos merge & dedupe.

Required: subfinder, amass, chaos (chaos requires PDCP API key).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List

from . import layout, runner
from .utils import (
    make_result,
    raw_dir,
    read_lines,
    write_lines,
)


def _all_outputs_exist(out_dir: Path, tools: List[str]) -> bool:
    base = layout.path(out_dir, "subdomains.txt")
    if not base.exists() or base.stat().st_size == 0:
        return False
    for tool in tools:
        if not (raw_dir(out_dir, "subdomain") / f"{tool}.txt").exists():
            return False
    return True


def collect(
    domain: str,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    """Run subdomain enumeration, merge & dedupe.

    Returns the standard result dict.
    """
    stage = "subdomain"
    raw_sub = raw_dir(output_dir, "subdomain")
    layout.ensure_tree(output_dir)

    tools = cfg.get("subdomain", {}).get("tools", ["subfinder", "amass", "chaos"])
    timeout = int(cfg.get("subdomain", {}).get("timeout", 900))

    if resume and _all_outputs_exist(output_dir, tools):
        existing = read_lines(layout.path(output_dir, "subdomains.txt"))
        return make_result(
            stage, "success", input_path=domain,
            outputs=[layout.path(output_dir, "subdomains.txt")], count=len(existing),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=domain,
            outputs=[raw_sub / f"{t}.txt" for t in tools] + [layout.path(output_dir, "subdomains.txt")],
            count=0, error="dry-run",
        )

    chaos_key = cfg.get("subdomain", {}).get("chaos_api_key", "").strip()

    # All three sub-tools share the same logs/subdomain.log so the
    # reader gets a single chronological view of the stage.
    for tool in tools:
        out_file = raw_sub / f"{tool}.txt"
        if tool == "subfinder":
            if not runner.tool_available("subfinder"):
                print(f"[{stage}] subfinder not installed — skipping")
                out_file.write_text("")
                continue
            r = runner.run(
                ["subfinder", "-d", domain, "-all", "-silent", "-o", str(out_file)],
                stage=f"{stage}_subfinder", log_name=stage,
                output_dir=output_dir, timeout=timeout, capture_stdout=False,
            )
        elif tool == "amass":
            if not runner.tool_available("amass"):
                print(f"[{stage}] amass not installed — skipping")
                out_file.write_text("")
                continue
            r = runner.run(
                ["amass", "enum", "-passive", "-d", domain, "-o", str(out_file)],
                stage=f"{stage}_amass", log_name=stage,
                output_dir=output_dir, timeout=timeout, capture_stdout=False,
            )
        elif tool == "chaos":
            # ProjectDiscovery's `go install .../chaos-client/cmd/chaos@latest`
            # gives a binary literally named ``chaos``, but the Homebrew
            # formula (``brew install chaos-client``) installs it as
            # ``chaos-client`` instead — same tool, same flags, different
            # name. Try both so either install method works.
            if runner.tool_available("chaos"):
                chaos_bin = "chaos"
            elif runner.tool_available("chaos-client"):
                chaos_bin = "chaos-client"
            else:
                print(f"[{stage}] chaos not installed — skipping")
                out_file.write_text("")
                continue
            # chaos hard-fails with "PDCP_API_KEY not specified" when it has
            # no key from either -key or the env var — skip up front instead
            # of burning a subprocess call on a call we know will error out.
            if not chaos_key and not os.environ.get("PDCP_API_KEY"):
                print(f"[{stage}] chaos skipped — no chaos_api_key in config.yml "
                      f"and PDCP_API_KEY not set (free key: "
                      f"https://cloud.projectdiscovery.io)")
                out_file.write_text("")
                continue
            cmd = [chaos_bin, "-d", domain, "-silent", "-o", str(out_file)]
            if chaos_key:
                cmd.extend(["-key", chaos_key])
            r = runner.run(
                cmd, stage=f"{stage}_chaos", log_name=stage,
                output_dir=output_dir, timeout=timeout, capture_stdout=False,
            )
        else:
            # unknown tool — skip gracefully
            out_file.write_text("")
            continue
        if not r["success"] and not r["missing_binary"]:
            print(f"[{stage}] {tool} failed: {r['stderr'][:200]}")

    # Merge & dedupe — preserve original raw outputs
    merged: list[str] = []
    for tool in tools:
        merged.extend(read_lines(raw_sub / f"{tool}.txt"))
    count = write_lines(layout.path(output_dir, "subdomains.txt"), merged)

    # --------------------------------------------------------------
    # puredns — validate + filter the merged list.
    # If enabled, this overwrites processed/subdomains.txt with the
    # wildcard-free, deduplicated, actually-resolving subset. Skips
    # gracefully if puredns isn't installed (returns "skipped"
    # status with no error — the raw merged list is still in place).
    # --------------------------------------------------------------
    from . import puredns as puredns_mod
    if bool(cfg.get("puredns", {}).get("enabled", True)):
        puredns_result = puredns_mod.collect(
            domain, layout.path(output_dir, "subdomains.txt"), output_dir, cfg,
            resume=resume, dry_run=dry_run,
        )
        if puredns_result.get("status") == "success":
            # Use the validated list everywhere from now on.
            return puredns_result
        # puredns skipped/failed → keep the raw merged list.
        return make_result(
            stage, "success", input_path=domain,
            outputs=[raw_sub / f"{t}.txt" for t in tools] + [layout.path(output_dir, "subdomains.txt")],
            count=count,
            extra={"puredns": puredns_result.get("status")},
        )

    return make_result(
        stage, "success", input_path=domain,
        outputs=[raw_sub / f"{t}.txt" for t in tools] + [layout.path(output_dir, "subdomains.txt")],
        count=count,
    )
