"""subdomain — stage 1: subfinder + amass + chaos merge & dedupe.

Required: subfinder, amass, chaos (chaos requires PDCP API key).
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from . import runner
from .utils import (
    make_result,
    read_lines,
    write_lines,
)


def _all_outputs_exist(out_dir: Path, tools: List[str]) -> bool:
    base = out_dir / "processed" / "subdomains.txt"
    if not base.exists() or base.stat().st_size == 0:
        return False
    for tool in tools:
        if not (out_dir / "raw" / f"{tool}.txt").exists():
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
    raw = output_dir / "raw"
    proc = output_dir / "processed"
    raw.mkdir(parents=True, exist_ok=True)
    proc.mkdir(parents=True, exist_ok=True)

    tools = cfg.get("subdomain", {}).get("tools", ["subfinder", "amass", "chaos"])
    timeout = int(cfg.get("subdomain", {}).get("timeout", 900))

    if resume and _all_outputs_exist(output_dir, tools):
        existing = read_lines(proc / "subdomains.txt")
        return make_result(
            stage, "success", input_path=domain,
            outputs=[proc / "subdomains.txt"], count=len(existing),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=domain,
            outputs=[raw / f"{t}.txt" for t in tools] + [proc / "subdomains.txt"],
            count=0, error="dry-run",
        )

    chaos_key = cfg.get("subdomain", {}).get("chaos_api_key", "").strip()

    for tool in tools:
        out_file = raw / f"{tool}.txt"
        if tool == "subfinder":
            if not runner.tool_available("subfinder"):
                print(f"[{stage}] subfinder not installed — skipping")
                out_file.write_text("")
                continue
            r = runner.run(
                ["subfinder", "-d", domain, "-all", "-silent", "-o", str(out_file)],
                stage=f"{stage}_subfinder", output_dir=output_dir, timeout=timeout,
            )
        elif tool == "amass":
            if not runner.tool_available("amass"):
                print(f"[{stage}] amass not installed — skipping")
                out_file.write_text("")
                continue
            r = runner.run(
                ["amass", "enum", "-passive", "-d", domain, "-o", str(out_file)],
                stage=f"{stage}_amass", output_dir=output_dir, timeout=timeout,
            )
        elif tool == "chaos":
            if not runner.tool_available("chaos"):
                print(f"[{stage}] chaos not installed — skipping")
                out_file.write_text("")
                continue
            cmd = ["chaos", "-d", domain, "-silent", "-o", str(out_file)]
            if chaos_key:
                cmd.extend(["-key", chaos_key])
            r = runner.run(cmd, stage=f"{stage}_chaos", output_dir=output_dir, timeout=timeout)
        else:
            # unknown tool — skip gracefully
            out_file.write_text("")
            continue
        if not r["success"] and not r["missing_binary"]:
            print(f"[{stage}] {tool} failed: {r['stderr'][:200]}")

    # Merge & dedupe — preserve original raw outputs
    merged: list[str] = []
    for tool in tools:
        merged.extend(read_lines(raw / f"{tool}.txt"))
    count = write_lines(proc / "subdomains.txt", merged)
    return make_result(
        stage, "success", input_path=domain,
        outputs=[raw / f"{t}.txt" for t in tools] + [proc / "subdomains.txt"],
        count=count,
    )
