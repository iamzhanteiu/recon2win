"""waymore — stage 4.3: archived URLs and JS files.

waymore writes a single text file of URLs. We post-filter by:
  * file extension (sensitive list)
  * .js files (always kept)
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

from . import runner
from .sensitive_ext import SENSITIVE_EXT
from .utils import make_result, read_lines, write_lines


# All extensions we want to keep, with JS always included
_KEEP_EXT = set(ext.lstrip(".") for ext in SENSITIVE_EXT) | {"js"}


def _should_keep(url: str) -> bool:
    p = urlparse(url)
    path = p.path.lower()
    if path.endswith(".js"):
        return True
    for ext in _KEEP_EXT:
        if path.endswith("." + ext):
            return True
    return False


def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "waymore_urls.txt"
    return p.exists() and p.stat().st_size > 0


def collect(
    domain: str,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "waymore"
    raw = output_dir / "raw"
    proc = output_dir / "processed"
    raw.mkdir(parents=True, exist_ok=True)
    proc.mkdir(parents=True, exist_ok=True)
    raw_out = raw / "waymore_raw.txt"
    proc_out = proc / "waymore_urls.txt"

    if skip:
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=domain,
            outputs=[raw_out, proc_out], count=0, error="--skip-waymore",
        )

    if resume and _outputs_exist(output_dir):
        existing = read_lines(proc_out)
        return make_result(
            stage, "success", input_path=domain,
            outputs=[raw_out, proc_out], count=len(existing),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=domain,
            outputs=[raw_out, proc_out], count=0, error="dry-run",
        )

    if not runner.tool_available("waymore"):
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=domain,
            outputs=[raw_out, proc_out], count=0,
            error="waymore binary not found (optional, skipped)",
        )

    w_cfg = cfg.get("waymore", {})
    timeout = int(w_cfg.get("timeout", 1800))

    # waymore ≥3.0 dropped `-nocolor`; use `NO_COLOR=1` env to suppress
    # ANSI escapes (PEP-0001 / no-color.org convention — read by most tools).
    cmd = ["waymore", "-i", domain, "-mode", "U", "-oU", str(raw_out)]
    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout,
                   env={**os.environ, "NO_COLOR": "1"})
    if not r["success"] and not r["missing_binary"]:
        # waymore can be flaky, but we still want to keep its partial output
        print(f"[{stage}] waymore exited non-zero: {r['stderr'][:200]}")

    raw_lines = raw_out.read_text(errors="ignore").splitlines() if raw_out.exists() else []
    # waymore may interleave progress messages — keep only http(s) URLs
    urls = [ln.strip() for ln in raw_lines if ln.strip().startswith(("http://", "https://"))]
    # post-filter
    filtered = [u for u in urls if _should_keep(u)]
    n = write_lines(proc_out, filtered)
    return make_result(
        stage, "success", input_path=domain,
        outputs=[raw_out, proc_out], count=n,
        extra={"raw_count": len(urls), "kept_count": n},
    )
