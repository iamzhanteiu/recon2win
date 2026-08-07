"""waymore — stage 4.4: archived URLs and JS files.

waymore writes a single text file of URLs. We post-filter by:
  * file extension (sensitive list)
  * .js files (always kept)
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from . import layout, runner
from .sensitive_ext import SENSITIVE_EXT, SENSITIVE_FILES
from .utils import make_result, raw_dir, read_lines, write_lines


# All extensions we want to keep, with JS always included
_KEEP_EXT = set(ext.lstrip(".") for ext in SENSITIVE_EXT) | {"js"}

# Tên file đầy đủ (``.env``, ``docker-compose.yml``) không phải extension nên
# không khớp được bằng ``endswith("." + ext)``. Từ khi SENSITIVE_EXT tách khỏi
# SENSITIVE_FILES, thiếu tập này thì waymore sẽ vứt đúng những URL đáng giữ
# nhất trong kho archive.
_KEEP_FILES = set(f.lower().lstrip("/") for f in SENSITIVE_FILES)


def _should_keep(url: str) -> bool:
    p = urlparse(url)
    path = p.path.lower()
    if path.endswith(".js"):
        return True
    for ext in _KEEP_EXT:
        if path.endswith("." + ext):
            return True
    stripped = path.lstrip("/")
    for name in _KEEP_FILES:
        if stripped == name or path.endswith("/" + name):
            return True
    return False


def _outputs_exist(out_dir: Path) -> bool:
    p = layout.path(out_dir, "waymore_urls.txt")
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
    raw_wm = raw_dir(output_dir, "waymore")
    layout.ensure_tree(output_dir)
    raw_out = raw_wm / "waymore_raw.txt"
    proc_out = layout.path(output_dir, "waymore_urls.txt")

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
                   env={**os.environ, "NO_COLOR": "1"}, capture_stdout=False)
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
