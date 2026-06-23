"""arjun — stage 7: parameter discovery on dynamic URLs."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from . import runner
from .utils import make_result, read_lines, write_lines


_PARAM_RE = re.compile(r"\[(\d{1,4})\] (.+)$")


def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "arjun_params.txt"
    return p.exists() and p.stat().st_size > 0


def discover(
    dynamic_urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "arjun"
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    params_out = proc / "arjun_params.txt"
    urls_out = proc / "parameterized_urls.txt"

    if skip:
        params_out.write_text("")
        urls_out.write_text("")
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0, error="--skip-arjun",
        )

    if resume and _outputs_exist(output_dir):
        return make_result(
            stage, "success", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=len(read_lines(urls_out)),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0, error="dry-run",
        )

    if not runner.tool_available("arjun"):
        params_out.write_text("")
        urls_out.write_text("")
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0,
            error="arjun binary not found (optional, skipped)",
        )

    a_cfg = cfg.get("arjun", {})
    threads = int(a_cfg.get("threads", 5))
    timeout = int(a_cfg.get("timeout", 3600))

    urls = read_lines(dynamic_urls_file)
    if not urls:
        params_out.write_text("")
        urls_out.write_text("")
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0, error="no dynamic URLs to scan",
        )

    r = runner.run(
        ["arjun", "-i", str(dynamic_urls_file),
         "-o", str(params_out),
         "-t", str(threads),
         "--stable"],
        stage=stage, output_dir=output_dir, timeout=timeout,
    )
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0,
            error=(r["stderr"] or "")[:300],
        )

    # arjun output format: "[200] https://example.com/api?id=&x="
    # We extract the parameterised URL list and dedupe.
    param_lines: list[str] = []
    if params_out.exists():
        param_lines = params_out.read_text(errors="ignore").splitlines()
    parameterized = []
    for ln in param_lines:
        m = _PARAM_RE.match(ln.strip())
        if m:
            parameterized.append(m.group(2).strip())
    n = write_lines(urls_out, parameterized)
    return make_result(
        stage, "success", input_path=dynamic_urls_file,
        outputs=[params_out, urls_out], count=n,
    )
