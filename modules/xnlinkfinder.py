"""xnlinkfinder — stage 6.2: extract endpoints from JS files."""
from __future__ import annotations

import re
from pathlib import Path

from . import runner
from .utils import make_result, read_lines, write_lines


# xnLinkFinder emits both endpoints ("/api/v1/users") and absolute URLs.
_ENDPOINT_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/-]+$")


def _classify(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if s.startswith(("http://", "https://")):
        return "url"
    if _ENDPOINT_RE.match(s):
        return "endpoint"
    return None


def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "xnlinkfinder_urls.txt"
    return p.exists() and p.stat().st_size > 0


def scan(
    js_urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "xnlinkfinder"
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    ep_out = proc / "xnlinkfinder_endpoints.txt"
    url_out = proc / "xnlinkfinder_urls.txt"

    if skip:
        ep_out.write_text("")
        url_out.write_text("")
        return make_result(
            stage, "skipped", input_path=js_urls_file,
            outputs=[ep_out, url_out], count=0, error="--skip-xnlinkfinder",
        )

    if resume and _outputs_exist(output_dir):
        return make_result(
            stage, "success", input_path=js_urls_file,
            outputs=[ep_out, url_out], count=len(read_lines(url_out)),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=js_urls_file,
            outputs=[ep_out, url_out], count=0, error="dry-run",
        )

    if not runner.tool_available("xnlinkfinder"):
        ep_out.write_text("")
        url_out.write_text("")
        return make_result(
            stage, "skipped", input_path=js_urls_file,
            outputs=[ep_out, url_out], count=0,
            error="xnlinkfinder binary not found (optional, skipped)",
        )

    timeout = int(cfg.get("xnlinkfinder", {}).get("timeout", 1200))

    endpoints: list[str] = []
    urls: list[str] = []
    for js_url in read_lines(js_urls_file):
        r = runner.run(
            ["xnlinkfinder", "-i", js_url, "-sp", "-d", "1", "-sf", domain_only(js_url)],
            stage=f"xnlinkfinder::{js_url[:60]}",
            output_dir=output_dir, timeout=timeout,
        )
        if not r["success"] and not r["missing_binary"]:
            print(f"[{stage}] {js_url} failed: {r['stderr'][:200]}")
            continue
        for ln in (r["stdout"] or "").splitlines():
            kind = _classify(ln)
            if kind == "url":
                urls.append(ln.strip())
            elif kind == "endpoint":
                endpoints.append(ln.strip())

    n_ep = write_lines(ep_out, endpoints)
    n_url = write_lines(url_out, urls)
    return make_result(
        stage, "success", input_path=js_urls_file,
        outputs=[ep_out, url_out], count=n_url + n_ep,
        extra={"endpoints": n_ep, "urls": n_url},
    )


def domain_only(url: str) -> str:
    """Extract the host (no scheme, no path) for xnLinkFinder's -sf flag."""
    try:
        from urllib.parse import urlsplit
        return urlsplit(url).netloc or url
    except Exception:  # noqa: BLE001
        return url
