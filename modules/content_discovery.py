"""content_discovery — stage 4.1: katana + urlfinder crawling.

The output is split:
  * raw/content_discovery/katana_urls.txt, raw/content_discovery/urlfinder_urls.txt  — raw tool output
  * processed/crawler_urls.txt                    — deduped union
  * processed/js_urls.txt                         — *.js URLs found while crawling
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from . import runner
from .telegram import notify_stage_result
from .utils import (
    make_result,
    raw_dir,
    read_lines,
    write_lines,
)


JS_RE = re.compile(r"https?://[^\s\"'<>]+\.js(?:[?#][^\s\"'<>]*)?", re.IGNORECASE)


def _hosts_from_urls(url_lines: list[str]) -> list[str]:
    """Reduce a list of full URLs (httpx alive output) to unique bare hosts.

    urlfinder's ``-list`` expects domains/hosts, not full ``scheme://host/path``
    URLs, so we strip everything but the hostname (port dropped) and dedupe
    while preserving first-seen order.
    """
    seen: set[str] = set()
    hosts: list[str] = []
    for ln in url_lines:
        s = ln.strip()
        if not s:
            continue
        if "://" not in s:
            s = "http://" + s  # bare host — give urlsplit a scheme to parse
        host = urlsplit(s).hostname or ""
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "crawler_urls.txt"
    return p.exists() and p.stat().st_size > 0


def crawl(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    stage = "content_discovery"
    raw_cd = raw_dir(output_dir, "content_discovery")
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)

    if resume and _outputs_exist(output_dir):
        return make_result(
            stage, "success", input_path=alive_file,
            outputs=[proc / "crawler_urls.txt", proc / "js_urls.txt"],
            count=len(read_lines(proc / "crawler_urls.txt")),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_cd / "katana_urls.txt", raw_cd / "urlfinder_urls.txt",
                     proc / "crawler_urls.txt", proc / "js_urls.txt"],
            count=0, error="dry-run",
        )

    cd_cfg = cfg.get("content_discovery", {})
    outputs: list[Path] = []
    all_urls: list[str] = []

    # 4.1.a — katana
    if cd_cfg.get("katana", {}).get("enabled", True):
        out = raw_cd / "katana_urls.txt"
        if runner.tool_available("katana"):
            depth = int(cd_cfg.get("katana", {}).get("depth", 3))
            to = int(cd_cfg.get("katana", {}).get("timeout", 1800))
            r = runner.run(
                ["katana", "-list", str(alive_file), "-depth", str(depth),
                 "-silent", "-output", str(out)],
                stage="content_discovery_katana", log_name=stage,
                output_dir=output_dir, timeout=to,
            )
            if not r["success"] and not r["missing_binary"]:
                print(f"[{stage}] katana failed: {r['stderr'][:200]}")
        else:
            print(f"[{stage}] katana not installed — skipping")
            out.write_text("")
        outputs.append(out)
        all_urls.extend(read_lines(out))
    else:
        (raw_cd / "katana_urls.txt").write_text("")
        outputs.append(raw_cd / "katana_urls.txt")

    # 4.1.b — urlfinder (projectdiscovery/urlfinder). ``-list`` takes a file of
    # *domains/hosts* (not full URLs), so we feed it hostnames extracted from
    # the httpx alive list. ``-d`` is for a literal domain string and would
    # silently do nothing when handed a file path — that was the old bug.
    if cd_cfg.get("urlfinder", {}).get("enabled", True):
        out = raw_cd / "urlfinder_urls.txt"
        if runner.tool_available("urlfinder"):
            to = int(cd_cfg.get("urlfinder", {}).get("timeout", 1800))
            hosts = _hosts_from_urls(read_lines(alive_file))
            if hosts:
                # Temp host list — not persisted (keeps the output tree lean).
                tmp = tempfile.NamedTemporaryFile(
                    "w", suffix=".txt", prefix="urlfinder_hosts_",
                    delete=False, encoding="utf-8",
                )
                try:
                    tmp.write("\n".join(hosts) + "\n")
                    tmp.close()
                    r = runner.run(
                        ["urlfinder", "-list", tmp.name, "-o", str(out), "-silent"],
                        stage="content_discovery_urlfinder", log_name=stage,
                        output_dir=output_dir, timeout=to,
                    )
                    if not r["success"] and not r["missing_binary"]:
                        print(f"[{stage}] urlfinder failed: {r['stderr'][:200]}")
                finally:
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
            else:
                print(f"[{stage}] no alive hosts for urlfinder — skipping")
                out.write_text("")
        else:
            print(f"[{stage}] urlfinder not installed — skipping")
            out.write_text("")
        outputs.append(out)
        all_urls.extend(read_lines(out))
    else:
        (raw_cd / "urlfinder_urls.txt").write_text("")
        outputs.append(raw_cd / "urlfinder_urls.txt")

    crawler_txt = proc / "crawler_urls.txt"
    js_txt = proc / "js_urls.txt"
    n_crawl = write_lines(crawler_txt, all_urls)
    # ``js_urls.txt`` is the only JS-URL file now — ``js_urls_from_crawler.txt``
    # was dropped because it's just a subset of the union produced by
    # the later url_merge stage. Other stages (crawler-derived JS) get
    # folded in by url_merge.
    n_js = write_lines(js_txt, [u for u in all_urls if JS_RE.match(u)])

    result = make_result(
        stage, "success", input_path=alive_file,
        outputs=outputs + [crawler_txt, js_txt],
        count=n_crawl, extra={"js_urls": n_js},
    )

    # stage-complete summary — only fires when URLs > 0
    notify_stage_result(stage, result, cfg.get("telegram") or {})

    return result
