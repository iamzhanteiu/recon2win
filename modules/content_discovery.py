"""content_discovery — stage 4.1: katana + urlfinder crawling.

The output is split:
  * raw/katana_urls.txt, raw/urlfinder_urls.txt  — raw tool output
  * processed/crawler_urls.txt                    — deduped union
  * processed/js_urls_from_crawler.txt            — *.js URLs found while crawling
"""
from __future__ import annotations

import re
from pathlib import Path

from . import runner
from .telegram import notify_stage_result
from .utils import (
    make_result,
    read_lines,
    write_lines,
)


JS_RE = re.compile(r"https?://[^\s\"'<>]+\.js(?:[?#][^\s\"'<>]*)?", re.IGNORECASE)


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
    raw = output_dir / "raw"
    proc = output_dir / "processed"
    raw.mkdir(parents=True, exist_ok=True)
    proc.mkdir(parents=True, exist_ok=True)

    if resume and _outputs_exist(output_dir):
        return make_result(
            stage, "success", input_path=alive_file,
            outputs=[proc / "crawler_urls.txt", proc / "js_urls_from_crawler.txt"],
            count=len(read_lines(proc / "crawler_urls.txt")),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw / "katana_urls.txt", raw / "urlfinder_urls.txt",
                     proc / "crawler_urls.txt", proc / "js_urls_from_crawler.txt"],
            count=0, error="dry-run",
        )

    cd_cfg = cfg.get("content_discovery", {})
    outputs: list[Path] = []
    all_urls: list[str] = []

    # 4.1.a — katana
    if cd_cfg.get("katana", {}).get("enabled", True):
        out = raw / "katana_urls.txt"
        if runner.tool_available("katana"):
            depth = int(cd_cfg.get("katana", {}).get("depth", 3))
            to = int(cd_cfg.get("katana", {}).get("timeout", 1800))
            r = runner.run(
                ["katana", "-list", str(alive_file), "-depth", str(depth),
                 "-silent", "-output", str(out)],
                stage="content_discovery_katana", output_dir=output_dir, timeout=to,
            )
            if not r["success"] and not r["missing_binary"]:
                print(f"[{stage}] katana failed: {r['stderr'][:200]}")
        else:
            print(f"[{stage}] katana not installed — skipping")
            out.write_text("")
        outputs.append(out)
        all_urls.extend(read_lines(out))
    else:
        (raw / "katana_urls.txt").write_text("")
        outputs.append(raw / "katana_urls.txt")

    # 4.1.b — urlfinder (projectdiscovery/urlfinder — flags: -d for input,
    # -o for output, -silent for URL-only stdout). Earlier versions used -i;
    # projectdiscovery's tool has always used -d / -list.
    if cd_cfg.get("urlfinder", {}).get("enabled", True):
        out = raw / "urlfinder_urls.txt"
        if runner.tool_available("urlfinder"):
            to = int(cd_cfg.get("urlfinder", {}).get("timeout", 1800))
            r = runner.run(
                ["urlfinder", "-d", str(alive_file), "-o", str(out), "-silent"],
                stage="content_discovery_urlfinder", output_dir=output_dir, timeout=to,
            )
            if not r["success"] and not r["missing_binary"]:
                print(f"[{stage}] urlfinder failed: {r['stderr'][:200]}")
        else:
            print(f"[{stage}] urlfinder not installed — skipping")
            out.write_text("")
        outputs.append(out)
        all_urls.extend(read_lines(out))
    else:
        (raw / "urlfinder_urls.txt").write_text("")
        outputs.append(raw / "urlfinder_urls.txt")

    crawler_txt = proc / "crawler_urls.txt"
    js_txt = proc / "js_urls_from_crawler.txt"
    n_crawl = write_lines(crawler_txt, all_urls)
    n_js = write_lines(js_txt, [u for u in all_urls if JS_RE.match(u)])

    result = make_result(
        stage, "success", input_path=alive_file,
        outputs=outputs + [crawler_txt, js_txt],
        count=n_crawl, extra={"js_urls": n_js},
    )

    # stage-complete summary — only fires when URLs > 0
    notify_stage_result(stage, result, cfg.get("telegram") or {})

    return result
