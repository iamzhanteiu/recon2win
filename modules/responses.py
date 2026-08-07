"""responses — capture a short body preview for ffuf + dirsearch hits.

ffuf and dirsearch only record ``status + URL``. To triage a hit (is a 200 a
real page or a soft-404? what does that 403 body actually say?) you want a
glimpse of the body. This stage re-requests every ffuf + dirsearch hit with
httpx and writes a preview table (status / size / type / title / body
snippet) to ``responses/index.md`` — it does NOT store full response bodies.

httpx flags used:
  -bp <n>      body-preview: httpx returns only the first ~n chars of the
               body (field ``body_preview``) — no full body is fetched/kept
  -json -o     structured output we parse for the preview

``max_urls`` caps how many hits are probed, highest-value first (sensitive-
looking paths win). Skips cleanly when both hit lists are empty or httpx is
missing.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import layout, runner
from .utils import make_result, raw_dir, read_lines, write_json, write_lines


# Paths that are worth reading first when the cap bites — admin panels,
# configs, dumps, VCS/CI leaks. Higher score = fetched before the long tail.
_HINTS = (
    "admin", "config", "backup", "dump", "api", "graphql", "swagger",
    "actuator", "console", "debug", "phpinfo", "server-status",
    ".git", ".env", ".svn", "wp-", "install", "setup", "internal",
)


def _score(url: str) -> int:
    lo = url.lower()
    return sum(1 for h in _HINTS if h in lo)


def _clean(text: str, limit: int) -> str:
    """Collapse whitespace + strip so a body snippet fits one table cell.

    Pipes and backticks are neutralised so the snippet can't break the
    surrounding Markdown table.
    """
    if not text:
        return ""
    flat = " ".join(text.split())
    flat = flat.replace("|", "¦").replace("`", "'")
    return flat[:limit]


def _preview_path(output_dir: Path) -> Path:
    return output_dir / "responses" / "preview.json"


def collect(output_dir: Path, cfg: dict, *, resume: bool = False,
            dry_run: bool = False, skip: bool = False) -> dict:
    stage = "responses"
    output_dir = Path(output_dir)
    rdir = raw_dir(output_dir, "responses")
    resp_dir = output_dir / "responses"
    resp_dir.mkdir(parents=True, exist_ok=True)
    index_md = resp_dir / "index.md"
    preview_json = _preview_path(output_dir)
    outputs = [index_md, preview_json]

    r_cfg = cfg.get("responses", {}) if isinstance(cfg, dict) else {}

    if skip:
        index_md.write_text("")
        write_json(preview_json, {"previews": []})
        return make_result(stage, "skipped", input_path=str(output_dir),
                           outputs=outputs, count=0, error="--skip-responses")
    if not r_cfg.get("enabled", True):
        index_md.write_text("")
        write_json(preview_json, {"previews": []})
        return make_result(stage, "skipped", input_path=str(output_dir),
                           outputs=outputs, count=0, error="disabled in config")

    # Gather hits from both tools, remembering which tool(s) found each URL.
    sources: dict[str, set[str]] = {}
    for url in read_lines(layout.path(output_dir, "ffuf_urls.txt")):
        sources.setdefault(url, set()).add("ffuf")
    for url in read_lines(layout.path(output_dir, "dirsearch_urls.txt")):
        sources.setdefault(url, set()).add("dirsearch")

    if not sources:
        index_md.write_text("")
        write_json(preview_json, {"previews": []})
        return make_result(stage, "skipped", input_path=str(output_dir),
                           outputs=outputs, count=0,
                           error="no ffuf/dirsearch hits to fetch")

    if dry_run:
        return make_result(stage, "skipped", input_path=str(output_dir),
                           outputs=outputs, count=0, error="dry-run")

    if not runner.tool_available("httpx"):
        index_md.write_text("")
        write_json(preview_json, {"previews": []})
        return make_result(stage, "skipped", input_path=str(output_dir),
                           outputs=outputs, count=0,
                           error="httpx binary not found (optional, skipped)")

    # Rank (sensitive paths first) then cap.
    max_urls = int(r_cfg.get("max_urls", 500))
    urls = sorted(sources, key=lambda u: (-_score(u), len(u), u))
    capped = 0
    if max_urls and max_urls > 0 and len(urls) > max_urls:
        capped = len(urls) - max_urls
        urls = urls[:max_urls]

    input_file = rdir / "input.txt"
    write_lines(input_file, urls)
    detail_json = rdir / "httpx_detail.json"

    threads = int(r_cfg.get("threads", 40))
    req_timeout = int(r_cfg.get("request_timeout", 10))
    timeout = int(r_cfg.get("timeout", 900))
    snippet_bytes = int(r_cfg.get("snippet_bytes", 50))

    cmd = [
        "httpx", "-l", str(input_file),
        "-json", "-silent",
        "-threads", str(threads),
        "-timeout", str(req_timeout),
        # body-preview only: httpx returns the first ~N chars (body_preview),
        # never the full body — so nothing heavy is fetched or stored.
        "-bp", str(max(1, snippet_bytes)),
        "-o", str(detail_json),
    ]
    r = runner.run(cmd, stage=stage, log_name=stage,
                   output_dir=output_dir, timeout=timeout)
    timed_out = r.get("timed_out", False)
    if not r["success"] and not r["missing_binary"] and not timed_out:
        index_md.write_text("")
        write_json(preview_json, {"previews": []})
        return make_result(stage, "failed", input_path=str(output_dir),
                           outputs=outputs, count=0,
                           error=(r["stderr"] or "")[:300])

    # Parse the httpx JSONL into compact previews (drop the heavy body).
    # httpx is asked for ``-o detail_json``, but it has been observed to
    # finish cleanly while never creating that file, emitting the JSONL on
    # stdout instead. The old code only read the file, so the stage reported
    # ``fetched: 0`` on a run where httpx had in fact answered for all 500
    # URLs — the triage net that would have exposed 44k false ffuf hits went
    # dark, and said nothing about it. Read whichever channel we actually got.
    detail_text = detail_json.read_text(errors="ignore") if detail_json.exists() else ""
    if not detail_text.strip():
        detail_text = r.get("stdout") or ""

    previews: list[dict] = []
    if detail_text.strip():
        for ln in detail_text.splitlines():
            ln = ln.strip()
            if not ln or not ln.startswith("{"):
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            url = obj.get("url") or obj.get("input") or ""
            previews.append({
                "url": url,
                "sources": sorted(sources.get(url, set())),
                "status": obj.get("status_code"),
                "content_length": obj.get("content_length"),
                "content_type": obj.get("content_type") or "",
                "title": obj.get("title") or "",
                "webserver": obj.get("webserver") or "",
                "snippet": _clean(obj.get("body_preview") or "", snippet_bytes),
            })

    previews.sort(key=lambda p: (-_score(p["url"]), p["url"]))
    write_json(preview_json, {
        "previews": previews,
        "stats": {"hits": len(sources), "fetched": len(previews),
                  "capped": capped},
    })
    _write_index(index_md, output_dir.name, previews, capped)

    extra = {"fetched": len(previews), "capped": capped, "hits": len(sources)}
    status = "success"
    error = None
    if timed_out:
        error = (f"timeout after {timeout}s — saved {len(previews)} "
                 f"responses before cutoff")
    elif not previews:
        # This stage exists to triage the other two, so it going quiet is
        # exactly when someone must be told. Silence used to look identical
        # to "nothing worth previewing".
        error = (f"probed {len(urls)} of {len(sources)} hit(s) but parsed 0 "
                 f"responses — httpx wrote neither {detail_json.name} nor "
                 f"usable stdout")
        extra["blocked"] = True
    return make_result(stage, status, input_path=str(output_dir),
                       outputs=outputs, count=len(previews),
                       error=error, extra=extra)


def _write_index(path: Path, domain: str, previews: list[dict],
                 capped: int) -> None:
    lines: list[str] = []
    lines.append(f"# Response previews — {domain}")
    lines.append("")
    note = (f"{len(previews)} ffuf/dirsearch hit(s) probed with httpx. Only a "
            f"short body preview is kept — no full response bodies are stored. ")
    if capped:
        note += f"{capped} lower-value hit(s) skipped by the max_urls cap."
    lines.append(note)
    lines.append("")
    lines.append("| status | size | type | source | url | title | snippet |")
    lines.append("|--------|------|------|--------|-----|-------|---------|")
    for p in previews:
        size = p["content_length"]
        size_s = f"{size:,}" if isinstance(size, int) else "—"
        ctype = (p["content_type"] or "").split(";")[0]
        src = "+".join(p["sources"])
        title = _clean(p["title"], 60)
        snip = p["snippet"] or ""
        lines.append(
            f"| {p['status']} | {size_s} | {ctype} | {src} | {p['url']} "
            f"| {title} | {snip} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
