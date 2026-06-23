"""dirsearch — stage 4.2: fuzz endpoints with wordlists and/or extensions.

Two modes, controlled by config:

  * **wordlist mode**  (default when ``dirsearch.wordlists`` is non-empty)
        Pass each wordlist file via ``-w``. Directory entries are recursively
        expanded to every ``*.txt`` inside. ``-e`` is omitted unless the
        operator also sets ``dirsearch.combine: true``.

  * **extension mode** (legacy behaviour — fallback when no wordlists)
        Pass the curated sensitive-extension list via ``-e``.

dirsearch prints lines like:
    200  10KB  https://example.com/.env

We normalize those to URL-only, one per line, in the form:
    https://example.com/.env
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from . import runner
from .sensitive_ext import SENSITIVE_EXT, to_dirsearch_flag
from .utils import make_result, read_lines, write_lines


# Matches "<status>  <len>  <url>" or "<status>  <len>B  <url> [-> <redirect>]"
# Non-greedy URL + optional ` -> <redirect>` suffix so redirect lines still
# produce the original (source) URL.
LINE_RE = re.compile(
    r"^\s*(\d{3})\s+\S+\s+(https?://\S+?)(?:\s*->\s*https?://\S+)?\s*$"
)


# ----------------------------------------------------------------------
# Pure helpers — no I/O beyond Path.stat(), fully unit-testable.
# ----------------------------------------------------------------------
def normalize_output(raw_lines: Iterable[str]) -> list[str]:
    """Reduce dirsearch stdout to a list of clean URLs."""
    out: list[str] = []
    for ln in raw_lines:
        m = LINE_RE.match(ln)
        if m:
            out.append(m.group(2).strip())
        else:
            s = ln.strip()
            if s.startswith("http://") or s.startswith("https://"):
                out.append(s)
    seen: set[str] = set()
    deduped: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def _resolve_wordlists(
    paths: Iterable[str | Path],
    *,
    missing_callback=None,
) -> list[Path]:
    """Expand a list of paths into a flat list of wordlist files.

    Rules:
      * ``~`` is expanded.
      * Non-existent paths are skipped (and reported via ``missing_callback``).
      * A directory path is recursively expanded to every ``*.txt`` inside it
        (sorted for deterministic command-line order).
      * Regular files are kept as-is.
    """
    resolved: list[Path] = []
    for raw in paths:
        if raw is None:
            continue
        p = Path(raw).expanduser()
        if not p.exists():
            if missing_callback:
                missing_callback(f"[dirsearch] wordlist not found: {p}")
            continue
        if p.is_dir():
            # Recursively pick up every .txt under the directory.
            for f in sorted(p.rglob("*.txt")):
                if f.is_file():
                    resolved.append(f)
        else:
            resolved.append(p)
    return resolved


def _build_cmd(
    alive_file: Path,
    raw_out: Path,
    wordlists: list[Path],
    extensions: list[str] | None,
    *,
    threads: int,
    recursive: bool,
    combine: bool,
) -> list[str]:
    """Build the dirsearch argv.

    Precedence:
      1. If wordlists is non-empty → use wordlists. Extensions are added too
         only when ``combine`` is True (extremely noisy — opt-in).
      2. Else → fall back to extensions.
    """
    cmd = [
        "dirsearch",
        "-l", str(alive_file),
        # Modern dirsearch (>=1.0) infers format from the output file
        # extension; --format was removed. Our raw_out is .txt → plain.
        "-o", str(raw_out),
        "-t", str(threads),
    ]
    if recursive:
        cmd.append("-r")

    if wordlists:
        for wl in wordlists:
            cmd.extend(["-w", str(wl)])
        if combine and extensions:
            cmd.extend(["-e", to_dirsearch_flag(extensions)])
    elif extensions:
        cmd.extend(["-e", to_dirsearch_flag(extensions)])

    return cmd


# ----------------------------------------------------------------------
# Resume / dry-run helpers
# ----------------------------------------------------------------------
def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "dirsearch_urls.txt"
    return p.exists() and p.stat().st_size > 0


# ----------------------------------------------------------------------
# Stage entrypoint
# ----------------------------------------------------------------------
def scan(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "dirsearch"
    raw = output_dir / "raw"
    proc = output_dir / "processed"
    raw.mkdir(parents=True, exist_ok=True)
    proc.mkdir(parents=True, exist_ok=True)
    raw_out = raw / "dirsearch_raw.txt"
    proc_out = proc / "dirsearch_urls.txt"

    if skip:
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0, error="--skip-dirsearch",
        )

    if resume and _outputs_exist(output_dir):
        existing = read_lines(proc_out)
        return make_result(
            stage, "success", input_path=alive_file,
            outputs=[raw_out, proc_out], count=len(existing),
        )

    if dry_run:
        d_cfg = cfg.get("dirsearch", {}) if isinstance(cfg, dict) else {}
        wl_paths = _resolve_wordlists(
            d_cfg.get("wordlists", []) or [], missing_callback=print,
        )
        cmd = _build_cmd(
            alive_file, raw_out, wl_paths,
            extensions=d_cfg.get("extensions"),
            threads=int(d_cfg.get("threads", 30)),
            recursive=bool(d_cfg.get("recursive", True)),
            combine=bool(d_cfg.get("combine", False)),
        )
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0, error="dry-run",
            extra={"planned_cmd": cmd, "wordlists": [str(p) for p in wl_paths]},
        )

    if not runner.tool_available("dirsearch"):
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="dirsearch binary not found (optional, skipped)",
        )

    d_cfg = cfg.get("dirsearch", {})
    threads = int(d_cfg.get("threads", 30))
    timeout = int(d_cfg.get("timeout", 3600))
    recursive = bool(d_cfg.get("recursive", True))
    combine = bool(d_cfg.get("combine", False))
    extensions = d_cfg.get("extensions")  # if None we fall back to SENSITIVE_EXT

    wl_paths = _resolve_wordlists(
        d_cfg.get("wordlists", []) or [], missing_callback=print,
    )

    # Fallback to the curated extension list when no extensions are configured
    # AND no wordlists are configured. Operators who provide either an explicit
    # extensions list OR wordlists are presumed to know what they want.
    if not wl_paths and not extensions:
        extensions = SENSITIVE_EXT

    cmd = _build_cmd(
        alive_file, raw_out, wl_paths,
        extensions=extensions,
        threads=threads,
        recursive=recursive,
        combine=combine,
    )

    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error=(r["stderr"] or "")[:300],
        )

    src = raw_out.read_text(errors="ignore") if raw_out.exists() else (r["stdout"] or "")
    urls = normalize_output(src.splitlines())
    n = write_lines(proc_out, urls)
    return make_result(
        stage, "success", input_path=alive_file,
        outputs=[raw_out, proc_out], count=n,
        extra={"wordlists": [str(p) for p in wl_paths],
               "mode": "wordlist" if wl_paths else "extension"},
    )