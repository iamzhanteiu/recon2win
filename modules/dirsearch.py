"""dirsearch — stage 4.2: fuzz endpoints with wordlists and/or extensions.

Two modes, controlled by config:

  * **wordlist mode**  (default when ``dirsearch.wordlists`` is non-empty)
        Each entry in ``wordlists`` is either a single ``.txt`` file or a
        directory (recursively expanded to every ``*.txt`` inside, sorted).
        ``_merge_wordlists()`` then combines the resolved files into ONE
        single deduped file because **dirsearch only accepts a single
        ``-w`` flag** — multiple ``-w`` flags are silently dropped on
        most versions (only the first is honoured). ``-e`` is appended
        too only when ``combine: true`` is set.

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

from . import console, runner
from .sensitive_ext import SENSITIVE_EXT, to_dirsearch_flag
from .utils import make_result, raw_dir, read_lines, write_lines


# Matches "<status>  <len>  <url>" or "<status>  <len>B  <url> [-> <redirect>]".
# Non-greedy URL + optional redirect suffix so redirect lines still produce
# the original (source) URL.
#
# dirsearch's real ``plain`` report (lib/reports/plain_text_report.py) writes
# the redirect suffix as ``    -> REDIRECTS TO: <url>`` — NOT a bare
# ``-> <url>``. Both spellings are accepted here so redirect entries aren't
# silently dropped (which they were when only ``-> <url>`` was matched).
LINE_RE = re.compile(
    r"^\s*(\d{3})\s+\S+\s+(https?://\S+?)"
    r"(?:\s*->\s*(?:REDIRECTS TO:\s*)?https?://\S+)?\s*$"
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


def _merge_wordlists(
    wordlists: list[Path],
    merged_path: Path,
) -> tuple[Path, int, int]:
    """Merge multiple wordlist files into a single deduped file.

    Why this exists: dirsearch only accepts a single ``-w`` flag —
    multiple ``-w`` flags are silently dropped on most versions (only
    the first is honoured), and on others they trigger an argparse
    error. The two valid workarounds are:
      1. Merge into one file (this function — chosen by default
         because it is one process / one timeout window).
      2. Run dirsearch once per wordlist (not implemented; can be
         approximated by repeating the stage via ``--resume`` with
         different configs).

    Lines starting with ``#`` are treated as comments and dropped,
    matching the behaviour of ``read_lines()`` elsewhere in the
    framework. Duplicates are deduped case-sensitively; the first
    occurrence wins (preserves the ordering from the first wordlist
    that contributed the entry).

    Returns ``(merged_path, lines_in, lines_out)`` so the caller can
    log the dedup ratio.
    """
    seen: set[str] = set()
    lines_in = 0
    lines_out = 0
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    with merged_path.open("w", encoding="utf-8") as out:
        for wl in wordlists:
            if not wl.exists() or not wl.is_file():
                continue
            for raw_line in wl.read_text(errors="ignore").splitlines():
                s = raw_line.strip()
                if not s or s.startswith("#"):
                    continue
                lines_in += 1
                if s in seen:
                    continue
                seen.add(s)
                out.write(s + "\n")
                lines_out += 1
    return merged_path, lines_in, lines_out


def _build_cmd(
    alive_file: Path,
    raw_out: Path,
    wordlist: Path | None,
    extensions: list[str] | None,
    *,
    threads: int,
    recursive: bool,
    combine: bool,
    follow_redirects: bool = True,
    include_status: list[str] | None = None,
    exclude_status: list[str] | None = None,
) -> list[str]:
    """Build the dirsearch argv.

    ``wordlist`` is a *single* merged file (or ``None``). Callers with
    multiple input wordlists should run ``_merge_wordlists()`` first —
    dirsearch does not accept multiple ``-w`` flags.

    Precedence:
      1. If wordlist is set → ``-w <path>``. Extensions are added too
         only when ``combine`` is True (extremely noisy — opt-in).
      2. Else → fall back to extensions via ``-e``.

    Status-code filtering (dirsearch v3.x ``-i`` / ``-x``):
      * ``include_status`` — only show these codes (empty = show all).
      * ``exclude_status`` — hide these codes (applied after include).
      * ``follow_redirects`` — ``--follow-redirects`` flag; when True,
        3xx responses are followed and the FINAL status is reported
        (so ``/admin → 302 → /login (200)`` shows up as a 200).
    """
    cmd = [
        "dirsearch",
        "-l", str(alive_file),
        # Format is inferred from the output file extension — ``-o foo.txt``
        # produces plain text, ``-o foo.json`` produces JSON. The legacy
        # dirsearch (pre-1.0, the version most bug-bounty boxes ship) does
        # NOT accept ``--format``; dirsearch 1.x accepts it but ignores
        # it when the extension is unambiguous. Don't pass ``--format``
        # here so we work on both versions.
        "-o", str(raw_out),
        "-t", str(threads),
    ]
    if recursive:
        cmd.append("-r")
    if follow_redirects:
        cmd.append("--follow-redirects")

    # Status-code filtering. Both flags are optional — empty lists mean
    # "no filter". -i / -x are comma-separated status codes
    # (e.g. ``-i 200,403``). dirsearch's pre-1.0 versions don't accept
    # these flags; if we detect they're unsupported (rare on modern
    # bug-bounty boxes) the operator should leave both empty.
    if include_status:
        clean = [str(s).strip() for s in include_status if str(s).strip()]
        if clean:
            cmd.extend(["-i", ",".join(clean)])
    if exclude_status:
        clean = [str(s).strip() for s in exclude_status if str(s).strip()]
        if clean:
            cmd.extend(["-x", ",".join(clean)])

    if wordlist:
        cmd.extend(["-w", str(wordlist)])
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
    raw_ds = raw_dir(output_dir, "dirsearch")
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    raw_out = raw_ds / "dirsearch_raw.txt"
    merged_wl_path = raw_ds / "merged_wordlists.txt"
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
        # If multiple wordlists were resolved, dry-run still won't
        # create the merged file on disk — we only need to know what
        # the argv *would* look like. Report the planned merge path
        # in the extra so the operator can see it.
        planned_wordlist: Path | None = None
        planned_merge: dict | None = None
        if len(wl_paths) == 1:
            planned_wordlist = wl_paths[0]
        elif wl_paths:
            planned_wordlist = merged_wl_path
            planned_merge = {"files": len(wl_paths),
                             "path": str(planned_wordlist)}
        cmd = _build_cmd(
            alive_file, raw_out, planned_wordlist,
            extensions=d_cfg.get("extensions"),
            threads=int(d_cfg.get("threads", 30)),
            recursive=bool(d_cfg.get("recursive", True)),
            combine=bool(d_cfg.get("combine", False)),
            follow_redirects=bool(d_cfg.get("follow_redirects", True)),
            include_status=d_cfg.get("include_status") or [],
            exclude_status=d_cfg.get("exclude_status") or [],
        )
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0, error="dry-run",
            extra={
                "planned_cmd": cmd,
                "wordlists": [str(p) for p in wl_paths],
                "merge": planned_merge,
            },
        )

    if not runner.tool_available("dirsearch"):
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="dirsearch binary not found (optional, skipped)",
        )

    # Nothing alive to scan → skip without spawning dirsearch. dirsearch
    # exits non-zero on an empty -l file which we would otherwise
    # misinterpret as a real failure.
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="no alive hosts to scan",
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

    # dirsearch accepts only one ``-w`` flag. If we resolved multiple
    # wordlists (very common — one big raft-small-directories.txt
    # plus 50 service-specific files), merge them into a single
    # deduped file under raw/dirsearch/merged_wordlists.txt. A
    # single wordlist is used as-is to avoid an unnecessary
    # round-trip through disk.
    wordlist_file: Path | None = None
    merge_stats: dict | None = None
    if wl_paths:
        if len(wl_paths) == 1:
            wordlist_file = wl_paths[0]
        else:
            merged_path, lines_in, lines_out = _merge_wordlists(
                wl_paths, merged_wl_path,
            )
            wordlist_file = merged_path
            merge_stats = {
                "files": len(wl_paths),
                "lines_in": lines_in,
                "lines_out": lines_out,
                "path": str(merged_path),
            }
            print(
                console.phase_info_line(
                    f"merged {len(wl_paths)} wordlists "
                    f"({lines_in} lines → {lines_out} unique) into {merged_path}"
                )
            )

    cmd = _build_cmd(
        alive_file, raw_out, wordlist_file,
        extensions=extensions,
        threads=threads,
        recursive=recursive,
        combine=combine,
        follow_redirects=bool(d_cfg.get("follow_redirects", True)),
        include_status=d_cfg.get("include_status") or [],
        exclude_status=d_cfg.get("exclude_status") or [],
    )

    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error=(r["stderr"] or "")[:300],
            extra={"wordlists": [str(p) for p in wl_paths], "merge": merge_stats},
        )

    src = raw_out.read_text(errors="ignore") if raw_out.exists() else (r["stdout"] or "")
    urls = normalize_output(src.splitlines())
    n = write_lines(proc_out, urls)
    return make_result(
        stage, "success", input_path=alive_file,
        outputs=[raw_out, proc_out], count=n,
        extra={"wordlists": [str(p) for p in wl_paths],
               "merge": merge_stats,
               "mode": "wordlist" if wl_paths else "extension"},
    )