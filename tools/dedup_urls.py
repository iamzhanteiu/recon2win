"""tools/dedup_urls.py — dedup URLs in dirsearch-style output files.

dirsearch prints one line per finding in the form::

    <status>  <size>  <url>  [<extracted>...]

This script reads those lines and emits a deduplicated stream —
the **first occurrence** of each URL wins. Status codes and sizes
are stripped; only the URL column is kept, one per line.

Equivalent shell one-liner (for the user's reference)::

    awk '!seen[$2]++' <dirsearch-output>.txt

But the Python version is cross-platform, handles malformed lines
gracefully (skips them instead of crashing), and supports a
``--in-place`` rewrite of the source file.

Usage::

    python3 tools/dedup_urls.py raw/dirsearch_raw.txt
    python3 tools/dedup_urls.py raw/dirsearch_raw.txt > unique_urls.txt
    python3 tools/dedup_urls.py -i outputs/apple.com/raw/dirsearch/dirsearch_raw.txt
    python3 tools/dedup_urls.py raw/dirsearch_raw.txt --status 200,500

If ``--status`` is given, lines whose status code (first column)
isn't in the list are dropped BEFORE dedup — so e.g. ``--status 200,500``
keeps only 200/500 responses and dedups within them.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def parse_line(line: str) -> tuple[str, str] | None:
    """Return ``(status_code, url)`` if *line* looks like a dirsearch
    finding line, else ``None``.

    dirsearch lines look like::

        200   123B   https://example.com/.env
        200   123B   https://example.com/.env  ["DB_PASS=..."]
        301     0B   https://example.com/admin  -> https://example.com/admin/

    The URL is the first ``http(s)://...`` token; everything after
    the URL (extracted-results, redirect target, …) is dropped.
    """
    parts = line.split()
    if len(parts) < 3:
        return None
    status = parts[0]
    # URL is the first http(s)://… token; redirect arrows and
    # extracted-results come after it and we ignore them.
    url = None
    for tok in parts[2:]:
        if tok.startswith(("http://", "https://")):
            url = tok
            break
    if url is None:
        return None
    return status, url


def dedup_file(
    path: Path,
    *,
    status_filter: set[str] | None = None,
) -> tuple[list[str], int]:
    """Read *path*, return (deduped_lines, skipped_count)."""
    out: list[str] = []
    seen: set[str] = set()
    skipped = 0
    for raw in path.read_text(errors="ignore").splitlines():
        parsed = parse_line(raw)
        if parsed is None:
            skipped += 1
            continue
        status, url = parsed
        if status_filter and status not in status_filter:
            skipped += 1
            continue
        if url in seen:
            skipped += 1
            continue
        seen.add(url)
        out.append(url)
    return out, skipped


def main() -> int:
    p = argparse.ArgumentParser(
        prog="dedup-urls",
        description="Deduplicate URLs in a dirsearch-style output file",
    )
    p.add_argument("input", type=Path,
                   help="Path to the dirsearch output file")
    p.add_argument("-i", "--in-place", action="store_true",
                   help="Overwrite the input file with deduplicated output")
    p.add_argument("--status", type=str, default=None,
                   help="Comma-separated status codes to keep "
                        "(e.g. '200,500'). Default: keep all.")
    args = p.parse_args()

    if not args.input.exists():
        print(f"error: {args.input} does not exist", file=sys.stderr)
        return 2

    status_filter: set[str] | None = None
    if args.status:
        status_filter = {s.strip() for s in args.status.split(",") if s.strip()}

    lines, skipped = dedup_file(args.input, status_filter=status_filter)
    text = "\n".join(lines) + ("\n" if lines else "")

    if args.in_place:
        args.input.write_text(text, encoding="utf-8")
        print(f"wrote {len(lines)} unique URLs to {args.input} "
              f"(skipped {skipped})", file=sys.stderr)
    else:
        # stdout — operator can pipe to file or `less`.
        sys.stdout.write(text)
        print(f"# {len(lines)} unique URLs (skipped {skipped} non-finding "
              f"or duplicate lines)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())