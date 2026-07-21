"""Tests for tools/dedup_urls.py.

Covers:
  * Parse dirsearch-style lines (status / size / url / [extras])
  * Deduplicate by URL — first occurrence wins
  * --status filter (drop everything except listed codes)
  * --in-place rewrite of the source file
  * Skips malformed lines gracefully
"""
from __future__ import annotations

import sys
from pathlib import Path


# Add tools/ to sys.path so we can import dedup_urls.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import dedup_urls  # noqa: E402


# ----------------------------------------------------------------------
# parse_line
# ----------------------------------------------------------------------
def test_parse_line_basic():
    status, url = dedup_urls.parse_line("200   123B   https://example.com/.env")
    assert status == "200"
    assert url == "https://example.com/.env"


def test_parse_line_drops_extracted_results():
    """``["DB_PASS=..."]`` and other trailing tokens are dropped."""
    status, url = dedup_urls.parse_line(
        '200   50B   https://example.com/.env  ["DB_PASS=hunter2"]'
    )
    assert status == "200"
    assert url == "https://example.com/.env"


def test_parse_line_drops_redirect_arrow():
    """dirsearch prints ``->`` for redirects — those tokens are ignored."""
    status, url = dedup_urls.parse_line(
        "301     0B   https://example.com/admin  ->  https://example.com/admin/"
    )
    assert status == "301"
    assert url == "https://example.com/admin"


def test_parse_line_returns_none_for_garbage():
    assert dedup_urls.parse_line("") is None
    assert dedup_urls.parse_line("hello world") is None
    assert dedup_urls.parse_line("not a dirsearch line at all") is None
    assert dedup_urls.parse_line("200  https://x.com") is None  # only 2 parts


def test_parse_line_finds_url_among_other_tokens():
    """URL doesn't have to be at position 2 if there are intermediate tokens."""
    status, url = dedup_urls.parse_line(
        "404  200B  https://example.com/.git/HEAD"
    )
    assert url == "https://example.com/.git/HEAD"


# ----------------------------------------------------------------------
# dedup_file
# ----------------------------------------------------------------------
def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "dirsearch.txt"
    p.write_text(content)
    return p


def test_dedup_file_first_occurrence_wins(tmp_path):
    p = _write(tmp_path,
        "200  10B  https://a.example.com\n"
        "200  10B  https://a.example.com\n"   # duplicate
        "200  10B  https://b.example.com\n"
    )
    lines, skipped = dedup_urls.dedup_file(p)
    assert lines == [
        "https://a.example.com",
        "https://b.example.com",
    ]
    assert skipped == 1   # the duplicate


def test_dedup_file_keeps_order(tmp_path):
    """Output order matches first-occurrence order (stable)."""
    p = _write(tmp_path,
        "200  1B  https://c.example.com\n"
        "200  1B  https://a.example.com\n"
        "200  1B  https://c.example.com\n"
        "200  1B  https://b.example.com\n"
    )
    lines, _ = dedup_urls.dedup_file(p)
    assert lines == [
        "https://c.example.com",
        "https://a.example.com",
        "https://b.example.com",
    ]


def test_dedup_file_skips_garbage(tmp_path):
    p = _write(tmp_path,
        "garbage line with no URL\n"
        "200  10B  https://a.example.com\n"
        "\n"
        "another bad line\n"
        "200  10B  https://b.example.com\n"
    )
    lines, skipped = dedup_urls.dedup_file(p)
    assert lines == [
        "https://a.example.com",
        "https://b.example.com",
    ]
    # Three garbage lines: the two non-URL lines + the blank line.
    assert skipped == 3


def test_dedup_file_status_filter(tmp_path):
    p = _write(tmp_path,
        "200  10B  https://a.example.com\n"
        "404  10B  https://b.example.com\n"
        "500  10B  https://c.example.com\n"
        "200  10B  https://a.example.com\n"   # duplicate of first
    )
    lines, skipped = dedup_urls.dedup_file(p, status_filter={"200", "500"})
    assert lines == [
        "https://a.example.com",
        "https://c.example.com",
    ]
    # 1 × 404 dropped, 1 × duplicate of 200 dropped
    assert skipped == 2


def test_dedup_file_empty(tmp_path):
    p = _write(tmp_path, "")
    lines, skipped = dedup_urls.dedup_file(p)
    assert lines == []
    assert skipped == 0


# ----------------------------------------------------------------------
# CLI integration — drive main() directly by patching argv
# ----------------------------------------------------------------------
def _drive(argv: list[str]):
    """Set sys.argv, call main(), restore argv. Returns (rc, stdout, stderr)."""
    import sys as _sys
    saved = _sys.argv
    _sys.argv = argv
    from io import StringIO
    out, err = StringIO(), StringIO()
    saved_stdout, saved_stderr = _sys.stdout, _sys.stderr
    _sys.stdout, _sys.stderr = out, err
    try:
        rc = dedup_urls.main()
        return rc, out.getvalue(), err.getvalue()
    finally:
        _sys.argv = saved
        _sys.stdout, _sys.stderr = saved_stdout, saved_stderr


def test_main_writes_to_stdout(tmp_path):
    p = _write(tmp_path,
        "200  10B  https://a.example.com\n"
        "200  10B  https://a.example.com\n"
        "200  10B  https://b.example.com\n"
    )
    rc, out, err = _drive(["dedup-urls", str(p)])
    assert rc == 0
    assert "https://a.example.com" in out
    assert "https://b.example.com" in out
    # Duplicate is dropped — only one 'a' line.
    assert out.count("https://a.example.com") == 1
    # Status message on stderr.
    assert "2 unique URLs" in err


def test_main_in_place_rewrites_file(tmp_path):
    p = _write(tmp_path,
        "200  10B  https://a.example.com\n"
        "200  10B  https://a.example.com\n"
        "200  10B  https://b.example.com\n"
    )
    rc, _, err = _drive(["dedup-urls", "-i", str(p)])
    assert rc == 0
    content = p.read_text()
    # File now contains one URL per line, no duplicates.
    assert content.count("https://a.example.com") == 1
    assert content.count("https://b.example.com") == 1
    # Stderr announces the rewrite.
    assert "wrote 2 unique URLs" in err


def test_main_status_flag_filter(tmp_path):
    p = _write(tmp_path,
        "200  10B  https://a.example.com\n"
        "404  10B  https://b.example.com\n"
        "500  10B  https://c.example.com\n"
    )
    rc, out, _ = _drive(["dedup-urls", "--status", "200,500", str(p)])
    assert rc == 0
    assert "https://a.example.com" in out
    assert "https://c.example.com" in out
    # 404 dropped.
    assert "https://b.example.com" not in out


def test_main_missing_file_exits_2(tmp_path):
    rc, _, err = _drive(["dedup-urls", str(tmp_path / "nope.txt")])
    assert rc == 2
    assert "does not exist" in err