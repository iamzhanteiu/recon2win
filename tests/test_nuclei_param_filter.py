"""Tests for the nuclei_dynamic "parameterised endpoints only" guard.

The dynamic scan is meant to fuzz URLs that carry a query parameter
(``?name=``). Upstream (arjun + jsluice) already produce such URLs, but
``dynamic_scan`` enforces it at the scan boundary so a bare URL that leaks
into ``parameterized_urls.txt`` never reaches nuclei.

Covers:
  * _has_param — requires both ``?`` and a ``name=`` pair
  * _filter_param_urls — drops bare URLs, no-op when nothing to drop
  * dynamic_scan — nuclei receives only the param URLs, and the drop
    count is surfaced in result["extra"]["param_filter"]
"""
from __future__ import annotations

from pathlib import Path

from modules import nuclei as nuclei_mod
from modules.nuclei import _has_param, _filter_param_urls
from modules.utils import read_lines, write_lines


# ----------------------------------------------------------------------
# _has_param — pure helper, no I/O
# ----------------------------------------------------------------------
def test_has_param_true_for_query_pair():
    assert _has_param("https://x.com/api?id=&q=")
    assert _has_param("https://x.com/api?token=")


def test_has_param_false_for_bare_url():
    assert not _has_param("https://x.com/api")
    assert not _has_param("https://x.com/")


def test_has_param_false_for_empty_query_string():
    """A trailing ``?`` with no ``name=`` pair is nothing to fuzz."""
    assert not _has_param("https://x.com/api?")


# ----------------------------------------------------------------------
# _filter_param_urls — writes a derived input, no-op when clean
# ----------------------------------------------------------------------
def test_filter_drops_bare_urls(tmp_path: Path):
    inp = tmp_path / "processed" / "parameterized_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, [
        "https://x.com/a?id=&q=",
        "https://x.com/bare",
        "https://x.com/b?t=",
    ])
    scan_file, stats = _filter_param_urls(inp, tmp_path)

    assert stats["dropped_no_param"] == 1
    assert stats["selected"] == 2
    # A derived file under raw/nuclei_dynamic/ — not the original.
    assert scan_file != inp
    assert scan_file.as_posix().endswith("raw/nuclei_dynamic/param_urls.txt")
    assert read_lines(scan_file) == [
        "https://x.com/a?id=&q=",
        "https://x.com/b?t=",
    ]


def test_filter_is_noop_when_all_have_params(tmp_path: Path):
    """Nothing dropped → return the original file untouched (no stray
    derived file for the common case)."""
    inp = tmp_path / "processed" / "parameterized_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, ["https://x.com/a?id=", "https://x.com/b?q="])
    scan_file, stats = _filter_param_urls(inp, tmp_path)

    assert stats["selected"] == 2
    assert stats["dropped_no_param"] == 0
    assert stats["deduped"] == 0
    assert stats["capped"] == 0
    assert scan_file == inp
    assert not (tmp_path / "raw" / "nuclei_dynamic" / "param_urls.txt").exists()


# ----------------------------------------------------------------------
# _filter_param_urls — dedup near-identical param shapes + cap
# ----------------------------------------------------------------------
def test_filter_dedups_same_param_shape(tmp_path: Path):
    """``?id=1`` and ``?id=2`` fuzz identically — collapse to one."""
    inp = tmp_path / "processed" / "parameterized_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, [
        "https://x.com/a?id=1",
        "https://x.com/a?id=2",     # same shape as line 1 → deduped
        "https://x.com/a?id=3",     # same shape → deduped
        "https://x.com/b?q=x",      # distinct shape
    ])
    scan_file, stats = _filter_param_urls(inp, tmp_path)

    assert stats["deduped"] == 2
    assert stats["selected"] == 2
    assert read_lines(scan_file) == [
        "https://x.com/a?id=1",
        "https://x.com/b?q=x",
    ]


def test_filter_caps_to_max_urls_keeping_high_value(tmp_path: Path):
    inp = tmp_path / "processed" / "parameterized_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, [
        "https://x.com/blog/1?ref=a",         # low value
        "https://x.com/blog/2?ref=b",         # low value
        "https://x.com/api/v1/user?id=7",     # high value (api + id=)
    ])
    scan_file, stats = _filter_param_urls(inp, tmp_path, max_urls=1)

    assert stats["capped"] == 2
    assert stats["selected"] == 1
    # The high-value api/id URL survives the cap.
    assert read_lines(scan_file) == ["https://x.com/api/v1/user?id=7"]


# ----------------------------------------------------------------------
# dynamic_scan — end-to-end: nuclei only sees param URLs
# ----------------------------------------------------------------------
def test_dynamic_scan_feeds_only_param_urls_to_nuclei(tmp_path: Path, monkeypatch):
    captured_cmd: list[str] = []

    def fake_run(cmd, **kw):
        captured_cmd.extend(cmd)
        json_out = Path(cmd[cmd.index("-o") + 1])
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text("")
        return {
            "returncode": 0, "stdout": "", "stderr": "",
            "missing_binary": False, "timed_out": False, "success": True,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    param_urls = tmp_path / "processed" / "parameterized_urls.txt"
    param_urls.parent.mkdir(parents=True)
    write_lines(param_urls, [
        "https://x.com/a?id=",
        "https://x.com/leaked-bare-url",   # must be dropped
        "https://x.com/b?token=",
    ])

    res = nuclei_mod.dynamic_scan(
        param_urls, tmp_path,
        cfg={"nuclei": {"dynamic": {"enabled": True}}},
        resume=False, dry_run=False, skip=False,
    )

    # nuclei's -l must point at the filtered derived file, and that file
    # must NOT contain the bare URL.
    scanned = read_lines(Path(captured_cmd[captured_cmd.index("-l") + 1]))
    assert scanned == ["https://x.com/a?id=", "https://x.com/b?token="]

    # The drop is surfaced for the report.
    pf = res["extra"]["param_filter"]
    assert pf["dropped_no_param"] == 1
    assert pf["selected"] == 2


def test_dynamic_scan_no_param_filter_key_when_nothing_dropped(tmp_path: Path, monkeypatch):
    def fake_run(cmd, **kw):
        json_out = Path(cmd[cmd.index("-o") + 1])
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text("")
        return {
            "returncode": 0, "stdout": "", "stderr": "",
            "missing_binary": False, "timed_out": False, "success": True,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    param_urls = tmp_path / "processed" / "parameterized_urls.txt"
    param_urls.parent.mkdir(parents=True)
    write_lines(param_urls, ["https://x.com/a?id="])

    res = nuclei_mod.dynamic_scan(
        param_urls, tmp_path,
        cfg={"nuclei": {"dynamic": {"enabled": True}}},
        resume=False, dry_run=False, skip=False,
    )
    assert "param_filter" not in (res.get("extra") or {})
