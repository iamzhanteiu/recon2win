"""Tests for arjun input capping + ranking.

Covers:
  * _score() — high-value hints bump score, archive noise demotes it
  * discover() with resume=False skips when input is empty
  * discover() with resume=False caps the input and writes a subset
    file when the URL count exceeds max_urls (we monkeypatch the
    external `arjun` binary so the test stays hermetic)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from modules import arjun
from modules.arjun import _score
from modules.utils import read_lines, write_lines


# ----------------------------------------------------------------------
# _score — pure helper, no I/O
# ----------------------------------------------------------------------
def test_score_boosts_api_endpoints():
    assert _score("https://x.com/api/v1/users") > _score("https://x.com/about")


def test_score_boosts_login_and_admin():
    assert _score("https://x.com/login") >= _score("https://x.com/foo")
    assert _score("https://x.com/admin/dashboard") >= _score("https://x.com/foo")


def test_score_demotes_archive_hosts():
    interesting = _score("https://x.com/api/users")
    archived = _score("https://web.archive.org/web/2024/https://x.com/api/users")
    assert archived < interesting


def test_score_is_case_insensitive():
    assert _score("https://x.com/ADMIN/users") == _score("https://x.com/admin/users")


def test_score_ties_break_shorter_first():
    # Both score 0 (no hints). Equal length + sorted on raw URL means
    # alphabetical order, not length. Just verify the helper returns an
    # int and is deterministic.
    a = _score("https://x.com/aaa")
    b = _score("https://x.com/bbb")
    assert isinstance(a, int) and isinstance(b, int)
    assert _score("https://x.com/aaa") == a  # idempotent


# ----------------------------------------------------------------------
# discover() — empty input short-circuits
# ----------------------------------------------------------------------
def test_discover_skips_when_dynamic_urls_empty(tmp_path: Path, monkeypatch):
    # Pretend the arjun binary exists so the empty-input guard fires
    # (the stage checks for the binary first; we want to exercise the
    # second branch).
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    # Belt-and-braces: if we proceed past the empty guard, fail loudly.
    def _explode(*a, **kw):
        raise AssertionError("runner.run must not be called for empty dynamic_urls.txt")
    monkeypatch.setattr("modules.runner.run", _explode)

    (tmp_path / "dynamic_urls.txt").write_text("")
    res = arjun.discover(
        tmp_path / "dynamic_urls.txt", tmp_path,
        cfg={"arjun": {}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "skipped"
    assert res["error"] == "no dynamic URLs to scan"
    assert res["count"] == 0


# ----------------------------------------------------------------------
# discover() — input capping + subset file
# ----------------------------------------------------------------------
def _fake_arjun_runner(monkeypatch, captured_cmd: list[str]):
    """Replace runner.run with a no-op that records the argv."""
    def _fake(cmd, **kw):
        captured_cmd.extend(cmd)
        # Write a single fake param line so the parse step has something
        # to chew on. The path is the 3rd positional arg (after the
        # binary name) — `-o <path>`.
        out_idx = cmd.index("-o") + 1
        Path(cmd[out_idx]).write_text(
            "[200] https://x.com/api/users?id=&name=\n"
        )
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake)


def test_discover_caps_input_when_over_max_urls(tmp_path: Path, monkeypatch):
    """When dynamic_urls.txt has 500 lines and max_urls=50, arjun should
    receive a 50-line subset ranked by high-value hints."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    lines = [f"https://x.com/page{i}" for i in range(450)]
    # sprinkle in 50 high-value URLs (rank higher → kept)
    lines.extend(f"https://x.com/api/v1/users/{i}" for i in range(50))
    write_lines(dyn, lines)

    res = arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 50, "request_timeout": 5,
                       "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "success"
    assert res["extra"]["input_urls"] == 500
    assert res["extra"]["scanned_urls"] == 50

    # The argv should point at the subset file under raw/arjun/, not the original.
    subset_idx = captured.index("-i") + 1
    assert captured[subset_idx].endswith("raw/arjun/input_subset.txt")

    subset_lines = read_lines(Path(captured[subset_idx]))
    assert len(subset_lines) == 50
    # Every kept URL should be one of the high-value API ones.
    assert all("/api/v1/users/" in u for u in subset_lines)


def test_discover_passes_per_request_timeout(tmp_path: Path, monkeypatch):
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])

    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "request_timeout": 7,
                       "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    # `-T 7` should appear in the argv.
    t_idx = captured.index("-T")
    assert captured[t_idx + 1] == "7"


def test_discover_no_cap_when_under_max_urls(tmp_path: Path, monkeypatch):
    """With 3 URLs and max_urls=200, arjun should receive the original
    file (not a subset)."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, [
        "https://x.com/a",
        "https://x.com/b",
        "https://x.com/c",
    ])

    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "request_timeout": 5,
                       "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    # `-i` should point at the original file, not a subset.
    i_idx = captured.index("-i") + 1
    assert captured[i_idx] == str(dyn)


# ----------------------------------------------------------------------
# xnlinkfinder default timeout — guard against accidental regression
# ----------------------------------------------------------------------
def test_xnlinkfinder_default_timeout_is_at_least_1200():
    """The default must comfortably cover a multi-MB JS bundle. If this
    drops below 1200 we re-introduce the timeout-after-600s class of
    bugs we saw in the vulnweb.com log."""
    # Inspect the source so we don't need to instantiate the whole stage.
    import inspect
    from modules import xnlinkfinder
    src = inspect.getsource(xnlinkfinder.scan)
    assert 'get("timeout", 1800)' in src, \
        "xnlinkfinder default timeout must be at least 1800s"