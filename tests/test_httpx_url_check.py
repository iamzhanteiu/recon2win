"""Tests for httpx stage 6.1 (URL alive-check) input cap + timeout salvage.

Two failure modes from a real large-target run motivate these:
  * 400k+ merged URLs blow the 1800s timeout → we cap the list
    (``httpx.max_url_check``) to the highest-value URLs first.
  * On timeout httpx has already streamed partial results to ``-o``;
    we salvage them so ``alive_urls.txt`` isn't empty — an empty file
    silently STARVES nuclei_endpoints (it skips on empty input).
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import httpx as httpx_mod
from modules.httpx import _cap_urls, _score_url, _table_path, _write_alive_table
from modules.utils import read_lines, write_lines


# ----------------------------------------------------------------------
# _write_alive_table — status | length | content-type | url companion
# ----------------------------------------------------------------------
def test_table_path_names_companion():
    assert _table_path(Path("/o/processed/alive_urls.txt")).name == "alive_urls_table.txt"
    assert _table_path(Path("/o/processed/alive.txt")).name == "alive_table.txt"


def test_alive_table_columns_sort_and_defaults(tmp_path: Path):
    rows = [
        {"url": "https://x.com/big", "status_code": 200, "content_length": 5000,
         "content_type": "text/html; charset=utf-8"},
        {"url": "https://x.com/api", "status_code": 200, "content_length": 90,
         "content_type": "application/json"},
        {"url": "https://x.com/gone", "status_code": 404},  # missing len/ctype
        {"status_code": 200, "content_length": 1},           # no url → skipped
    ]
    out = tmp_path / "alive_urls_table.txt"
    n = _write_alive_table(rows, out)
    assert n == 3  # url-less row dropped
    lines = out.read_text().splitlines()
    assert lines[0].split() == ["ST", "LENGTH", "CONTENT-TYPE", "URL"]
    # sorted by (status, -length): 200/5000, then 200/90, then 404
    assert lines[1].split() == ["200", "5000", "text/html", "https://x.com/big"]
    assert lines[2].split() == ["200", "90", "application/json", "https://x.com/api"]
    # missing content_type → "-", missing length → 0; charset param stripped
    assert lines[3].split() == ["404", "0", "-", "https://x.com/gone"]


# ----------------------------------------------------------------------
# _cap_urls — pure-ish helper
# ----------------------------------------------------------------------
def test_cap_is_noop_when_under_limit(tmp_path: Path):
    inp = tmp_path / "all_urls.txt"
    write_lines(inp, ["https://x.com/a", "https://x.com/b"])
    scan_file, total, kept, n_static = _cap_urls(inp, tmp_path, 60000)
    assert (total, kept, n_static) == (2, 2, 0)
    assert scan_file == inp  # original returned untouched


def test_cap_keeps_high_value_urls_first(tmp_path: Path):
    inp = tmp_path / "all_urls.txt"
    write_lines(inp, [
        "https://x.com/static/img/1.png",
        "https://x.com/static/img/2.png",
        "https://x.com/api/v1/user?id=7",   # high value
    ])
    scan_file, total, kept, _ = _cap_urls(inp, tmp_path, 1)
    assert (total, kept) == (3, 1)
    assert scan_file != inp
    assert read_lines(scan_file) == ["https://x.com/api/v1/user?id=7"]


def test_cap_drops_static_before_probing(tmp_path: Path):
    inp = tmp_path / "all_urls.txt"
    write_lines(inp, [
        "https://x.com/logo.png", "https://x.com/app.css",
        "https://x.com/font.woff2", "https://x.com/main.js",   # .js is KEPT
        "https://x.com/api/user?id=1",
    ])
    scan_file, total, kept, n_static = _cap_urls(
        inp, tmp_path, 60000, drop_static=True)
    assert total == 5
    assert n_static == 3            # png + css + woff2 dropped
    survivors = read_lines(scan_file)
    assert "https://x.com/main.js" in survivors       # JS kept for analysis
    assert "https://x.com/api/user?id=1" in survivors
    assert not any(u.endswith((".png", ".css", ".woff2")) for u in survivors)


def test_score_prefers_params_and_api():
    assert _score_url("https://x.com/api/user?id=1") > _score_url("https://x.com/style.css")


# ----------------------------------------------------------------------
# check_urls — salvage partial output on timeout
# ----------------------------------------------------------------------
def _fake_run_factory(detail_rows: list[dict], *, timed_out: bool):
    def fake_run(cmd, **kw):
        # Emulate httpx streaming JSONL to its ``-o`` file, then a timeout.
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(json.dumps(r) for r in detail_rows))
        return {
            "returncode": -1 if timed_out else 0,
            "stdout": "", "stderr": "timeout" if timed_out else "",
            "missing_binary": False, "timed_out": timed_out,
            "success": not timed_out,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }
    return fake_run


def test_check_urls_salvages_partial_on_timeout(tmp_path: Path, monkeypatch):
    rows = [
        {"url": "https://x.com/a", "status_code": 200},
        {"url": "https://x.com/b", "status_code": 200},
    ]
    monkeypatch.setattr("modules.runner.run", _fake_run_factory(rows, timed_out=True))
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    urls = tmp_path / "processed" / "all_urls.txt"
    urls.parent.mkdir(parents=True)
    write_lines(urls, ["https://x.com/a", "https://x.com/b"])

    res = httpx_mod.check_urls(urls, tmp_path, cfg={}, resume=False, dry_run=False)

    alive = tmp_path / "processed" / "alive_urls.txt"
    # The critical property: alive_urls.txt is NOT empty after a timeout,
    # so nuclei_endpoints downstream has real input.
    assert read_lines(alive) == ["https://x.com/a", "https://x.com/b"]
    assert res["status"] == "failed"          # honestly flags the timeout
    assert res["count"] == 2                   # but reports salvaged data
    assert "salvaged" in (res["error"] or "")


def test_check_urls_success_path_unchanged(tmp_path: Path, monkeypatch):
    rows = [{"url": "https://x.com/a", "status_code": 200}]
    monkeypatch.setattr("modules.runner.run", _fake_run_factory(rows, timed_out=False))
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    urls = tmp_path / "processed" / "all_urls.txt"
    urls.parent.mkdir(parents=True)
    write_lines(urls, ["https://x.com/a"])

    res = httpx_mod.check_urls(urls, tmp_path, cfg={}, resume=False, dry_run=False)
    assert res["status"] == "success"
    assert res["count"] == 1
    assert read_lines(tmp_path / "processed" / "alive_urls.txt") == ["https://x.com/a"]
