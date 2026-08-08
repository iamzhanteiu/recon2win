"""Tests for modules/fuzz_recurse.py — fuzzing under discovered directories.

The value of the stage is entirely in WHICH directories it decides to fuzz:
it must find the roots the corpus revealed, rank the interesting ones above
static-asset trees, and collapse wildcard-duplicate hosts to one — all
before spending a single request.
"""
from __future__ import annotations

import json

from modules import fuzz_recurse as fr
from modules import layout
from modules.utils import create_output_structure, read_lines, write_lines


# ----------------------------------------------------------------------
# dir_prefixes / dir_interest — pure
# ----------------------------------------------------------------------
def test_dir_prefixes_of_file_path():
    assert fr.dir_prefixes("/a/b/c.php", 3) == ["/a/", "/a/b/"]


def test_dir_prefixes_of_dir_path():
    assert fr.dir_prefixes("/a/b/", 3) == ["/a/", "/a/b/"]


def test_dir_prefixes_root_is_empty():
    assert fr.dir_prefixes("/", 3) == []


def test_dir_prefixes_respects_max_depth():
    assert fr.dir_prefixes("/a/b/c/d/e/", 2) == ["/a/", "/a/b/"]


def test_dir_interest_api_beats_generic():
    assert fr.dir_interest("/api/") > fr.dir_interest("/blog/")


def test_dir_interest_static_is_negative():
    assert fr.dir_interest("/static/img/") < 0
    assert fr.dir_interest("/assets/js/") < 0


# ----------------------------------------------------------------------
# collect_dir_targets
# ----------------------------------------------------------------------
def test_collect_groups_by_host_and_orders_by_interest():
    urls = [
        "https://h.com/blog/post.html",
        "https://h.com/api/v2/keys.json",
        "https://h.com/static/app.js",       # dropped (skip tree)
    ]
    got = fr.collect_dir_targets(urls, max_depth=3)
    assert set(got) == {"https://h.com"}
    dirs = got["https://h.com"]
    assert "/static/" not in dirs
    # /api/ ranks above /blog/
    assert dirs.index("/api/") < dirs.index("/blog/")


def test_collect_dedupes_dirs():
    urls = ["https://h.com/api/a", "https://h.com/api/b", "https://h.com/api/c"]
    got = fr.collect_dir_targets(urls, max_depth=3)
    assert got["https://h.com"].count("/api/") == 1


# ----------------------------------------------------------------------
# scan — plan + skip/dry-run paths
# ----------------------------------------------------------------------
def _base(tmp_path, urls):
    base = create_output_structure("example.com", root=str(tmp_path))
    write_lines(layout.path(base, "all_urls.txt"), urls)
    return base


def test_scan_disabled_writes_empty(tmp_path):
    base = _base(tmp_path, ["https://a.example.com/api/x"])
    res = fr.scan(base, {"fuzz_recurse": {"enabled": False}})
    assert res["status"] == "skipped"
    assert read_lines(layout.path(base, "fuzz_recurse_urls.txt")) == []


def test_scan_skip_flag(tmp_path):
    base = _base(tmp_path, ["https://a.example.com/api/x"])
    res = fr.scan(base, {}, skip=True)
    assert res["status"] == "skipped"
    assert res["error"] == "--skip-fuzz-recurse"


def test_scan_dry_run_reports_targets(tmp_path):
    base = _base(tmp_path, ["https://a.example.com/api/v2/x",
                            "https://a.example.com/admin/"])
    res = fr.scan(base, {"fuzz_recurse": {}}, dry_run=True)
    assert res["status"] == "skipped"
    assert res["extra"]["targets"] >= 2
    assert res["extra"]["planned_cmd"][0] == "ffuf"


def test_scan_parses_hits_and_writes_urls(tmp_path, monkeypatch):
    base = _base(tmp_path, ["https://a.example.com/api/users.json"])
    monkeypatch.setattr(fr.runner, "tool_available", lambda b: True)

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-o") + 1]
        report = {"results": [
            {"url": "https://a.example.com/api/secret", "status": 200,
             "length": 12, "words": 3, "lines": 1, "content-type": "application/json"},
        ]}
        with open(out, "w") as fh:
            json.dump(report, fh)
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(fr.runner, "run", fake_run)
    res = fr.scan(base, {"fuzz_recurse": {}})
    assert res["status"] == "success"
    urls = read_lines(layout.path(base, "fuzz_recurse_urls.txt"))
    assert "https://a.example.com/api/secret" in urls


def test_scan_no_dirs_is_success_not_failure(tmp_path, monkeypatch):
    # only a root URL → nothing to recurse into
    base = _base(tmp_path, ["https://a.example.com/"])
    monkeypatch.setattr(fr.runner, "tool_available", lambda b: True)
    res = fr.scan(base, {"fuzz_recurse": {}})
    assert res["status"] == "success"
    assert res["count"] == 0
