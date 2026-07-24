"""Tests for nuclei.endpoints_scan — scanning discovered live endpoints.

Closes the coverage gap where nuclei_default only saw the root hosts.
endpoints_scan runs after discovery on alive_urls.txt and writes to
findings/endpoints/.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import nuclei as nuclei_mod
from modules.nuclei import _filter_endpoint_urls
from modules.utils import create_output_structure, read_lines, write_lines


def _fake_run_writes_json(captured: list):
    """Return a runner.run stand-in that records argv and writes a finding
    to the -json-export path so _run's parser has something to read."""
    def _fake(cmd, **kw):
        captured.clear()
        captured.extend(cmd)
        jpath = Path(cmd[cmd.index("-json-export") + 1])
        jpath.parent.mkdir(parents=True, exist_ok=True)
        jpath.write_text(json.dumps([
            {"template-id": "backup-file",
             "info": {"name": "Backup", "severity": "medium"},
             "matched-at": "https://x.com/backup.zip"},
        ]))
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "", "duration": 1}
    return _fake


def test_endpoints_scan_writes_to_endpoints_findings_dir(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run_writes_json(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/backup.zip", "https://x.com/a"])

    res = nuclei_mod.endpoints_scan(alive_urls, base, {}, skip=False)
    assert res["status"] == "success"
    assert res["stage"] == "nuclei_endpoints"
    # output must land in findings/endpoints/, not default/dynamic
    assert (base / "findings" / "endpoints" / "nuclei.json").exists()
    assert res["count"] == 1
    # default severity is critical,high,medium (no info/low noise)
    sev = captured[captured.index("-severity") + 1]
    assert sev == "critical,high,medium"


def test_endpoints_scan_respects_custom_severity(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run_writes_json(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/a"])

    cfg = {"nuclei": {"endpoints": {"severity": ["critical", "high"]}}}
    nuclei_mod.endpoints_scan(alive_urls, base, cfg, skip=False)
    assert captured[captured.index("-severity") + 1] == "critical,high"


def test_endpoints_scan_disabled_in_config(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/a"])

    cfg = {"nuclei": {"endpoints": {"enabled": False}}}
    res = nuclei_mod.endpoints_scan(alive_urls, base, cfg, skip=False)
    assert res["status"] == "skipped"
    assert "disabled" in (res["error"] or "")


def test_endpoints_scan_skip_flag(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/a"])

    res = nuclei_mod.endpoints_scan(alive_urls, base, {}, skip=True)
    assert res["status"] == "skipped"
    # skip still writes empty artefacts so downstream readers don't crash
    assert (base / "findings" / "endpoints" / "nuclei.json").exists()


# ----------------------------------------------------------------------
# _filter_endpoint_urls — pure helper, no requirement for a query param
# (unlike _filter_param_urls, which only exists to feed dynamic_scan)
# ----------------------------------------------------------------------
def test_filter_endpoint_urls_dedups_same_host_path(tmp_path):
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, [
        "https://x.com/a?ref=1",
        "https://x.com/a?ref=2",   # same host+path, different query → dedup
        "https://x.com/b",
    ])
    scan_file, stats = _filter_endpoint_urls(inp, tmp_path)

    assert stats["deduped"] == 1
    assert stats["selected"] == 2
    assert read_lines(scan_file) == ["https://x.com/a?ref=1", "https://x.com/b"]


def test_filter_endpoint_urls_noop_when_nothing_to_change(tmp_path):
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, ["https://x.com/a", "https://x.com/b"])
    scan_file, stats = _filter_endpoint_urls(inp, tmp_path)

    assert stats["deduped"] == 0
    assert stats["capped"] == 0
    assert scan_file == inp
    assert not (tmp_path / "raw" / "nuclei_endpoints" / "endpoint_urls.txt").exists()


def test_filter_endpoint_urls_caps_keeping_high_value(tmp_path):
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, [
        "https://x.com/blog/post-1",     # low value
        "https://x.com/api/v1/user",     # high value (api hint)
        "https://x.com/blog/post-2",     # low value
    ])
    scan_file, stats = _filter_endpoint_urls(inp, tmp_path, max_urls=1)

    assert stats["capped"] == 2
    assert stats["selected"] == 1
    assert read_lines(scan_file) == ["https://x.com/api/v1/user"]


def test_endpoints_scan_caps_large_url_list(tmp_path, monkeypatch):
    """10k+ discovered URLs must not all be handed to nuclei uncapped —
    the exact failure mode that walled a real scan at its 7200s timeout
    with 0 findings (see logs/stages.json from that run)."""
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run_writes_json(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, [f"https://x.com/p{i}" for i in range(20)])

    cfg = {"nuclei": {"endpoints": {"max_urls": 5}}}
    res = nuclei_mod.endpoints_scan(alive_urls, base, cfg, skip=False)

    scanned = read_lines(Path(captured[captured.index("-l") + 1]))
    assert len(scanned) == 5
    assert res["extra"]["url_filter"]["capped"] == 15
