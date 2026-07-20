"""Tests for nuclei.endpoints_scan — scanning discovered live endpoints.

Closes the coverage gap where nuclei_default only saw the root hosts.
endpoints_scan runs after discovery on alive_urls.txt and writes to
findings/endpoints/.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import nuclei as nuclei_mod
from modules.utils import create_output_structure, write_lines


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
