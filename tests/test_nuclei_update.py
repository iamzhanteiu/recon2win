"""Tests for nuclei.update_templates — refresh templates before scanning."""
from __future__ import annotations

from pathlib import Path

from modules import nuclei as nuclei_mod
from modules.utils import create_output_structure


def _ok_run(captured: list):
    def _fake(cmd, **kw):
        captured.clear()
        captured.extend(cmd)
        return {"returncode": 0, "stdout": "", "stderr": "", "success": True,
                "missing_binary": False, "timed_out": False,
                "stdout_path": "", "stderr_path": "", "log_path": "", "duration": 1}
    return _fake


def test_update_runs_nuclei_update_templates(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _ok_run(captured))
    base = create_output_structure("x.com", root=str(tmp_path))
    res = nuclei_mod.update_templates(base, {})
    assert res["status"] == "success"
    assert captured[:2] == ["nuclei", "-update-templates"]


def test_update_disabled_in_config(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    res = nuclei_mod.update_templates(base, {"nuclei": {"update_templates": False}})
    assert res["status"] == "skipped"
    assert "disabled" in (res["error"] or "")


def test_update_skipped_on_skip_flag(tmp_path):
    base = create_output_structure("x.com", root=str(tmp_path))
    assert nuclei_mod.update_templates(base, {}, skip=True)["status"] == "skipped"


def test_update_skipped_on_dry_run(tmp_path):
    base = create_output_structure("x.com", root=str(tmp_path))
    assert nuclei_mod.update_templates(base, {}, dry_run=True)["status"] == "skipped"


def test_update_skipped_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: False)
    base = create_output_structure("x.com", root=str(tmp_path))
    res = nuclei_mod.update_templates(base, {})
    assert res["status"] == "skipped"
    assert "not found" in (res["error"] or "")


def test_update_failure_is_non_fatal(tmp_path, monkeypatch):
    def _fail(cmd, **kw):
        return {"returncode": 1, "stdout": "", "stderr": "network error",
                "success": False, "missing_binary": False, "timed_out": False,
                "stdout_path": "", "stderr_path": "", "log_path": "", "duration": 1}
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fail)
    base = create_output_structure("x.com", root=str(tmp_path))
    res = nuclei_mod.update_templates(base, {})
    assert res["status"] == "failed"       # reported, but caller treats as non-fatal
