"""Tests for the chaos sub-tool inside subdomain.collect().

Covers two real-world failures seen in the field:
  * chaos installed via Homebrew as ``chaos-client`` (not ``chaos``) —
    the stage must still find and run it.
  * no API key anywhere (config.yml nor $PDCP_API_KEY) — chaos always
    hard-fails with "PDCP_API_KEY not specified" in that case, so the
    stage should skip up front instead of shelling out to a call that's
    guaranteed to error.
"""
from __future__ import annotations

from modules import subdomain
from modules.utils import create_output_structure, read_lines


def _cfg(chaos_api_key: str = ""):
    return {
        "subdomain": {
            "tools": ["chaos"],
            "chaos_api_key": chaos_api_key,
        }
    }


def test_chaos_skipped_without_key_and_no_subprocess_call(tmp_path, monkeypatch):
    monkeypatch.delenv("PDCP_API_KEY", raising=False)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: b == "chaos")

    called = []
    monkeypatch.setattr("modules.runner.run", lambda *a, **kw: called.append(a))

    base = create_output_structure("x.com", root=str(tmp_path))
    subdomain.collect("x.com", base, _cfg(), resume=False, dry_run=False)

    assert called == []  # never invoked — key missing, skip up front
    assert read_lines(base / "raw" / "subdomain" / "chaos.txt") == []


def test_chaos_runs_when_env_key_present(tmp_path, monkeypatch):
    monkeypatch.setenv("PDCP_API_KEY", "envkey123")
    monkeypatch.setattr("modules.runner.tool_available", lambda b: b == "chaos")

    captured = []

    def fake_run(cmd, **kw):
        captured.extend(cmd)
        return {"success": True, "missing_binary": False, "stderr": ""}

    monkeypatch.setattr("modules.runner.run", fake_run)

    base = create_output_structure("x.com", root=str(tmp_path))
    subdomain.collect("x.com", base, _cfg(), resume=False, dry_run=False)

    assert captured[0] == "chaos"
    assert "-key" not in captured  # key comes from env, not config → no -key flag


def test_chaos_falls_back_to_chaos_client_binary(tmp_path, monkeypatch):
    """Homebrew's ``chaos-client`` formula installs the binary under that
    name, not ``chaos`` — the stage must still find and invoke it."""
    monkeypatch.setattr(
        "modules.runner.tool_available", lambda b: b == "chaos-client"
    )

    captured = []

    def fake_run(cmd, **kw):
        captured.extend(cmd)
        return {"success": True, "missing_binary": False, "stderr": ""}

    monkeypatch.setattr("modules.runner.run", fake_run)

    base = create_output_structure("x.com", root=str(tmp_path))
    subdomain.collect(
        "x.com", base, _cfg(chaos_api_key="cfgkey"), resume=False, dry_run=False,
    )

    assert captured[0] == "chaos-client"
    assert captured[captured.index("-key") + 1] == "cfgkey"


def test_chaos_skipped_when_neither_binary_installed(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: False)
    called = []
    monkeypatch.setattr("modules.runner.run", lambda *a, **kw: called.append(a))

    base = create_output_structure("x.com", root=str(tmp_path))
    subdomain.collect(
        "x.com", base, _cfg(chaos_api_key="cfgkey"), resume=False, dry_run=False,
    )

    assert called == []
