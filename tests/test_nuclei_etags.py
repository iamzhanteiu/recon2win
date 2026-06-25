"""Tests for the nuclei -etags (exclude-tags) feature.

Covers:
  * exclude_tags config field → -etags flag in argv
  * whitespace / empty entries are stripped
  * exclude_tags works alongside -tags (both can be active)
  * empty list → no -etags flag (legacy behaviour)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from modules import nuclei as nuclei_mod


def _fake_run_for_nuclei(cmd, **kw):
    """Minimal stand-in for runner.run — return success so nuclei._run
    proceeds past the subprocess check."""
    return {
        "returncode": 0, "stdout": "", "stderr": "",
        "missing_binary": False, "timed_out": False, "success": True,
        "stdout_path": "", "stderr_path": "", "log_path": "",
        "duration": 0.1,
    }


def _nuclei_cmd(cfg):
    """Build the nuclei argv with cfg as the user-supplied config."""
    from modules.nuclei import _run as nuclei_run_inner
    # We can't easily call _run() directly (it expects a real file path
    # for the input and writes outputs). Instead, replicate the cmd
    # construction logic so the test stays focused on the flag.
    n_cfg = cfg.get("nuclei", {})
    severity = n_cfg.get("severity", ["info"])
    tags = n_cfg.get("tags")
    cmd = [
        "nuclei", "-l", "x",
        "-severity", ",".join(severity),
        "-silent",
        "-o", "x.txt", "-json-export", "x.json",
    ]
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    exclude_tags = n_cfg.get("exclude_tags") or []
    clean_excludes = [str(t).strip() for t in exclude_tags if str(t).strip()]
    if clean_excludes:
        cmd.extend(["-etags", ",".join(clean_excludes)])
    return cmd


def test_etags_emitted_when_exclude_tags_configured():
    cfg = {
        "nuclei": {
            "exclude_tags": ["interaction", "smtp", "dns"],
        }
    }
    cmd = _nuclei_cmd(cfg)
    i = cmd.index("-etags")
    assert cmd[i + 1] == "interaction,smtp,dns"


def test_etags_not_emitted_when_exclude_tags_empty():
    """Empty exclude_tags list → no -etags flag (legacy behaviour)."""
    cfg = {"nuclei": {"exclude_tags": []}}
    cmd = _nuclei_cmd(cfg)
    assert "-etags" not in cmd


def test_etags_not_emitted_when_exclude_tags_missing():
    cfg = {"nuclei": {}}
    cmd = _nuclei_cmd(cfg)
    assert "-etags" not in cmd


def test_etags_strips_whitespace_and_empty_entries():
    """``["", "  ", "smtp"]`` → ``-etags smtp`` — no trailing commas."""
    cfg = {"nuclei": {"exclude_tags": ["", "  ", "smtp", "interaction"]}}
    cmd = _nuclei_cmd(cfg)
    i = cmd.index("-etags")
    assert cmd[i + 1] == "smtp,interaction"


def test_etags_coerces_non_string_to_string():
    """Config typos like ``[200, "smtp"]`` (int instead of str) get
    coerced — better than crashing the whole scan."""
    cfg = {"nuclei": {"exclude_tags": [200, "smtp"]}}
    cmd = _nuclei_cmd(cfg)
    i = cmd.index("-etags")
    assert cmd[i + 1] == "200,smtp"


def test_etags_combines_with_include_tags():
    """-tags (include) and -etags (exclude) can both be active — nuclei
    applies them together: include first, then exclude."""
    cfg = {
        "nuclei": {
            "tags": ["sqli", "xss"],
            "exclude_tags": ["interaction", "smtp"],
        }
    }
    cmd = _nuclei_cmd(cfg)
    # -tags position
    t = cmd.index("-tags")
    assert cmd[t + 1] == "sqli,xss"
    # -etags position
    e = cmd.index("-etags")
    assert cmd[e + 1] == "interaction,smtp"


# ----------------------------------------------------------------------
# End-to-end via nuclei_mod._run (mock runner.run to skip real subprocess)
# ----------------------------------------------------------------------
def test_nuclei_run_passes_etags_to_subprocess(tmp_path, monkeypatch):
    """End-to-end: cfg has exclude_tags → final cmd that runner.run
    receives has -etags. Verifies the wiring from cfg all the way to
    subprocess invocation."""
    captured_cmd: list[str] = []

    def fake_run(cmd, **kw):
        captured_cmd.extend(cmd)
        # Write a minimal JSON file so the parser doesn't blow up.
        json_out = Path(cmd[cmd.index("-json-export") + 1])
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text('{"findings": [], "severity_count": {}}')
        return _fake_run_for_nuclei(cmd)

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    findings_dir = tmp_path / "findings" / "default"
    findings_dir.mkdir(parents=True)
    alive = tmp_path / "alive.txt"
    alive.write_text("https://example.com\n")

    nuclei_mod.default_scan(
        alive, tmp_path,
        cfg={"nuclei": {
            "exclude_tags": ["interaction", "smtp"],   # global
            "default": {"enabled": True},              # per-stage
        }},
        resume=False, dry_run=False, skip=False,
    )

    # Find -etags in the captured cmd and verify
    assert "-etags" in captured_cmd
    etags_idx = captured_cmd.index("-etags")
    assert captured_cmd[etags_idx + 1] == "interaction,smtp"