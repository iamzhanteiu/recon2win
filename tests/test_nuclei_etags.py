"""Tests for the nuclei -etags (exclude-tags) feature.

Covers:
  * exclude_tags config field → -etags flag in argv
  * whitespace / empty entries are stripped
  * exclude_tags works alongside -tags (both can be active)
  * empty list → no -etags flag (legacy behaviour)
"""
from __future__ import annotations

from pathlib import Path


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
    """Build the nuclei argv with cfg as the user-supplied config.

    Calls the real builder rather than replicating it — an earlier copy of
    this logic silently drifted out of sync with the module it was meant
    to be testing.
    """
    n_cfg = cfg.get("nuclei", {})
    return nuclei_mod._build_nuclei_cmd(
        Path("x"), Path("x.jsonl"),
        severity=n_cfg.get("severity", ["info"]),
        tags=n_cfg.get("tags"),
        n_cfg=n_cfg,
    )


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


def test_dast_flag_emitted_only_when_enabled():
    """nuclei refuses to load its ~250 fuzzing templates without -dast
    (it errors with "no templates provided for scan" if they are all you
    ask for), and their tags look like ordinary ones — so a missing flag
    silently drops every fuzzing template. Off unless asked for."""
    assert "-dast" not in _nuclei_cmd({"nuclei": {}})
    assert "-dast" not in _nuclei_cmd({"nuclei": {"dast": False}})
    assert "-dast" in _nuclei_cmd({"nuclei": {"dast": True}})


def test_default_scan_passes_per_scan_dast_to_argv(tmp_path, monkeypatch):
    """``dast`` is opt-in per scan via ``nuclei.default.dast``; the
    per-scan sub-config must actually reach the nuclei argv."""
    captured: list[str] = []

    def fake_run(cmd, **kw):
        captured.extend(cmd)
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("")
        return _fake_run_for_nuclei(cmd)

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    (tmp_path / "findings" / "default").mkdir(parents=True)
    params = tmp_path / "params.txt"
    params.write_text("https://example.com/a?id=1\n")

    nuclei_mod.default_scan(
        params, tmp_path,
        cfg={"nuclei": {"default": {"enabled": True, "dast": True}}},
        resume=False, dry_run=False, skip=False,
    )
    assert "-dast" in captured


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
        json_out = Path(cmd[cmd.index("-o") + 1])
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text("")
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

# ----------------------------------------------------------------------
# -fuzz-aggression + the "no -tags under -dast" rule
# ----------------------------------------------------------------------
def test_fuzz_aggression_only_applies_to_dast_runs():
    """-fuzz-aggression is a DAST-only knob (payload count per fuzz
    point). It must not leak into the default/endpoints scans, which load
    no fuzzing templates at all."""
    assert "-fuzz-aggression" not in _nuclei_cmd(
        {"nuclei": {"fuzz_aggression": "medium"}})
    cmd = _nuclei_cmd({"nuclei": {"dast": True, "fuzz_aggression": "medium"}})
    assert cmd[cmd.index("-fuzz-aggression") + 1] == "medium"


def test_fuzz_aggression_omitted_when_unset():
    """Unset / blank → don't pass the flag, let nuclei use its default."""
    assert "-fuzz-aggression" not in _nuclei_cmd({"nuclei": {"dast": True}})
    assert "-fuzz-aggression" not in _nuclei_cmd(
        {"nuclei": {"dast": True, "fuzz_aggression": "  "}})


def test_dast_run_ships_without_a_tags_filter():
    """``-dast`` IS the filter — it restricts the run to the fuzzing
    corpus (54 loadable templates on nuclei-templates v10.4.6). Layering
    the old tag set on top cut that to 41, dropping cmdi / crlf /
    open-redirect / rfi / xinclude / csv-injection and the DAST CVE
    templates. An empty tags list must therefore emit no -tags at all."""
    cmd = _nuclei_cmd({"nuclei": {"dast": True, "tags": []}})
    assert "-dast" in cmd
    assert "-tags" not in cmd
