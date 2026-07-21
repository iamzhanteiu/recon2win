"""Tests for the v2 output directory layout.

Covers:
  * create_output_structure() — creates the per-stage subdirs
  * raw_dir() / findings_dir() — typed accessors with validation
  * runner.run() with log_name= — sub-stages land in one log file
  * end-to-end smoke: subdomain + dirsearch populate the right paths
"""
from __future__ import annotations

from pathlib import Path

import pytest

from modules import runner
from modules.utils import (
    create_output_structure,
    findings_dir,
    raw_dir,
)


# ----------------------------------------------------------------------
# create_output_structure — v2 subdirs
# ----------------------------------------------------------------------
def test_create_output_structure_creates_per_stage_raw_subdirs(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    for stage in ("subdomain", "content_discovery", "dirsearch",
                  "waymore", "arjun"):
        assert (base / "raw" / stage).is_dir(), \
            f"missing raw/{stage} subdir"


def test_create_output_structure_creates_findings_per_kind(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    for kind in ("default", "endpoints", "dynamic"):
        assert (base / "findings" / kind).is_dir(), \
            f"missing findings/{kind} subdir"


def test_create_output_structure_creates_logs_and_report(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    assert (base / "logs").is_dir()
    assert (base / "report").is_dir()
    assert (base / "processed").is_dir()


def test_create_output_structure_is_idempotent(tmp_path: Path):
    """Calling create_output_structure twice on the same root must not
    raise (mkdir with exist_ok=True is the whole point)."""
    a = create_output_structure("example.com", root=str(tmp_path))
    b = create_output_structure("example.com", root=str(tmp_path))
    assert a == b


# ----------------------------------------------------------------------
# raw_dir() — typed accessor with validation
# ----------------------------------------------------------------------
def test_raw_dir_returns_existing_subdir(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    d = raw_dir(base, "subdomain")
    assert d == base / "raw" / "subdomain"
    assert d.is_dir()


def test_raw_dir_rejects_unknown_stage(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    with pytest.raises(ValueError, match="unknown raw subfolder"):
        raw_dir(base, "not-a-real-stage")


def test_raw_dir_accepts_every_known_stage(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    for stage in ("subdomain", "content_discovery", "dirsearch",
                  "waymore", "arjun"):
        d = raw_dir(base, stage)
        assert d.exists()


# ----------------------------------------------------------------------
# findings_dir() — typed accessor
# ----------------------------------------------------------------------
def test_findings_dir_returns_default_subdir(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    assert findings_dir(base, "default") == base / "findings" / "default"


def test_findings_dir_returns_dynamic_subdir(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    assert findings_dir(base, "dynamic") == base / "findings" / "dynamic"


def test_findings_dir_rejects_unknown_kind(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    with pytest.raises(ValueError, match="unknown findings subfolder"):
        findings_dir(base, "not-a-real-kind")


# ----------------------------------------------------------------------
# runner.run() with log_name= — sub-stages land in one log file
# ----------------------------------------------------------------------
def _make_proc_dict(stdout: str = "", stderr: str = "", rc: int = 0):
    """Build a fake ``runner.run()`` return value (the dict shape that
    the real function returns) so the calling module can do
    ``r["stdout"]`` / ``r["stderr"]`` without crashing."""
    return {
        "returncode": rc, "stdout": stdout, "stderr": stderr,
        "stdout_path": "", "stderr_path": "", "log_path": "",
        "success": rc == 0, "timed_out": False, "missing_binary": False,
    }


def test_runner_run_uses_log_name_for_output_path(tmp_path: Path, monkeypatch):
    """When log_name is set, the log file is logs/<log_name>.log,
    not logs/<stage>.log. The 'stage' is preserved as a section header
    inside the log."""
    import subprocess
    captured: list[str] = []

    def fake_subprocess(cmd, **kw):
        captured.append(cmd[0])
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="hello", stderr="",
        )

    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("modules.runner.subprocess.run", fake_subprocess)

    base = create_output_structure("example.com", root=str(tmp_path))
    runner.run(["echo", "x"], stage="subdomain_subfinder", log_name="subdomain",
               output_dir=base, timeout=10)
    runner.run(["echo", "y"], stage="subdomain_amass", log_name="subdomain",
               output_dir=base, timeout=10)
    runner.run(["echo", "z"], stage="subdomain_chaos", log_name="subdomain",
               output_dir=base, timeout=10)

    # Three sub-stages, one shared log
    log = base / "logs" / "subdomain.log"
    assert log.exists()
    content = log.read_text()
    # All three section headers present
    assert "=== subdomain_subfinder ===" in content
    assert "=== subdomain_amass ===" in content
    assert "=== subdomain_chaos ===" in content
    # The stdout from each call is captured
    assert "hello" in content
    # The full command was passed to subprocess.run (3 times)
    assert len(captured) == 3


def test_runner_run_default_log_name_is_stage(tmp_path: Path, monkeypatch):
    """Without log_name= the log file is logs/<stage>.log (backward
    compat for stages that don't need sub-stage aggregation)."""
    import subprocess
    def fake_subprocess(cmd, **kw):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="x", stderr="",
        )
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("modules.runner.subprocess.run", fake_subprocess)

    base = create_output_structure("example.com", root=str(tmp_path))
    runner.run(["echo", "x"], stage="dnsx", output_dir=base, timeout=10)

    log = base / "logs" / "dnsx.log"
    assert log.exists()
    assert "=== dnsx ===" in log.read_text()


def test_runner_run_appends_on_subsequent_calls(tmp_path: Path, monkeypatch):
    """Calling runner.run twice with the same log_name must APPEND to
    the same file (not overwrite)."""
    import subprocess
    call_count = {"n": 0}

    def fake_subprocess(cmd, **kw):
        call_count["n"] += 1
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=f"call-{call_count['n']}", stderr="",
        )

    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("modules.runner.subprocess.run", fake_subprocess)

    base = create_output_structure("example.com", root=str(tmp_path))
    runner.run(["echo", "1"], stage="httpx_alive", output_dir=base, timeout=10)
    runner.run(["echo", "2"], stage="httpx_alive", output_dir=base, timeout=10)

    log = base / "logs" / "httpx_alive.log"
    content = log.read_text()
    # Both calls preserved (each writes its own section header).
    assert content.count("=== httpx_alive ===") == 2
    # And both stdout payloads are present (proves append, not overwrite).
    assert "call-1" in content
    assert "call-2" in content


# ----------------------------------------------------------------------
# End-to-end smoke: subdomain + dirsearch populate the right paths
# ----------------------------------------------------------------------
def test_subdomain_writes_under_raw_subdomain(tmp_path: Path, monkeypatch):
    """The full subdomain stage must write tool outputs to
    raw/subdomain/{tool}.txt, NOT the old flat raw/{tool}.txt."""
    def fake_run(cmd, **kw):
        # Pretend subfinder writes a subdomain to its -o path.
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("a.example.com\nb.example.com\n")
        return _make_proc_dict(stdout="")
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("modules.runner.subprocess.run", fake_run)

    base = create_output_structure("example.com", root=str(tmp_path))
    from modules.subdomain import collect
    # puredns disabled here — this test only cares about where the
    # subfinder/amass/chaos raw outputs land, not the validation step.
    collect("example.com", base,
            {"subdomain": {"tools": ["subfinder", "amass", "chaos"]},
             "puredns": {"enabled": False}},
            resume=False, dry_run=False)

    # Tools live under raw/subdomain/
    assert (base / "raw" / "subdomain" / "subfinder.txt").exists()
    assert (base / "raw" / "subdomain" / "amass.txt").exists()
    assert (base / "raw" / "subdomain" / "chaos.txt").exists()
    # …NOT directly under raw/
    assert not (base / "raw" / "subfinder.txt").exists()
    # …and the merged list lives in processed/ as before
    assert (base / "processed" / "subdomains.txt").exists()


def test_dirsearch_merged_wordlist_lives_under_raw_dirsearch(tmp_path: Path, monkeypatch):
    """When multiple wordlists are configured, the merged file lands at
    raw/dirsearch/merged_wordlists.txt — not the old raw/merged_wordlists/."""
    def fake_run(cmd, **kw):
        # Pretend dirsearch runs successfully.
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("200  10B  https://x.com/.env\n")
        return _make_proc_dict(stdout="")
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("modules.runner.subprocess.run", fake_run)

    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("/admin\n")
    b.write_text("/login\n")

    base = create_output_structure("example.com", root=str(tmp_path))
    (base / "processed").mkdir(parents=True, exist_ok=True)
    (base / "processed" / "alive.txt").write_text("https://x.com\n")

    from modules.dirsearch import scan
    scan(base / "processed" / "alive.txt", base,
         {"dirsearch": {"wordlists": [str(a), str(b)]}},
         resume=False, dry_run=False, skip=False)

    # Merged file under raw/dirsearch/
    assert (base / "raw" / "dirsearch" / "merged_wordlists.txt").exists()
    # …NOT under the old raw/merged_wordlists/
    assert not (base / "raw" / "merged_wordlists").exists()