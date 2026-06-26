"""Tests for modules/puredns.py.

Covers:
  * Trickest resolver fetch + offline fallback
  * puredns.collect cmd construction (resolvers, rate-limit, etc.)
  * Resume path (skip re-run if cache exists)
  * Skips gracefully when puredns binary missing
  * Skips gracefully when network fetch fails AND no cache
  * Output written to canonical processed/subdomains.txt so
    downstream stages (dnsx, httpx_alive) see the FILTERED list
"""
from __future__ import annotations

import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from modules import puredns as puredns_mod


# ----------------------------------------------------------------------
# fetch_trickest_resolvers
# ----------------------------------------------------------------------
def _trickest_sample() -> str:
    """Realistic slice of the trickest resolver file."""
    return (
        "# Public DNS resolvers (curated by trickest)\n"
        "1.1.1.1\n"
        "1.0.0.1\n"
        "8.8.8.8\n"
        "8.8.4.4\n"
        "9.9.9.9\n"
        "149.112.112.10\n"
        "\n"   # blank line — should be stripped
        "# duplicate below should be deduped by puredns, not us\n"
        "1.1.1.1\n"
    )


def test_fetch_trickest_resolvers_strips_comments_and_blanks(tmp_path):
    """Comments (``#...``) and blank lines are dropped — puredns
    can't handle them and would fail on the first non-resolver line.
    Duplicate IPs are kept as-is (puredns dedups its own input)."""
    cache = tmp_path / "resolvers.txt"

    fake_resp = type("R", (), {
        "__enter__": lambda self: self,
        "__exit__": lambda self, *a: None,
        "read": lambda self: _trickest_sample().encode(),
    })()
    with patch.object(urllib.request, "urlopen", return_value=fake_resp):
        out = puredns_mod.fetch_trickest_resolvers(cache)
    assert out == cache
    text = cache.read_text()
    # No comments, no blank lines — but duplicates from the upstream
    # list are kept (puredns dedups on its own).
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert lines == [
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.10",
        "1.1.1.1",  # duplicate kept (puredns dedups internally)
    ]
    assert "#" not in text
    assert "" not in lines


def test_fetch_trickest_falls_back_to_cache_on_network_error(tmp_path):
    """If the network is down, use the cached file. The cache must
    be NON-EMPTY or we raise (an empty cache is useless for puredns)."""
    cache = tmp_path / "resolvers.txt"
    cache.write_text("1.1.1.1\n8.8.8.8\n")

    with patch.object(urllib.request, "urlopen",
                      side_effect=urllib.error.URLError("no network")):
        out = puredns_mod.fetch_trickest_resolvers(cache)
    assert out == cache
    # The cached content is preserved.
    assert cache.read_text() == "1.1.1.1\n8.8.8.8\n"


def test_fetch_trickest_raises_when_both_network_and_cache_fail(tmp_path):
    """No network AND no cache → raise. puredns without resolvers
    would silently do nothing useful; better to fail loud."""
    cache = tmp_path / "resolvers.txt"
    # No cache file written.
    with patch.object(urllib.request, "urlopen",
                      side_effect=urllib.error.URLError("no network")):
        with pytest.raises(urllib.error.URLError):
            puredns_mod.fetch_trickest_resolvers(cache)


def test_fetch_trickest_raises_when_network_fails_and_cache_empty(tmp_path):
    """Cache exists but is empty → treat as no cache and raise."""
    cache = tmp_path / "resolvers.txt"
    cache.write_text("")
    with patch.object(urllib.request, "urlopen",
                      side_effect=urllib.error.URLError("no network")):
        with pytest.raises(urllib.error.URLError):
            puredns_mod.fetch_trickest_resolvers(cache)


# ----------------------------------------------------------------------
# collect — cmd construction + stage integration
# ----------------------------------------------------------------------
def _stage_input(tmp_path: Path, content: str = "") -> Path:
    """Write a fake candidate list for puredns to consume."""
    inp = tmp_path / "subdomains.txt"
    inp.write_text(content)
    return inp


def _patch_runner(monkeypatch, *, success: bool, returncode: int = 0,
                  valid_lines: list[str] | None = None):
    """Replace modules.runner.run with a fake that writes valid_lines
    to the --write output path. Returns the mock so tests can inspect."""
    def fake_run(cmd, **kw):
        # Find --write path
        try:
            write_idx = cmd.index("--write")
            write_path = Path(cmd[write_idx + 1])
        except (ValueError, IndexError):
            write_path = None
        if write_path and valid_lines is not None:
            write_path.parent.mkdir(parents=True, exist_ok=True)
            write_path.write_text("\n".join(valid_lines) + "\n")
        return {
            "returncode": returncode, "stdout": "", "stderr": "",
            "missing_binary": False, "timed_out": False, "success": success,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")


def _patch_trickest(monkeypatch, content: str = "1.1.1.1\n"):
    """Make fetch_trickest_resolvers return a static file instead of
    hitting the network."""
    def fake_fetch(cache_path: Path) -> Path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(content)
        return cache_path
    monkeypatch.setattr(
        "modules.puredns.fetch_trickest_resolvers", fake_fetch
    )


def test_collect_passes_resolvers_to_puredns(tmp_path, monkeypatch):
    inp = _stage_input(tmp_path, "a.example.com\nb.example.com\n")
    _patch_trickest(monkeypatch, "1.1.1.1\n8.8.8.8\n")

    captured: dict = {}
    def fake_run(cmd, **kw):
        # cmd[1] is the puredns verb ("resolve"). Capture full cmd.
        captured["cmd"] = list(cmd)
        # Simulate writing valid output.
        write_path = Path(cmd[cmd.index("--write") + 1])
        write_path.parent.mkdir(parents=True, exist_ok=True)
        write_path.write_text("a.example.com\n")
        return {
            "returncode": 0, "stdout": "", "stderr": "",
            "missing_binary": False, "timed_out": False, "success": True,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    out_dir = tmp_path / "out"
    r = puredns_mod.collect("example.com", inp, out_dir, {})
    assert r["status"] == "success"
    # --resolvers / -r points at the trickest cache file.
    r_idx = captured["cmd"].index("-r")
    rfile = Path(captured["cmd"][r_idx + 1])
    assert rfile.exists()
    assert "1.1.1.1" in rfile.read_text()


def test_collect_includes_bruteforce_wordlist_when_enabled(tmp_path, monkeypatch):
    inp = _stage_input(tmp_path)
    _patch_trickest(monkeypatch)

    captured: list = []
    def fake_run(cmd, **kw):
        captured.extend(cmd)
        return {
            "returncode": 0, "stdout": "", "stderr": "",
            "missing_binary": False, "timed_out": False, "success": True,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    cfg = {"puredns": {"bruteforce": True,
                        "wordlist": "/tmp/custom-wordlist.txt"}}
    puredns_mod.collect("example.com", inp, tmp_path, cfg)

    # -w flag should appear with the custom wordlist path.
    w_idx = captured.index("-w")
    assert captured[w_idx + 1] == "/tmp/custom-wordlist.txt"


def test_collect_omits_wordlist_flag_by_default(tmp_path, monkeypatch):
    """Bruteforce is off by default — don't pass -w (puredns would
    reject /dev/null as a wordlist path)."""
    inp = _stage_input(tmp_path)
    _patch_trickest(monkeypatch)

    captured: list = []
    def fake_run(cmd, **kw):
        captured.extend(cmd)
        return {
            "returncode": 0, "stdout": "", "stderr": "",
            "missing_binary": False, "timed_out": False, "success": True,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    puredns_mod.collect("example.com", inp, tmp_path, {})
    assert "-w" not in captured


def test_collect_skips_when_puredns_binary_missing(tmp_path, monkeypatch):
    """Missing binary → skip (not fail). The raw merged subdomains
    list is still in processed/subdomains.txt from subdomain.collect."""
    inp = _stage_input(tmp_path, "a.example.com\n")
    _patch_trickest(monkeypatch)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: False)

    r = puredns_mod.collect("example.com", inp, tmp_path, {})
    assert r["status"] == "skipped"
    assert "not found" in (r.get("error") or "").lower()


def test_collect_skips_when_trickest_fetch_fails_no_cache(tmp_path, monkeypatch):
    """Network fails + no cache → skip. We don't fail the whole scan
    just because we couldn't validate — raw merged list is in place."""
    inp = _stage_input(tmp_path, "a.example.com\n")
    # Trickest fetch fails AND no cache file.
    def fake_fetch(cache_path: Path) -> Path:
        raise urllib.error.URLError("no network")
    monkeypatch.setattr(
        "modules.puredns.fetch_trickest_resolvers", fake_fetch
    )
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    r = puredns_mod.collect("example.com", inp, tmp_path, {})
    assert r["status"] == "failed"
    assert "resolvers" in (r.get("error") or "").lower()


def test_collect_writes_valid_to_processed_subdomains(tmp_path, monkeypatch):
    """Critical: processed/subdomains.txt must contain puredns's
    validated output (not the raw 45k candidates) so downstream
    stages (dnsx, httpx_alive) get the filtered list."""
    inp = _stage_input(tmp_path, "raw1.example.com\nraw2.example.com\nraw3.example.com\n")
    _patch_trickest(monkeypatch)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    # puredns "validates" only 1 host out of 3.
    def fake_run(cmd, **kw):
        write_path = Path(cmd[cmd.index("--write") + 1])
        write_path.parent.mkdir(parents=True, exist_ok=True)
        write_path.write_text("raw1.example.com\n")
        return {
            "returncode": 0, "stdout": "", "stderr": "",
            "missing_binary": False, "timed_out": False, "success": True,
            "stdout_path": "", "stderr_path": "", "log_path": "",
            "duration": 0.1,
        }
    monkeypatch.setattr("modules.runner.run", fake_run)

    out_dir = tmp_path / "out"
    r = puredns_mod.collect("example.com", inp, out_dir, {})

    # The canonical file must reflect puredns's output (1 host), NOT
    # the raw input (3 hosts). Downstream stages read this file.
    proc_sub = out_dir / "processed" / "subdomains.txt"
    assert proc_sub.read_text().strip() == "raw1.example.com"
    assert r["count"] == 1
    assert r["status"] == "success"


def test_collect_resume_uses_cached_valid_output(tmp_path, monkeypatch):
    """With resume=True and a cached raw/puredns/valid.txt, puredns
    isn't re-run — the cached file is just copied to processed/."""
    inp = _stage_input(tmp_path, "raw.example.com\n")
    out_dir = tmp_path / "out"
    (out_dir / "raw" / "puredns").mkdir(parents=True)
    (out_dir / "raw" / "puredns" / "valid.txt").write_text("cached.example.com\n")
    _patch_trickest(monkeypatch)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")
    # runner.run must NOT be called when resuming.
    def fail_run(*a, **kw):
        raise AssertionError("runner.run must not be called on resume")
    monkeypatch.setattr("modules.runner.run", fail_run)

    r = puredns_mod.collect("example.com", inp, out_dir, {}, resume=True)
    assert r["status"] == "success"
    assert r["count"] == 1   # from the cached file
    proc_sub = out_dir / "processed" / "subdomains.txt"
    assert proc_sub.read_text().strip() == "cached.example.com"


def test_collect_dry_run_returns_skipped(tmp_path, monkeypatch):
    """--dry-run → status=skipped, no subprocess invocation."""
    inp = _stage_input(tmp_path, "a.example.com\n")

    def fail_run(*a, **kw):
        raise AssertionError("dry-run must not invoke runner.run")
    monkeypatch.setattr("modules.runner.run", fail_run)

    r = puredns_mod.collect("example.com", inp, tmp_path / "out", {},
                            dry_run=True)
    assert r["status"] == "skipped"
    assert r["error"] == "dry-run"