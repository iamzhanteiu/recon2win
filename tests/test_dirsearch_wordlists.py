"""Tests for dirsearch wordlist resolution and command construction.

Covers:
  * _resolve_wordlists() — file, directory, missing path, ~ expansion
  * _build_cmd()        — wordlist mode, extension fallback, combine flag
"""
from pathlib import Path

import pytest

from modules.dirsearch import _build_cmd, _resolve_wordlists
from modules.sensitive_ext import to_dirsearch_flag


# ----------------------------------------------------------------------
# Helpers — populate a tmp wordlist tree
# ----------------------------------------------------------------------
@pytest.fixture
def wl_tree(tmp_path: Path) -> Path:
    """Build a small wordlist tree:

        tmp_path/
        ├── single.txt
        ├── service-specific/
        │   ├── apache.txt
        │   ├── nginx.txt
        │   └── spring.txt
        └── empty_dir/         (no .txt inside)
    """
    (tmp_path / "single.txt").write_text("admin\nlogin\n")
    svc = tmp_path / "service-specific"
    svc.mkdir()
    (svc / "nginx.txt").write_text("/api/v1\n")
    (svc / "apache.txt").write_text("/server-status\n")
    (svc / "spring.txt").write_text("/actuator/env\n")
    # An unrelated file extension (should be ignored)
    (svc / "README.md").write_text("ignore me")
    # A directory with no .txt files inside (rglob yields nothing)
    (tmp_path / "empty_dir").mkdir()
    (tmp_path / "empty_dir" / "nothing.here").write_text("nope")
    return tmp_path


# ----------------------------------------------------------------------
# _resolve_wordlists
# ----------------------------------------------------------------------
def test_resolve_single_file(wl_tree: Path):
    out = _resolve_wordlists([wl_tree / "single.txt"])
    assert out == [wl_tree / "single.txt"]


def test_resolve_directory_recurses_to_txt(wl_tree: Path):
    out = _resolve_wordlists([wl_tree / "service-specific"])
    names = sorted(p.name for p in out)
    # README.md is filtered out (only .txt kept)
    assert names == ["apache.txt", "nginx.txt", "spring.txt"]


def test_resolve_directory_is_sorted(wl_tree: Path):
    out = _resolve_wordlists([wl_tree / "service-specific"])
    # sorted for deterministic command order
    assert out == sorted(out, key=lambda p: str(p))


def test_resolve_missing_path_is_skipped(tmp_path: Path):
    captured: list[str] = []
    out = _resolve_wordlists(
        [tmp_path / "does-not-exist.txt"],
        missing_callback=captured.append,
    )
    assert out == []
    assert len(captured) == 1
    assert "not found" in captured[0]


def test_resolve_none_entries_are_ignored(wl_tree: Path):
    out = _resolve_wordlists([None, wl_tree / "single.txt", None])
    assert out == [wl_tree / "single.txt"]


def test_resolve_tilde_expansion(tmp_path: Path, monkeypatch):
    """If HOME is monkeypatched to point at our tree, ~/x.txt resolves."""
    f = tmp_path / "alpha.txt"
    f.write_text("a\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    out = _resolve_wordlists(["~/alpha.txt"])
    assert out == [f]


def test_resolve_mixed_file_dir_and_missing(wl_tree: Path):
    captured: list[str] = []
    out = _resolve_wordlists(
        [
            wl_tree / "single.txt",
            wl_tree / "service-specific",
            wl_tree / "nope.txt",   # missing
        ],
        missing_callback=captured.append,
    )
    names = sorted(p.name for p in out)
    assert names == ["apache.txt", "nginx.txt", "single.txt", "spring.txt"]
    assert captured == ["[dirsearch] wordlist not found: " + str(wl_tree / "nope.txt")]


# ----------------------------------------------------------------------
# _build_cmd — wordlist mode
# ----------------------------------------------------------------------
def _fake_alive_out(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "alive.txt", tmp_path / "raw.txt"


def test_build_cmd_wordlist_mode_emits_one_dash_w_per_file(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    wls = [tmp_path / "a.txt", tmp_path / "b.txt"]
    cmd = _build_cmd(
        alive, raw, wls, extensions=None,
        threads=20, recursive=True, combine=False,
    )
    # one "-w <path>" pair per wordlist
    assert "-w" in cmd
    assert cmd.count("-w") == 2
    assert str(wls[0]) in cmd
    assert str(wls[1]) in cmd
    # no extensions flag
    assert "-e" not in cmd


def test_build_cmd_wordlist_mode_no_combine_omits_extensions(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    wls = [tmp_path / "a.txt"]
    cmd = _build_cmd(
        alive, raw, wls, extensions=[".bak", ".old"],
        threads=10, recursive=True, combine=False,
    )
    # extensions are intentionally suppressed when wordlists are present
    # unless combine=True (avoids word×extension blowup)
    assert "-e" not in cmd


def test_build_cmd_combine_true_adds_extensions(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    wls = [tmp_path / "a.txt"]
    exts = [".bak", ".old"]
    cmd = _build_cmd(
        alive, raw, wls, extensions=exts,
        threads=10, recursive=True, combine=True,
    )
    assert "-e" in cmd
    idx = cmd.index("-e")
    assert cmd[idx + 1] == to_dirsearch_flag(exts)


# ----------------------------------------------------------------------
# _build_cmd — extension fallback
# ----------------------------------------------------------------------
def test_build_cmd_extension_fallback_when_no_wordlists(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, [], extensions=[".env", ".git"],
        threads=10, recursive=True, combine=False,
    )
    assert "-e" in cmd
    assert cmd[cmd.index("-e") + 1] == to_dirsearch_flag([".env", ".git"])
    assert "-w" not in cmd


def test_build_cmd_extension_fallback_none_uses_nothing(tmp_path: Path):
    """With no wordlists AND extensions=None, no -e/-w is emitted.
    Caller (scan()) injects the curated SENSITIVE_EXT list before this."""
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, [], extensions=None,
        threads=10, recursive=True, combine=False,
    )
    assert "-e" not in cmd
    assert "-w" not in cmd


def test_build_cmd_recursive_flag(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd_on = _build_cmd(
        alive, raw, [tmp_path / "a.txt"], extensions=None,
        threads=10, recursive=True, combine=False,
    )
    cmd_off = _build_cmd(
        alive, raw, [tmp_path / "a.txt"], extensions=None,
        threads=10, recursive=False, combine=False,
    )
    assert "-r" in cmd_on
    assert "-r" not in cmd_off


def test_build_cmd_threads_are_passed(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, [], extensions=[".bak"],
        threads=42, recursive=False, combine=False,
    )
    assert "-t" in cmd
    assert cmd[cmd.index("-t") + 1] == "42"


def test_build_cmd_always_passes_l_and_format(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, [], extensions=[".bak"],
        threads=10, recursive=False, combine=False,
    )
    assert cmd[0] == "dirsearch"
    assert "-l" in cmd and cmd[cmd.index("-l") + 1] == str(alive)
    assert "--format" in cmd and cmd[cmd.index("--format") + 1] == "plain"
    assert "-o" in cmd and cmd[cmd.index("-o") + 1] == str(raw)