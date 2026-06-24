"""Tests for dirsearch wordlist resolution, merging, and command construction.

Covers:
  * _resolve_wordlists() — file, directory, missing path, ~ expansion
  * _merge_wordlists()   — dedup, comments, missing files, ordering
  * _build_cmd()         — single-wordlist mode, extension fallback, combine
  * scan()               — empty alive.txt short-circuits to skipped
"""
from pathlib import Path

import pytest

from modules import dirsearch
from modules.dirsearch import _build_cmd, _merge_wordlists, _resolve_wordlists
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
# _merge_wordlists — collapses N files into 1 deduped file
# ----------------------------------------------------------------------
def test_merge_wordlists_dedupes_across_files(tmp_path: Path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("/admin\n/login\n")
    b.write_text("/login\n/api\n")  # /login is a duplicate of a.txt
    out = tmp_path / "merged.txt"
    path, lines_in, lines_out = _merge_wordlists([a, b], out)
    assert path == out
    assert lines_in == 4          # 2 + 2
    assert lines_out == 3         # /admin, /login, /api
    assert out.read_text().splitlines() == ["/admin", "/login", "/api"]


def test_merge_wordlists_skips_comments_and_blanks(tmp_path: Path):
    a = tmp_path / "a.txt"
    a.write_text("# this is a comment\n\n/admin\n   \n# another\n/login\n")
    out = tmp_path / "merged.txt"
    _, lines_in, lines_out = _merge_wordlists([a], out)
    assert lines_in == 2
    assert lines_out == 2
    assert out.read_text().splitlines() == ["/admin", "/login"]


def test_merge_wordlists_first_occurrence_wins(tmp_path: Path):
    """When the same entry appears in two files, the first one wins
    (preserves ordering from the input list)."""
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("z-first\nshared\n")
    b.write_text("shared\nz-second\n")
    out = tmp_path / "merged.txt"
    _, _, _ = _merge_wordlists([a, b], out)
    # 'shared' came from a.txt first → kept once
    assert out.read_text().splitlines() == ["z-first", "shared", "z-second"]


def test_merge_wordlists_creates_parent_dir(tmp_path: Path):
    a = tmp_path / "a.txt"
    a.write_text("/x\n")
    out = tmp_path / "deep" / "nested" / "merged.txt"
    _merge_wordlists([a], out)
    assert out.exists()
    assert out.read_text().splitlines() == ["/x"]


def test_merge_wordlists_skips_missing_files(tmp_path: Path):
    a = tmp_path / "a.txt"
    a.write_text("/x\n")
    out = tmp_path / "merged.txt"
    # The non-existent file is silently skipped — we don't fail the
    # whole merge if one of many wordlists disappears.
    _, lines_in, lines_out = _merge_wordlists(
        [a, tmp_path / "nope.txt", a], out,
    )
    assert lines_in == 2     # a.txt read twice (no internal dedup of files)
    assert lines_out == 1    # but only one unique line
    assert out.read_text().splitlines() == ["/x"]


def test_merge_wordlists_handles_binary_garbage_gracefully(tmp_path: Path):
    a = tmp_path / "a.txt"
    # write_text errors="ignore" handles this, but we also want to make
    # sure the helper doesn't blow up on weird content.
    a.write_bytes(b"/admin\n\xff\xfe\xfd\n/login\n")
    out = tmp_path / "merged.txt"
    _, lines_in, lines_out = _merge_wordlists([a], out)
    # Binary bytes are stripped and counted as a line (still unique).
    assert lines_in >= 2
    assert "/admin" in out.read_text()
    assert "/login" in out.read_text()


# ----------------------------------------------------------------------
# _build_cmd — single-wordlist mode
# ----------------------------------------------------------------------
def _fake_alive_out(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "alive.txt", tmp_path / "raw.txt"


def test_build_cmd_wordlist_mode_emits_single_dash_w(tmp_path: Path):
    """dirsearch only accepts one -w. The signature is a single Path
    (the merged file) — verify the argv has exactly one -w pair."""
    alive, raw = _fake_alive_out(tmp_path)
    wl = tmp_path / "merged.txt"
    cmd = _build_cmd(
        alive, raw, wl, extensions=None,
        threads=20, recursive=True, combine=False,
    )
    assert cmd.count("-w") == 1
    assert cmd[cmd.index("-w") + 1] == str(wl)
    assert "-e" not in cmd


def test_build_cmd_wordlist_mode_no_combine_omits_extensions(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    wl = tmp_path / "a.txt"
    cmd = _build_cmd(
        alive, raw, wl, extensions=[".bak", ".old"],
        threads=10, recursive=True, combine=False,
    )
    # extensions are intentionally suppressed when wordlists are present
    # unless combine=True (avoids word×extension blowup)
    assert "-e" not in cmd


def test_build_cmd_combine_true_adds_extensions(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    wl = tmp_path / "a.txt"
    exts = [".bak", ".old"]
    cmd = _build_cmd(
        alive, raw, wl, extensions=exts,
        threads=10, recursive=True, combine=True,
    )
    assert "-e" in cmd
    idx = cmd.index("-e")
    assert cmd[idx + 1] == to_dirsearch_flag(exts)


def test_build_cmd_none_wordlist_skips_dash_w(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, None, extensions=[".env"],
        threads=10, recursive=True, combine=False,
    )
    assert "-w" not in cmd
    assert "-e" in cmd


# ----------------------------------------------------------------------
# _build_cmd — extension fallback
# ----------------------------------------------------------------------
def test_build_cmd_extension_fallback_when_no_wordlist(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, None, extensions=[".env", ".git"],
        threads=10, recursive=True, combine=False,
    )
    assert "-e" in cmd
    assert cmd[cmd.index("-e") + 1] == to_dirsearch_flag([".env", ".git"])
    assert "-w" not in cmd


def test_build_cmd_extension_fallback_none_uses_nothing(tmp_path: Path):
    """With no wordlist AND extensions=None, no -e/-w is emitted.
    Caller (scan()) injects the curated SENSITIVE_EXT list before this."""
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, None, extensions=None,
        threads=10, recursive=True, combine=False,
    )
    assert "-e" not in cmd
    assert "-w" not in cmd


def test_build_cmd_recursive_flag(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    wl = tmp_path / "a.txt"
    cmd_on = _build_cmd(
        alive, raw, wl, extensions=None,
        threads=10, recursive=True, combine=False,
    )
    cmd_off = _build_cmd(
        alive, raw, wl, extensions=None,
        threads=10, recursive=False, combine=False,
    )
    assert "-r" in cmd_on
    assert "-r" not in cmd_off


def test_build_cmd_threads_are_passed(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, None, extensions=[".bak"],
        threads=42, recursive=False, combine=False,
    )
    assert "-t" in cmd
    assert cmd[cmd.index("-t") + 1] == "42"


# ----------------------------------------------------------------------
# _build_cmd — status-code filtering + follow-redirects
# ----------------------------------------------------------------------
def test_build_cmd_emits_follow_redirects_when_enabled(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, Path(tmp_path / "a.txt"), extensions=None,
        threads=10, recursive=True, combine=False,
        follow_redirects=True,
    )
    assert "--follow-redirects" in cmd


def test_build_cmd_omits_follow_redirects_when_disabled(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, Path(tmp_path / "a.txt"), extensions=None,
        threads=10, recursive=True, combine=False,
        follow_redirects=False,
    )
    assert "--follow-redirects" not in cmd


def test_build_cmd_emits_include_status_flag(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, Path(tmp_path / "a.txt"), extensions=None,
        threads=10, recursive=True, combine=False,
        include_status=[200, 401, 403, 500],
    )
    i_idx = cmd.index("-i")
    assert cmd[i_idx + 1] == "200,401,403,500"


def test_build_cmd_emits_exclude_status_flag(tmp_path: Path):
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, Path(tmp_path / "a.txt"), extensions=None,
        threads=10, recursive=True, combine=False,
        exclude_status=[404, 429],
    )
    x_idx = cmd.index("-x")
    assert cmd[x_idx + 1] == "404,429"


def test_build_cmd_no_status_filter_means_no_flags(tmp_path: Path):
    """Empty include/exclude lists (default) → no -i / -x flag emitted
    so dirsearch reports everything (legacy behaviour)."""
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, Path(tmp_path / "a.txt"), extensions=None,
        threads=10, recursive=True, combine=False,
        include_status=[], exclude_status=[],
    )
    assert "-i" not in cmd
    assert "-x" not in cmd


def test_build_cmd_filters_strip_empty_strings(tmp_path: Path):
    """``["", "  ", "200"]`` should produce ``-i 200`` — no trailing
    empty / whitespace entries in the comma-separated list."""
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, Path(tmp_path / "a.txt"), extensions=None,
        threads=10, recursive=True, combine=False,
        include_status=["", "  ", "200"],
    )
    i_idx = cmd.index("-i")
    assert cmd[i_idx + 1] == "200"


def test_build_cmd_emits_both_include_and_exclude(tmp_path: Path):
    """Both filters can be active simultaneously — dirsearch applies
    include first, then exclude."""
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, Path(tmp_path / "a.txt"), extensions=None,
        threads=10, recursive=True, combine=False,
        include_status=[200, 401, 403],
        exclude_status=[404, 429],
    )
    assert cmd[cmd.index("-i") + 1] == "200,401,403"
    assert cmd[cmd.index("-x") + 1] == "404,429"


def test_build_cmd_does_not_pass_format_flag(tmp_path: Path):
    """The legacy dirsearch (pre-1.0) doesn't accept ``--format`` and
    exits with "no such option: --format". Both old and new versions
    infer the format from the output file extension, so we never pass
    it. Test guards against the flag creeping back in.
    """
    alive, raw = _fake_alive_out(tmp_path)
    cmd = _build_cmd(
        alive, raw, None, extensions=[".bak"],
        threads=10, recursive=False, combine=False,
    )
    assert cmd[0] == "dirsearch"
    assert "-l" in cmd and cmd[cmd.index("-l") + 1] == str(alive)
    assert "--format" not in cmd  # must NOT pass --format (breaks legacy dirsearch)
    assert "-o" in cmd and cmd[cmd.index("-o") + 1] == str(raw)


# ----------------------------------------------------------------------
# scan() — multiple wordlists get merged before the build
# ----------------------------------------------------------------------
def test_scan_merges_multiple_wordlists(tmp_path: Path, monkeypatch):
    """End-to-end: with two wordlists configured, scan() must produce a
    single -w pointing at the merged file (not two -w flags)."""
    captured: list[str] = []

    def _fake_run(cmd, **kw):
        captured.extend(cmd)
        # Pretend dirsearch ran and produced nothing — the assertion we
        # care about is the argv shape, not the output.
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run)

    alive = tmp_path / "alive.txt"
    alive.write_text("https://x.com\n")
    (tmp_path / "raw").mkdir()
    (tmp_path / "processed").mkdir()

    a = tmp_path / "wl_a.txt"
    b = tmp_path / "wl_b.txt"
    a.write_text("/admin\n")
    b.write_text("/login\n")

    dirsearch.scan(
        alive, tmp_path,
        cfg={"dirsearch": {"wordlists": [str(a), str(b)]}},
        resume=False, dry_run=False, skip=False,
    )

    # The merged file should exist under raw/dirsearch/ and contain both entries.
    merged = tmp_path / "raw" / "dirsearch" / "merged_wordlists.txt"
    assert merged.exists()
    assert sorted(merged.read_text().splitlines()) == ["/admin", "/login"]

    # The argv must have exactly one -w flag pointing at the merged file.
    assert captured.count("-w") == 1
    assert captured[captured.index("-w") + 1] == str(merged)


def test_scan_does_not_merge_when_only_one_wordlist(tmp_path: Path, monkeypatch):
    """If there's only one wordlist, scan() should use it directly —
    no merged_wordlists/ directory should be created."""
    captured: list[str] = []

    def _fake_run(cmd, **kw):
        captured.extend(cmd)
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run)

    alive = tmp_path / "alive.txt"
    alive.write_text("https://x.com\n")
    (tmp_path / "raw").mkdir()
    (tmp_path / "processed").mkdir()

    a = tmp_path / "single.txt"
    a.write_text("/admin\n")

    dirsearch.scan(
        alive, tmp_path,
        cfg={"dirsearch": {"wordlists": [str(a)]}},
        resume=False, dry_run=False, skip=False,
    )

    # No merged file should be created — single wordlist is used as-is.
    assert not (tmp_path / "raw" / "dirsearch" / "merged_wordlists.txt").exists()
    # And the argv should point at the original file.
    assert captured.count("-w") == 1
    assert captured[captured.index("-w") + 1] == str(a)


def test_scan_reports_merge_stats_in_extra(tmp_path: Path, monkeypatch):
    """The stage result's extra dict should include merge stats
    (files, lines_in, lines_out, path) for visibility in the report."""
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run",
                        lambda *a, **kw: {"success": True, "stdout": "",
                                          "stderr": "", "missing_binary": False,
                                          "timed_out": False})

    alive = tmp_path / "alive.txt"
    alive.write_text("https://x.com\n")
    (tmp_path / "raw").mkdir()
    (tmp_path / "processed").mkdir()

    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("/admin\n/login\n")
    b.write_text("/login\n/api\n")  # /login duplicates

    res = dirsearch.scan(
        alive, tmp_path,
        cfg={"dirsearch": {"wordlists": [str(a), str(b)]}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "success"
    assert res["extra"]["merge"]["files"] == 2
    assert res["extra"]["merge"]["lines_in"] == 4     # 2 + 2
    assert res["extra"]["merge"]["lines_out"] == 3   # /admin, /login, /api


# ----------------------------------------------------------------------
# scan() — empty input guard
# ----------------------------------------------------------------------
def test_scan_skips_when_alive_file_is_empty(tmp_path: Path, monkeypatch):
    """If alive.txt is empty we must NOT spawn dirsearch — dirsearch
    exits non-zero on an empty -l file and we used to misreport that
    as a real failure."""
    # Pretend the binary is installed so we hit the empty-input branch
    # rather than the "missing binary" branch.
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    # Belt-and-braces: if the empty-input guard is missing and the code
    # proceeds to call runner.run, fail loudly.
    def _explode(*a, **kw):
        raise AssertionError("runner.run must not be called for empty alive.txt")
    monkeypatch.setattr("modules.runner.run", _explode)

    alive = tmp_path / "alive.txt"
    alive.write_text("")  # empty

    res = dirsearch.scan(
        alive, tmp_path,
        cfg={"dirsearch": {}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "skipped"
    assert res["error"] == "no alive hosts to scan"
    assert res["count"] == 0


def test_scan_skips_when_alive_file_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            AssertionError("must not call runner.run")))

    res = dirsearch.scan(
        tmp_path / "does_not_exist.txt", tmp_path,
        cfg={"dirsearch": {}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "skipped"
    assert res["error"] == "no alive hosts to scan"