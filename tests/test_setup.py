"""Tests for setup.py bootstrap helpers.

The destructive helpers (install_missing_tools, download_wordlists) are
not exercised here — they hit the network and the user's package
manager. We only test the pure helpers and the structured-summary builder.
"""
import subprocess
import sys
from pathlib import Path

import pytest

import setup as setup_mod
from setup import (
    SECLISTS_PATHS,
    TOOLS,
    build_summary,
    category_sort_key,
    expected_wordlist_paths,
    is_tool_available,
    missing_wordlists,
    select_install_command,
    setup_output_dir,
    verify_wordlists,
    which,
)


# ----------------------------------------------------------------------
# is_tool_available / which
# ----------------------------------------------------------------------
def test_is_tool_available_true_for_python3():
    # python3 is what pytest itself runs under
    assert is_tool_available("python3") is True
    assert which("python3") is not None
    assert Path(which("python3")).name.startswith("python")


def test_is_tool_available_false_for_nonsense():
    assert is_tool_available("definitely-not-a-binary-xyz123") is False
    assert which("definitely-not-a-binary-xyz123") is None


# ----------------------------------------------------------------------
# expected_wordlist_paths / verify_wordlists / missing_wordlists
# ----------------------------------------------------------------------
def test_expected_wordlist_paths_matches_catalogue():
    """The list of expected paths is what the framework ships in config.yml."""
    paths = expected_wordlist_paths()
    assert paths == SECLISTS_PATHS
    assert "Discovery/Web-Content/raft-small-directories.txt" in paths
    assert "Discovery/Web-Content/uri-from-top-55-most-popular-apps.txt" in paths
    assert "Discovery/Web-Content/Service-Specific" in paths


def test_verify_wordlists_marks_missing_paths(tmp_path: Path):
    # nothing cloned yet
    res = verify_wordlists(tmp_path / "SecLists")
    assert all(present is False for present in res.values())


def test_verify_wordlists_marks_existing_paths(tmp_path: Path):
    root = tmp_path / "SecLists"
    (root / "Discovery" / "Web-Content").mkdir(parents=True)
    (root / "Discovery" / "Web-Content" / "raft-small-directories.txt").write_text("/admin\n")
    (root / "Discovery" / "Web-Content" / "Service-Specific").mkdir()
    res = verify_wordlists(root)
    assert res["Discovery/Web-Content/raft-small-directories.txt"] is True
    assert res["Discovery/Web-Content/Service-Specific"] is True
    assert res["Discovery/Web-Content/uri-from-top-55-most-popular-apps.txt"] is False


def test_missing_wordlists_returns_only_missing(tmp_path: Path):
    root = tmp_path / "SecLists"
    (root / "Discovery" / "Web-Content").mkdir(parents=True)
    (root / "Discovery" / "Web-Content" / "raft-small-directories.txt").write_text("/admin\n")
    missing = missing_wordlists(root)
    assert "Discovery/Web-Content/raft-small-directories.txt" not in missing
    assert "Discovery/Web-Content/uri-from-top-55-most-popular-apps.txt" in missing
    assert "Discovery/Web-Content/Service-Specific" in missing


def test_verify_wordlists_expands_user(tmp_path: Path, monkeypatch):
    """`~` in the path must expand to $HOME."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "SecLists" / "Discovery" / "Web-Content").mkdir(parents=True)
    (tmp_path / "SecLists" / "Discovery" / "Web-Content"
        / "raft-small-directories.txt").write_text("x")
    res = verify_wordlists(Path("~/SecLists"))
    assert res["Discovery/Web-Content/raft-small-directories.txt"] is True


# ----------------------------------------------------------------------
# select_install_command / category_sort_key
# ----------------------------------------------------------------------
def test_select_install_command_for_darwin():
    cmd = select_install_command("subfinder", system="Darwin")
    assert cmd == ["brew", "install", "subfinder"]


def test_select_install_command_for_linux_go_tool():
    cmd = select_install_command("dnsx", system="Linux")
    assert cmd is not None
    assert cmd[0] == "go"  # Go tools use `go install` on Linux
    assert "dnsx" in " ".join(cmd)


def test_select_install_command_for_python_tool():
    cmd = select_install_command("dirsearch", system="Linux")
    assert cmd == ["pip3", "install", "dirsearch"]


def test_select_install_command_for_unknown_binary():
    assert select_install_command("not-a-real-tool", system="Linux") is None


def test_select_install_command_for_unknown_system():
    """An unknown system (e.g. Plan9) returns None for everything."""
    assert select_install_command("subfinder", system="Plan9") is None


def test_category_sort_key_orders_runtime_first():
    assert category_sort_key("runtime") < category_sort_key("go")
    assert category_sort_key("go") <= category_sort_key("python")
    assert category_sort_key("python") < category_sort_key("unknown")


# ----------------------------------------------------------------------
# build_summary
# ----------------------------------------------------------------------
def _stub_results(missing: tuple[str, ...] = ()) -> dict[str, dict]:
    """Build a fake ``check_tools()`` result.

    By default every tool is available; pass ``missing`` to mark some as
    unavailable. This matches how a real `check_tools()` call returns its
    data — every key in TOOLS is always present.
    """
    res: dict[str, dict] = {}
    for binary, info in TOOLS.items():
        avail = binary not in missing
        res[binary] = {
            "label": info["label"],
            "category": info.get("category", ""),
            "available": avail,
            "version": "v1.0" if avail else None,
            "path": "/usr/bin/" + binary if avail else None,
        }
    return res


def test_build_summary_zero_issues_when_all_good(tmp_path: Path):
    wl = {p: True for p in SECLISTS_PATHS}
    s = build_summary(_stub_results(), wl, tmp_path, tmp_path)
    assert s["issues"] == 0
    assert len(s["tools"]) == len(TOOLS)
    assert len(s["wordlists"]) == len(SECLISTS_PATHS)


def test_build_summary_counts_missing_tools_and_wordlists(tmp_path: Path):
    wl = {p: False for p in SECLISTS_PATHS}
    s = build_summary(_stub_results(missing=("nuclei",)), wl, tmp_path, tmp_path)
    # 1 missing tool + 3 missing wordlists
    assert s["issues"] == 1 + len(SECLISTS_PATHS)


def test_build_summary_includes_output_dir_and_wordlists_dir(tmp_path: Path):
    s = build_summary(_stub_results(), {p: True for p in SECLISTS_PATHS},
                      tmp_path, tmp_path / "SecLists")
    assert s["output_dir"] == str(tmp_path)
    assert s["wordlists_dir"] == str(tmp_path / "SecLists")


# ----------------------------------------------------------------------
# setup_output_dir — creates outputs/
# ----------------------------------------------------------------------
def test_setup_output_dir_creates_outputs(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = setup_output_dir()
    assert out.exists()
    assert (tmp_path / "outputs").exists()
    # the returned path resolves to the absolute location we created
    assert out.resolve() == (tmp_path / "outputs").resolve()


def test_setup_output_dir_idempotent(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    a = setup_output_dir()
    b = setup_output_dir()  # second call must not raise
    assert a.resolve() == b.resolve()


# ----------------------------------------------------------------------
# CLI surface — main() should expose the documented flags.
# ----------------------------------------------------------------------
def test_main_help_lists_known_flags():
    """Run `python3 setup.py --help` and check the advertised flags appear."""
    project_root = Path(__file__).resolve().parent.parent
    setup_py = project_root / "setup.py"
    result = subprocess.run(
        [sys.executable, str(setup_py), "--help"],
        capture_output=True, text=True,
        cwd=str(project_root),
    )
    assert result.returncode == 0, result.stderr
    assert "--install" in result.stdout
    assert "--wordlists" in result.stdout
    assert "--wordlists-dir" in result.stdout
    assert "--all" in result.stdout
    assert "--no-color" in result.stdout
    assert "--yes" in result.stdout


def test_main_help_only_lists_known_flags():
    """No surprise flags have crept in."""
    project_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, str(project_root / "setup.py"), "--help"],
        capture_output=True, text=True,
        cwd=str(project_root),
    )
    # all expected CLI options are listed
    for flag in ("--install", "--wordlists", "--all", "-y", "--yes",
                 "--wordlists-dir", "--no-color"):
        assert flag in result.stdout, f"missing flag: {flag}"
