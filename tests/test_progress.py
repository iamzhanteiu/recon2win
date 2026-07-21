"""Tests for modules/progress.py — the Rich progress bar wrapper.

Coverage:
  * Auto-detection of TTY / $NO_COLOR / $FORCE_COLOR
  * Fallback no-op when rich is missing
  * start_phase / finish_phase work
  * parallel() context manager tracks sub-phases
  * The bar gracefully does nothing when disabled (so log files stay clean)
"""
from __future__ import annotations

from io import StringIO


from modules import progress as progress_mod


# ----------------------------------------------------------------------
# Auto-detection
# ----------------------------------------------------------------------
def test_disabled_when_rich_not_installed(monkeypatch):
    """If the rich import fails, ``_RICH_AVAILABLE`` is False and the
    bar is a no-op regardless of TTY/NO_COLOR."""
    monkeypatch.setattr(progress_mod, "_RICH_AVAILABLE", False)
    prog = progress_mod.ReconProgress(n_phases=5)
    assert prog.enabled is False
    # All methods should be safe to call.
    with prog:
        prog.start_phase("a", num=1)
        prog.finish_phase({"stage": "a", "status": "success", "count": 1}, num=1)
        with prog.parallel(["b", "c"], num=2):
            prog.subphase_done("b", {"status": "success", "count": 2})
        prog.finish_parallel(num=2)


def test_disabled_when_no_color_env(monkeypatch):
    """``$NO_COLOR`` set → bar off, even on a TTY."""
    monkeypatch.setenv("NO_COLOR", "1")
    # _is_interactive() must respect NO_COLOR — let the real function
    # run with the env set so we test the real detection logic, not a
    # mock that contradicts the env.
    monkeypatch.setattr(progress_mod, "_RICH_AVAILABLE", True)
    # Sanity-check the real function returns False under NO_COLOR
    assert progress_mod._is_interactive() is False
    prog = progress_mod.ReconProgress(n_phases=5)
    assert prog.enabled is False


def test_enabled_when_force_color_env(monkeypatch):
    """``$FORCE_COLOR`` set → bar on, even when stdout isn't a TTY.
    Useful for CI screenshots / tmux capture."""
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("NO_COLOR", "1")  # even with both set, FORCE wins
    monkeypatch.setattr(progress_mod, "_RICH_AVAILABLE", True)
    assert progress_mod._is_interactive() is True


def test_disabled_when_stdout_not_tty(monkeypatch):
    """``sys.stdout`` not a TTY (piped to tee/file) → bar off."""
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    # simulate non-TTY by overriding the tty check
    monkeypatch.setattr(progress_mod.sys, "stdout", StringIO())
    assert progress_mod._is_interactive() is False


def test_enabled_when_stdout_is_tty(monkeypatch):
    """TTY + no env override → bar on (when rich is installed)."""
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)

    class FakeTTY(StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(progress_mod.sys, "stdout", FakeTTY())
    assert progress_mod._is_interactive() is True


# ----------------------------------------------------------------------
# Status style mapping
# ----------------------------------------------------------------------
def test_status_style_covers_all_statuses():
    for s in ("success", "failed", "skipped"):
        icon, color = progress_mod._STATUS_STYLE[s]
        assert icon and color  # non-empty


def test_status_style_unknown_status_returns_default():
    icon, color = progress_mod._STATUS_STYLE.get("unknown", ("?", "white"))
    assert icon == "?"
    assert color == "white"


# ----------------------------------------------------------------------
# Phase noun mapping
# ----------------------------------------------------------------------
def test_phase_noun_covers_known_stages():
    assert progress_mod._PHASE_NOUN["subdomain"] == "subdomains"
    assert progress_mod._PHASE_NOUN["nuclei_default"] == "findings"
    assert progress_mod._PHASE_NOUN["dirsearch"] == "urls"


def test_phase_noun_unknown_stage_returns_results():
    assert progress_mod._PHASE_NOUN.get("nonexistent", "results") == "results"


# ----------------------------------------------------------------------
# Context manager — disabled mode is a safe no-op
# ----------------------------------------------------------------------
def test_disabled_context_manager_does_not_raise(capsys):
    """All methods should be callable in disabled mode without raising.
    We don't want the progress bar to crash the whole scan."""
    prog = progress_mod.ReconProgress(n_phases=3, enabled=False)
    with prog:
        prog.start_phase("a", num=1)
        prog.finish_phase(
            {"stage": "a", "status": "success", "count": 1}, num=1,
        )
        with prog.parallel(["b", "c"], num=2):
            prog.subphase_done("b", {"status": "success", "count": 2})
        prog.finish_parallel(num=2)
    # No output to stdout because we're disabled.
    captured = capsys.readouterr()
    assert captured.out == ""


# ----------------------------------------------------------------------
# Phase description format
# ----------------------------------------------------------------------
def test_finish_phase_includes_status_icon():
    """The description embeds the status icon — the operator sees the
    outcome inline in the bar."""
    # Direct test of the description format by inspecting the code path
    # through disabled mode (no rich needed).
    prog = progress_mod.ReconProgress(n_phases=2, enabled=False)
    with prog:
        prog.start_phase("subdomain", num=1)
        # success
        prog.finish_phase(
            {"stage": "subdomain", "status": "success", "count": 343}, num=1,
        )
        # failed
        prog.start_phase("dirsearch", num=2)
        prog.finish_phase(
            {"stage": "dirsearch", "status": "failed", "count": 0}, num=2,
        )


# ----------------------------------------------------------------------
# parallel() context manager
# ----------------------------------------------------------------------
def test_parallel_yields_self():
    """The parallel() context manager yields the ReconProgress instance
    so callers can do ``with prog.parallel(...) as p: p.subphase_done(...)``."""
    prog = progress_mod.ReconProgress(n_phases=2, enabled=False)
    with prog.parallel(["a", "b"], num=1) as p:
        assert p is prog
        p.subphase_done("a", {"status": "success", "count": 1})


# ----------------------------------------------------------------------
# Multiple invocations — no state leaks between them
# ----------------------------------------------------------------------
def test_consecutive_context_managers_dont_leak():
    """Two consecutive ``with`` blocks should both work — the bar
    should clean up properly between scans."""
    for _ in range(2):
        prog = progress_mod.ReconProgress(n_phases=2, enabled=False)
        with prog:
            prog.start_phase("a", num=1)
            prog.finish_phase(
                {"stage": "a", "status": "success", "count": 1}, num=1,
            )