"""Tests for the seamless HackerOne flow glue in main.py.

Covers the interactive picker helpers that stitch --h1-list → pick program →
pick root → recon together. The HackerOne API itself is faked; we only test
main.py's selection/branching logic.
"""
from __future__ import annotations

import builtins

import pytest

import main


class _FakeH1:
    """Stand-in for ``modules.hackerone`` injected into main's helpers."""

    class H1Error(Exception):
        pass

    def __init__(self, *, programs=None, roots=None, raise_on=None):
        self._programs = programs or []
        self._roots = roots or []
        self._raise_on = raise_on  # "creds" | "list" | "roots" | None

    def get_credentials(self, cfg=None):
        if self._raise_on == "creds":
            raise self.H1Error("no HackerOne credentials")
        return ("user", "token")

    def list_programs(self, user, token, *, timeout=30):
        if self._raise_on == "list":
            raise self.H1Error("401 Unauthorized")
        return self._programs

    def roots_for_program(self, user, token, handle, *, timeout=30):
        if self._raise_on == "roots":
            raise self.H1Error("api down")
        return self._roots


@pytest.fixture
def patch_h1(monkeypatch):
    """Patch the lazily-imported ``modules.hackerone`` inside main's helpers."""
    def _apply(fake: _FakeH1):
        import modules.hackerone as real
        monkeypatch.setattr(real, "get_credentials", fake.get_credentials)
        monkeypatch.setattr(real, "list_programs", fake.list_programs)
        monkeypatch.setattr(real, "roots_for_program", fake.roots_for_program)
        monkeypatch.setattr(real, "H1Error", fake.H1Error)
    return _apply


def _answer(monkeypatch, text: str):
    monkeypatch.setattr(builtins, "input", lambda prompt="": text)


def _tty(monkeypatch, is_tty: bool):
    monkeypatch.setattr("sys.stdin.isatty", lambda: is_tty)


# ---------------------------------------------------------------- _prompt_index
@pytest.mark.parametrize("answer,default,expected", [
    ("2", None, 1),      # 1-based → 0-based
    ("1", None, 0),
    ("", 0, 0),          # empty → default (first)
    ("", None, None),    # empty → default (abort)
    ("5", 0, None),      # out of range
    ("abc", 0, None),    # not a number
])
def test_prompt_index(monkeypatch, answer, default, expected):
    _answer(monkeypatch, answer)
    assert main._prompt_index(3, "pick: ", default=default) == expected


def test_prompt_index_eof_returns_default(monkeypatch):
    def _raise(prompt=""):
        raise EOFError
    monkeypatch.setattr(builtins, "input", _raise)
    assert main._prompt_index(3, "pick: ", default=0) == 0
    assert main._prompt_index(3, "pick: ", default=None) is None


# -------------------------------------------------------- _h1_choose_program
def test_choose_program_interactive_pick(patch_h1, monkeypatch):
    patch_h1(_FakeH1(programs=[{"handle": "acme", "name": "Acme"},
                               {"handle": "globex", "name": "Globex"}]))
    _tty(monkeypatch, True)
    _answer(monkeypatch, "2")
    handle, rc = main._h1_choose_program({})
    assert (handle, rc) == ("globex", 0)


def test_choose_program_enter_quits(patch_h1, monkeypatch):
    patch_h1(_FakeH1(programs=[{"handle": "acme", "name": "Acme"}]))
    _tty(monkeypatch, True)
    _answer(monkeypatch, "")  # Enter → quit, nothing to recon
    handle, rc = main._h1_choose_program({})
    assert handle is None and rc == 0


def test_choose_program_non_tty_lists_and_exits(patch_h1, monkeypatch, capsys):
    # Piped/scripted: never blocks on input(), just prints the list + hint.
    patch_h1(_FakeH1(programs=[{"handle": "acme", "name": "Acme"}]))
    _tty(monkeypatch, False)
    def _boom(prompt=""):
        raise AssertionError("input() must not be called in a non-TTY shell")
    monkeypatch.setattr(builtins, "input", _boom)
    handle, rc = main._h1_choose_program({})
    assert handle is None and rc == 0
    assert "--h1-program" in capsys.readouterr().out


def test_choose_program_credentials_error_is_rc2(patch_h1, monkeypatch):
    patch_h1(_FakeH1(raise_on="creds"))
    handle, rc = main._h1_choose_program({})
    assert handle is None and rc == 2


def test_choose_program_empty_list_is_rc0(patch_h1, monkeypatch):
    patch_h1(_FakeH1(programs=[]))
    handle, rc = main._h1_choose_program({})
    assert handle is None and rc == 0


# -------------------------------------------------------------- _h1_pick_root
def test_pick_root_single_auto_selected(patch_h1, monkeypatch):
    # One in-scope root → no prompt, recon it straight away.
    patch_h1(_FakeH1(roots=["acme.com"]))
    def _boom(prompt=""):
        raise AssertionError("should not prompt for a single root")
    monkeypatch.setattr(builtins, "input", _boom)
    assert main._h1_pick_root({}, "acme") == "acme.com"


def test_pick_root_multi_pick(patch_h1, monkeypatch):
    patch_h1(_FakeH1(roots=["acme.com", "acme.io", "acme.net"]))
    _answer(monkeypatch, "3")
    assert main._h1_pick_root({}, "acme") == "acme.net"


def test_pick_root_default_first(patch_h1, monkeypatch):
    patch_h1(_FakeH1(roots=["acme.com", "acme.io"]))
    _answer(monkeypatch, "")  # Enter → default first
    assert main._h1_pick_root({}, "acme") == "acme.com"


def test_pick_root_no_roots_returns_none(patch_h1, monkeypatch):
    patch_h1(_FakeH1(roots=[]))
    assert main._h1_pick_root({}, "acme") is None
