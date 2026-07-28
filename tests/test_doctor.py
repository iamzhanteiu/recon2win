"""Tests for the preflight doctor + PATH augmentation.

doctor reports installed tools / configured keys / wordlists and exits 1
only when a REQUIRED tool is missing. _augment_path (in main) prepends user
tool dirs so subprocesses find go/pip/pdtm-installed binaries.
"""
from __future__ import annotations

import os
from pathlib import Path

from modules import doctor
import main


# ----------------------------------------------------------------------
# tool resolution + alias (chaos / chaos-client)
# ----------------------------------------------------------------------
def test_chaos_alias_resolves_via_chaos_client(monkeypatch):
    monkeypatch.setattr(doctor, "which",
                        lambda b: "/usr/bin/chaos-client" if b == "chaos-client" else None)
    assert doctor._resolve_tool("chaos") == "/usr/bin/chaos-client"


def test_required_missing_sets_exit_code(monkeypatch, capsys):
    # only subfinder present → the other required tools are missing
    monkeypatch.setattr(doctor, "which",
                        lambda b: "/usr/bin/subfinder" if b == "subfinder" else None)
    code = doctor.run({}, added_paths=[])
    out = capsys.readouterr().out
    assert code == 1
    assert "required tools missing" in out
    assert "httpx" in out and "nuclei" in out


def test_all_required_present_exit_zero(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "which", lambda b: f"/usr/bin/{b}")
    code = doctor.run({"ffuf": {"wordlists": []}}, added_paths=["/home/u/.local/bin"])
    out = capsys.readouterr().out
    assert code == 0
    assert "all required tools present" in out
    assert "PATH augmented" in out


# ----------------------------------------------------------------------
# API-key detection (cfg is already env-resolved by _load_config)
# ----------------------------------------------------------------------
def test_keys_read_resolved_config(monkeypatch):
    rows = doctor._check_keys({
        "subdomain": {"chaos_api_key": "abc"},
        "telegram": {"bot_token": "", "chat_id": ""},
        "hackerone": {"api_username": "u", "api_token": "t"},
    })
    by_label = {r[0]: r[1] for r in rows}
    assert by_label["chaos API key"] is True
    assert by_label["Telegram"] is False
    assert by_label["HackerOne API"] is True


# ----------------------------------------------------------------------
# wordlist existence
# ----------------------------------------------------------------------
def test_wordlist_check(tmp_path):
    exists = tmp_path / "wl.txt"
    exists.write_text("a\n")
    rows = doctor._check_wordlists({
        "ffuf": {"wordlists": [str(exists), str(tmp_path / "missing.txt")]},
        "dirsearch": {"wordlists": [str(exists)]},  # dup — collapsed
    })
    paths = {p: e for p, e in rows}
    assert paths[str(exists)] is True
    assert paths[str(tmp_path / "missing.txt")] is False
    # the duplicate is only listed once
    assert len(rows) == 2


def test_summarise_counts(monkeypatch):
    monkeypatch.setattr(doctor, "which",
                        lambda b: f"/usr/bin/{b}" if b in ("subfinder", "dnsx",
                        "httpx", "katana", "nuclei") else None)
    s = doctor.summarise({})
    assert s["missing_required"] == []          # all 5 required present
    assert "ffuf" in s["missing_optional"]      # optional ones absent


# ----------------------------------------------------------------------
# _augment_path
# ----------------------------------------------------------------------
def test_augment_path_prepends_existing_dirs(tmp_path, monkeypatch):
    fake_local = tmp_path / ".local" / "bin"
    fake_local.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.delenv("GOPATH", raising=False)
    monkeypatch.delenv("GOBIN", raising=False)

    added = main._augment_path()
    assert str(fake_local) in added
    assert os.environ["PATH"].startswith(str(fake_local))
    # a non-existent candidate (~/go/bin here) is never added
    assert str(tmp_path / "go" / "bin") not in added


def test_augment_path_no_duplicates(tmp_path, monkeypatch):
    fake_local = tmp_path / ".local" / "bin"
    fake_local.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    # already on PATH → must not be added again
    monkeypatch.setenv("PATH", f"{fake_local}:/usr/bin")
    monkeypatch.delenv("GOPATH", raising=False)
    monkeypatch.delenv("GOBIN", raising=False)

    added = main._augment_path()
    assert str(fake_local) not in added
