"""Tests for modules/runlog.py — the leveled logs/run.log handler."""
from __future__ import annotations

import logging
from pathlib import Path

from modules import runlog


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_setup_creates_run_log_and_writes_info(tmp_path: Path):
    log = runlog.setup(tmp_path, {})
    log.info("hello %s", "world")
    for h in log.handlers:
        h.flush()

    run_log = tmp_path / "logs" / "run.log"
    assert run_log.exists()
    text = _read(run_log)
    assert "hello world" in text
    assert "INFO" in text


def test_default_level_drops_debug(tmp_path: Path):
    log = runlog.setup(tmp_path, {})
    log.debug("should not appear")
    for h in log.handlers:
        h.flush()

    text = _read(tmp_path / "logs" / "run.log")
    assert "should not appear" not in text


def test_configured_level_allows_debug(tmp_path: Path):
    log = runlog.setup(tmp_path, {"logging": {"level": "DEBUG"}})
    log.debug("now it shows")
    for h in log.handlers:
        h.flush()

    text = _read(tmp_path / "logs" / "run.log")
    assert "now it shows" in text


def test_disabled_writes_no_file(tmp_path: Path):
    log = runlog.setup(tmp_path, {"logging": {"enabled": False}})
    log.error("nobody sees this")

    assert not (tmp_path / "logs" / "run.log").exists()
    assert any(isinstance(h, logging.NullHandler) for h in log.handlers)


def test_setup_twice_same_dir_does_not_duplicate_handler(tmp_path: Path):
    log1 = runlog.setup(tmp_path, {})
    file_handlers_1 = [h for h in log1.handlers if isinstance(h, logging.FileHandler)]
    log2 = runlog.setup(tmp_path, {})
    file_handlers_2 = [h for h in log2.handlers if isinstance(h, logging.FileHandler)]

    assert log1 is log2
    assert len(file_handlers_1) == 1
    assert len(file_handlers_2) == 1
    assert file_handlers_1[0] is file_handlers_2[0]


def test_setup_different_dir_switches_target_file(tmp_path: Path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"

    log = runlog.setup(dir_a, {})
    log.info("goes to a")
    for h in log.handlers:
        h.flush()

    log = runlog.setup(dir_b, {})
    log.info("goes to b")
    for h in log.handlers:
        h.flush()

    assert "goes to a" in _read(dir_a / "logs" / "run.log")
    assert "goes to b" not in _read(dir_a / "logs" / "run.log")
    assert "goes to b" in _read(dir_b / "logs" / "run.log")
    # exactly one FileHandler survives — the old one was closed and removed.
    file_handlers = [h for h in log.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1


def test_get_before_setup_does_not_raise(tmp_path: Path):
    # A fresh logger name would have no handler but the NullHandler; simulate
    # by just calling get() and logging — must not raise even if setup()
    # was never called in this test.
    log = runlog.get()
    log.info("no-op is fine")
