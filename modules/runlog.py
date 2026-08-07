"""runlog — leveled, persistent run log (``logs/run.log``).

``main.py::_run_stage`` prints a narrative to the terminal (via
``modules/console.py``), but almost none of it survives on disk
incrementally: ``logs/stages.json`` is only written once, at the very end
of a successful run. A run killed mid-way (SSH drop, OOM on a long nuclei
scan, VPS reboot) leaves no record of what happened before the crash beyond
raw subprocess output in per-stage ``.log`` files — no "which stage was
running, for how long, when it died" trail. ``logs/run.log`` fixes that:
every record is flushed to disk as it happens, not batched to the end.

Deliberately does NOT attach a console/stream handler — ``console.py`` /
``print()`` already own the terminal, and a second handler here would
either double-print or fight over color/formatting. This is additive: a
second, plain-text, leveled record of the same events, for anything that
isn't watching the terminal live (a cron run, a post-mortem, log shipping).

Usage::

    from modules import runlog
    logger = runlog.setup(output_dir, cfg)   # once, after create_output_structure()
    logger.info("stage dnsx status=success count=1234 elapsed=12.3s")
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

_LOGGER_NAME = "recon2win"

# Library-author idiom: a NullHandler at import time means any log call made
# before setup() (or when logging.enabled: false) is silently dropped
# instead of falling back to Python's stderr "lastResort" handler.
logging.getLogger(_LOGGER_NAME).addHandler(logging.NullHandler())


def setup(output_dir: Path, cfg: Optional[dict] = None) -> logging.Logger:
    """Attach a file handler for this run's ``logs/run.log``; return the logger.

    Idempotent per *output_dir*: calling it again for the same target reuses
    the existing handler (just updates the level) instead of duplicating log
    lines. Calling it for a different *output_dir* closes the previous file
    handler first, so a process never holds more than one ``run.log`` open —
    matters for tests, which call this once per ``tmp_path``.

    ``cfg["logging"]``:
      * ``enabled`` (default ``True``) — ``False`` disables the file handler
        entirely; log calls become no-ops (via the module-level NullHandler).
      * ``level`` (default ``"INFO"``) — ``DEBUG``/``INFO``/``WARNING``/
        ``ERROR``, case-insensitive.
    """
    logging_cfg = (cfg or {}).get("logging") or {}
    logger = logging.getLogger(_LOGGER_NAME)
    logger.propagate = False

    if not logging_cfg.get("enabled", True):
        _close_handlers(logger)
        logger.addHandler(logging.NullHandler())
        return logger

    log_path = Path(output_dir) / "logs" / "run.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    resolved = str(log_path.resolve())

    already_open = any(
        isinstance(h, logging.FileHandler) and h.baseFilename == resolved
        for h in logger.handlers
    )
    if not already_open:
        _close_handlers(logger)
        handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        formatter.converter = time.gmtime  # UTC — matches logs/commands.log
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(_resolve_level(logging_cfg.get("level", "INFO")))
    return logger


def get() -> logging.Logger:
    """Return the recon2win logger. Safe to call before ``setup()`` — log
    calls are simply dropped (module-level NullHandler) until it runs."""
    return logging.getLogger(_LOGGER_NAME)


def _close_handlers(logger: logging.Logger) -> None:
    for h in list(logger.handlers):
        try:
            h.close()
        except Exception:  # noqa: BLE001 — best-effort cleanup, never fatal
            pass
        logger.removeHandler(h)


def _resolve_level(level: str) -> int:
    resolved = getattr(logging, str(level).upper(), None)
    return resolved if isinstance(resolved, int) else logging.INFO
