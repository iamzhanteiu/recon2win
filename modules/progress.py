"""progress — Rich progress bar for the recon workflow.

A thin wrapper around ``rich.progress.Progress`` that:
  * shows a single overall progress bar (14 phases in the canonical scan)
  * updates the description with each phase's status (✓/✗/⊘ + count)
  * auto-detects TTY + respects ``$NO_COLOR`` / ``$FORCE_COLOR``
  * falls back to a no-op when rich isn't installed OR stdout isn't a TTY
    (so log files stay grep-friendly and ``pip install`` doesn't fail
    in headless CI)

The bar lives at the bottom of the terminal. ``print()`` calls (phase
headers, status lines, output paths) write ABOVE the bar — Rich's
``Live`` keeps its region separate so the two streams don't fight.
"""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from typing import Iterator, Optional

try:
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        TaskID,
    )
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


# Status → (icon, rich color)
_STATUS_STYLE = {
    "success": ("✓", "green"),
    "failed":  ("✗", "red"),
    "skipped": ("⊘", "yellow"),
}


def _is_interactive() -> bool:
    """Only show the progress bar when stdout is a TTY.

    Respects the same conventions as ``modules/console.py``:
      * ``$FORCE_COLOR`` set → always show (CI screenshots etc.)
      * ``$NO_COLOR`` set → never show (log files, cron)
      * stdout not a TTY (piped to tee/file) → never show
    """
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(sys.stdout.isatty())


class ReconProgress:
    """Context manager that renders a single overall progress bar.

    Falls back to a no-op when rich isn't installed or stdout isn't a
    TTY, so all methods are safe to call regardless of environment.

    Usage::

        prog = ReconProgress(n_phases=14)
        with prog:
            prog.start_phase("subdomain", num=1)
            result = run_stage(...)
            prog.finish_phase("subdomain", result, num=1)

            prog.start_parallel(["cd", "dirsearch", "waymore", "nuclei"], num=4)
            # ... run in ThreadPoolExecutor ...
            prog.finish_parallel(num=4, results=[r1, r2, r3, r4])

    The bar description shows the CURRENT phase with its icon and count,
    so the operator sees at a glance which stage is running and how it
    finished.
    """

    def __init__(self, n_phases: int = 14, enabled: bool = True):
        self.n_phases = n_phases
        self.enabled = enabled and _RICH_AVAILABLE and _is_interactive()
        self._progress: Optional[Progress] = None
        self._overall: Optional[TaskID] = None
        self._parallel_tasks: dict[str, TaskID] = {}

    # ------------------------------------------------------------------
    # context manager
    # ------------------------------------------------------------------
    def __enter__(self) -> "ReconProgress":
        if not self.enabled:
            return self
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("{task.completed}/{task.total}"),
            TextColumn("•"),
            TimeElapsedColumn(),
        )
        self._progress.__enter__()
        self._overall = self._progress.add_task(
            "[bold]recon-agent[/bold]", total=self.n_phases,
        )
        return self

    def __exit__(self, *exc_info) -> bool:
        if self._progress:
            self._progress.__exit__(*exc_info)
        return False

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def start_phase(self, name: str, num: int) -> None:
        """Mark a sequential phase as starting.

        Updates the bar description so the operator sees which stage is
        running. The bar does NOT advance yet — call ``finish_phase()``
        when the stage completes.
        """
        if not self.enabled:
            return
        desc = f"[cyan][{num:02d}/{self.n_phases:02d}][/cyan] {name}"
        self._progress.update(self._overall, description=desc)

    def finish_phase(self, result: dict, num: int) -> None:
        """Mark a sequential phase as complete.

        Updates the bar description with the result (icon + count) and
        advances the bar by one.
        """
        if not self.enabled:
            return
        name = result.get("stage") or "?"
        status = result.get("status") or "skipped"
        count = result.get("count", 0)
        noun = _PHASE_NOUN.get(name, "results")
        icon, color = _STATUS_STYLE.get(status, ("?", "white"))
        desc = (
            f"[{color}][{num:02d}/{self.n_phases:02d}] {name} "
            f"{icon} {count} {noun}[/{color}]"
        )
        self._progress.update(self._overall, advance=1, description=desc)

    @contextmanager
    def parallel(self, names: list[str], num: int) -> Iterator["ReconProgress"]:
        """Context manager for a parallel stage group.

        While inside, the bar description reads
        ``"[N/total] parallel: a, b, c, d"``. Each sub-phase gets its own
        task so its status appears inline.

        Example::

            with prog.parallel(["cd", "dirsearch"], num=6) as p:
                # advance each sub-phase independently:
                p.subphase_done("cd", r_cd)
                p.subphase_done("dirsearch", r_dirsearch)
        """
        if not self.enabled:
            yield self
            return
        names_str = ", ".join(names)
        desc = (
            f"[magenta][{num:02d}/{self.n_phases:02d}][/magenta] "
            f"parallel: {names_str}"
        )
        self._progress.update(self._overall, description=desc)
        # Create one sub-task per sub-phase. Each is sized at 1; we
        # ``advance(1)`` when the sub-phase finishes.
        for n in names:
            self._parallel_tasks[n] = self._progress.add_task(n, total=1, visible=False)
        try:
            yield self
        finally:
            # Make all sub-task rows visible (so the operator sees the
            # final ✓/✗ after the group completes) and clear them so
            # the next sequential phase doesn't see stale rows.
            for tid in self._parallel_tasks.values():
                self._progress.update(tid, visible=True)
            self._parallel_tasks.clear()

    def subphase_done(self, name: str, result: dict) -> None:
        """Mark one sub-phase within a ``parallel`` group as complete."""
        if not self.enabled:
            return
        tid = self._parallel_tasks.get(name)
        if tid is None:
            return
        status = result.get("status") or "skipped"
        count = result.get("count", 0)
        icon, color = _STATUS_STYLE.get(status, ("?", "white"))
        desc = f"{name} {icon} {count}"
        self._progress.update(tid, advance=1, description=desc)

    def finish_parallel(self, num: int) -> None:
        """Mark a parallel group as done — advance the overall bar by 1."""
        if not self.enabled:
            return
        desc = (
            f"[magenta][{num:02d}/{self.n_phases:02d}][/magenta] "
            f"parallel done"
        )
        self._progress.update(self._overall, advance=1, description=desc)


# Noun used for the per-phase status description in the bar.
# Kept here (not in main.py) so the bar stays self-contained.
_PHASE_NOUN: dict[str, str] = {
    "subdomain":         "subdomains",
    "dnsx":              "resolved",
    "httpx_alive":       "alive hosts",
    "content_discovery": "urls",
    "dirsearch":         "urls",
    "waymore":           "urls",
    "nuclei_default":    "findings",
    "url_merge":         "urls",
    "url_merge_append":  "urls",
    "httpx_urls":        "alive urls",
    "xnlinkfinder":      "endpoints",
    "jsluice":           "endpoints+secrets",
    "arjun":             "parameterized urls",
    "nuclei_endpoints":  "findings",
    "nuclei_dynamic":    "findings",
    "report":            "artifacts",
}