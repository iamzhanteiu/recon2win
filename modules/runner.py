"""runner — every external command is invoked through here.

We:
  * log the command (with UTC timestamp) to logs/commands.log
  * echo the command line to stderr right before it runs (one line per command)
  * capture stdout/stderr to logs/<stage>.{out,err}
  * enforce a per-stage timeout
  * return a structured dict so the caller can build a stage result

If the binary is missing the runner still returns a dict (success=False)
instead of raising — the caller decides whether the stage is optional.

The persistent record of every command is ``logs/commands.log`` (UTC
timestamp, stage name, full argv). Tail it live with::

    tail -f outputs/<domain>/logs/commands.log
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import console
from .utils import ensure_dir, safe_append


def which(binary: str) -> Optional[str]:
    """Return absolute path to *binary* on ``$PATH`` (case-insensitive), or None.

    ``shutil.which`` is case-sensitive on POSIX, so it misses binaries
    installed with mixed-case names (e.g. ``xnLinkFinder`` from
    ``pip install xnLinkFinder``) when callers look them up lower-cased.
    We walk ``$PATH`` manually and match by name + suffix ignoring case.
    On Windows we also accept ``.exe``/``.bat``/``.cmd`` suffixes.
    """
    if not binary:
        return None
    target = binary.lower()
    suffixes = ("", ".exe", ".bat", ".cmd") if os.name == "nt" else ("",)
    for dir_path in os.environ.get("PATH", "").split(os.pathsep):
        if not dir_path:
            continue
        try:
            entries = os.listdir(dir_path)
        except (OSError, PermissionError):
            continue
        for entry in entries:
            entry_lower = entry.lower()
            for suffix in suffixes:
                if entry_lower == target + suffix:
                    return os.path.join(dir_path, entry)
    return None


def tool_available(binary: str) -> bool:
    return which(binary) is not None


# ----------------------------------------------------------------------
# Command logging
# ----------------------------------------------------------------------
def _log_command(log_file: Path, cmd: Sequence[str], stage: str) -> None:
    ensure_dir(log_file.parent)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    safe_append(
        log_file,
        f"[{ts}] [{stage}] {' '.join(str(c) for c in cmd)}",
    )


# ----------------------------------------------------------------------
# The single run() function every module calls.
# ----------------------------------------------------------------------
def run(
    cmd: List[str],
    *,
    stage: str,
    output_dir: Path,
    timeout: int = 600,
    log_name: Optional[str] = None,
    input_data: Optional[str] = None,
    env: Optional[dict] = None,
    check: bool = False,
) -> dict:
    """Run a subprocess and return a structured dict.

    Output paths are derived from ``output_dir/logs/``:

    * ``commands.log`` — cumulative command history (UTC ts + stage + argv)
    * ``<log_name>.log`` — process output, append mode. ``log_name``
      defaults to ``stage`` but stages with multiple sub-calls (e.g.
      ``subdomain`` runs subfinder + amass + chaos) pass a shared
      ``log_name`` so all three outputs land in one log file with
      clear sub-stage headers.

    The full command line is echoed to stderr as a single ``$ ...``
    line right before exec so the operator can see what is running
    without scrolling through ``commands.log``. Child stdout/stderr
    is *not* streamed — inspect ``<log_name>.log`` afterwards.
    """
    logs_dir = ensure_dir(Path(output_dir) / "logs")
    cmd_log = logs_dir / "commands.log"
    log_target = log_name or stage
    out_log = logs_dir / f"{log_target}.log"

    _log_command(cmd_log, cmd, stage)

    # Resolve cmd[0] to the actual on-disk path. Two cases:
    #   1. Common — the bare name matches a binary on PATH exactly.
    #      We use ``shutil.which()`` (case-sensitive) and keep the
    #      bare name so the operator sees ``$ dirsearch -l ...`` in the
    #      echo, not ``$ /usr/local/bin/dirsearch -l ...``. Even if
    #      ``/usr/local/bin/dirsearch`` is a broken symlink or stale
    #      installation, ``shutil.which`` returns the *first* PATH
    #      match — which is the one subprocess.run will also find.
    #   2. Case-mismatch (xnLinkFinder is camelCase on disk but our
    #      command is ``xnlinkfinder``). ``shutil.which`` returns None
    #      on case-sensitive filesystems, so we fall back to our own
    #      case-insensitive ``which()`` to find ``xnLinkFinder``.
    # In both cases the resolved path is what we hand to subprocess.run;
    # the original ``cmd`` is what we show in the echo (preserves the
    # user's intent and avoids leaking system paths into log files).
    resolved = list(cmd)
    if cmd:
        bare_match = shutil.which(cmd[0])
        if bare_match:
            # Keep the bare name — subprocess.run will look it up on
            # PATH the same way shutil.which did, so the result is
            # identical. The echo stays clean.
            resolved[0] = cmd[0]
        else:
            path = which(cmd[0])
            if path:
                # Case-insensitive match — must use the resolved path
                # otherwise subprocess.run gets the wrong name.
                resolved[0] = path

    # Single line on stderr — what command is being run, nothing else.
    # Colored via console.cmd_echo() so parallel-stage output stays
    # scannable. Stays on stderr so it shows up immediately while the
    # process is starting (stdout would be buffered).
    # We echo the *original* cmd (not resolved) so the operator sees
    # ``$ dirsearch -l ...`` instead of ``$ /usr/local/bin/dirsearch -l ...``.
    print(console.cmd_echo(stage, cmd), file=sys.stderr, flush=True)
    start = time.time()
    try:
        proc = subprocess.run(
            resolved,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            env=env,
            check=check,
        )
        # Append to the per-stage log. Multiple sub-stages that share
        # a log_name (e.g. subdomain_subfinder + subdomain_amass +
        # subdomain_chaos all writing to logs/subdomain.log) get
        # clear section headers so the reader can tell them apart.
        elapsed = round(time.time() - start, 2)
        with out_log.open("a", encoding="utf-8") as fh:
            fh.write(f"=== {stage} ===\n")
            fh.write(f"--- stdout ---\n{proc.stdout or ''}")
            if proc.stderr and proc.stderr.strip():
                fh.write(f"--- stderr ---\n{proc.stderr}\n")
            fh.write(f"--- exit {proc.returncode} ({elapsed}s) ---\n\n")
        duration = elapsed
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "stdout_path": str(out_log),
            "stderr_path": str(out_log),  # combined into one log file (v2 layout)
            "log_path": str(out_log),
            "duration": duration,
            "success": proc.returncode == 0,
            "timed_out": False,
            "missing_binary": False,
        }
    except FileNotFoundError as exc:
        # binary not on PATH
        with out_log.open("a", encoding="utf-8") as fh:
            fh.write(f"=== {stage} ===\n--- stderr ---\nFileNotFoundError: {exc}\n\n")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "stdout_path": str(out_log),
            "stderr_path": str(out_log),
            "log_path": str(out_log),
            "duration": round(time.time() - start, 2),
            "success": False,
            "timed_out": False,
            "missing_binary": True,
        }
    except subprocess.TimeoutExpired:
        with out_log.open("a", encoding="utf-8") as fh:
            fh.write(f"=== {stage} ===\n--- stderr ---\nTimeoutExpired after {timeout}s\n\n")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
            "stdout_path": str(out_log),
            "stderr_path": str(out_log),
            "log_path": str(out_log),
            "duration": round(time.time() - start, 2),
            "success": False,
            "timed_out": True,
            "missing_binary": False,
        }
    except Exception as exc:  # noqa: BLE001
        with out_log.open("a", encoding="utf-8") as fh:
            fh.write(f"=== {stage} ===\n--- stderr ---\nException: {exc}\n\n")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "stdout_path": str(out_log),
            "stderr_path": str(out_log),
            "log_path": str(out_log),
            "duration": round(time.time() - start, 2),
            "success": False,
            "timed_out": False,
            "missing_binary": False,
        }


# ----------------------------------------------------------------------
# Convenience: warn (or fail) when a binary is missing.
# ----------------------------------------------------------------------
def require_binary(binary: str, stage: str, optional: bool = False) -> Optional[str]:
    """Return path if present, else print a warning. None signals the caller to skip."""
    path = which(binary)
    if path:
        return path
    msg = f"[{stage}] WARNING: '{binary}' not found on PATH"
    if optional:
        print(msg + " — optional, skipping.")
        return None
    print(msg + " — required stage, this will likely fail.")
    return None
