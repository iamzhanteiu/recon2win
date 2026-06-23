"""runner — every external command is invoked through here.

We:
  * log the command (with UTC timestamp) to logs/commands.log
  * capture stdout/stderr to logs/<stage>.{out,err}
  * enforce a per-stage timeout
  * return a structured dict so the caller can build a stage result

If the binary is missing the runner still returns a dict (success=False)
instead of raising — the caller decides whether the stage is optional.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Sequence

from .utils import ensure_dir, safe_append


def which(binary: str) -> Optional[str]:
    """Return absolute path to *binary* or None if not on PATH."""
    return shutil.which(binary)


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
    input_data: Optional[str] = None,
    env: Optional[dict] = None,
    check: bool = False,
) -> dict:
    """Run a subprocess and return a structured dict.

    Output paths are derived from `output_dir/logs/`:
      - commands.log: cumulative command history
      - <stage>.stdout: process stdout
      - <stage>.stderr: process stderr
    """
    logs_dir = ensure_dir(Path(output_dir) / "logs")
    cmd_log = logs_dir / "commands.log"
    out_log = logs_dir / f"{stage}.stdout"
    err_log = logs_dir / f"{stage}.stderr"

    _log_command(cmd_log, cmd, stage)

    start = time.time()
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            env=env,
            check=check,
        )
        out_log.write_text(proc.stdout or "", encoding="utf-8")
        err_log.write_text(proc.stderr or "", encoding="utf-8")
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "stdout_path": str(out_log),
            "stderr_path": str(err_log),
            "duration": round(time.time() - start, 2),
            "success": proc.returncode == 0,
            "timed_out": False,
            "missing_binary": False,
        }
    except FileNotFoundError as exc:
        # binary not on PATH
        err_log.write_text(f"FileNotFoundError: {exc}\n", encoding="utf-8")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "stdout_path": str(out_log),
            "stderr_path": str(err_log),
            "duration": round(time.time() - start, 2),
            "success": False,
            "timed_out": False,
            "missing_binary": True,
        }
    except subprocess.TimeoutExpired:
        err_log.write_text(f"TimeoutExpired after {timeout}s\n", encoding="utf-8")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
            "stdout_path": str(out_log),
            "stderr_path": str(err_log),
            "duration": round(time.time() - start, 2),
            "success": False,
            "timed_out": True,
            "missing_binary": False,
        }
    except Exception as exc:  # noqa: BLE001
        err_log.write_text(f"Exception: {exc}\n", encoding="utf-8")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "stdout_path": str(out_log),
            "stderr_path": str(err_log),
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
