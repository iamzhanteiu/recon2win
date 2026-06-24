"""console — colors, status icons, pretty phase headers.

Single source of truth for terminal formatting. Auto-detects TTY +
``NO_COLOR`` / ``FORCE_COLOR`` environment variables so the output is:

* colorful when run interactively in a terminal
* plain text when piped to ``tee``, ``less``, a file, or anything else
* overridable via ``--no-color`` / ``--color`` (handled in ``main.py``)

Every helper returns plain text when colors are disabled — log files
stay grep-friendly, and ``2>&1 | tee /tmp/scan.log`` produces a clean
file even though the user sees colors on their terminal.
"""
from __future__ import annotations

import os
import shutil
import sys


# ----------------------------------------------------------------------
# ANSI codes — minimal subset, no external deps
# ----------------------------------------------------------------------
_RESET = "\033[0m"

_COLORS: dict[str, str] = {
    "black":         "\033[30m",
    "red":           "\033[31m",
    "green":         "\033[32m",
    "yellow":        "\033[33m",
    "blue":          "\033[34m",
    "magenta":       "\033[35m",
    "cyan":          "\033[36m",
    "white":         "\033[37m",
    "bright_black":   "\033[90m",
    "bright_red":     "\033[91m",
    "bright_green":   "\033[92m",
    "bright_yellow":  "\033[93m",
    "bright_blue":    "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan":    "\033[96m",
    "bright_white":   "\033[97m",
}

_STYLES: dict[str, str] = {
    "bold":      "\033[1m",
    "dim":       "\033[2m",
    "italic":    "\033[3m",
    "underline": "\033[4m",
}


# ----------------------------------------------------------------------
# Phase color map — every recon stage gets a distinct hue so the
# output is scannable at a glance, especially when parallel stages
# interleave (stage 4 runs 4 stages concurrently, stage 6 runs 2).
# Each phase has a unique color; related categories use shades of
# the same family (the two yellow dirsearch/waymore stages, etc.)
#
# ``summary`` is intentionally absent — it's a synthesised stage that
# never gets a phase header, so it falls through to the default white.
# ----------------------------------------------------------------------
PHASE_COLORS: dict[str, str] = {
    "subdomain":          "bright_cyan",
    "dnsx":               "blue",
    "httpx_alive":        "bright_blue",
    "content_discovery":  "bright_magenta",
    "dirsearch":          "bright_yellow",
    "waymore":            "yellow",
    "nuclei_default":     "bright_red",
    "url_merge":          "white",
    "url_merge_append":   "bright_black",
    "httpx_urls":         "cyan",
    "xnlinkfinder":       "bright_green",
    "arjun":              "green",
    "nuclei_dynamic":     "red",
    "report":             "bright_white",
}


# Stage ordering used to render the [NN/TT] prefix. Anything not in
# this list falls back to no prefix.
_PHASE_ORDER: list[str] = [
    "subdomain",
    "dnsx",
    "httpx_alive",
    "content_discovery",
    "dirsearch",
    "waymore",
    "nuclei_default",
    "url_merge",
    "httpx_urls",
    "xnlinkfinder",
    "url_merge_append",
    "arjun",
    "nuclei_dynamic",
    "report",
]


# ----------------------------------------------------------------------
# Color enable/disable — auto-detected on import, overridable
# ----------------------------------------------------------------------
def _detect_color() -> bool:
    """Return True when ANSI color codes should be emitted.

    Precedence (highest first):
      1. ``FORCE_COLOR`` set to anything truthy → always color
      2. ``NO_COLOR`` set to anything (even empty) → never color
         (per https://no-color.org standard)
      3. ``sys.stdout.isatty()`` → color only when interactive
    """
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(sys.stdout.isatty())


_ENABLED: bool = _detect_color()


def is_enabled() -> bool:
    return _ENABLED


def set_enabled(flag: bool) -> None:
    """Override the auto-detected flag. Used by ``--no-color`` /
    ``--color`` CLI flags and by tests."""
    global _ENABLED
    _ENABLED = bool(flag)


# ----------------------------------------------------------------------
# Low-level colorizer
# ----------------------------------------------------------------------
def c(text: str, color: str | None = None, *,
      bold: bool = False, dim: bool = False) -> str:
    """Wrap *text* with the given color/style. Returns plain text when
    colors are disabled. ``color=None`` means no color but styles
    still apply.

    Multiple styles can be combined by calling ``c()`` multiple times.
    Nesting is fine — the ``\\033[0m`` reset only stops at the end of
    this call so styles compose cleanly.
    """
    if not _ENABLED or not text:
        return text
    out = text
    if dim:
        out = _STYLES["dim"] + out
    if bold:
        out = _STYLES["bold"] + out
    if color and color in _COLORS:
        out = _COLORS[color] + out + _RESET
    elif (bold or dim) and color is None:
        # close the style span we opened
        out = out + _RESET
    return out


# ----------------------------------------------------------------------
# Status icons — unicode when colors are on, ASCII when off
# ----------------------------------------------------------------------
_ICONS_COLOR: dict[str, str] = {
    "success": "✓",
    "failed":  "✗",
    "skipped": "⊘",
}
_ICONS_PLAIN: dict[str, str] = {
    "success": "[OK]",
    "failed":  "[FAIL]",
    "skipped": "[SKIP]",
}


def icon(status: str) -> str:
    """Return the glyph for *status*. ASCII fallback when colors are
    disabled so log files stay grep-friendly."""
    table = _ICONS_COLOR if _ENABLED else _ICONS_PLAIN
    return table.get(status, "·")


_STATUS_COLORS: dict[str, str] = {
    "success": "bright_green",
    "failed":  "bright_red",
    "skipped": "bright_yellow",
}


def status_color(status: str) -> str:
    return _STATUS_COLORS.get(status, "white")


# ----------------------------------------------------------------------
# High-level formatters used by main.py
# ----------------------------------------------------------------------
def phase_color(stage: str) -> str:
    """Return the canonical color for *stage*. Falls back to white."""
    return PHASE_COLORS.get(stage, "white")


def phase_number(stage: str, total: int | None = None) -> str:
    """Return ``[03]`` (or ``[03/13]``) for *stage*. Returns ``""``
    when the stage is not in the known ordering."""
    try:
        n = _PHASE_ORDER.index(stage) + 1
    except ValueError:
        return ""
    if total is None:
        total = len(_PHASE_ORDER)
    return f"[{n:02d}/{total:02d}]"


def phase_header(stage: str) -> str:
    """Wide horizontal rule with ``[03] stage_name`` centered.

    Width adapts to the terminal (40..100 cols) so it looks good in
    both narrow and wide terminals. Falls back to ASCII hyphens when
    colors are disabled so the file log stays plain.
    """
    width = shutil.get_terminal_size((80, 20)).columns
    width = max(40, min(width, 100))
    color = phase_color(stage)
    num = phase_number(stage)
    label = f"{num} {stage}" if num else stage
    bar_char = "━" if _ENABLED else "-"
    # 4 chars after the label, rest before
    side = max(2, (width - len(label) - 4) // 2)
    line = bar_char * side + " " + label + " " + bar_char * side
    return c(line, color, bold=True)


def phase_status_line(
    stage: str,
    status: str,
    count: int,
    elapsed: float,
    *,
    noun: str = "results",
) -> str:
    """``  ✓ success · 343 results · 152.78s`` (with appropriate colors)."""
    ic = c(icon(status), status_color(status), bold=True)
    word = c(status, status_color(status), bold=True)
    n = c(f"{count:,}", "bright_white", bold=True)
    t = c(f"{elapsed:.2f}s", "white")
    return f"  {ic} {word} · {n} {noun} · {t}"


def phase_error_line(err: str) -> str:
    """``  ! error message`` in dim red."""
    return f"  {c('!', 'bright_red', bold=True)} {c(err, 'bright_red')}"


def phase_warn_line(msg: str) -> str:
    """``  ! warn message`` in dim yellow (for non-fatal warnings)."""
    return f"  {c('!', 'bright_yellow', bold=True)} {c(msg, 'yellow')}"


def phase_info_line(msg: str) -> str:
    """``  ℹ info message`` in dim cyan (for informational lines)."""
    return f"  {c('ℹ', 'cyan', bold=True)} {c(msg, 'cyan')}"


def phase_outputs(result: dict, output_dir) -> list[str]:
    """Return one dim line per output file in the stage result.

    Paths are shown relative to ``output_dir`` so the output stays
    readable in a 100-column terminal. Output paths that don't fall
    under ``output_dir`` (rare — e.g. an absolute path passed by a
    stage) are shown as-is.

    Example::

        → processed/subdomains.txt
        → raw/subdomain/subfinder.txt
        → raw/subdomain/amass.txt
        → raw/subdomain/chaos.txt

    Returns an empty list when the stage has no outputs to report.
    """
    from pathlib import Path
    outputs = (result or {}).get("outputs") or []
    if not outputs:
        return []
    lines: list[str] = []
    arrow = c("→", "dim")
    for raw in outputs:
        try:
            p = Path(str(raw))
            try:
                rel = p.relative_to(output_dir)
                shown = str(rel)
            except ValueError:
                shown = str(p)
        except Exception:  # noqa: BLE001
            shown = str(raw)
        lines.append(f"  {arrow} {c(shown, 'dim')}")
    return lines


def cmd_echo(stage: str, cmd) -> str:
    """``  [stage_name] $ cmd arg1 arg2 ...`` for printing.

    The stage tag is colored with the phase color (so a glance at the
    log tells you which stage a cmd belongs to); the dollar sign and
    command itself are dim. ``cmd`` may be a list of strings or a
    pre-formatted string.
    """
    color = phase_color(stage)
    cmd_str = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
    tag = c(f"[{stage}]", color, bold=True)
    dollar = c("$", "dim")
    body = c(cmd_str, "white")
    return f"  {tag} {dollar} {body}"


def kv(key: str, value: str, *, value_color: str = "bright_white") -> str:
    """Format a ``key: value`` pair — key dim, value colored."""
    return f"{c(key + ':', 'dim')} {c(str(value), value_color)}"


def banner(text: str, color: str = "bright_cyan") -> str:
    """Single-line banner used for the top ``[+] target:`` lines."""
    return c(f"[+] {text}", color, bold=True)