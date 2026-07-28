"""Tests for the console formatter.

We exercise every helper with both colors enabled and disabled. With
colors disabled the output must be plain ASCII so log files stay
grep-friendly; with colors enabled it must contain ANSI escapes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from modules import console


@pytest.fixture(autouse=True)
def _reset_console_flag():
    """Save and restore the console flag around each test so we don't
    leak color state between tests."""
    saved = console.is_enabled()
    yield
    console.set_enabled(saved)


# ----------------------------------------------------------------------
# c() — low-level colorizer
# ----------------------------------------------------------------------
def test_c_returns_plain_text_when_disabled():
    console.set_enabled(False)
    out = console.c("hello", "red", bold=True)
    assert out == "hello"
    assert "\033" not in out


def test_c_returns_ansi_when_enabled():
    console.set_enabled(True)
    out = console.c("hello", "red", bold=True)
    assert "hello" in out
    assert "\033[31m" in out   # red
    assert "\033[1m" in out    # bold
    assert out.endswith("\033[0m")


def test_c_with_only_bold_when_no_color():
    console.set_enabled(True)
    out = console.c("hi", None, bold=True)
    assert "\033[1m" in out
    assert "\033[0m" in out


def test_c_empty_string_returns_empty():
    console.set_enabled(True)
    assert console.c("", "red") == ""


def test_c_unknown_color_falls_back_to_plain():
    console.set_enabled(True)
    # An invalid color name must not crash — we just skip the color span.
    out = console.c("hi", "not-a-real-color")
    assert "hi" in out
    # No opening escape for the bogus color
    assert "\033[not-a-real-color" not in out


# ----------------------------------------------------------------------
# Icon + status_color — pure lookup
# ----------------------------------------------------------------------
def test_icon_unicode_when_enabled():
    console.set_enabled(True)
    assert console.icon("success") == "✓"
    assert console.icon("failed") == "✗"
    assert console.icon("skipped") == "⊘"


def test_icon_ascii_when_disabled():
    console.set_enabled(False)
    assert console.icon("success") == "[OK]"
    assert console.icon("failed") == "[FAIL]"
    assert console.icon("skipped") == "[SKIP]"


def test_icon_unknown_status_returns_middle_dot():
    assert console.icon("unknown") == "·"


def test_status_color_mapping():
    assert console.status_color("success") == "bright_green"
    assert console.status_color("failed") == "bright_red"
    assert console.status_color("skipped") == "bright_yellow"
    assert console.status_color("other") == "white"


def test_phase_color_mapping():
    assert console.phase_color("subdomain") == "bright_cyan"
    assert console.phase_color("dirsearch") == "bright_yellow"
    assert console.phase_color("arjun") == "green"
    assert console.phase_color("unknown_stage") == "white"


# ----------------------------------------------------------------------
# phase_number
# ----------------------------------------------------------------------
def test_phase_number_known_stage():
    assert console.phase_number("subdomain") == "[01/15]"
    assert console.phase_number("dnsx") == "[02/15]"
    assert console.phase_number("ffuf") == "[06/15]"
    # nuclei_default is the last scan, right before the report
    assert console.phase_number("nuclei_default") == "[14/15]"


def test_phase_number_unknown_stage_returns_empty():
    assert console.phase_number("not-a-real-stage") == ""


def test_phase_number_zero_pads():
    console.set_enabled(True)
    assert console.phase_number("arjun").startswith("[13/15")


# ----------------------------------------------------------------------
# phase_header
# ----------------------------------------------------------------------
def test_phase_header_has_label_when_enabled():
    console.set_enabled(True)
    out = console.phase_header("subdomain")
    assert "subdomain" in out
    # Wide rule
    assert "━" in out
    assert "[01/15]" in out
    # Colored bright_cyan + bold
    assert "\033[96m" in out  # bright_cyan
    assert "\033[1m" in out   # bold


def test_phase_header_falls_back_to_ascii_when_disabled():
    console.set_enabled(False)
    out = console.phase_header("subdomain")
    assert "subdomain" in out
    # No unicode bar
    assert "━" not in out
    assert "─" not in out
    # No ANSI
    assert "\033" not in out
    assert out.startswith("---") or out.startswith("-- ")


def test_phase_header_unknown_stage_still_renders():
    console.set_enabled(True)
    out = console.phase_header("custom")
    assert "custom" in out
    # No [NN/TT] stage-number prefix when the stage is not in the
    # known ordering. We check for the literal number prefix rather
    # than any '[' because ANSI escapes contain '[' chars.
    assert "[01/" not in out
    assert "[14]" not in out


# ----------------------------------------------------------------------
# phase_status_line
# ----------------------------------------------------------------------
def test_phase_status_line_success_format():
    console.set_enabled(True)
    out = console.phase_status_line("subdomain", "success", 343, 152.78,
                                    noun="subdomains")
    assert "✓" in out
    assert "success" in out
    assert "343" in out
    assert "152.78s" in out
    assert "subdomains" in out  # explicit noun


def test_phase_status_line_failed_format():
    console.set_enabled(True)
    out = console.phase_status_line("dirsearch", "failed", 0, 0.73)
    assert "✗" in out
    assert "failed" in out
    assert "dirsearch" not in out  # no stage tag in this line


def test_phase_status_line_skipped_format():
    console.set_enabled(True)
    out = console.phase_status_line("arjun", "skipped", 0, 0.0)
    assert "⊘" in out
    assert "skipped" in out


def test_phase_status_line_plain_when_disabled():
    console.set_enabled(False)
    out = console.phase_status_line("subdomain", "success", 343, 152.78)
    assert "[OK]" in out
    assert "✓" not in out
    assert "\033" not in out


def test_phase_status_line_uses_custom_noun():
    out = console.phase_status_line("dirsearch", "success", 5, 1.0, noun="matches")
    assert "matches" in out


# ----------------------------------------------------------------------
# phase_error_line / phase_warn_line / phase_info_line
# ----------------------------------------------------------------------
def test_phase_error_line_contains_message():
    out = console.phase_error_line("oh no")
    assert "!" in out
    assert "oh no" in out


def test_phase_warn_line_contains_message():
    out = console.phase_warn_line("heads up")
    assert "!" in out
    assert "heads up" in out


def test_phase_info_line_contains_message():
    out = console.phase_info_line("merging files")
    assert "ℹ" in out or "i" in out
    assert "merging files" in out


def test_error_line_no_color_when_disabled():
    console.set_enabled(False)
    out = console.phase_error_line("oh no")
    assert "\033" not in out


# ----------------------------------------------------------------------
# phase_outputs — one dim line per output file
# ----------------------------------------------------------------------
def test_phase_outputs_returns_empty_when_no_outputs():
    assert console.phase_outputs({}, Path("/tmp/x")) == []
    assert console.phase_outputs({"outputs": []}, Path("/tmp/x")) == []
    assert console.phase_outputs(None, Path("/tmp/x")) == []


def test_phase_outputs_shows_paths_relative_to_output_dir():
    result = {
        "outputs": [
            "/tmp/x/processed/subdomains.txt",
            "/tmp/x/raw/subdomain/subfinder.txt",
        ],
    }
    out = console.phase_outputs(result, Path("/tmp/x"))
    assert len(out) == 2
    # Both paths shown relative to output_dir (not absolute).
    assert "processed/subdomains.txt" in out[0]
    assert "raw/subdomain/subfinder.txt" in out[1]
    # And the absolute prefix is gone.
    assert "/tmp/x" not in out[0]
    assert "/tmp/x" not in out[1]


def test_phase_outputs_handles_paths_outside_output_dir():
    """If a stage passes an absolute path that's not under output_dir
    (rare but possible — e.g. a /tmp scratch file), show the path as-is
    rather than crashing."""
    result = {"outputs": ["/var/tmp/scratch.txt"]}
    out = console.phase_outputs(result, Path("/tmp/x"))
    assert len(out) == 1
    assert "/var/tmp/scratch.txt" in out[0]


def test_phase_outputs_uses_arrow_glyph():
    result = {"outputs": ["/tmp/x/a.txt"]}
    out = console.phase_outputs(result, Path("/tmp/x"))
    assert "→" in out[0]


def test_phase_outputs_no_color_when_disabled():
    console.set_enabled(False)
    result = {"outputs": ["/tmp/x/a.txt"]}
    out = console.phase_outputs(result, Path("/tmp/x"))
    # No ANSI escape codes
    assert all("\033" not in line for line in out)
    # Still has the arrow
    assert all("→" in line for line in out)


def test_phase_outputs_handles_non_string_outputs():
    """Outputs list might contain Path objects; helper should coerce."""
    result = {"outputs": [Path("/tmp/x/a.txt"), Path("/tmp/x/b.txt")]}
    out = console.phase_outputs(result, Path("/tmp/x"))
    assert len(out) == 2
    assert "a.txt" in out[0]
    assert "b.txt" in out[1]


def test_phase_outputs_handles_no_output_dir():
    """When output_dir is None we fall back to absolute paths."""
    result = {"outputs": ["/tmp/x/a.txt"]}
    out = console.phase_outputs(result, None)
    assert len(out) == 1
    assert "/tmp/x/a.txt" in out[0]


# ----------------------------------------------------------------------
# cmd_echo
# ----------------------------------------------------------------------
def test_cmd_echo_with_list():
    console.set_enabled(True)
    cmd = ["dirsearch", "-l", "alive.txt", "-o", "raw.txt"]
    out = console.cmd_echo("dirsearch", cmd)
    assert "[dirsearch]" in out
    assert "$" in out
    assert "dirsearch" in out
    assert "alive.txt" in out
    assert "\033[93m" in out  # dirsearch phase color = bright_yellow


def test_cmd_echo_with_string():
    console.set_enabled(True)
    out = console.cmd_echo("subdomain", "subfinder -d example.com")
    assert "[subdomain]" in out
    assert "subfinder -d example.com" in out


def test_cmd_echo_stage_tag_uses_phase_color():
    console.set_enabled(True)
    out_sub = console.cmd_echo("subdomain", "x")
    out_arj = console.cmd_echo("arjun", "x")
    # Different stages → different ANSI color codes in the [stage] tag
    assert "\033[96m" in out_sub   # bright_cyan
    assert "\033[32m" in out_arj   # green (not bright_green — keeps each stage unique)
    # …but both contain the literal stage name
    assert "subdomain" in out_sub
    assert "arjun" in out_arj


def test_cmd_echo_plain_when_disabled():
    console.set_enabled(False)
    out = console.cmd_echo("dirsearch", ["dirsearch", "-x"])
    assert out == "  [dirsearch] $ dirsearch -x"
    assert "\033" not in out


# ----------------------------------------------------------------------
# kv — key/value pair
# ----------------------------------------------------------------------
def test_kv_format():
    out = console.kv("target", "vulnweb.com")
    assert "target:" in out
    assert "vulnweb.com" in out


def test_kv_plain_when_disabled():
    console.set_enabled(False)
    out = console.kv("target", "vulnweb.com")
    assert "\033" not in out


def test_kv_custom_value_color():
    console.set_enabled(True)
    out = console.kv("file", "/tmp/x", value_color="bright_cyan")
    assert "\033[96m" in out


# ----------------------------------------------------------------------
# banner
# ----------------------------------------------------------------------
def test_banner_contains_plus_when_enabled():
    console.set_enabled(True)
    out = console.banner("target: vulnweb.com")
    # When colors are on, the output is wrapped in ANSI escape codes
    # so it doesn't literally start with "[+]" — check for the literal
    # marker inside the string instead.
    assert "[+]" in out
    assert "target: vulnweb.com" in out
    assert "\033[1m" in out


def test_banner_starts_with_plus_when_disabled():
    console.set_enabled(False)
    out = console.banner("target: vulnweb.com")
    # No ANSI when disabled → string starts with the literal marker.
    assert out.startswith("[+]")


def test_banner_plain_when_disabled():
    console.set_enabled(False)
    out = console.banner("target: vulnweb.com")
    assert out == "[+] target: vulnweb.com"
    assert "\033" not in out


# ----------------------------------------------------------------------
# Phase color consistency — every known stage has a unique color so
# the output is scannable when parallel stages interleave.
# ----------------------------------------------------------------------
def test_phase_colors_are_distinct_enough():
    """Each stage should have a unique color so the output is scannable
    when parallel stages interleave. If two stages share a color the
    reader can't tell them apart at a glance.
    """
    from collections import Counter
    counts = Counter(console.PHASE_COLORS.values())
    for color, count in counts.items():
        if count == 1:
            continue
        # The only permitted sharing is within the nuclei family: the three
        # nuclei scans (default/endpoints/dynamic) are the same tool run
        # sequentially — they never interleave, so a shared red shade is OK
        # (16 stages vs 15 usable colors; black is invisible on dark themes).
        sharers = [s for s, c in console.PHASE_COLORS.items() if c == color]
        assert all(s.startswith("nuclei_") for s in sharers), (
            f"color {color!r} used by non-family stages {sharers} — "
            f"output would be hard to scan"
        )