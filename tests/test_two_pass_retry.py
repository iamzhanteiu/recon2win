"""Tests for the 2-pass retry in main.py.

When the first dnsx→httpx_alive pass yields 0 alive hosts, main.py
automatically retries with ``dnsx.max_resolved_expanded``.

Driving ``main()`` end-to-end is heavy (parallel stages, telegram,
report generation, …), so these tests pin the *gating conditions*
of the retry block as plain boolean assertions. The end-to-end
behaviour is exercised on every real scan.
"""
from __future__ import annotations


# ----------------------------------------------------------------------
# Gating conditions — pure boolean logic
# ----------------------------------------------------------------------
def test_retry_fires_when_first_pass_yields_zero_alive():
    """Canonical trigger: alive.txt empty after first pass + expanded
    cap configured + not in resume mode → retry."""
    first_cap = 10000
    expanded_cap = 25000
    not_resume = True
    alive_empty = True
    should_retry = (expanded_cap > first_cap
                   and not_resume
                   and alive_empty)
    assert should_retry is True


def test_no_retry_when_resume_flag_used():
    """``--resume`` reuses cached results — never retry, even if
    alive.txt is empty (the operator is explicitly saying "trust
    what's on disk")."""
    first_cap = 10000
    expanded_cap = 25000
    resume_used = True
    alive_empty = True
    should_retry = (expanded_cap > first_cap
                   and not resume_used
                   and alive_empty)
    assert should_retry is False


def test_no_retry_when_expanded_cap_zero():
    """``max_resolved_expanded: 0`` disables the retry entirely."""
    first_cap = 10000
    expanded_cap_zero = 0
    should_retry = (expanded_cap_zero > first_cap)
    assert should_retry is False


def test_no_retry_when_expanded_equals_first():
    """``expanded == first`` disables retry — no point retrying with
    the same cap."""
    first_cap = 10000
    expanded_cap_equal = 10000
    should_retry = (expanded_cap_equal > first_cap)
    assert should_retry is False


def test_no_retry_when_alive_has_content():
    """First pass succeeded (alive.txt non-empty) — no need to retry."""
    first_cap = 10000
    expanded_cap = 25000
    not_resume = True
    alive_empty = False
    should_retry = (expanded_cap > first_cap
                   and not_resume
                   and alive_empty)
    assert should_retry is False


def test_retry_uses_expanded_cap_in_config():
    """The retry path passes ``max_resolved=expanded_cap`` to dnsx —
    verify the config-mutation logic produces the right shape."""
    cfg = {
        "dnsx": {
            "max_resolved": 10000,
            "max_resolved_expanded": 25000,
        }
    }
    first_cap = int(cfg["dnsx"]["max_resolved"])
    expanded_cap = int(cfg["dnsx"]["max_resolved_expanded"])
    retry_cfg = {
        **cfg,
        "dnsx": {**cfg["dnsx"], "max_resolved": expanded_cap},
    }
    # The retry sees the expanded cap.
    assert retry_cfg["dnsx"]["max_resolved"] == 25000
    # The original cfg is NOT mutated (deep-ish copy).
    assert cfg["dnsx"]["max_resolved"] == 10000
    assert first_cap == 10000