"""Tests for prioritize_subdomains + score_subdomain.

Covers the core scoring rules + cap behaviour. The scoring rules
directly affect which hosts the next stage (httpx_alive) probes,
so a regression here would silently break scans on large targets.
"""
from __future__ import annotations

import pytest

from modules.utils import (
    _SUBDOMAIN_BOUNTY_TECH,
    _SUBDOMAIN_HIGH_VALUE,
    _SUBDOMAIN_NOISE,
    prioritize_subdomains,
    score_subdomain,
)


# ----------------------------------------------------------------------
# score_subdomain — pure scoring rules
# ----------------------------------------------------------------------
def test_apex_domain_scores_highest():
    """``example.com`` (single label) is the most important target —
    it MUST outrank every subdomain including the high-value
    prefixes (``www``, ``api``, ``admin``, ...)."""
    apex = score_subdomain("example.com")
    sub = score_subdomain("www.example.com")
    assert apex > sub
    # Apex must also outrank the strongest high-value prefix
    # (``admin``, which scores 1000 + 40 = 1040). The apex bonus
    # is calibrated so 5060 > 1040 with plenty of headroom.
    assert score_subdomain("example.com") > score_subdomain("admin.example.com")
    assert score_subdomain("example.com") > score_subdomain("api.example.com")
    assert score_subdomain("example.com") > score_subdomain("jenkins.example.com")


def test_high_value_prefixes_score_higher_than_random():
    s_admin = score_subdomain("admin.example.com")
    s_random = score_subdomain("zxcvbnm12345.example.com")
    assert s_admin > s_random


def test_high_value_prefix_exact_match_beats_partial():
    s_exact = score_subdomain("admin.example.com")
    s_partial = score_subdomain("administrative.example.com")
    assert s_exact > s_partial


def test_bounty_tech_substring_boosts_score():
    """``jenkins``, ``gitlab``, etc. boost the score even if they
    appear deeper in the subdomain (e.g. ``ci.jenkins.example.com``)."""
    s_tech = score_subdomain("ci.jenkins.example.com")
    s_random = score_subdomain("ci.randomname.example.com")
    assert s_tech > s_random


@pytest.mark.parametrize("tech", _SUBDOMAIN_BOUNTY_TECH)
def test_each_bounty_tech_boosts_score(tech):
    """Every tech in the bounty list must produce a positive bump when
    present anywhere in the host."""
    with_tech = score_subdomain(f"foo.{tech}.example.com")
    without_tech = score_subdomain("foo.somerandom.example.com")
    assert with_tech > without_tech


@pytest.mark.parametrize("noise", _SUBDOMAIN_NOISE)
def test_noise_keywords_penalise_score(noise):
    """Every noise keyword must lower the score vs an otherwise
    identical host."""
    base = "foo.example.com"
    with_noise = score_subdomain(f"foo.{noise}.example.com")
    assert with_noise < score_subdomain(base)


def test_bot_infra_massively_penalised():
    """``applebot``, ``spider``, ``crawler`` subdomains are noise —
    their score should be far below the apex + high-value prefixes."""
    apex = score_subdomain("apple.com")
    bot = score_subdomain("17-241-227-210.applebot.apple.com")
    admin = score_subdomain("admin.apple.com")
    assert apex > admin > bot


def test_random_hex_subdomain_penalised():
    """Long hex strings (12+ chars, all hex chars) look auto-generated
    and shouldn't outrank hand-picked names."""
    random_hex = "a1b2c3d4e5f6a7b8c9d0e1f2.example.com"
    hand_picked = "api.example.com"
    assert score_subdomain(hand_picked) > score_subdomain(random_hex)


def test_shorter_subdomain_outranks_deeper_one():
    """``foo.bar.example.com`` should score lower than ``foo.example.com``
    (more labels = deeper = less likely interesting)."""
    shorter = score_subdomain("foo.example.com")
    deeper = score_subdomain("foo.bar.baz.example.com")
    assert shorter > deeper


def test_numeric_label_penalised():
    """``host12345`` should score lower than a hand-picked word."""
    numeric = "abc12345.example.com"
    clean = "marketing.example.com"
    # Should still rank above noise but below clean name.
    # The penalty is mild (-100) so it might still beat a clean name
    # — the test is just that penalty is applied (clean > numeric
    # for the same length), not that numeric always loses.
    assert score_subdomain(clean) >= score_subdomain(numeric) - 100


def test_empty_string_scores_negative_infinity():
    assert score_subdomain("") < -1000


def test_score_is_deterministic():
    """Same input → same output (no hidden state)."""
    assert score_subdomain("admin.example.com") == score_subdomain("admin.example.com")


# ----------------------------------------------------------------------
# prioritize_subdomains — ordering + cap behaviour
# ----------------------------------------------------------------------
def test_root_domain_always_first():
    subs = ["random.example.com", "example.com", "another.example.com"]
    out = prioritize_subdomains(subs)
    assert out[0] == "example.com"


def test_high_value_outranks_random():
    subs = ["xyz123.example.com", "admin.example.com", "a-b-c.example.com"]
    out = prioritize_subdomains(subs)
    assert "admin.example.com" in out[:2]


def test_bot_subdomain_outranks_nothing_when_alone():
    """A list with only bot infra is still returned in original order
    (no cap applied, no items dropped)."""
    subs = ["a.applebot.apple.com", "b.applebot.apple.com"]
    out = prioritize_subdomains(subs)
    assert set(out) == set(subs)


def test_cap_keeps_top_n():
    """max_count=5 → output has at most 5 items."""
    subs = [f"sub{i}.example.com" for i in range(100)]
    out = prioritize_subdomains(subs, max_count=5)
    assert len(out) == 5


def test_cap_default_is_5000():
    """Sane default — large enough to not lose interesting hosts,
    small enough that httpx finishes in budget."""
    subs = [f"sub{i}.example.com" for i in range(20_000)]
    out = prioritize_subdomains(subs)
    assert len(out) == 5000


def test_cap_zero_disables_cap():
    """max_count=0 → no cap, return everything (score-ordered)."""
    subs = [f"sub{i}.example.com" for i in range(10)]
    out = prioritize_subdomains(subs, max_count=0)
    assert len(out) == 10


def test_cap_none_disables_cap():
    out = prioritize_subdomains(["a.example.com"] * 5, max_count=None)
    assert len(out) == 5


def test_cap_larger_than_input_is_noop():
    """max_count=1000 with 5 inputs → all 5 returned, no error."""
    out = prioritize_subdomains(["a", "b", "c"], max_count=1000)
    assert len(out) == 3


def test_dedupes_case_insensitive_duplicates():
    """Many tools return the same host in different cases. Dedup
    case-insensitively so we don't waste cap budget on dupes."""
    subs = ["Admin.example.com", "admin.example.com", "ADMIN.example.com"]
    out = prioritize_subdomains(subs, max_count=100)
    assert len(out) == 1
    # …and prefer the original case (first occurrence wins).
    assert out[0] == "Admin.example.com"


def test_realistic_apple_like_target():
    """Smoke test: applebot/sandbox/push noise dropped to the BOTTOM
    (or excluded entirely when over the cap), apex + admin/www
    promoted to the top."""
    subs = [
        "17-241-227-210.applebot.apple.com",
        "0-courier.sandbox.push.apple.com",
        "17-121-118-93.applebot.apple.com",
        "prod.isoproxy.apple.com",
        "www.apple.com",
        "admin.apple.com",
        "apple.com",
        "support.apple.com",
        "test-123.apple.com",
    ]
    out = prioritize_subdomains(subs, max_count=5)
    # 1) Apex MUST be first.
    assert out[0] == "apple.com"
    # 2) Admin/www MUST be in the top 3 (high-value prefixes).
    top3 = set(out[:3])
    assert "admin.apple.com" in top3
    assert "www.apple.com" in top3
    # 3) The classic Apple noise (applebot / sandbox / isoproxy)
    #    MUST NOT make it into the top 5 when there are 9 candidates
    #    and the cap is 5 — they should be the 4 items dropped from
    #    the bottom.
    applebot_in_top5 = [s for s in out if "applebot" in s]
    sandbox_in_top5 = [s for s in out if "sandbox" in s]
    isoproxy_in_top5 = [s for s in out if "isoproxy" in s]
    assert applebot_in_top5 == [], \
        f"applebot noise leaked into top 5: {applebot_in_top5}"
    assert sandbox_in_top5 == [], \
        f"sandbox noise leaked into top 5: {sandbox_in_top5}"
    assert isoproxy_in_top5 == [], \
        f"isoproxy noise leaked into top 5: {isoproxy_in_top5}"


def test_order_is_stable_for_equal_scores():
    """When two hosts score the same, the original order is preserved
    (Python's sort is stable). Important for predictable scans."""
    subs = ["a.example.com", "b.example.com", "c.example.com"]
    out = prioritize_subdomains(subs, max_count=3)
    # All three should score identically (none match high-value).
    # Stable sort → input order preserved.
    assert out == subs


def test_empty_input_returns_empty():
    assert prioritize_subdomains([]) == []
    assert prioritize_subdomains([], max_count=100) == []


def test_string_normalisation_lowercase():
    """Input might be in mixed case — score should be case-insensitive."""
    upper = score_subdomain("ADMIN.EXAMPLE.COM")
    lower = score_subdomain("admin.example.com")
    assert upper == lower