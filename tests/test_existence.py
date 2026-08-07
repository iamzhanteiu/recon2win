"""Tests for modules/existence.py — behavioural endpoint-existence classifier.

Ground truth for each case comes from the spec this module implements: don't
conclude from HTTP status alone, treat validation/parsing/auth/business-logic/
framework-specific body text and baseline-shape agreement as the real
evidence.
"""
from __future__ import annotations

from modules import existence


# ----------------------------------------------------------------------
# match_signals — pure regex taxonomy
# ----------------------------------------------------------------------
def test_match_signals_empty_snippet_yields_no_categories():
    assert existence.match_signals("") == {}
    assert existence.match_signals(None) == {}


def test_match_signals_validation_category():
    sig = existence.match_signals("Error: Missing required parameter 'id'")
    assert "validation" in sig
    assert "missing required parameter" in sig["validation"]


def test_match_signals_parsing_category():
    sig = existence.match_signals('{"error": "Malformed JSON in request body"}')
    assert "parsing" in sig


def test_match_signals_auth_category():
    sig = existence.match_signals("401 Unauthorized: Invalid JWT token")
    assert "auth" in sig


def test_match_signals_business_logic_category():
    sig = existence.match_signals('{"error": "User not found"}')
    assert "business_logic" in sig


def test_match_signals_framework_category_spring_boot():
    sig = existence.match_signals(
        '{"timestamp":"...","status":400,"error":"Bad Request",'
        '"trace":"org.springframework.web.bind.MissingServletRequestParam..."}')
    assert "framework" in sig


def test_match_signals_multiple_categories_at_once():
    sig = existence.match_signals(
        "Validation failed: Missing required parameter. Also Malformed JSON.")
    assert "validation" in sig
    assert "parsing" in sig


def test_match_signals_ordinary_text_matches_nothing():
    sig = existence.match_signals("Welcome to our homepage! Check out our products.")
    assert sig == {}


# ----------------------------------------------------------------------
# classify — definite-exists statuses (2xx/3xx): CONFIRMED requires baseline
# to actually prove it, not just be absent — see the "exists" branch's
# comment in modules/existence.py for the real acronis.com false-positive
# (a client-side-router catch-all echoing into the URL fragment) this guards
# against: an unmeasured host looks exactly like a real one from status alone.
# ----------------------------------------------------------------------
def test_classify_200_with_no_baseline_is_likely_not_confirmed():
    r = existence.classify(200, "")
    assert r.verdict == existence.LIKELY
    assert r.status_signal == "exists"


def test_classify_redirect_with_no_baseline_is_likely_not_confirmed():
    r = existence.classify(302, "")
    assert r.verdict == existence.LIKELY


def test_classify_200_matching_blanket_baseline_is_likely():
    # SPA fallback / catch-all: every path, real or fake, answers 200 with
    # the identical shape — a 200 alone no longer proves this ONE path exists.
    r = existence.classify(200, "", baseline_is_noise=True)
    assert r.verdict == existence.LIKELY


def test_classify_200_baseline_confirms_it_differs_is_confirmed():
    # The ONLY way a bare 2xx/3xx reaches CONFIRMED: baseline was actually
    # measured and this hit's shape does NOT match the not-found shape.
    r = existence.classify(200, "", baseline_is_noise=False)
    assert r.verdict == existence.CONFIRMED


# ----------------------------------------------------------------------
# classify — ambiguous statuses, body-signal driven
# ----------------------------------------------------------------------
def test_classify_400_with_validation_text_is_likely():
    r = existence.classify(400, "Missing required parameter: id")
    assert r.verdict == existence.LIKELY
    assert "validation" in r.signals


def test_classify_400_with_two_signal_categories_is_confirmed():
    r = existence.classify(400, "Missing required parameter. Also Malformed JSON.")
    assert r.verdict == existence.CONFIRMED


def test_classify_403_alone_no_baseline_is_likely():
    r = existence.classify(403, "")
    assert r.verdict == existence.LIKELY
    assert r.status_signal == "strong"


def test_classify_403_plus_body_signal_is_confirmed():
    r = existence.classify(403, "Missing Authorization header")
    assert r.verdict == existence.CONFIRMED


def test_classify_405_alone_is_likely():
    r = existence.classify(405, "")
    assert r.verdict == existence.LIKELY


def test_classify_429_alone_no_baseline_is_unknown():
    # Ambiguous on its own — could hit any path, including nonexistent ones.
    r = existence.classify(429, "")
    assert r.verdict == existence.UNKNOWN


def test_classify_500_alone_no_baseline_is_unknown():
    r = existence.classify(500, "")
    assert r.verdict == existence.UNKNOWN


def test_classify_business_logic_404_is_likely_not_dismissed():
    # A 404 naming a RESOURCE ("user not found") means routing + business
    # logic both ran — very different from a blank webserver 404 page.
    r = existence.classify(404, '{"error": "user not found"}')
    assert r.verdict == existence.LIKELY
    assert "business_logic" in r.signals


def test_classify_plain_404_no_evidence_is_unknown():
    r = existence.classify(404, "")
    assert r.verdict == existence.UNKNOWN


# ----------------------------------------------------------------------
# classify — baseline shape comparison
# ----------------------------------------------------------------------
def test_classify_baseline_noise_no_signals_is_not_found():
    r = existence.classify(403, "", baseline_is_noise=True)
    assert r.verdict == existence.NOT_FOUND


def test_classify_baseline_noise_status_alone_is_not_enough_to_upgrade():
    # status is already baked into what made baseline_is_noise True in the
    # first place — not independent evidence on its own.
    r = existence.classify(405, "", baseline_is_noise=True)
    assert r.verdict == existence.NOT_FOUND


def test_classify_baseline_noise_with_body_signal_upgrades_to_likely_not_confirmed():
    # Body text differs from the not-found baseline — worth a second look —
    # but the identical response SHAPE caps it below confirmed.
    r = existence.classify(403, "Missing Authorization header", baseline_is_noise=True)
    assert r.verdict == existence.LIKELY


def test_classify_baseline_differs_with_no_other_signal_is_likely():
    r = existence.classify(404, "", baseline_is_noise=False)
    assert r.verdict == existence.LIKELY


def test_classify_no_baseline_available_falls_back_to_body_and_status():
    r = existence.classify(404, "", baseline_is_noise=None)
    assert r.verdict == existence.UNKNOWN


# ----------------------------------------------------------------------
# Existence.reasons — human-readable evidence lines
# ----------------------------------------------------------------------
def test_reasons_include_matched_phrase_and_status_and_baseline():
    r = existence.classify(403, "Missing Authorization header", baseline_is_noise=False)
    reasons = r.reasons
    assert any("auth" in line for line in reasons)
    assert any("401/403/405/406/415/422" in line for line in reasons)
    assert any("differs from this host's not-found baseline" in line for line in reasons)


def test_reasons_empty_when_nothing_fired():
    r = existence.classify(404, "")
    assert r.reasons == []


# ----------------------------------------------------------------------
# summary_counts
# ----------------------------------------------------------------------
def test_summary_counts_has_all_four_keys_even_at_zero():
    counts = existence.summary_counts([])
    assert counts == {"confirmed": 0, "likely": 0, "unknown": 0, "not_found": 0}


def test_summary_counts_tallies_verdicts():
    results = [
        existence.classify(200, "", baseline_is_noise=False),
        existence.classify(200, "", baseline_is_noise=False),
        existence.classify(403, "", baseline_is_noise=True),
        existence.classify(404, ""),
    ]
    counts = existence.summary_counts(results)
    assert counts["confirmed"] == 2
    assert counts["not_found"] == 1
    assert counts["unknown"] == 1
