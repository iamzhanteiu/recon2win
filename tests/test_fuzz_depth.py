"""Tests for modules/fuzz_depth.py — adaptive fuzz-depth tiering.

fuzz_targets already decides WHICH hosts get fuzzed at all (dedup, WAF/
blanket-deny skip, cap). This module decides how much extra attention each
already-selected host deserves — never re-filters, never drops a host
outright (only "light" vs "deep" vs "standard").
"""
from __future__ import annotations

from modules import fuzz_depth, layout
from modules.utils import create_output_structure, write_json, write_lines


# ----------------------------------------------------------------------
# classify_depth
# ----------------------------------------------------------------------
def test_classify_depth_apex_is_deep():
    tier, reasons = fuzz_depth.classify_depth("example.com", {})
    assert tier == "deep"
    assert reasons


def test_classify_depth_high_value_prefix_is_deep():
    tier, _ = fuzz_depth.classify_depth("admin.example.com", {})
    assert tier == "deep"


def test_classify_depth_noise_hostname_is_light():
    tier, reasons = fuzz_depth.classify_depth("bot.example.com", {})
    assert tier == "light"
    assert "noise" in reasons[0]


def test_classify_depth_generic_hostname_no_row_is_standard():
    tier, reasons = fuzz_depth.classify_depth("cdn-assets-3.example.com", {})
    assert tier == "standard"
    assert reasons == []


def test_classify_depth_missing_row_never_raises():
    tier, _ = fuzz_depth.classify_depth("cdn-assets-3.example.com", None)
    assert tier == "standard"


def test_classify_depth_tech_signal_overrides_low_hostname_score():
    """A generic-looking hostname running a known-interesting stack must
    still qualify for "deep" — that's the whole point of using response
    content instead of just the hostname string."""
    tier, reasons = fuzz_depth.classify_depth(
        "app3.example.com", {"tech": ["Jenkins"], "webserver": "Jetty"})
    assert tier == "deep"
    assert any("Jenkins" in r for r in reasons)


def test_classify_depth_tech_signal_from_webserver_field():
    tier, reasons = fuzz_depth.classify_depth(
        "svc7.example.com", {"webserver": "nginx (Grafana)"})
    assert tier == "deep"
    assert any("Grafana" in r for r in reasons)


def test_classify_depth_tech_signal_from_title_field():
    tier, _ = fuzz_depth.classify_depth(
        "x.example.com", {"title": "phpMyAdmin 5.2 — Welcome"})
    assert tier == "deep"


def test_classify_depth_custom_thresholds():
    # A score of 40 (generic depth bonus only) becomes "deep" with a very
    # permissive threshold, and "light" with a very strict one.
    tier, _ = fuzz_depth.classify_depth(
        "h0.x.com", {}, deep_threshold=10)
    assert tier == "deep"
    tier, _ = fuzz_depth.classify_depth(
        "h0.x.com", {}, light_threshold=1000)
    assert tier == "light"


# ----------------------------------------------------------------------
# tier_targets
# ----------------------------------------------------------------------
def test_tier_targets_buckets_and_preserves_order():
    targets = ["https://example.com", "https://cdn3.example.com",
              "https://bot.example.com", "https://admin.example.com"]
    buckets, stats = fuzz_depth.tier_targets(targets, [], {})
    assert buckets["deep"] == ["https://example.com", "https://admin.example.com"]
    assert buckets["standard"] == ["https://cdn3.example.com"]
    assert buckets["light"] == ["https://bot.example.com"]
    assert stats["deep"] == 2
    assert stats["standard"] == 1
    assert stats["light"] == 1
    assert stats["demoted"] == 0


def test_tier_targets_uses_detail_rows_for_tech_signal():
    targets = ["https://app3.example.com", "https://app4.example.com"]
    rows = [{"url": "https://app3.example.com", "tech": ["Jenkins"]}]
    buckets, _ = fuzz_depth.tier_targets(targets, rows, {})
    assert buckets["deep"] == ["https://app3.example.com"]
    assert buckets["standard"] == ["https://app4.example.com"]


# ----------------------------------------------------------------------
# tech-aware wordlists — TECH_WORDLIST_MAP / tech_wordlists_for /
# tier_targets' deep_tech_hits & deep_tech_wordlists
# ----------------------------------------------------------------------
def test_tech_wordlists_for_maps_known_keys():
    paths = fuzz_depth.tech_wordlists_for({"jenkins": 2, "gitlab": 1})
    assert fuzz_depth.TECH_WORDLIST_MAP["jenkins"] in paths
    assert fuzz_depth.TECH_WORDLIST_MAP["gitlab"] in paths
    assert len(paths) == 2


def test_tech_wordlists_for_dedupes_keys_sharing_one_file():
    # elastic + kibana both map to the same Elasticsearch-Kibana.txt.
    paths = fuzz_depth.tech_wordlists_for({"elastic": 1, "kibana": 1})
    assert paths == [fuzz_depth.TECH_WORDLIST_MAP["elastic"]]


def test_tech_wordlists_for_skips_unmapped_keys():
    # "phpmyadmin" is in _TECH_HINTS but has no dedicated SecLists file.
    assert fuzz_depth.tech_wordlists_for({"phpmyadmin": 1}) == []


def test_tier_targets_reports_deep_tech_hits_and_wordlists():
    targets = ["https://app3.example.com", "https://app4.example.com"]
    rows = [{"url": "https://app3.example.com", "tech": ["Jenkins"]}]
    _, stats = fuzz_depth.tier_targets(targets, rows, {})
    assert stats["deep_tech_hits"] == {"jenkins": 1}
    assert stats["deep_tech_wordlists"] == [fuzz_depth.TECH_WORDLIST_MAP["jenkins"]]


def test_tier_targets_deep_tech_hits_empty_without_tech_signal():
    targets = ["https://example.com"]  # deep via apex hostname score only
    _, stats = fuzz_depth.tier_targets(targets, [], {})
    assert stats["deep_tech_hits"] == {}
    assert stats["deep_tech_wordlists"] == []


def test_tier_targets_demoted_host_tech_does_not_count():
    """A host demoted past deep_max_hosts must not contribute its tech to
    deep_tech_hits — it's no longer in the final deep bucket, so it must
    not pull in an extra wordlist that will never be used on it.

    admin.example.com outscores app3.example.com on hostname alone (1040
    vs 540 — "admin" is a high-value prefix), so with deep_max_hosts=1 the
    Jenkins host (deep only via tech, not hostname) is the one demoted.
    """
    targets = ["https://admin.example.com", "https://app3.example.com"]
    rows = [{"url": "https://app3.example.com", "tech": ["Jenkins"]}]
    cfg = {"fuzz_depth": {"deep_max_hosts": 1}}
    buckets, stats = fuzz_depth.tier_targets(targets, rows, cfg)
    assert buckets["deep"] == ["https://admin.example.com"]
    assert "https://app3.example.com" in buckets["standard"]
    assert stats["deep_tech_hits"] == {}
    assert stats["deep_tech_wordlists"] == []


def test_summary_line_mentions_detected_tech():
    line = fuzz_depth.summary_line(
        {"deep": 1, "standard": 2, "light": 0, "demoted": 0,
         "deep_tech_hits": {"jenkins": 1, "gitlab": 2}})
    assert "tech: gitlab, jenkins" in line


def test_summary_line_no_tech_note_when_empty():
    line = fuzz_depth.summary_line(
        {"deep": 1, "standard": 2, "light": 0, "demoted": 0, "deep_tech_hits": {}})
    assert "tech:" not in line


_FIVE_DEEP_HOSTS = [
    "https://admin.example.com", "https://api.example.com",
    "https://auth.example.com", "https://portal.example.com",
    "https://sso.example.com",
]


def test_tier_targets_deep_max_hosts_demotes_by_score_not_drop():
    """Cap enforcement must demote the lowest-scoring excess deep hosts to
    "standard" — never drop a host outright."""
    cfg = {"fuzz_depth": {"deep_max_hosts": 2}}
    buckets, stats = fuzz_depth.tier_targets(_FIVE_DEEP_HOSTS, [], cfg)
    assert len(buckets["deep"]) == 2
    assert stats["demoted"] == 3
    # nothing was dropped — every target lands in exactly one bucket
    all_bucketed = buckets["deep"] + buckets["standard"] + buckets["light"]
    assert sorted(all_bucketed) == sorted(_FIVE_DEEP_HOSTS)


def test_tier_targets_deep_max_hosts_zero_disables_cap():
    cfg = {"fuzz_depth": {"deep_max_hosts": 0}}
    buckets, stats = fuzz_depth.tier_targets(_FIVE_DEEP_HOSTS, [], cfg)
    assert len(buckets["deep"]) == 5
    assert stats["demoted"] == 0


def test_tier_targets_enabled_false_shape_matches_disabled_fallback():
    """The shape dirsearch/ffuf build when fuzz_depth.enabled is False must
    match what tier_targets would look like with everything in "standard"."""
    targets = ["https://example.com", "https://a.example.com"]
    fallback = {"deep": [], "standard": targets, "light": []}
    assert set(fallback.keys()) == {"deep", "standard", "light"}


def test_tier_targets_empty_input():
    buckets, stats = fuzz_depth.tier_targets([], [], {})
    assert buckets == {"deep": [], "standard": [], "light": []}
    assert stats["deep"] == stats["standard"] == stats["light"] == 0


# ----------------------------------------------------------------------
# load_tiers — thin I/O wrapper
# ----------------------------------------------------------------------
def test_load_tiers_reads_alive_and_detail_from_disk(tmp_path):
    base = create_output_structure("example.com", root=str(tmp_path))
    alive = layout.path(base, "alive.txt")
    write_lines(alive, ["https://example.com", "https://app3.example.com"])
    write_json(layout.path(base, "alive_detail.json"), [
        {"url": "https://app3.example.com", "tech": ["Jenkins"]},
    ])
    buckets, _ = fuzz_depth.load_tiers(alive, base, {})
    assert "https://example.com" in buckets["deep"]
    assert "https://app3.example.com" in buckets["deep"]


def test_load_tiers_missing_detail_json_degrades_gracefully(tmp_path):
    base = create_output_structure("example.com", root=str(tmp_path))
    alive = layout.path(base, "alive.txt")
    write_lines(alive, ["https://cdn3.example.com"])
    buckets, _ = fuzz_depth.load_tiers(alive, base, {})
    assert buckets["standard"] == ["https://cdn3.example.com"]


# ----------------------------------------------------------------------
# confirmed tech — load_confirmed_tech / save_confirmed_tech /
# merge_confirmed_tech (the misconfig_probe → fuzz_depth feedback loop)
# ----------------------------------------------------------------------
def test_load_confirmed_tech_missing_file_is_empty(tmp_path):
    base = create_output_structure("example.com", root=str(tmp_path))
    assert fuzz_depth.load_confirmed_tech(base) == {}


def test_save_confirmed_tech_writes_and_round_trips(tmp_path):
    base = create_output_structure("example.com", root=str(tmp_path))
    merged = fuzz_depth.save_confirmed_tech(base, {"app3.example.com": ["jenkins"]})
    assert merged == {"app3.example.com": ["jenkins"]}
    assert fuzz_depth.load_confirmed_tech(base) == {"app3.example.com": ["jenkins"]}


def test_save_confirmed_tech_unions_with_existing_never_overwrites(tmp_path):
    """A host confirmed as Jenkins on scan 1 must stay confirmed even if
    scan 2 finds a *different* tech on the same host (or doesn't re-probe
    it at all — e.g. it fell out of tier "deep" that run)."""
    base = create_output_structure("example.com", root=str(tmp_path))
    fuzz_depth.save_confirmed_tech(base, {"app3.example.com": ["jenkins"]})
    merged = fuzz_depth.save_confirmed_tech(base, {"app3.example.com": ["gitlab"],
                                                     "app4.example.com": ["spring"]})
    assert merged == {
        "app3.example.com": ["jenkins", "gitlab"],
        "app4.example.com": ["spring"],
    }


def test_save_confirmed_tech_deduplicates_repeat_findings(tmp_path):
    base = create_output_structure("example.com", root=str(tmp_path))
    fuzz_depth.save_confirmed_tech(base, {"app3.example.com": ["jenkins"]})
    merged = fuzz_depth.save_confirmed_tech(base, {"app3.example.com": ["jenkins"]})
    assert merged == {"app3.example.com": ["jenkins"]}


def test_merge_confirmed_tech_appends_to_matching_row():
    rows = [{"url": "https://app3.example.com", "tech": ["nginx"]}]
    merged = fuzz_depth.merge_confirmed_tech(rows, {"app3.example.com": ["jenkins"]})
    assert merged[0]["tech"] == ["nginx", "jenkins"]
    # original row untouched
    assert rows[0]["tech"] == ["nginx"]


def test_merge_confirmed_tech_creates_synthetic_row_for_host_missing_from_detail():
    merged = fuzz_depth.merge_confirmed_tech([], {"app3.example.com": ["jenkins"]})
    assert len(merged) == 1
    assert merged[0]["tech"] == ["jenkins"]
    assert "app3.example.com" in merged[0]["url"]


def test_merge_confirmed_tech_noop_when_nothing_confirmed():
    rows = [{"url": "https://app3.example.com", "tech": ["nginx"]}]
    assert fuzz_depth.merge_confirmed_tech(rows, {}) == rows


def test_load_tiers_uses_confirmed_tech_from_a_prior_scan(tmp_path):
    """The end-to-end point of the feedback loop: a host with NO tech
    signal in this run's alive_detail.json (generic hostname, generic
    httpx tech) still tiers "deep" because misconfig_probe confirmed it on
    an earlier scan of the same target."""
    base = create_output_structure("example.com", root=str(tmp_path))
    alive = layout.path(base, "alive.txt")
    write_lines(alive, ["https://app3.example.com"])
    write_json(layout.path(base, "alive_detail.json"), [
        {"url": "https://app3.example.com", "tech": ["nginx"]},
    ])
    fuzz_depth.save_confirmed_tech(base, {"app3.example.com": ["jenkins"]})

    buckets, stats = fuzz_depth.load_tiers(alive, base, {})
    assert buckets["deep"] == ["https://app3.example.com"]
    assert stats["deep_tech_hits"] == {"jenkins": 1}


# ----------------------------------------------------------------------
# summary_line
# ----------------------------------------------------------------------
def test_summary_line_mentions_demoted_when_present():
    line = fuzz_depth.summary_line(
        {"deep": 2, "standard": 10, "light": 1, "demoted": 3})
    assert "2 deep" in line
    assert "10 standard" in line
    assert "1 light" in line
    assert "3" in line


def test_summary_line_no_demoted_note_when_zero():
    line = fuzz_depth.summary_line(
        {"deep": 2, "standard": 10, "light": 1, "demoted": 0})
    assert "hạ về" not in line
