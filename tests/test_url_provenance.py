"""Tests for URL provenance — processed/all_urls.jsonl.

The merge used to flatten every producer into one anonymous list, which is
what let ``arjun.max_urls=200`` draw its whole sample from a wildcard-403
ffuf blow-up on a real discover.com run. These tests pin the two properties
that fix depends on:

  * every URL in all_urls.txt has a matching JSONL record, in the same
    order, naming the tool(s) that produced it;
  * a capped consumer sorting by ``source_score`` gets the trustworthy
    sources first.
"""
from __future__ import annotations

from modules import layout, url_merge
from modules.utils import read_jsonl, read_lines, write_lines


def _seed(tmp_path, **by_tool):
    """Write ``processed/<name>.txt`` files and return the output dir.

    Keyword names are the producer stems (``crawler_urls=[...]``); the
    ``.txt`` matters, since the filename is what carries the provenance.
    """
    for name, urls in by_tool.items():
        write_lines(layout.path(tmp_path, f"{name}.txt"), urls)
    return tmp_path


# ----------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------
def test_source_label_maps_producer_filenames():
    assert url_merge.source_label("processed/ffuf_urls.txt") == "ffuf"
    assert url_merge.source_label("processed/jsluice_endpoints.txt") == "jsluice"
    assert url_merge.source_label("processed/nope.txt") == "unknown"


def test_source_score_takes_the_best_source():
    # A URL both jsluice and ffuf found is a real endpoint ffuf stumbled
    # onto — it must not be dragged down to ffuf's rank.
    assert url_merge.source_score(["ffuf", "jsluice"]) == \
        url_merge.source_score(["jsluice"])


def test_source_score_ranks_js_mining_above_brute_force():
    assert url_merge.source_score(["jsluice"]) > url_merge.source_score(["ffuf"])
    assert url_merge.source_score(["apidocs"]) > url_merge.source_score(["dirsearch"])


def test_unknown_source_outranks_known_noise():
    # An unprovenanced URL (older run, hand-added list) is an unknown, not
    # a known-bad — it must not sort below ffuf.
    assert url_merge.source_score([]) > url_merge.source_score(["ffuf"])


# ----------------------------------------------------------------------
# merge() writes provenance
# ----------------------------------------------------------------------
def test_merge_writes_jsonl_parallel_to_txt(tmp_path):
    out = _seed(
        tmp_path,
        crawler_urls=["https://a.x.com/one"],
        ffuf_urls=["https://a.x.com/two"],
    )
    url_merge.merge(out, "x.com", {})

    urls = read_lines(layout.path(out, "all_urls.txt"))
    rows = read_jsonl(layout.path(out, "all_urls.jsonl"))
    assert [r["url"] for r in rows] == urls


def test_merge_records_the_producing_tool(tmp_path):
    out = _seed(
        tmp_path,
        crawler_urls=["https://a.x.com/one"],
        ffuf_urls=["https://a.x.com/two"],
    )
    url_merge.merge(out, "x.com", {})

    src = url_merge.load_url_sources(out)
    assert src["https://a.x.com/one"] == ["crawler"]
    assert src["https://a.x.com/two"] == ["ffuf"]


def test_merge_unions_sources_for_a_shared_url(tmp_path):
    # Same URL from two tools, differing only by the trailing slash that
    # normalisation strips — one record, both sources.
    out = _seed(
        tmp_path,
        crawler_urls=["https://a.x.com/dup/"],
        ffuf_urls=["https://a.x.com/dup"],
    )
    url_merge.merge(out, "x.com", {})

    assert url_merge.load_url_sources(out)["https://a.x.com/dup"] == \
        ["crawler", "ffuf"]


def test_merge_reports_source_counts(tmp_path):
    out = _seed(
        tmp_path,
        crawler_urls=["https://a.x.com/one"],
        ffuf_urls=[f"https://a.x.com/f{i}" for i in range(5)],
    )
    r = url_merge.merge(out, "x.com", {})
    assert r["extra"]["sources"] == {"ffuf": 5, "crawler": 1}


# ----------------------------------------------------------------------
# append_urls() must not lose stage-5 provenance
# ----------------------------------------------------------------------
def test_append_keeps_earlier_sources_and_adds_new_ones(tmp_path):
    out = _seed(
        tmp_path,
        crawler_urls=["https://a.x.com/one"],
        jsluice_urls=["https://a.x.com/mined"],
    )
    url_merge.merge(out, "x.com", {})
    url_merge.append_urls(out, [layout.path(out, "jsluice_urls.txt")], "x.com", {})

    src = url_merge.load_url_sources(out)
    # ffuf/crawler are NOT in extra_files — rebuilding from scratch here
    # would silently drop them.
    assert src["https://a.x.com/one"] == ["crawler"]
    assert src["https://a.x.com/mined"] == ["jsluice"]


def test_append_still_lines_up_with_the_txt(tmp_path):
    out = _seed(
        tmp_path,
        crawler_urls=["https://a.x.com/one"],
        xnlinkfinder_urls=["https://a.x.com/found"],
    )
    url_merge.merge(out, "x.com", {})
    url_merge.append_urls(
        out, [layout.path(out, "xnlinkfinder_urls.txt")], "x.com", {},
    )

    urls = read_lines(layout.path(out, "all_urls.txt"))
    rows = read_jsonl(layout.path(out, "all_urls.jsonl"))
    assert [r["url"] for r in rows] == urls


# ----------------------------------------------------------------------
# The point of all this: sorting before a cap
# ----------------------------------------------------------------------
def test_rank_puts_trustworthy_sources_first():
    sources = {
        "https://x.com/noise": ["ffuf"],
        "https://x.com/real": ["jsluice"],
        "https://x.com/spec": ["apidocs"],
    }
    ranked = url_merge.rank_urls_by_source(sources.keys(), sources)
    assert ranked[0] == "https://x.com/spec"
    assert ranked[-1] == "https://x.com/noise"


def test_rank_is_stable_within_a_tier():
    sources = {f"https://x.com/{i}": ["ffuf"] for i in range(5)}
    order = list(sources)
    assert url_merge.rank_urls_by_source(order, sources) == order


def test_load_sources_is_empty_on_a_pre_provenance_tree(tmp_path):
    # A --resume over an output dir written before provenance existed must
    # degrade to "no signal", not crash.
    (tmp_path / "processed").mkdir(parents=True)
    assert url_merge.load_url_sources(tmp_path) == {}
