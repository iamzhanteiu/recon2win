"""Tests for URL scope filtering in url_merge (stage 5 + 6.post).

Content discovery pulls out-of-scope URLs on purpose (katana ``-do``) so the
JS-analysis stages can mine endpoints from CDN-hosted bundles. Scope filtering
then trims ``all_urls.txt`` / ``dynamic_urls.txt`` down to in-scope + related
hosts so httpx/arjun/nuclei don't waste budget on youtube/fb/google — while
out-of-scope ``.js`` is deliberately preserved in ``js_urls.txt``.
"""
from __future__ import annotations

from pathlib import Path

from modules import layout, url_merge
from modules.url_merge import (
    filter_in_scope,
    is_in_scope,
    normalize_root,
)
from modules.utils import read_lines, write_lines


# ----------------------------------------------------------------------
# pure helpers
# ----------------------------------------------------------------------
def test_normalize_root_forms():
    assert normalize_root("foo.com") == "foo.com"
    assert normalize_root(".foo.com") == "foo.com"
    assert normalize_root("*.foo.com") == "foo.com"
    assert normalize_root("https://foo.com/x") == "foo.com"
    assert normalize_root("") == ""


def test_is_in_scope_root_and_subdomain():
    assert is_in_scope("https://guildwars2.com/a", "guildwars2.com")
    assert is_in_scope("https://www.guildwars2.com/a", "guildwars2.com")
    assert not is_in_scope("https://youtube.com/watch", "guildwars2.com")
    # a domain that merely ends with the root string but isn't a subdomain
    assert not is_in_scope("https://notguildwars2.com/a", "guildwars2.com")


def test_is_in_scope_related_roots():
    related = ["staticwars.com", "*.arena.net"]
    assert is_in_scope("https://services.staticwars.com/x", "guildwars2.com", related)
    assert is_in_scope("https://playtest.arena.net/x", "guildwars2.com", related)
    assert not is_in_scope("https://facebook.com/x", "guildwars2.com", related)


def test_filter_in_scope_preserves_order():
    urls = [
        "https://guildwars2.com/1",
        "https://youtube.com/2",
        "https://cdn.staticwars.com/3",
        "https://google-analytics.com/4",
    ]
    assert filter_in_scope(urls, "guildwars2.com", ["staticwars.com"]) == [
        "https://guildwars2.com/1",
        "https://cdn.staticwars.com/3",
    ]


# ----------------------------------------------------------------------
# merge() — all_urls filtered, js_urls keeps out-of-scope .js
# ----------------------------------------------------------------------
def _seed_inputs(out: Path, urls: list[str]) -> None:
    write_lines(layout.path(out, "crawler_urls.txt"), urls)
    for name in ("dirsearch_urls.txt", "ffuf_urls.txt", "waymore_urls.txt"):
        write_lines(layout.path(out, name), [])


def test_merge_filters_all_urls_but_keeps_out_of_scope_js(tmp_path: Path):
    _seed_inputs(tmp_path, [
        "https://guildwars2.com/app",
        "https://cdn.staticwars.com/bundle.js",   # out-of-scope but .js → js_urls
        "https://www.youtube.com/embed",           # pure 3rd-party → dropped
        "https://www.google-analytics.com/ga.js",  # 3rd-party .js → js_urls, NOT all_urls
    ])
    cfg = {"scope": {"filter_urls": True, "related_roots": []}}

    res = url_merge.merge(tmp_path, "guildwars2.com", cfg)

    all_urls = read_lines(layout.path(tmp_path, "all_urls.txt"))
    js_urls = read_lines(layout.path(tmp_path, "js_urls.txt"))

    # all_urls: only the in-scope host survives (staticwars is not related here).
    assert all_urls == ["https://guildwars2.com/app"]
    # js_urls: every .js kept for analysis, in-scope or not.
    assert "https://cdn.staticwars.com/bundle.js" in js_urls
    assert "https://www.google-analytics.com/ga.js" in js_urls
    # out-of-scope .js is NOT in the scan set.
    assert "https://cdn.staticwars.com/bundle.js" not in all_urls
    assert res["extra"]["scope_dropped"] == 3


def test_merge_related_roots_kept_in_all_urls(tmp_path: Path):
    _seed_inputs(tmp_path, [
        "https://guildwars2.com/app",
        "https://services.staticwars.com/api?id=1",
        "https://youtube.com/x",
    ])
    cfg = {"scope": {"filter_urls": True, "related_roots": ["staticwars.com"]}}

    url_merge.merge(tmp_path, "guildwars2.com", cfg)
    all_urls = read_lines(layout.path(tmp_path, "all_urls.txt"))
    dyn = read_lines(layout.path(tmp_path, "dynamic_urls.txt"))

    assert "https://services.staticwars.com/api?id=1" in all_urls
    assert "https://youtube.com/x" not in all_urls
    # the related-root dynamic URL flows into dynamic_urls.txt
    assert "https://services.staticwars.com/api?id=1" in dyn


def test_merge_filter_disabled_keeps_everything(tmp_path: Path):
    _seed_inputs(tmp_path, [
        "https://guildwars2.com/app",
        "https://youtube.com/x",
    ])
    cfg = {"scope": {"filter_urls": False}}

    url_merge.merge(tmp_path, "guildwars2.com", cfg)
    all_urls = read_lines(layout.path(tmp_path, "all_urls.txt"))
    assert "https://youtube.com/x" in all_urls


def test_merge_no_domain_fails_open(tmp_path: Path):
    """Empty domain must NOT drop everything — filtering needs a root."""
    _seed_inputs(tmp_path, ["https://guildwars2.com/app", "https://youtube.com/x"])
    cfg = {"scope": {"filter_urls": True}}

    url_merge.merge(tmp_path, "", cfg)
    all_urls = read_lines(layout.path(tmp_path, "all_urls.txt"))
    assert len(all_urls) == 2  # nothing dropped


# ----------------------------------------------------------------------
# append_urls() — re-filters merged set, preserves out-of-scope js_urls
# ----------------------------------------------------------------------
def test_append_urls_refilters_and_preserves_js(tmp_path: Path):
    # State after merge(): all_urls filtered, js_urls holds an out-of-scope bundle.
    write_lines(layout.path(tmp_path, "all_urls.txt"), ["https://guildwars2.com/app"])
    write_lines(layout.path(tmp_path, "js_urls.txt"), ["https://cdn.staticwars.com/bundle.js"])
    write_lines(layout.path(tmp_path, "dynamic_urls.txt"), ["https://guildwars2.com/app"])

    # xnLinkFinder surfaced one in-scope endpoint and one 3rd-party one.
    extra = layout.path(tmp_path, "xnlinkfinder_urls.txt")
    write_lines(extra, [
        "https://api.guildwars2.com/v2/account",
        "https://www.facebook.com/tr",
    ])
    cfg = {"scope": {"filter_urls": True, "related_roots": []}}

    url_merge.append_urls(tmp_path, [extra], "guildwars2.com", cfg)

    all_urls = read_lines(layout.path(tmp_path, "all_urls.txt"))
    js_urls = read_lines(layout.path(tmp_path, "js_urls.txt"))

    assert "https://api.guildwars2.com/v2/account" in all_urls
    assert "https://www.facebook.com/tr" not in all_urls   # re-filtered out
    # out-of-scope bundle from the earlier merge is still present.
    assert "https://cdn.staticwars.com/bundle.js" in js_urls
