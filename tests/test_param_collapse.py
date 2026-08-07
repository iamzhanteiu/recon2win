"""Tests for param-template collapsing in url_merge.

A crawl emits the same endpoint many times with only the param VALUE changing
(``/e?id=1`` … ``/e?id=999``) plus URLs that repeat a param name
(``/e?p=a&p=b``). ``collapse_param_shapes`` keeps one representative per
(host, path, param shape) — "smart": keyword-like values stay distinct, only
machine-id values fold.
"""
from __future__ import annotations

from pathlib import Path

from modules import layout, url_merge
from modules.url_merge import (
    _is_meaningful_value,
    collapse_param_shapes,
    param_template_key,
)
from modules.utils import read_lines, write_lines


# ----------------------------------------------------------------------
# _is_meaningful_value
# ----------------------------------------------------------------------
def test_meaningful_value_keywords_vs_ids():
    assert _is_meaningful_value("delete")
    assert _is_meaningful_value("admin")
    assert _is_meaningful_value("true")
    # machine ids / noise → not meaningful
    assert not _is_meaningful_value("1")
    assert not _is_meaningful_value("99999")
    assert not _is_meaningful_value("")
    assert not _is_meaningful_value("a1b2c3d4e5f6")     # hex-ish
    assert not _is_meaningful_value("2024-01-01")        # date, no letters
    assert not _is_meaningful_value("x" * 40)            # long blob


# ----------------------------------------------------------------------
# collapse_param_shapes
# ----------------------------------------------------------------------
def test_collapse_folds_value_only_variants():
    urls = ["https://x.com/e/?id=1", "https://x.com/e/?id=2", "https://x.com/e/?id=9999"]
    assert collapse_param_shapes(urls) == ["https://x.com/e/?id=1"]


def test_collapse_folds_repeated_param_name():
    urls = [
        "https://x.com/e/?p=a&p=b",
        "https://x.com/e/?p=c&p=d",   # same shape (repeated name) → folds
    ]
    assert collapse_param_shapes(urls) == ["https://x.com/e/?p=a&p=b"]


def test_collapse_keeps_keyword_values_distinct():
    urls = ["https://x.com/act/?action=delete", "https://x.com/act/?action=view"]
    assert collapse_param_shapes(urls) == urls  # both kept


def test_collapse_is_order_independent():
    urls = ["https://x.com/e/?p1=1&p2=2", "https://x.com/e/?p2=9&p1=8"]
    assert collapse_param_shapes(urls) == ["https://x.com/e/?p1=1&p2=2"]


def test_collapse_keeps_distinct_paths_and_no_param_urls():
    urls = [
        "https://x.com/a",
        "https://x.com/b",
        "https://x.com/a?id=1",
    ]
    assert collapse_param_shapes(urls) == urls  # all distinct keys


def test_param_template_key_different_endpoints_differ():
    assert param_template_key("https://x.com/a?id=1") != param_template_key(
        "https://x.com/b?id=1"
    )


# ----------------------------------------------------------------------
# merge() integration — collapse applied to all_urls + dynamic_urls
# ----------------------------------------------------------------------
def _seed(out: Path, urls: list[str]) -> None:
    write_lines(layout.path(out, "crawler_urls.txt"), urls)
    for name in ("dirsearch_urls.txt", "ffuf_urls.txt", "waymore_urls.txt"):
        write_lines(layout.path(out, name), [])


def test_merge_collapses_param_variants(tmp_path: Path):
    _seed(tmp_path, [
        "https://guildwars2.com/e?id=1",
        "https://guildwars2.com/e?id=2",
        "https://guildwars2.com/e?id=3",
        "https://guildwars2.com/act?action=delete",
        "https://guildwars2.com/act?action=view",
    ])
    cfg = {"scope": {"filter_urls": True}, "url_dedup": {"collapse_params": True}}

    res = url_merge.merge(tmp_path, "guildwars2.com", cfg)
    all_urls = read_lines(layout.path(tmp_path, "all_urls.txt"))

    assert "https://guildwars2.com/e?id=1" in all_urls
    assert "https://guildwars2.com/e?id=2" not in all_urls   # folded
    assert "https://guildwars2.com/act?action=delete" in all_urls
    assert "https://guildwars2.com/act?action=view" in all_urls  # kept distinct
    assert res["extra"]["param_collapsed"] == 2


def test_merge_collapse_disabled(tmp_path: Path):
    _seed(tmp_path, ["https://guildwars2.com/e?id=1", "https://guildwars2.com/e?id=2"])
    cfg = {"scope": {"filter_urls": True}, "url_dedup": {"collapse_params": False}}

    url_merge.merge(tmp_path, "guildwars2.com", cfg)
    all_urls = read_lines(layout.path(tmp_path, "all_urls.txt"))
    assert len(all_urls) == 2  # nothing folded
