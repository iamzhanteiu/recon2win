"""Tests for seeding already-parameterized URLs into nuclei_dynamic input.

nuclei_dynamic scans only parameterized_urls.txt. URLs that already carry
``?id=1`` in the crawl/waymore output are prime injection targets but only
reached the dynamic scan if arjun re-discovered them — so a --skip-arjun /
capped / failed arjun run silently dropped them. seed_parameterized_urls
adds them directly from dynamic_urls.txt.
"""
from __future__ import annotations

from pathlib import Path

from modules.url_merge import has_query_params, seed_parameterized_urls
from modules.utils import create_output_structure, read_lines, write_lines


# ----------------------------------------------------------------------
# has_query_params — pure
# ----------------------------------------------------------------------
def test_has_query_params_true():
    assert has_query_params("https://x.com/a?id=1")
    assert has_query_params("https://x.com/a?q=1&p=2")
    assert has_query_params("https://x.com/a?flag")  # bare key still a query


def test_has_query_params_false():
    assert not has_query_params("https://x.com/a")
    assert not has_query_params("https://x.com/a?")   # empty query
    assert not has_query_params("")
    assert not has_query_params("https://x.com/style.css")


# ----------------------------------------------------------------------
# seed_parameterized_urls — the fix
# ----------------------------------------------------------------------
def _setup(tmp_path: Path, dynamic: list[str], existing_param: list[str] | None = None):
    base = create_output_structure("x.com", root=str(tmp_path))
    write_lines(base / "processed" / "dynamic_urls.txt", dynamic)
    if existing_param is not None:
        write_lines(base / "processed" / "parameterized_urls.txt", existing_param)
    return base


def test_seed_adds_param_urls_when_arjun_skipped(tmp_path: Path):
    # arjun skipped → parameterized_urls.txt empty; dynamic has param URLs
    base = _setup(tmp_path, [
        "https://x.com/list?id=1",
        "https://x.com/item?cat=2",
        "https://x.com/about",          # no param → not seeded
        "https://x.com/api/users",      # no param → not seeded
    ], existing_param=[])
    res = seed_parameterized_urls(base)
    assert res["count"] == 2
    out = read_lines(base / "processed" / "parameterized_urls.txt")
    assert out == ["https://x.com/list?id=1", "https://x.com/item?cat=2"]


def test_seed_merges_with_existing_arjun_output_deduped(tmp_path: Path):
    # arjun already found one; seed adds the rest without duplicating it
    base = _setup(
        tmp_path,
        dynamic=["https://x.com/list?id=1", "https://x.com/item?cat=2"],
        existing_param=["https://x.com/list?id=1"],   # arjun already has this
    )
    res = seed_parameterized_urls(base)
    assert res["count"] == 1                          # only /item?cat=2 is new
    out = read_lines(base / "processed" / "parameterized_urls.txt")
    assert out.count("https://x.com/list?id=1") == 1  # no duplicate
    assert "https://x.com/item?cat=2" in out


def test_seed_noop_when_no_param_urls(tmp_path: Path):
    base = _setup(tmp_path, ["https://x.com/a", "https://x.com/b"], existing_param=[])
    res = seed_parameterized_urls(base)
    assert res["count"] == 0


def test_seed_creates_file_when_missing(tmp_path: Path):
    # parameterized_urls.txt does not exist yet (arjun never wrote it)
    base = _setup(tmp_path, ["https://x.com/list?id=1"])
    target = base / "processed" / "parameterized_urls.txt"
    assert not target.exists()
    res = seed_parameterized_urls(base)
    assert res["count"] == 1
    assert target.exists()
    assert read_lines(target) == ["https://x.com/list?id=1"]


def test_seed_reports_total(tmp_path: Path):
    base = _setup(
        tmp_path,
        dynamic=["https://x.com/a?x=1", "https://x.com/b?y=2"],
        existing_param=["https://x.com/found?z=3"],
    )
    res = seed_parameterized_urls(base)
    assert res["extra"]["seeded"] == 2
    assert res["extra"]["total"] == 3
