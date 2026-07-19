"""Tests for modules/jsluice.py — the pure parser/resolver helpers.

The subprocess (jsluice) and network fetch are not exercised here; we
test the JSONL parsing, relative-URL resolution against the source JS
file, scope filtering, param extraction, and secret parsing — the logic
that turns jsluice's raw output into the framework's canonical files.
"""
from __future__ import annotations

from modules.jsluice import (
    _in_scope,
    _iter_jsonl,
    _parse_secrets,
    _resolve_urls,
)


FNAME_TO_URL = {
    "/tmp/raw/0001.js": "https://app.example.com/static/main.js",
    "/tmp/raw/0002.js": "https://cdn.other.com/vendor.js",
}


# ----------------------------------------------------------------------
# _iter_jsonl — tolerant JSONL parsing
# ----------------------------------------------------------------------
def test_iter_jsonl_skips_blank_and_broken_lines():
    text = '\n{"url":"/a"}\nnot-json\n{"url":"/b"}\n[1,2,3]\n'
    objs = list(_iter_jsonl(text))
    # blank, "not-json", and the non-dict array are all skipped
    assert objs == [{"url": "/a"}, {"url": "/b"}]


def test_iter_jsonl_empty():
    assert list(_iter_jsonl("")) == []
    assert list(_iter_jsonl(None)) == []


# ----------------------------------------------------------------------
# _in_scope
# ----------------------------------------------------------------------
def test_in_scope_matches_domain_and_subdomains():
    assert _in_scope("example.com", "example.com")
    assert _in_scope("app.example.com", "example.com")
    assert not _in_scope("evil-example.com", "example.com")
    assert not _in_scope("cdn.other.com", "example.com")


def test_in_scope_empty_domain_allows_all():
    assert _in_scope("anything.com", "")


# ----------------------------------------------------------------------
# _resolve_urls — the core logic
# ----------------------------------------------------------------------
def test_resolve_relative_against_source_js_url():
    records = [
        {"url": "/api/v1/users", "queryParams": [], "bodyParams": [],
         "method": "GET", "filename": "/tmp/raw/0001.js"},
    ]
    urls, endpoints, params = _resolve_urls(records, FNAME_TO_URL, "example.com")
    # /api/v1/users resolves against app.example.com (the source JS host)
    assert urls == ["https://app.example.com/api/v1/users"]
    assert endpoints == ["/api/v1/users"]
    assert params == []


def test_resolve_scope_filters_out_third_party_hosts():
    records = [
        {"url": "https://tracker.evil.com/collect", "filename": "/tmp/raw/0001.js"},
        {"url": "/keep/me", "filename": "/tmp/raw/0001.js"},
    ]
    urls, endpoints, _ = _resolve_urls(records, FNAME_TO_URL, "example.com")
    assert urls == ["https://app.example.com/keep/me"]
    assert "https://tracker.evil.com/collect" not in urls


def test_resolve_extracts_params_and_strips_expr_placeholder():
    records = [
        {"url": "/search?q=EXPR", "queryParams": ["q"], "bodyParams": [],
         "method": "GET", "filename": "/tmp/raw/0001.js"},
        {"url": "/login", "queryParams": [], "bodyParams": ["user", "pass"],
         "method": "POST", "filename": "/tmp/raw/0001.js"},
    ]
    urls, endpoints, params = _resolve_urls(records, FNAME_TO_URL, "example.com")
    # EXPR placeholder neutralised in the emitted URL
    assert "https://app.example.com/search?q=" in urls
    # both param-bearing records captured
    assert {p["url"] for p in params} == {
        "https://app.example.com/search?q=",
        "https://app.example.com/login",
    }
    post = [p for p in params if p["method"] == "POST"][0]
    assert post["bodyParams"] == ["user", "pass"]


def test_resolve_dedupes_and_ignores_bare_expr():
    records = [
        {"url": "EXPR", "filename": "/tmp/raw/0001.js"},          # dropped
        {"url": "/dup", "filename": "/tmp/raw/0001.js"},
        {"url": "/dup", "filename": "/tmp/raw/0001.js"},          # dedup
        {"url": "", "filename": "/tmp/raw/0001.js"},              # dropped
    ]
    urls, endpoints, _ = _resolve_urls(records, FNAME_TO_URL, "example.com")
    assert urls == ["https://app.example.com/dup"]
    assert endpoints == ["/dup"]


def test_resolve_protocol_relative_url():
    records = [{"url": "//app.example.com/x", "filename": "/tmp/raw/0001.js"}]
    urls, _, _ = _resolve_urls(records, FNAME_TO_URL, "example.com")
    assert urls == ["https://app.example.com/x"]


# ----------------------------------------------------------------------
# _parse_secrets
# ----------------------------------------------------------------------
def test_parse_secrets_maps_filename_to_url_and_counts_severity():
    records = [
        {"kind": "AWSAccessKey", "severity": "high",
         "data": {"key": "AKIA..."}, "filename": "/tmp/raw/0001.js"},
        {"kind": "GenericToken", "severity": "low",
         "data": {"t": "x"}, "filename": "/tmp/raw/0002.js"},
        {"kind": "AWSAccessKey", "severity": "high",
         "data": {"key": "AKIB..."}, "filename": "/tmp/raw/0001.js"},
    ]
    findings, sev = _parse_secrets(records, FNAME_TO_URL)
    assert len(findings) == 3
    # filename resolved back to the original JS URL
    assert findings[0]["url"] == "https://app.example.com/static/main.js"
    assert sev == {"high": 2, "low": 1}


def test_parse_secrets_defaults_severity_to_info():
    findings, sev = _parse_secrets(
        [{"kind": "X", "filename": "/tmp/raw/0001.js"}], FNAME_TO_URL,
    )
    assert findings[0]["severity"] == "info"
    assert sev == {"info": 1}
