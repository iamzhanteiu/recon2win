"""Tests for modules/hackerone.py.

Covers:
  * get_credentials       — env precedence, config fallback, missing → error
  * parse_scopes          — in-scope filtering (eligible_for_submission)
  * extract_root_domains  — WILDCARD/URL → host, dedupe, sort, skip non-domain
  * list_programs / get_structured_scopes — pagination + error handling
    (requests.get is monkeypatched — no real network)
"""
import pytest

from modules import hackerone as h1


# ----------------------------------------------------------------------
# Credentials
# ----------------------------------------------------------------------
def test_get_credentials_env_wins(monkeypatch):
    monkeypatch.setenv("H1_API_USERNAME", "env-user")
    monkeypatch.setenv("H1_API_TOKEN", "env-token")
    cfg = {"hackerone": {"api_username": "cfg-user", "api_token": "cfg-token"}}
    assert h1.get_credentials(cfg) == ("env-user", "env-token")


def test_get_credentials_config_fallback(monkeypatch):
    monkeypatch.delenv("H1_API_USERNAME", raising=False)
    monkeypatch.delenv("H1_API_TOKEN", raising=False)
    cfg = {"hackerone": {"api_username": "cfg-user", "api_token": "cfg-token"}}
    assert h1.get_credentials(cfg) == ("cfg-user", "cfg-token")


def test_get_credentials_missing_raises(monkeypatch):
    monkeypatch.delenv("H1_API_USERNAME", raising=False)
    monkeypatch.delenv("H1_API_TOKEN", raising=False)
    with pytest.raises(h1.H1Error):
        h1.get_credentials({})
    with pytest.raises(h1.H1Error):
        h1.get_credentials(None)


# ----------------------------------------------------------------------
# parse_scopes
# ----------------------------------------------------------------------
def _scope(asset_type, ident, *, submit=True, bounty=False):
    return {
        "id": "1",
        "type": "structured-scope",
        "attributes": {
            "asset_type": asset_type,
            "asset_identifier": ident,
            "eligible_for_submission": submit,
            "eligible_for_bounty": bounty,
        },
    }


def test_parse_scopes_filters_out_of_scope():
    raw = [
        _scope("URL", "in.example.com", submit=True),
        _scope("URL", "out.example.com", submit=False),
    ]
    parsed = h1.parse_scopes(raw)
    idents = [p["asset_identifier"] for p in parsed]
    assert idents == ["in.example.com"]


def test_parse_scopes_in_scope_only_false_keeps_all():
    raw = [
        _scope("URL", "in.example.com", submit=True),
        _scope("URL", "out.example.com", submit=False),
    ]
    parsed = h1.parse_scopes(raw, in_scope_only=False)
    assert len(parsed) == 2


def test_parse_scopes_handles_empty_and_missing_attrs():
    assert h1.parse_scopes([]) == []
    assert h1.parse_scopes([{"attributes": {}}]) == []  # not eligible → dropped


# ----------------------------------------------------------------------
# extract_root_domains
# ----------------------------------------------------------------------
def test_extract_root_domains_wildcard_stripped():
    scopes = h1.parse_scopes([_scope("WILDCARD", "*.example.com")])
    assert h1.extract_root_domains(scopes) == ["example.com"]


def test_extract_root_domains_url_to_host():
    scopes = h1.parse_scopes([_scope("URL", "https://app.example.com/login?x=1")])
    assert h1.extract_root_domains(scopes) == ["app.example.com"]


def test_extract_root_domains_bare_host():
    scopes = h1.parse_scopes([_scope("URL", "api.example.com")])
    assert h1.extract_root_domains(scopes) == ["api.example.com"]


def test_extract_root_domains_skips_non_domain_types():
    scopes = h1.parse_scopes([
        _scope("CIDR", "10.0.0.0/8"),
        _scope("GOOGLE_PLAY_APP_ID", "com.example.app"),
        _scope("SOURCE_CODE", "github.com/example/repo"),
    ])
    assert h1.extract_root_domains(scopes) == []


def test_extract_root_domains_dedupe_and_sort():
    scopes = h1.parse_scopes([
        _scope("URL", "https://b.example.com"),
        _scope("WILDCARD", "*.a.example.com"),
        _scope("URL", "b.example.com"),          # dup of the first host
    ])
    assert h1.extract_root_domains(scopes) == ["a.example.com", "b.example.com"]


# ----------------------------------------------------------------------
# Network calls (monkeypatched requests.get)
# ----------------------------------------------------------------------
class _FakeResp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


def test_list_programs_follows_pagination(monkeypatch):
    page1 = {
        "data": [{"attributes": {"handle": "alpha", "name": "Alpha"}}],
        "links": {"next": "https://api.hackerone.com/v1/hackers/programs?page[number]=2"},
    }
    page2 = {
        "data": [{"attributes": {"handle": "beta", "name": "Beta"}}],
        "links": {},
    }
    responses = iter([_FakeResp(payload=page1), _FakeResp(payload=page2)])
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return next(responses)

    monkeypatch.setattr(h1.requests, "get", fake_get)
    progs = h1.list_programs("u", "t")
    assert [p["handle"] for p in progs] == ["alpha", "beta"]
    assert len(calls) == 2  # followed links.next once


def test_get_paginated_401_raises(monkeypatch):
    monkeypatch.setattr(h1.requests, "get",
                        lambda url, **kw: _FakeResp(status_code=401, text="nope"))
    with pytest.raises(h1.H1Error) as ei:
        h1.list_programs("u", "bad")
    assert "401" in str(ei.value)


def test_get_paginated_network_error_raises(monkeypatch):
    def boom(url, **kw):
        raise h1.requests.RequestException("dns fail")

    monkeypatch.setattr(h1.requests, "get", boom)
    with pytest.raises(h1.H1Error):
        h1.list_programs("u", "t")


def test_roots_for_program_end_to_end(monkeypatch):
    payload = {
        "data": [
            {"attributes": {"asset_type": "WILDCARD",
                            "asset_identifier": "*.example.com",
                            "eligible_for_submission": True}},
            {"attributes": {"asset_type": "URL",
                            "asset_identifier": "https://api.example.com",
                            "eligible_for_submission": True}},
            {"attributes": {"asset_type": "URL",
                            "asset_identifier": "out.example.com",
                            "eligible_for_submission": False}},
            {"attributes": {"asset_type": "CIDR",
                            "asset_identifier": "10.0.0.0/8",
                            "eligible_for_submission": True}},
        ],
        "links": {},
    }
    monkeypatch.setattr(h1.requests, "get", lambda url, **kw: _FakeResp(payload=payload))
    roots = h1.roots_for_program("u", "t", "example")
    assert roots == ["api.example.com", "example.com"]
