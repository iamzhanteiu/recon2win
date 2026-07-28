"""Tests for modules/apidocs.py — API documentation discovery.

The load-bearing property is precision, not recall: a great many hosts
answer 200-with-index.html to every path, so anything that trusts a status
code reports a swagger doc on every host in the run. Nothing counts unless
the body actually parses as a spec.
"""
from __future__ import annotations

import json

from modules import apidocs
from modules.apidocs import (
    build_candidates,
    domain_tokens,
    parse_spec,
    spec_endpoints,
    spec_summary,
)
from modules.utils import create_output_structure, read_lines


OPENAPI3 = {
    "openapi": "3.0.1",
    "info": {"title": "Billing API", "version": "2.1"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "components": {"securitySchemes": {"bearerAuth": {"type": "http"}}},
    "paths": {
        "/users": {
            "get": {"parameters": [
                {"name": "page", "in": "query"},
                {"name": "limit", "in": "query"},
                {"name": "X-Trace", "in": "header"},
            ]},
            "post": {},
        },
        "/users/{id}": {"get": {}, "delete": {}},
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Legacy", "version": "1.0"},
    "host": "legacy.example.com",
    "basePath": "/api",
    "schemes": ["https"],
    "paths": {"/ping": {"get": {}}},
}


# ----------------------------------------------------------------------
# parse_spec — the precision gate
# ----------------------------------------------------------------------
def test_parse_spec_accepts_openapi3_and_swagger2():
    assert parse_spec(json.dumps(OPENAPI3))["openapi"] == "3.0.1"
    assert parse_spec(json.dumps(SWAGGER2))["swagger"] == "2.0"


def test_parse_spec_accepts_yaml():
    yaml_spec = (
        "openapi: 3.0.0\n"
        "info:\n  title: Y\n  version: '1'\n"
        "paths:\n  /a:\n    get: {}\n"
    )
    assert parse_spec(yaml_spec) is not None


def test_parse_spec_rejects_html_catch_all():
    """The whole reason this function exists: SPA hosts answer 200 with
    index.html on every path. Trusting the status code would report a spec
    on every candidate path of every host."""
    assert parse_spec("<!DOCTYPE html><html><body>hi</body></html>") is None


def test_parse_spec_rejects_json_that_is_not_a_spec():
    assert parse_spec('{"status":"ok","data":[1,2,3]}') is None
    # version key but no paths → not usable as a spec
    assert parse_spec('{"openapi":"3.0.0"}') is None
    # paths but no version key
    assert parse_spec('{"paths":{"/a":{}}}') is None


def test_parse_spec_rejects_empty_and_garbage():
    assert parse_spec("") is None
    assert parse_spec("   ") is None
    assert parse_spec("{not json at all") is None
    assert parse_spec("[1,2,3]") is None          # list, not dict


# ----------------------------------------------------------------------
# spec_endpoints
# ----------------------------------------------------------------------
def test_spec_endpoints_uses_servers_url():
    urls, params = spec_endpoints(OPENAPI3, "https://x.example.com/openapi.json")
    assert "https://api.example.com/v2/users" in urls
    assert "https://api.example.com/v2/users/{id}" in urls


def test_spec_endpoints_emits_only_query_params():
    _, params = spec_endpoints(OPENAPI3, "https://x.example.com/openapi.json")
    assert params == ["https://api.example.com/v2/users?page=&limit="]
    # header params must not become query params
    assert not any("X-Trace" in p for p in params)


def test_spec_endpoints_keeps_path_templates_intact():
    """Rewriting {id} to a guessed value fabricates a URL nobody observed.
    Leaving it makes it obvious the operator has to supply a value."""
    urls, _ = spec_endpoints(OPENAPI3, "https://x.example.com/openapi.json")
    assert any(u.endswith("/users/{id}") for u in urls)


def test_spec_endpoints_swagger2_host_basepath():
    urls, _ = spec_endpoints(SWAGGER2, "https://legacy.example.com/swagger.json")
    assert urls == ["https://legacy.example.com/api/ping"]


def test_spec_endpoints_falls_back_to_doc_url_host():
    spec = {"openapi": "3.0.0", "paths": {"/a": {}}}
    urls, _ = spec_endpoints(spec, "https://only.example.com/sub/openapi.json")
    assert urls == ["https://only.example.com/a"]


def test_spec_endpoints_relative_server_url_resolves():
    spec = {"openapi": "3.0.0", "servers": [{"url": "/api/v1"}],
            "paths": {"/a": {}}}
    urls, _ = spec_endpoints(spec, "https://h.example.com/openapi.json")
    assert urls == ["https://h.example.com/api/v1/a"]


def test_spec_endpoints_survives_malformed_paths():
    spec = {"openapi": "3.0.0", "paths": {
        "/ok": {"get": {}},
        "not-a-path": {},          # no leading slash
        "/junk": "not-a-dict",
    }}
    urls, _ = spec_endpoints(spec, "https://h.example.com/openapi.json")
    assert "https://h.example.com/ok" in urls
    assert "https://h.example.com/junk" in urls
    assert not any("not-a-path" in u for u in urls)


def test_spec_summary_counts_methods_and_security():
    s = spec_summary(OPENAPI3, "https://x.example.com/openapi.json")
    assert s["kind"] == "openapi"
    assert s["title"] == "Billing API"
    assert s["paths"] == 2
    assert s["methods"] == {"get": 2, "post": 1, "delete": 1}
    assert s["security_schemes"] == ["bearerAuth"]


# ----------------------------------------------------------------------
# build_candidates
# ----------------------------------------------------------------------
def test_build_candidates_crosses_hosts_and_paths():
    out = build_candidates(["https://a.com", "https://b.com/"],
                           ("/x", "/y"))
    assert out == ["https://a.com/x", "https://a.com/y",
                   "https://b.com/x", "https://b.com/y"]


def test_build_candidates_skips_non_http_lines():
    out = build_candidates(["a.com", "ftp://b.com", "https://c.com"], ("/x",))
    assert out == ["https://c.com/x"]


def test_build_candidates_dedups():
    out = build_candidates(["https://a.com", "https://a.com/"], ("/x",))
    assert out == ["https://a.com/x"]


# ----------------------------------------------------------------------
# domain_tokens — OSINT noise filter
# ----------------------------------------------------------------------
def test_domain_tokens_drops_tld_and_generic_words():
    assert domain_tokens("discover.com") == ["discover"]
    assert domain_tokens("api.acronis.com") == ["acronis"]
    assert "com" not in domain_tokens("example.com")


def test_domain_tokens_drops_short_fragments():
    # 3-letter labels are too generic to filter on
    assert domain_tokens("abc.com") == []


def test_postman_relevance_rejects_generic_workspaces():
    """Measured 2026-07-28: searching "discover.com" returned "Postman
    Public Workspace" at score 252, above where a genuine hit for a small
    org would land. Score alone cannot be trusted."""
    toks = domain_tokens("discover.com")
    assert not apidocs._postman_relevant("Postman Public Workspace", toks)
    assert not apidocs._postman_relevant("Spotify", toks)
    assert apidocs._postman_relevant("Discover Card Public API", toks)


def test_postman_relevance_matches_words_not_substrings():
    """Regression against live Postman data: substring matching let
    "discover" hit "Bloomreach - Discovery Workspace", "Ticketmaster
    Discovery API" and "Postman Open Technologies - Discovery" — 25
    results, none of them the target. Word boundaries drop all three
    because "discovery" is not "discover"."""
    toks = domain_tokens("discover.com")
    for noise in ("Bloomreach - Discovery Workspace",
                  "Ticketmaster Discovery API",
                  "Postman Open Technologies - Discovery",
                  "AllTrails Restaurant Discovery API"):
        assert not apidocs._postman_relevant(noise, toks), noise
    for real in ("discover", "Discover", "R1 Discover API"):
        assert apidocs._postman_relevant(real, toks), real


def test_search_postman_drops_bare_request_hits(monkeypatch):
    """A single request named "discover users" inside somebody else's
    collection is not a finding about the target; Postman scores those at
    ~0.01 and returns dozens per query."""
    payload = {"data": {
        "workspace": [{"score": 300, "document": {
            "name": "Discover API", "slug": "discover-api", "id": "w1"}}],
        "request": [{"score": 0.01, "document": {
            "name": "discover users", "id": "r1"}}],
    }}

    class _R:
        status_code = 200

        def json(self):
            return payload

    monkeypatch.setattr("requests.post", lambda *a, **k: _R())
    hits = apidocs.search_postman("discover.com")
    assert [h["kind"] for h in hits] == ["workspace"]


# ----------------------------------------------------------------------
# _classify_hit
# ----------------------------------------------------------------------
def test_classify_hit_spec_beats_everything():
    row = {"body": json.dumps(OPENAPI3), "content_type": "application/json"}
    assert apidocs._classify_hit(row) == "spec"


def test_classify_hit_detects_ui_shell():
    row = {"body": '<html><div id="swagger-ui"></div></html>',
           "content_type": "text/html"}
    assert apidocs._classify_hit(row) == "ui"


def test_classify_hit_detects_openid_discovery():
    row = {"body": json.dumps({"issuer": "https://x.com",
                               "token_endpoint": "https://x.com/token"}),
           "content_type": "application/json"}
    assert apidocs._classify_hit(row) == "discovery"


def test_classify_hit_returns_none_for_ordinary_page():
    row = {"body": "<html><body>Welcome to our site</body></html>",
           "content_type": "text/html"}
    assert apidocs._classify_hit(row) is None
    row2 = {"body": '{"ok":true}', "content_type": "application/json"}
    assert apidocs._classify_hit(row2) is None


# ----------------------------------------------------------------------
# discover — stage wiring
# ----------------------------------------------------------------------
def _base(tmp_path, hosts=("https://a.example.com",)):
    base = create_output_structure("example.com", root=str(tmp_path))
    alive = base / "processed" / "alive.txt"
    alive.write_text("\n".join(hosts) + "\n")
    return base, alive


def test_discover_skip_flag_writes_empty_outputs(tmp_path):
    base, alive = _base(tmp_path)
    res = apidocs.discover(alive, base, {}, skip=True)
    assert res["status"] == "skipped"
    assert (base / "findings" / "api_docs.json").exists()
    assert read_lines(base / "processed" / "apidocs_urls.txt") == []


def test_discover_disabled_in_config(tmp_path):
    base, alive = _base(tmp_path)
    res = apidocs.discover(alive, base, {"apidocs": {"enabled": False}})
    assert res["status"] == "skipped"
    assert "disabled" in res["error"]


def test_discover_dry_run_makes_no_requests(tmp_path, monkeypatch):
    base, alive = _base(tmp_path)
    called = []
    monkeypatch.setattr(apidocs.runner, "run",
                        lambda *a, **k: called.append(1))
    res = apidocs.discover(alive, base, {}, dry_run=True)
    assert res["status"] == "skipped"
    assert called == []


def test_discover_parses_spec_and_writes_endpoints(tmp_path, monkeypatch):
    base, alive = _base(tmp_path)
    monkeypatch.setattr(apidocs.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(apidocs, "search_postman", lambda *a, **k: [])

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-o") + 1]
        rows = [
            {"url": "https://a.example.com/openapi.json",
             "status_code": 200, "content_type": "application/json",
             "body": json.dumps(OPENAPI3)},
            # a catch-all 200 that must NOT be counted
            {"url": "https://a.example.com/docs",
             "status_code": 200, "content_type": "text/html",
             "body": "<html>home page</html>"},
        ]
        with open(out, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(apidocs.runner, "run", fake_run)
    res = apidocs.discover(alive, base, {}, domain="example.com")

    assert res["status"] == "success"
    assert res["extra"]["specs"] == 1
    assert res["extra"]["documented_paths"] == 2
    urls = read_lines(base / "processed" / "apidocs_urls.txt")
    assert "https://api.example.com/v2/users" in urls
    params = read_lines(base / "processed" / "apidocs_params.txt")
    assert params == ["https://api.example.com/v2/users?page=&limit="]
    saved = json.loads((base / "findings" / "api_docs.json").read_text())
    assert saved["specs"][0]["title"] == "Billing API"


def test_discover_does_not_count_catch_all_200_as_spec(tmp_path, monkeypatch):
    """A host answering 200-with-html on every path must produce zero
    specs — otherwise every host in the run looks like it exposes one."""
    base, alive = _base(tmp_path)
    monkeypatch.setattr(apidocs.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(apidocs, "search_postman", lambda *a, **k: [])

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w") as fh:
            for p in apidocs.SPEC_PATHS[:10]:
                fh.write(json.dumps({
                    "url": f"https://a.example.com{p}", "status_code": 200,
                    "content_type": "text/html",
                    "body": "<html><body>Our homepage</body></html>",
                }) + "\n")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(apidocs.runner, "run", fake_run)
    res = apidocs.discover(alive, base, {}, domain="example.com")
    assert res["extra"]["specs"] == 0
    assert read_lines(base / "processed" / "apidocs_urls.txt") == []


def test_discover_caps_hosts(tmp_path, monkeypatch):
    hosts = [f"https://h{i}.example.com" for i in range(10)]
    base, alive = _base(tmp_path, hosts)
    monkeypatch.setattr(apidocs.runner, "tool_available", lambda b: False)
    monkeypatch.setattr(apidocs, "search_postman", lambda *a, **k: [])
    res = apidocs.discover(alive, base, {"apidocs": {"max_hosts": 3}},
                           domain="example.com")
    pr = res["extra"]["probe"]
    assert pr["hosts"] == 3
    assert pr["hosts_capped"] == 7
    assert pr["error"] == "httpx binary not found"


def test_discover_extra_paths_from_config(tmp_path, monkeypatch):
    base, alive = _base(tmp_path)
    monkeypatch.setattr(apidocs.runner, "tool_available", lambda b: False)
    monkeypatch.setattr(apidocs, "search_postman", lambda *a, **k: [])
    res = apidocs.discover(
        alive, base,
        {"apidocs": {"extra_paths": ["/custom/spec.json", "no-slash"]}},
        domain="example.com")
    # only the slash-prefixed one is accepted
    assert res["extra"]["probe"]["paths"] == len(apidocs.SPEC_PATHS) + 1


def test_discover_osint_failure_is_not_fatal(tmp_path, monkeypatch):
    """Postman's endpoint is unofficial; a shape change or outage must
    degrade to probe-only, never break the stage."""
    base, alive = _base(tmp_path)
    monkeypatch.setattr(apidocs.runner, "tool_available", lambda b: False)

    def boom(*a, **k):
        raise RuntimeError("postman is down")

    monkeypatch.setattr(apidocs, "requests", None, raising=False)
    monkeypatch.setattr(apidocs, "search_github", lambda *a, **k: [])
    # search_postman itself swallows everything — prove it
    monkeypatch.setattr("requests.post", boom)
    res = apidocs.discover(alive, base, {}, domain="example.com")
    assert res["status"] == "success"
    assert res["extra"]["osint"] == 0


def test_search_github_without_token_returns_empty():
    assert apidocs.search_github("example.com", "") == []
