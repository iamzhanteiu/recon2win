"""Tests for modules/jsluice.py — the pure parser/resolver helpers.

The subprocess (jsluice) and network fetch are not exercised here; we
test the JSONL parsing, relative-URL resolution against the source JS
file, scope filtering, param extraction, and secret parsing — the logic
that turns jsluice's raw output into the framework's canonical files.
"""
from __future__ import annotations

from pathlib import Path

from modules import layout
from modules.jsluice import (
    _in_scope,
    _is_js_url,
    _iter_jsonl,
    _parse_secrets,
    _resolve_urls,
    build_param_urls,
    merge_params_into_nuclei_input,
)
from modules.utils import create_output_structure, write_json, write_lines


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
# _is_js_url — drives the recursive JS-of-JS fetch in scan()
# ----------------------------------------------------------------------
def test_is_js_url_matches_js_and_mjs():
    assert _is_js_url("https://x.com/static/chunk.42.js")
    assert _is_js_url("https://x.com/mod.mjs")
    assert _is_js_url("https://x.com/CHUNK.JS")  # case-insensitive


def test_is_js_url_ignores_query_and_rejects_non_js():
    assert _is_js_url("https://x.com/app.js?v=123")
    assert not _is_js_url("https://x.com/app.json")
    assert not _is_js_url("https://x.com/api/users")


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


# ----------------------------------------------------------------------
# build_param_urls — feed jsluice param intel to the param shortlist
# ----------------------------------------------------------------------
def test_build_param_urls_attaches_query_and_body_params():
    recs = [
        {"url": "https://x.com/search?q=", "method": "GET",
         "queryParams": ["q"], "bodyParams": []},
        {"url": "https://x.com/login", "method": "POST",
         "queryParams": [], "bodyParams": ["user", "pass"]},
    ]
    out = build_param_urls(recs)
    # GET query rebuilt from queryParams; POST body params become a query
    # string so nuclei can fuzz them (arjun, GET-only, never would).
    assert out == [
        "https://x.com/search?q=",
        "https://x.com/login?user=&pass=",
    ]


def test_build_param_urls_skips_records_without_params():
    recs = [{"url": "https://x.com/api", "method": "GET",
             "queryParams": [], "bodyParams": []}]
    assert build_param_urls(recs) == []


def test_build_param_urls_dedupes_and_rebuilds_query():
    recs = [
        {"url": "https://x.com/a?id=EXPR", "queryParams": ["id"], "bodyParams": []},
        {"url": "https://x.com/a?id=", "queryParams": ["id"], "bodyParams": []},
    ]
    # both collapse to the same rebuilt URL → deduped
    assert build_param_urls(recs) == ["https://x.com/a?id="]


def test_build_param_urls_handles_garbage():
    assert build_param_urls([]) == []
    assert build_param_urls([{"url": ""}, "not-a-dict", None]) == []


# ----------------------------------------------------------------------
# merge_params_into_nuclei_input — append to parameterized_urls.txt
# ----------------------------------------------------------------------
def test_merge_appends_jsluice_params_deduped(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    # arjun already produced one URL
    write_lines(layout.path(base, "parameterized_urls.txt"),
                ["https://x.com/existing?a="])
    write_json(layout.path(base, "jsluice_params.json"), [
        {"url": "https://x.com/new", "queryParams": ["id"], "bodyParams": []},
        {"url": "https://x.com/existing?a=", "queryParams": ["a"], "bodyParams": []},
    ])
    res = merge_params_into_nuclei_input(base)
    out = (layout.path(base, "parameterized_urls.txt")).read_text().split()
    assert res["count"] == 1                       # only /new is added
    assert "https://x.com/new?id=" in out
    assert out.count("https://x.com/existing?a=") == 1  # no duplicate


def test_merge_creates_file_when_arjun_skipped(tmp_path: Path):
    """When arjun was skipped, parameterized_urls.txt may be empty/missing —
    jsluice params alone should still populate the shortlist."""
    base = create_output_structure("example.com", root=str(tmp_path))
    write_json(layout.path(base, "jsluice_params.json"), [
        {"url": "https://x.com/p", "queryParams": ["x"], "bodyParams": ["y"]},
    ])
    res = merge_params_into_nuclei_input(base)
    assert res["count"] == 1
    out = read_target(base)
    assert out == ["https://x.com/p?x=&y="]


def test_merge_noop_when_no_params(tmp_path: Path):
    base = create_output_structure("example.com", root=str(tmp_path))
    write_json(layout.path(base, "jsluice_params.json"), [])
    res = merge_params_into_nuclei_input(base)
    assert res["count"] == 0


def read_target(base: Path) -> list[str]:
    from modules.utils import read_lines
    return read_lines(layout.path(base, "parameterized_urls.txt"))


# ----------------------------------------------------------------------
# Recursion budget — regression guard
# ----------------------------------------------------------------------
# Recursion into JS-referenced JS (webpack chunks, lazy-loaded bundles)
# used to share the ``max_js`` budget with the first pass. Round 0 takes
# ``js_lines[:max_js]``, so on any target with >= max_js JS URLs the
# remaining budget was 0 and the loop broke before fetching anything —
# silently disabling the feature on exactly the SPA-heavy targets it
# exists for (3,956 / 815 / 4,961 JS URLs against a 500 cap in the stored
# runs). Recursion now has its own ``max_js_recurse`` budget.
def _recursion_harness(monkeypatch, tmp_path: Path, cfg_jsluice: dict,
                       n_js_urls: int):
    """Run jsluice.scan with fetch + binary mocked; return (result, rounds)."""
    from modules import jsluice as js_mod

    base = create_output_structure("example.com", root=str(tmp_path))
    js_file = layout.path(base, "js_urls.txt")
    write_lines(js_file, [f"https://example.com/a{i}.js" for i in range(n_js_urls)])

    fetch_calls: list[list[str]] = []

    def fake_fetch(urls, dest_dir, *, timeout, max_workers=12):
        fetch_calls.append(list(urls))
        mapping = {f"{dest_dir}/{i:04d}.js": u for i, u in enumerate(urls)}
        detail = [{"url": u, "status": 200, "bytes": 10} for u in urls]
        return mapping, detail

    chain_len = cfg_jsluice.pop("_chain_len", None)

    def fake_analyze(files, modes, fname_to_url, domain, **kwargs):
        # Each pass reports one *new* JS URL, so recursion has something to
        # chase. With _chain_len the chain is finite, so the walk can
        # actually converge — that is what "until no JS left" means.
        n = len(fetch_calls)
        if chain_len is not None and n > chain_len:
            return ([], [], [], [], {})
        return ([f"https://example.com/chunk{n}.js"], [], [], [], {})

    monkeypatch.setattr(js_mod, "_fetch_js", fake_fetch)
    monkeypatch.setattr(js_mod, "_analyze", fake_analyze)
    monkeypatch.setattr(js_mod.runner, "tool_available", lambda b: True)

    res = js_mod.scan(js_file, base, {"jsluice": cfg_jsluice})
    return res, fetch_calls


def test_recursion_runs_when_first_pass_fills_max_js(monkeypatch, tmp_path: Path):
    # The regression: n_js_urls == max_js left zero shared budget.
    res, calls = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 5, "js_recurse_depth": 2, "max_js_recurse": 300,
         "mode": ["urls"]},
        n_js_urls=5,
    )
    assert res["extra"]["js_recursed_rounds"] == 2, "recursion must still run"
    assert len(calls) == 3, "one initial fetch + two recursion rounds"


def test_recursion_budget_is_independent_of_max_js(monkeypatch, tmp_path: Path):
    res, calls = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 2, "js_recurse_depth": 3, "max_js_recurse": 2,
         "mode": ["urls"]},
        n_js_urls=10,
    )
    # First pass capped at max_js=2; recursion gets its own 2, one per round.
    assert len(calls[0]) == 2
    assert res["extra"]["js_recursed_rounds"] == 2
    assert res["extra"]["js_recursed_fetched"] == 2


def test_max_js_recurse_zero_means_depth_only(monkeypatch, tmp_path: Path):
    res, _ = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 3, "js_recurse_depth": 3, "max_js_recurse": 0,
         "mode": ["urls"]},
        n_js_urls=3,
    )
    assert res["extra"]["js_recursed_rounds"] == 3


def test_recurse_depth_zero_disables_recursion(monkeypatch, tmp_path: Path):
    res, calls = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 5, "js_recurse_depth": 0, "max_js_recurse": 300,
         "mode": ["urls"]},
        n_js_urls=5,
    )
    assert res["extra"]["js_recursed_rounds"] == 0
    assert len(calls) == 1


def test_recursion_runs_until_no_js_left(monkeypatch, tmp_path: Path):
    """js_recurse_depth < 0 walks the chunk graph to exhaustion."""
    res, calls = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 5, "js_recurse_depth": -1, "max_js_recurse": 0,
         "mode": ["urls"], "_chain_len": 4},
        n_js_urls=5,
    )
    # initial fetch + one round per link in the chain, then it converges
    assert res["extra"]["js_recursed_rounds"] == 4
    assert len(calls) == 5
    assert res["extra"]["js_recurse_exhausted"] is True
    assert res["extra"]["js_pending_unfetched"] == 0


def test_exhausted_flag_false_when_budget_truncates(monkeypatch, tmp_path: Path):
    """A budget cut-off must not look like convergence."""
    res, _ = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 5, "js_recurse_depth": -1, "max_js_recurse": 2,
         "mode": ["urls"]},   # infinite chain
        n_js_urls=5,
    )
    assert res["extra"]["js_recurse_exhausted"] is False
    assert res["extra"]["js_pending_unfetched"] >= 1


def test_unbounded_recursion_has_runaway_guard(monkeypatch, tmp_path: Path):
    """An endless chunk graph stops at _MAX_RECURSE_ROUNDS, not forever."""
    from modules import jsluice as js_mod
    res, _ = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 5, "js_recurse_depth": -1, "max_js_recurse": 0,
         "mode": ["urls"]},   # infinite chain, no fetch budget
        n_js_urls=5,
    )
    assert res["extra"]["js_recursed_rounds"] == js_mod._MAX_RECURSE_ROUNDS


def test_budget_trimmed_js_is_not_dropped(monkeypatch, tmp_path: Path):
    """JS trimmed by a round's budget stays queued for the next round.

    The old moving-frontier loop discarded it, so the walk could never
    converge no matter how deep it was allowed to go.
    """
    from modules import jsluice as js_mod

    base = create_output_structure("example.com", root=str(tmp_path))
    js_file = layout.path(base, "js_urls.txt")
    write_lines(js_file, ["https://example.com/entry.js"])

    fetched: list[str] = []

    def fake_fetch(urls, dest_dir, *, timeout, max_workers=12):
        fetched.extend(urls)
        mapping = {f"{dest_dir}/{i:04d}.js": u for i, u in enumerate(urls)}
        return mapping, [{"url": u, "status": 200, "bytes": 10} for u in urls]

    def fake_analyze(files, modes, fname_to_url, domain, **kwargs):
        # The entry point references three chunks at once; a budget of one
        # per round means two get deferred rather than lost.
        if len(fetched) == 1:
            return ([f"https://example.com/c{i}.js" for i in range(3)],
                    [], [], [], {})
        return ([], [], [], [], {})

    monkeypatch.setattr(js_mod, "_fetch_js", fake_fetch)
    monkeypatch.setattr(js_mod, "_analyze", fake_analyze)
    monkeypatch.setattr(js_mod.runner, "tool_available", lambda b: True)

    res = js_mod.scan(js_file, base, {"jsluice": {
        "max_js": 1, "js_recurse_depth": -1, "max_js_recurse": 0,
        "mode": ["urls"]}})

    for i in range(3):
        assert f"https://example.com/c{i}.js" in fetched, "deferred JS was dropped"
    assert res["extra"]["js_recurse_exhausted"] is True


def test_failed_fetch_round_does_not_abort_walk(monkeypatch, tmp_path: Path):
    """One round where every fetch fails must not end the walk."""
    from modules import jsluice as js_mod

    base = create_output_structure("example.com", root=str(tmp_path))
    js_file = layout.path(base, "js_urls.txt")
    write_lines(js_file, ["https://example.com/entry.js"])
    fetched: list[str] = []

    def fake_fetch(urls, dest_dir, *, timeout, max_workers=12):
        fetched.extend(urls)
        detail = [{"url": u, "status": 0, "bytes": 0} for u in urls]
        if any("dead" in u for u in urls):
            return {}, detail          # every fetch in this round failed
        return {f"{dest_dir}/0.js": urls[0]}, detail

    def fake_analyze(files, modes, fname_to_url, domain, **kwargs):
        if len(fetched) == 1:
            return (["https://example.com/dead.js",
                     "https://example.com/live.js"], [], [], [], {})
        return ([], [], [], [], {})

    monkeypatch.setattr(js_mod, "_fetch_js", fake_fetch)
    monkeypatch.setattr(js_mod, "_analyze", fake_analyze)
    monkeypatch.setattr(js_mod.runner, "tool_available", lambda b: True)

    js_mod.scan(js_file, base, {"jsluice": {
        "max_js": 1, "js_recurse_depth": -1, "max_js_recurse": 0,
        "mode": ["urls"]}})
    assert "https://example.com/live.js" in fetched, \
        "a dead round must not strand the queue"


def test_recursion_stops_on_time_budget(monkeypatch, tmp_path: Path):
    """Wall clock bounds an unbounded walk; stage timeout only bounds one
    jsluice subprocess, so without this the loop could run for hours."""
    from modules import jsluice as js_mod

    clock = {"t": 0.0}
    monkeypatch.setattr(js_mod.time, "monotonic", lambda: clock["t"])

    base = create_output_structure("example.com", root=str(tmp_path))
    js_file = layout.path(base, "js_urls.txt")
    write_lines(js_file, ["https://example.com/entry.js"])

    n = {"i": 0}

    def fake_fetch(urls, dest_dir, *, timeout, max_workers=12):
        clock["t"] += 10.0          # each round burns 10s
        n["i"] += 1
        mapping = {f"{dest_dir}/{i}.js": u for i, u in enumerate(urls)}
        return mapping, [{"url": u, "status": 200, "bytes": 1} for u in urls]

    def fake_analyze(files, modes, fname_to_url, domain, **kwargs):
        return ([f"https://example.com/c{n['i']}.js"], [], [], [], {})

    monkeypatch.setattr(js_mod, "_fetch_js", fake_fetch)
    monkeypatch.setattr(js_mod, "_analyze", fake_analyze)
    monkeypatch.setattr(js_mod.runner, "tool_available", lambda b: True)

    res = js_mod.scan(js_file, base, {"jsluice": {
        "max_js": 1, "js_recurse_depth": -1, "max_js_recurse": 0,
        "recurse_time_budget": 25, "mode": ["urls"]}})

    # The clock starts after the initial fetch (t=10), so elapsed is checked
    # at 0s, 10s and 20s — three rounds run — then 30s > 25s stops the walk.
    assert res["extra"]["js_recursed_rounds"] == 3
    assert res["extra"]["js_recurse_exhausted"] is False


def test_time_budget_zero_means_no_time_limit(monkeypatch, tmp_path: Path):
    res, _ = _recursion_harness(
        monkeypatch, tmp_path,
        {"max_js": 2, "js_recurse_depth": -1, "max_js_recurse": 0,
         "recurse_time_budget": 0, "mode": ["urls"], "_chain_len": 3},
        n_js_urls=2,
    )
    assert res["extra"]["js_recursed_rounds"] == 3
    assert res["extra"]["js_recurse_exhausted"] is True
