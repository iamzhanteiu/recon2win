"""Tests for modules/report.py.

We build a small but realistic output tree under tmp_path, then verify the
report module:
  * reads every file safely
  * survives missing optional files
  * classifies URLs as high-value
  * extracts interesting API paths
  * generates valid HTML / Markdown / JSON artefacts
  * uses clickable relative links
  * groups nuclei findings by severity
  * includes config snapshot, tool versions, and stage classifications
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from modules import baseline, layout
from modules.report import (
    ReportBuilder,
    ReportInputs,
    build_report,
    classify_stages,
    classify_url,
    count_lines,
    endpoint_existence,
    existence_counts,
    extract_interesting_api_paths,
    form_score,
    fuzz_coverage,
    is_high_value,
    load_json_safe,
    missing_tools_from_skips,
    parse_httpx_jsonl,
    parse_nuclei_summary,
    rank_forms,
    rel_link,
    severity_rank,
    summarize_url_surface,
)


# ----------------------------------------------------------------------
# summarize_url_surface — status / content-type breakdown
# ----------------------------------------------------------------------
def test_summarize_url_surface_counts_sorts_and_flags():
    rows = [
        {"url": "https://x/a", "status_code": 200, "content_type": "text/html; charset=utf-8"},
        {"url": "https://x/b", "status_code": 403, "content_type": "text/html"},
        {"url": "https://x/c", "status_code": 403, "content_type": "text/html"},
        {"url": "https://x/api", "status_code": 200, "content_type": "application/json"},
        {"url": "https://x/gated", "status_code": 401},   # no ctype → "-"
        {"status_code": 200},                              # no url → skipped
    ]
    s = summarize_url_surface(rows)
    assert s["total"] == 5
    # counts: 200×2 (a, api), 403×2 (b, c), 401×1
    assert s["by_status"] == {200: 2, 403: 2, 401: 1}
    # ties keep insertion order (200 seen before 403), 401 last (lower count)
    assert list(s["by_status"]) == [200, 403, 401]
    assert s["by_type"]["text/html"] == 3      # charset param stripped + merged
    assert s["by_type"]["-"] == 1
    assert s["apis"] == 1                       # application/json
    assert s["auth_gated"] == 3                 # 403 + 403 + 401


def test_summarize_url_surface_empty():
    s = summarize_url_surface([])
    assert s == {"total": 0, "by_status": {}, "by_type": {}, "apis": 0, "auth_gated": 0}


# ----------------------------------------------------------------------
# fuzz_coverage — surfaces fuzz_targets.select_targets()'s stats, which
# previously landed in extra.selection and were never read back out.
# ----------------------------------------------------------------------
def test_fuzz_coverage_reads_selection_stats():
    stage_results = [
        {"stage": "dirsearch", "status": "success", "extra": {
            "selection": {"input": 312, "deduped": 250, "waf_skipped": 0,
                         "blanket_skipped": 11, "selected": 50, "capped": 1}}},
    ]
    sel = fuzz_coverage(stage_results, "dirsearch")
    assert sel["input"] == 312
    assert sel["capped"] == 1


def test_fuzz_coverage_missing_stage_returns_empty():
    assert fuzz_coverage([], "dirsearch") == {}
    assert fuzz_coverage([{"stage": "ffuf", "extra": {}}], "dirsearch") == {}


def test_fuzz_coverage_missing_selection_key_returns_empty():
    assert fuzz_coverage(
        [{"stage": "dirsearch", "extra": {"mode": "wordlist"}}], "dirsearch",
    ) == {}


# ----------------------------------------------------------------------
# endpoint_existence / existence_counts — classify ffuf/dirsearch hits by
# response BEHAVIOUR (modules/existence.py) instead of status code alone.
# ----------------------------------------------------------------------
def test_endpoint_existence_joins_detail_body_and_baseline():
    detail_index = {
        "https://x.example.com/api/users/1": {
            "status_code": 400, "content_type": "application/json",
            "words": 12, "lines": 3},
        "https://x.example.com/xyz123": {
            "status_code": 403, "content_type": "text/html",
            "words": 13, "lines": 11},
    }
    body_snippets = {
        "https://x.example.com/api/users/1": "Missing required parameter: id",
    }
    # x.example.com consistently answers 403/html/13w/11l to guaranteed-fake
    # paths — the exact shape of the second hit below.
    fake_shape = (403, "html", "", 13, 11)
    baselines = {"x.example.com": baseline.Baseline("x.example.com", shape=fake_shape)}
    hit_urls = {
        "https://x.example.com/api/users/1": {"ffuf"},
        "https://x.example.com/xyz123": {"ffuf", "dirsearch"},
    }
    results = endpoint_existence(hit_urls, detail_index, body_snippets, baselines)
    by_url = {r["url"]: r for r in results}

    # one signal category + an ambiguous status (400 isn't in the "strong"
    # status set) reaches LIKELY, not CONFIRMED — see modules/existence.py's
    # own test suite for the full verdict matrix this module just wires up.
    likely = by_url["https://x.example.com/api/users/1"]
    assert likely["verdict"] == "likely"
    assert likely["sources"] == ["ffuf"]
    assert likely["status"] == 400

    not_found = by_url["https://x.example.com/xyz123"]
    assert not_found["verdict"] == "not_found"
    assert not_found["sources"] == ["dirsearch", "ffuf"]


def test_endpoint_existence_no_detail_row_or_baseline_falls_back_to_unknown():
    results = endpoint_existence(
        {"https://x.example.com/weird": {"ffuf"}}, {}, {}, {},
    )
    assert results == [{
        "url": "https://x.example.com/weird", "sources": ["ffuf"],
        "status": None, "verdict": "unknown", "reasons": [],
    }]


def test_existence_counts_tallies_and_fills_zero_keys():
    counts = existence_counts([
        {"verdict": "confirmed"}, {"verdict": "confirmed"}, {"verdict": "not_found"},
    ])
    assert counts == {"confirmed": 2, "likely": 0, "unknown": 0, "not_found": 1}


def test_existence_counts_empty_list():
    assert existence_counts([]) == {
        "confirmed": 0, "likely": 0, "unknown": 0, "not_found": 0}


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
@pytest.fixture
def fake_outputs(tmp_path: Path) -> Path:
    """Populate ``tmp_path`` with a realistic but minimal output tree
    using the v2 layout (raw grouped per stage, findings per kind)."""
    proc = tmp_path / "processed"
    base = tmp_path
    raw_sub = base / "raw" / "subdomain"
    raw_cd = base / "raw" / "content_discovery"
    raw_ds = base / "raw" / "dirsearch"
    raw_ff = base / "raw" / "ffuf"
    raw_wm = base / "raw" / "waymore"
    raw_ar = base / "raw" / "arjun"
    fnd_def = base / "findings" / "default"
    logs = base / "logs"
    for d in (raw_sub, raw_cd, raw_ds, raw_ff, raw_wm, raw_ar,
              proc, fnd_def, logs):
        d.mkdir(parents=True, exist_ok=True)

    # raw/subdomain/
    (raw_sub / "subfinder.txt").write_text("a.example.com\nb.example.com\n")
    (raw_sub / "amass.txt").write_text("c.example.com\n")
    (raw_sub / "chaos.txt").write_text("")
    # raw/content_discovery/
    (raw_cd / "katana_urls.txt").write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
    )
    (raw_cd / "urlfinder_urls.txt").write_text("https://example.com/api/users\n")
    # raw/dirsearch/
    (raw_ds / "dirsearch_raw.txt").write_text(
        "200  10B  https://example.com/.env\n"
        "200   5B  https://example.com/.git/HEAD\n"
    )
    (raw_ds / "merged_wordlists.txt").write_text("/.env\n/.git\n/admin\n")
    (raw_ds / "targets.txt").write_text("https://a.example.com\n")
    # raw/ffuf/
    (raw_ff / "ffuf_raw.txt").write_text(
        "200 https://example.com/admin\n301 https://example.com/api/\n"
    )
    (raw_ff / "merged_wordlists.txt").write_text("admin\napi\n")
    # raw/waymore/
    (raw_wm / "waymore_raw.txt").write_text("https://example.com/old/login\n")
    # raw/arjun/
    (raw_ar / "input_subset.txt").write_text("https://example.com/login\n")

    # processed
    (layout.path(base, "subdomains.txt")).write_text("a.example.com\nb.example.com\nc.example.com\n")
    (layout.path(base, "resolved.txt")).write_text("a.example.com\nb.example.com\n")
    (layout.path(base, "resolved_detail.json")).write_text(json.dumps([
        {"subdomain": "a.example.com", "ip": "1.2.3.4",
         "asn": {"asn": "AS13335", "name": "Cloudflare"}, "cname": None},
        {"subdomain": "b.example.com", "ip": "5.6.7.8",
         "asn": {"asn": "AS16509", "name": "Amazon"}, "cname": "edge.example.com"},
    ]))
    (layout.path(base, "alive.txt")).write_text(
        "https://a.example.com\nhttps://b.example.com\n"
    )
    (layout.path(base, "alive_detail.json")).write_text(json.dumps([
        {"url": "https://a.example.com", "input": "a.example.com",
         "status_code": 200, "title": "Login", "content_type": "text/html",
         "content_length": 1234, "webserver": "nginx", "tech": "PHP"},
        {"url": "https://b.example.com", "input": "b.example.com",
         "status_code": 200, "title": "API", "content_type": "application/json",
         "content_length": 567, "webserver": "nginx", "tech": "Node.js"},
    ]))
    (layout.path(base, "alive_table.txt")).write_text(
        "200  1234  text/html  https://a.example.com\n"
    )
    (layout.path(base, "crawler_urls.txt")).write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/api/users\n"
    )
    (layout.path(base, "dirsearch_urls.txt")).write_text(
        "https://example.com/.env\nhttps://example.com/.git/HEAD\n"
    )
    (layout.path(base, "ffuf_urls.txt")).write_text(
        "https://example.com/admin\nhttps://example.com/api/\n"
    )
    (layout.path(base, "fuzz_recurse_urls.txt")).write_text(
        "https://example.com/api/keys\n"
    )
    (layout.path(base, "waymore_urls.txt")).write_text("https://example.com/old/login\n")
    (layout.path(base, "all_urls.txt")).write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/.env\nhttps://example.com/api/users\n"
        "https://example.com/app.js\n"
    )
    (layout.path(base, "js_urls.txt")).write_text("https://example.com/app.js\n")
    (layout.path(base, "dynamic_urls.txt")).write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/api/users\n"
        "https://example.com/.env\nhttps://example.com/.git/HEAD\n"
    )
    (layout.path(base, "xnlinkfinder_endpoints.txt")).write_text(
        "/api/v1/users\n/api/v1/login\n/graphql/query\n"
    )
    (layout.path(base, "xnlinkfinder_urls.txt")).write_text(
        "https://example.com/api/v1/users\n"
        "https://example.com/graphql/query\n"
    )
    (layout.path(base, "alive_urls.txt")).write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/.env\nhttps://example.com/.git/HEAD\n"
    )
    (layout.path(base, "alive_urls_detail.json")).write_text(json.dumps([
        {"url": "https://example.com/login", "status_code": 200,
         "content_length": 900, "content_type": "text/html"},
    ]))
    (layout.path(base, "alive_urls_table.txt")).write_text(
        "200  900  text/html  https://example.com/login\n"
    )
    (layout.path(base, "arjun_params.txt")).write_text(
        "[200] https://example.com/login?id=&q=\n"
        "[200] https://example.com/admin?debug=\n"
    )
    (layout.path(base, "parameterized_urls.txt")).write_text(
        "https://example.com/login?id=&q=\n"
        "https://example.com/admin?debug=\n"
    )

    # findings/<kind>/
    (fnd_def / "nuclei.txt").write_text(
        "https://a.example.com\nhttps://b.example.com\n"
        "https://example.com/login?id=\n"
    )
    (fnd_def / "nuclei.json").write_text(json.dumps({
        "findings": [
            {"template-id": "tech-detect", "info": {"name": "Nginx",
             "severity": "info"}, "matched-at": "https://a.example.com"},
            {"template-id": "exposed-env", "info": {"name": "Exposed .env",
             "severity": "high"}, "matched-at": "https://b.example.com/.env",
             "matcher-name": "env-file", "extracted-results": ["DB_PASS=hunter2"]},
            {"template-id": "sqli-error", "info": {"name": "SQL error",
             "severity": "critical"}, "matched-at": "https://example.com/login?id=",
             "matcher-name": "error-pattern"},
        ],
        "severity_count": {"info": 1, "high": 1, "medium": 0, "low": 0, "critical": 1},
    }))

    # findings/jsluice_secrets.json (findings root, not per-kind)
    (base / "findings" / "jsluice_secrets.json").write_text(json.dumps({
        "findings": [
            {"kind": "AWSAccessKey", "severity": "high",
             "url": "https://example.com/app.js", "data": {"key": "AKIAEXAMPLE123"}},
            {"kind": "GenericToken", "severity": "low",
             "url": "https://example.com/vendor.js", "data": {"token": "abc123"}},
        ],
        "severity_count": {"high": 1, "low": 1},
    }))

    # processed/jsluice_* — the AST half of the JS analysis
    (layout.path(base, "jsluice_endpoints.txt")).write_text(
        "/api/v2/session\n/api/v2/upload\n"
    )
    (layout.path(base, "jsluice_urls.txt")).write_text(
        "https://example.com/api/v2/session\n"
    )
    (layout.path(base, "jsluice_params.json")).write_text(json.dumps([
        {"url": "https://example.com/api/v2/session", "method": "POST",
         "queryParams": ["lang"], "bodyParams": ["email", "password"]},
        {"url": "https://example.com/search", "method": "",
         "queryParams": ["q"], "bodyParams": []},
    ]))
    (layout.path(base, "jsluice_js_detail.json")).write_text(json.dumps([
        {"url": "https://example.com/app.js", "status_code": 200,
         "content_type": "application/javascript", "content_length": 4096},
        {"url": "https://example.com/static/chunks/missing-chunk.js",
         "status_code": 404, "content_type": "text/html", "content_length": 0},
    ]))
    (layout.path(base, "jsluice_js_table.txt")).write_text(
        " ST     LENGTH  CONTENT-TYPE              URL\n"
        "200       4096  application/javascript    https://example.com/app.js\n"
        "404          0  text/html                 "
        "https://example.com/static/chunks/missing-chunk.js\n"
    )
    (layout.path(base, "jsluice_method_check.json")).write_text(json.dumps([
        {"url": "https://example.com/api/v2/session", "method": "POST",
         "status": 200, "content_length": 512, "content_type": "application/json",
         "body_preview": "{\"token\":\"...\"}", "get_status": 404,
         "get_content_length": 0},
    ]))
    (layout.path(base, "jsluice_method_check_table.txt")).write_text(
        "METHOD   ST     LENGTH  CONTENT-TYPE               GET-ST  URL\n"
        "POST    200        512  application/json               404  "
        "https://example.com/api/v2/session\n"
    )

    # processed/apidocs_* + findings/api_docs.json — API documentation
    (layout.path(base, "apidocs_urls.txt")).write_text(
        "https://api.example.com/v2/users\n"
        "https://api.example.com/v2/users/{id}\n"
    )
    (layout.path(base, "apidocs_params.txt")).write_text(
        "https://api.example.com/v2/users?page=&limit=\n"
    )
    (base / "findings" / "api_docs.json").write_text(json.dumps({
        "specs": [{
            "url": "https://api.example.com/openapi.json",
            "kind": "openapi", "version": "3.0.1", "title": "Billing API",
            "api_version": "2.1", "paths": 2,
            "methods": {"get": 2, "post": 1},
            "security_schemes": ["bearerAuth"],
            "servers": ["https://api.example.com/v2"],
        }],
        "ui": [{"url": "https://example.com/swagger-ui.html", "status": 200}],
        "discovery": [],
        "osint": [{"source": "postman", "kind": "workspace",
                   "name": "Example Public API", "score": 310,
                   "url": "https://www.postman.com/example-api", "id": ""}],
        "probe": {"hosts": 2, "paths": 60, "requests": 120, "responses": 3},
    }))

    # findings/misconfig_probe.json — server/microservice misconfig probe
    (layout.path(base, "misconfig_urls.txt")).write_text(
        "https://app3.example.com/actuator/env\n"
    )
    (base / "findings" / "misconfig_probe.json").write_text(json.dumps({
        "findings": [{
            "url": "https://app3.example.com/actuator/env",
            "service": "Spring Boot actuator/env", "confidence": "high",
            "status": 200,
        }],
        "hosts_probed": 3,
        "probe": {"hosts": 3, "paths": 30, "requests": 90, "responses": 5},
    }))

    # findings/graphql_schema.json — GraphQL introspection probe
    (base / "findings" / "graphql_schema.json").write_text(json.dumps({
        "targets": [{
            "url": "https://api.example.com/graphql", "status_code": 200,
            "query_fields": ["users", "me"],
            "mutation_fields": ["deleteUser", "createInvoice"],
            "subscription_fields": [],
            "type_count": 12,
            "types": ["User", "Invoice"],
        }],
        "probed": 5,
    }))

    # findings/cors.json — CORS misconfiguration probe
    (base / "findings" / "cors.json").write_text(json.dumps({
        "findings": [{
            "url": "https://api.example.com", "acao": "https://evil.invalid",
            "acac": True, "severity": "critical",
            "note": "reflects arbitrary Origin AND allows credentials",
        }],
        "probed": 2, "test_origin": "https://recon2win-cors-test.invalid",
    }))

    # findings/buckets.json — cloud storage bucket enumeration
    (base / "findings" / "buckets.json").write_text(json.dumps({
        "findings": [{
            "bucket": "example-uploads", "provider": "s3",
            "url": "https://example-uploads.s3.amazonaws.com/",
            "state": "public-listing", "severity": "critical",
        }],
        "azure_references": ["exampleacct"],
        "extracted": {"s3": ["example-uploads"], "gcs": []},
        "guessed_count": 20, "probed": 40,
    }))

    # findings/git_dump.json — .git exposure dump summary
    (base / "findings" / "git_dump.json").write_text(json.dumps({
        "hosts": [{
            "host": "https://staging.example.com", "ref": "ref: refs/heads/main",
            "files_in_index": 42, "files_recovered": 30, "files_skipped": 12,
            "output_dir": "raw/gitdump/repos/staging.example.com",
        }],
    }))

    # processed/screenshots_index.json — httpx -screenshot capture
    (layout.path(base, "screenshots_index.json")).write_text(json.dumps([
        {"url": "https://example.com", "status_code": 200, "title": "Example",
         "screenshot_path": "raw/httpx_screenshot/screenshots/example.png"},
    ]))

    # processed/forms.json — forms/inputs mined from the crawl
    (layout.path(base, "forms.json")).write_text(json.dumps({
        "forms": [
            {"url": "https://example.com/login", "action": "https://example.com/login",
             "method": "POST", "enctype": "application/x-www-form-urlencoded",
             "parameters": ["username", "password", "csrf"]},
            {"url": "https://example.com/upload", "action": "https://example.com/upload",
             "method": "POST", "enctype": "multipart/form-data",
             "parameters": ["file"]},
            {"url": "https://example.com/", "action": "https://example.com/search",
             "method": "GET", "enctype": "", "parameters": []},
        ],
        "count": 3,
    }))

    # responses/ — full ffuf/dirsearch response capture + preview
    (base / "responses").mkdir(parents=True, exist_ok=True)
    (base / "responses" / "index.md").write_text(
        "# Response previews — example.com\n\n| status | url |\n")
    (base / "responses" / "preview.json").write_text(json.dumps({
        "previews": [
            {"url": "https://example.com/admin", "status": 200,
             "content_length": 12, "sources": ["ffuf"], "snippet": "hi"},
        ],
        "stats": {"hits": 1, "fetched": 1, "capped": 0},
    }))

    # logs
    (logs / "commands.log").write_text(
        "[2026-06-23T10:00:00Z] [subdomain] subfinder -d example.com -all\n"
        "[2026-06-23T10:00:05Z] [dnsx] dnsx -l subdomains.txt -json\n"
    )
    (logs / "stages.json").write_text("[]")
    return base


# ----------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------
def test_count_lines_handles_missing_file(tmp_path: Path):
    assert count_lines(tmp_path / "nope.txt") == 0


def test_count_lines_counts_non_empty_only(tmp_path: Path):
    f = tmp_path / "f.txt"
    f.write_text("a\n\nb\n   \nc\n")
    assert count_lines(f) == 3


def test_load_json_safe_handles_missing(tmp_path: Path):
    assert load_json_safe(tmp_path / "nope.json") is None


def test_load_json_safe_handles_malformed(tmp_path: Path):
    f = tmp_path / "broken.json"
    f.write_text("not json at all")
    assert load_json_safe(f) is None


def test_load_json_safe_handles_empty(tmp_path: Path):
    f = tmp_path / "empty.json"
    f.write_text("")
    assert load_json_safe(f) is None


def test_parse_nuclei_summary_reads_structured_format(tmp_path: Path):
    p = tmp_path / "nuclei.json"
    p.write_text(json.dumps({
        "findings": [{"template-id": "t1", "info": {"severity": "high"}}],
        "severity_count": {"high": 1, "critical": 0},
    }))
    findings, sev = parse_nuclei_summary(p)
    assert len(findings) == 1
    assert sev["high"] == 1


def test_parse_nuclei_summary_handles_missing(tmp_path: Path):
    findings, sev = parse_nuclei_summary(tmp_path / "nope.json")
    assert findings == []
    assert sev == {}


def test_parse_nuclei_summary_handles_structured_format(tmp_path: Path):
    """The standard format ``modules/nuclei.py`` writes — must parse
    exactly as written."""
    import json as _json
    p = tmp_path / "nuclei.json"
    doc = {
        "findings": [
            {"template-id": "tech-detect",
             "info": {"severity": "info"},
             "matched-at": "https://a"},
            {"template-id": "exposed-env",
             "info": {"severity": "high"},
             "matched-at": "https://b/.env"},
        ],
        "severity_count": {"info": 1, "high": 1, "low": 0,
                           "medium": 0, "critical": 0},
    }
    p.write_text(_json.dumps(doc))
    findings, sev = parse_nuclei_summary(p)
    assert len(findings) == 2
    assert sev == {"info": 1, "high": 1, "low": 0,
                   "medium": 0, "critical": 0}


def test_parse_nuclei_summary_handles_raw_jsonl(tmp_path: Path):
    """Some nuclei v3.x builds write JSONL directly via -json-export.
    The report must still extract findings even if modules/nuclei.py
    didn't successfully overwrite the file with our structured format.
    """
    import json as _json
    p = tmp_path / "nuclei.json"
    lines = [
        _json.dumps({"template-id": "tech-detect",
                     "info": {"severity": "info"},
                     "matched-at": "https://a"}),
        _json.dumps({"template-id": "exposed-env",
                     "info": {"severity": "high"},
                     "matched-at": "https://b/.env"}),
    ]
    p.write_text("\n".join(lines) + "\n")
    findings, sev = parse_nuclei_summary(p)
    assert len(findings) == 2
    assert findings[0]["template-id"] == "tech-detect"
    # Severity breakdown still works on raw JSONL.
    assert sev.get("info") == 1
    assert sev.get("high") == 1


def test_parse_nuclei_summary_handles_raw_json_array(tmp_path: Path):
    """Other nuclei v3.x builds write the entire findings as a single
    JSON array on one line. The report must parse that too."""
    import json as _json
    p = tmp_path / "nuclei.json"
    arr = [
        {"template-id": "tech-detect",
         "info": {"severity": "info"},
         "matched-at": "https://a"},
        {"template-id": "php-detect",
         "info": {"severity": "low"},
         "matched-at": "https://b"},
    ]
    p.write_text(_json.dumps(arr))
    findings, sev = parse_nuclei_summary(p)
    assert len(findings) == 2
    assert sev.get("info") == 1
    assert sev.get("low") == 1


def test_parse_nuclei_summary_skips_non_dict_in_jsonl(tmp_path: Path):
    """JSONL can contain stray primitives (some templating quirks).
    Skip them defensively — same logic the stage parser uses."""
    import json as _json
    p = tmp_path / "nuclei.json"
    valid1 = _json.dumps({"template-id": "ok", "info": {"severity": "info"},
                          "matched-at": "https://a"})
    valid2 = _json.dumps({"template-id": "ok2", "info": {"severity": "high"},
                          "matched-at": "https://b"})
    p.write_text(valid1 + "\n[1, 2, 3]\n42\n" + valid2 + "\n")
    findings, sev = parse_nuclei_summary(p)
    assert len(findings) == 2
    assert sev.get("info") == 1
    assert sev.get("high") == 1


def test_parse_nuclei_summary_returns_empty_on_garbage(tmp_path: Path):
    """If the file is genuinely garbage, return empty rather than crash.
    The severity-count dict is always pre-populated with zeros for
    every severity — that's the shape the rest of the report expects."""
    p = tmp_path / "nuclei.json"
    p.write_text("not json at all\n[[[")
    findings, sev = parse_nuclei_summary(p)
    assert findings == []
    assert sum(sev.values()) == 0
    # Every known severity has a zero entry.
    assert all(v == 0 for v in sev.values())


# ----------------------------------------------------------------------
# Nuclei output parser — defensive against non-JSONL formats
# ----------------------------------------------------------------------
def test_nuclei_run_handles_json_array_output(tmp_path: Path, monkeypatch):
    """Some nuclei v3.x builds write the entire findings as a single
    JSON array (``[{...}, {...}]``) instead of JSONL. The parser must
    handle BOTH formats without crashing — and must NOT append the
    list itself into ``findings`` (which would later raise
    ``'list' object has no attribute 'get'``)."""
    import json as _json
    from modules import nuclei as nuclei_mod

    fdir = tmp_path / "findings" / "default"
    fdir.mkdir(parents=True)
    txt_out = fdir / "nuclei.txt"

    # nuclei writes a single JSON array with two findings; the canonical
    # nuclei.json is derived from what we parse back out of that stream.
    findings_doc = [
        {"template-id": "tech-detect",
         "info": {"name": "Nginx", "severity": "info"},
         "matched-at": "https://a"},
        {"template-id": "exposed-env",
         "info": {"name": ".env", "severity": "high"},
         "matched-at": "https://b/.env"},
    ]

    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_json.dumps(findings_doc))
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 1.0}
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    alive = tmp_path / "alive.txt"
    alive.write_text("https://a.example.com\n")
    res = nuclei_mod.default_scan(
        alive, tmp_path,
        cfg={"nuclei": {"default": {"enabled": True, "severity": ["info"]}}},
        resume=False, dry_run=False, skip=False,
    )
    # Both findings extracted despite JSON-array format.
    assert res["status"] == "success"
    assert res["count"] == 2
    # txt_out has the matched URLs.
    txt_content = txt_out.read_text()
    assert "https://a" in txt_content
    assert "https://b/.env" in txt_content


def test_nuclei_run_skips_non_dict_jsonl_lines(tmp_path: Path, monkeypatch):
    """If a JSONL line is a list (``[1, 2, 3]``) or primitive (rare,
    but possible from a third-party templating), the parser must
    skip it rather than append it to findings (which would crash
    later in ``f.get('matched-at')``)."""
    from modules import nuclei as nuclei_mod

    fdir = tmp_path / "findings" / "default"
    fdir.mkdir(parents=True)
    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        # Mix of valid finding, stray list, blank line, stray int, valid finding.
        out.write_text(
            '{"template-id": "t1", "info": {"severity": "info"}, "matched-at": "https://a"}\n'
            '[1, 2, 3]\n'
            '\n'
            '42\n'
            '{"template-id": "t2", "info": {"severity": "high"}, "matched-at": "https://b"}\n'
        )
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False,
                "success": True, "stdout_path": "", "stderr_path": "",
                "log_path": "", "duration": 1.0}
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    alive = tmp_path / "alive.txt"
    alive.write_text("https://a.example.com\n")
    res = nuclei_mod.default_scan(
        alive, tmp_path,
        cfg={"nuclei": {"default": {"enabled": True}}},
        resume=False, dry_run=False, skip=False,
    )
    # Only the two valid dict findings were extracted; the stray list
    # and integer didn't pollute the findings list.
    assert res["status"] == "success"
    assert res["count"] == 2
    extra = res.get("extra") or {}
    sev = extra.get("severity_count") or {}
    assert sev.get("info") == 1
    assert sev.get("high") == 1


def test_parse_httpx_jsonl_dedupes_corrupt_lines(tmp_path: Path):
    p = tmp_path / "h.jsonl"
    p.write_text(
        '{"url":"https://x"}\n'
        'this is not json\n'
        '{"url":"https://y"}\n'
    )
    out = parse_httpx_jsonl(p)
    assert len(out) == 2


def test_parse_httpx_jsonl_handles_empty(tmp_path: Path):
    p = tmp_path / "h.jsonl"
    p.write_text("")
    assert parse_httpx_jsonl(p) == []


# ----------------------------------------------------------------------
# classify_url / is_high_value
# ----------------------------------------------------------------------
@pytest.mark.parametrize("url,expected_labels", [
    ("https://example.com/admin/login",      ["admin panel", "login portal"]),
    ("https://example.com/.env",              ["env file"]),
    # .env.local contains the substring .env so both labels are emitted —
    # the longer one is emitted first.
    ("https://example.com/.env.local",        ["env file (local)", "env file"]),
    ("https://example.com/.env.production",   ["env file (production)", "env file"]),
    ("https://example.com/.git/HEAD",         ["git exposure"]),
    ("https://example.com/.git/config",       ["git config exposure"]),
    ("https://example.com/swagger/index.html",["swagger / openapi"]),
    ("https://example.com/graphql",           ["graphql endpoint"]),
    ("https://example.com/api/v1/users",      ["api endpoint", "api endpoint (versioned)", "versioned api"]),
    ("https://example.com/upload.php",        ["upload endpoint"]),
    ("https://example.com/.bak",              ["backup file"]),
    ("https://example.com/dump.sql",          ["database dump"]),
    ("https://example.com/jenkins",           ["jenkins"]),
    ("https://staging.example.com",           ["staging environment"]),
    ("https://dev.example.com",               ["dev environment"]),
    ("https://example.com/actuator/.env",    ["env file", "spring actuator"]),
    ("https://example.com/normal-page",       []),
])
def test_classify_url(url, expected_labels):
    labels = classify_url(url)
    # the expected set is a superset (we may emit more from overlapping patterns)
    for expected in expected_labels:
        assert expected in labels, f"expected {expected!r} in labels for {url}, got {labels}"
    # duplicates are not allowed
    assert len(labels) == len(set(labels)), f"duplicate labels for {url}: {labels}"


def test_is_high_value():
    assert is_high_value("https://example.com/admin") is True
    assert is_high_value("https://example.com/blog") is False


def test_classify_url_handles_empty():
    assert classify_url("") == []
    assert is_high_value("") is False


# ----------------------------------------------------------------------
# extract_interesting_api_paths
# ----------------------------------------------------------------------
def test_extract_interesting_api_paths():
    urls = [
        "https://example.com/login",          # no
        "https://example.com/api/v1/users",   # yes
        "https://example.com/graphql/query",  # yes
        "https://example.com/rest/products",  # yes
        "https://example.com/v2/orders",      # yes (versioned)
        "https://example.com/about",          # no
    ]
    out = extract_interesting_api_paths(urls)
    assert out == [
        "https://example.com/api/v1/users",
        "https://example.com/graphql/query",
        "https://example.com/rest/products",
        "https://example.com/v2/orders",
    ]


def test_extract_interesting_api_paths_dedupes():
    urls = [
        "https://example.com/api/v1/users",
        "https://example.com/api/v1/users",
    ]
    assert extract_interesting_api_paths(urls) == ["https://example.com/api/v1/users"]


# ----------------------------------------------------------------------
# rel_link
# ----------------------------------------------------------------------
def test_rel_link_from_report_to_raw(tmp_path: Path):
    report = tmp_path / "report" / "final_report.html"
    target = tmp_path / "raw" / "subdomain" / "subfinder.txt"
    # from report/final_report.html, target is ../raw/subdomain/subfinder.txt
    link = rel_link(report, target)
    assert link == "../raw/subdomain/subfinder.txt"


def test_rel_link_from_report_to_logs(tmp_path: Path):
    report = tmp_path / "report" / "final_report.html"
    target = tmp_path / "logs" / "commands.log"
    assert rel_link(report, target) == "../logs/commands.log"


# ----------------------------------------------------------------------
# classify_stages / missing_tools_from_skips
# ----------------------------------------------------------------------
def test_classify_stages_buckets_correctly():
    results = [
        {"stage": "subdomain", "status": "success"},
        {"stage": "dirsearch", "status": "skipped", "error": "binary not found"},
        {"stage": "nuclei",    "status": "failed",  "error": "exit=1"},
    ]
    buckets = classify_stages(results)
    assert len(buckets["success"]) == 1
    assert len(buckets["skipped"]) == 1
    assert len(buckets["failed"])  == 1


def test_missing_tools_extracts_unique_binaries():
    results = [
        {"stage": "katana",     "status": "skipped", "error": "katana binary not found"},
        {"stage": "dirsearch",  "status": "skipped", "error": "dirsearch binary not found"},
        {"stage": "nuclei_default", "status": "skipped", "error": "nuclei binary not found"},
        {"stage": "httpx_urls", "status": "skipped", "error": "httpx binary not found"},
        {"stage": "httpx_alive", "status": "skipped", "error": "httpx binary not found"},
        {"stage": "subdomain",  "status": "success"},
    ]
    out = missing_tools_from_skips(results)
    # suffixed stage names collapse to the binary: "nuclei_default" → nuclei,
    # and the two httpx_* stages report one missing tool, not two
    assert sorted(out) == ["dirsearch", "httpx", "katana", "nuclei"]


def test_missing_tools_ignores_unrelated_skips():
    results = [
        {"stage": "subdomain", "status": "skipped", "error": "--skip-subdomain"},
    ]
    assert missing_tools_from_skips(results) == []


# ----------------------------------------------------------------------
# severity_rank
# ----------------------------------------------------------------------
def test_severity_rank_orders_correctly():
    assert severity_rank("critical") > severity_rank("high")
    assert severity_rank("high") > severity_rank("medium")
    assert severity_rank("medium") > severity_rank("low")
    assert severity_rank("low") > severity_rank("info")
    assert severity_rank("unknown") < 0


# ----------------------------------------------------------------------
# ReportBuilder end-to-end
# ----------------------------------------------------------------------
def _make_inputs(output_dir: Path, *, with_findings=True) -> ReportInputs:
    return ReportInputs(
        output_dir=output_dir,
        domain="example.com",
        cfg={"output_root": "outputs"},
        cfg_path="config.yml",
        cfg_text="subdomain:\n  tools: [subfinder]\n",
        scan_start=datetime(2026, 6, 23, 10, 0, 0),
        scan_end=datetime(2026, 6, 23, 10, 5, 0),
        tool_versions={"subfinder": "v2.14.0", "nuclei": "v3.8.0"},
        stage_results=[
            {"stage": "subdomain", "status": "success", "count": 3, "error": None},
            {"stage": "dirsearch", "status": "skipped", "count": 0,
             "error": "dirsearch binary not found (optional, skipped)"},
            {"stage": "nuclei_default", "status": "success", "count": 2, "error": None},
        ],
        scan_mode="active",
    )


def test_collect_reads_every_file(fake_outputs: Path):
    builder = ReportBuilder(_make_inputs(fake_outputs))
    data = builder.collect()

    assert data["meta"]["domain"] == "example.com"
    assert data["meta"]["scan_duration_seconds"] == 300.0
    # counts match the fixture
    assert data["counts"]["subdomains"] == 3
    assert data["counts"]["resolved"] == 2
    assert data["counts"]["alive_hosts"] == 2
    assert data["counts"]["all_urls"] == 5
    assert data["counts"]["js_urls"] == 1
    assert data["counts"]["dynamic_urls"] == 5
    assert data["counts"]["parameterized_urls"] == 2
    assert data["counts"]["nuclei_default_findings"] == 3

    # every file in OUTPUT_FILES is in the inventory
    assert len(data["files"]) == len(ReportBuilder.OUTPUT_FILES)
    # all files exist in the fixture
    assert all(f["exists"] for f in data["files"])


def test_collect_survives_missing_files(tmp_path: Path):
    """No outputs at all — collect() must not raise."""
    builder = ReportBuilder(_make_inputs(tmp_path))
    data = builder.collect()
    # counts are all zero
    assert data["counts"]["subdomains"] == 0
    assert data["counts"]["nuclei_default_findings"] == 0
    # nothing exists
    assert all(not f["exists"] for f in data["files"])
    # high-value and recommendations are empty (not crashing)
    assert data["high_value_targets"] == []
    assert data["interesting_api_paths"] == []


def test_collect_survives_partial_outputs(tmp_path: Path):
    """Only a few outputs — must not crash on the missing ones."""
    (tmp_path / "processed").mkdir(parents=True)
    (tmp_path / "raw").mkdir(parents=True)
    (tmp_path / "logs").mkdir(parents=True)
    (tmp_path / "logs" / "commands.log").write_text("x")
    (layout.path(tmp_path, "all_urls.txt")).write_text("https://x.example.com\n")
    (layout.path(tmp_path, "alive.txt")).write_text("https://x.example.com\n")
    # write an interesting URL into one of the candidate files
    (layout.path(tmp_path, "alive_urls.txt")).write_text("https://x.example.com/admin\n")

    builder = ReportBuilder(_make_inputs(tmp_path))
    data = builder.collect()
    # admin URL still detected (because it is in alive_urls.txt — a candidate)
    assert any("admin panel" in h["categories"] for h in data["high_value_targets"])
    # most files are "not generated"
    missing = [f for f in data["files"] if not f["exists"]]
    assert len(missing) >= 25


def test_high_value_targets_in_fixture(fake_outputs: Path):
    builder = ReportBuilder(_make_inputs(fake_outputs))
    data = builder.collect()
    urls = {h["url"] for h in data["high_value_targets"]}
    assert "https://example.com/admin" in urls
    assert "https://example.com/.env" in urls
    assert "https://example.com/.git/HEAD" in urls


def test_high_value_targets_drop_404_and_429(tmp_path: Path):
    """A path that 404s doesn't exist; a 429 means the probe got
    rate-limited. Neither is a lead, so section 9 must not list them."""
    (tmp_path / "processed").mkdir(parents=True)
    (tmp_path / "raw").mkdir(parents=True)
    (tmp_path / "logs").mkdir(parents=True)
    (tmp_path / "logs" / "commands.log").write_text("x")
    (layout.path(tmp_path, "alive_urls.txt")).write_text(
        "https://x.example.com/admin\n"
        "https://x.example.com/.env\n"
        "https://x.example.com/.git/HEAD\n"
    )
    (layout.path(tmp_path, "alive_urls_detail.json")).write_text(json.dumps([
        {"url": "https://x.example.com/admin", "status_code": 403,
         "content_length": 10, "content_type": "text/html"},
        {"url": "https://x.example.com/.env", "status_code": 404,
         "content_length": 0, "content_type": "text/html"},
        {"url": "https://x.example.com/.git/HEAD", "status_code": 429,
         "content_length": 0, "content_type": "text/html"},
    ]))

    builder = ReportBuilder(_make_inputs(tmp_path))
    data = builder.collect()
    statuses = {h["url"]: h["status"] for h in data["high_value_targets"]}
    assert statuses == {"https://x.example.com/admin": 403}


def test_directory_listing_detected_from_title(tmp_path: Path):
    """An autoindex page has no URL keyword ("/uploads/" matches nothing in
    HIGH_VALUE_PATTERNS) — it only gives itself away via the response
    title, so it must still land in high_value_targets."""
    (tmp_path / "processed").mkdir(parents=True)
    (tmp_path / "raw").mkdir(parents=True)
    (tmp_path / "logs").mkdir(parents=True)
    (tmp_path / "logs" / "commands.log").write_text("x")
    (layout.path(tmp_path, "alive_urls.txt")).write_text(
        "https://x.example.com/uploads/\n"
        "https://x.example.com/about/\n"
    )
    (layout.path(tmp_path, "alive_urls_detail.json")).write_text(json.dumps([
        {"url": "https://x.example.com/uploads/", "status_code": 200,
         "content_length": 512, "content_type": "text/html",
         "title": "Index of /uploads"},
        {"url": "https://x.example.com/about/", "status_code": 200,
         "content_length": 512, "content_type": "text/html",
         "title": "About us"},
    ]))

    builder = ReportBuilder(_make_inputs(tmp_path))
    data = builder.collect()
    by_url = {h["url"]: h["categories"] for h in data["high_value_targets"]}
    assert "directory listing" in by_url["https://x.example.com/uploads/"]
    assert "https://x.example.com/about/" not in by_url


def test_is_directory_listing_helper():
    from modules.report import is_directory_listing
    assert is_directory_listing({"title": "Index of /backup"})
    assert is_directory_listing({"title": "index of /"})
    assert not is_directory_listing({"title": "Welcome to nginx"})
    assert not is_directory_listing(None)
    assert is_directory_listing(None, "<html><title>Index of /x</title></html>")


def test_interesting_api_paths_extracted(fake_outputs: Path):
    builder = ReportBuilder(_make_inputs(fake_outputs))
    data = builder.collect()
    # the fixture has /api/v1/users, /graphql/query, /api/users
    joined = "\n".join(data["interesting_api_paths"])
    assert "/api/v1/users" in joined
    assert "graphql" in joined.lower()


def test_stages_bucketed_in_collect(fake_outputs: Path):
    inputs = _make_inputs(fake_outputs)
    builder = ReportBuilder(inputs)
    data = builder.collect()
    assert len(data["stages"]["success"]) == 2
    assert len(data["stages"]["skipped"]) == 1
    assert "dirsearch" in data["missing_tools"]


# ----------------------------------------------------------------------
# HTML rendering
# ----------------------------------------------------------------------
def test_render_html_includes_all_required_sections(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    for section in [
        "1. Executive Summary",
        "2. Recon Coverage Summary",
        "3. JavaScript Analysis",
        "3.1 JavaScript Secrets",
        "4. Nuclei Findings",
        "4.1 GraphQL Introspection",
        "4.2 CORS Misconfiguration",
        "4.3 Cloud Storage Buckets",
        "4.4 Git Exposure Dump",
        "5. Asset Inventory",
        "6. DNS Inventory",
        "7. Content Discovery",
        "8. Parameter Discovery",
        "9. High-Value Targets",
        "10. Errors / Skipped / Missing Tools",
        "11. Manual Testing Recommendations",
        "12. Appendix",
    ]:
        assert section in html, f"missing section: {section}"


def test_html_secrets_section_lists_findings(fake_outputs: Path):
    builder = ReportBuilder(_make_inputs(fake_outputs))
    html = builder.render_html(builder.collect())
    assert "3.1 JavaScript Secrets" in html
    assert "AWSAccessKey" in html
    assert "AKIAEXAMPLE123" in html
    assert "https://example.com/app.js" in html
    # high severity should render before low (sorted by severity)
    assert html.index("AWSAccessKey") < html.index("GenericToken")


def test_collect_counts_jsluice_secrets(fake_outputs: Path):
    data = ReportBuilder(_make_inputs(fake_outputs)).collect()
    assert data["counts"]["jsluice_secrets"] == 2
    assert len(data["jsluice_secrets"]["findings"]) == 2


def test_html_secrets_section_empty_when_none(tmp_path: Path):
    # No jsluice_secrets.json → section renders a graceful "no secrets" note.
    for sub in ("findings", "processed", "report", "logs"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    builder = ReportBuilder(_make_inputs(tmp_path))
    html = builder.render_html(builder.collect())
    assert "3.1 JavaScript Secrets" in html
    assert "No secrets found" in html


def test_markdown_secrets_section(fake_outputs: Path):
    builder = ReportBuilder(_make_inputs(fake_outputs))
    md = builder.render_markdown(builder.collect())
    assert "## 3.1 JavaScript Secrets" in md
    assert "AWSAccessKey" in md


def test_render_html_uses_clickable_links(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    # every required link should be present (v2 layout)
    for rel in [
        "../raw/subdomain/subfinder.txt",
        "../raw/subdomain/amass.txt",
        "../raw/subdomain/chaos.txt",
        "../processed/hosts/subdomains.txt",
        "../processed/hosts/resolved.txt",
        "../processed/hosts/resolved_detail.json",
        "../processed/hosts/alive.txt",
        "../processed/hosts/alive_detail.json",
        "../raw/content_discovery/katana_urls.txt",
        "../raw/content_discovery/urlfinder_urls.txt",
        "../processed/sources/crawler_urls.txt",
        "../raw/dirsearch/dirsearch_raw.txt",
        "../raw/dirsearch/merged_wordlists.txt",
        "../raw/dirsearch/targets.txt",
        "../processed/sources/dirsearch_urls.txt",
        "../raw/ffuf/ffuf_raw.txt",
        "../raw/ffuf/merged_wordlists.txt",
        "../processed/sources/ffuf_urls.txt",
        "../raw/waymore/waymore_raw.txt",
        "../processed/sources/waymore_urls.txt",
        "../processed/corpus/all_urls.txt",
        "../processed/corpus/js_urls.txt",
        "../processed/corpus/dynamic_urls.txt",
        "../processed/js/xnlinkfinder_endpoints.txt",
        "../processed/js/xnlinkfinder_urls.txt",
        "../processed/hosts/alive_urls.txt",
        "../processed/hosts/alive_urls_detail.json",
        "../processed/targets/arjun_params.txt",
        "../raw/arjun/input_subset.txt",
        "../processed/targets/parameterized_urls.txt",
        "../findings/default/nuclei.txt",
        "../findings/default/nuclei.json",
        "../logs/commands.log",
        "../logs/stages.json",
    ]:
        assert f'href="{rel}"' in html, f"missing clickable link: {rel}"


def test_render_html_groups_nuclei_findings_by_severity(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    # severities that have findings in the fixture must appear (uppercased)
    # fixture has critical + high + info, all in the default scan
    for sev in ("CRITICAL", "HIGH", "INFO"):
        assert sev in html, f"missing severity section: {sev}"


def test_render_html_includes_searchable_filters(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    # filter input + filterTable script
    assert "filterTable" in html
    assert 'class="filter"' in html


def test_render_html_collapses_large_lists_by_default(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    assert "<details>" in html
    # findings sections use <details open> so they're visible
    assert "<details open>" in html


def test_render_html_embeds_css_and_tool_versions(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    assert "<style>" in html
    assert "v2.14.0" in html
    assert "v3.8.0" in html
    # config snapshot
    assert "config.yml" in html or "subdomain" in html


# ----------------------------------------------------------------------
# Markdown rendering
# ----------------------------------------------------------------------
def test_render_markdown_includes_all_sections(fake_outputs: Path):
    md = ReportBuilder(_make_inputs(fake_outputs)).render_markdown(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    for section in [
        "## 1. Executive Summary",
        "## 2. Recon Coverage Summary",
        "## 3. JavaScript Analysis",
        "## 4. Nuclei Findings",
        "## 4.1 GraphQL Introspection",
        "## 4.2 CORS Misconfiguration",
        "## 4.3 Cloud Storage Buckets",
        "## 4.4 Git Exposure Dump",
        "## 5. Asset Inventory",
        "## 6. DNS Inventory",
        "## 7. Content Discovery",
        "## 8. Parameter Discovery",
        "## 9. High-Value Targets",
        "## 10. Errors / Skipped / Missing Tools",
        "## 11. Manual Testing Recommendations",
        "## 12. Appendix",
    ]:
        assert section in md, f"missing section: {section}"


def test_render_markdown_uses_relative_links(fake_outputs: Path):
    md = ReportBuilder(_make_inputs(fake_outputs)).render_markdown(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    assert "](../raw/subdomain/subfinder.txt)" in md
    assert "](../logs/commands.log)" in md
    assert "](../findings/default/nuclei.json)" in md


def test_render_markdown_includes_timing(fake_outputs: Path):
    md = ReportBuilder(_make_inputs(fake_outputs)).render_markdown(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    assert "300" in md or "5.0" in md  # duration


# ----------------------------------------------------------------------
# write() — produces all three artefacts
# ----------------------------------------------------------------------
def test_write_creates_all_three_files(fake_outputs: Path):
    info = build_report(
        fake_outputs, "example.com", {"output_root": "outputs"},
        cfg_path="config.yml",
        cfg_text="subdomain:\n  tools: [subfinder]\n",
        scan_start=datetime(2026, 6, 23, 10, 0, 0),
        scan_end=datetime(2026, 6, 23, 10, 5, 0),
        tool_versions={"subfinder": "v2.14.0"},
        stage_results=[{"stage": "subdomain", "status": "success", "count": 3}],
    )
    assert Path(info["html"]).exists()
    assert Path(info["md"]).exists()
    assert Path(info["json"]).exists()
    assert info["html"].endswith("final_report.html")
    assert info["md"].endswith("final_report.md")
    assert info["json"].endswith("summary.json")


def test_write_html_is_self_contained(fake_outputs: Path):
    info = build_report(
        fake_outputs, "example.com", {},
        scan_start=datetime(2026, 6, 23, 10, 0, 0),
        scan_end=datetime(2026, 6, 23, 10, 5, 0),
    )
    html = Path(info["html"]).read_text()
    # self-contained: no external stylesheets, no remote images
    assert '<link rel="stylesheet"' not in html
    assert '<script src="http' not in html
    # has the <style> tag
    assert "<style>" in html


def test_write_json_round_trips(fake_outputs: Path):
    info = build_report(
        fake_outputs, "example.com", {},
        scan_start=datetime(2026, 6, 23, 10, 0, 0),
        scan_end=datetime(2026, 6, 23, 10, 5, 0),
    )
    j = json.loads(Path(info["json"]).read_text())
    assert j["meta"]["domain"] == "example.com"
    assert "counts" in j
    assert "files" in j
    assert "nuclei" in j
    assert "high_value_targets" in j


def test_write_handles_zero_outputs(tmp_path: Path):
    """build_report() must not raise on an empty output directory."""
    info = build_report(
        tmp_path, "example.com", {},
        scan_start=datetime.now(timezone.utc),
        scan_end=datetime.now(timezone.utc),
    )
    assert Path(info["html"]).exists()
    # counts all zero
    md = Path(info["md"]).read_text()
    assert "Not generated" in md or "Not recorded" in md


# ----------------------------------------------------------------------
# form_score / rank_forms — ordering the input surface by testing value
# ----------------------------------------------------------------------
def test_form_score_ranks_upload_above_post_above_get():
    upload = {"method": "POST", "enctype": "multipart/form-data",
              "parameters": ["file"]}
    post = {"method": "POST", "enctype": "", "parameters": ["a"]}
    get_empty = {"method": "GET", "enctype": "", "parameters": []}
    assert form_score(upload) > form_score(post) > form_score(get_empty)
    assert form_score(get_empty) == 0


def test_form_score_boosts_auth_fields():
    plain = {"method": "POST", "parameters": ["colour"]}
    auth = {"method": "POST", "parameters": ["password"]}
    assert form_score(auth) > form_score(plain)


def test_form_score_ignores_framework_plumbing():
    """Regression: on a real acronis.com run an ASP.NET postback stub
    outscored a login form 84 to 74, purely by carrying more hidden
    fields. __VIEWSTATE and friends are on every page of the stack and are
    never the target, so they must not buy rank."""
    viewstate_stub = {
        "method": "POST", "enctype": "application/x-www-form-urlencoded",
        "parameters": ["__EVENTTARGET", "__EVENTARGUMENT", "__LASTFOCUS",
                       "__VIEWSTATE", "__VIEWSTATEGENERATOR",
                       "__EVENTVALIDATION", "__SCROLLPOSITIONX"],
    }
    login = {
        "method": "POST", "enctype": "application/x-www-form-urlencoded",
        "parameters": ["csrfmiddlewaretoken", "next", "username", "password"],
    }
    assert form_score(login) > form_score(viewstate_stub)


def test_form_score_credits_csrf_token_without_treating_it_as_a_target():
    """A CSRF token means the form really changes state (worth a nudge),
    but the token field itself is never the bug (no keyword bonus)."""
    with_csrf = {"method": "POST", "parameters": ["_token", "colour"]}
    without = {"method": "POST", "parameters": ["colour"]}
    assert form_score(with_csrf) > form_score(without)
    # ...but far less than a real identity field is worth
    identity = {"method": "POST", "parameters": ["colour", "email"]}
    assert form_score(identity) > form_score(with_csrf)


def test_form_score_does_not_substring_match_keywords():
    """"id" inside "disasterRecovery" is not an identifier field."""
    false_hit = {"method": "POST", "parameters": ["disasterRecovery"]}
    real_hit = {"method": "POST", "parameters": ["user_id"]}
    assert form_score(real_hit) > form_score(false_hit)


def test_form_score_survives_junk_input():
    assert form_score({}) == 0
    assert form_score({"parameters": "not-a-list"}) == 0
    assert form_score("not-a-dict") == 0          # type: ignore[arg-type]


def test_rank_forms_orders_and_drops_non_dicts():
    forms = [
        {"method": "GET", "parameters": []},
        "junk",
        {"method": "POST", "enctype": "multipart/form-data", "parameters": ["f"]},
    ]
    out = rank_forms(forms)          # type: ignore[arg-type]
    assert len(out) == 2             # "junk" dropped
    assert "multipart" in out[0]["enctype"]


# ----------------------------------------------------------------------
# Forms + jsluice surfaced in the report (previously collected, never shown)
# ----------------------------------------------------------------------
def test_collect_counts_forms_and_jsluice(fake_outputs: Path):
    data = ReportBuilder(_make_inputs(fake_outputs)).collect()
    c = data["counts"]
    assert c["forms"] == 3
    assert c["forms_post"] == 2
    assert c["forms_upload"] == 1
    assert c["jsluice_endpoints"] == 2
    assert c["jsluice_urls"] == 1
    assert c["jsluice_params"] == 2
    # the lists themselves ride along, not just their lengths
    assert len(data["forms"]) == 3
    assert len(data["jsluice_params"]) == 2
    # highest-value form first: the multipart upload
    assert "multipart" in data["forms"][0]["enctype"]


def test_collect_counts_jsluice_recursion_from_stage_extra(fake_outputs: Path):
    """js_recursed_* live in the jsluice stage's own result dict (not a
    file), so collect() must pull them from stage_results, not re-derive
    them from processed/jsluice_*."""
    inputs = _make_inputs(fake_outputs)
    inputs.stage_results = inputs.stage_results + [
        {"stage": "jsluice", "status": "success", "count": 5, "error": None,
         "extra": {"js_fetched": 7, "js_recursed_rounds": 2,
                   "js_recursed_fetched": 4}},
    ]
    data = ReportBuilder(inputs).collect()
    c = data["counts"]
    assert c["jsluice_js_fetched"] == 7
    assert c["jsluice_js_recursed_rounds"] == 2
    assert c["jsluice_js_recursed_fetched"] == 4


def test_collect_jsluice_recursion_defaults_to_zero_without_stage(fake_outputs: Path):
    """No jsluice entry in stage_results (e.g. stage skipped) → counts
    default to 0 instead of KeyError."""
    data = ReportBuilder(_make_inputs(fake_outputs)).collect()
    c = data["counts"]
    assert c["jsluice_js_recursed_rounds"] == 0
    assert c["jsluice_js_recursed_fetched"] == 0


def test_md_and_html_show_jsluice_recursion_note(fake_outputs: Path):
    inputs = _make_inputs(fake_outputs)
    inputs.stage_results = inputs.stage_results + [
        {"stage": "jsluice", "status": "success", "count": 5, "error": None,
         "extra": {"js_fetched": 7, "js_recursed_rounds": 2,
                   "js_recursed_fetched": 4}},
    ]
    b = ReportBuilder(inputs)
    data = b.collect()
    md = b.render_markdown(data)
    html = b.render_html(data)
    assert "recursed into JS-referenced-JS" in md
    assert "2` round(s)" in md
    assert "recursed into JS-referenced-JS" in html
    assert "2</code> round(s)" in html


def test_md_and_html_hide_jsluice_recursion_note_when_no_recursion(fake_outputs: Path):
    """No rounds run (depth=0 or nothing to recurse into) → note omitted
    rather than printed as '0 round(s)' noise."""
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    md = b.render_markdown(data)
    html = b.render_html(data)
    assert "recursed into JS-referenced-JS" not in md
    assert "recursed into JS-referenced-JS" not in html


# ----------------------------------------------------------------------
# jsluice JS fetch detail — status/length/content-type of every JS file
# jsluice attempted (2xx and 4xx/5xx alike, incl. recursive rounds)
# ----------------------------------------------------------------------
def test_collect_summarizes_jsluice_js_detail(fake_outputs: Path):
    data = ReportBuilder(_make_inputs(fake_outputs)).collect()
    c = data["counts"]
    assert c["jsluice_js_fetched_total"] == 2
    surf = data["jsluice_js_surface"]
    assert surf["by_status"] == {200: 1, 404: 1}
    assert surf["by_type"]["application/javascript"] == 1
    # the raw rows ride along too, not just the summary
    assert len(data["jsluice_js_detail"]) == 2


def test_md_and_html_show_jsluice_js_fetch_surface(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    md = b.render_markdown(data)
    html = b.render_html(data)
    assert "jsluice JS fetch surface" in md
    assert "jsluice_js_table.txt" in md
    assert "jsluice JS fetch surface" in html
    assert "jsluice_js_table.txt" in html
    # the 404'd chunk is visible in the status breakdown, not swallowed
    assert "`404`" in md
    assert "404" in html


def test_md_and_html_hide_jsluice_js_fetch_surface_when_empty(tmp_path: Path):
    """No jsluice_js_detail.json (stage skipped/pre-upgrade run) → section
    omitted rather than rendered empty."""
    from modules.utils import create_output_structure
    base = create_output_structure("bare.com", root=str(tmp_path))
    b = ReportBuilder(_make_inputs(base))
    data = b.collect()
    md = b.render_markdown(data)
    html = b.render_html(data)
    assert "jsluice JS fetch surface" not in md
    assert "jsluice JS fetch surface" not in html



# ----------------------------------------------------------------------
# jsluice method check — endpoints re-probed with their recorded verb,
# so a POST-only route a GET-only probe reads as 404 shows up alive
# ----------------------------------------------------------------------
def test_collect_reads_jsluice_method_check(fake_outputs: Path):
    data = ReportBuilder(_make_inputs(fake_outputs)).collect()
    assert data["counts"]["jsluice_method_check"] == 1
    assert data["counts"]["jsluice_method_bypass"] == 1
    row = data["jsluice_method_check"][0]
    assert row["method"] == "POST" and row["status"] == 200
    assert row["get_status"] == 404


def test_md_and_html_show_method_check_bypass(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    md = b.render_markdown(data)
    html = b.render_html(data)
    assert "HTTP Method Check (verb tampering)" in md
    assert "HTTP Method Check (verb tampering)" in html
    # the bypass row: real method (POST) got a 200 where GET got a 404
    assert "POST" in md and "token" in md
    assert "POST" in html and "token" in html


def test_md_and_html_hide_method_check_when_empty(tmp_path: Path):
    from modules.utils import create_output_structure
    base = create_output_structure("bare.com", root=str(tmp_path))
    b = ReportBuilder(_make_inputs(base))
    data = b.collect()
    md = b.render_markdown(data)
    html = b.render_html(data)
    assert "No method-tagged endpoints to re-test" in md
    assert "No method-tagged endpoints to re-test" in html


def test_collect_samples_parameterized_urls(fake_outputs: Path):
    """No truncation: the report embeds the full parameterized_urls.txt,
    not a capped sample."""
    data = ReportBuilder(_make_inputs(fake_outputs)).collect()
    assert data["parameterized_sample"]
    assert all(isinstance(u, str) for u in data["parameterized_sample"])
    assert len(data["parameterized_sample"]) == data["counts"]["parameterized_urls"]


def test_html_shows_forms_section(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    html = b.render_html(b.collect())
    assert "Forms &amp; Input Surface" in html
    assert "multipart/form-data" in html
    assert "username, password, csrf" in html


def test_html_shows_jsluice_params_with_body(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    html = b.render_html(b.collect())
    assert "jsluice endpoints (AST)" in html
    assert "jsluice params" in html
    # body params are the whole point — arjun never sees them
    assert "email, password" in html


def test_html_embeds_parameterized_sample(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    html = b.render_html(b.collect())
    assert "Injection candidates" in html


def test_html_links_response_previews(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    html = b.render_html(b.collect())
    assert "../responses/index.md" in html
    assert "Response previews" in html


def test_md_shows_forms_and_jsluice(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    md = b.render_markdown(b.collect())
    assert "## 8.1 Forms & Input Surface" in md
    assert "jsluice param records (AST)" in md
    assert "email, password" in md
    assert "Injection candidates" in md


def test_report_survives_missing_forms_and_jsluice(tmp_path: Path):
    """A run where the crawl found no forms and jsluice was skipped must
    still render both sections rather than crash on the missing files."""
    from modules.utils import create_output_structure
    base = create_output_structure("bare.com", root=str(tmp_path))
    b = ReportBuilder(_make_inputs(base))
    data = b.collect()
    assert data["counts"]["forms"] == 0
    assert data["counts"]["jsluice_params"] == 0
    assert data["forms"] == []
    html = b.render_html(data)
    assert "No forms extracted" in html
    md = b.render_markdown(data)
    assert "_No forms extracted from the crawl._" in md


# ----------------------------------------------------------------------
# API documentation section
# ----------------------------------------------------------------------
def test_collect_counts_api_docs(fake_outputs: Path):
    data = ReportBuilder(_make_inputs(fake_outputs)).collect()
    c = data["counts"]
    assert c["api_specs"] == 1
    assert c["api_documented_paths"] == 2
    assert c["api_docs_ui"] == 1
    assert c["api_osint"] == 1
    assert c["apidocs_urls"] == 2


def test_html_shows_api_docs_section(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    html = b.render_html(b.collect())
    assert "8.2 API Documentation" in html
    assert "Billing API" in html
    assert "bearerAuth" in html
    assert "swagger-ui.html" in html
    assert "Example Public API" in html


def test_md_shows_api_docs_section(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    md = b.render_markdown(b.collect())
    assert "## 8.2 API Documentation" in md
    assert "Billing API" in md
    assert "OSINT `postman`" in md


def test_api_docs_section_graceful_when_nothing_found(tmp_path: Path):
    from modules.utils import create_output_structure
    base = create_output_structure("bare.com", root=str(tmp_path))
    b = ReportBuilder(_make_inputs(base))
    data = b.collect()
    assert data["counts"]["api_specs"] == 0
    assert "No OpenAPI/Swagger specs" in b.render_html(data)
    assert "_No OpenAPI/Swagger specs" in b.render_markdown(data)


def test_html_shows_graphql_cors_buckets_gitdump_sections(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    html = b.render_html(b.collect())
    assert "deleteUser" in html
    assert "createInvoice" in html
    assert "https://evil.invalid" in html
    assert "example-uploads" in html
    assert "public-listing" in html
    assert "exampleacct" in html
    assert "staging.example.com" in html
    assert "30" in html and "42" in html          # recovered / in-index counts


def test_md_shows_graphql_cors_buckets_gitdump_sections(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    md = b.render_markdown(b.collect())
    assert "deleteUser" in md
    assert "https://evil.invalid" in md
    assert "example-uploads" in md
    assert "staging.example.com" in md


def test_graphql_cors_buckets_gitdump_graceful_when_nothing_found(tmp_path: Path):
    from modules.utils import create_output_structure
    base = create_output_structure("bare.com", root=str(tmp_path))
    b = ReportBuilder(_make_inputs(base))
    data = b.collect()
    assert data["counts"]["graphql_introspectable"] == 0
    assert data["counts"]["cors_findings"] == 0
    assert data["counts"]["buckets_findings"] == 0
    assert data["counts"]["gitdump_hosts"] == 0
    html = b.render_html(data)
    assert "No endpoint answered a live introspection" in html
    assert "No host reflected the test Origin" in html
    assert "No S3/GCS bucket confirmed" in html
    assert "No confirmed .git exposure" in html
    md = b.render_markdown(data)
    assert "_No endpoint answered a live introspection" in md
    assert "_No host reflected the test Origin" in md
    assert "_No S3/GCS bucket confirmed" in md
    assert "_No confirmed .git exposure" in md


def test_content_discovery_shows_fuzz_coverage_when_hosts_capped(fake_outputs: Path):
    inputs = _make_inputs(fake_outputs)
    inputs.stage_results = [
        r for r in inputs.stage_results if r["stage"] != "dirsearch"
    ] + [
        {"stage": "dirsearch", "status": "success", "extra": {"selection": {
            "input": 312, "deduped": 250, "waf_skipped": 0,
            "blanket_skipped": 11, "selected": 50, "capped": 1}}},
        {"stage": "ffuf", "status": "success", "extra": {"selection": {
            "input": 312, "deduped": 260, "waf_skipped": 2,
            "blanket_skipped": 0, "selected": 50, "capped": 0}}},
    ]
    b = ReportBuilder(inputs)
    data = b.collect()
    assert data["fuzz_coverage"]["dirsearch"]["capped"] == 1
    assert data["fuzz_coverage"]["ffuf"]["capped"] == 0

    html = b.render_html(data)
    assert "Host fuzzing coverage" in html
    assert "never fuzzed" in html          # dirsearch's capped=1 callout
    assert "no cap hit" in html            # ffuf's capped=0 callout

    md = b.render_markdown(data)
    assert "**Host fuzzing coverage**" in md
    assert "| dirsearch | 312 | 250 | 0 | 11 | 50 | 1 |" in md
    assert "| ffuf | 312 | 260 | 2 | 0 | 50 | 0 |" in md


def test_content_discovery_omits_fuzz_coverage_when_no_stage_data(fake_outputs: Path):
    """dirsearch/ffuf ran under an older report.py, or were skipped without
    ever reaching selection — the section must not render an empty table."""
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    assert data["fuzz_coverage"] == {"dirsearch": {}, "ffuf": {}}
    assert "Host fuzzing coverage" not in b.render_html(data)


def test_content_discovery_shows_fuzz_screen_when_hosts_blanket(fake_outputs: Path):
    inputs = _make_inputs(fake_outputs)
    inputs.stage_results = [
        r for r in inputs.stage_results if r["stage"] != "dirsearch"
    ] + [
        {"stage": "dirsearch", "status": "success", "extra": {"screen": {
            "enabled": True, "raw_hits": 4171, "kept": 89, "dropped": 4082,
            "blanket_hosts": ["mapi.discover.com"]}}},
        {"stage": "ffuf", "status": "success", "extra": {"screen": {
            "enabled": True, "raw_hits": 200, "kept": 200, "dropped": 0,
            "blanket_hosts": []}}},
    ]
    b = ReportBuilder(inputs)
    data = b.collect()
    assert data["fuzz_screen"]["dirsearch"]["dropped"] == 4082
    assert data["fuzz_screen"]["ffuf"]["dropped"] == 0

    html = b.render_html(data)
    assert "Behavioural hit screening" in html
    assert "mapi.discover.com" in html
    assert "one response wearing many paths" in html

    md = b.render_markdown(data)
    assert "**Behavioural hit screening**" in md
    assert "| dirsearch | 4171 | 89 | 4082 | `mapi.discover.com` |" in md
    assert "| ffuf | 200 | 200 | 0 | — |" in md


def test_content_discovery_omits_fuzz_screen_when_disabled_or_missing(fake_outputs: Path):
    """``screen.enabled: false`` (config opt-out) and a stage that never ran
    both collapse to the same empty result — no half-populated table."""
    inputs = _make_inputs(fake_outputs)
    inputs.stage_results = [
        r for r in inputs.stage_results if r["stage"] != "dirsearch"
    ] + [
        {"stage": "dirsearch", "status": "success", "extra": {"screen": {
            "enabled": False, "raw_hits": 10, "kept": 10, "dropped": 0,
            "blanket_hosts": []}}},
    ]
    b = ReportBuilder(inputs)
    data = b.collect()
    assert data["fuzz_screen"] == {"dirsearch": {}, "ffuf": {}}
    assert "Behavioural hit screening" not in b.render_html(data)


def test_content_discovery_shows_endpoint_existence_when_present(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    data["endpoint_existence"] = {
        "results": [
            {"url": "https://x.example.com/api/users/1", "sources": ["ffuf"],
             "status": 400, "verdict": "confirmed",
             "reasons": ["validation: missing required parameter"]},
            {"url": "https://x.example.com/api/tenants/1", "sources": ["dirsearch"],
             "status": 404, "verdict": "likely",
             "reasons": ["business_logic: tenant not found"]},
            {"url": "https://x.example.com/xyz123", "sources": ["ffuf"],
             "status": 403, "verdict": "not_found",
             "reasons": ["identical shape to this host's not-found baseline"]},
        ],
        "counts": {"confirmed": 1, "likely": 1, "unknown": 0, "not_found": 1},
    }

    html = b.render_html(data)
    assert "Endpoint existence" in html
    assert "Confirmed Exists" in html
    assert "missing required parameter" in html
    assert "https://x.example.com/api/users/1" in html
    # not_found entries are counted but not listed in the actionable table
    assert "https://x.example.com/xyz123" not in html

    md = b.render_markdown(data)
    assert "**Endpoint existence**" in md
    assert "tenant not found" in md
    assert "| Confirmed Exists | 1 |" in md
    assert "| Not Found (matches baseline noise) | 1 |" in md


def test_content_discovery_omits_endpoint_existence_when_no_hits(tmp_path: Path):
    """No ffuf_urls.txt/dirsearch_urls.txt at all (stages skipped, or an
    output tree from before this feature existed) — no half-populated
    section."""
    b = ReportBuilder(_make_inputs(tmp_path))
    data = b.collect()
    assert data["endpoint_existence"]["results"] == []
    assert "Endpoint existence" not in b.render_html(data)
    assert "**Endpoint existence**" not in b.render_markdown(data)


def test_params_section_shows_arjun_coverage_when_capped(fake_outputs: Path):
    inputs = _make_inputs(fake_outputs)
    inputs.stage_results = inputs.stage_results + [
        {"stage": "arjun", "status": "success",
         "extra": {"input_urls": 5000, "scanned_urls": 200}},
    ]
    b = ReportBuilder(inputs)
    data = b.collect()
    assert data["counts"]["arjun_input_urls"] == 5000
    assert data["counts"]["arjun_scanned_urls"] == 200

    html = b.render_html(data)
    assert "Arjun actually scanned" in html
    assert "200 / 5,000" in html
    assert "never checked for hidden params" in html

    md = b.render_markdown(data)
    assert "Arjun actually scanned: `200 / 5000`" in md
    assert "never checked for hidden params" in md


def test_params_section_arjun_no_cap_note_when_everything_scanned(fake_outputs: Path):
    inputs = _make_inputs(fake_outputs)
    inputs.stage_results = inputs.stage_results + [
        {"stage": "arjun", "status": "success",
         "extra": {"input_urls": 12, "scanned_urls": 12}},
    ]
    b = ReportBuilder(inputs)
    data = b.collect()
    html = b.render_html(data)
    assert "every candidate URL was scanned" in html
    assert "never checked for hidden params" not in html


def test_params_section_omits_arjun_row_when_no_stage_data(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    assert data["counts"]["arjun_input_urls"] is None
    assert "Arjun actually scanned" not in b.render_html(data)


def test_high_value_section_shows_blanket_hosts_callout(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    data["counts"]["high_value_blanket_hosts"] = ["archertprm.discover.com"]

    html = b.render_html(data)
    assert "archertprm.discover.com" in html
    assert "one WAF/soft-catch-all page repeated" in html

    md = b.render_markdown(data)
    assert "archertprm.discover.com" in md
    assert "one WAF/soft-catch-all page repeated" in md


def test_high_value_section_no_blanket_callout_when_none(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    data = b.collect()
    assert data["counts"].get("high_value_blanket_hosts") in ([], None)
    assert "soft-catch-all page repeated" not in b.render_html(data)
    assert "soft-catch-all page repeated" not in b.render_markdown(data)


def test_parse_nuclei_summary_counts_unknown_severity(tmp_path: Path):
    """nuclei labels a template that declares no severity ``unknown``, and
    the default scan now runs those. The count must be carried, not dropped
    into a severity bucket the report never iterates."""
    import json as _json
    p = tmp_path / "nuclei.json"
    p.write_text(_json.dumps({"template-id": "no-sev",
                              "info": {"severity": "unknown"},
                              "matched-at": "https://a"}) + "\n")
    findings, sev = parse_nuclei_summary(p)
    assert len(findings) == 1
    assert sev.get("unknown") == 1
    assert ReportBuilder.SEV_ORDER.count("unknown") == 1


# ----------------------------------------------------------------------
# Section 9 — High-Value Targets carries the response facts
# ----------------------------------------------------------------------
def _hv_rows():
    return [
        {"url": "https://x.com/api/v1/users", "status_code": 200,
         "content_length": 45678, "content_type": "application/json"},
        {"url": "https://x.com/admin", "status_code": 403,
         "content_length": 1200, "content_type": "text/html; charset=utf-8",
         "title": "Forbidden"},
        {"url": "https://x.com/login", "status_code": 302, "content_length": 0,
         "content_type": "text/html", "location": "https://sso.x.com/"},
        {"url": "https://x.com/backup.sql", "status_code": 404,
         "content_length": 300, "content_type": "text/html"},
    ]


def test_enrich_target_attaches_the_response_facts():
    from modules.report import enrich_target

    t = enrich_target("https://x.com/admin", ["admin"], _hv_rows()[1])
    assert t["status"] == 403
    assert t["content_length"] == 1200
    assert t["content_type"] == "text/html"      # charset stripped
    assert t["probed"] is True


def test_an_unprobed_target_reports_missing_not_zero():
    from modules.report import enrich_target

    t = enrich_target("https://x.com/.git/config", ["config"], None)
    assert t["status"] is None and t["content_length"] is None
    assert t["probed"] is False


def test_targets_sort_by_what_the_server_returned():
    from modules.report import enrich_target, index_detail_by_url, target_sort_key

    rows = _hv_rows()
    idx = index_detail_by_url(rows)
    urls = [r["url"] for r in rows] + ["https://x.com/.git/config"]
    hv = sorted((enrich_target(u, ["t"], idx.get(u)) for u in urls),
                key=target_sort_key)

    # reachable → auth-gated → other → 404 → never probed
    assert [h["status"] for h in hv] == [200, 403, 302, 404, None]


def test_index_prefers_the_first_source_for_a_duplicate_url():
    from modules.report import index_detail_by_url

    idx = index_detail_by_url(
        [{"url": "https://x.com/a", "status_code": 200}],
        [{"url": "https://x.com/a", "status_code": 500}],
    )
    assert idx["https://x.com/a"]["status_code"] == 200


def test_index_falls_back_to_the_input_field():
    from modules.report import index_detail_by_url

    idx = index_detail_by_url([{"input": "https://x.com/b", "status_code": 204}])
    assert "https://x.com/b" in idx


def test_status_class_calls_out_auth_gated_separately():
    from modules.report import _status_class

    # 401/403 is the strongest lead the report has — it must not be styled
    # as an error alongside 500s.
    assert _status_class(403) == "st-gated"
    assert _status_class(401) == "st-gated"
    assert _status_class(200) == "st-ok"
    assert _status_class(302) == "st-redir"
    assert _status_class(500) == "st-dead"
    assert _status_class(None) == "st-none"


def test_length_formatter_distinguishes_zero_from_unknown():
    from modules.report import _fmt_len, _fmt_status

    assert _fmt_len(0) == "0B"
    assert _fmt_len(None) == "—"
    assert _fmt_status(0) == "0"
    assert _fmt_status(None) == "—"


def test_every_url_listing_section_carries_the_response_facts(fake_outputs: Path):
    """The point of the whole join: no section quotes a URL without evidence.

    Sections 3 (jsluice params, API paths), 8 (injection candidates), 8.1
    (forms), 8.2 (docs UIs) and 9 (high-value) all list URLs/endpoints. Each
    used to print the bare string, so a reader could not tell an endpoint
    that answers 200 JSON from one the server has never heard of.
    """
    b = ReportBuilder(_make_inputs(fake_outputs))
    html = b.render_html(b.collect())

    # Every facts table shares the same header triple.
    assert html.count("<th>ST</th><th>Length</th><th>Type</th>") >= 4, (
        "expected the ST/Length/Type header in several sections")


def test_markdown_url_sections_carry_the_facts_header(fake_outputs: Path):
    b = ReportBuilder(_make_inputs(fake_outputs))
    md = b.render_markdown(b.collect())
    assert md.count("ST | Length | Type") >= 3


def test_facts_cells_report_unprobed_urls_as_unknown():
    from modules.report import html_facts_cells, md_facts_cells

    assert "—" in md_facts_cells({}, "https://x.com/never-probed")
    assert "st-none" in html_facts_cells({}, "https://x.com/never-probed")


def test_body_snippet_rides_along_as_a_tooltip():
    from modules.report import html_facts_cells

    idx = {"https://x.com/a": {"url": "https://x.com/a", "status_code": 200}}
    cells = html_facts_cells(idx, "https://x.com/a",
                             {"https://x.com/a": "{\"error\":\"nope\"}"})
    assert 'title="' in cells and "nope" in cells


def test_static_assets_never_outrank_real_endpoints():
    """Host-derived categories land on every asset that host serves.

    ``securedocupload.*`` tags all its files "upload endpoint", so without
    the static demotion a 755 KB webpack chunk outranked the actual upload
    form — measured on the real tree.
    """
    from modules.report import target_sort_key

    chunk = {"url": "https://up.x.com/static/js/main.abc.js", "status": 200,
             "content_length": 755391, "categories": ["upload endpoint"]}
    real = {"url": "https://up.x.com/tasks/upload-urls", "status": 200,
            "content_length": 40500, "categories": ["upload endpoint"]}
    assert sorted([chunk, real], key=target_sort_key)[0] is real


def test_a_repeated_response_shape_sinks_but_is_not_hidden():
    """A soft-200 catch-all leaves a residue under the screen's min_cluster.

    archertprm.discover.com left 21 entries all answering "200, 92 bytes"
    and they outranked every genuine finding. They must sink — and still be
    listed, with the repeat count as the tell.
    """
    from modules.report import target_sort_key

    dup = {"url": "https://a.x.com/ADMIN", "status": 200, "content_length": 92,
           "categories": ["admin panel"], "shape_count": 21}
    uniq = {"url": "https://b.x.com/sign-in", "status": 200,
            "content_length": 43574, "categories": ["login portal"],
            "shape_count": 1}
    assert sorted([dup, uniq], key=target_sort_key)[0] is uniq


def test_category_weight_ranks_path_findings_over_host_tags():
    from modules.report import category_weight

    # "backup file" is a finding on its own; "qa environment" only says
    # where the URL lives.
    assert category_weight(["backup file"]) > category_weight(["qa environment"])
    assert category_weight(["admin panel"]) > category_weight(["test environment"])
    assert category_weight([]) == 0


def test_source_maps_are_not_treated_as_static_assets():
    from modules.report import is_static_asset

    assert is_static_asset("https://x.com/a/main.js") is True
    assert is_static_asset("https://x.com/a/main.css?v=2") is True
    # A .map is one of the better things this section can surface.
    assert is_static_asset("https://x.com/a/main.js.map") is False
    assert is_static_asset("https://x.com/api/v1/users") is False
