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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from modules import report as report_mod
from modules.report import (
    HIGH_VALUE_PATTERNS,
    ReportBuilder,
    ReportInputs,
    build_report,
    classify_stages,
    classify_url,
    count_lines,
    extract_interesting_api_paths,
    is_high_value,
    load_json_safe,
    missing_tools_from_skips,
    parse_httpx_jsonl,
    parse_nuclei_summary,
    rel_link,
    severity_rank,
)


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
@pytest.fixture
def fake_outputs(tmp_path: Path) -> Path:
    """Populate ``tmp_path`` with a realistic but minimal output tree
    using the v2 layout (raw grouped per stage, findings per kind)."""
    base = tmp_path
    raw_sub = base / "raw" / "subdomain"
    raw_cd = base / "raw" / "content_discovery"
    raw_ds = base / "raw" / "dirsearch"
    raw_wm = base / "raw" / "waymore"
    raw_ar = base / "raw" / "arjun"
    proc = base / "processed"
    fnd_def = base / "findings" / "default"
    fnd_dyn = base / "findings" / "dynamic"
    logs = base / "logs"
    for d in (raw_sub, raw_cd, raw_ds, raw_wm, raw_ar,
              proc, fnd_def, fnd_dyn, logs):
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
    # raw/waymore/
    (raw_wm / "waymore_raw.txt").write_text("https://example.com/old/login\n")
    # raw/arjun/
    (raw_ar / "input_subset.txt").write_text("https://example.com/login\n")

    # processed
    (proc / "subdomains.txt").write_text("a.example.com\nb.example.com\nc.example.com\n")
    (proc / "resolved.txt").write_text("a.example.com\nb.example.com\n")
    (proc / "resolved_detail.json").write_text(json.dumps([
        {"subdomain": "a.example.com", "ip": "1.2.3.4",
         "asn": {"asn": "AS13335", "name": "Cloudflare"}, "cname": None},
        {"subdomain": "b.example.com", "ip": "5.6.7.8",
         "asn": {"asn": "AS16509", "name": "Amazon"}, "cname": "edge.example.com"},
    ]))
    (proc / "alive.txt").write_text(
        "https://a.example.com\nhttps://b.example.com\n"
    )
    (proc / "alive_detail.json").write_text(json.dumps([
        {"url": "https://a.example.com", "input": "a.example.com",
         "status_code": 200, "title": "Login", "content_type": "text/html",
         "content_length": 1234, "webserver": "nginx", "tech": "PHP"},
        {"url": "https://b.example.com", "input": "b.example.com",
         "status_code": 200, "title": "API", "content_type": "application/json",
         "content_length": 567, "webserver": "nginx", "tech": "Node.js"},
    ]))
    (proc / "crawler_urls.txt").write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/api/users\n"
    )
    (proc / "dirsearch_urls.txt").write_text(
        "https://example.com/.env\nhttps://example.com/.git/HEAD\n"
    )
    (proc / "waymore_urls.txt").write_text("https://example.com/old/login\n")
    (proc / "all_urls.txt").write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/.env\nhttps://example.com/api/users\n"
        "https://example.com/app.js\n"
    )
    (proc / "js_urls.txt").write_text("https://example.com/app.js\n")
    (proc / "dynamic_urls.txt").write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/api/users\n"
        "https://example.com/.env\nhttps://example.com/.git/HEAD\n"
    )
    (proc / "xnlinkfinder_endpoints.txt").write_text(
        "/api/v1/users\n/api/v1/login\n/graphql/query\n"
    )
    (proc / "xnlinkfinder_urls.txt").write_text(
        "https://example.com/api/v1/users\n"
        "https://example.com/graphql/query\n"
    )
    (proc / "alive_urls.txt").write_text(
        "https://example.com/login\nhttps://example.com/admin\n"
        "https://example.com/.env\nhttps://example.com/.git/HEAD\n"
    )
    (proc / "alive_urls_detail.json").write_text(json.dumps([
        {"url": "https://example.com/login", "status_code": 200,
         "content_length": 900, "content_type": "text/html"},
    ]))
    (proc / "arjun_params.txt").write_text(
        "[200] https://example.com/login?id=&q=\n"
        "[200] https://example.com/admin?debug=\n"
    )
    (proc / "parameterized_urls.txt").write_text(
        "https://example.com/login?id=&q=\n"
        "https://example.com/admin?debug=\n"
    )

    # findings/<kind>/
    (fnd_def / "nuclei.txt").write_text(
        "https://a.example.com\nhttps://b.example.com\n"
    )
    (fnd_def / "nuclei.json").write_text(json.dumps({
        "findings": [
            {"template-id": "tech-detect", "info": {"name": "Nginx",
             "severity": "info"}, "matched-at": "https://a.example.com"},
            {"template-id": "exposed-env", "info": {"name": "Exposed .env",
             "severity": "high"}, "matched-at": "https://b.example.com/.env",
             "matcher-name": "env-file", "extracted-results": ["DB_PASS=hunter2"]},
        ],
        "severity_count": {"info": 1, "high": 1, "medium": 0, "low": 0, "critical": 0},
    }))
    (fnd_dyn / "nuclei.txt").write_text("https://example.com/login?id=\n")
    (fnd_dyn / "nuclei.json").write_text(json.dumps({
        "findings": [
            {"template-id": "sqli-error", "info": {"name": "SQL error",
             "severity": "critical"}, "matched-at": "https://example.com/login?id=",
             "matcher-name": "error-pattern"},
        ],
        "severity_count": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
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
    json_out = fdir / "nuclei.json"

    # nuclei writes a single JSON array with two findings.
    findings_doc = [
        {"template-id": "tech-detect",
         "info": {"name": "Nginx", "severity": "info"},
         "matched-at": "https://a"},
        {"template-id": "exposed-env",
         "info": {"name": ".env", "severity": "high"},
         "matched-at": "https://b/.env"},
    ]
    json_out.write_text(_json.dumps(findings_doc))
    txt_out = fdir / "nuclei.txt"

    def fake_run(cmd, **kw):
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
    json_out = fdir / "nuclei.json"
    # Mix of valid finding, stray list, blank line, stray int, valid finding.
    json_out.write_text(
        '{"template-id": "t1", "info": {"severity": "info"}, "matched-at": "https://a"}\n'
        '[1, 2, 3]\n'
        '\n'
        '42\n'
        '{"template-id": "t2", "info": {"severity": "high"}, "matched-at": "https://b"}\n'
    )

    def fake_run(cmd, **kw):
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
        {"stage": "nuclei_dynamic", "status": "skipped", "error": "nuclei binary not found"},
        {"stage": "subdomain",  "status": "success"},
    ]
    out = missing_tools_from_skips(results)
    # "nuclei_default" and "nuclei_dynamic" both extract to "nuclei"
    assert sorted(out) == ["dirsearch", "katana", "nuclei"]


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
    assert data["counts"]["nuclei_default_findings"] == 2
    assert data["counts"]["nuclei_dynamic_findings"] == 1

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
    (tmp_path / "processed" / "all_urls.txt").write_text("https://x.example.com\n")
    (tmp_path / "processed" / "alive.txt").write_text("https://x.example.com\n")
    # write an interesting URL into one of the candidate files
    (tmp_path / "processed" / "alive_urls.txt").write_text("https://x.example.com/admin\n")

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
        "3. Asset Inventory",
        "4. DNS Inventory",
        "5. Content Discovery",
        "6. JavaScript Analysis",
        "7. Parameter Discovery",
        "8. Nuclei Findings",
        "9. High-Value Targets",
        "10. Errors / Skipped / Missing Tools",
        "11. Manual Testing Recommendations",
        "12. Appendix",
    ]:
        assert section in html, f"missing section: {section}"


def test_render_html_uses_clickable_links(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    # every required link should be present (v2 layout)
    for rel in [
        "../raw/subdomain/subfinder.txt",
        "../raw/subdomain/amass.txt",
        "../raw/subdomain/chaos.txt",
        "../processed/subdomains.txt",
        "../processed/resolved.txt",
        "../processed/resolved_detail.json",
        "../processed/alive.txt",
        "../processed/alive_detail.json",
        "../raw/content_discovery/katana_urls.txt",
        "../raw/content_discovery/urlfinder_urls.txt",
        "../processed/crawler_urls.txt",
        "../raw/dirsearch/dirsearch_raw.txt",
        "../raw/dirsearch/merged_wordlists.txt",
        "../processed/dirsearch_urls.txt",
        "../raw/waymore/waymore_raw.txt",
        "../processed/waymore_urls.txt",
        "../processed/all_urls.txt",
        "../processed/js_urls.txt",
        "../processed/dynamic_urls.txt",
        "../processed/xnlinkfinder_endpoints.txt",
        "../processed/xnlinkfinder_urls.txt",
        "../processed/alive_urls.txt",
        "../processed/alive_urls_detail.json",
        "../processed/arjun_params.txt",
        "../raw/arjun/input_subset.txt",
        "../processed/parameterized_urls.txt",
        "../findings/default/nuclei.txt",
        "../findings/default/nuclei.json",
        "../findings/dynamic/nuclei.txt",
        "../findings/dynamic/nuclei.json",
        "../logs/commands.log",
        "../logs/stages.json",
    ]:
        assert f'href="{rel}"' in html, f"missing clickable link: {rel}"


def test_render_html_groups_nuclei_findings_by_severity(fake_outputs: Path):
    html = ReportBuilder(_make_inputs(fake_outputs)).render_html(
        ReportBuilder(_make_inputs(fake_outputs)).collect()
    )
    # severities that have findings in the fixture must appear (uppercased)
    # fixture has critical (dynamic) + high + info (default)
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
        "## 3. Asset Inventory",
        "## 4. DNS Inventory",
        "## 5. Content Discovery",
        "## 6. JavaScript Analysis",
        "## 7. Parameter Discovery",
        "## 8. Nuclei Findings",
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
