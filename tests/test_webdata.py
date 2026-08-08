"""Tests for modules/webdata.py — read-only data access for web/app.py's
results browser (/results/*)."""
from __future__ import annotations

import json
from pathlib import Path

from modules import layout, webdata
from modules.utils import create_output_structure


# ----------------------------------------------------------------------
# resolve_target
# ----------------------------------------------------------------------
def test_resolve_target_ungrouped(tmp_path: Path):
    create_output_structure("a.com", root=str(tmp_path))
    ref = webdata.resolve_target(tmp_path, "a.com")
    assert ref == {"path": tmp_path / "a.com", "project": None, "domain": "a.com"}


def test_resolve_target_grouped(tmp_path: Path):
    create_output_structure("a.com", root=str(tmp_path), project="acme")
    ref = webdata.resolve_target(tmp_path, "acme/a.com")
    assert ref == {"path": tmp_path / "acme" / "a.com", "project": "acme", "domain": "a.com"}


def test_resolve_target_not_found_returns_none(tmp_path: Path):
    assert webdata.resolve_target(tmp_path, "nope.com") is None


def test_resolve_target_rejects_traversal(tmp_path: Path):
    create_output_structure("a.com", root=str(tmp_path))
    assert webdata.resolve_target(tmp_path, "../../../etc/passwd") is None
    assert webdata.resolve_target(tmp_path, "a.com/../../../etc") is None


def test_resolve_target_rejects_too_deep(tmp_path: Path):
    create_output_structure("a.com", root=str(tmp_path), project="acme")
    assert webdata.resolve_target(tmp_path, "acme/a.com/report") is None


# ----------------------------------------------------------------------
# list_targets
# ----------------------------------------------------------------------
def test_list_targets_reuses_dashboard_load_target(tmp_path: Path):
    base = create_output_structure("a.com", root=str(tmp_path))
    (base / "report").mkdir(parents=True, exist_ok=True)
    (base / "report" / "summary.json").write_text(json.dumps({
        "meta": {"scan_end": "2026-07-28T10:00:00+00:00"},
        "nuclei": {"default": {"severity_count": {"critical": 1}}},
    }))
    (base / "logs" / "stages.json").write_text("[]")

    targets = webdata.list_targets(tmp_path)
    assert len(targets) == 1
    assert targets[0]["domain"] == "a.com"
    assert targets[0]["project"] is None
    assert targets[0]["nuclei_severity"] == {"critical": 1}


# ----------------------------------------------------------------------
# paginate_table
# ----------------------------------------------------------------------
def _write_table(path: Path, rows: list[tuple[str, str, str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [" ST     LENGTH  CONTENT-TYPE              URL"]
    lines += [f"{st}\t{length}\t{ctype}\t{url}" for st, length, ctype, url in rows]
    path.write_text("\n".join(lines) + "\n")


def test_paginate_table_skips_header_and_parses_rows(tmp_path: Path):
    f = tmp_path / "alive_table.txt"
    _write_table(f, [("200", "1234", "text/html", "https://a.example.com")])
    res = webdata.paginate_table(f)
    assert res["total"] == 1
    assert res["rows"][0] == {
        "status": "200", "length": "1234", "content_type": "text/html",
        "url": "https://a.example.com",
    }


def test_paginate_table_missing_file_is_empty_not_error(tmp_path: Path):
    res = webdata.paginate_table(tmp_path / "does_not_exist.txt")
    assert res == {"rows": [], "total": 0, "page": 1, "pages": 1, "limit": 100}


def test_paginate_table_filters_by_status(tmp_path: Path):
    f = tmp_path / "t.txt"
    _write_table(f, [
        ("200", "10", "text/html", "https://a.com"),
        ("403", "10", "text/html", "https://b.com"),
    ])
    res = webdata.paginate_table(f, status="403")
    assert res["total"] == 1
    assert res["rows"][0]["url"] == "https://b.com"


def test_paginate_table_filters_by_query_on_url_and_content_type(tmp_path: Path):
    f = tmp_path / "t.txt"
    _write_table(f, [
        ("200", "10", "application/json", "https://a.com/api"),
        ("200", "10", "text/html", "https://b.com/login"),
    ])
    assert webdata.paginate_table(f, q="api")["total"] == 1
    assert webdata.paginate_table(f, q="json")["total"] == 1
    assert webdata.paginate_table(f, q="login")["total"] == 1
    assert webdata.paginate_table(f, q="nope")["total"] == 0


def test_paginate_table_pagination_math(tmp_path: Path):
    f = tmp_path / "t.txt"
    _write_table(f, [("200", "1", "text/html", f"https://{i}.com") for i in range(25)])
    page1 = webdata.paginate_table(f, page=1, limit=10)
    assert page1["total"] == 25
    assert page1["pages"] == 3
    assert len(page1["rows"]) == 10
    page3 = webdata.paginate_table(f, page=3, limit=10)
    assert len(page3["rows"]) == 5


def test_paginate_table_page_beyond_range_clamps_to_last(tmp_path: Path):
    f = tmp_path / "t.txt"
    _write_table(f, [("200", "1", "text/html", "https://a.com")])
    res = webdata.paginate_table(f, page=999, limit=10)
    assert res["page"] == 1
    assert len(res["rows"]) == 1


def test_hosts_table_and_urls_table_use_layout_resolution(tmp_path: Path):
    base = create_output_structure("a.com", root=str(tmp_path))
    _write_table(layout.path(base, "alive_table.txt"),
                  [("200", "1", "text/html", "https://a.com")])
    _write_table(layout.path(base, "alive_urls_table.txt"),
                  [("200", "1", "text/html", "https://a.com/x"),
                   ("200", "1", "text/html", "https://a.com/y")])
    assert webdata.hosts_table(base)["total"] == 1
    assert webdata.urls_table(base)["total"] == 2


# ----------------------------------------------------------------------
# list_findings
# ----------------------------------------------------------------------
def _seed_findings(base: Path, findings: list[dict]) -> None:
    d = base / "findings" / "default"
    d.mkdir(parents=True, exist_ok=True)
    (d / "nuclei.json").write_text(json.dumps({
        "findings": findings,
        "severity_count": {},
        "complete": True,
    }))


def test_list_findings_reads_and_sorts_by_severity(tmp_path: Path):
    base = create_output_structure("a.com", root=str(tmp_path))
    _seed_findings(base, [
        {"template-id": "t1", "info": {"name": "Low finding", "severity": "low"},
         "matched-at": "https://a.com/x"},
        {"template-id": "t2", "info": {"name": "Crit finding", "severity": "critical"},
         "matched-at": "https://a.com/y"},
    ])
    res = webdata.list_findings(base)
    assert res["total"] == 2
    assert res["rows"][0]["severity"] == "critical"
    assert res["rows"][1]["severity"] == "low"


def test_list_findings_filters_by_severity(tmp_path: Path):
    base = create_output_structure("a.com", root=str(tmp_path))
    _seed_findings(base, [
        {"template-id": "t1", "info": {"name": "A", "severity": "low"}, "matched-at": "x"},
        {"template-id": "t2", "info": {"name": "B", "severity": "critical"}, "matched-at": "y"},
    ])
    res = webdata.list_findings(base, severity="critical")
    assert res["total"] == 1
    assert res["rows"][0]["name"] == "B"


def test_list_findings_filters_by_query(tmp_path: Path):
    base = create_output_structure("a.com", root=str(tmp_path))
    _seed_findings(base, [
        {"template-id": "git-exposure", "info": {"name": "Git config exposed",
         "severity": "high"}, "matched-at": "https://a.com/.git/config"},
        {"template-id": "cors-misconfig", "info": {"name": "CORS issue",
         "severity": "info"}, "matched-at": "https://a.com/api"},
    ])
    assert webdata.list_findings(base, q="git")["total"] == 1
    assert webdata.list_findings(base, q="cors")["total"] == 1
    assert webdata.list_findings(base, q="nope")["total"] == 0


def test_list_findings_missing_file_is_empty(tmp_path: Path):
    base = create_output_structure("a.com", root=str(tmp_path))
    res = webdata.list_findings(base)
    assert res == {"rows": [], "total": 0, "page": 1, "pages": 1, "limit": 100,
                    "severity_count": {}}
