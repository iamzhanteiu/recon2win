"""Tests for web/app.py's /results/* routes — the read-only results browser.

All data comes from modules/webdata.py (already unit-tested in
tests/test_webdata.py); these tests exercise routing, templates, and the
output_root/target_ref plumbing that ties Flask to it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from modules.utils import create_output_structure  # noqa: E402


@pytest.fixture
def web_app(monkeypatch, tmp_path):
    """web.app with _output_root() pointed at an isolated tmp_path."""
    import web.app as wapp
    monkeypatch.setattr(wapp, "_output_root", lambda: tmp_path)
    wapp.app.config["TESTING"] = True
    return wapp, tmp_path


def _seed(root: Path, domain: str, *, project=None, findings=None,
          hosts=None, urls=None) -> Path:
    base = create_output_structure(domain, root=str(root), project=project)
    (base / "report").mkdir(parents=True, exist_ok=True)
    (base / "report" / "summary.json").write_text(json.dumps({
        "meta": {"scan_end": "2026-08-08T00:00:00+00:00", "scan_duration_seconds": 12.0},
        "nuclei": {"default": {"severity_count": {}}},
        "jsluice_secrets": {"findings": [], "severity_count": {}},
        "high_value_targets": [],
    }))
    (base / "report" / "final_report.html").write_text("<html>full report</html>")
    (base / "logs" / "stages.json").write_text("[]")

    if hosts is not None:
        from modules import layout
        lines = [" ST     LENGTH  CONTENT-TYPE              URL"]
        lines += [f"{st}\t10\ttext/html\t{url}" for st, url in hosts]
        layout.path(base, "alive_table.txt").write_text("\n".join(lines) + "\n")

    if urls is not None:
        from modules import layout
        lines = [" ST     LENGTH  CONTENT-TYPE              URL"]
        lines += [f"{st}\t10\ttext/html\t{url}" for st, url in urls]
        layout.path(base, "alive_urls_table.txt").write_text("\n".join(lines) + "\n")

    if findings is not None:
        d = base / "findings" / "default"
        d.mkdir(parents=True, exist_ok=True)
        (d / "nuclei.json").write_text(json.dumps({
            "findings": findings, "severity_count": {}, "complete": True,
        }))
    return base


# ----------------------------------------------------------------------
# /results — landing page
# ----------------------------------------------------------------------
def test_results_index_empty_state(web_app):
    wapp, root = web_app
    with wapp.app.test_client() as c:
        r = c.get("/results")
        assert r.status_code == 200
        assert b"No targets scanned yet" in r.data


def test_results_index_lists_ungrouped_and_grouped(web_app):
    wapp, root = web_app
    _seed(root, "solo.com")
    _seed(root, "a.acme.com", project="acme")
    with wapp.app.test_client() as c:
        r = c.get("/results")
        assert r.status_code == 200
        assert b"solo.com" in r.data
        assert b"a.acme.com" in r.data
        assert b"acme" in r.data
        assert b"Ungrouped" in r.data


# ----------------------------------------------------------------------
# /results/<target_ref> — overview
# ----------------------------------------------------------------------
def test_results_target_overview_ungrouped(web_app):
    wapp, root = web_app
    _seed(root, "solo.com")
    with wapp.app.test_client() as c:
        r = c.get("/results/solo.com")
        assert r.status_code == 200
        assert b"solo.com" in r.data
        assert b"Full report" in r.data or b"final_report" in r.data


def test_results_target_overview_grouped(web_app):
    wapp, root = web_app
    _seed(root, "a.com", project="acme")
    with wapp.app.test_client() as c:
        r = c.get("/results/acme/a.com")
        assert r.status_code == 200
        assert b"a.com" in r.data


def test_results_target_overview_404_for_unknown_target(web_app):
    wapp, root = web_app
    with wapp.app.test_client() as c:
        r = c.get("/results/nope.com")
        assert r.status_code == 404


def test_results_target_overview_404_for_path_traversal(web_app):
    wapp, root = web_app
    _seed(root, "a.com")
    # Extra path segment outside root, or attempted traversal — must not 200.
    with wapp.app.test_client() as c:
        r = c.get("/results/..%2f..%2f..%2fetc%2fpasswd")
        assert r.status_code == 404


# ----------------------------------------------------------------------
# /results/<target_ref>/hosts + /urls
# ----------------------------------------------------------------------
def test_results_hosts_table_renders_rows(web_app):
    wapp, root = web_app
    _seed(root, "a.com", hosts=[("200", "https://a.com"), ("403", "https://x.a.com")])
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/hosts")
        assert r.status_code == 200
        assert b"a.com" in r.data
        assert b"x.a.com" in r.data
        assert b"200" in r.data


def test_results_hosts_table_filters_by_status(web_app):
    wapp, root = web_app
    _seed(root, "a.com", hosts=[("200", "https://a.com"), ("403", "https://x.a.com")])
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/hosts?status=403")
        assert r.status_code == 200
        assert b"x.a.com" in r.data
        assert b"https://a.com<" not in r.data  # the 200 row's exact URL text


def test_results_hosts_table_empty_state(web_app):
    wapp, root = web_app
    _seed(root, "a.com")
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/hosts")
        assert r.status_code == 200
        assert b"No data yet" in r.data


def test_results_urls_table_paginates(web_app):
    wapp, root = web_app
    urls = [("200", f"https://a.com/{i}") for i in range(150)]
    _seed(root, "a.com", urls=urls)
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/urls?limit=100")
        assert r.status_code == 200
        assert b"Page 1 of 2" in r.data
        r2 = c.get("/results/a.com/urls?limit=100&page=2")
        assert b"Page 2 of 2" in r2.data


# ----------------------------------------------------------------------
# /results/<target_ref>/findings
# ----------------------------------------------------------------------
def test_results_findings_renders_and_filters(web_app):
    wapp, root = web_app
    _seed(root, "a.com", findings=[
        {"template-id": "t1", "info": {"name": "Low one", "severity": "low"},
         "matched-at": "https://a.com/x"},
        {"template-id": "t2", "info": {"name": "Crit one", "severity": "critical"},
         "matched-at": "https://a.com/y"},
    ])
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/findings")
        assert r.status_code == 200
        assert b"Crit one" in r.data
        assert b"Low one" in r.data

        r2 = c.get("/results/a.com/findings?severity=critical")
        assert b"Crit one" in r2.data
        assert b"Low one" not in r2.data


def test_results_findings_empty_state(web_app):
    wapp, root = web_app
    _seed(root, "a.com")
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/findings")
        assert r.status_code == 200
        assert b"No findings recorded" in r.data


# ----------------------------------------------------------------------
# /results/<target_ref>/report/<filename>
# ----------------------------------------------------------------------
def test_results_report_file_served(web_app):
    wapp, root = web_app
    _seed(root, "a.com")
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/report/final_report.html")
        assert r.status_code == 200
        assert b"full report" in r.data


def test_results_report_file_404_for_unknown_target(web_app):
    wapp, root = web_app
    with wapp.app.test_client() as c:
        r = c.get("/results/nope.com/report/final_report.html")
        assert r.status_code == 404


def test_results_report_file_404_for_missing_file(web_app):
    wapp, root = web_app
    _seed(root, "a.com")
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/report/does-not-exist.html")
        assert r.status_code == 404

# ----------------------------------------------------------------------
# /results/<target_ref>/files  and  /file/<rel>
# ----------------------------------------------------------------------
def test_results_files_lists_recon_output(web_app):
    wapp, root = web_app
    base = _seed(root, "a.com", findings=[])
    (base / "raw" / "apidocs").mkdir(parents=True, exist_ok=True)
    (base / "raw" / "apidocs" / "candidates.txt").write_text("https://a.com/api\n")
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/files")
        assert r.status_code == 200
        # Both a report file and a nested raw file are listed.
        assert b"final_report.html" in r.data
        assert b"candidates.txt" in r.data
        assert b"raw/apidocs" in r.data


def test_results_file_view_text_inline(web_app):
    wapp, root = web_app
    base = _seed(root, "a.com")
    (base / "raw").mkdir(parents=True, exist_ok=True)
    (base / "raw" / "note.txt").write_text("hello-recon-file")
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/file/raw/note.txt")
        assert r.status_code == 200
        assert b"file-content" in r.data      # rendered in the inline template
        assert b"hello-recon-file" in r.data


def test_results_file_view_raw_serves_plain(web_app):
    wapp, root = web_app
    base = _seed(root, "a.com")
    (base / "raw").mkdir(parents=True, exist_ok=True)
    (base / "raw" / "note.txt").write_text("hello-recon-file")
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/file/raw/note.txt?raw=1")
        assert r.status_code == 200
        assert r.data == b"hello-recon-file"


def test_results_file_view_report_not_swallowed_by_report_route(web_app):
    """`.../file/report/<name>` must resolve to the file viewer, not the
    legacy report-serving route (greedy <path> collision)."""
    wapp, root = web_app
    _seed(root, "a.com")  # writes report/final_report.html
    with wapp.app.test_client() as c:
        r = c.get("/results/a.com/file/report/final_report.html?raw=1")
        assert r.status_code == 200
        assert b"full report" in r.data
        # And the original report route still works unchanged.
        assert c.get("/results/a.com/report/final_report.html").status_code == 200


def test_results_file_view_blocks_traversal(web_app):
    wapp, root = web_app
    _seed(root, "a.com")
    with wapp.app.test_client() as c:
        assert c.get("/results/a.com/file/logs/../../../../etc/passwd").status_code == 404
        assert c.get("/results/a.com/file/raw/nope.txt").status_code == 404


def test_results_file_view_unknown_target_404(web_app):
    wapp, root = web_app
    with wapp.app.test_client() as c:
        assert c.get("/results/nope.com/files").status_code == 404
        assert c.get("/results/nope.com/file/raw/x.txt").status_code == 404
