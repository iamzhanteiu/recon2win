"""Tests for modules/xlsx_report.py.

Covers:
  * feature is fully opt-in — ``build_report(..., xlsx=False)`` (the
    default) never touches openpyxl or writes an .xlsx file
  * ``--xlsx-report`` / ``report.xlsx: true`` produces a workbook with the
    expected sheets, sized from the same ``data`` dict as HTML/MD/JSON
  * the hub ("URL Surface") sheet and detail sheets cross-link both ways
  * a missing ``openpyxl`` degrades to a skipped result, never an exception
  * values that look like spreadsheet formulas (target-controlled data:
    titles, secrets, URLs) are neutralized, not written as live formulas
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from modules import xlsx_report
from modules.report import ReportBuilder, ReportInputs, build_report
from tests.test_report import fake_outputs as _fake_outputs_fixture

openpyxl = pytest.importorskip("openpyxl")


@pytest.fixture
def fake_outputs(tmp_path: Path) -> Path:
    """Reuse test_report.py's realistic output tree instead of duplicating it."""
    return _fake_outputs_fixture.__wrapped__(tmp_path)


# ----------------------------------------------------------------------
# Opt-in behaviour
# ----------------------------------------------------------------------
def test_xlsx_not_generated_by_default(fake_outputs: Path):
    info = build_report(
        fake_outputs, "example.com", {},
        scan_start=datetime.now(timezone.utc),
        scan_end=datetime.now(timezone.utc),
    )
    assert info["xlsx"] is None
    assert info["xlsx_skipped_reason"] is None
    assert not (fake_outputs / "report" / "final_report.xlsx").exists()


def test_xlsx_generated_when_requested(fake_outputs: Path):
    info = build_report(
        fake_outputs, "example.com", {},
        scan_start=datetime.now(timezone.utc),
        scan_end=datetime.now(timezone.utc),
        xlsx=True,
    )
    assert info["xlsx"] == str(fake_outputs / "report" / "final_report.xlsx")
    assert info["xlsx_skipped_reason"] is None
    assert Path(info["xlsx"]).exists()


# ----------------------------------------------------------------------
# Sheet coverage
# ----------------------------------------------------------------------
def _collect(output_dir: Path) -> dict:
    inputs = ReportInputs(
        output_dir=output_dir, domain="example.com", cfg={},
        scan_start=datetime.now(timezone.utc), scan_end=datetime.now(timezone.utc),
    )
    return ReportBuilder(inputs).collect()


def test_workbook_has_every_expected_sheet(fake_outputs: Path):
    data = _collect(fake_outputs)
    result = xlsx_report.build_xlsx_report(data, fake_outputs / "report")
    assert not result["skipped"]
    wb = openpyxl.load_workbook(result["path"])
    for expected in [
        "Mục lục", "Tổng quan", "URL Surface", "Nuclei Findings",
        "High-Value Targets", "JS Secrets", "Params", "Forms", "API Docs",
        "Misconfig", "GraphQL", "CORS", "Buckets", "Git Dump",
        "Subdomains & DNS", "Files",
    ]:
        assert expected in wb.sheetnames

    nuclei_ws = wb["Nuclei Findings"]
    # header + 3 findings from the fixture
    assert nuclei_ws.max_row == 4
    assert [c.value for c in nuclei_ws[1]][:4] == [
        "Severity", "Template ID", "Name", "Matched At"]


def test_toc_row_counts_match_sheet_row_counts(fake_outputs: Path):
    data = _collect(fake_outputs)
    result = xlsx_report.build_xlsx_report(data, fake_outputs / "report")
    wb = openpyxl.load_workbook(result["path"])
    toc = wb["Mục lục"]
    rows = {r[0].value: r[1].value for r in toc.iter_rows(min_row=2)}
    assert rows["Nuclei Findings"] == 3
    assert rows["JS Secrets"] == 2


# ----------------------------------------------------------------------
# Cross-referencing — the whole point of the feature
# ----------------------------------------------------------------------
def test_detail_sheet_links_back_to_hub_row(fake_outputs: Path):
    data = _collect(fake_outputs)
    result = xlsx_report.build_xlsx_report(data, fake_outputs / "report")
    wb = openpyxl.load_workbook(result["path"])
    nuclei_ws = wb["Nuclei Findings"]
    hub_ws = wb["URL Surface"]

    # row 2 is the "Exposed .env" finding at https://b.example.com/.env
    matched_url = nuclei_ws.cell(row=2, column=4).value
    hub_link_cell = nuclei_ws.cell(row=2, column=7)
    assert hub_link_cell.hyperlink is not None
    target = hub_link_cell.hyperlink.target
    assert target.startswith("#'URL Surface'!B")
    hub_row = int(target.rsplit("B", 1)[1])
    assert hub_ws.cell(row=hub_row, column=2).value == matched_url


def test_hub_links_forward_to_first_matching_detail_row(fake_outputs: Path):
    data = _collect(fake_outputs)
    result = xlsx_report.build_xlsx_report(data, fake_outputs / "report")
    wb = openpyxl.load_workbook(result["path"])
    hub_ws = wb["URL Surface"]
    nuclei_ws = wb["Nuclei Findings"]

    headers = [c.value for c in hub_ws[1]]
    nuclei_col = headers.index("Nuclei Findings") + 1
    url_col_idx = headers.index("URL") + 1

    hit_row = None
    for r in range(2, hub_ws.max_row + 1):
        if hub_ws.cell(row=r, column=nuclei_col).value:
            hit_row = r
            break
    assert hit_row is not None, "expected at least one URL with a nuclei hit"

    cell = hub_ws.cell(row=hit_row, column=nuclei_col)
    assert cell.hyperlink is not None
    assert cell.hyperlink.target.startswith("#'Nuclei Findings'!A")
    target_row = int(cell.hyperlink.target.rsplit("A", 1)[1])
    assert nuclei_ws.cell(row=target_row, column=4).value == \
        hub_ws.cell(row=hit_row, column=url_col_idx).value


def test_files_sheet_links_to_real_files(fake_outputs: Path):
    data = _collect(fake_outputs)
    result = xlsx_report.build_xlsx_report(data, fake_outputs / "report")
    wb = openpyxl.load_workbook(result["path"])
    files_ws = wb["Files"]
    linked = [
        r for r in files_ws.iter_rows(min_row=2)
        if r[3].value == "yes" and r[5].hyperlink is not None
    ]
    assert linked, "at least one existing file should carry an Open hyperlink"


# ----------------------------------------------------------------------
# Missing dependency degrades gracefully
# ----------------------------------------------------------------------
def test_missing_openpyxl_skips_without_raising(monkeypatch, fake_outputs: Path):
    data = _collect(fake_outputs)
    monkeypatch.setattr(xlsx_report, "HAVE_OPENPYXL", False)
    result = xlsx_report.build_xlsx_report(data, fake_outputs / "report")
    assert result["skipped"] is True
    assert result["path"] is None
    assert "openpyxl" in result["reason"]
    assert "pip install" in result["reason"]


def test_malformed_data_skips_instead_of_raising(tmp_path: Path):
    # e.g. a corrupted summary.json round-trip that yields wrong shapes.
    bad_data = {"nuclei": "not-a-dict", "counts": {}, "meta": {}, "files": []}
    result = xlsx_report.build_xlsx_report(bad_data, tmp_path)
    assert result["skipped"] is True
    assert result["path"] is None
    assert "xlsx generation failed" in result["reason"]


# ----------------------------------------------------------------------
# Formula / CSV injection: target-controlled strings must not become
# live formulas when the workbook is opened in Excel.
# ----------------------------------------------------------------------
@pytest.mark.parametrize("payload", [
    "=cmd|'/c calc'!A1",
    "+1+1",
    "-2+3",
    "@SUM(1,1)",
])
def test_formula_trigger_characters_are_neutralized(payload: str):
    data = {
        "meta": {}, "counts": {}, "files": [],
        "high_value_targets": [{
            "url": "https://example.com/x", "categories": ["admin panel"],
            "status": 200, "content_length": 10,
            "content_type": "text/html", "title": payload,
            "webserver": "nginx", "probed": True,
        }],
        "url_detail_index": {}, "nuclei": {}, "jsluice_secrets": {},
        "jsluice_params": [], "parameterized_sample": [], "forms": [],
        "api_docs": {}, "misconfig_probe": {}, "graphql_targets": [],
        "cors_findings": [], "buckets": {}, "gitdump_hosts": [],
        "dns_records": [], "tool_versions": {},
    }
    builder = xlsx_report._XlsxBuilder(data)
    builder.build_tables()

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        result = builder.write(Path(td) / "out.xlsx")
        wb = openpyxl.load_workbook(result["path"])
        ws = wb["High-Value Targets"]
        title_cell = ws.cell(row=2, column=6)  # Title column
        assert title_cell.value.startswith("'")
        assert title_cell.value == "'" + payload
        assert title_cell.data_type != "f"


def test_safe_leaves_ordinary_strings_and_non_strings_untouched():
    assert xlsx_report._safe("https://example.com/admin") == "https://example.com/admin"
    assert xlsx_report._safe(200) == 200
    assert xlsx_report._safe(None) is None
    assert xlsx_report._safe(["a", "b"]) == "a, b"
