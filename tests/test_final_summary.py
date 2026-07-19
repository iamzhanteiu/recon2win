"""Tests for main._build_final_summary — nuclei findings path (v2 layout).

Regression guard for the path drift where nuclei writes to
``findings/<kind>/nuclei.json`` (v2, via ``findings_dir``) but the
summary builder read the old flat ``findings/nuclei_<kind>.json`` (v1),
so ``load_json`` silently returned None and the severity breakdown was
always empty even when nuclei found hundreds of issues.
"""
from __future__ import annotations

from pathlib import Path

from main import _build_final_summary
from modules.utils import create_output_structure, write_json


def _seed_nuclei(base: Path, kind: str, sev_count: dict) -> None:
    """Write a nuclei.json exactly where the nuclei stage writes it."""
    (base / "findings" / kind).mkdir(parents=True, exist_ok=True)
    write_json(
        base / "findings" / kind / "nuclei.json",
        {"findings": [], "severity_count": sev_count},
    )


def test_final_summary_reads_v2_findings_path(tmp_path: Path):
    """Severity counts from findings/<kind>/nuclei.json must surface in
    the summary (not be swallowed by a stale path)."""
    base = create_output_structure("example.com", root=str(tmp_path))
    _seed_nuclei(base, "default", {"info": 533, "low": 52, "high": 0})
    _seed_nuclei(base, "dynamic", {"critical": 1})

    summary = _build_final_summary("example.com", base)
    extra = summary["extra"]

    assert extra["nuclei_default_findings_by_severity"] == {
        "info": 533, "low": 52, "high": 0,
    }
    assert extra["nuclei_dynamic_findings_by_severity"] == {"critical": 1}


def test_final_summary_does_not_read_v1_flat_path(tmp_path: Path):
    """A file at the OLD flat path must be ignored — proves the reader
    no longer points there."""
    base = create_output_structure("example.com", root=str(tmp_path))
    # Old v1 location — must NOT be consulted.
    write_json(
        base / "findings" / "nuclei_default.json",
        {"severity_count": {"critical": 99}},
    )
    # Correct v2 location — this is what should win.
    _seed_nuclei(base, "default", {"info": 5})

    summary = _build_final_summary("example.com", base)
    sev = summary["extra"]["nuclei_default_findings_by_severity"]
    assert sev == {"info": 5}
    assert "critical" not in sev  # the stale v1 file was not read


def test_final_summary_empty_when_no_findings(tmp_path: Path):
    """Missing nuclei.json → empty dict, no crash."""
    base = create_output_structure("example.com", root=str(tmp_path))
    summary = _build_final_summary("example.com", base)
    extra = summary["extra"]
    assert extra["nuclei_default_findings_by_severity"] == {}
    assert extra["nuclei_dynamic_findings_by_severity"] == {}
