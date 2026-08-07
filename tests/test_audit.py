"""Tests for modules.audit — the reviewer's-map / duplicate-check tooling.

build_index writes INDEX.md grouping artefacts by review role; audit_overlap
reports real containment, byte-identical duplicates and empty files. Neither
touches the pipeline, so these tests just exercise the reporting logic on a
hand-built output tree.
"""
from __future__ import annotations

from pathlib import Path

from modules import audit, layout
from modules.utils import create_output_structure, write_lines


def _seed(tmp_path) -> Path:
    """A minimal but representative output tree."""
    base = create_output_structure("x.com", root=str(tmp_path))
    # master + a true subset of it
    write_lines(layout.path(base, "all_urls.txt"),
                [f"https://x.com/{i}" for i in range(10)])
    write_lines(layout.path(base, "dynamic_urls.txt"),
                [f"https://x.com/{i}" for i in range(5)])   # ⊆ all_urls
    write_lines(layout.path(base, "subdomains.txt"), ["a.x.com", "b.x.com"])
    # empty (skipped tool) — created but 0 bytes
    (layout.path(base, "arjun_params.txt")).write_text("")
    (base / "raw" / "waymore").mkdir(parents=True, exist_ok=True)
    (base / "raw" / "waymore" / "waymore_raw.txt").write_text("")
    return base


def test_build_index_writes_grouped_markdown(tmp_path):
    base = _seed(tmp_path)
    res = audit.build_index(base, "x.com")

    assert res["status"] == "success"
    idx = base / "INDEX.md"
    assert idx.exists()
    text = idx.read_text()
    # the three review groups are present
    assert "🎯 Review these" in text
    assert "🔧 Intermediate" in text
    assert "📦 raw/" in text
    # subset relationship is spelled out
    assert "subset of `all_urls.txt`" in text
    # counts render
    assert "10 lines" in text


def test_build_index_lists_empty_files(tmp_path):
    base = _seed(tmp_path)
    res = audit.build_index(base, "x.com")

    assert res["extra"]["empty_files"] == 2   # arjun_params + waymore_raw
    text = (base / "INDEX.md").read_text()
    assert "⚪ Empty" in text
    assert "processed/targets/arjun_params.txt" in text
    assert "raw/waymore/waymore_raw.txt" in text


def test_find_empty_scans_processed_and_raw(tmp_path):
    base = _seed(tmp_path)
    empties = audit._find_empty(base)
    assert "processed/targets/arjun_params.txt" in empties
    assert "raw/waymore/waymore_raw.txt" in empties
    # a non-empty file is never listed
    assert "processed/corpus/all_urls.txt" not in empties


def test_audit_overlap_flags_identical_and_subset(tmp_path, capsys):
    base = _seed(tmp_path)
    # make two byte-identical files to trigger the duplicate detector
    dup_a = layout.path(base, "js_urls.txt")
    dup_b = layout.path(base, "ffuf_urls.txt")
    write_lines(dup_a, ["https://x.com/same"])
    dup_b.write_text(dup_a.read_text())

    summary = audit.audit_overlap(base)
    out = capsys.readouterr().out

    # dynamic_urls is fully contained in all_urls → reported as subset
    assert "dynamic_urls.txt" in out
    assert "⊆ subset" in out
    # identical files detected
    assert summary["duplicates"], "expected at least one duplicate group"
    flat = {f for group in summary["duplicates"] for f in group}
    assert "processed/corpus/js_urls.txt" in flat and "processed/sources/ffuf_urls.txt" in flat
    # empties surfaced
    assert "processed/targets/arjun_params.txt" in summary["empty"]


def test_audit_overlap_no_false_self_duplicate(tmp_path):
    """A file catalogued in two lists must not be reported identical to
    itself (regression: all_urls appears in both _URL_FILES and the
    intermediate catalogue)."""
    base = _seed(tmp_path)
    summary = audit.audit_overlap(base)
    for group in summary["duplicates"]:
        assert len(set(group)) == len(group), f"self-dupe in {group}"


def test_main_requires_arg(capsys):
    assert audit.main([]) == 2
    assert "usage" in capsys.readouterr().out
