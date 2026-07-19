"""Tests for modules/scandiff.py — "what's new since the last scan".

diff_snapshots is pure; build_scan_diff is the I/O wrapper that persists
state across runs. We test the diff logic, the first-run baseline, and a
full baseline→change→detect cycle.
"""
from __future__ import annotations

from pathlib import Path

from modules.scandiff import (
    STATE_FILE,
    build_scan_diff,
    diff_snapshots,
    render,
    snapshot,
)
from modules.utils import create_output_structure, load_json, write_json, write_lines


# ----------------------------------------------------------------------
# diff_snapshots — pure logic
# ----------------------------------------------------------------------
def test_diff_detects_new_items():
    prev = {"subdomains": ["a.x.com"], "findings": []}
    curr = {"subdomains": ["a.x.com", "b.x.com"], "findings": ["cve@u"]}
    d = diff_snapshots(prev, curr)
    assert d["subdomains"]["new"] == ["b.x.com"]
    assert d["subdomains"]["total"] == 2
    assert d["findings"]["new"] == ["cve@u"]


def test_diff_counts_removed():
    prev = {"alive": ["a", "b", "c"]}
    curr = {"alive": ["a"]}
    d = diff_snapshots(prev, curr)
    assert d["alive"]["new"] == []
    assert d["alive"]["removed"] == 2
    assert d["alive"]["total"] == 1


def test_diff_empty_prev_is_all_new():
    curr = {"urls": ["u1", "u2"]}
    d = diff_snapshots({}, curr)
    assert d["urls"]["new"] == ["u1", "u2"]


def test_diff_no_change():
    snap = {"subdomains": ["a", "b"]}
    d = diff_snapshots(snap, snap)
    assert d["subdomains"]["new"] == []
    assert d["subdomains"]["removed"] == 0


# ----------------------------------------------------------------------
# render
# ----------------------------------------------------------------------
def test_render_first_run_is_baseline():
    diff = diff_snapshots({}, {"subdomains": ["a"], "alive": [], "urls": [],
                               "findings": []})
    txt = render(diff, "x.com", first_run=True)
    assert "baseline established" in txt


def test_render_lists_new_findings_first():
    diff = diff_snapshots(
        {"findings": [], "subdomains": [], "alive": [], "urls": []},
        {"findings": ["cve-2024@https://x.com/a"], "subdomains": ["new.x.com"],
         "alive": [], "urls": []},
    )
    txt = render(diff, "x.com", first_run=False)
    assert txt.index("New nuclei findings") < txt.index("New subdomains")
    assert "cve-2024@https://x.com/a" in txt


def test_render_caps_url_list():
    many = [f"https://x.com/{i}" for i in range(250)]
    diff = diff_snapshots(
        {"findings": [], "subdomains": [], "alive": [], "urls": []},
        {"findings": [], "subdomains": [], "alive": [], "urls": many},
    )
    txt = render(diff, "x.com", first_run=False)
    assert "and 150 more" in txt  # 250 new, capped at 100


# ----------------------------------------------------------------------
# build_scan_diff — full baseline → change → detect cycle
# ----------------------------------------------------------------------
def test_build_first_run_then_detects_change(tmp_path: Path):
    base = create_output_structure("x.com", root=str(tmp_path))
    write_lines(base / "processed" / "subdomains.txt", ["a.x.com"])
    write_lines(base / "processed" / "alive.txt", ["https://a.x.com"])
    write_lines(base / "processed" / "all_urls.txt", ["https://a.x.com/1"])

    # Run 1 — baseline.
    r1 = build_scan_diff(base, "x.com")
    assert r1["extra"]["first_run"] is True
    assert (base / STATE_FILE).exists()

    # Run 2 — a new subdomain + a new finding appear.
    write_lines(base / "processed" / "subdomains.txt", ["a.x.com", "b.x.com"])
    write_json(base / "findings" / "default" / "nuclei.json",
               {"findings": [{"template-id": "cve-2024-1",
                              "matched-at": "https://b.x.com"}]})
    r2 = build_scan_diff(base, "x.com")
    assert r2["extra"]["first_run"] is False
    assert r2["extra"]["new"]["subdomains"] == 1
    assert r2["extra"]["new"]["findings"] == 1

    delta = (base / "report" / "delta.md").read_text()
    assert "b.x.com" in delta
    assert "cve-2024-1@https://b.x.com" in delta

    # Run 3 — nothing changed since run 2.
    r3 = build_scan_diff(base, "x.com")
    assert sum(r3["extra"]["new"].values()) == 0


def test_snapshot_builds_finding_keys(tmp_path: Path):
    base = create_output_structure("x.com", root=str(tmp_path))
    write_json(base / "findings" / "dynamic" / "nuclei.json",
               {"findings": [{"template-id": "xss", "matched-at": "https://x.com/q"}]})
    snap = snapshot(base)
    assert "xss@https://x.com/q" in snap["findings"]


def test_state_persists_current_snapshot(tmp_path: Path):
    base = create_output_structure("x.com", root=str(tmp_path))
    write_lines(base / "processed" / "subdomains.txt", ["a.x.com", "b.x.com"])
    build_scan_diff(base, "x.com")
    state = load_json(base / STATE_FILE)
    assert sorted(state["subdomains"]) == ["a.x.com", "b.x.com"]
