"""Tests for modules/priority.py — post-scan triage ranking.

score_targets is a pure function over already-loaded data; build_priority_targets
is the I/O wrapper. We test the ranking logic (severity weighting, multi-source
accumulation, path bonuses, dedup) and the end-to-end file write.
"""
from __future__ import annotations

from pathlib import Path

from modules.priority import build_priority_targets, render, score_targets
from modules.utils import create_output_structure, write_json, write_lines


def _finding(url, severity, name="x"):
    return {"matched-at": url, "info": {"severity": severity, "name": name}}


# ----------------------------------------------------------------------
# score_targets — ranking logic
# ----------------------------------------------------------------------
def test_high_severity_outranks_info_flood():
    findings = [_finding("https://x.com/db.sql", "high", "DB backup")]
    findings += [_finding(f"https://x.com/i{i}", "info", "header") for i in range(50)]
    ranked = score_targets(nuclei_findings=findings)
    # the single high finding must be #1 despite 50 info findings
    assert ranked[0]["url"] == "https://x.com/db.sql"
    assert ranked[0]["score"] > ranked[1]["score"]


def test_multi_source_accumulates_score_and_reasons():
    # same URL is a nuclei medium AND a parameterized URL
    ranked = score_targets(
        nuclei_findings=[_finding("https://x.com/api/user?id=", "medium", "SQLi")],
        parameterized_urls=["https://x.com/api/user?id="],
    )
    top = ranked[0]
    assert top["url"] == "https://x.com/api/user?id="
    # medium (400) + parameterized (300) + path hints (/api/ 150 + versioned? no)
    assert top["score"] >= 400 + 300
    assert any("nuclei medium" in r for r in top["reasons"])
    assert "parameterized" in top["reasons"]


def test_path_hint_bonus_applied():
    ranked = score_targets(dirsearch_urls=["https://x.com/.env"])
    assert ranked[0]["url"] == "https://x.com/.env"
    assert "env file" in ranked[0]["reasons"]
    # dirsearch base (220) + .env hint (350)
    assert ranked[0]["score"] == 220 + 350


def test_secret_scores_with_severity_bonus():
    ranked = score_targets(secrets=[
        {"url": "https://x.com/app.js", "severity": "high", "kind": "AWSKey"},
    ])
    assert ranked[0]["url"] == "https://x.com/app.js"
    assert any("secret (AWSKey)" in r for r in ranked[0]["reasons"])


def test_trailing_slash_merges_and_dedupes():
    ranked = score_targets(
        parameterized_urls=["https://x.com/a", "https://x.com/a/"],
    )
    # both normalise to the same URL → one entry
    assert len(ranked) == 1
    assert ranked[0]["url"] == "https://x.com/a"


def test_extra_urls_only_score_via_path_hints():
    ranked = score_targets(extra_urls=[
        "https://x.com/boring/page",     # no hint → dropped (score 0)
        "https://x.com/admin/panel",     # /admin hint → kept
    ])
    urls = [t["url"] for t in ranked]
    assert "https://x.com/admin/panel" in urls
    assert "https://x.com/boring/page" not in urls


def test_ignores_non_http_and_garbage():
    ranked = score_targets(
        parameterized_urls=["ftp://x.com/a", "", "not-a-url"],
        nuclei_findings=["not-a-dict", {}],
    )
    assert ranked == []


def test_limit_caps_results():
    findings = [_finding(f"https://x.com/h{i}", "high") for i in range(300)]
    ranked = score_targets(nuclei_findings=findings, limit=25)
    assert len(ranked) == 25


# ----------------------------------------------------------------------
# render
# ----------------------------------------------------------------------
def test_render_includes_score_url_reasons():
    txt = render([{"url": "https://x.com/db.sql", "score": 1520,
                   "reasons": ["nuclei high: DB backup", "sql dump"]}], "x.com")
    assert "https://x.com/db.sql" in txt
    assert "1520" in txt
    assert "nuclei high: DB backup" in txt


def test_render_empty():
    txt = render([], "x.com")
    assert "nothing scored" in txt


# ----------------------------------------------------------------------
# build_priority_targets — end-to-end file write
# ----------------------------------------------------------------------
def test_build_reads_files_and_writes_report(tmp_path: Path):
    base = create_output_structure("x.com", root=str(tmp_path))
    write_json(base / "findings" / "default" / "nuclei.json",
               {"findings": [_finding("https://x.com/db.sql", "high", "DB backup")]})
    write_json(base / "findings" / "jsluice_secrets.json",
               {"findings": [{"url": "https://x.com/app.js",
                              "severity": "high", "kind": "AWSKey"}]})
    write_lines(base / "processed" / "parameterized_urls.txt",
                ["https://x.com/api/user?id="])
    write_lines(base / "processed" / "dirsearch_urls.txt",
                ["https://x.com/.env"])

    res = build_priority_targets(base, "x.com")
    assert res["status"] == "success"
    assert res["count"] >= 4

    out = base / "report" / "priority_targets.txt"
    assert out.exists()
    body = out.read_text()
    # db.sql (high + sql dump path) should rank first
    first_line = [ln for ln in body.splitlines() if ln.startswith("[")][0]
    assert "db.sql" in first_line


def test_build_handles_no_findings(tmp_path: Path):
    base = create_output_structure("x.com", root=str(tmp_path))
    res = build_priority_targets(base, "x.com")
    assert res["status"] == "success"
    assert res["count"] == 0
    assert (base / "report" / "priority_targets.txt").exists()
