"""Tests for modules/priority.py — post-scan triage ranking.

score_targets is a pure function over already-loaded data; build_priority_targets
is the I/O wrapper. We test the ranking logic (severity weighting, multi-source
accumulation, path bonuses, dedup) and the end-to-end file write.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import layout
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


def test_misconfig_path_hints_score():
    # /actuator/heapdump matches BOTH the specific heapdump hint (500) and
    # the pre-existing generic "actuator" substring hint (300) — correct
    # accumulation, not double-counting the same signal twice.
    ranked = score_targets(extra_urls=["https://x.com/actuator/heapdump"])
    assert ranked[0]["url"] == "https://x.com/actuator/heapdump"
    assert "heap dump" in ranked[0]["reasons"]
    assert "spring actuator" in ranked[0]["reasons"]
    assert ranked[0]["score"] == 500 + 300


def test_jenkins_script_console_path_hint_scores():
    ranked = score_targets(extra_urls=["https://ci.x.com/script"])
    assert "jenkins script console" in ranked[0]["reasons"]
    assert ranked[0]["score"] == 400


def test_misconfig_finding_high_confidence_scores_like_medium_nuclei():
    ranked = score_targets(misconfig_findings=[
        {"url": "https://ci.x.com/whoAmI",
         "service": "Jenkins whoAmI", "confidence": "high"},
    ])
    assert ranked[0]["url"] == "https://ci.x.com/whoAmI"
    assert any("misconfig (Jenkins whoAmI)" in r for r in ranked[0]["reasons"])
    assert ranked[0]["score"] == 400


def test_misconfig_finding_low_confidence_scores_like_info():
    ranked = score_targets(misconfig_findings=[
        {"url": "https://c.x.com/agent/self",
         "service": "unverified (/v1/agent/self)", "confidence": "low"},
    ])
    assert ranked[0]["score"] == 15


def test_misconfig_finding_and_nuclei_accumulate_on_same_url():
    ranked = score_targets(
        nuclei_findings=[_finding("https://ci.x.com/whoAmI", "info")],
        misconfig_findings=[
            {"url": "https://ci.x.com/whoAmI",
             "service": "Jenkins whoAmI", "confidence": "high"},
        ],
    )
    assert ranked[0]["score"] == 15 + 400


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
# score_targets — demote blanket-deny hosts / baseline-noise URLs
# ----------------------------------------------------------------------
def test_blanket_host_is_demoted_not_dropped():
    plain = score_targets(ffuf_urls=["https://x.com/.git/config"])[0]
    demoted = score_targets(
        ffuf_urls=["https://x.com/.git/config"], blanket_hosts={"x.com"},
    )[0]
    assert demoted["score"] == round(plain["score"] * 0.1)
    assert demoted["score"] > 0
    assert "blanket-deny host" in demoted["reasons"][0]


def test_noise_url_is_demoted_not_dropped():
    plain = score_targets(parameterized_urls=["https://x.com/api/thing?a=1"])[0]
    demoted = score_targets(
        parameterized_urls=["https://x.com/api/thing?a=1"],
        noise_urls={"x.com/api/thing"},
    )[0]
    assert demoted["score"] == round(plain["score"] * 0.1)
    assert "not-found shape" in demoted["reasons"][0]


def test_noise_match_ignores_query_value_template_mismatch():
    # parameterized_urls.txt writes the value-stripped template
    # ("?limit="); alive_urls_detail.json (what _noise_urls reads) has the
    # real probed value ("?limit=100") — the match must survive that.
    plain = score_targets(
        parameterized_urls=["https://spa.x.com/patients/me/encounters?limit="],
    )[0]
    demoted = score_targets(
        parameterized_urls=["https://spa.x.com/patients/me/encounters?limit="],
        noise_urls={"spa.x.com/patients/me/encounters"},
    )[0]
    assert demoted["score"] == round(plain["score"] * 0.1)


def test_blanket_and_noise_leave_unrelated_urls_untouched():
    ranked = score_targets(
        ffuf_urls=["https://good.com/real", "https://x.com/.git/config"],
        blanket_hosts={"x.com"},
    )
    good = next(t for t in ranked if t["url"] == "https://good.com/real")
    assert good["reasons"] == ["ffuf hit"]


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
    write_lines(layout.path(base, "parameterized_urls.txt"),
                ["https://x.com/api/user?id="])
    write_lines(layout.path(base, "dirsearch_urls.txt"),
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


def test_build_demotes_blanket_deny_host(tmp_path: Path):
    # ecouch.dialogue.co: 24/25 ffuf hits were an identical Cloudflare 403
    # block page, yet .git/config still ranked #3 in the real run.
    base = create_output_structure("x.com", root=str(tmp_path))
    write_lines(layout.path(base, "ffuf_urls.txt"),
                ["https://ecouch.x.com/.git/config"])
    ffuf_dir = base / "raw" / "ffuf"
    ffuf_dir.mkdir(parents=True, exist_ok=True)
    (ffuf_dir / "ecouch.x.com.json").write_text(json.dumps({"results": [
        {"url": f"https://ecouch.x.com/p{i}", "status": 403, "words": 20}
        for i in range(40)
    ]}), encoding="utf-8")

    res = build_priority_targets(base, "x.com")
    hit = next(t for t in res["extra"]["targets"]
               if t["url"] == "https://ecouch.x.com/.git/config")
    assert "blanket-deny host" in hit["reasons"][0]
    # undemoted this would be 220 (ffuf) + 350 (/.git hint) + 200 (/config
    # hint, since "/.git/config" also contains "/config") = 770 — matches
    # the real score measured on outputs/dialogue.co exactly.
    assert hit["score"] == round(770 * 0.1)


def test_build_demotes_spa_fallback_noise_url(tmp_path: Path):
    # app.dialogue.co: every path (including a jsluice-mined one that was
    # never a real route) came back as the same SPA shell.
    base = create_output_structure("x.com", root=str(tmp_path))
    rdir = base / "raw" / "baseline"
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "probe_dirsearch.jsonl").write_text("\n".join(
        json.dumps({"url": u, "input": u, "status_code": 200,
                    "content_length": 4267, "words": 300, "lines": 20,
                    "content_type": "text/html"})
        for u in ("https://spa.x.com/ab12cd34",
                  "https://spa.x.com/ab12cd34/ab12cd34",
                  "https://spa.x.com/ab12cd34.html")
    ), encoding="utf-8")
    write_json(layout.path(base, "alive_urls_detail.json"), [
        {"url": "https://spa.x.com/patients/me/encounters?limit=100",
         "status_code": 200, "content_length": 4267,
         "words": 300, "lines": 20, "content_type": "text/html"},
    ])
    write_lines(layout.path(base, "parameterized_urls.txt"),
                ["https://spa.x.com/patients/me/encounters?limit=100"])

    res = build_priority_targets(base, "x.com")
    hit = next(t for t in res["extra"]["targets"]
               if t["url"] == "https://spa.x.com/patients/me/encounters?limit=100")
    assert "not-found shape" in hit["reasons"][0]
    assert hit["score"] == round(300 * 0.1)
