"""Tests for modules.dashboard — the cross-target outputs/ overview.

build_dashboard reads report/summary.json + logs/stages.json for every
outputs/<target>/ directory and writes a single outputs/dashboard.html.
Neither file source is touched here — we hand-build minimal but realistic
copies of what modules/report.py + main.py actually write, matching the
shapes verified against a real outputs/<domain>/ tree.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import dashboard
from modules.utils import create_output_structure


# ----------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------
def test_classify_health_no_summary_is_no_report():
    assert dashboard._classify_health([], has_summary=False) == "no_report"


def test_classify_health_no_failures_is_ok():
    stages = [{"stage": "subdomain", "status": "success"},
              {"stage": "nuclei_default", "status": "success"}]
    assert dashboard._classify_health(stages, has_summary=True) == "ok"


def test_classify_health_core_stage_failure_is_broken():
    stages = [{"stage": "httpx", "status": "failed", "error": "timeout"}]
    assert dashboard._classify_health(stages, has_summary=True) == "broken"


def test_classify_health_peripheral_failure_is_degraded():
    stages = [{"stage": "apidocs", "status": "failed", "error": "boom"}]
    assert dashboard._classify_health(stages, has_summary=True) == "degraded"


def test_risk_score_weights_critical_highest():
    high_crit = dashboard._risk_score({"critical": 1}, {}, 0)
    many_low = dashboard._risk_score({"low": 50}, {}, 0)
    assert high_crit > many_low


def test_risk_score_adds_secrets_and_high_value():
    base = dashboard._risk_score({}, {}, 0)
    with_secrets = dashboard._risk_score({}, {"high": 1}, 0)
    with_hv = dashboard._risk_score({}, {}, 3)
    assert with_secrets > base
    assert with_hv == base + 3


def test_risk_score_caps_high_value_so_url_count_cant_dominate():
    """Regression: on a real guildwars2.com run, high_value_targets hit
    75,981 (pattern-matched URLs, not findings) and swamped every
    severity-weighted score before the cap was added."""
    huge_url_count_no_findings = dashboard._risk_score({}, {}, 75_981)
    real_findings_small_surface = dashboard._risk_score(
        {"critical": 1}, {"high": 1}, 5,
    )
    assert real_findings_small_surface > huge_url_count_no_findings


def test_stale_days_computes_from_iso_timestamp():
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    assert dashboard._stale_days(old) >= 44


def test_stale_days_handles_missing_and_bad_input():
    assert dashboard._stale_days(None) is None
    assert dashboard._stale_days("not-a-date") is None


# ----------------------------------------------------------------------
# discover_targets
# ----------------------------------------------------------------------
def test_discover_targets_lists_dirs_skips_dotfiles(tmp_path: Path):
    (tmp_path / "a.com").mkdir()
    (tmp_path / "b.com").mkdir()
    (tmp_path / ".gitkeep").write_text("")
    found = dashboard.discover_targets(tmp_path)
    assert [p.name for p in found] == ["a.com", "b.com"]


def test_discover_targets_missing_root_returns_empty(tmp_path: Path):
    assert dashboard.discover_targets(tmp_path / "nope") == []


# ----------------------------------------------------------------------
# _load_target — single target, hand-built summary.json + stages.json
# ----------------------------------------------------------------------
def _seed_target(root: Path, domain: str, *, health_stages=None,
                  nuclei_sev=None, secrets_sev=None, secrets_findings=None,
                  high_value=None, scan_end="2026-07-28T10:00:00+00:00",
                  with_summary=True, delta_extra=None) -> Path:
    base = create_output_structure(domain, root=str(root))
    if with_summary:
        summary = {
            "meta": {"domain": domain, "scan_start": "2026-07-28T09:00:00+00:00",
                      "scan_end": scan_end, "scan_duration_seconds": 3600.0},
            "counts": {"subdomains": 10, "all_urls": 100},
            "nuclei": {"default": {"findings": [], "severity_count": nuclei_sev or {}}},
            "jsluice_secrets": {"findings": secrets_findings or [],
                                 "severity_count": secrets_sev or {}},
            "high_value_targets": high_value or [],
        }
        (base / "report").mkdir(parents=True, exist_ok=True)
        (base / "report" / "summary.json").write_text(json.dumps(summary))
        (base / "report" / "final_report.html").write_text("<html></html>")

    stages = list(health_stages or [])
    if delta_extra is not None:
        stages.append({"stage": "scan_diff", "status": "success", "extra": delta_extra})
    (base / "logs" / "stages.json").write_text(json.dumps(stages))
    return base


def test_load_target_ok_run(tmp_path: Path):
    base = _seed_target(
        tmp_path, "ok.com",
        health_stages=[{"stage": "subdomain", "status": "success"}],
        nuclei_sev={"critical": 1, "high": 2},
        secrets_sev={"high": 1}, secrets_findings=[{"kind": "X"}],
        high_value=[{"url": "https://ok.com/admin", "categories": ["admin"]}],
        delta_extra={"first_run": False,
                     "new": {"subdomains": 5, "alive": 0, "urls": 12, "findings": 1},
                     "totals": {"subdomains": 50, "alive": 10, "urls": 500, "findings": 3}},
    )
    rec = dashboard._load_target(base, tmp_path / "dashboard.html")
    assert rec["domain"] == "ok.com"
    assert rec["has_report"] is True
    assert rec["health"] == "ok"
    assert rec["nuclei_severity"] == {"critical": 1, "high": 2}
    assert rec["secrets_total"] == 1
    assert rec["high_value_count"] == 1
    assert rec["delta"]["new"]["subdomains"] == 5
    assert rec["report_rel"] == "ok.com/report/final_report.html"
    assert rec["risk_score"] > 0


def test_load_target_no_summary_is_no_report(tmp_path: Path):
    base = _seed_target(tmp_path, "crashed.com", with_summary=False)
    rec = dashboard._load_target(base, tmp_path / "dashboard.html")
    assert rec["has_report"] is False
    assert rec["health"] == "no_report"
    assert rec["report_rel"] is None
    assert rec["risk_score"] == 0


def test_load_target_reports_failed_stages_and_missing_tools(tmp_path: Path):
    base = _seed_target(
        tmp_path, "degraded.com",
        health_stages=[
            {"stage": "apidocs", "status": "failed", "error": "boom"},
            {"stage": "dirsearch", "status": "skipped",
             "error": "dirsearch binary not found (optional, skipped)"},
        ],
    )
    rec = dashboard._load_target(base, tmp_path / "dashboard.html")
    assert rec["health"] == "degraded"
    assert "apidocs" in rec["failed_stages"]
    assert "dirsearch" in rec["missing_tools"]


# ----------------------------------------------------------------------
# build_dashboard — multi-target, I/O
# ----------------------------------------------------------------------
def test_build_dashboard_lists_all_targets_sorted_by_risk(tmp_path: Path):
    root = tmp_path / "outputs"
    _seed_target(root, "hot.com",
                 health_stages=[{"stage": "subdomain", "status": "success"}],
                 nuclei_sev={"critical": 2})
    _seed_target(root, "quiet.com",
                 health_stages=[{"stage": "subdomain", "status": "success"}],
                 nuclei_sev={"low": 1})
    _seed_target(root, "crashed.com", with_summary=False)

    res = dashboard.build_dashboard(root)
    assert res["status"] == "success"
    assert res["count"] == 3
    html = (root / "dashboard.html").read_text()

    # hottest target (critical findings) appears before the quiet one
    assert html.index("hot.com") < html.index("quiet.com")
    # crashed (no report) target is still listed, not silently dropped
    assert "crashed.com" in html
    assert "NO REPORT" in html
    assert 'href="hot.com/report/final_report.html"' in html


def test_build_dashboard_flags_stale_and_broken(tmp_path: Path):
    root = tmp_path / "outputs"
    _seed_target(root, "old.com", scan_end="2020-01-01T00:00:00+00:00")
    _seed_target(root, "broken.com",
                 health_stages=[{"stage": "httpx", "status": "failed", "error": "x"}])

    res = dashboard.build_dashboard(root)
    assert res["extra"]["stale"] == 1
    assert res["extra"]["broken"] == 1
    html = (root / "dashboard.html").read_text()
    assert "stale" in html.lower()
    assert "BROKEN" in html


def test_build_dashboard_empty_state_when_no_targets(tmp_path: Path):
    root = tmp_path / "outputs"
    res = dashboard.build_dashboard(root)
    assert res["status"] == "skipped"
    assert res["count"] == 0
    html = (root / "dashboard.html").read_text()
    assert "No targets scanned yet" in html


def test_build_dashboard_missing_root_still_writes_empty_state(tmp_path: Path):
    root = tmp_path / "does-not-exist-yet"
    res = dashboard.build_dashboard(root)
    assert res["status"] == "skipped"
    assert (root / "dashboard.html").exists()


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def test_main_defaults_to_outputs_and_prints_summary(tmp_path: Path, capsys, monkeypatch):
    root = tmp_path / "outputs"
    _seed_target(root, "a.com", health_stages=[{"stage": "subdomain", "status": "success"}])
    monkeypatch.chdir(tmp_path)
    rc = dashboard.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dashboard:" in out
    assert "1 target" in out


def test_main_accepts_explicit_root(tmp_path: Path, capsys):
    root = tmp_path / "custom_outputs"
    rc = dashboard.main([str(root)])
    assert rc == 0
    assert (root / "dashboard.html").exists()
    assert "0 target" in capsys.readouterr().out
