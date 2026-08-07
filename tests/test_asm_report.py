"""Tests for modules.asm_report — the correlated ASM report.

The four behaviours worth locking down are the ones that fix real defects
observed in outputs/acronis.com (see docs/report-design.md §B):

  1. a host answering every path identically is a WAF, not a discovery
  2. out-of-scope hosts never enter the ranking
  3. a vendor's own product noun must not outrank verified findings
  4. duplicated secret values collapse to distinct leaks

Fixtures are hand-built minimal copies of what the real stages write,
matching shapes verified against a real outputs/<domain>/ tree.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import asm_report, layout
from modules.utils import create_output_structure


# ----------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------
def test_canon_collapses_dot_segments():
    # expenses.acronis.com ranked the same login page twice because of this.
    a = asm_report.canon("https://x.com/./Login.aspx?ReturnUrl=%2f")
    b = asm_report.canon("https://x.com/Login.aspx?ReturnUrl=%2f")
    assert a == b


def test_canon_sorts_query_and_drops_default_port():
    assert (asm_report.canon("https://X.com:443/a?b=2&a=1")
            == asm_report.canon("https://x.com/a?a=1&b=2"))


def test_canon_strips_trailing_slash():
    assert asm_report.canon("https://x.com/a/") == asm_report.canon("https://x.com/a")


def test_in_scope_matches_domain_and_subdomains():
    assert asm_report.in_scope("api.acronis.com", "acronis.com")
    assert asm_report.in_scope("acronis.com", "acronis.com")
    # the real leak: a lookalike suffix must not pass
    assert not asm_report.in_scope("elearning.unyp.cz", "acronis.com")
    assert not asm_report.in_scope("notacronis.com", "acronis.com")


def test_classify_context_prefers_higher_value_label():
    mult, label = asm_report.classify_context("us-kibana.acronis.com")
    assert mult > 1.0 and label == "infra panel"


def test_classify_context_downgrades_publishing_surfaces():
    mult, label = asm_report.classify_context("kb.acronis.com")
    assert mult < 1.0 and label == "docs/marketing"


def test_classify_context_does_not_downgrade_support_portals():
    # care.acronis.com holds customer data — it carried the one verified
    # finding and must not be treated as marketing.
    mult, _ = asm_report.classify_context("care.acronis.com")
    assert mult >= 1.0


def test_exposure_penalises_bot_protection():
    plain = asm_report.exposure_factor(200, [], None)
    botted = asm_report.exposure_factor(200, ["Cloudflare Bot Management"], "cloudflare")
    assert botted < plain


# ----------------------------------------------------------------------
# Blanket-deny detection
# ----------------------------------------------------------------------
def _write_ffuf(target: Path, host: str, results: list[dict]) -> None:
    d = target / "raw" / "ffuf"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{host}.json").write_text(json.dumps({"results": results}), encoding="utf-8")


def test_blanket_deny_flags_uniform_responder(tmp_path):
    # web-api-arp.acronis.com: 4,097 of 4,099 hits were an identical 403.
    target = tmp_path / "acronis.com"
    _write_ffuf(target, "web-api-arp.acronis.com",
                [{"url": f"https://web-api-arp.acronis.com/p{i}",
                  "status": 403, "words": 20} for i in range(40)])
    flagged = asm_report.detect_blanket_deny(target)
    assert "web-api-arp.acronis.com" in flagged
    assert flagged["web-api-arp.acronis.com"]["share"] == 1.0


def test_blanket_deny_ignores_varied_responses(tmp_path):
    target = tmp_path / "acronis.com"
    _write_ffuf(target, "real.acronis.com",
                [{"url": f"https://real.acronis.com/p{i}",
                  "status": 200, "words": i} for i in range(40)])
    assert asm_report.detect_blanket_deny(target) == {}


def test_blanket_deny_ignores_small_samples(tmp_path):
    target = tmp_path / "acronis.com"
    _write_ffuf(target, "tiny.acronis.com",
                [{"url": "https://tiny.acronis.com/a", "status": 403, "words": 20}] * 3)
    assert asm_report.detect_blanket_deny(target) == {}


# ----------------------------------------------------------------------
# Secret deduplication
# ----------------------------------------------------------------------
def test_dedup_secrets_collapses_repeated_values():
    # acronis.com: 9 findings, 3 distinct GCP keys.
    raw = [
        {"kind": "gcpKey", "severity": "low", "url": "https://a.x.com/1.js", "data": {"key": "K1"}},
        {"kind": "gcpKey", "severity": "low", "url": "https://b.x.com/1.js", "data": {"key": "K1"}},
        {"kind": "gcpKey", "severity": "low", "url": "https://c.x.com/2.js", "data": {"key": "K2"}},
    ]
    out = asm_report.dedup_secrets(raw)
    assert len(out) == 2
    top = out[0]
    assert top["count"] == 2
    assert top["hosts"] == ["a.x.com", "b.x.com"]


def test_dedup_secrets_handles_empty():
    assert asm_report.dedup_secrets([]) == []


# ----------------------------------------------------------------------
# Stage health
# ----------------------------------------------------------------------
def test_stage_health_reports_failed_stage():
    stages = [
        {"stage": "subdomain", "status": "success"},
        {"stage": "arjun", "status": "failed", "error": "timeout",
         "extra": {"elapsed_seconds": 3601}},
    ]
    h = asm_report.stage_health(stages)
    assert h["overall"] < 1.0
    assert any(b["stage"] == "arjun" for b in h["broken"])
    assert h["areas"]["Parameter discovery"]["confidence"] == 0.0


def test_stage_health_treats_error_on_success_as_degraded():
    # dirsearch reports success while carrying "timeout after 4484s".
    stages = [{"stage": "dirsearch", "status": "success", "error": "timeout — salvaged 318"}]
    h = asm_report.stage_health(stages)
    assert h["broken"], "a success carrying an error is still degraded"


def test_stage_health_clean_run_is_full_confidence():
    stages = [{"stage": "subdomain", "status": "success"},
              {"stage": "dnsx", "status": "success"}]
    assert asm_report.stage_health(stages)["overall"] == 1.0


# ----------------------------------------------------------------------
# IDF weighting
# ----------------------------------------------------------------------
def test_idf_downweights_ubiquitous_keyword():
    # A vendor whose product noun is "backup" floods the corpus with it.
    common = ["https://x.com/backup/%d" % i for i in range(1000)]
    rare = ["https://x.com/page/%d" % i for i in range(1000)]
    w_common = asm_report.idf_weights(common)["backup"]
    w_rare = asm_report.idf_weights(rare)["backup"]
    assert w_common < w_rare


# ----------------------------------------------------------------------
# End-to-end
# ----------------------------------------------------------------------
def _build_target(tmp_path: Path) -> Path:
    proc = tmp_path / "processed"
    out = create_output_structure("acme.com", root=str(tmp_path))
    proc, rep, find = out / "processed", out / "report", out / "findings"
    for p in (proc, rep, find / "default", out / "logs"):
        p.mkdir(parents=True, exist_ok=True)

    (proc / "subdomains.txt").write_text("api.acme.com\nwww.acme.com\n", encoding="utf-8")
    (proc / "alive.txt").write_text("https://api.acme.com\n", encoding="utf-8")
    (proc / "alive_urls.txt").write_text("https://api.acme.com/v1/users\n", encoding="utf-8")
    (proc / "all_urls.txt").write_text(
        "https://api.acme.com/v1/users\nhttps://api.acme.com/login\n", encoding="utf-8")
    (proc / "alive_detail.json").write_text(json.dumps([{
        "url": "https://api.acme.com", "host": "api.acme.com", "status_code": 200,
        "tech": ["Nginx"], "webserver": "nginx", "cdn_name": "none",
        "host_ip": "1.2.3.4", "content_type": "application/json",
    }]), encoding="utf-8")
    (proc / "forms.json").write_text(json.dumps({"count": 1, "forms": [{
        "url": "https://api.acme.com/login", "action": "https://evil-third-party.net/x",
        "method": "POST", "enctype": "", "parameters": ["username", "password"],
    }]}), encoding="utf-8")
    (find / "default" / "nuclei.json").write_text(json.dumps({
        "findings": [{
            "template-id": "test-template", "host": "api.acme.com",
            "matched-at": "https://api.acme.com/v1/users",
            "info": {"name": "Test Issue", "severity": "high", "tags": ["test"],
                     "description": "d"},
        }], "severity_count": {"high": 1}, "complete": True,
    }), encoding="utf-8")
    (find / "jsluice_secrets.json").write_text(json.dumps({
        "findings": [], "severity_count": {}}), encoding="utf-8")
    (out / "logs" / "stages.json").write_text(json.dumps(
        [{"stage": "subdomain", "status": "success"}]), encoding="utf-8")
    (rep / "summary.json").write_text(json.dumps(
        {"meta": {"domain": "acme.com", "scan_mode": "active"}}), encoding="utf-8")
    return out


def test_build_asm_report_writes_html(tmp_path):
    out = _build_target(tmp_path)
    res = asm_report.build_asm_report(out)
    assert res["status"] == "success"
    html = (out / "report" / "asm_report.html").read_text(encoding="utf-8")
    assert "Attack Surface Report" in html
    assert "acme.com" in html


def test_report_ranks_verified_finding(tmp_path):
    out = _build_target(tmp_path)
    model = asm_report.build_model(out)
    top = asm_report.score_targets(model)
    assert top, "expected at least one ranked target"
    assert top[0]["verified"] is True
    assert "test-template" not in top[0]["url"]  # ranked by URL, not template id


def test_report_excludes_out_of_scope_from_ranking(tmp_path):
    out = _build_target(tmp_path)
    model = asm_report.build_model(out)
    # The form action points at a third-party host — it must be reported
    # under out-of-scope, never ranked.
    assert "evil-third-party.net" in model["oos"]
    ranked = {asm_report.url_host(t["url"]) for t in asm_report.score_targets(model)}
    assert "evil-third-party.net" not in ranked


def test_blanket_deny_host_is_deprioritised(tmp_path):
    out = _build_target(tmp_path)
    (layout.path(out, "ffuf_urls.txt")).write_text(
        "https://api.acme.com/.git/config\n", encoding="utf-8")
    _write_ffuf(out, "api.acme.com",
                [{"url": f"https://api.acme.com/p{i}", "status": 403, "words": 20}
                 for i in range(40)])
    model = asm_report.build_model(out)
    scored = {t["url"]: t for t in asm_report.score_targets(model, limit=999, per_host=0)}
    hit = scored.get(asm_report.canon("https://api.acme.com/.git/config"))
    assert hit is not None
    assert hit["conf_used"] <= asm_report._CONFIDENCE["blanket_deny"]


def test_score_targets_caps_results_per_host(tmp_path):
    out = _build_target(tmp_path)
    model = asm_report.build_model(out)
    model["param_urls"] = [f"https://api.acme.com/p{i}?a=1" for i in range(20)]
    top = asm_report.score_targets(model, limit=20, per_host=2)
    hosts = [t["host"] for t in top]
    assert hosts.count("api.acme.com") <= 2


def test_data_quality_flags_degraded_stage(tmp_path):
    out = _build_target(tmp_path)
    (out / "logs" / "stages.json").write_text(json.dumps([
        {"stage": "arjun", "status": "failed", "error": "timeout",
         "extra": {"elapsed_seconds": 3601}}]), encoding="utf-8")
    model = asm_report.build_model(out)
    checks = asm_report.data_quality(model)
    assert any("arjun" in c["check"] for c in checks)


def test_build_asm_report_never_raises_on_empty_dir(tmp_path):
    # example.com in the real tree is an empty run; the report must not
    # take down a finished scan.
    empty = tmp_path / "empty.com"
    empty.mkdir()
    res = asm_report.build_asm_report(empty)
    assert res["status"] in ("success", "failed")


def test_unknown_severity_finding_renders(tmp_path):
    """nuclei.default.severity includes ``unknown`` (templates that declare
    no severity), so findings carrying it reach the report. The issue-card
    sort used _SEV_ORDER.index(), which raised ValueError on any severity
    outside the five standard ones and took the whole report down."""
    out = _build_target(tmp_path)
    (out / "findings" / "default" / "nuclei.json").write_text(json.dumps({
        "findings": [{
            "template-id": "no-sev-template", "host": "api.acme.com",
            "matched-at": "https://api.acme.com/v1/users",
            "info": {"name": "Unrated Issue", "severity": "unknown",
                     "tags": ["test"], "description": "d"},
        }], "severity_count": {"unknown": 1}, "complete": True,
    }), encoding="utf-8")
    res = asm_report.build_asm_report(out)
    assert res["status"] == "success"
    html = (out / "report" / "asm_report.html").read_text(encoding="utf-8")
    assert "Unrated Issue" in html
    assert "UNKNOWN" in html
