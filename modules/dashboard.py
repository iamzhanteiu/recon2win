"""dashboard — cross-target overview across every ``outputs/<domain>/``.

``recon2win`` scans one target at a time; each run already produces a rich
per-target report (``modules/report.py`` → ``report/final_report.html``).
But nothing answers "across everything I've scanned, what needs attention
right now" — an operator has to open every target folder one by one to
spot the stale run, the degraded one (missing tool / failed stage), or the
one that just picked up a pile of new critical findings.

This module writes a single ``outputs/dashboard.html`` listing every
target directory, sorted by a risk score, with health status, a findings
summary, and delta-since-last-scan. It is read-only/visualize-only: it
never triggers a scan, only reads what's already on disk. Regenerated at
the end of every ``main.py`` run (same "static, always fresh" model as
``final_report.html``), and can be rebuilt standalone via
``python3 -m modules.dashboard [outputs_root]``.

Per-target data comes from two files a completed run already writes:

  * ``report/summary.json`` — meta (scan window), counts, nuclei severity
    breakdown, jsluice secrets, high-value targets. Written by
    ``ReportBuilder.collect()``.
  * ``logs/stages.json`` — the FULL, final stage-result list (written at
    the very end of ``main.py``, after report/priority/scandiff/graph/
    index all ran — more complete than ``summary.json``'s own ``stages``
    bucket, which is computed before those later stages run). Reused via
    ``classify_stages()`` / ``missing_tools_from_skips()`` (both already
    pure functions in ``modules/report.py``) for health, and its
    ``scan_diff`` entry (written by ``modules/scandiff.py``) for the
    delta-since-last-scan numbers — no need to re-parse ``delta.md``.

A target directory with no ``report/summary.json`` (crashed mid-run, or
never finished) is still listed, marked ``health="no_report"`` — this is
a management view, not just a findings feed.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from .report import classify_stages, load_json_safe, missing_tools_from_skips, rel_link
from .utils import make_result, now_iso

# Core stages whose failure means the whole run's output is suspect —
# distinct from a failure in something peripheral (e.g. apidocs).
_CORE_STAGES = {"subdomain", "dnsx", "httpx", "httpx_urls"}

# A run older than this is flagged stale in the UI. Hardcoded rather than
# config-driven (matches scandiff.py's _URL_CAP=100) — one operator-facing
# threshold, not worth a config surface.
_STALE_DAYS = 30

# Risk-score weights — tunable heuristic for default sort order only, not
# a severity classification. Nuclei criticals dominate; secrets and
# high-value targets add smaller weight since they need manual triage.
_RISK_WEIGHTS = {
    "nuclei": {"critical": 100, "high": 25, "medium": 5, "low": 1, "info": 0},
    "secrets": {"high": 20, "medium": 10, "low": 2, "info": 0},
}
# See _risk_score()'s docstring — caps high_value_targets' contribution so
# raw URL-list size can't drown out severity-weighted findings.
_HIGH_VALUE_CAP = 50


# ----------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------
def _classify_health(stage_results: list[dict], has_summary: bool) -> str:
    """One-word health badge for a target's most recent run.

    A lightweight heuristic for an at-a-glance badge — not a replacement
    for the ``recon-health`` skill's deep dive.
    """
    if not has_summary:
        return "no_report"
    buckets = classify_stages(stage_results)
    failed = buckets.get("failed") or []
    if not failed:
        return "ok"
    failed_stages = {r.get("stage") for r in failed}
    if failed_stages & _CORE_STAGES:
        return "broken"
    return "degraded"


def _risk_score(nuclei_sev: dict, secrets_sev: dict, high_value_count: int) -> int:
    """Higher = more worth looking at first. Sort key only.

    ``high_value_count`` is capped before adding: it's a count of URLs that
    merely *pattern-match* as interesting (``/admin``, ``/api``, ...), not
    exploitable findings, and on a large target it can reach the tens of
    thousands (measured: 75,981 on a real guildwars2.com run) — three
    orders of magnitude past any severity-weighted score. Left uncapped,
    URL-list size alone decides sort order and real critical/secret
    findings never matter. Capped, it can still nudge the ranking among
    similar-severity targets without swamping it.
    """
    score = 0
    for sev, weight in _RISK_WEIGHTS["nuclei"].items():
        score += (nuclei_sev.get(sev, 0) or 0) * weight
    for sev, weight in _RISK_WEIGHTS["secrets"].items():
        score += (secrets_sev.get(sev, 0) or 0) * weight
    score += min(high_value_count, _HIGH_VALUE_CAP)
    return score


def _stale_days(scan_end: str | None) -> int | None:
    """Days since *scan_end* (an ISO timestamp), or None if unknown/bad."""
    if not scan_end:
        return None
    try:
        end = datetime.fromisoformat(scan_end)
    except ValueError:
        return None
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - end).days


# ----------------------------------------------------------------------
# Target discovery + per-target record
# ----------------------------------------------------------------------
def _is_target_dir(p: Path) -> bool:
    """True if *p* looks like a scan-target root — has at least one of the
    subdirs ``create_output_structure()`` always creates. Distinguishes a
    target directory from a project directory that merely CONTAINS target
    subdirectories (see ``discover_targets``)."""
    return any((p / sub).is_dir() for sub in ("raw", "logs", "report", "processed"))


def discover_targets(outputs_root: Path) -> list[dict]:
    """List every scan-target directory under *outputs_root*, one or two
    levels deep.

    Two shapes coexist on purpose — no forced migration of existing scans:

      * ``outputs/<domain>/``            — legacy/ungrouped (``project: None``)
      * ``outputs/<project>/<domain>/``  — grouped (``main.py --project NAME``)

    A top-level directory is a target itself if it has the skeleton
    ``create_output_structure()`` always creates (see ``_is_target_dir``);
    otherwise it's treated as a project folder and its immediate
    subdirectories are checked the same way, one level down only (no
    deeper nesting). Includes directories that never finished a report —
    a crashed/partial run is something an operator managing targets wants
    to see, not have silently dropped. Skips dotfiles (``.gitkeep``).

    Returns ``[{"path": Path, "project": str | None, "domain": str}, ...]``,
    sorted by ``(project or "", domain)`` so ungrouped targets sort first.
    """
    outputs_root = Path(outputs_root)
    if not outputs_root.is_dir():
        return []

    found: list[dict] = []
    for p in sorted(outputs_root.iterdir()):
        if not p.is_dir() or p.name.startswith("."):
            continue
        if _is_target_dir(p):
            found.append({"path": p, "project": None, "domain": p.name})
            continue
        for sub in sorted(p.iterdir()):
            if sub.is_dir() and not sub.name.startswith(".") and _is_target_dir(sub):
                found.append({"path": sub, "project": p.name, "domain": sub.name})
    return sorted(found, key=lambda t: (t["project"] or "", t["domain"]))


def _load_target(
    target_dir: Path, dashboard_path: Path, project: str | None = None,
) -> dict[str, Any]:
    """Build one dashboard row from a target directory's on-disk state."""
    domain = target_dir.name
    summary = load_json_safe(target_dir / "report" / "summary.json")
    has_summary = isinstance(summary, dict)
    summary = summary if has_summary else {}

    stage_results = load_json_safe(target_dir / "logs" / "stages.json")
    stage_results = stage_results if isinstance(stage_results, list) else []

    meta = summary.get("meta") or {}
    counts = summary.get("counts") or {}
    nuclei_sev = ((summary.get("nuclei") or {}).get("default") or {}).get(
        "severity_count"
    ) or {}
    secrets_blk = summary.get("jsluice_secrets") or {}
    secrets_sev = secrets_blk.get("severity_count") or {}
    secrets_total = len(secrets_blk.get("findings") or [])
    high_value = summary.get("high_value_targets") or []
    high_value_count = len(high_value) if isinstance(high_value, list) else 0

    buckets = classify_stages(stage_results)
    failed_stages = sorted({r.get("stage", "?") for r in (buckets.get("failed") or [])})
    missing_tools = missing_tools_from_skips(stage_results)

    delta = None
    for r in stage_results:
        if r.get("stage") == "scan_diff":
            extra = r.get("extra") or {}
            delta = {
                "first_run": bool(extra.get("first_run")),
                "new": extra.get("new") or {},
                "totals": extra.get("totals") or {},
            }
            break

    report_file = target_dir / "report" / "final_report.html"
    report_rel = rel_link(dashboard_path, report_file) if report_file.exists() else None

    return {
        "domain": domain,
        "project": project,
        "has_report": has_summary,
        "scan_start": meta.get("scan_start"),
        "scan_end": meta.get("scan_end"),
        "duration_seconds": meta.get("scan_duration_seconds"),
        "counts": counts,
        "nuclei_severity": nuclei_sev,
        "secrets_severity": secrets_sev,
        "secrets_total": secrets_total,
        "high_value_count": high_value_count,
        "health": _classify_health(stage_results, has_summary),
        "failed_stages": failed_stages,
        "missing_tools": missing_tools,
        "delta": delta,
        "stale_days": _stale_days(meta.get("scan_end")),
        "risk_score": _risk_score(nuclei_sev, secrets_sev, high_value_count),
        "report_rel": report_rel,
    }


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------
_HEALTH_LABEL = {
    "ok": "OK",
    "degraded": "DEGRADED",
    "broken": "BROKEN",
    "no_report": "NO REPORT",
}


def _health_badge(health: str) -> str:
    cls = {"ok": "low", "degraded": "medium", "broken": "critical",
           "no_report": "info"}.get(health, "info")
    label = _HEALTH_LABEL.get(health, health.upper())
    return f'<span class="badge badge-{cls}">{escape(label)}</span>'


def _sev_chips(sev: dict) -> str:
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    parts = [f'<span class="chip"><code>{s}</code> {sev.get(s, 0)}</span>'
             for s in order if sev.get(s)]
    return " ".join(parts) if parts else '<span class="small">—</span>'


def _delta_cell(delta: dict | None) -> str:
    """Plain-text summary of ``scan_diff``'s extra — caller escapes+wraps it."""
    if not delta:
        return "—"
    if delta.get("first_run"):
        return "first scan"
    n = delta.get("new") or {}
    parts = [f"+{n.get(k, 0)} {k}" for k in ("subdomains", "alive", "urls", "findings")
             if n.get(k)]
    return ", ".join(parts) if parts else "no changes"


_CSS = """
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px; background: #f5f5f7; color: #1d1d1f; }
  .container { max-width: 1400px; margin: 0 auto; }
  h1 { border-bottom: 3px solid #0066cc; padding-bottom: 12px; }
  table { border-collapse: collapse; width: 100%; background: #fff; margin: 10px 0; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
  th, td { padding: 8px 12px; border: 1px solid #e5e5ea; text-align: left; font-size: 14px; vertical-align: top; }
  th { background: #f0f0f5; position: sticky; top: 0; cursor: pointer; }
  tr:nth-child(even) td { background: #fafafa; }
  code { background: #f0f0f5; padding: 2px 6px; border-radius: 3px; font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: #fff; }
  .badge-critical { background: #d32f2f; }
  .badge-high     { background: #f57c00; }
  .badge-medium   { background: #fbc02d; color: #000; }
  .badge-low      { background: #388e3c; }
  .badge-info     { background: #1976d2; }
  .chip { display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 10px; background: #eef1f5; font-size: 12px; }
  .small { font-size: 12px; color: #666; }
  .stale { color: #b26a00; font-weight: 600; }
  .filter { width: 100%; padding: 8px 12px; margin: 10px 0; border: 1px solid #d2d2d7; border-radius: 4px; box-sizing: border-box; }
  a { color: #0066cc; text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
"""

_SCRIPT = """
<script>
function filterTable(input, tableId) {
  const filter = input.value.toLowerCase();
  const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
  for (const row of rows) {
    row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
  }
}
</script>
"""


def _render_html(targets: list[dict], generated_at: str) -> str:
    n_stale = sum(1 for t in targets if (t["stale_days"] or 0) > _STALE_DAYS)
    n_broken = sum(1 for t in targets if t["health"] == "broken")
    n_no_report = sum(1 for t in targets if t["health"] == "no_report")

    if not targets:
        body = (
            "<h1>recon2win — Target Dashboard</h1>"
            f'<p class="small">Generated {escape(generated_at)}</p>'
            '<p>No targets scanned yet — run <code>main.py &lt;domain&gt;</code> '
            "to populate <code>outputs/</code>.</p>"
        )
        return (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<title>recon2win — Target Dashboard</title>\n"
            f"{_CSS}\n</head>\n<body>\n<div class=\"container\">\n{body}\n"
            "</div>\n</body>\n</html>\n"
        )

    rows = []
    for t in targets:
        domain_cell = (
            f'<a href="{escape(t["report_rel"])}"><code>{escape(t["domain"])}</code></a>'
            if t["report_rel"] else f'<code>{escape(t["domain"])}</code>'
        )
        project_cell = (
            f'<code>{escape(t["project"])}</code>' if t["project"]
            else '<span class="small">—</span>'
        )
        stale_note = ""
        if t["stale_days"] is not None and t["stale_days"] > _STALE_DAYS:
            stale_note = f'<br><span class="stale">stale — {t["stale_days"]}d ago</span>'
        dur = t["duration_seconds"]
        dur_str = f"{dur:,.0f}s" if isinstance(dur, (int, float)) else "—"
        rows.append(
            "<tr>"
            f"<td>{project_cell}</td>"
            f"<td>{domain_cell}</td>"
            f"<td>{_health_badge(t['health'])}</td>"
            f"<td><span class=\"small\">{escape(str(t['scan_end'] or '—'))}</span>"
            f"<br><span class=\"small\">{dur_str}</span>{stale_note}</td>"
            f"<td>{_sev_chips(t['nuclei_severity'])}</td>"
            f"<td>{_sev_chips(t['secrets_severity'])} "
            f'<span class="small">({t["secrets_total"]} total)</span></td>'
            f"<td><code>{t['high_value_count']}</code></td>"
            f"<td><span class=\"small\">{escape(_delta_cell(t['delta']))}</span></td>"
            f"<td><code>{t['risk_score']:,}</code></td>"
            "</tr>"
        )

    summary_line = (
        f"{len(targets)} target(s) · {n_stale} stale (&gt;{_STALE_DAYS}d) · "
        f"{n_broken} broken · {n_no_report} no report"
    )

    body = (
        "<h1>recon2win — Target Dashboard</h1>"
        f'<p class="small">Generated {escape(generated_at)} — {summary_line}</p>'
        '<input class="filter" placeholder="filter… (domain)" '
        'onkeyup="filterTable(this, \'tbl-targets\')">\n'
        '<table id="tbl-targets"><thead><tr>'
        "<th>Project</th><th>Domain</th><th>Health</th><th>Last scan</th>"
        "<th>Nuclei severity</th><th>Secrets</th><th>High-value</th>"
        "<th>Delta since last scan</th><th>Risk</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )

    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<title>recon2win — Target Dashboard</title>\n"
        f"{_CSS}\n</head>\n<body>\n<div class=\"container\">\n{body}\n</div>\n"
        f"{_SCRIPT}\n</body>\n</html>\n"
    )


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def build_dashboard(outputs_root: Path) -> dict:
    """Write ``<outputs_root>/dashboard.html``. Returns a stage-result dict."""
    outputs_root = Path(outputs_root)
    dashboard_path = outputs_root / "dashboard.html"

    refs = discover_targets(outputs_root)
    targets = [_load_target(r["path"], dashboard_path, project=r["project"]) for r in refs]
    targets.sort(key=lambda t: t["risk_score"], reverse=True)

    generated_at = now_iso()
    outputs_root.mkdir(parents=True, exist_ok=True)
    dashboard_path.write_text(_render_html(targets, generated_at), encoding="utf-8")

    status = "success" if targets else "skipped"
    error = None if targets else "no targets found under outputs/"
    return make_result(
        "dashboard", status, input_path=outputs_root,
        outputs=[dashboard_path], count=len(targets), error=error,
        extra={
            "targets": [
                f"{t['project']}/{t['domain']}" if t["project"] else t["domain"]
                for t in targets
            ],
            "stale": sum(1 for t in targets if (t["stale_days"] or 0) > _STALE_DAYS),
            "broken": sum(1 for t in targets if t["health"] == "broken"),
            "no_report": sum(1 for t in targets if t["health"] == "no_report"),
        },
    )


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    root = Path(argv[0]) if argv else Path("outputs")
    result = build_dashboard(root)
    print(f"dashboard: {result['outputs'][0] if result['outputs'] else root / 'dashboard.html'}"
          f"  ({result['count']} target(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
