"""report — final report generator.

Produces three artefacts under ``outputs/<domain>/report/``:

    final_report.html   — primary deliverable. Self-contained HTML with
                          clickable links to every output, severity-grouped
                          findings, KPI cards, searchable tables and
                          collapsible sections.
    final_report.md     — a flat Markdown mirror for quick terminal review.
    summary.json        — the same data the report renders, as JSON.

Robustness rules:
  * Reading any output file MUST be safe — missing files are reported as
    "Not generated", never as exceptions.
  * Links are computed RELATIVE to ``report/final_report.html`` so the report
    works when opened from disk (``file://``) or copied elsewhere.
  * Tables get a simple client-side filter (no frameworks).
  * Large lists collapse by default via ``<details>``.

Stage results and tool versions are passed in by ``main.py`` so the report
stays a pure read-only consumer of data already on disk.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .utils import load_json, now_iso, read_lines, write_json


# ----------------------------------------------------------------------
# High-value target keywords. Order matters (longer first) so that
# ".env.local" wins over ".env".
# ----------------------------------------------------------------------
HIGH_VALUE_PATTERNS: list[tuple[str, str]] = [
    (".env.local",       "env file (local)"),
    (".env.production",  "env file (production)"),
    (".env",             "env file"),
    ("swagger",          "swagger / openapi"),
    ("openapi",          "openapi spec"),
    ("graphql",          "graphql endpoint"),
    ("playground",       "graphql playground"),
    ("admin",            "admin panel"),
    ("administrator",    "admin panel"),
    ("dashboard",        "dashboard"),
    ("signin",           "login portal"),
    ("sign-in",          "login portal"),
    ("login",            "login portal"),
    ("signup",           "signup"),
    ("sign-up",          "signup"),
    ("register",         "registration"),
    ("forgot-password",  "password reset"),
    ("reset-password",   "password reset"),
    ("upload",           "upload endpoint"),
    ("fileupload",       "upload endpoint"),
    ("phpinfo",          "phpinfo"),
    ("server-status",    "server-status"),
    (".git/config",      "git config exposure"),
    (".git/head",        "git exposure"),
    ("/.svn/",           "svn exposure"),
    ("backup",           "backup file"),
    (".bak",             "backup file"),
    (".sql",             "database dump"),
    (".dump",            "database dump"),
    ("wp-config",        "wordpress config"),
    ("credentials",      "credentials"),
    ("secret",           "secret"),
    ("debug",            "debug endpoint"),
    ("trace",            "debug endpoint"),
    ("internal",         "internal"),
    ("staging",          "staging environment"),
    ("staging-",         "staging environment"),
    ("stage.",           "staging environment"),
    ("dev-",             "dev environment"),
    ("dev.",             "dev environment"),
    ("test-",            "test environment"),
    ("test.",            "test environment"),
    ("qa-",              "qa environment"),
    ("qa.",              "qa environment"),
    ("sandbox",          "sandbox"),
    ("jenkins",          "jenkins"),
    ("grafana",          "grafana"),
    ("kibana",           "kibana"),
    ("prometheus",       "prometheus"),
    ("actuator",         "spring actuator"),
    ("/api/",            "api endpoint"),
    ("/api/v",           "api endpoint (versioned)"),
    ("/rest/",           "rest endpoint"),
    ("/v1/",             "versioned api"),
    ("/v2/",             "versioned api"),
    ("/v3/",             "versioned api"),
]

INTERESTING_API_PATTERNS = [
    re.compile(r"/api/v?\d+/[^\s\"'<>]*", re.IGNORECASE),
    re.compile(r"/v\d+/[^\s\"'<>]*", re.IGNORECASE),
    re.compile(r"/rest/[^\s\"'<>]*", re.IGNORECASE),
    re.compile(r"/graphql[^\s\"'<>]*", re.IGNORECASE),
]


# ----------------------------------------------------------------------
# Pure helpers — no I/O beyond Path.exists() and read_text().
# All exported for unit testing.
# ----------------------------------------------------------------------
def count_lines(path: Path) -> int:
    """Count non-empty lines in *path*. 0 if missing."""
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(errors="ignore").splitlines() if ln.strip())


def load_json_safe(path: Path) -> Any:
    """Load JSON from *path* or return None on missing / malformed."""
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text(errors="ignore"))
    except (json.JSONDecodeError, ValueError):
        return None


def parse_nuclei_summary(path: Path) -> tuple[list[dict], dict[str, int]]:
    """Parse the nuclei output file — handles all three formats nuclei
    can produce so the report stays robust even if ``modules/nuclei.py``
    didn't successfully overwrite the raw file:

    1. **Structured** (what ``modules/nuclei.py`` writes):
       ``{"findings": [...], "severity_count": {...}}``
    2. **JSONL** (some nuclei v3.x builds via ``-json-export``):
       one ``{"template-id": ..., "info": {...}, ...}`` per line
    3. **JSON array** (other nuclei v3.x builds):
       single line ``[{...}, {...}, ...]``

    Anything that doesn't parse cleanly → returns ``([], {})``.
    """
    SEV_ORDER = ("info", "low", "medium", "high", "critical")
    if not path.exists() or path.stat().st_size == 0:
        return [], {}

    raw = path.read_text(errors="ignore").strip()

    # Try structured first (most efficient — single json.loads).
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "findings" in data:
            return (
                list(data.get("findings") or []),
                dict(data.get("severity_count") or {}),
            )
        if isinstance(data, list):
            # JSON array of findings.
            findings = [o for o in data if isinstance(o, dict)]
            return _aggregate_findings(findings, SEV_ORDER)
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to JSONL — one object per line.
    findings = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            findings.append(obj)
    return _aggregate_findings(findings, SEV_ORDER)


def _aggregate_findings(
    findings: list[dict], sev_order: tuple[str, ...]
) -> tuple[list[dict], dict[str, int]]:
    """Compute the severity_count breakdown for a flat findings list."""
    sev_count: dict[str, int] = {s: 0 for s in sev_order}
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = ((f.get("info") or {}).get("severity") or "info").lower()
        sev_count[sev] = sev_count.get(sev, 0) + 1
    return findings, sev_count


def parse_httpx_jsonl(path: Path) -> list[dict]:
    """Parse httpx output — accepts either JSONL or a JSON array.

    httpx can emit one of two shapes:
      * JSONL: ``{"url": "..."}\\n{"url": "..."}`` (one object per line)
      * JSON array: ``[{"url": "..."}, {"url": "..."}]`` (single line)

    Returns a flat list of dicts. Anything that does not parse to a dict is
    dropped.
    """
    if not path.exists() or path.stat().st_size == 0:
        return []
    out: list[dict] = []
    for ln in path.read_text(errors="ignore").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list):
            out.extend(x for x in obj if isinstance(x, dict))
        elif isinstance(obj, dict):
            out.append(obj)
    return out


def classify_url(url: str) -> list[str]:
    """Return the list of high-value labels matched by *url*."""
    if not url:
        return []
    u = url.lower()
    labels: list[str] = []
    seen: set[str] = set()
    for kw, label in HIGH_VALUE_PATTERNS:
        if kw in u and label not in seen:
            seen.add(label)
            labels.append(label)
    return labels


def is_high_value(url: str) -> bool:
    return bool(classify_url(url))


def extract_interesting_api_paths(urls: Iterable[str]) -> list[str]:
    """Filter URLs down to ones that look like interesting API paths."""
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if not u:
            continue
        for pat in INTERESTING_API_PATTERNS:
            if pat.search(u) and u not in seen:
                seen.add(u)
                out.append(u)
                break
    return out


def rel_link(from_file: Path, to_file: Path) -> str:
    """Compute a relative link from ``from_file`` to ``to_file``.

    Both paths are interpreted as filesystem paths. Result is forward-slash
    encoded so it works as both an HTML ``href`` and a Markdown link target.

    Uses string-based path manipulation (not ``Path.relative_to``) so the
    function works even when ``from_file`` does not exist on disk yet and
    when one of the paths crosses a symlink (e.g. macOS ``/var/folders``
    vs ``/private/var/folders``).
    """
    import os
    try:
        rel = os.path.relpath(str(to_file), start=str(from_file.parent))
    except (ValueError, OSError):
        return str(to_file)
    return rel.replace(os.sep, "/")


def severity_badge(sev: str) -> str:
    s = (sev or "info").lower()
    return f'<span class="badge badge-{escape(s)}">{escape(s.upper())}</span>'


def severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        (sev or "").lower(), -1
    )


# ----------------------------------------------------------------------
# Tool-version capture (best-effort, never raises).
# ----------------------------------------------------------------------
VERSION_CMDS: list[tuple[str, list[str]]] = [
    ("subfinder",  ["subfinder", "-version"]),
    ("amass",      ["amass", "version"]),
    ("chaos",      ["chaos", "version"]),
    ("dnsx",       ["dnsx", "-version"]),
    ("httpx",      ["httpx", "-version"]),
    ("katana",     ["katana", "-version"]),
    ("nuclei",     ["nuclei", "-version"]),
    ("xnlinkfinder", ["xnlinkfinder", "-h"]),
    ("urlfinder",  ["urlfinder", "--help"]),
    ("dirsearch",  ["dirsearch", "--help"]),
    ("waymore",    ["waymore", "-h"]),
    ("arjun",      ["arjun", "-h"]),
    ("go",         ["go", "version"]),
    ("python3",    ["python3", "--version"]),
]


def capture_tool_versions(timeout: int = 10) -> dict[str, str]:
    """Return ``{tool: "first line of -version output"}`` for installed tools."""
    out: dict[str, str] = {}
    for binary, cmd in VERSION_CMDS:
        # Use the runner's case-insensitive which() so mixed-case binaries
        # like ``xnLinkFinder`` (lookup: ``xnlinkfinder``) are still found.
        from .runner import which
        if not which(cmd[0]):
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            continue
        text = (r.stdout or r.stderr or "").strip()
        if text:
            first = text.splitlines()[0].strip()
            if first:
                out[binary] = first
    return out


# ----------------------------------------------------------------------
# Stage-result classification for the Errors / Skipped section.
# ----------------------------------------------------------------------
def classify_stages(results: Iterable[dict]) -> dict[str, list[dict]]:
    """Bucket stage result dicts by status."""
    buckets: dict[str, list[dict]] = {
        "failed": [], "skipped": [], "success": [],
    }
    for r in results or []:
        status = (r.get("status") or "").lower()
        buckets.setdefault(status, []).append(r)
    return buckets


def missing_tools_from_skips(results: Iterable[dict]) -> list[str]:
    """Extract a unique list of binaries whose stages were skipped due to
    the binary being missing."""
    seen: set[str] = set()
    out: list[str] = []
    for r in results or []:
        if (r.get("status") or "").lower() != "skipped":
            continue
        err = (r.get("error") or "").lower()
        if "binary not found" in err or "not installed" in err:
            stage = r.get("stage", "")
            # Best-effort: strip suffixes like "_default" / "_alive" / "_urls"
            tool = stage.split("_")[0]
            if tool and tool not in seen:
                seen.add(tool)
                out.append(tool)
    return out


# ----------------------------------------------------------------------
# Collector — pulls everything together into a single dict the renderers
# can iterate over without touching the filesystem again.
# ----------------------------------------------------------------------
@dataclass
class ReportInputs:
    output_dir: Path
    domain: str
    cfg: dict
    cfg_path: str = ""
    cfg_text: str = ""
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    tool_versions: dict[str, str] = field(default_factory=dict)
    stage_results: list[dict] = field(default_factory=list)
    scan_mode: str = "active"     # "active" or "dry-run" — set by caller


class ReportBuilder:
    SEV_ORDER = ["critical", "high", "medium", "low", "info"]

    # Every file the report must reference. ``kind`` drives the empty-state
    # label: ``"raw"`` / ``"processed"`` / ``"findings"`` / ``"logs"``.
    # Paths follow the v2 layout: raw outputs are grouped per stage
    # (``raw/<stage>/...``) and findings are grouped per kind
    # (``findings/<kind>/nuclei.{json,txt}``).
    OUTPUT_FILES: list[tuple[str, str, Path]] = [
        # raw/subdomain/
        ("raw/subdomain/subfinder.txt",  "raw",       "subfinder raw output"),
        ("raw/subdomain/amass.txt",      "raw",       "amass raw output"),
        ("raw/subdomain/chaos.txt",      "raw",       "chaos raw output"),
        # raw/content_discovery/
        ("raw/content_discovery/katana_urls.txt",    "raw", "katana raw crawl"),
        ("raw/content_discovery/urlfinder_urls.txt", "raw", "urlfinder raw crawl"),
        # raw/dirsearch/
        ("raw/dirsearch/dirsearch_raw.txt",   "raw",  "dirsearch raw output"),
        ("raw/dirsearch/merged_wordlists.txt","raw",  "merged wordlists (deduped)"),
        # raw/waymore/
        ("raw/waymore/waymore_raw.txt",     "raw",    "waymore raw output"),
        # raw/arjun/
        ("raw/arjun/input_subset.txt",      "raw",    "arjun capped input"),
        # processed/
        ("processed/subdomains.txt",     "processed", "merged unique subdomains"),
        ("processed/resolved.txt",       "processed", "dnsx-resolved hosts"),
        ("processed/resolved_detail.json","processed","dnsx per-host detail"),
        ("processed/alive.txt",          "processed", "httpx alive URLs"),
        ("processed/alive_detail.json",  "processed", "httpx per-host JSON"),
        ("processed/crawler_urls.txt",   "processed", "crawler union"),
        ("processed/dirsearch_urls.txt", "processed", "dirsearch URL list"),
        ("processed/waymore_urls.txt",   "processed", "waymore URL list"),
        ("processed/all_urls.txt",       "processed", "merged normalised URLs"),
        ("processed/js_urls.txt",        "processed", "JS URLs (final)"),
        ("processed/dynamic_urls.txt",   "processed", "dynamic URLs only"),
        ("processed/xnlinkfinder_endpoints.txt","processed","xnLinkFinder endpoints"),
        ("processed/xnlinkfinder_urls.txt","processed","xnLinkFinder URLs"),
        ("processed/alive_urls.txt",     "processed", "httpx URL check (final)"),
        ("processed/alive_urls_detail.json","processed","httpx URL check detail"),
        ("processed/arjun_params.txt",   "processed", "Arjun raw output"),
        ("processed/parameterized_urls.txt","processed","parameterized URLs"),
        # findings/<kind>/
        ("findings/default/nuclei.txt",  "findings",  "nuclei default matched URLs"),
        ("findings/default/nuclei.json", "findings",  "nuclei default findings"),
        ("findings/endpoints/nuclei.txt", "findings", "nuclei endpoints matched URLs"),
        ("findings/endpoints/nuclei.json","findings", "nuclei endpoints findings"),
        ("findings/dynamic/nuclei.txt",  "findings",  "nuclei dynamic matched URLs"),
        ("findings/dynamic/nuclei.json", "findings",  "nuclei dynamic findings"),
        ("findings/jsluice_secrets.json","findings",  "secrets extracted from JS"),
        # logs/
        ("logs/commands.log",            "logs",      "every command ever run"),
        ("logs/stages.json",             "logs",      "per-stage structured result"),
    ]

    def __init__(self, inputs: ReportInputs):
        self.inputs = inputs
        self.report_dir = inputs.output_dir / "report"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.html_path = self.report_dir / "final_report.html"
        self.md_path = self.report_dir / "final_report.md"
        self.json_path = self.report_dir / "summary.json"

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------
    def collect(self) -> dict:
        i = self.inputs
        proc = i.output_dir / "processed"
        raw = i.output_dir / "raw"
        findings = i.output_dir / "findings"

        # file inventory — every referenced file with presence flag
        file_inventory = []
        for rel, kind, label in self.OUTPUT_FILES:
            abs_path = i.output_dir / rel
            file_inventory.append({
                "rel": rel, "kind": kind, "label": label,
                "exists": abs_path.exists(),
                "size": abs_path.stat().st_size if abs_path.exists() else 0,
                "rel_link": rel_link(self.html_path, abs_path),
            })

        # counts
        counts = {
            "subdomains":        count_lines(proc / "subdomains.txt"),
            "resolved":          count_lines(proc / "resolved.txt"),
            "alive_hosts":       count_lines(proc / "alive.txt"),
            "all_urls":          count_lines(proc / "all_urls.txt"),
            "js_urls":           count_lines(proc / "js_urls.txt"),
            "dynamic_urls":      count_lines(proc / "dynamic_urls.txt"),
            "alive_urls":        count_lines(proc / "alive_urls.txt"),
            "parameterized_urls":count_lines(proc / "parameterized_urls.txt"),
            "arjun_params":      count_lines(proc / "arjun_params.txt"),
            "crawler_urls":      count_lines(proc / "crawler_urls.txt"),
            "dirsearch_urls":    count_lines(proc / "dirsearch_urls.txt"),
            "waymore_urls":      count_lines(proc / "waymore_urls.txt"),
            "xnlinkfinder_endpoints": count_lines(proc / "xnlinkfinder_endpoints.txt"),
            "xnlinkfinder_urls": count_lines(proc / "xnlinkfinder_urls.txt"),
        }

        # dns / assets
        dns_records = load_json_safe(proc / "resolved_detail.json") or []
        if not isinstance(dns_records, list):
            dns_records = []
        assets = parse_httpx_jsonl(proc / "alive_detail.json")
        # alive_detail.json might be the JSON array form too — handle either
        if not assets:
            data = load_json_safe(proc / "alive_detail.json")
            if isinstance(data, list):
                assets = data
        # de-dup by URL preserving order
        seen_urls: set[str] = set()
        assets_dedup: list[dict] = []
        for a in assets:
            u = a.get("url") or ""
            if u and u not in seen_urls:
                seen_urls.add(u)
                assets_dedup.append(a)
        assets = assets_dedup

        # nuclei — v2 layout puts the scans under findings/<kind>/
        n_def_findings, n_def_sev = parse_nuclei_summary(
            findings / "default" / "nuclei.json"
        )
        n_end_findings, n_end_sev = parse_nuclei_summary(
            findings / "endpoints" / "nuclei.json"
        )
        n_dyn_findings, n_dyn_sev = parse_nuclei_summary(
            findings / "dynamic" / "nuclei.json"
        )
        counts["nuclei_default_findings"] = len(n_def_findings)
        counts["nuclei_endpoints_findings"] = len(n_end_findings)
        counts["nuclei_dynamic_findings"] = len(n_dyn_findings)

        # jsluice secrets — API keys/tokens extracted from JS (findings/jsluice_secrets.json)
        jsl = load_json_safe(findings / "jsluice_secrets.json") or {}
        jsluice_secrets = jsl.get("findings", []) if isinstance(jsl, dict) else []
        if not isinstance(jsluice_secrets, list):
            jsluice_secrets = []
        jsluice_sev = jsl.get("severity_count", {}) if isinstance(jsl, dict) else {}
        counts["jsluice_secrets"] = len(jsluice_secrets)

        # high-value targets — scan the union of alive URLs + parameterized
        candidate_urls: list[str] = []
        candidate_urls.extend(read_lines(proc / "alive_urls.txt"))
        candidate_urls.extend(read_lines(proc / "dynamic_urls.txt"))
        candidate_urls.extend(read_lines(proc / "parameterized_urls.txt"))
        # de-dup preserving order
        seen_u: set[str] = set()
        unique_urls: list[str] = []
        for u in candidate_urls:
            if u and u not in seen_u:
                seen_u.add(u)
                unique_urls.append(u)
        high_value = []
        for u in unique_urls:
            labels = classify_url(u)
            if labels:
                high_value.append({"url": u, "categories": labels})

        # interesting API paths from JS endpoints
        api_paths = extract_interesting_api_paths(
            list(read_lines(proc / "xnlinkfinder_urls.txt"))
            + list(read_lines(proc / "js_urls.txt"))
        )

        # stage classification
        stage_buckets = classify_stages(i.stage_results)
        missing_tools = missing_tools_from_skips(i.stage_results)

        # timing
        if i.scan_start and i.scan_end:
            duration = (i.scan_end - i.scan_start).total_seconds()
        else:
            duration = None

        return {
            "meta": {
                "domain": i.domain,
                "output_dir": str(i.output_dir),
                "report_dir": str(self.report_dir),
                "config_path": i.cfg_path,
                "scan_mode": i.scan_mode,
                "scan_start": i.scan_start.isoformat() if i.scan_start else None,
                "scan_end": i.scan_end.isoformat() if i.scan_end else None,
                "scan_duration_seconds": duration,
                "generated_at": now_iso(),
            },
            "counts": counts,
            "files": file_inventory,
            "dns_records": dns_records,
            "assets": assets,
            "nuclei": {
                "default": {
                    "findings": n_def_findings,
                    "severity_count": n_def_sev,
                },
                "endpoints": {
                    "findings": n_end_findings,
                    "severity_count": n_end_sev,
                },
                "dynamic": {
                    "findings": n_dyn_findings,
                    "severity_count": n_dyn_sev,
                },
            },
            "jsluice_secrets": {
                "findings": jsluice_secrets,
                "severity_count": jsluice_sev,
            },
            "high_value_targets": high_value,
            "interesting_api_paths": api_paths,
            "stages": stage_buckets,
            "missing_tools": missing_tools,
            "tool_versions": i.tool_versions,
            "config_text": i.cfg_text,
        }

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------
    def render_html(self, data: dict) -> str:
        c = (
            "<style>\n"
            "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', "
            "Roboto, sans-serif; margin: 0; padding: 24px; background: #f5f5f7; "
            "color: #1d1d1f; }\n"
            "  .container { max-width: 1400px; margin: 0 auto; }\n"
            "  h1 { border-bottom: 3px solid #0066cc; padding-bottom: 12px; }\n"
            "  h2 { background: #fff; padding: 12px 18px; border-left: 4px solid "
            "#0066cc; border-radius: 4px; margin-top: 32px; }\n"
            "  h3 { margin-top: 24px; }\n"
            "  table { border-collapse: collapse; width: 100%; background: #fff; "
            "margin: 10px 0; box-shadow: 0 1px 2px rgba(0,0,0,.05); }\n"
            "  th, td { padding: 8px 12px; border: 1px solid #e5e5ea; text-align: "
            "left; font-size: 14px; }\n"
            "  th { background: #f0f0f5; position: sticky; top: 0; }\n"
            "  tr:nth-child(even) td { background: #fafafa; }\n"
            "  code { background: #f0f0f5; padding: 2px 6px; border-radius: 3px; "
            "font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px; }\n"
            "  .badge { display: inline-block; padding: 2px 10px; border-radius: "
            "12px; font-size: 12px; font-weight: bold; color: #fff; }\n"
            "  .badge-critical { background: #d32f2f; }\n"
            "  .badge-high     { background: #f57c00; }\n"
            "  .badge-medium   { background: #fbc02d; color: #000; }\n"
            "  .badge-low      { background: #388e3c; }\n"
            "  .badge-info     { background: #1976d2; }\n"
            "  details { background: #fff; padding: 12px 18px; margin: 10px 0; "
            "border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,.05); }\n"
            "  summary { cursor: pointer; font-weight: 600; }\n"
            "  .kpis { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0; }\n"
            "  .kpi { background: #fff; padding: 16px 22px; border-radius: 6px; "
            "min-width: 150px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }\n"
            "  .kpi .v { font-size: 28px; font-weight: 700; color: #0066cc; }\n"
            "  .kpi .l { font-size: 12px; color: #666; text-transform: uppercase; "
            "letter-spacing: .04em; }\n"
            "  .filter { width: 100%; padding: 8px 12px; margin: 10px 0; border: "
            "1px solid #d2d2d7; border-radius: 4px; box-sizing: border-box; }\n"
            "  a { color: #0066cc; text-decoration: none; }\n"
            "  a:hover { text-decoration: underline; }\n"
            "  .file-grid { display: grid; grid-template-columns: repeat(auto-fill, "
            "minmax(360px, 1fr)); gap: 8px; }\n"
            "  .file-card { background: #fff; border: 1px solid #e5e5ea; padding: "
            "8px 12px; border-radius: 4px; display: flex; justify-content: space-"
            "between; }\n"
            "  .file-card .exists-yes { color: #388e3c; }\n"
            "  .file-card .exists-no  { color: #999; }\n"
            "  .small { font-size: 12px; color: #666; }\n"
            "  pre { background: #1e1e1e; color: #f5f5f5; padding: 12px; border-"
            "radius: 4px; overflow-x: auto; font-size: 12px; }\n"
            "</style>"
        )

        body = []
        body.append(self._html_head(data))
        body.append(self._html_kpis(data))
        body.append(self._html_section_coverage(data))
        body.append(self._html_section_dns(data))
        body.append(self._html_section_assets(data))
        body.append(self._html_section_content_discovery(data))
        body.append(self._html_section_js(data))
        body.append(self._html_section_secrets(data))
        body.append(self._html_section_params(data))
        body.append(self._html_section_nuclei(data))
        body.append(self._html_section_high_value(data))
        body.append(self._html_section_errors(data))
        body.append(self._html_section_recommendations(data))
        body.append(self._html_section_appendix(data))

        script = (
            "<script>\n"
            "function filterTable(input, tableId) {\n"
            "  const filter = input.value.toLowerCase();\n"
            "  const rows = document.querySelectorAll('#' + tableId + ' tbody tr');\n"
            "  for (const row of rows) {\n"
            "    row.style.display = row.textContent.toLowerCase().includes(filter) "
            "? '' : 'none';\n"
            "  }\n"
            "}\n"
            "</script>"
        )

        return (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            "<meta charset=\"utf-8\">\n"
            f"<title>recon-agent report — {escape(data['meta']['domain'])}</title>\n"
            f"{c}\n"
            "</head>\n<body>\n<div class=\"container\">\n"
            + "\n".join(body)
            + "\n</div>\n" + script + "\n</body>\n</html>\n"
        )

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------
    def render_markdown(self, data: dict) -> str:
        m = data["meta"]
        c = data["counts"]
        out: list[str] = []

        out.append(f"# recon-agent report — `{m['domain']}`\n")
        out.append("## 1. Executive Summary\n")
        out.append(f"- **Target domain**: `{m['domain']}`")
        out.append(f"- **Scan start**  : `{m['scan_start'] or 'Not recorded'}`")
        out.append(f"- **Scan end**    : `{m['scan_end'] or 'Not recorded'}`")
        dur = m["scan_duration_seconds"]
        out.append(f"- **Duration**    : `{dur:.1f}s`" if dur else "- **Duration**    : Not recorded")
        out.append(f"- **Output dir**  : `{m['output_dir']}`")
        out.append(f"- **Scan mode**   : `{m['scan_mode']}`")
        out.append(f"- **Config**      : `{m['config_path'] or 'default'}`")
        out.append("")

        # KPIs
        out.append("## 2. Recon Coverage Summary\n")
        for label, key in [
            ("Subdomains",       "subdomains"),
            ("Resolved",         "resolved"),
            ("Alive hosts",      "alive_hosts"),
            ("Collected URLs",   "all_urls"),
            ("JS URLs",          "js_urls"),
            ("Dynamic URLs",     "dynamic_urls"),
            ("Alive URLs",       "alive_urls"),
            ("Parameterized URLs","parameterized_urls"),
            ("Nuclei default",   "nuclei_default_findings"),
            ("Nuclei dynamic",   "nuclei_dynamic_findings"),
        ]:
            out.append(f"- **{label}**: `{c.get(key, 0)}`")
        out.append("")

        # Asset inventory
        out.append("## 3. Asset Inventory\n")
        if data["assets"]:
            out.append("| URL | Status | Length | Content-Type | Title | Tech |")
            out.append("|-----|-------:|-------:|--------------|-------|------|")
            for a in data["assets"][:200]:
                out.append(
                    f"| `{escape(a.get('url',''))}` | "
                    f"{a.get('status_code','')} | "
                    f"{a.get('content_length','')} | "
                    f"`{escape(str(a.get('content_type','')))}` | "
                    f"{escape(str(a.get('title','')))} | "
                    f"{escape(str(a.get('tech','')))} |"
                )
            if len(data["assets"]) > 200:
                out.append(f"\n_… {len(data['assets']) - 200} more not shown._\n")
        else:
            out.append("_Not generated._\n")

        # DNS inventory
        out.append("\n## 4. DNS Inventory\n")
        if data["dns_records"]:
            out.append("| Subdomain | IP | ASN | CNAME |")
            out.append("|-----------|----|-----|-------|")
            for r in data["dns_records"][:200]:
                asn = r.get("asn") or {}
                asn_str = asn.get("asn", "") if isinstance(asn, dict) else str(asn)
                out.append(
                    f"| `{escape(r.get('subdomain',''))}` | "
                    f"`{escape(str(r.get('ip','')))}` | "
                    f"{escape(str(asn_str))} | "
                    f"`{escape(str(r.get('cname','')))}` |"
                )
            if len(data["dns_records"]) > 200:
                out.append(f"\n_… {len(data['dns_records']) - 200} more not shown._\n")
        else:
            out.append("_Not generated._\n")

        # Content discovery
        out.append("## 5. Content Discovery\n")
        out.append("| Source | Count | Output file |")
        out.append("|--------|------:|-------------|")
        for label, key, rel in [
            ("katana + urlfinder (union)", "crawler_urls", "../processed/crawler_urls.txt"),
            ("dirsearch",                  "dirsearch_urls", "../processed/dirsearch_urls.txt"),
            ("waymore",                    "waymore_urls", "../processed/waymore_urls.txt"),
        ]:
            out.append(f"| {label} | `{c.get(key,0)}` | [{rel}]({rel}) |")
        out.append("")

        # JS analysis
        out.append("## 6. JavaScript Analysis\n")
        out.append(f"- JS files (final): `{c.get('js_urls', 0)}`")
        out.append(f"- xnLinkFinder endpoints: `{c.get('xnlinkfinder_endpoints', 0)}`")
        out.append(f"- xnLinkFinder URLs:      `{c.get('xnlinkfinder_urls', 0)}`")
        out.append(f"- Interesting API paths:  `{len(data['interesting_api_paths'])}`")
        out.append("- Output files:")
        out.append("  - [`../processed/js_urls.txt`](../processed/js_urls.txt)")
        out.append("  - [`../processed/xnlinkfinder_endpoints.txt`](../processed/xnlinkfinder_endpoints.txt)")
        out.append("  - [`../processed/xnlinkfinder_urls.txt`](../processed/xnlinkfinder_urls.txt)")
        if data["interesting_api_paths"]:
            out.append("\n<details><summary>Sample interesting API paths</summary>\n")
            for p in data["interesting_api_paths"][:30]:
                out.append(f"- `{escape(p)}`")
            out.append("\n</details>\n")

        # JS secrets (jsluice)
        out.append("## 6.1 JavaScript Secrets\n")
        _secrets = (data.get("jsluice_secrets") or {}).get("findings") or []
        if not _secrets:
            out.append("_No secrets found in JS by jsluice._\n")
        else:
            out.append(f"Total: `{len(_secrets)}` — verify before reporting.\n")
            out.append("| Severity | Kind | Value | JS URL |")
            out.append("|----------|------|-------|--------|")
            _ordered = sorted(
                _secrets,
                key=lambda s: -severity_rank((s.get("severity") or "info").lower()),
            )
            for s in _ordered[:100]:
                raw = s.get("data")
                val = (", ".join(f"{k}={v}" for k, v in raw.items())
                       if isinstance(raw, dict) else str(raw or ""))
                out.append(
                    f"| {(s.get('severity') or 'info').upper()} "
                    f"| `{escape(str(s.get('kind', '?')))}` "
                    f"| `{escape(val[:120])}` "
                    f"| `{escape(str(s.get('url', '')))}` |"
                )
            if len(_ordered) > 100:
                out.append(f"\n_… {len(_ordered) - 100} more in jsluice_secrets.json._\n")
            out.append("")

        # Parameter discovery
        out.append("## 7. Parameter Discovery\n")
        out.append(f"- Dynamic URLs scanned: `{c.get('dynamic_urls', 0)}`")
        out.append(f"- Parameters discovered: `{c.get('arjun_params', 0)}`")
        out.append(f"- Parameterized URLs:    `{c.get('parameterized_urls', 0)}`")
        out.append("- Output files:")
        out.append("  - [`../processed/arjun_params.txt`](../processed/arjun_params.txt)")
        out.append("  - [`../processed/parameterized_urls.txt`](../processed/parameterized_urls.txt)")
        out.append("")

        # Nuclei
        out.append("## 8. Nuclei Findings\n")
        for kind, label in [
            ("default", "Default scan (hosts)"),
            ("endpoints", "Endpoints scan (discovered URLs)"),
            ("dynamic", "Dynamic scan (params)"),
        ]:
            blk = data["nuclei"][kind]
            out.append(f"### {label}\n")
            sc = blk["severity_count"] or {}
            for sev in self.SEV_ORDER:
                out.append(f"- {sev}: `{sc.get(sev, 0)}`")
            out.append(f"- Total: `{len(blk['findings'])}`\n")
            if blk["findings"]:
                # group by severity, show only High & Critical by default
                by_sev: dict[str, list[dict]] = {s: [] for s in self.SEV_ORDER}
                for f in blk["findings"]:
                    s = ((f.get("info") or {}).get("severity") or "info").lower()
                    by_sev.setdefault(s, []).append(f)
                out.append("<details><summary>Findings by severity</summary>\n")
                for sev in self.SEV_ORDER:
                    items = by_sev.get(sev) or []
                    if not items:
                        continue
                    out.append(f"#### {sev.upper()} ({len(items)})\n")
                    out.append("| Severity | Template | Name | URL |")
                    out.append("|----------|----------|------|-----|")
                    for f in items[:100]:
                        info = f.get("info") or {}
                        out.append(
                            f"| {sev.upper()} | `{escape(f.get('template-id','?'))}` "
                            f"| {escape(info.get('name','?'))} "
                            f"| `{escape(f.get('matched-at') or f.get('host','?'))}` |"
                        )
                    if len(items) > 100:
                        out.append(f"\n_… {len(items) - 100} more._\n")
                    out.append("")
                out.append("</details>\n")

        # High-value
        out.append("## 9. High-Value Targets\n")
        if data["high_value_targets"]:
            out.append(f"Total: `{len(data['high_value_targets'])}`\n")
            out.append("| URL | Categories |")
            out.append("|-----|------------|")
            for h in data["high_value_targets"][:200]:
                out.append(
                    f"| `{escape(h['url'])}` | {', '.join(escape(c) for c in h['categories'])} |"
                )
            if len(data["high_value_targets"]) > 200:
                out.append(f"\n_… {len(data['high_value_targets']) - 200} more._\n")
        else:
            out.append("_No high-value targets identified._\n")

        # Errors / skipped
        out.append("## 10. Errors / Skipped / Missing Tools\n")
        if data["stages"].get("failed"):
            out.append("### Failed stages\n")
            for r in data["stages"]["failed"]:
                out.append(f"- `{r.get('stage','?')}` — {r.get('error','(no error)')}")
            out.append("")
        if data["stages"].get("skipped"):
            out.append("### Skipped stages\n")
            for r in data["stages"]["skipped"]:
                out.append(f"- `{r.get('stage','?')}` — {r.get('error','(skipped)')}")
            out.append("")
        if data["missing_tools"]:
            out.append("### Missing tools\n")
            for t in data["missing_tools"]:
                out.append(f"- `{t}`")
            out.append("")
        if not (data["stages"].get("failed") or data["stages"].get("skipped") or data["missing_tools"]):
            out.append("_No failures or skips recorded._\n")
        out.append("- Full command log: [`../logs/commands.log`](../logs/commands.log)\n")

        # Recommendations
        out.append("## 11. Manual Testing Recommendations\n")
        recs = self._recommendations(data)
        for tier, items in recs.items():
            if items:
                out.append(f"### {tier}\n")
                for u in items[:50]:
                    out.append(f"- `{escape(u)}`")
                if len(items) > 50:
                    out.append(f"\n_… {len(items) - 50} more._\n")
                out.append("")

        # Appendix
        out.append("## 12. Appendix\n")
        if data["tool_versions"]:
            out.append("### Tool versions\n")
            for tool, ver in sorted(data["tool_versions"].items()):
                out.append(f"- `{tool}`: {escape(ver)}")
            out.append("")
        out.append("### Command log\n")
        out.append("[`../logs/commands.log`](../logs/commands.log)\n")
        if data["config_text"]:
            out.append("### Config snapshot\n")
            out.append("```yaml")
            out.append(data["config_text"].rstrip())
            out.append("```\n")
        out.append("### All output files\n")
        out.append("| File | Status |")
        out.append("|------|--------|")
        for f in data["files"]:
            status = "✓ generated" if f["exists"] else "✗ not generated"
            out.append(f"| [`{f['rel']}`]({f['rel_link']}) | {status} |")
        out.append("")

        return "\n".join(out) + "\n"

    # ------------------------------------------------------------------
    # Recommendations — derived from collected data, no external calls.
    # ------------------------------------------------------------------
    def _recommendations(self, data: dict) -> dict[str, list[str]]:
        recs: dict[str, list[str]] = {
            "🔥 High priority targets (admin / login / config)": [],
            "📡 Interesting API / GraphQL endpoints": [],
            "🔧 URLs with parameters (worth fuzzing)": [],
            "🧩 JS-extracted API paths": [],
            "📂 Exposed files (env / git / backups)": [],
            "🚨 Nuclei High/Critical findings": [],
        }

        # High priority = admin/login/config categories from high_value
        for h in data["high_value_targets"]:
            cats = h["categories"]
            if any(c in ("admin panel", "login portal", "signup",
                         "password reset", "env file", "git config exposure",
                         "git exposure", "backup file", "database dump",
                         "credentials", "secret", "wordpress config")
                   for c in cats):
                recs["🔥 High priority targets (admin / login / config)"].append(h["url"])

        # Interesting APIs
        for u in data["interesting_api_paths"]:
            recs["📡 Interesting API / GraphQL endpoints"].append(u)

        # Parameterized URLs
        proc = self.inputs.output_dir / "processed"
        for u in read_lines(proc / "parameterized_urls.txt"):
            recs["🔧 URLs with parameters (worth fuzzing)"].append(u)

        # JS-extracted API paths (de-dup against existing)
        for u in data["interesting_api_paths"]:
            recs["🧩 JS-extracted API paths"].append(u)

        # Exposed files
        for h in data["high_value_targets"]:
            if any(c in ("env file", "env file (local)", "env file (production)",
                         "git config exposure", "git exposure", "backup file",
                         "database dump", "credentials", "secret",
                         "wordpress config", "phpinfo", "server-status",
                         "svn exposure") for c in h["categories"]):
                recs["📂 Exposed files (env / git / backups)"].append(h["url"])

        # Nuclei high/critical
        for kind in ("default", "dynamic"):
            for f in data["nuclei"][kind]["findings"]:
                sev = ((f.get("info") or {}).get("severity") or "").lower()
                if sev in ("high", "critical"):
                    url = f.get("matched-at") or f.get("host") or ""
                    if url:
                        recs["🚨 Nuclei High/Critical findings"].append(url)

        # de-dup within each bucket
        for k, v in recs.items():
            seen: set[str] = set()
            dedup: list[str] = []
            for u in v:
                if u not in seen:
                    seen.add(u)
                    dedup.append(u)
            recs[k] = dedup

        return recs

    # ------------------------------------------------------------------
    # HTML section helpers (kept short for readability)
    # ------------------------------------------------------------------
    def _html_head(self, data: dict) -> str:
        m = data["meta"]
        dur = m["scan_duration_seconds"]
        dur_str = f"{dur:.1f}s" if dur is not None else "Not recorded"
        return (
            f"<h1>recon-agent report — <code>{escape(m['domain'])}</code></h1>\n"
            "<h2>1. Executive Summary</h2>\n"
            "<table>\n"
            f"<tr><th>Target domain</th><td><code>{escape(m['domain'])}</code></td></tr>\n"
            f"<tr><th>Scan start</th><td><code>{escape(m['scan_start'] or 'Not recorded')}</code></td></tr>\n"
            f"<tr><th>Scan end</th><td><code>{escape(m['scan_end'] or 'Not recorded')}</code></td></tr>\n"
            f"<tr><th>Total duration</th><td><code>{dur_str}</code></td></tr>\n"
            f"<tr><th>Output folder</th><td><code>{escape(m['output_dir'])}</code></td></tr>\n"
            f"<tr><th>Scan mode</th><td><code>{escape(m['scan_mode'])}</code></td></tr>\n"
            f"<tr><th>Config file</th><td><code>{escape(m['config_path'] or 'default')}</code></td></tr>\n"
            "</table>"
        )

    def _html_kpis(self, data: dict) -> str:
        c = data["counts"]
        items = [
            ("Subdomains",        c.get("subdomains", 0)),
            ("Resolved",          c.get("resolved", 0)),
            ("Alive hosts",       c.get("alive_hosts", 0)),
            ("Collected URLs",    c.get("all_urls", 0)),
            ("JS URLs",           c.get("js_urls", 0)),
            ("Dynamic URLs",      c.get("dynamic_urls", 0)),
            ("Alive URLs",        c.get("alive_urls", 0)),
            ("Parameterized URLs",c.get("parameterized_urls", 0)),
            ("Nuclei default",    c.get("nuclei_default_findings", 0)),
            ("Nuclei dynamic",    c.get("nuclei_dynamic_findings", 0)),
        ]
        cards = "\n".join(
            f'<div class="kpi"><div class="v">{v:,}</div><div class="l">{escape(label)}</div></div>'
            for label, v in items
        )
        return (
            "<h2>2. Recon Coverage Summary</h2>\n"
            f"<div class=\"kpis\">{cards}</div>"
        )

    def _html_section_coverage(self, data: dict) -> str:
        # Coverage KPIs are already in section 2; nothing extra to render here.
        # The user spec listed this as a separate section — keep it as a
        # human-readable cross-reference / source list.
        c = data["counts"]
        rows = []
        for label, key, rel in [
            ("Subdomains",            "subdomains",            "../processed/subdomains.txt"),
            ("Resolved",              "resolved",              "../processed/resolved.txt"),
            ("Alive hosts",           "alive_hosts",           "../processed/alive.txt"),
            ("Crawler URLs (union)",  "crawler_urls",          "../processed/crawler_urls.txt"),
            ("dirsearch URLs",        "dirsearch_urls",        "../processed/dirsearch_urls.txt"),
            ("waymore URLs",          "waymore_urls",          "../processed/waymore_urls.txt"),
            ("All URLs (merged)",     "all_urls",              "../processed/all_urls.txt"),
            ("JS URLs (final)",       "js_urls",               "../processed/js_urls.txt"),
            ("Dynamic URLs",          "dynamic_urls",          "../processed/dynamic_urls.txt"),
            ("Alive URLs (after httpx)","alive_urls",          "../processed/alive_urls.txt"),
            ("xnLinkFinder endpoints","xnlinkfinder_endpoints","../processed/xnlinkfinder_endpoints.txt"),
            ("xnLinkFinder URLs",     "xnlinkfinder_urls",     "../processed/xnlinkfinder_urls.txt"),
            ("Arjun params",          "arjun_params",          "../processed/arjun_params.txt"),
            ("Parameterized URLs",    "parameterized_urls",    "../processed/parameterized_urls.txt"),
        ]:
            rows.append(
                f"<tr><td>{escape(label)}</td><td><code>{c.get(key, 0):,}</code></td>"
                f"<td><a href=\"{escape(rel)}\"><code>{escape(rel)}</code></a></td></tr>"
            )
        body = "\n".join(rows)
        return (
            "<h2>2.1 Source counts (clickable)</h2>\n"
            "<table><thead><tr><th>Source</th><th>Count</th><th>File</th></tr></thead>"
            f"<tbody>{body}</tbody></table>"
        )

    def _html_section_dns(self, data: dict) -> str:
        rows = data["dns_records"]
        if not rows:
            return '<h2>4. DNS Inventory</h2><p class="small">Not generated.</p>'
        body = []
        for r in rows[:500]:
            asn = r.get("asn") or {}
            asn_str = asn.get("asn", "") if isinstance(asn, dict) else str(asn)
            body.append(
                "<tr>"
                f"<td><code>{escape(str(r.get('subdomain','')))}</code></td>"
                f"<td><code>{escape(str(r.get('ip','')))}</code></td>"
                f"<td>{escape(str(asn_str))}</td>"
                f"<td><code>{escape(str(r.get('cname','')))}</code></td>"
                f"<td><a href=\"../processed/resolved_detail.json\"><code>resolved_detail.json</code></a></td>"
                "</tr>"
            )
        extra = ""
        if len(rows) > 500:
            extra = f'<p class="small">… {len(rows) - 500} more in the JSON file.</p>'
        return (
            "<h2>4. DNS Inventory</h2>\n"
            '<input class="filter" placeholder="filter… (subdomain, IP, ASN, CNAME)" '
            'onkeyup="filterTable(this, \'tbl-dns\')">\n'
            '<table id="tbl-dns"><thead><tr>'
            '<th>Subdomain</th><th>IP</th><th>ASN</th><th>CNAME</th><th>Source</th>'
            "</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>{extra}"
        )

    def _html_section_assets(self, data: dict) -> str:
        rows = data["assets"]
        if not rows:
            return '<h2>3. Asset Inventory</h2><p class="small">Not generated.</p>'
        body = []
        for a in rows[:500]:
            body.append(
                "<tr>"
                f"<td><code>{escape(str(a.get('url','')))}</code></td>"
                f"<td>{a.get('status_code', '')}</td>"
                f"<td>{a.get('content_length', '')}</td>"
                f"<td>{escape(str(a.get('content_type','')))}</td>"
                f"<td>{escape(str(a.get('title','')))}</td>"
                f"<td>{escape(str(a.get('tech','')))}</td>"
                f"<td><a href=\"../processed/alive_detail.json\"><code>alive_detail.json</code></a></td>"
                "</tr>"
            )
        extra = ""
        if len(rows) > 500:
            extra = f'<p class="small">… {len(rows) - 500} more in the JSON file.</p>'
        return (
            "<h2>3. Asset Inventory</h2>\n"
            '<input class="filter" placeholder="filter…" '
            'onkeyup="filterTable(this, \'tbl-assets\')">\n'
            '<table id="tbl-assets"><thead><tr>'
            '<th>URL</th><th>Status</th><th>Length</th><th>Type</th>'
            '<th>Title</th><th>Tech</th><th>Source</th>'
            "</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>{extra}"
        )

    def _html_section_content_discovery(self, data: dict) -> str:
        c = data["counts"]
        rows = "\n".join(
            f"<tr><td>{escape(label)}</td><td><code>{c.get(key,0):,}</code></td>"
            f"<td><a href=\"{escape(rel)}\"><code>{escape(rel)}</code></a></td></tr>"
            for label, key, rel in [
                ("katana + urlfinder (union)", "crawler_urls",  "../processed/crawler_urls.txt"),
                ("dirsearch",                  "dirsearch_urls","../processed/dirsearch_urls.txt"),
                ("waymore",                    "waymore_urls",  "../processed/waymore_urls.txt"),
                ("raw katana output",          None,            "../raw/content_discovery/katana_urls.txt"),
                ("raw urlfinder output",       None,            "../raw/content_discovery/urlfinder_urls.txt"),
                ("raw dirsearch output",       None,            "../raw/dirsearch/dirsearch_raw.txt"),
                ("raw waymore output",         None,            "../raw/waymore/waymore_raw.txt"),
            ]
        )
        return (
            "<h2>5. Content Discovery</h2>\n"
            "<table><thead><tr><th>Source</th><th>Count</th><th>File</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    def _html_section_js(self, data: dict) -> str:
        c = data["counts"]
        api = data["interesting_api_paths"]
        api_html = "".join(f"<li><code>{escape(p)}</code></li>" for p in api[:80])
        more = ""
        if len(api) > 80:
            more = f'<p class="small">… {len(api) - 80} more in js_urls.txt</p>'
        return (
            "<h2>6. JavaScript Analysis</h2>\n"
            "<table>"
            f"<tr><th>JS files (final)</th><td><code>{c.get('js_urls',0):,}</code></td>"
            f"<td><a href=\"../processed/js_urls.txt\"><code>js_urls.txt</code></a></td></tr>"
            f"<tr><th>xnLinkFinder endpoints</th><td><code>{c.get('xnlinkfinder_endpoints',0):,}</code></td>"
            f"<td><a href=\"../processed/xnlinkfinder_endpoints.txt\"><code>xnlinkfinder_endpoints.txt</code></a></td></tr>"
            f"<tr><th>xnLinkFinder URLs</th><td><code>{c.get('xnlinkfinder_urls',0):,}</code></td>"
            f"<td><a href=\"../processed/xnlinkfinder_urls.txt\"><code>xnlinkfinder_urls.txt</code></a></td></tr>"
            f"<tr><th>Interesting API paths</th><td><code>{len(api):,}</code></td>"
            "<td><span class=\"small\">filtered from the two files above</span></td></tr>"
            "</table>\n"
            "<details><summary>Interesting API paths (top 80)</summary>\n"
            f"<ul>{api_html}</ul>{more}"
            "</details>"
        )

    def _html_section_secrets(self, data: dict) -> str:
        blk = data.get("jsluice_secrets") or {}
        secrets = blk.get("findings") or []
        if not secrets:
            return (
                "<h2>6.1 JavaScript Secrets</h2>\n"
                '<p class="small">No secrets found in JS by jsluice.</p>'
            )
        sc = blk.get("severity_count") or {}
        sev_headers = "".join(f"<th>{s}</th>" for s in self.SEV_ORDER)
        sev_cells = "".join(
            f"<td><code>{sc.get(s, 0):,}</code></td>" for s in self.SEV_ORDER
        )
        # Highest-severity first so the scary ones sit at the top.
        ordered = sorted(
            secrets,
            key=lambda s: -severity_rank((s.get("severity") or "info").lower()),
        )
        rows = []
        for s in ordered[:200]:
            sev = (s.get("severity") or "info").lower()
            # ``data`` may be a dict of {name: value}; render compactly + escaped.
            raw = s.get("data")
            if isinstance(raw, dict):
                val = ", ".join(f"{k}={v}" for k, v in raw.items())
            else:
                val = str(raw or "")
            rows.append(
                "<tr>"
                f"<td>{severity_badge(sev)}</td>"
                f"<td><code>{escape(str(s.get('kind', '?')))}</code></td>"
                f"<td><span class=\"small\"><code>{escape(val[:160])}</code></span></td>"
                f"<td><code>{escape(str(s.get('url', '')))}</code></td>"
                "</tr>"
            )
        extra = ""
        if len(ordered) > 200:
            extra = f'<p class="small">… {len(ordered) - 200} more in jsluice_secrets.json</p>'
        return (
            "<h2>6.1 JavaScript Secrets</h2>\n"
            '<p class="small">API keys / tokens extracted from JavaScript by '
            "jsluice (AST). Verify before reporting — some are low-risk or "
            "false positives.</p>\n"
            f"<table><tr>{sev_headers}</tr><tr>{sev_cells}</tr></table>\n"
            f"<details open><summary><strong>{len(secrets):,} secret(s)</strong></summary>\n"
            "<table><thead><tr>"
            "<th>Severity</th><th>Kind</th><th>Value</th><th>JS URL</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>{extra}"
            "</details>"
        )

    def _html_section_params(self, data: dict) -> str:
        c = data["counts"]
        return (
            "<h2>7. Parameter Discovery</h2>\n"
            "<table>"
            f"<tr><th>Dynamic URLs scanned</th><td><code>{c.get('dynamic_urls',0):,}</code></td></tr>"
            f"<tr><th>Arjun params</th><td><code>{c.get('arjun_params',0):,}</code></td>"
            f"<td><a href=\"../processed/arjun_params.txt\"><code>arjun_params.txt</code></a></td></tr>"
            f"<tr><th>Parameterized URLs</th><td><code>{c.get('parameterized_urls',0):,}</code></td>"
            f"<td><a href=\"../processed/parameterized_urls.txt\"><code>parameterized_urls.txt</code></a></td></tr>"
            "</table>"
        )

    def _html_section_nuclei(self, data: dict) -> str:
        out = ["<h2>8. Nuclei Findings</h2>"]
        for kind, label in [
            ("default", "Default scan (hosts)"),
            ("endpoints", "Endpoints scan (discovered URLs)"),
            ("dynamic", "Dynamic scan (params)"),
        ]:
            blk = data["nuclei"][kind]
            sc = blk["severity_count"] or {}
            sev_cells = "".join(
                f"<td><code>{sc.get(s, 0):,}</code></td>" for s in self.SEV_ORDER
            )
            sev_headers = "".join(f"<th>{s}</th>" for s in self.SEV_ORDER)
            out.append(
                f"<h3>{label} <span class=\"small\">— {len(blk['findings']):,} total</span></h3>\n"
                f"<table><tr>{sev_headers}</tr><tr>{sev_cells}</tr></table>"
            )
            findings = blk["findings"]
            if not findings:
                out.append('<p class="small">No findings.</p>')
                continue
            # group by severity
            by_sev: dict[str, list[dict]] = {s: [] for s in self.SEV_ORDER}
            for f in findings:
                s = ((f.get("info") or {}).get("severity") or "info").lower()
                by_sev.setdefault(s, []).append(f)
            for sev in self.SEV_ORDER:
                items = by_sev.get(sev) or []
                if not items:
                    continue
                rows = []
                for f in items[:100]:
                    info = f.get("info") or {}
                    matcher = f.get("matcher-name") or f.get("matcher_name") or ""
                    evidence = f.get("extracted-results") or f.get("evidence") or ""
                    evidence_str = ""
                    if isinstance(evidence, list):
                        evidence_str = ", ".join(str(e) for e in evidence[:2])
                    elif evidence:
                        evidence_str = str(evidence)[:200]
                    rows.append(
                        "<tr>"
                        f"<td>{severity_badge(sev)}</td>"
                        f"<td><code>{escape(f.get('template-id','?'))}</code></td>"
                        f"<td>{escape(info.get('name','?'))}</td>"
                        f"<td><code>{escape(f.get('matched-at') or f.get('host','?'))}</code></td>"
                        f"<td>{escape(str(matcher))}</td>"
                        f"<td><span class=\"small\">{escape(evidence_str)}</span></td>"
                        f"<td><a href=\"../findings/{kind}/nuclei.json\"><code>nuclei.json</code></a></td>"
                        "</tr>"
                    )
                extra = ""
                if len(items) > 100:
                    extra = f'<p class="small">… {len(items) - 100} more in nuclei_{kind}.json</p>'
                out.append(
                    f"<details open><summary><strong>{sev.upper()}</strong> "
                    f"— {len(items):,} finding(s)</summary>\n"
                    "<table><thead><tr>"
                    "<th>Severity</th><th>Template</th><th>Name</th>"
                    "<th>URL</th><th>Matcher</th><th>Evidence</th><th>Source</th>"
                    "</tr></thead>"
                    f"<tbody>{''.join(rows)}</tbody></table>{extra}"
                    "</details>"
                )
        return "\n".join(out)

    def _html_section_high_value(self, data: dict) -> str:
        rows = data["high_value_targets"]
        if not rows:
            return '<h2>9. High-Value Targets</h2><p class="small">None identified.</p>'
        body = []
        for r in rows[:500]:
            cats = ", ".join(escape(c) for c in r["categories"])
            body.append(
                "<tr>"
                f"<td><code>{escape(r['url'])}</code></td>"
                f"<td>{cats}</td>"
                "</tr>"
            )
        extra = ""
        if len(rows) > 500:
            extra = f'<p class="small">… {len(rows) - 500} more (search all_urls.txt / dynamic_urls.txt)</p>'
        return (
            "<h2>9. High-Value Targets</h2>\n"
            '<input class="filter" placeholder="filter…" '
            'onkeyup="filterTable(this, \'tbl-hv\')">\n'
            '<table id="tbl-hv"><thead><tr><th>URL</th><th>Categories</th></tr></thead>'
            f"<tbody>{''.join(body)}</tbody></table>{extra}"
        )

    def _html_section_errors(self, data: dict) -> str:
        out = ["<h2>10. Errors / Skipped / Missing Tools</h2>"]
        st = data["stages"]
        if st.get("failed"):
            rows = "".join(
                f"<tr><td><code>{escape(r.get('stage','?'))}</code></td>"
                f"<td>{escape(r.get('error') or '(no error)')}</td></tr>"
                for r in st["failed"]
            )
            out.append(
                "<details open><summary>❌ Failed stages "
                f"({len(st['failed'])})</summary>"
                "<table><thead><tr><th>Stage</th><th>Error</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></details>"
            )
        if st.get("skipped"):
            rows = "".join(
                f"<tr><td><code>{escape(r.get('stage','?'))}</code></td>"
                f"<td>{escape(r.get('error') or '(skipped)')}</td></tr>"
                for r in st["skipped"]
            )
            out.append(
                "<details><summary>⏭ Skipped stages "
                f"({len(st['skipped'])})</summary>"
                "<table><thead><tr><th>Stage</th><th>Reason</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></details>"
            )
        if data["missing_tools"]:
            items = "".join(f"<li><code>{escape(t)}</code></li>" for t in data["missing_tools"])
            out.append(f"<details><summary>🔧 Missing tools ({len(data['missing_tools'])})</summary><ul>{items}</ul></details>")
        if not (st.get("failed") or st.get("skipped") or data["missing_tools"]):
            out.append('<p class="small">No failures or skips recorded.</p>')
        out.append(
            '<p>Full command log: <a href="../logs/commands.log"><code>../logs/commands.log</code></a></p>'
        )
        return "\n".join(out)

    def _html_section_recommendations(self, data: dict) -> str:
        recs = self._recommendations(data)
        out = ["<h2>11. Manual Testing Recommendations</h2>"]
        for tier, items in recs.items():
            if not items:
                continue
            lis = "".join(f"<li><code>{escape(u)}</code></li>" for u in items[:50])
            more = ""
            if len(items) > 50:
                more = f'<p class="small">… {len(items) - 50} more.</p>'
            out.append(
                f"<details open><summary>{escape(tier)} ({len(items)})</summary>"
                f"<ul>{lis}</ul>{more}</details>"
            )
        if not any(recs.values()):
            out.append('<p class="small">No actionable items generated.</p>')
        return "\n".join(out)

    def _html_section_appendix(self, data: dict) -> str:
        out = ["<h2>12. Appendix</h2>"]
        if data["tool_versions"]:
            rows = "".join(
                f"<tr><td><code>{escape(tool)}</code></td><td>{escape(ver)}</td></tr>"
                for tool, ver in sorted(data["tool_versions"].items())
            )
            out.append(
                "<h3>Tool versions</h3>"
                "<table><thead><tr><th>Tool</th><th>Version</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        else:
            out.append('<h3>Tool versions</h3><p class="small">Not collected.</p>')

        out.append(
            "<h3>Command log</h3>"
            '<p><a href="../logs/commands.log"><code>../logs/commands.log</code></a></p>'
        )

        if data["config_text"]:
            out.append(
                "<h3>Config snapshot</h3>"
                f"<pre>{escape(data['config_text'])}</pre>"
            )

        out.append("<h3>All output files</h3>")
        cards = []
        for f in data["files"]:
            klass = "exists-yes" if f["exists"] else "exists-no"
            label = "✓" if f["exists"] else "✗"
            size = f["size"]
            size_str = f"{size:,}B" if size else "—"
            cards.append(
                f'<div class="file-card"><span><a href="{escape(f["rel_link"])}">'
                f'<code>{escape(f["rel"])}</code></a> '
                f'<span class="small">{escape(f["label"])}</span></span>'
                f'<span class="{klass}">{label} {size_str}</span></div>'
            )
        out.append(f'<div class="file-grid">{"".join(cards)}</div>')
        return "\n".join(out)

    # ------------------------------------------------------------------
    # Write all three artefacts
    # ------------------------------------------------------------------
    def write(self) -> dict:
        data = self.collect()
        self.html_path.write_text(self.render_html(data), encoding="utf-8")
        self.md_path.write_text(self.render_markdown(data), encoding="utf-8")
        write_json(self.json_path, data)
        return {
            "html": str(self.html_path),
            "md": str(self.md_path),
            "json": str(self.json_path),
            "issues": sum(len(v) for k, v in data["stages"].items() if k == "failed"),
        }


# ----------------------------------------------------------------------
# Convenience wrapper used by main.py
# ----------------------------------------------------------------------
def build_report(
    output_dir: Path,
    domain: str,
    cfg: dict,
    *,
    cfg_path: str = "",
    cfg_text: str = "",
    scan_start: Optional[datetime] = None,
    scan_end: Optional[datetime] = None,
    tool_versions: Optional[dict[str, str]] = None,
    stage_results: Optional[list[dict]] = None,
    scan_mode: str = "active",
) -> dict:
    """Build the three report artefacts under ``output_dir/report/``."""
    inputs = ReportInputs(
        output_dir=output_dir,
        domain=domain,
        cfg=cfg,
        cfg_path=cfg_path,
        cfg_text=cfg_text,
        scan_start=scan_start,
        scan_end=scan_end,
        tool_versions=tool_versions or {},
        stage_results=stage_results or [],
        scan_mode=scan_mode,
    )
    return ReportBuilder(inputs).write()
