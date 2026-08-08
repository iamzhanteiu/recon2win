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
from urllib.parse import urlsplit
from typing import Any, Iterable, Optional

from . import baseline, behavior, existence, layout, xlsx_report
from .utils import now_iso, read_lines, write_json


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
    SEV_ORDER = ("unknown", "info", "low", "medium", "high", "critical")
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


def summarize_url_surface(rows: list[dict]) -> dict:
    """Aggregate httpx URL-detail rows into a status / content-type breakdown.

    Powers the report's discovered-URL surface view — the human-readable
    counterpart of ``processed/alive_urls_table.txt``. ``application/json`` is
    called out as APIs and ``401/403`` as auth-gated because those two buckets
    are what a tester scans for first. ``by_status`` / ``by_type`` are ordered
    by descending count so the display can just take the head.
    """
    def _int(v) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    by_status: dict[int, int] = {}
    by_type: dict[str, int] = {}
    apis = auth_gated = total = 0
    for r in rows:
        if not isinstance(r, dict) or not r.get("url"):
            continue
        total += 1
        st = _int(r.get("status_code"))
        by_status[st] = by_status.get(st, 0) + 1
        ctype = (r.get("content_type") or "-").split(";")[0].strip().lower() or "-"
        by_type[ctype] = by_type.get(ctype, 0) + 1
        if ctype == "application/json":
            apis += 1
        if st in (401, 403):
            auth_gated += 1
    return {
        "total": total,
        "by_status": dict(sorted(by_status.items(), key=lambda kv: -kv[1])),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "apis": apis,
        "auth_gated": auth_gated,
    }


def stage_extra(stage_results: list[dict], stage: str) -> dict:
    """``extra`` dict of the named stage's result, or ``{}`` if it never
    ran. Every stage-specific coverage helper below is a thin wrapper over
    this — the shared join so a stage's own diagnostic numbers (computed
    once, at run time) can be read back into the report instead of
    silently living only in ``logs/stages.json``.
    """
    row = next((r for r in stage_results or [] if r.get("stage") == stage), None)
    if not isinstance(row, dict):
        return {}
    extra = row.get("extra")
    return extra if isinstance(extra, dict) else {}


def fuzz_coverage(stage_results: list[dict], stage: str) -> dict:
    """Pull ``modules.fuzz_targets.select_targets``'s host-selection stats
    out of a stage result, for ``"dirsearch"`` / ``"ffuf"``.

    Both stages compute exactly the numbers needed to answer "how much of
    the alive-host surface did this actually touch" (``modules/fuzz_targets.py``
    even says so in its own docstring: "stats đi thẳng vào extra của stage
    result nên operator nhìn báo cáo là biết đã cắt được bao nhiêu") — but
    until this function existed nothing ever read ``extra.selection`` back
    out. A run that fuzzed 40 of 300 distinct hosts looked identical, in
    the report, to one that fuzzed all 300: both just show a URL count.

    Returns ``{}`` when the stage didn't run or has no selection stats
    (e.g. an older output tree, or ``--skip-dirsearch``).
    """
    sel = stage_extra(stage_results, stage).get("selection")
    return sel if isinstance(sel, dict) else {}


def fuzz_screen(stage_results: list[dict], stage: str) -> dict:
    """Pull ``modules.behavior.screen``'s post-fuzz verdict out of a stage
    result, for ``"dirsearch"`` / ``"ffuf"``: ``{"enabled", "raw_hits",
    "dropped", "kept", "blanket_hosts"}``.

    Distinct from :func:`fuzz_coverage`, which answers "which HOSTS got
    fuzzed at all" from a PRE-fuzz baseline probe (``fuzz_targets.py``).
    This answers "of the HITS the wordlist actually produced, how many
    were one response shape wearing many paths" — computed AFTER fuzzing
    by clustering on status/content-type/redirect-target/words-lines
    (``modules/behavior.py``). The two numbers are unrelated passes;
    neither implies the other, and until this function existed the second
    one only ever reached the operator via a console line or
    ``logs/stages.json`` — never the report.

    Returns ``{}`` when the stage didn't run, has no screen stats (older
    output tree), or ``<stage>.screen.enabled`` was turned off in config.
    """
    scr = stage_extra(stage_results, stage).get("screen")
    return scr if isinstance(scr, dict) and scr.get("enabled") else {}


def endpoint_existence(
    hit_urls: dict[str, set[str]],
    detail_index: dict[str, dict],
    body_snippets: dict[str, str],
    baselines_by_host: dict[str, "baseline.Baseline"],
) -> list[dict]:
    """Classify every ffuf/dirsearch hit by RESPONSE BEHAVIOUR rather than
    status code alone — see ``modules/existence.py``'s module docstring for
    the full reasoning (baseline shape + body-preview signal families +
    status family, combined). ``hit_urls`` is ``{url: {"ffuf", "dirsearch"}}``
    — a URL both tools found carries both names.

    Every input here is already on disk from an earlier stage of the same
    run: ``detail_index`` (httpx probe of the merged URL corpus, for status),
    ``body_snippets`` (``responses/preview.json``, capped by
    ``responses.max_urls`` — a hit outside that cap still gets classified,
    just from status/baseline alone, with no body signal to add), and
    ``baselines_by_host`` (:func:`modules.baseline.load_from_raw`, the
    not-found shape each host was measured against before fuzzing started).
    No new HTTP requests.
    """
    out: list[dict] = []
    for url, sources in hit_urls.items():
        row = detail_index.get(url) or {}
        status = int(row.get("status_code") or 0)
        host = (urlsplit(url).hostname or "").lower()
        bl = baselines_by_host.get(host)
        baseline_is_noise = None
        if bl is not None and bl.consistent:
            b = baseline.row_to_behavior(row) if row else behavior.Behavior(url=url, status=status)
            baseline_is_noise = bl.is_noise(b)
        result = existence.classify(
            status, body_snippets.get(url, ""), baseline_is_noise=baseline_is_noise,
        )
        out.append({
            "url": url,
            "sources": sorted(sources),
            "status": status or None,
            "verdict": result.verdict,
            "reasons": result.reasons,
        })
    return out


def existence_counts(results: list[dict]) -> dict[str, int]:
    """Every verdict key present even at zero — see :func:`fuzz_coverage`'s
    docstring for why report tables need this rather than a bare Counter."""
    out = {existence.CONFIRMED: 0, existence.LIKELY: 0,
           existence.UNKNOWN: 0, existence.NOT_FOUND: 0}
    for r in results:
        out[r["verdict"]] = out.get(r["verdict"], 0) + 1
    return out


def url_facts(index: dict[str, dict], url: str,
              snippets: dict[str, str] | None = None) -> dict:
    """Response facts for an arbitrary URL — the shared join for every
    section that lists URLs, endpoints or JS URLs.

    Every one of those sections used to print bare strings, so the report
    could not distinguish an endpoint that answers 200 with JSON from one
    the server has never heard of. The run already probed them; the facts
    just were not joined on.

    Relative endpoints (``/api/v1/x`` mined out of JS) legitimately have no
    row — they resolve to blanks, which reads as "not probed" rather than as
    a fabricated zero.
    """
    facts = enrich_target(url, [], index.get(url) if index else None)
    facts["snippet"] = (snippets or {}).get(url, "")
    return facts


def md_facts_cells(index: dict[str, dict], url: str) -> str:
    """``"`403` | `1.2KB` | `text/html`"`` — three Markdown table cells."""
    f = url_facts(index, url)
    return (f"`{_fmt_status(f['status'])}` | `{_fmt_len(f['content_length'])}` "
            f"| `{escape(f['content_type'] or '-')}`")


MD_FACTS_HEAD = "ST | Length | Type"
MD_FACTS_SEP = "----|--------|------"


def html_facts_cells(index: dict[str, dict], url: str,
                     snippets: dict[str, str] | None = None) -> str:
    """Three ``<td>`` cells; the body snippet rides along as a tooltip so it
    costs no column width (``response body optional``)."""
    f = url_facts(index, url, snippets)
    tip = f' title="{escape(f["snippet"][:200])}"' if f.get("snippet") else ""
    return (f'<td class="{_status_class(f["status"])}"{tip}>'
            f"{_fmt_status(f['status'])}</td>"
            f"<td>{_fmt_len(f['content_length'])}</td>"
            f"<td><code>{escape(f['content_type'] or '-')}</code></td>")


HTML_FACTS_HEAD = "<th>ST</th><th>Length</th><th>Type</th>"


def _status_class(status: int | None) -> str:
    """CSS class for a status cell in section 9.

    401/403 gets its own colour rather than being lumped in with errors: a
    gated endpoint is the strongest lead the report can offer — the path
    demonstrably exists and something is guarding it.
    """
    if status is None:
        return "st-none"
    if status in (401, 403):
        return "st-gated"
    if 200 <= status < 300:
        return "st-ok"
    if 300 <= status < 400:
        return "st-redir"
    return "st-dead"


def _fmt_status(status: int | None) -> str:
    """``None`` is "we never asked", not 0 — say so rather than printing a
    number the run never observed."""
    return "—" if status is None else str(status)


def _fmt_len(n: int | None) -> str:
    if n is None:
        return "—"
    if n < 1024:
        return f"{n}B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f}KB"
    return f"{n / 1024 ** 2:.1f}MB"


def is_method_bypass(row: dict) -> bool:
    """True when a jsluice_method_check row's real-method status got
    further than the GET baseline did — the row worth surfacing first."""
    st = row.get("status")
    get_st = row.get("get_status")
    return (isinstance(st, int) and 200 <= st < 400
            and (get_st is None or get_st in (401, 403, 404, 405)))


def index_detail_by_url(*row_sets: list[dict]) -> dict[str, dict]:
    """``{url: httpx row}`` from one or more detail files, first wins.

    Order matters: pass the more authoritative probe first. ``alive_urls``
    covers the merged corpus, while ``jsluice_alive`` re-probes the URLs
    mined out of JS *after* that corpus was built — so a JS-derived endpoint
    only has a row in the second file.
    """
    out: dict[str, dict] = {}
    for rows in row_sets:
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            url = str(r.get("url") or r.get("input") or "").strip()
            if url and url not in out:
                out[url] = r
    return out


def enrich_target(url: str, categories: list[str], row: dict | None) -> dict:
    """A high-value entry with the response facts attached.

    "High value" used to be decided from the URL string alone, which meant
    the report ranked ``/admin`` on a host that 404s it exactly the same as
    ``/admin`` returning 200 with a login form. Status, size and content-type
    are what separate the two, and the run has already probed for them —
    they were simply never joined onto this section.

    ``row`` is the matching httpx record, or ``None`` when the URL was never
    probed (it came from a source that runs after the probe). Missing is
    reported as missing, never as zero.
    """
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    entry: dict = {"url": url, "categories": categories,
                   "status": None, "content_length": None,
                   "content_type": "", "title": "", "webserver": "",
                   "location": "", "probed": False}
    if not isinstance(row, dict):
        return entry
    entry.update({
        "status": _int(row.get("status_code")),
        "content_length": _int(row.get("content_length")),
        "content_type": (row.get("content_type") or "").split(";")[0].strip(),
        "title": (row.get("title") or "").strip(),
        "webserver": (row.get("webserver") or "").strip(),
        "location": (row.get("location") or "").strip(),
        "probed": True,
    })
    return entry


# How much a category actually earns a place in this section. Some labels
# describe the PATH (a backup file, an actuator) and are findings on their
# own; others describe the HOST (``qa.``, ``test.``) and merely say where a
# URL lives — on a QA host that tag lands on every static asset it serves.
# Measured on discover.com: 446 of 951 entries were "qa environment", most
# of them webpack chunks.
_CATEGORY_WEIGHT = {
    "database dump": 100, "backup file": 100, "config file": 95,
    "version control": 95, "directory listing": 90, "spring actuator": 90,
    "debug endpoint": 85,
    "admin panel": 80, "upload endpoint": 75, "graphql": 70,
    "login portal": 60, "api endpoint (versioned)": 55,
    "versioned api": 55, "api endpoint": 50,
    # Host-derived tags: real signal, but weak on its own.
    "qa environment": 15, "test environment": 15, "staging environment": 15,
    "dev environment": 15,
}
_DEFAULT_CATEGORY_WEIGHT = 40

# Apache/nginx/IIS autoindex pages all title the page "Index of <path>" —
# the one signature that survives across every server that implements
# directory listing. Detectable only from the RESPONSE (title/body), never
# from the URL text, which is why it needs its own join instead of a
# HIGH_VALUE_PATTERNS entry.
_DIR_LISTING_TITLE_RE = re.compile(r"^index of\b", re.IGNORECASE)
_DIR_LISTING_BODY_RE = re.compile(r"<title>\s*index of\b", re.IGNORECASE)


def is_directory_listing(row: dict | None, snippet: str = "") -> bool:
    """True when *row* (an httpx detail record) looks like an autoindex page.

    Checked via ``title`` first (httpx always parses it when present) and
    falls back to the captured body snippet for hits that only have a
    preview (ffuf/dirsearch), since those never got an httpx title field.
    """
    if isinstance(row, dict):
        title = str(row.get("title") or "").strip()
        if _DIR_LISTING_TITLE_RE.match(title):
            return True
    if snippet and _DIR_LISTING_BODY_RE.search(snippet):
        return True
    return False

# Assets that are content, not attack surface. Source maps are deliberately
# NOT here — a .map is one of the better things this section can surface.
_STATIC_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".webp")


def _hv_shape_key(h: dict) -> tuple:
    """Host + response shape. Entries sharing one are the same answer."""
    try:
        host = (urlsplit(h.get("url", "")).hostname or "").lower()
    except ValueError:
        host = ""
    return (host, h.get("status"), h.get("content_length"),
            h.get("content_type", ""), h.get("location", ""))


def category_weight(categories: list[str]) -> int:
    """Weight of the strongest category on an entry."""
    if not categories:
        return 0
    return max(_CATEGORY_WEIGHT.get(c, _DEFAULT_CATEGORY_WEIGHT)
               for c in categories)


def is_static_asset(url: str) -> bool:
    path = (url or "").split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith(_STATIC_SUFFIXES)


# Ranking for section 9. Lower sorts first.
#   status tier  — 200 reachable, then 401/403 (exists AND guarded: the best
#                  kind of lead), then other codes, then 404, then unprobed
#   category     — what actually makes it interesting
#   static asset — a 1.9 MB webpack chunk on a QA host is not a target; it
#                  used to sort FIRST because the tiebreak was body size
#   size         — only as a last resort
def target_sort_key(t: dict) -> tuple:
    st = t.get("status")
    if st is None:
        tier = 4
    elif st in (401, 403):
        tier = 1
    elif st in (404, 410):
        tier = 3
    elif 200 <= st < 300:
        tier = 0
    else:
        tier = 2
    return (
        tier,
        # A shape repeated across many URLs on one host is one answer, not
        # many findings — rank the unique responses above it.
        1 if (t.get("shape_count") or 1) > 1 else 0,
        # Static demotion outranks the category on purpose: the categories
        # that come from the HOSTNAME ("upload endpoint" on
        # securedocupload.*) land on every asset that host serves, so a
        # webpack chunk would otherwise outrank the real endpoints.
        1 if is_static_asset(t.get("url", "")) else 0,
        -category_weight(t.get("categories") or []),
        -(t.get("content_length") or 0),
        t.get("url", ""),
    )


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
# Form ranking — a crawl returns hundreds of forms and most are search
# boxes and newsletter signups. Order by what is actually worth an hour of
# manual testing so the top of the table is the part someone reads.
# ----------------------------------------------------------------------
# Framework plumbing that appears on every page of a given stack and is
# never itself the target. Counting these as "inputs" is how an ASP.NET
# postback stub outranks a login form — measured on a real acronis.com run,
# where __VIEWSTATE forms scored 84 vs 74 for username/password.
_FORM_NOISE_PARAMS = frozenset({
    "__eventtarget", "__eventargument", "__lastfocus", "__viewstate",
    "__viewstategenerator", "__viewstateencrypted", "__eventvalidation",
    "__requestverificationtoken", "__scrollpositionx", "__scrollpositiony",
})

# CSRF tokens mark a genuinely state-changing form, so they are not noise —
# but the token field itself is never the bug, so it earns no keyword bonus.
_FORM_CSRF_PARAMS = frozenset({
    "_token", "csrfmiddlewaretoken", "authenticity_token", "csrf_token",
    "csrf", "_csrf",
})

# Field names that mark a form worth an hour of manual testing. Matched on
# the whole field name (or as a word part), never as a bare substring of the
# joined list — "id" inside "disasterRecovery" is not an identifier field.
_FORM_HOT_KEYWORDS = (
    "password", "passwd", "email", "user", "username", "login", "role",
    "admin", "file", "upload", "redirect", "return", "url", "callback",
    "id", "uuid", "account", "amount", "price", "token",
)


def form_score(form: dict) -> int:
    """Rank a ``forms.json`` entry: higher = test this one first.

    File uploads outrank everything (RCE / path traversal / content-type
    bypass all start there), then POST bodies (CSRF, mass assignment),
    then forms carrying auth/identity fields. A GET form with no inputs is
    a search box and scores 0.

    Quantity deliberately counts for little: a form with twenty framework
    hidden fields is not twenty times more interesting than a login form
    with two real ones.
    """
    if not isinstance(form, dict):
        return 0
    score = 0
    if "multipart" in str(form.get("enctype", "")).lower():
        score += 100
    if str(form.get("method", "")).upper() == "POST":
        score += 50

    params = form.get("parameters")
    if not isinstance(params, list):
        return score

    names = [str(p).strip().lower() for p in params if str(p).strip()]
    real = [n for n in names
            if n not in _FORM_NOISE_PARAMS and n not in _FORM_CSRF_PARAMS]
    # Capped low on purpose — see the docstring.
    score += min(len(real), 8)
    if any(n in _FORM_CSRF_PARAMS for n in names):
        score += 3          # a CSRF token means the form really does something

    hits = 0
    for n in real:
        parts = set(re.split(r"[^a-z0-9]+", n)) | {n}
        if parts & set(_FORM_HOT_KEYWORDS):
            hits += 1
    score += min(hits, 6) * 8
    return score


def rank_forms(forms: list[dict]) -> list[dict]:
    """Sort forms by :func:`form_score`, highest first (stable on ties)."""
    return sorted(
        (f for f in forms if isinstance(f, dict)),
        key=lambda f: -form_score(f),
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
    ("ffuf",       ["ffuf", "-V"]),
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
    xlsx: bool = False            # also render report/final_report.xlsx


class ReportBuilder:
    # Descending, with nuclei's ``unknown`` (template declares no severity)
    # last. Every per-severity table/breakdown iterates this list, so a
    # severity missing here is a finding that never reaches the report.
    SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

    # Every file the report must reference. ``kind`` drives the empty-state
    # label: ``"raw"`` / ``"processed"`` / ``"findings"`` / ``"logs"``.
    # Paths follow the v2 layout: raw outputs are grouped per stage
    # (``raw/<stage>/...``) and findings are grouped per kind
    # (``findings/<kind>/nuclei.{json,txt}``).
    # ``(rel_path, kind, label)`` — cả ba đều là str. Annotation cũ ghi
    # ``Path`` cho phần tử thứ ba, nhưng nó là nhãn mô tả cho báo cáo
    # (xem vòng lặp ở ``collect()``), không phải đường dẫn. ruff không
    # type-check nên chỗ này lọt lưới cho tới khi pyright soi ra.
    OUTPUT_FILES: list[tuple[str, str, str]] = [
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
        ("raw/dirsearch/targets.txt",          "raw",  "host đã chọn để fuzz (sau dedup)"),
        # raw/ffuf/ (plus one <host>.json report per fuzzed target)
        ("raw/ffuf/ffuf_raw.txt",             "raw",  "ffuf hits (status + length + url)"),
        ("raw/ffuf/merged_wordlists.txt",     "raw",  "ffuf merged wordlists (deduped)"),
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
        ("processed/alive_table.txt",    "processed", "httpx table (status|length|ctype|url)"),
        ("processed/crawler_urls.txt",   "processed", "crawler union"),
        ("processed/dirsearch_urls.txt", "processed", "dirsearch URL list"),
        ("processed/ffuf_urls.txt",      "processed", "ffuf URL list"),
        ("processed/fuzz_recurse_urls.txt", "processed", "hits under discovered dirs"),
        ("processed/waymore_urls.txt",   "processed", "waymore URL list"),
        ("processed/all_urls.txt",       "processed", "merged normalised URLs"),
        ("processed/js_urls.txt",        "processed", "JS URLs (final)"),
        ("processed/dynamic_urls.txt",   "processed", "dynamic URLs only"),
        ("processed/xnlinkfinder_endpoints.txt","processed","xnLinkFinder endpoints (regex)"),
        ("processed/xnlinkfinder_urls.txt","processed","xnLinkFinder URLs (regex)"),
        ("processed/jsluice_endpoints.txt","processed","jsluice endpoints (AST)"),
        ("processed/jsluice_urls.txt",    "processed", "jsluice URLs (AST)"),
        ("processed/jsluice_params.json", "processed", "jsluice params (url/method/query/body)"),
        ("processed/jsluice_js_detail.json","processed","JS files jsluice fetched (status/length/content-type)"),
        ("processed/jsluice_js_table.txt","processed", "same, as a status|length|content-type table"),
        ("processed/jsluice_method_check.json","processed","JS endpoints re-probed with their recorded method (status/length/type/body preview vs. GET)"),
        ("processed/jsluice_method_check_table.txt","processed", "same, as a method|status|length|content-type|GET-status table"),
        ("processed/alive_urls.txt",     "processed", "httpx URL check (final)"),
        ("processed/alive_urls_detail.json","processed","httpx URL check detail"),
        ("processed/alive_urls_table.txt","processed","httpx URL table (status|length|ctype|url)"),
        ("processed/screenshots_index.json","processed","host screenshots (url/title/screenshot path)"),
        ("processed/arjun_params.txt",   "processed", "Arjun raw output"),
        ("processed/parameterized_urls.txt","processed","parameterized URLs"),
        ("processed/forms.json",         "processed", "forms/inputs from crawl (POST/upload/login surface)"),
        ("processed/apidocs_urls.txt",   "processed", "endpoints from OpenAPI/Swagger specs"),
        ("processed/apidocs_params.txt", "processed", "spec-declared param URLs"),
        ("processed/misconfig_urls.txt", "processed", "server/microservice misconfig hit URLs (deep-tier hosts)"),
        # findings/<kind>/
        ("findings/default/nuclei.txt",  "findings",  "nuclei default matched URLs"),
        ("findings/default/nuclei.json", "findings",  "nuclei default findings"),
        ("findings/jsluice_secrets.json","findings",  "secrets extracted from JS"),
        ("findings/api_docs.json",       "findings",  "API docs found (specs / UIs / OSINT)"),
        ("findings/misconfig_probe.json","findings",  "server/microservice misconfig hits (deep-tier hosts)"),
        ("findings/graphql_schema.json", "findings",  "GraphQL introspection results"),
        ("findings/cors.json",           "findings",  "CORS misconfiguration probe results"),
        ("findings/buckets.json",        "findings",  "cloud storage bucket enumeration results"),
        ("findings/git_dump.json",       "findings",  ".git exposure dump summary"),
        # responses/ (ffuf/dirsearch body previews — no full bodies stored)
        ("responses/index.md",           "responses", "ffuf/dirsearch response previews (status/size/short body snippet)"),
        ("responses/preview.json",       "responses", "response previews (machine-readable)"),
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
        findings = i.output_dir / "findings"

        # file inventory — every referenced file with presence flag.
        # ``processed/`` entries are written here as flat paths for
        # readability; layout.path decides which group subfolder they
        # actually live in (and falls back to the flat path on an output
        # tree from before the split), so ``rel`` is recomputed from what
        # was resolved rather than trusted as written.
        file_inventory = []
        for rel, kind, label in self.OUTPUT_FILES:
            if kind == "processed":
                abs_path = layout.path(i.output_dir, Path(rel).name)
                rel = str(abs_path.relative_to(i.output_dir))
            else:
                abs_path = i.output_dir / rel
            file_inventory.append({
                "rel": rel, "kind": kind, "label": label,
                "exists": abs_path.exists(),
                "size": abs_path.stat().st_size if abs_path.exists() else 0,
                "rel_link": rel_link(self.html_path, abs_path),
            })

        # counts
        counts = {
            "subdomains":        count_lines(layout.path(self.inputs.output_dir, "subdomains.txt")),
            "resolved":          count_lines(layout.path(self.inputs.output_dir, "resolved.txt")),
            "alive_hosts":       count_lines(layout.path(self.inputs.output_dir, "alive.txt")),
            "all_urls":          count_lines(layout.path(self.inputs.output_dir, "all_urls.txt")),
            "js_urls":           count_lines(layout.path(self.inputs.output_dir, "js_urls.txt")),
            "dynamic_urls":      count_lines(layout.path(self.inputs.output_dir, "dynamic_urls.txt")),
            "alive_urls":        count_lines(layout.path(self.inputs.output_dir, "alive_urls.txt")),
            "parameterized_urls":count_lines(layout.path(self.inputs.output_dir, "parameterized_urls.txt")),
            "arjun_params":      count_lines(layout.path(self.inputs.output_dir, "arjun_params.txt")),
            "crawler_urls":      count_lines(layout.path(self.inputs.output_dir, "crawler_urls.txt")),
            "dirsearch_urls":    count_lines(layout.path(self.inputs.output_dir, "dirsearch_urls.txt")),
            "ffuf_urls":         count_lines(layout.path(self.inputs.output_dir, "ffuf_urls.txt")),
            "fuzz_recurse_urls": count_lines(layout.path(self.inputs.output_dir, "fuzz_recurse_urls.txt")),
            "waymore_urls":      count_lines(layout.path(self.inputs.output_dir, "waymore_urls.txt")),
            "xnlinkfinder_endpoints": count_lines(layout.path(self.inputs.output_dir, "xnlinkfinder_endpoints.txt")),
            "xnlinkfinder_urls": count_lines(layout.path(self.inputs.output_dir, "xnlinkfinder_urls.txt")),
            "jsluice_endpoints": count_lines(layout.path(self.inputs.output_dir, "jsluice_endpoints.txt")),
            "jsluice_urls":      count_lines(layout.path(self.inputs.output_dir, "jsluice_urls.txt")),
        }

        # Arjun's OWN record of how many dynamic URLs it actually scanned —
        # counts["dynamic_urls"] above is the full candidate list, but
        # arjun.max_urls (default 200) caps how many of those it ever
        # touches. Without this, "Dynamic URLs scanned: 5,000" next to
        # "Arjun params: 12" reads as "we checked all 5,000 and found 12",
        # when the true story could be "we checked 200 and never got to
        # the other 4,800".
        _arjun_extra = stage_extra(i.stage_results, "arjun")
        counts["arjun_input_urls"] = _arjun_extra.get("input_urls")
        counts["arjun_scanned_urls"] = _arjun_extra.get("scanned_urls")

        # dns / assets
        dns_records = load_json_safe(layout.path(self.inputs.output_dir, "resolved_detail.json")) or []
        if not isinstance(dns_records, list):
            dns_records = []
        assets = parse_httpx_jsonl(layout.path(self.inputs.output_dir, "alive_detail.json"))
        # alive_detail.json might be the JSON array form too — handle either
        if not assets:
            data = load_json_safe(layout.path(self.inputs.output_dir, "alive_detail.json"))
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

        # discovered-URL surface — status/content-type breakdown of the full
        # probed URL list (processed/alive_urls_detail.json), the human summary
        # of the new processed/alive_urls_table.txt.
        url_detail = parse_httpx_jsonl(layout.path(self.inputs.output_dir, "alive_urls_detail.json"))
        if not url_detail:
            _d = load_json_safe(layout.path(self.inputs.output_dir, "alive_urls_detail.json"))
            if isinstance(_d, list):
                url_detail = _d
        url_surface = summarize_url_surface(url_detail)

        # host-fuzzing coverage — how much of the alive-host surface
        # dirsearch/ffuf actually touched vs. deduped/WAF-skipped/capped
        # away. See fuzz_coverage()'s docstring for why this needs its own
        # join instead of being inferred from the URL counts.
        fuzz_cov = {
            "dirsearch": fuzz_coverage(i.stage_results, "dirsearch"),
            "ffuf": fuzz_coverage(i.stage_results, "ffuf"),
        }
        # post-fuzz behavioural screen — see fuzz_screen()'s docstring for
        # why this is a second, unrelated number from fuzz_cov above.
        fuzz_scr = {
            "dirsearch": fuzz_screen(i.stage_results, "dirsearch"),
            "ffuf": fuzz_screen(i.stage_results, "ffuf"),
        }

        # nuclei — v2 layout puts the scans under findings/<kind>/
        n_def_findings, n_def_sev = parse_nuclei_summary(
            findings / "default" / "nuclei.json"
        )
        counts["nuclei_default_findings"] = len(n_def_findings)

        # GraphQL introspection — findings/graphql_schema.json
        gql = load_json_safe(findings / "graphql_schema.json") or {}
        graphql_targets = gql.get("targets", []) if isinstance(gql, dict) else []
        if not isinstance(graphql_targets, list):
            graphql_targets = []
        counts["graphql_introspectable"] = len(graphql_targets)
        counts["graphql_mutations_exposed"] = sum(
            len(t.get("mutation_fields") or []) for t in graphql_targets
            if isinstance(t, dict)
        )

        # CORS misconfiguration probe — findings/cors.json
        cors_data = load_json_safe(findings / "cors.json") or {}
        cors_findings = cors_data.get("findings", []) if isinstance(cors_data, dict) else []
        if not isinstance(cors_findings, list):
            cors_findings = []
        counts["cors_findings"] = len(cors_findings)
        counts["cors_critical"] = sum(
            1 for f in cors_findings
            if isinstance(f, dict) and f.get("severity") == "critical"
        )

        # Cloud storage bucket enumeration — findings/buckets.json
        buckets_data = load_json_safe(findings / "buckets.json") or {}
        bucket_findings = buckets_data.get("findings", []) if isinstance(buckets_data, dict) else []
        if not isinstance(bucket_findings, list):
            bucket_findings = []
        azure_refs = buckets_data.get("azure_references", []) if isinstance(buckets_data, dict) else []
        counts["buckets_findings"] = len(bucket_findings)
        counts["buckets_public"] = sum(
            1 for f in bucket_findings
            if isinstance(f, dict) and f.get("state") == "public-listing"
        )
        counts["azure_blob_references"] = len(azure_refs) if isinstance(azure_refs, list) else 0

        # .git exposure dump — findings/git_dump.json
        gitdump_data = load_json_safe(findings / "git_dump.json") or {}
        gitdump_hosts = gitdump_data.get("hosts", []) if isinstance(gitdump_data, dict) else []
        if not isinstance(gitdump_hosts, list):
            gitdump_hosts = []
        counts["gitdump_hosts"] = len(gitdump_hosts)
        counts["gitdump_files_recovered"] = sum(
            (h.get("files_recovered") or 0) for h in gitdump_hosts if isinstance(h, dict)
        )

        # jsluice secrets — API keys/tokens extracted from JS (findings/jsluice_secrets.json)
        jsl = load_json_safe(findings / "jsluice_secrets.json") or {}
        jsluice_secrets = jsl.get("findings", []) if isinstance(jsl, dict) else []
        if not isinstance(jsluice_secrets, list):
            jsluice_secrets = []
        jsluice_sev = jsl.get("severity_count", {}) if isinstance(jsl, dict) else {}
        counts["jsluice_secrets"] = len(jsluice_secrets)

        # forms/inputs mined from the crawl (processed/forms.json). The
        # densest attack surface in the run — POST bodies and file uploads
        # are where CSRF / mass-assignment / injection actually live — so
        # the list itself is carried through, not just its length.
        forms_data = load_json_safe(layout.path(self.inputs.output_dir, "forms.json")) or {}
        forms_list = forms_data.get("forms", []) if isinstance(forms_data, dict) else []
        if not isinstance(forms_list, list):
            forms_list = []
        forms_list = rank_forms(forms_list)
        counts["forms"] = len(forms_list)
        counts["forms_post"] = sum(
            1 for f in forms_list
            if isinstance(f, dict) and str(f.get("method", "")).upper() == "POST"
        )
        counts["forms_upload"] = sum(
            1 for f in forms_list
            if isinstance(f, dict) and "multipart" in str(f.get("enctype", "")).lower()
        )

        # API documentation — specs, docs UIs, and external OSINT hits.
        api_docs = load_json_safe(findings / "api_docs.json") or {}
        if not isinstance(api_docs, dict):
            api_docs = {}
        api_specs = api_docs.get("specs") or []
        api_specs = api_specs if isinstance(api_specs, list) else []
        counts["api_specs"] = len(api_specs)
        counts["api_documented_paths"] = sum(
            int(s.get("paths", 0) or 0) for s in api_specs if isinstance(s, dict)
        )
        counts["api_docs_ui"] = len(api_docs.get("ui") or [])
        counts["api_osint"] = len(api_docs.get("osint") or [])
        counts["apidocs_urls"] = count_lines(layout.path(self.inputs.output_dir, "apidocs_urls.txt"))

        # Server/microservice misconfig probe — tier "deep" hosts only.
        misconfig_probe = load_json_safe(findings / "misconfig_probe.json") or {}
        if not isinstance(misconfig_probe, dict):
            misconfig_probe = {}
        misconfig_findings_list = misconfig_probe.get("findings") or []
        misconfig_findings_list = (
            misconfig_findings_list if isinstance(misconfig_findings_list, list) else []
        )
        counts["misconfig_hits"] = len(misconfig_findings_list)
        counts["misconfig_hosts_probed"] = int(misconfig_probe.get("hosts_probed", 0) or 0)

        # jsluice params — {url, method, queryParams, bodyParams} pulled out
        # of JS by AST. The ONLY source of POST/JSON body params in the whole
        # run: arjun is GET-only and only sees what looks dynamic in the URL.
        jsluice_params = load_json_safe(layout.path(self.inputs.output_dir, "jsluice_params.json")) or []
        if not isinstance(jsluice_params, list):
            jsluice_params = []
        counts["jsluice_params"] = len(jsluice_params)

        # jsluice method check — endpoints re-probed with the HTTP verb the
        # JS source itself used (not a blind GET), so a POST-only/DELETE-only
        # route that a GET-only probe reads as 404/405 shows up alive, with
        # a body preview to triage it by eye.
        jsluice_method_check = load_json_safe(
            layout.path(self.inputs.output_dir, "jsluice_method_check.json")) or []
        if not isinstance(jsluice_method_check, list):
            jsluice_method_check = []
        counts["jsluice_method_check"] = len(jsluice_method_check)
        counts["jsluice_method_bypass"] = sum(
            1 for r in jsluice_method_check
            if isinstance(r, dict) and is_method_bypass(r))

        # jsluice JS fetch detail — status/length/content-type for every JS
        # file jsluice attempted (incl. 4xx/5xx and recursive rounds), so a
        # 404'd chunk or WAF-blocked bundle shows up instead of vanishing.
        jsluice_js_detail = load_json_safe(layout.path(self.inputs.output_dir, "jsluice_js_detail.json")) or []
        if not isinstance(jsluice_js_detail, list):
            jsluice_js_detail = []
        jsluice_js_surface = summarize_url_surface(jsluice_js_detail)
        counts["jsluice_js_fetched_total"] = jsluice_js_surface["total"]

        # jsluice recursion — how much of the above came from chasing
        # JS-referenced-JS (webpack chunks / lazy bundles) rather than the
        # original js_urls.txt crawl. Pulled from the stage's own result
        # dict (modules/jsluice.py::scan extra=), not re-derived from files.
        jsluice_stage = next(
            (r for r in i.stage_results if r.get("stage") == "jsluice"), {},
        )
        jsluice_extra = jsluice_stage.get("extra") or {}
        counts["jsluice_js_fetched"] = jsluice_extra.get("js_fetched", 0)
        counts["jsluice_js_recursed_rounds"] = jsluice_extra.get("js_recursed_rounds", 0)
        counts["jsluice_js_recursed_fetched"] = jsluice_extra.get("js_recursed_fetched", 0)

        # captured responses — full ffuf/dirsearch hit bodies (responses/)
        resp = load_json_safe(i.output_dir / "responses" / "preview.json") or {}
        resp_previews = resp.get("previews", []) if isinstance(resp, dict) else []
        if not isinstance(resp_previews, list):
            resp_previews = []
        counts["responses_captured"] = len(resp_previews)

        # high-value targets — scan the union of alive URLs + parameterized
        candidate_urls: list[str] = []
        candidate_urls.extend(read_lines(layout.path(self.inputs.output_dir, "alive_urls.txt")))
        candidate_urls.extend(read_lines(layout.path(self.inputs.output_dir, "dynamic_urls.txt")))
        candidate_urls.extend(read_lines(layout.path(self.inputs.output_dir, "parameterized_urls.txt")))
        # de-dup preserving order
        seen_u: set[str] = set()
        unique_urls: list[str] = []
        for u in candidate_urls:
            if u and u not in seen_u:
                seen_u.add(u)
                unique_urls.append(u)
        # Join the response facts onto each candidate. jsluice_alive is the
        # second source because JS-mined URLs are probed after the main
        # corpus, so they exist only there.
        detail_index = index_detail_by_url(
            url_detail,
            parse_httpx_jsonl(
                layout.path(self.inputs.output_dir, "jsluice_alive_detail.json")),
        )
        # Body snippets from the responses stage, keyed by URL — the
        # "optional" half of the join. Only ffuf/dirsearch hits have one.
        body_snippets = {
            str(p.get("url") or ""): str(p.get("snippet") or "")
            for p in resp_previews
            if isinstance(p, dict) and p.get("url") and p.get("snippet")
        }

        high_value = []
        for u in unique_urls:
            row = detail_index.get(u)
            labels = classify_url(u)
            # Autoindex pages are a response-body signature, not a URL
            # pattern — HIGH_VALUE_PATTERNS can never catch a "/uploads/"
            # that happens to have directory listing on, so this is checked
            # separately and folded in regardless of what the URL matched.
            if is_directory_listing(row, body_snippets.get(u, "")):
                if "directory listing" not in labels:
                    labels = labels + ["directory listing"]
            if labels:
                high_value.append(enrich_target(u, labels, row))

        # Now that the response facts are attached, the same behavioural
        # screen the fuzz stages use applies here too — and it is needed.
        # Measured on the discover.com tree: 11,751 "high-value targets", of
        # which 10,576 were one WAF 403 wearing 10,576 different paths. The
        # URL classifier cannot see that; the response shape can.
        hv_before = len(high_value)
        kept_hv, hv_verdicts = behavior.screen_by_host([
            behavior.Behavior(
                url=h["url"], status=h["status"] or 0,
                length=h["content_length"] if h["content_length"] is not None
                else behavior.UNKNOWN,
                content_type=h["content_type"], location=h["location"],
            )
            for h in high_value if h["probed"]
        ])
        keep_urls = {b.url for b in kept_hv}
        # Unprobed entries are kept: no evidence is not evidence of noise.
        high_value = [h for h in high_value
                      if not h["probed"] or h["url"] in keep_urls]

        # 404 means the path doesn't exist; 429 means the probe got
        # rate-limited, not that anything was found. Neither is a lead, so
        # they don't belong in a "high value" list — drop them outright
        # rather than just sinking them in the sort.
        high_value = [h for h in high_value if h.get("status") not in (404, 429)]

        # A cluster below ``min_cluster`` survives the screen on purpose —
        # wiping out a small host would cost more than it saves. But the
        # residue lands at the TOP of this section, because a soft-200
        # catch-all makes every path look like a reachable admin panel.
        # Measured: archertprm.discover.com left 21 entries all answering
        # ``200, 92 bytes``, and they outranked every genuine finding.
        # So: count identical shapes and let the sort sink them, rather than
        # dropping rows a tester might want to see. Nothing is hidden.
        shape_counts: dict[tuple, int] = {}
        for h in high_value:
            h["shape_key"] = _hv_shape_key(h)
            shape_counts[h["shape_key"]] = shape_counts.get(h["shape_key"], 0) + 1
        for h in high_value:
            h["shape_count"] = shape_counts[h.pop("shape_key")]

        high_value.sort(key=target_sort_key)
        counts["high_value_collapsed"] = hv_before - len(high_value)
        counts["high_value_blanket_hosts"] = sorted(
            h for h, v in hv_verdicts.items() if v.blanket)

        # endpoint existence — classify every ffuf/dirsearch hit by response
        # BEHAVIOUR (baseline shape + body-preview signal families + status
        # family) instead of status code alone. See endpoint_existence()'s
        # docstring; no new requests, everything read here is already on disk.
        _hit_urls: dict[str, set[str]] = {}
        for u in read_lines(layout.path(self.inputs.output_dir, "ffuf_urls.txt")):
            _hit_urls.setdefault(u, set()).add("ffuf")
        for u in read_lines(layout.path(self.inputs.output_dir, "dirsearch_urls.txt")):
            _hit_urls.setdefault(u, set()).add("dirsearch")
        _baselines_by_host = baseline.load_from_raw(self.inputs.output_dir)
        existence_results = endpoint_existence(
            _hit_urls, detail_index, body_snippets, _baselines_by_host)

        # interesting API paths from JS endpoints
        api_paths = extract_interesting_api_paths(
            list(read_lines(layout.path(self.inputs.output_dir, "xnlinkfinder_urls.txt")))
            + list(read_lines(layout.path(self.inputs.output_dir, "jsluice_urls.txt")))
            + list(read_lines(layout.path(self.inputs.output_dir, "jsluice_endpoints.txt")))
            + list(read_lines(layout.path(self.inputs.output_dir, "js_urls.txt")))
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
            "url_surface": url_surface,
            "fuzz_coverage": fuzz_cov,
            "fuzz_screen": fuzz_scr,
            "endpoint_existence": {
                "results": existence_results,
                "counts": existence_counts(existence_results),
            },
            "nuclei": {
                "default": {
                    "findings": n_def_findings,
                    "severity_count": n_def_sev,
                },
            },
            "graphql_targets": graphql_targets,
            "cors_findings": cors_findings,
            "buckets": {"findings": bucket_findings, "azure_references": azure_refs},
            "gitdump_hosts": gitdump_hosts,
            "jsluice_secrets": {
                "findings": jsluice_secrets,
                "severity_count": jsluice_sev,
            },
            "jsluice_params": jsluice_params,
            "jsluice_method_check": jsluice_method_check,
            "jsluice_js_detail": jsluice_js_detail,
            "jsluice_js_surface": jsluice_js_surface,
            "api_docs": api_docs,
            "misconfig_probe": misconfig_probe,
            "forms": forms_list,
            "parameterized_sample": list(
                read_lines(layout.path(self.inputs.output_dir, "parameterized_urls.txt"))
            ),
            "high_value_targets": high_value,
            # Shared join for every section that lists a URL/endpoint/JS URL.
            "url_detail_index": detail_index,
            "body_snippets": body_snippets,
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
            "  .badge-unknown  { background: #757575; }\n"
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
            # Status colouring for section 9 — the column a tester scans
            # first, so it must read at a glance rather than on inspection.
            "  .st-ok    { color: #388e3c; font-weight: 600; }\n"
            "  .st-gated { color: #e65100; font-weight: 600; }\n"
            "  .st-redir { color: #1565c0; }\n"
            "  .st-dead  { color: #999; }\n"
            "  .st-none  { color: #bbb; }\n"
            "  .chip { display: inline-block; padding: 2px 8px; margin: 2px; "
            "border-radius: 10px; background: #eef1f5; font-size: 12px; }\n"
            "  pre { background: #1e1e1e; color: #f5f5f5; padding: 12px; border-"
            "radius: 4px; overflow-x: auto; font-size: 12px; }\n"
            "</style>"
        )

        # Endpoint extraction (JS analysis) and nuclei findings sit right
        # after the KPIs — they are the two sections a reader wants first,
        # not buried after DNS/content-discovery bookkeeping.
        body = []
        body.append(self._html_head(data))
        body.append(self._html_kpis(data))
        body.append(self._html_section_coverage(data))
        body.append(self._html_section_js(data))
        body.append(self._html_section_secrets(data))
        body.append(self._html_section_method_check(data))
        body.append(self._html_section_nuclei(data))
        body.append(self._html_section_graphql(data))
        body.append(self._html_section_cors(data))
        body.append(self._html_section_buckets(data))
        body.append(self._html_section_gitdump(data))
        body.append(self._html_section_assets(data))
        body.append(self._html_section_dns(data))
        body.append(self._html_section_content_discovery(data))
        body.append(self._html_section_params(data))
        body.append(self._html_section_forms(data))
        body.append(self._html_section_apidocs(data))
        body.append(self._html_section_misconfig(data))
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
        # Shared response-facts join. Every section listing a URL, endpoint
        # or JS URL renders ST/Length/Type from this, so a reader never has
        # to guess whether a path the classifier liked actually exists.
        _idx = data.get("url_detail_index") or {}
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
            ("Forms",            "forms"),
            ("Nuclei default",   "nuclei_default_findings"),
        ]:
            out.append(f"- **{label}**: `{c.get(key, 0)}`")
        out.append("")

        # Endpoint extraction (JS analysis) and nuclei findings come right
        # after the KPIs — the two sections a reader wants first, not
        # buried after DNS/content-discovery bookkeeping.
        out.append("## 3. JavaScript Analysis (Endpoint Extraction)\n")
        out.append(f"- JS files (final): `{c.get('js_urls', 0)}`")
        out.append(f"- xnLinkFinder endpoints (regex): `{c.get('xnlinkfinder_endpoints', 0)}`")
        out.append(f"- xnLinkFinder URLs (regex):      `{c.get('xnlinkfinder_urls', 0)}`")
        out.append(f"- jsluice endpoints (AST):        `{c.get('jsluice_endpoints', 0)}`")
        out.append(f"- jsluice URLs (AST):             `{c.get('jsluice_urls', 0)}`")
        out.append(f"- jsluice param records (AST):    `{c.get('jsluice_params', 0)}`")
        if c.get("jsluice_js_recursed_rounds"):
            out.append(
                f"  - ↳ recursed into JS-referenced-JS (webpack chunks/lazy "
                f"bundles): `{c.get('jsluice_js_recursed_rounds', 0)}` round(s), "
                f"`{c.get('jsluice_js_recursed_fetched', 0)}` extra file(s) "
                f"fetched (of `{c.get('jsluice_js_fetched', 0)}` total)"
            )
        out.append(f"- Interesting API paths:          `{len(data['interesting_api_paths'])}`")
        out.append("- Output files:")
        out.append("  - [`../processed/js_urls.txt`](../processed/js_urls.txt)")
        out.append("  - [`../processed/xnlinkfinder_endpoints.txt`](../processed/xnlinkfinder_endpoints.txt)")
        out.append("  - [`../processed/xnlinkfinder_urls.txt`](../processed/xnlinkfinder_urls.txt)")
        out.append("  - [`../processed/jsluice_endpoints.txt`](../processed/jsluice_endpoints.txt)")
        out.append("  - [`../processed/jsluice_urls.txt`](../processed/jsluice_urls.txt)")
        out.append("  - [`../processed/jsluice_params.json`](../processed/jsluice_params.json)")

        jsurf = data.get("jsluice_js_surface") or {}
        if jsurf.get("total"):
            out.append(f"\n**jsluice JS fetch surface** — {jsurf['total']} JS file(s) "
                       "attempted, status/length/content-type "
                       "([`../processed/jsluice_js_table.txt`]"
                       "(../processed/jsluice_js_table.txt)):\n")
            jbs = " · ".join(f"`{k}`: {v}"
                             for k, v in jsurf["by_status"].items())
            out.append(f"- By status: {jbs}")

        _jp = [r for r in (data.get("jsluice_params") or []) if isinstance(r, dict)]
        if _jp:
            _nb = sum(1 for r in _jp if r.get("bodyParams"))
            out.append(f"\n<details><summary>jsluice params — {len(_jp)} record(s), "
                       f"{_nb} with body params</summary>\n")
            out.append("Body params never reach arjun (GET-only), so these are "
                       "unique to this table.\n")
            out.append("| {h} | Method | URL | Query params | Body params |"
                       .format(h=MD_FACTS_HEAD))
            out.append("|{s}|--------|-----|--------------|-------------|"
                       .format(s=MD_FACTS_SEP))
            for r in sorted(_jp, key=lambda r: (-len(r.get("bodyParams") or []),
                                                -len(r.get("queryParams") or []))):
                _q = ", ".join(str(x) for x in (r.get("queryParams") or []))
                _b = ", ".join(str(x) for x in (r.get("bodyParams") or []))
                _u = str(r.get("url", ""))
                out.append(
                    f"| {md_facts_cells(_idx, _u)} "
                    f"| `{escape(str(r.get('method') or '').upper() or '-')}` "
                    f"| `{escape(_u)}` "
                    f"| `{escape(_q)}` | `{escape(_b)}` |"
                )
            out.append("\n</details>\n")

        if data["interesting_api_paths"]:
            out.append("\n<details><summary>Interesting API paths</summary>\n")
            out.append(f"| {MD_FACTS_HEAD} | Path |")
            out.append(f"|{MD_FACTS_SEP}|------|")
            for p in data["interesting_api_paths"]:
                out.append(f"| {md_facts_cells(_idx, p)} | `{escape(p)}` |")
            out.append("\n</details>\n")

        # JS secrets (jsluice)
        out.append("## 3.1 JavaScript Secrets\n")
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
            for s in _ordered:
                raw = s.get("data")
                val = (", ".join(f"{k}={v}" for k, v in raw.items())
                       if isinstance(raw, dict) else str(raw or ""))
                out.append(
                    f"| {(s.get('severity') or 'info').upper()} "
                    f"| `{escape(str(s.get('kind', '?')))}` "
                    f"| `{escape(val)}` "
                    f"| `{escape(str(s.get('url', '')))}` |"
                )
            out.append("")

        # HTTP method check — endpoints re-probed with the method jsluice
        # observed in the JS source, not a blind GET.
        out.append("## 3.2 HTTP Method Check (verb tampering)\n")
        _mc = [r for r in (data.get("jsluice_method_check") or []) if isinstance(r, dict)]
        if not _mc:
            out.append("_No method-tagged endpoints to re-test "
                       "(jsluice found no non-GET method in the JS, or the "
                       "stage was skipped)._\n")
        else:
            _bypass = sum(1 for r in _mc if is_method_bypass(r))
            out.append(
                f"Total re-tested: `{len(_mc)}` · answer differently to "
                f"their real method than to GET: `{_bypass}`.\n")
            out.append("Endpoints below were re-requested with the HTTP "
                       "method jsluice found in the JS source (`fetch(url, "
                       "{method: ...})`), not a blind GET — a route the GET "
                       "probe reported as 404/403/405 can still be live.\n")
            out.append("| Method | ST | Length | Type | GET-ST | Body preview | URL |")
            out.append("|--------|----|--------|------|--------|--------------|-----|")
            for r in _mc:
                out.append(
                    f"| `{escape(str(r.get('method','')))}` "
                    f"| {_fmt_status(r.get('status'))} "
                    f"| {_fmt_len(r.get('content_length'))} "
                    f"| {escape(str(r.get('content_type') or '-'))} "
                    f"| {_fmt_status(r.get('get_status'))} "
                    f"| {escape(str(r.get('body_preview') or '-'))} "
                    f"| `{escape(str(r.get('url','')))}` |"
                )
            out.append("")

        # Nuclei — moved up next to endpoint extraction, see section 3.
        out.append("## 4. Nuclei Findings\n")
        blk = data["nuclei"]["default"]
        out.append("### Default scan (hosts)\n")
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
                for f in items:
                    info = f.get("info") or {}
                    out.append(
                        f"| {sev.upper()} | `{escape(f.get('template-id','?'))}` "
                        f"| {escape(info.get('name','?'))} "
                        f"| `{escape(f.get('matched-at') or f.get('host','?'))}` |"
                    )
                out.append("")
            out.append("</details>\n")

        # GraphQL introspection
        out.append("## 4.1 GraphQL Introspection\n")
        _gql = data.get("graphql_targets") or []
        if not _gql:
            out.append("_No endpoint answered a live introspection query._\n")
        else:
            _tm = sum(len(t.get("mutation_fields") or []) for t in _gql)
            out.append(f"Introspection ON at `{len(_gql)}` endpoint(s) — "
                       f"`{_tm}` mutation(s) exposed.\n")
            out.append("| URL | Types | Query fields | Mutation fields |")
            out.append("|-----|------:|--------------|-----------------|")
            for t in _gql:
                qf = ", ".join(t.get("query_fields") or []) or "-"
                mf = ", ".join(t.get("mutation_fields") or []) or "-"
                out.append(
                    f"| `{escape(str(t.get('url','')))}` "
                    f"| `{int(t.get('type_count', 0))}` "
                    f"| `{escape(qf)}` | `{escape(mf)}` |"
                )
            out.append("")

        # CORS misconfiguration
        out.append("## 4.2 CORS Misconfiguration\n")
        _cors = data.get("cors_findings") or []
        if not _cors:
            out.append("_No host reflected the test Origin with credentials "
                       "allowed._\n")
        else:
            _crit = sum(1 for f in _cors if f.get("severity") == "critical")
            out.append(f"`{len(_cors)}` host(s) reflect an arbitrary Origin — "
                       f"`{_crit}` also allow credentials.\n")
            out.append("| Severity | URL | Allow-Origin | Allow-Credentials | Note |")
            out.append("|----------|-----|--------------|--------------------|------|")
            for f in _cors:
                out.append(
                    f"| {(f.get('severity') or '').upper()} "
                    f"| `{escape(str(f.get('url','')))}` "
                    f"| `{escape(str(f.get('acao','')))}` "
                    f"| {'yes' if f.get('acac') else 'no'} "
                    f"| {escape(str(f.get('note','')))} |"
                )
            out.append("")

        # Cloud storage buckets
        out.append("## 4.3 Cloud Storage Buckets\n")
        _bk = data.get("buckets") or {}
        _bk_findings = _bk.get("findings") or []
        _bk_azure = _bk.get("azure_references") or []
        if not _bk_findings and not _bk_azure:
            out.append("_No S3/GCS bucket confirmed (enumeration is opt-in "
                       "— `buckets.enabled` in config.yml — and off by "
                       "default), and no Azure Blob reference observed._\n")
        else:
            if _bk_findings:
                _pub = sum(1 for f in _bk_findings if f.get("state") == "public-listing")
                out.append(f"`{len(_bk_findings)}` bucket(s) confirmed — "
                           f"`{_pub}` publicly listable.\n")
                out.append("| Severity | Provider | Bucket | State | URL |")
                out.append("|----------|----------|--------|-------|-----|")
                for f in _bk_findings:
                    out.append(
                        f"| {(f.get('severity') or '').upper()} "
                        f"| `{escape(str(f.get('provider','')))}` "
                        f"| `{escape(str(f.get('bucket','')))}` "
                        f"| {escape(str(f.get('state','')))} "
                        f"| `{escape(str(f.get('url','')))}` |"
                    )
                out.append("")
            if _bk_azure:
                out.append(f"Azure Blob account reference(s) found (recorded, "
                           f"not probed — needs a container name to check "
                           f"listing): {', '.join(f'`{escape(a)}`' for a in _bk_azure)}\n")

        # Git exposure dump
        out.append("## 4.4 Git Exposure Dump\n")
        _gd = data.get("gitdump_hosts") or []
        if not _gd:
            out.append("_No confirmed .git exposure reconstructed (dumping "
                       "is opt-in — `gitdump.enabled` in config.yml — and "
                       "off by default)._\n")
        else:
            _total = sum(h.get("files_recovered", 0) for h in _gd)
            out.append(f"`{_total}` file(s) reconstructed across "
                       f"`{len(_gd)}` confirmed host(s). Recovery is "
                       "best-effort — a host that ran `git gc` packs its "
                       "loose objects away, so files_recovered may be well "
                       "under files_in_index.\n")
            out.append("| Host | Ref | Recovered / in index | Output dir |")
            out.append("|------|-----|----------------------:|------------|")
            for h in _gd:
                out.append(
                    f"| `{escape(str(h.get('host','')))}` "
                    f"| `{escape(str(h.get('ref') or '-'))}` "
                    f"| {int(h.get('files_recovered', 0))} / "
                    f"{int(h.get('files_in_index', 0))} "
                    f"| `{escape(str(h.get('output_dir','')))}` |"
                )
            out.append("")

        # Asset inventory
        out.append("## 5. Asset Inventory\n")
        if data["assets"]:
            out.append("| URL | Status | Length | Content-Type | Title | Tech |")
            out.append("|-----|-------:|-------:|--------------|-------|------|")
            for a in data["assets"]:
                out.append(
                    f"| `{escape(a.get('url',''))}` | "
                    f"{a.get('status_code','')} | "
                    f"{a.get('content_length','')} | "
                    f"`{escape(str(a.get('content_type','')))}` | "
                    f"{escape(str(a.get('title','')))} | "
                    f"{escape(str(a.get('tech','')))} |"
                )
        else:
            out.append("_Not generated._\n")

        # DNS inventory
        out.append("\n## 6. DNS Inventory\n")
        if data["dns_records"]:
            out.append("| Subdomain | IP | ASN | CNAME |")
            out.append("|-----------|----|-----|-------|")
            for r in data["dns_records"]:
                asn = r.get("asn") or {}
                asn_str = asn.get("asn", "") if isinstance(asn, dict) else str(asn)
                out.append(
                    f"| `{escape(r.get('subdomain',''))}` | "
                    f"`{escape(str(r.get('ip','')))}` | "
                    f"{escape(str(asn_str))} | "
                    f"`{escape(str(r.get('cname','')))}` |"
                )
        else:
            out.append("_Not generated._\n")

        # Content discovery
        out.append("## 7. Content Discovery\n")
        out.append("| Source | Count | Output file |")
        out.append("|--------|------:|-------------|")
        for label, key, rel in [
            ("katana crawl (+urlfinder/gau if on)", "crawler_urls", "../processed/crawler_urls.txt"),
            ("dirsearch",                  "dirsearch_urls", "../processed/dirsearch_urls.txt"),
            ("ffuf",                       "ffuf_urls", "../processed/ffuf_urls.txt"),
            ("fuzz_recurse (under discovered dirs)", "fuzz_recurse_urls", "../processed/fuzz_recurse_urls.txt"),
            ("waymore",                    "waymore_urls", "../processed/waymore_urls.txt"),
        ]:
            out.append(f"| {label} | `{c.get(key,0)}` | [{rel}]({rel}) |")
        out.append("")
        _nr = c.get("responses_captured", 0)
        if _nr:
            out.append(f"**Response previews:** `{_nr}` hit(s) re-requested with "
                       "a short body preview — "
                       "[`../responses/index.md`](../responses/index.md)\n")
        else:
            out.append("**Response previews:** none captured (no ffuf/dirsearch "
                       "hits, or the stage was skipped).\n")

        surf = data.get("url_surface") or {}
        if surf.get("total"):
            out.append(f"**Discovered URL surface** — {surf['total']} probed "
                       "([`../processed/alive_urls_table.txt`]"
                       "(../processed/alive_urls_table.txt)):\n")
            bs = " · ".join(f"`{k}`: {v}"
                            for k, v in surf["by_status"].items())
            out.append(f"- By status: {bs}")
            bt = " · ".join(f"`{escape(k)}`: {v}"
                            for k, v in surf["by_type"].items())
            out.append(f"- By content-type: {bt}")
            out.append(f"- ⭐ APIs (`application/json`): `{surf['apis']}` · "
                       f"Auth-gated (`401/403`): `{surf['auth_gated']}`")
            out.append("")

        _cov = data.get("fuzz_coverage") or {}
        _cov_rows = [(label, _cov[label]) for label in ("dirsearch", "ffuf")
                    if _cov.get(label)]
        if _cov_rows:
            out.append("**Host fuzzing coverage** — alive hosts get deduped "
                       "(identical response = same app), WAF/blanket-response "
                       "hosts get dropped, then ranked and capped. \"Capped\" "
                       "hosts are real, distinct targets never touched — not "
                       "noise correctly filtered out:\n")
            out.append("| Stage | Alive hosts | Deduped | WAF-skipped "
                       "| Blanket-skipped | Fuzzed | Capped |")
            out.append("|-------|------------:|--------:|-------------"
                       "|-----------------:|-------:|-------:|")
            for label, sel in _cov_rows:
                out.append(
                    f"| {label} | {sel.get('input', 0)} | {sel.get('deduped', 0)} "
                    f"| {sel.get('waf_skipped', 0)} | {sel.get('blanket_skipped', 0)} "
                    f"| {sel.get('selected', 0)} | {sel.get('capped', 0)} |"
                )
            out.append("")

        _scr = data.get("fuzz_screen") or {}
        _scr_rows = [(label, _scr[label]) for label in ("dirsearch", "ffuf")
                    if _scr.get(label)]
        if _scr_rows:
            out.append("**Behavioural hit screening** — after fuzzing, every "
                       "hit is fingerprinted by response shape (status + "
                       "content-type + redirect target + words/lines, or "
                       "byte length when a tool reports no word count) and "
                       "any cluster that is both large *and* dominant on a "
                       "host is dropped as one response wearing many paths, "
                       "not distinct findings:\n")
            out.append("| Stage | Raw hits | Kept | Dropped | Blanket hosts |")
            out.append("|-------|---------:|-----:|--------:|---------------|")
            for label, scr in _scr_rows:
                blanket = scr.get("blanket_hosts") or []
                blanket_cell = (", ".join(f"`{escape(h)}`" for h in blanket)
                                if blanket else "—")
                out.append(
                    f"| {label} | {scr.get('raw_hits', 0)} | {scr.get('kept', 0)} "
                    f"| {scr.get('dropped', 0)} | {blanket_cell} |"
                )
            out.append("")

        _ex = data.get("endpoint_existence") or {}
        _ex_results = _ex.get("results") or []
        if _ex_results:
            _ex_counts = _ex.get("counts") or {}
            out.append("**Endpoint existence** — every ffuf/dirsearch hit "
                       "classified by response BEHAVIOUR, not status code "
                       "alone: baseline-shape agreement (does this look "
                       "exactly like a path guaranteed not to exist on this "
                       "host?), body-preview signals (validation/parsing/"
                       "auth/business-logic/framework-specific error text), "
                       "and whether the status itself implies a routed "
                       "request. See `modules/existence.py`:\n")
            out.append("| Verdict | Count |")
            out.append("|---------|------:|")
            for label, key in [("Confirmed Exists", "confirmed"),
                               ("Likely Exists", "likely"),
                               ("Unknown", "unknown"),
                               ("Not Found (matches baseline noise)", "not_found")]:
                out.append(f"| {label} | {_ex_counts.get(key, 0)} |")
            out.append("")
            _actionable = [r for r in _ex_results
                          if r["verdict"] in (existence.CONFIRMED, existence.LIKELY)]
            _actionable.sort(key=lambda r: (r["verdict"] != existence.CONFIRMED, r["url"]))
            _EX_CAP = 200
            if _actionable:
                out.append(f"<details><summary><b>Confirmed / Likely "
                           f"endpoints</b> — {len(_actionable)}"
                           f"{f', showing first {_EX_CAP}' if len(_actionable) > _EX_CAP else ''}"
                           "</summary>\n")
                out.append("| Verdict | Status | Source | URL | Evidence |")
                out.append("|---------|-------:|--------|-----|----------|")
                for r in _actionable[:_EX_CAP]:
                    out.append(
                        f"| {r['verdict']} | {r.get('status') or '—'} "
                        f"| {'+'.join(r['sources'])} | `{escape(r['url'])}` "
                        f"| {escape('; '.join(r['reasons']) or '—')} |"
                    )
                out.append("\n</details>\n")

        # Parameter discovery
        out.append("## 8. Parameter Discovery\n")
        out.append(f"- Dynamic URLs (candidates): `{c.get('dynamic_urls', 0)}`")
        _arjun_scanned = c.get("arjun_scanned_urls")
        _arjun_input = c.get("arjun_input_urls")
        if _arjun_scanned is not None and _arjun_input is not None:
            _capped_n = _arjun_input - _arjun_scanned
            note = (f"— capped by `arjun.max_urls`, {_capped_n} URL(s) never "
                    "checked for hidden params" if _capped_n > 0
                    else "— every candidate URL was scanned")
            out.append(f"- Arjun actually scanned: `{_arjun_scanned} / {_arjun_input}` {note}")
        out.append(f"- Parameters discovered: `{c.get('arjun_params', 0)}`")
        out.append(f"- jsluice param records: `{c.get('jsluice_params', 0)}`")
        out.append(f"- Parameterized URLs:    `{c.get('parameterized_urls', 0)}`")
        out.append("- Output files:")
        out.append("  - [`../processed/arjun_params.txt`](../processed/arjun_params.txt)")
        out.append("  - [`../processed/parameterized_urls.txt`](../processed/parameterized_urls.txt)")
        out.append("")

        _sample = data.get("parameterized_sample") or []
        _ptotal = c.get("parameterized_urls", 0)
        if _sample:
            out.append(f"<details open><summary><b>Injection candidates</b> — "
                       f"{_ptotal}</summary>\n")
            out.append("Nothing scans this list automatically — it is the "
                       "hand-testing shortlist.\n")
            out.append(f"| {MD_FACTS_HEAD} | URL |")
            out.append(f"|{MD_FACTS_SEP}|-----|")
            for u in _sample:
                out.append(f"| {md_facts_cells(_idx, u)} | `{escape(u)}` |")
            out.append("\n</details>\n")

        # Forms / input surface
        out.append("## 8.1 Forms & Input Surface\n")
        _forms = [f for f in (data.get("forms") or []) if isinstance(f, dict)]
        if not _forms:
            out.append("_No forms extracted from the crawl._\n")
        else:
            out.append("Ranked by testing value: file uploads first, then POST "
                       "bodies, then forms carrying auth/identity fields.\n")
            out.append(f"- Total forms: `{c.get('forms', 0)}`")
            out.append(f"- POST: `{c.get('forms_post', 0)}`")
            out.append(f"- File upload (multipart): `{c.get('forms_upload', 0)}`")
            out.append("- Output file: "
                       "[`../processed/forms.json`](../processed/forms.json)\n")
            out.append(f"| {MD_FACTS_HEAD} | Action | Method | Enctype "
                       "| Inputs | Found on |")
            out.append(f"|{MD_FACTS_SEP}|--------|--------|---------"
                       "|--------|----------|")
            for f in _forms:
                _pl = f.get("parameters")
                _pl = _pl if isinstance(_pl, list) else []
                _act = str(f.get("action") or f.get("url") or "")
                out.append(
                    f"| {md_facts_cells(_idx, _act)} "
                    f"| `{escape(_act)}` "
                    f"| `{escape(str(f.get('method') or 'GET').upper())}` "
                    f"| `{escape(str(f.get('enctype') or ''))}` "
                    f"| `{escape(', '.join(str(x) for x in _pl))}` "
                    f"| `{escape(str(f.get('url') or ''))}` |"
                )
            out.append("")

        # API documentation
        out.append("## 8.2 API Documentation\n")
        _ad = data.get("api_docs") or {}
        _specs = [x for x in (_ad.get("specs") or []) if isinstance(x, dict)]
        _ui = [x for x in (_ad.get("ui") or []) if isinstance(x, dict)]
        _disc = [x for x in (_ad.get("discovery") or []) if isinstance(x, dict)]
        _osint = [x for x in (_ad.get("osint") or []) if isinstance(x, dict)]
        if not (_specs or _ui or _disc or _osint):
            out.append("_No OpenAPI/Swagger specs, docs UIs or public "
                       "Postman/GitHub hits found._\n")
        else:
            out.append(f"- Specs parsed: `{c.get('api_specs', 0)}`")
            out.append(f"- Documented paths: `{c.get('api_documented_paths', 0)}`")
            out.append(f"- Docs UIs / discovery docs: `{len(_ui) + len(_disc)}`")
            out.append(f"- External OSINT hits: `{len(_osint)}`")
            out.append("- Output file: "
                       "[`../findings/api_docs.json`](../findings/api_docs.json)\n")
            _chased = sum(1 for x in _specs if x.get("source") == "ui-chase")
            if _chased:
                out.append(f"- Specs recovered by following a docs UI → spec: "
                           f"`{_chased}`")
            if _specs:
                out.append("| Type | Title | Paths | Auth | Source | Document |")
                out.append("|------|-------|------:|------|--------|----------|")
                for x in _specs:
                    out.append(
                        f"| `{escape(str(x.get('kind','')))} "
                        f"{escape(str(x.get('version','')))}` "
                        f"| {escape(str(x.get('title','')))} "
                        f"| `{int(x.get('paths', 0) or 0)}` "
                        f"| `{escape(', '.join(x.get('security_schemes') or []) or 'none')}` "
                        f"| `{escape(str(x.get('source','probe')))}` "
                        f"| `{escape(str(x.get('url','')))}` |"
                    )
                out.append("")
            if _ui or _disc:
                out.append(f"| {MD_FACTS_HEAD} | Docs UI / discovery |")
                out.append(f"|{MD_FACTS_SEP}|---------------------|")
                for x in _ui + _disc:
                    _u = str(x.get("url", ""))
                    out.append(f"| {md_facts_cells(_idx, _u)} | `{escape(_u)}` |")
                out.append("")
            for x in _osint:
                out.append(
                    f"- OSINT `{escape(str(x.get('source','')))}`: "
                    f"{escape(str(x.get('name','')))} — "
                    f"`{escape(str(x.get('url','')))}`"
                )
            out.append("")

        # High-value
        out.append("## 9. High-Value Targets\n")
        hv = data["high_value_targets"]
        if hv:
            probed = sum(1 for h in hv if h.get("probed"))
            live = sum(1 for h in hv
                       if (h.get("status") or 0) and h["status"] < 400)
            gated = sum(1 for h in hv if h.get("status") in (401, 403))
            out.append(
                f"Total: `{len(hv)}` · reachable `{live}` · auth-gated "
                f"`{gated}` · unprobed `{len(hv) - probed}`\n")
            out.append("Sorted by what the server actually returned, not by "
                       "the URL text: reachable first, then auth-gated (the "
                       "path exists and is protected), then 404s.\n")
            _blanket = data["counts"].get("high_value_blanket_hosts") or []
            if _blanket:
                out.append(
                    "⚠ Host(s) where an entire cluster of high-value-looking "
                    "entries was one WAF/soft-catch-all page repeated "
                    "(already collapsed above, not hidden): "
                    + ", ".join(f"`{escape(h)}`" for h in _blanket)
                    + ". Any single entry below on these hosts is one sample "
                    "of that shape, not a distinct finding.\n"
                )
            out.append("| ST | Length | Type | Title / Redirect | URL | Categories |")
            out.append("|----|--------|------|------------------|-----|------------|")
            for h in hv:
                note = h.get("title") or ""
                if h.get("location"):
                    note = f"→ {h['location']}"
                _n = h.get("shape_count") or 1
                if _n > 1:
                    note = (note + " " if note else "") + f"[×{_n} same shape]"
                out.append(
                    f"| {_fmt_status(h.get('status'))} "
                    f"| {_fmt_len(h.get('content_length'))} "
                    f"| {escape(h.get('content_type') or '-')} "
                    f"| {escape(note[:60]) or '-'} "
                    f"| `{escape(h['url'])}` "
                    f"| {', '.join(escape(c) for c in h['categories'])} |"
                )
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
                for u in items:
                    out.append(f"- `{escape(u)}`")
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
        for u in read_lines(layout.path(self.inputs.output_dir, "parameterized_urls.txt")):
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
                         "svn exposure", "directory listing") for c in h["categories"]):
                recs["📂 Exposed files (env / git / backups)"].append(h["url"])

        # Nuclei high/critical
        for f in data["nuclei"]["default"]["findings"]:
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
            ("Forms",             c.get("forms", 0)),
            ("Nuclei default",    c.get("nuclei_default_findings", 0)),
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
            ("ffuf URLs",             "ffuf_urls",             "../processed/ffuf_urls.txt"),
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
            return '<h2>6. DNS Inventory</h2><p class="small">Not generated.</p>'
        body = []
        for r in rows:
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
        return (
            "<h2>6. DNS Inventory</h2>\n"
            '<input class="filter" placeholder="filter… (subdomain, IP, ASN, CNAME)" '
            'onkeyup="filterTable(this, \'tbl-dns\')">\n'
            '<table id="tbl-dns"><thead><tr>'
            '<th>Subdomain</th><th>IP</th><th>ASN</th><th>CNAME</th><th>Source</th>'
            "</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>"
        )

    def _html_section_assets(self, data: dict) -> str:
        rows = data["assets"]
        if not rows:
            return '<h2>5. Asset Inventory</h2><p class="small">Not generated.</p>'
        body = []
        for a in rows:
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
        return (
            "<h2>5. Asset Inventory</h2>\n"
            '<input class="filter" placeholder="filter…" '
            'onkeyup="filterTable(this, \'tbl-assets\')">\n'
            '<table id="tbl-assets"><thead><tr>'
            '<th>URL</th><th>Status</th><th>Length</th><th>Type</th>'
            '<th>Title</th><th>Tech</th><th>Source</th>'
            "</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>"
        )

    def _html_section_content_discovery(self, data: dict) -> str:
        c = data["counts"]
        rows = "\n".join(
            f"<tr><td>{escape(label)}</td><td><code>{c.get(key,0):,}</code></td>"
            f"<td><a href=\"{escape(rel)}\"><code>{escape(rel)}</code></a></td></tr>"
            for label, key, rel in [
                ("katana crawl (+urlfinder/gau if on)", "crawler_urls",  "../processed/crawler_urls.txt"),
                ("dirsearch",                  "dirsearch_urls","../processed/dirsearch_urls.txt"),
                ("ffuf",                       "ffuf_urls",     "../processed/ffuf_urls.txt"),
                ("fuzz_recurse (under discovered dirs)", "fuzz_recurse_urls", "../processed/fuzz_recurse_urls.txt"),
                ("waymore",                    "waymore_urls",  "../processed/waymore_urls.txt"),
                ("raw katana output",          None,            "../raw/content_discovery/katana_urls.txt"),
                ("raw urlfinder output",       None,            "../raw/content_discovery/urlfinder_urls.txt"),
                ("raw dirsearch output",       None,            "../raw/dirsearch/dirsearch_raw.txt"),
                ("raw ffuf output",            None,            "../raw/ffuf/ffuf_raw.txt"),
                ("raw waymore output",         None,            "../raw/waymore/waymore_raw.txt"),
            ]
        )
        # Body previews for ffuf/dirsearch hits. A 200 on /backup/ means
        # nothing until you see whether the body is a listing or a login
        # page, and that is what responses/ holds.
        n_resp = c.get("responses_captured", 0)
        resp_html = (
            "<p class=\"small\">Response previews: "
            f"<b>{n_resp:,}</b> hit(s) re-requested with a short body preview — "
            "<a href=\"../responses/index.md\"><code>responses/index.md</code></a></p>"
            if n_resp else
            "<p class=\"small\">Response previews: none captured "
            "(no ffuf/dirsearch hits, or the stage was skipped).</p>"
        )
        surf = data.get("url_surface") or {}
        surface_html = ""
        if surf.get("total"):
            def _chips(items: list[tuple]) -> str:
                return " ".join(
                    f"<span class=\"chip\"><code>{escape(str(k))}</code> {v}</span>"
                    for k, v in items
                )
            status_chips = _chips(list(surf["by_status"].items()))
            type_chips = _chips(list(surf["by_type"].items()))
            surface_html = (
                "<h3>Discovered URL surface</h3>"
                f"<p class=\"small\">{surf['total']:,} probed — "
                "<a href=\"../processed/alive_urls_table.txt\">"
                "<code>alive_urls_table.txt</code></a> · "
                f"⭐ APIs (application/json): <b>{surf['apis']:,}</b> · "
                f"auth-gated (401/403): <b>{surf['auth_gated']:,}</b></p>"
                f"<p><b>By status:</b> {status_chips}</p>"
                f"<p><b>By content-type:</b> {type_chips}</p>"
            )
        coverage_html = self._html_fuzz_coverage(data)
        screen_html = self._html_fuzz_screen(data)
        existence_html = self._html_endpoint_existence(data)
        return (
            "<h2>7. Content Discovery</h2>\n"
            "<table><thead><tr><th>Source</th><th>Count</th><th>File</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            f"{resp_html}"
            f"{surface_html}"
            f"{coverage_html}"
            f"{screen_html}"
            f"{existence_html}"
        )

    def _html_fuzz_coverage(self, data: dict) -> str:
        """How much of the alive-host surface dirsearch/ffuf actually
        touched — see :func:`fuzz_coverage`'s docstring for why this exists.
        A URL count alone cannot tell a reader "capped at 50 of 312 hosts";
        this is the only place that number is visible at all.
        """
        cov = data.get("fuzz_coverage") or {}
        rows = []
        for label in ("dirsearch", "ffuf"):
            sel = cov.get(label) or {}
            if not sel:
                continue
            capped = sel.get("capped", 0)
            note = (f'<span class="st-gated">{capped:,} host(s) never '
                    f"fuzzed — capped by <code>{label}.max_hosts</code></span>"
                    if capped else "no cap hit — every selected host was fuzzed")
            rows.append(
                "<tr>"
                f"<td>{escape(label)}</td>"
                f"<td>{sel.get('input', 0):,}</td>"
                f"<td>{sel.get('deduped', 0):,}</td>"
                f"<td>{sel.get('waf_skipped', 0):,}</td>"
                f"<td>{sel.get('blanket_skipped', 0):,}</td>"
                f"<td>{sel.get('selected', 0):,}</td>"
                f"<td>{note}</td>"
                "</tr>"
            )
        if not rows:
            return ""
        return (
            "<h3>Host fuzzing coverage</h3>\n"
            '<p class="small">Alive hosts get deduped (identical response = '
            "same app), WAF/blanket-response hosts get dropped (fuzzing them "
            "wastes the whole budget on one answer), then ranked and capped. "
            "\"Capped\" hosts are real, distinct targets this run never "
            "touched — not noise that was correctly filtered out.</p>\n"
            "<table><thead><tr><th>Stage</th><th>Alive hosts</th>"
            "<th>Deduped</th><th>WAF-skipped</th><th>Blanket-skipped</th>"
            "<th>Fuzzed</th><th>Coverage</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _html_fuzz_screen(self, data: dict) -> str:
        """Post-fuzz behavioural screen (:func:`fuzz_screen`) — distinct from
        :meth:`_html_fuzz_coverage` above, which is a PRE-fuzz host-selection
        number. This one answers "of the hits the wordlist actually
        produced, how many were one response shape wearing many paths."
        """
        scr = data.get("fuzz_screen") or {}
        rows = []
        for label in ("dirsearch", "ffuf"):
            s = scr.get(label) or {}
            if not s:
                continue
            blanket = s.get("blanket_hosts") or []
            blanket_html = (
                " ".join(f"<code>{escape(h)}</code>" for h in blanket)
                if blanket else "—"
            )
            rows.append(
                "<tr>"
                f"<td>{escape(label)}</td>"
                f"<td>{s.get('raw_hits', 0):,}</td>"
                f"<td>{s.get('kept', 0):,}</td>"
                f"<td>{s.get('dropped', 0):,}</td>"
                f"<td>{blanket_html}</td>"
                "</tr>"
            )
        if not rows:
            return ""
        return (
            "<h3>Behavioural hit screening</h3>\n"
            '<p class="small">After fuzzing, every hit is fingerprinted by '
            "response shape (status + content-type + redirect target + "
            "words/lines, or byte length when a tool reports no word "
            "count) and any cluster that is both large <i>and</i> dominant "
            "on a host is dropped as one response wearing many paths, not "
            "distinct findings.</p>\n"
            "<table><thead><tr><th>Stage</th><th>Raw hits</th><th>Kept</th>"
            "<th>Dropped</th><th>Blanket hosts</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    _EXISTENCE_LABEL = {
        existence.CONFIRMED: ("Confirmed Exists", "st-ok"),
        existence.LIKELY: ("Likely Exists", "st-gated"),
        existence.UNKNOWN: ("Unknown", "st-none"),
        existence.NOT_FOUND: ("Not Found", "st-dead"),
    }
    _EXISTENCE_CAP = 200

    def _html_endpoint_existence(self, data: dict) -> str:
        """Every ffuf/dirsearch hit classified by response BEHAVIOUR rather
        than status code alone — see ``modules/existence.py``'s module
        docstring. Distinct from :meth:`_html_fuzz_screen` above: that drops
        NOISE clusters before a hit ever reaches this table; this classifies
        what SURVIVES that screen (and hits screening never touched).
        """
        ex = data.get("endpoint_existence") or {}
        results = ex.get("results") or []
        if not results:
            return ""
        counts = ex.get("counts") or {}
        count_rows = "".join(
            f"<tr><td>{label}</td><td>{counts.get(key, 0):,}</td></tr>"
            for key, (label, _cls) in self._EXISTENCE_LABEL.items()
        )
        actionable = [r for r in results
                     if r["verdict"] in (existence.CONFIRMED, existence.LIKELY)]
        actionable.sort(key=lambda r: (r["verdict"] != existence.CONFIRMED, r["url"]))
        detail_rows = "".join(
            "<tr>"
            f"<td class=\"{self._EXISTENCE_LABEL[r['verdict']][1]}\">"
            f"{self._EXISTENCE_LABEL[r['verdict']][0]}</td>"
            f"<td>{r.get('status') or '—'}</td>"
            f"<td>{escape('+'.join(r['sources']))}</td>"
            f"<td><code>{escape(r['url'])}</code></td>"
            f"<td class=\"small\">{escape('; '.join(r['reasons']) or '—')}</td>"
            "</tr>"
            for r in actionable[:self._EXISTENCE_CAP]
        )
        detail_html = ""
        if actionable:
            more = (f" (showing first {self._EXISTENCE_CAP})"
                    if len(actionable) > self._EXISTENCE_CAP else "")
            detail_html = (
                f"<h4>Confirmed / Likely endpoints — {len(actionable):,}{more}</h4>\n"
                "<table><thead><tr><th>Verdict</th><th>Status</th>"
                "<th>Source</th><th>URL</th><th>Evidence</th></tr></thead>"
                f"<tbody>{detail_rows}</tbody></table>"
            )
        return (
            "<h3>Endpoint existence</h3>\n"
            '<p class="small">Every ffuf/dirsearch hit, classified by '
            "response behaviour instead of status code alone: baseline-shape "
            "agreement (does this look exactly like a path guaranteed not to "
            "exist on this host?), body-preview signals (validation/parsing/"
            "auth/business-logic/framework-specific error text), and whether "
            "the status itself implies a routed request.</p>\n"
            "<table><thead><tr><th>Verdict</th><th>Count</th></tr></thead>"
            f"<tbody>{count_rows}</tbody></table>\n"
            f"{detail_html}"
        )

    def _html_section_js(self, data: dict) -> str:
        c = data["counts"]
        api = data["interesting_api_paths"]
        _idx = data.get("url_detail_index") or {}
        _snips = data.get("body_snippets") or {}
        # Endpoints mined out of JS are the most common thing in this report
        # to be quoted without evidence. Many are relative paths that were
        # never probed — those show "—" rather than an invented status.
        api_html = (
            "<table><thead><tr>"
            f"{HTML_FACTS_HEAD}<th>Path</th></tr></thead><tbody>"
            + "".join(
                f"<tr>{html_facts_cells(_idx, p, _snips)}"
                f"<td><code>{escape(p)}</code></td></tr>" for p in api
            )
            + "</tbody></table>"
        ) if api else '<p class="small">None.</p>' 

        def _row(label: str, key: str, rel: str) -> str:
            return (
                f"<tr><th>{escape(label)}</th>"
                f"<td><code>{c.get(key, 0):,}</code></td>"
                f"<td><a href=\"../processed/{rel}\"><code>{rel}</code></a></td></tr>"
            )

        # Both JS tools get equal billing. xnLinkFinder is regex (broad,
        # noisy), jsluice is AST (precise, sees params) — reporting only
        # the first hides the more accurate half of the analysis.
        counts_table = (
            "<table>"
            + _row("JS files (final)", "js_urls", "js_urls.txt")
            + _row("xnLinkFinder endpoints (regex)", "xnlinkfinder_endpoints",
                   "xnlinkfinder_endpoints.txt")
            + _row("xnLinkFinder URLs (regex)", "xnlinkfinder_urls",
                   "xnlinkfinder_urls.txt")
            + _row("jsluice endpoints (AST)", "jsluice_endpoints",
                   "jsluice_endpoints.txt")
            + _row("jsluice URLs (AST)", "jsluice_urls", "jsluice_urls.txt")
            + _row("jsluice param records (AST)", "jsluice_params",
                   "jsluice_params.json")
            + f"<tr><th>Interesting API paths</th><td><code>{len(api):,}</code></td>"
            + "<td><span class=\"small\">filtered from the files above</span></td></tr>"
            + "</table>\n"
        )
        recurse_note = ""
        if c.get("jsluice_js_recursed_rounds"):
            recurse_note = (
                '<p class="small">↳ jsluice recursed into JS-referenced-JS '
                f"(webpack chunks/lazy bundles): "
                f"<code>{c.get('jsluice_js_recursed_rounds', 0):,}</code> round(s), "
                f"<code>{c.get('jsluice_js_recursed_fetched', 0):,}</code> extra "
                f"file(s) fetched (of "
                f"<code>{c.get('jsluice_js_fetched', 0):,}</code> total)</p>\n"
            )

        jsurf = data.get("jsluice_js_surface") or {}
        jsluice_js_surface_html = ""
        if jsurf.get("total"):
            def _chips(items: list[tuple]) -> str:
                return " ".join(
                    f"<span class=\"chip\"><code>{escape(str(k))}</code> {v}</span>"
                    for k, v in items
                )
            jsluice_js_surface_html = (
                "<h3>jsluice JS fetch surface</h3>"
                f"<p class=\"small\">{jsurf['total']:,} JS file(s) attempted "
                "(incl. 4xx/5xx, initial + recursive rounds) — "
                "<a href=\"../processed/jsluice_js_table.txt\">"
                "<code>jsluice_js_table.txt</code></a></p>"
                f"<p><b>By status:</b> "
                f"{_chips(list(jsurf['by_status'].items()))}</p>"
            )

        return (
            "<h2>3. JavaScript Analysis (Endpoint Extraction)</h2>\n"
            + counts_table
            + recurse_note
            + jsluice_js_surface_html
            + self._html_jsluice_params(data)
            + "<details><summary>Interesting API paths</summary>\n"
            + api_html
            + "</details>"
        )

    def _html_jsluice_params(self, data: dict) -> str:
        """Table of jsluice's AST-extracted params.

        This is the only place in the run where **body** params show up:
        arjun is GET-only and only fuzzes what already looks dynamic in the
        URL, so a POST endpoint whose fields exist solely in a JS fetch()
        call is invisible everywhere else.
        """
        recs = [r for r in (data.get("jsluice_params") or []) if isinstance(r, dict)]
        if not recs:
            return (
                '<p class="small">jsluice extracted no parameter records '
                "from JS (nothing to show).</p>"
            )

        def _sort_key(r: dict) -> tuple:
            # Body params first (rarest + highest value), then most params.
            return (
                -len(r.get("bodyParams") or []),
                -len(r.get("queryParams") or []),
            )

        idx = data.get("url_detail_index") or {}
        snips = data.get("body_snippets") or {}
        rows = []
        for r in sorted(recs, key=_sort_key):
            q = ", ".join(str(x) for x in (r.get("queryParams") or []))
            b = ", ".join(str(x) for x in (r.get("bodyParams") or []))
            method = str(r.get("method") or "").upper() or "—"
            u = str(r.get("url", ""))
            rows.append(
                "<tr>"
                f"{html_facts_cells(idx, u, snips)}"
                f"<td><code>{escape(method)}</code></td>"
                f"<td><code>{escape(u)}</code></td>"
                f"<td><span class=\"small\"><code>{escape(q)}</code></span></td>"
                f"<td><span class=\"small\"><code>{escape(b)}</code></span></td>"
                "</tr>"
            )
        n_body = sum(1 for r in recs if r.get("bodyParams"))
        return (
            f"<details><summary><strong>jsluice params — {len(recs):,} record(s)"
            f"</strong>, {n_body:,} with body params</summary>\n"
            '<p class="small">Extracted from JS by AST. Body params never '
            "reach arjun (GET-only), so these are unique to this table.</p>\n"
            "<table><thead><tr>"
            f"{HTML_FACTS_HEAD}<th>Method</th><th>URL</th>"
            "<th>Query params</th><th>Body params</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "</details>"
        )

    def _html_section_secrets(self, data: dict) -> str:
        blk = data.get("jsluice_secrets") or {}
        secrets = blk.get("findings") or []
        if not secrets:
            return (
                "<h2>3.1 JavaScript Secrets</h2>\n"
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
        for s in ordered:
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
                f"<td><span class=\"small\"><code>{escape(val)}</code></span></td>"
                f"<td><code>{escape(str(s.get('url', '')))}</code></td>"
                "</tr>"
            )
        return (
            "<h2>3.1 JavaScript Secrets</h2>\n"
            '<p class="small">API keys / tokens extracted from JavaScript by '
            "jsluice (AST). Verify before reporting — some are low-risk or "
            "false positives.</p>\n"
            f"<table><tr>{sev_headers}</tr><tr>{sev_cells}</tr></table>\n"
            f"<details open><summary><strong>{len(secrets):,} secret(s)</strong></summary>\n"
            "<table><thead><tr>"
            "<th>Severity</th><th>Kind</th><th>Value</th><th>JS URL</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "</details>"
        )

    def _html_section_method_check(self, data: dict) -> str:
        """Endpoints re-probed with the HTTP method jsluice found in the JS
        source, not a blind GET — surfaces routes a GET-only probe reads
        as dead (404/403/405) but that answer to their real verb."""
        rows = [r for r in (data.get("jsluice_method_check") or [])
                if isinstance(r, dict)]
        if not rows:
            return (
                "<h2>3.2 HTTP Method Check (verb tampering)</h2>\n"
                '<p class="small">No method-tagged endpoints to re-test '
                "(jsluice found no non-GET method in the JS, or the stage "
                "was skipped).</p>"
            )
        bypass = sum(1 for r in rows if is_method_bypass(r))
        body = []
        for r in rows:
            st = r.get("status")
            body.append(
                "<tr>"
                f"<td><code>{escape(str(r.get('method', '')))}</code></td>"
                f'<td class="{_status_class(st)}">{_fmt_status(st)}</td>'
                f"<td>{_fmt_len(r.get('content_length'))}</td>"
                f"<td><code>{escape(str(r.get('content_type') or '-'))}</code></td>"
                f"<td>{_fmt_status(r.get('get_status'))}</td>"
                f'<td class="small">{escape(str(r.get("body_preview") or "-"))}</td>'
                f"<td><code>{escape(str(r.get('url', '')))}</code></td>"
                "</tr>"
            )
        return (
            "<h2>3.2 HTTP Method Check (verb tampering)</h2>\n"
            f'<p class="small">{len(rows)} endpoint(s) re-requested with '
            "the HTTP method jsluice found in the JS source "
            "(<code>fetch(url, {method: ...})</code>), not a blind GET — "
            f"<strong>{bypass}</strong> answer differently to their real "
            "method than to GET, sorted to the top.</p>\n"
            '<input class="filter" placeholder="filter…" '
            'onkeyup="filterTable(this, \'tbl-mc\')">\n'
            '<table id="tbl-mc"><thead><tr>'
            "<th>Method</th><th>ST</th><th>Length</th><th>Type</th>"
            "<th>GET-ST</th><th>Body preview</th><th>URL</th>"
            "</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>"
        )

    def _html_section_params(self, data: dict) -> str:
        c = data["counts"]
        sample = data.get("parameterized_sample") or []
        total = c.get("parameterized_urls", 0)
        # No nuclei stage consumes parameterized_urls.txt any more, so this
        # list IS the deliverable — printing only its line count and telling
        # the reader to go open an 80 KB file is not a report.
        idx = data.get("url_detail_index") or {}
        snips = data.get("body_snippets") or {}
        if sample:
            items = "".join(
                f"<tr>{html_facts_cells(idx, u, snips)}"
                f"<td><code>{escape(u)}</code></td></tr>"
                for u in sample
            )
            sample_html = (
                f"<details open><summary><strong>Injection candidates</strong> "
                f"— {total:,}</summary>\n"
                '<p class="small">Nothing scans this list automatically — '
                "it is the hand-testing shortlist (union of already-param "
                "URLs, arjun discoveries, and jsluice params). Hover a status "
                "for the response body preview where one was captured.</p>\n"
                f"<table><thead><tr>{HTML_FACTS_HEAD}<th>URL</th></tr></thead>"
                f"<tbody>{items}</tbody></table></details>"
            )
        else:
            sample_html = (
                '<p class="small">No parameterised URLs found — nothing to '
                "hand-test from this run.</p>"
            )
        _arjun_scanned = c.get("arjun_scanned_urls")
        _arjun_input = c.get("arjun_input_urls")
        if _arjun_scanned is not None and _arjun_input is not None:
            _capped_n = _arjun_input - _arjun_scanned
            if _capped_n > 0:
                _arjun_note = (
                    '<span class="st-gated">capped by '
                    f"<code>arjun.max_urls</code> — {_capped_n:,} URL(s) "
                    "never checked for hidden params</span>"
                )
            else:
                _arjun_note = "every candidate URL was scanned"
            _arjun_row = (
                "<tr><th>Arjun actually scanned</th>"
                f"<td><code>{_arjun_scanned:,} / {_arjun_input:,}</code></td>"
                f"<td>{_arjun_note}</td></tr>"
            )
        else:
            _arjun_row = ""
        return (
            "<h2>8. Parameter Discovery</h2>\n"
            "<table>"
            f"<tr><th>Dynamic URLs (candidates)</th><td><code>{c.get('dynamic_urls',0):,}</code></td></tr>"
            f"{_arjun_row}"
            f"<tr><th>Arjun params</th><td><code>{c.get('arjun_params',0):,}</code></td>"
            f"<td><a href=\"../processed/arjun_params.txt\"><code>arjun_params.txt</code></a></td></tr>"
            f"<tr><th>jsluice param records</th><td><code>{c.get('jsluice_params',0):,}</code></td>"
            f"<td><a href=\"../processed/jsluice_params.json\"><code>jsluice_params.json</code></a></td></tr>"
            f"<tr><th>Parameterized URLs</th><td><code>{total:,}</code></td>"
            f"<td><a href=\"../processed/parameterized_urls.txt\"><code>parameterized_urls.txt</code></a></td></tr>"
            "</table>\n"
            + sample_html
        )

    def _html_section_forms(self, data: dict) -> str:
        idx = data.get("url_detail_index") or {}
        snips = data.get("body_snippets") or {}
        """Forms + inputs mined from the crawl — ranked by testing value."""
        c = data["counts"]
        forms = [f for f in (data.get("forms") or []) if isinstance(f, dict)]
        if not forms:
            return (
                "<h2>8.1 Forms &amp; Input Surface</h2>\n"
                '<p class="small">No forms extracted from the crawl.</p>'
            )
        rows = []
        for f in forms:
            params = f.get("parameters")
            params = params if isinstance(params, list) else []
            pnames = ", ".join(str(x) for x in params)
            method = str(f.get("method") or "GET").upper()
            enctype = str(f.get("enctype") or "")
            badges = ""
            if "multipart" in enctype.lower():
                badges += '<span class="chip">upload</span> '
            if method == "POST":
                badges += '<span class="chip">POST</span> '
            action = str(f.get("action") or f.get("url") or "")
            rows.append(
                "<tr>"
                f"<td>{badges or '&mdash;'}</td>"
                f"{html_facts_cells(idx, action, snips)}"
                f"<td><code>{escape(action)}</code></td>"
                f"<td><code>{escape(method)}</code></td>"
                f"<td><span class=\"small\"><code>{escape(enctype)}</code></span></td>"
                f"<td><span class=\"small\"><code>{escape(pnames)}</code></span></td>"
                f"<td><code>{escape(str(f.get('url') or ''))}</code></td>"
                "</tr>"
            )
        return (
            "<h2>8.1 Forms &amp; Input Surface</h2>\n"
            '<p class="small">Every &lt;form&gt; the crawler saw, ranked by '
            "testing value: file uploads first, then POST bodies, then forms "
            "carrying auth/identity fields. This is where CSRF, mass "
            "assignment and injection actually live.</p>\n"
            "<table>"
            f"<tr><th>Total forms</th><td><code>{c.get('forms', 0):,}</code></td></tr>"
            f"<tr><th>POST</th><td><code>{c.get('forms_post', 0):,}</code></td></tr>"
            f"<tr><th>File upload (multipart)</th>"
            f"<td><code>{c.get('forms_upload', 0):,}</code></td></tr>"
            "</table>\n"
            f"<details open><summary><strong>{len(forms):,} form(s)</strong> "
            "— highest-value first</summary>\n"
            "<table><thead><tr>"
            f"<th></th>{HTML_FACTS_HEAD}<th>Action</th><th>Method</th>"
            "<th>Enctype</th><th>Inputs</th><th>Found on</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "</details>"
        )

    def _html_section_apidocs(self, data: dict) -> str:
        """OpenAPI/Swagger specs, docs UIs, and external OSINT hits."""
        c = data["counts"]
        blk = data.get("api_docs") or {}
        specs = [s for s in (blk.get("specs") or []) if isinstance(s, dict)]
        ui = [u for u in (blk.get("ui") or []) if isinstance(u, dict)]
        disc = [d for d in (blk.get("discovery") or []) if isinstance(d, dict)]
        osint = [o for o in (blk.get("osint") or []) if isinstance(o, dict)]
        if not (specs or ui or disc or osint):
            return (
                "<h2>8.2 API Documentation</h2>\n"
                '<p class="small">No OpenAPI/Swagger specs, docs UIs or '
                "public Postman/GitHub hits found.</p>"
            )
        out = ["<h2>8.2 API Documentation</h2>"]
        out.append(
            '<p class="small">A spec hands you every route, parameter and '
            "auth scheme the developers wrote down — the highest-signal "
            "artefact in the run. Endpoints below are already merged into "
            "<code>all_urls.txt</code>; declared params went to the "
            "shortlist.</p>"
        )
        out.append(
            "<table>"
            f"<tr><th>Specs parsed</th><td><code>{c.get('api_specs', 0):,}</code></td></tr>"
            f"<tr><th>Documented paths</th>"
            f"<td><code>{c.get('api_documented_paths', 0):,}</code></td></tr>"
            f"<tr><th>Docs UIs / discovery docs</th>"
            f"<td><code>{len(ui) + len(disc):,}</code></td></tr>"
            f"<tr><th>External OSINT hits</th><td><code>{len(osint):,}</code></td></tr>"
            "</table>"
        )
        if specs:
            chased = sum(1 for s in specs if s.get("source") == "ui-chase")
            rows = "".join(
                "<tr>"
                f"<td><code>{escape(str(s.get('kind', '')))} "
                f"{escape(str(s.get('version', '')))}</code></td>"
                f"<td>{escape(str(s.get('title', '')))}</td>"
                f"<td><code>{int(s.get('paths', 0) or 0):,}</code></td>"
                f"<td><span class=\"small\"><code>"
                f"{escape(', '.join(s.get('security_schemes') or []) or 'none')}"
                "</code></span></td>"
                f"<td><code>{escape(str(s.get('source', 'probe')))}</code></td>"
                f"<td><a href=\"{escape(str(s.get('url', '')))}\"><code>"
                f"{escape(str(s.get('url', '')))}</code></a></td>"
                "</tr>"
                for s in specs
            )
            chase_note = (f" &mdash; {chased} via UI&rarr;spec chase"
                          if chased else "")
            out.append(
                f"<details open><summary><strong>{len(specs):,} spec(s)"
                f"</strong>{chase_note}</summary>\n"
                "<table><thead><tr><th>Type</th><th>Title</th><th>Paths</th>"
                "<th>Auth</th><th>Source</th><th>Document</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></details>"
            )
        if ui or disc:
            idx = data.get("url_detail_index") or {}
            snips = data.get("body_snippets") or {}
            # The probe already recorded a status per candidate; prefer it
            # over the shared index, which may not have probed these at all.
            items = "".join(
                "<tr>"
                + (f'<td class="{_status_class(h.get("status"))}">'
                   f'{_fmt_status(h.get("status"))}</td>'
                   "<td>&mdash;</td><td><code>-</code></td>"
                   if h.get("status") is not None
                   else html_facts_cells(idx, str(h.get("url", "")), snips))
                + f"<td><code>{escape(str(h.get('url', '')))}</code></td></tr>"
                for h in (ui + disc)
            )
            out.append(
                f"<details><summary>{len(ui) + len(disc):,} docs UI / "
                "discovery document(s)</summary>"
                f"<table><thead><tr>{HTML_FACTS_HEAD}<th>URL</th></tr></thead>"
                f"<tbody>{items}</tbody></table></details>"
            )
        if osint:
            rows = "".join(
                "<tr>"
                f"<td><code>{escape(str(o.get('source', '')))}</code></td>"
                f"<td><code>{escape(str(o.get('kind', '')))}</code></td>"
                f"<td>{escape(str(o.get('name', '')))}</td>"
                f"<td><a href=\"{escape(str(o.get('url', '')))}\"><code>"
                f"{escape(str(o.get('url', '')))}</code></a></td>"
                "</tr>"
                for o in osint
            )
            out.append(
                f"<details open><summary><strong>{len(osint):,} external "
                "OSINT hit(s)</strong> — public Postman / GitHub</summary>\n"
                '<p class="small">Filtered to results naming the target org; '
                "verify each one actually belongs to the target before "
                "reporting.</p>\n"
                "<table><thead><tr><th>Source</th><th>Kind</th><th>Name</th>"
                "<th>Link</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></details>"
            )
        return "\n".join(out)

    def _html_section_misconfig(self, data: dict) -> str:
        """Server/microservice misconfig probe — deep-tier hosts only."""
        c = data["counts"]
        blk = data.get("misconfig_probe") or {}
        findings = [f for f in (blk.get("findings") or []) if isinstance(f, dict)]
        hosts_probed = int(blk.get("hosts_probed", 0) or 0)
        if not findings:
            reason = (" (no deep-tier host this run)" if not hosts_probed else "")
            return (
                "<h2>8.3 Server/Microservice Misconfig</h2>\n"
                f'<p class="small">No actuator/Jenkins/GitLab/Kubernetes/'
                f"phpMyAdmin-style misconfig confirmed on the "
                f"{hosts_probed:,} deep-tier host(s) probed{reason}.</p>"
            )
        out = ["<h2>8.3 Server/Microservice Misconfig</h2>"]
        out.append(
            '<p class="small">Sensitive sub-endpoints of known services '
            "(Spring actuator, Jenkins script console, GitLab/Kubernetes "
            "API, phpMyAdmin, ...) found on hosts <code>fuzz_depth</code> "
            "flagged as high-value. Each hit is content-validated, not "
            "just a status code — see <code>confidence</code>.</p>"
        )
        out.append(
            "<table>"
            f"<tr><th>Deep-tier hosts probed</th><td><code>{c.get('misconfig_hosts_probed', 0):,}</code></td></tr>"
            f"<tr><th>Hits</th><td><code>{c.get('misconfig_hits', 0):,}</code></td></tr>"
            "</table>"
        )
        rows = "".join(
            "<tr>"
            f"<td>{escape(str(f.get('service', '')))}</td>"
            f"<td><span class=\"small\"><code>{escape(str(f.get('confidence', '')))}"
            "</code></span></td>"
            f'<td class="{_status_class(f.get("status"))}">{_fmt_status(f.get("status"))}</td>'
            f"<td><a href=\"{escape(str(f.get('url', '')))}\"><code>"
            f"{escape(str(f.get('url', '')))}</code></a></td>"
            "</tr>"
            for f in sorted(findings, key=lambda f: f.get("confidence") != "high")
        )
        out.append(
            f"<details open><summary><strong>{len(findings):,} hit(s)"
            "</strong> — high confidence first</summary>\n"
            "<table><thead><tr><th>Service</th><th>Confidence</th>"
            "<th>Status</th><th>URL</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></details>"
        )
        return "\n".join(out)

    def _html_section_nuclei(self, data: dict) -> str:
        out = ["<h2>4. Nuclei Findings</h2>"]
        for kind, label in [
            ("default", "Default scan (hosts)"),
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
                for f in items:
                    info = f.get("info") or {}
                    matcher = f.get("matcher-name") or f.get("matcher_name") or ""
                    evidence = f.get("extracted-results") or f.get("evidence") or ""
                    evidence_str = ""
                    if isinstance(evidence, list):
                        evidence_str = ", ".join(str(e) for e in evidence)
                    elif evidence:
                        evidence_str = str(evidence)
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
                out.append(
                    f"<details open><summary><strong>{sev.upper()}</strong> "
                    f"— {len(items):,} finding(s)</summary>\n"
                    "<table><thead><tr>"
                    "<th>Severity</th><th>Template</th><th>Name</th>"
                    "<th>URL</th><th>Matcher</th><th>Evidence</th><th>Source</th>"
                    "</tr></thead>"
                    f"<tbody>{''.join(rows)}</tbody></table>"
                    "</details>"
                )
        return "\n".join(out)

    def _html_section_graphql(self, data: dict) -> str:
        targets = data.get("graphql_targets") or []
        if not targets:
            return (
                "<h2>4.1 GraphQL Introspection</h2>\n"
                '<p class="small">No endpoint answered a live introspection '
                "query (introspection disabled everywhere probed, or no "
                "GraphQL surface found).</p>"
            )
        rows = []
        for t in targets:
            qf = ", ".join(t.get("query_fields") or []) or "&mdash;"
            mf = ", ".join(t.get("mutation_fields") or []) or "&mdash;"
            rows.append(
                "<tr>"
                f"<td><code>{escape(str(t.get('url','')))}</code></td>"
                f"<td><code>{int(t.get('type_count', 0)):,}</code></td>"
                f"<td><span class=\"small\">{escape(qf)}</span></td>"
                f"<td><span class=\"small\">{escape(mf)}</span></td>"
                "</tr>"
            )
        total_mut = sum(len(t.get("mutation_fields") or []) for t in targets)
        return (
            "<h2>4.1 GraphQL Introspection</h2>\n"
            f'<p class="small">Introspection ON at <strong>{len(targets)}</strong> '
            f"endpoint(s) — {total_mut} mutation(s) exposed. One POST per "
            "endpoint, same risk class as fetching a Swagger doc — "
            "<a href=\"../findings/graphql_schema.json\">"
            "<code>graphql_schema.json</code></a> has the full type list.</p>\n"
            "<table><thead><tr><th>URL</th><th>Types</th>"
            "<th>Query fields</th><th>Mutation fields</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _html_section_cors(self, data: dict) -> str:
        findings = data.get("cors_findings") or []
        if not findings:
            return (
                "<h2>4.2 CORS Misconfiguration</h2>\n"
                '<p class="small">No host reflected the test Origin with '
                "credentials allowed.</p>"
            )
        rows = []
        for f in findings:
            rows.append(
                "<tr>"
                f"<td>{severity_badge(f.get('severity',''))}</td>"
                f"<td><code>{escape(str(f.get('url','')))}</code></td>"
                f"<td><code>{escape(str(f.get('acao','')))}</code></td>"
                f"<td>{'yes' if f.get('acac') else 'no'}</td>"
                f"<td class=\"small\">{escape(str(f.get('note','')))}</td>"
                "</tr>"
            )
        crit = sum(1 for f in findings if f.get("severity") == "critical")
        return (
            "<h2>4.2 CORS Misconfiguration</h2>\n"
            f'<p class="small"><strong>{len(findings)}</strong> host(s) '
            f"reflect an arbitrary Origin — <strong>{crit}</strong> also "
            "allow credentials (any site can read the authenticated "
            "response cross-origin).</p>\n"
            "<table><thead><tr><th>Severity</th><th>URL</th>"
            "<th>Allow-Origin</th><th>Allow-Credentials</th><th>Note</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _html_section_buckets(self, data: dict) -> str:
        blk = data.get("buckets") or {}
        findings = blk.get("findings") or []
        azure = blk.get("azure_references") or []
        if not findings and not azure:
            return (
                "<h2>4.3 Cloud Storage Buckets</h2>\n"
                '<p class="small">No S3/GCS bucket confirmed (enumeration '
                "is opt-in — see <code>buckets.enabled</code> in "
                "config.yml — and off by default), and no Azure Blob "
                "reference observed.</p>"
            )
        out = ["<h2>4.3 Cloud Storage Buckets</h2>"]
        if findings:
            rows = "".join(
                "<tr>"
                f"<td>{severity_badge(f.get('severity',''))}</td>"
                f"<td><code>{escape(str(f.get('provider','')))}</code></td>"
                f"<td><code>{escape(str(f.get('bucket','')))}</code></td>"
                f"<td>{escape(str(f.get('state','')))}</td>"
                f"<td><code>{escape(str(f.get('url','')))}</code></td>"
                "</tr>"
                for f in findings
            )
            public = sum(1 for f in findings if f.get("state") == "public-listing")
            out.append(
                f'<p class="small"><strong>{len(findings)}</strong> bucket(s) '
                f"confirmed — <strong>{public}</strong> publicly listable.</p>"
                "<table><thead><tr><th>Severity</th><th>Provider</th>"
                "<th>Bucket</th><th>State</th><th>URL</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )
        if azure:
            out.append(
                f'<p class="small">{len(azure)} Azure Blob account '
                "reference(s) found in the JS/URL corpus (recorded, not "
                "probed — needs a container name to check public listing): "
                f"{', '.join(f'<code>{escape(a)}</code>' for a in azure)}</p>"
            )
        return "\n".join(out)

    def _html_section_gitdump(self, data: dict) -> str:
        hosts = data.get("gitdump_hosts") or []
        if not hosts:
            return (
                "<h2>4.4 Git Exposure Dump</h2>\n"
                '<p class="small">No confirmed .git exposure reconstructed '
                "(dumping is opt-in — see <code>gitdump.enabled</code> in "
                "config.yml — and off by default).</p>"
            )
        rows = "".join(
            "<tr>"
            f"<td><code>{escape(str(h.get('host','')))}</code></td>"
            f"<td><code>{escape(str(h.get('ref') or '-'))}</code></td>"
            f"<td>{int(h.get('files_recovered', 0)):,} / "
            f"{int(h.get('files_in_index', 0)):,}</td>"
            f"<td><code>{escape(str(h.get('output_dir','')))}</code></td>"
            "</tr>"
            for h in hosts
        )
        total = sum(h.get("files_recovered", 0) for h in hosts)
        return (
            "<h2>4.4 Git Exposure Dump</h2>\n"
            f'<p class="small"><strong>{total}</strong> file(s) reconstructed '
            f"across {len(hosts)} confirmed host(s). Recovery is best-effort — "
            "a host that ran <code>git gc</code> packs its loose objects "
            "away, so files_recovered may be well under files_in_index.</p>\n"
            "<table><thead><tr><th>Host</th><th>Ref</th>"
            "<th>Recovered / in index</th><th>Output dir</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    def _html_section_high_value(self, data: dict) -> str:
        rows = data["high_value_targets"]
        if not rows:
            return '<h2>9. High-Value Targets</h2><p class="small">None identified.</p>'
        body = []
        for r in rows:
            cats = ", ".join(escape(c) for c in r["categories"])
            st = r.get("status")
            note = r.get("title") or ""
            if r.get("location"):
                note = f"→ {r['location']}"
            _n = r.get("shape_count") or 1
            if _n > 1:
                note = (note + " " if note else "") + f"[×{_n} same shape]"
            body.append(
                "<tr>"
                f'<td class="{_status_class(st)}">{_fmt_status(st)}</td>'
                f"<td>{_fmt_len(r.get('content_length'))}</td>"
                f"<td><code>{escape(r.get('content_type') or '-')}</code></td>"
                f'<td class="small">{escape(note[:80])}</td>'
                f"<td><code>{escape(r['url'])}</code></td>"
                f"<td>{cats}</td>"
                "</tr>"
            )
        probed = sum(1 for r in rows if r.get("probed"))
        gated = sum(1 for r in rows if r.get("status") in (401, 403))
        live = sum(1 for r in rows
                   if (r.get("status") or 0) and r["status"] < 400)
        blanket = data["counts"].get("high_value_blanket_hosts") or []
        blanket_html = (
            '<p class="small">⚠ Host(s) where an entire cluster of '
            f"high-value-looking entries was one WAF/soft-catch-all page "
            f"repeated (already collapsed above, not hidden): "
            f"{', '.join(f'<code>{escape(h)}</code>' for h in blanket)}. "
            "Any single entry below on these hosts is one sample of that "
            "shape, not a distinct finding.</p>"
            if blanket else ""
        )
        return (
            "<h2>9. High-Value Targets</h2>\n"
            f'<p class="small">{len(rows)} total · {live} reachable · '
            f'{gated} auth-gated · {len(rows) - probed} never probed. '
            "Sorted by what the server returned, not by the URL text.</p>\n"
            f"{blanket_html}"
            '<input class="filter" placeholder="filter…" '
            'onkeyup="filterTable(this, \'tbl-hv\')">\n'
            '<table id="tbl-hv"><thead><tr>'
            "<th>ST</th><th>Length</th><th>Type</th>"
            "<th>Title / Redirect</th><th>URL</th><th>Categories</th>"
            "</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table>"
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
            lis = "".join(f"<li><code>{escape(u)}</code></li>" for u in items)
            out.append(
                f"<details open><summary>{escape(tier)} ({len(items)})</summary>"
                f"<ul>{lis}</ul></details>"
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
        result = {
            "html": str(self.html_path),
            "md": str(self.md_path),
            "json": str(self.json_path),
            "xlsx": None,
            "xlsx_skipped_reason": None,
            "issues": sum(len(v) for k, v in data["stages"].items() if k == "failed"),
        }
        if self.inputs.xlsx:
            xlsx_info = xlsx_report.build_xlsx_report(data, self.report_dir)
            result["xlsx"] = xlsx_info.get("path")
            if xlsx_info.get("skipped"):
                result["xlsx_skipped_reason"] = xlsx_info.get("reason")
        return result


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
    xlsx: bool = False,
) -> dict:
    """Build the report artefacts under ``output_dir/report/`` — HTML, MD
    and JSON always; ``final_report.xlsx`` too when ``xlsx=True``."""
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
        xlsx=xlsx,
    )
    return ReportBuilder(inputs).write()
