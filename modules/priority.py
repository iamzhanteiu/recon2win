"""priority — post-scan triage: rank the URLs worth testing by hand.

A full scan emits thousands of URLs and (on noisy targets) hundreds of
``info``-level nuclei hits — the one High finding drowns in the flood.
This module distils everything the pipeline produced into a single
ranked file, ``report/priority_targets.txt``, so the operator can open
one file and see "test these first".

Signals combined (a URL accumulates score + reasons from every source):

  * nuclei findings   — by severity (critical/high/medium worth the most)
  * jsluice secrets   — the JS file that leaked a key/token
  * parameterized URLs — injection candidates (arjun + jsluice params)
  * dirsearch/ffuf hits— endpoints that passed the status filter (200/401/403/500)
  * high-value paths   — admin / login / api / graphql / upload / .env / .git / …

A URL that is already known to be noise gets demoted instead of scored blind:
a host that answers every path alike (``asm_report.detect_blanket_deny`` — a
WAF/edge block page, not a discovery) or a URL whose real probed response
matches its own host's not-found shape (``baseline.load_from_raw`` — an SPA
returning its shell for a path that was never a real route, which a URL mined
out of a JS bundle never gets screened against otherwise). Measured on
``outputs/dialogue.co``: ``.git/config`` on a blanket-deny host scored 770 and
ranked #3 despite ``asm_report.html`` already excluding it; demoted here it
sinks with the reason attached instead of silently agreeing with the WAF.

Everything here is deterministic and unit-tested: ``score_targets`` is a
pure function over already-loaded data; ``build_priority_targets`` is the
thin I/O wrapper that reads the canonical files and writes the report.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from . import asm_report, baseline, layout
from .utils import load_json, make_result, read_lines


# Severity → score for nuclei findings and jsluice secrets. ``info`` is
# deliberately low: an info finding alone shouldn't crowd the top.
_SEV_SCORE: dict[str, int] = {
    "critical": 1000,
    "high":      800,
    "medium":    400,
    "low":       120,
    "info":      15,
    # nuclei's severity for a template that declares none — scored like info
    # rather than dropped, since the default scan now runs those templates.
    "unknown":   15,
}

# Substrings that make a path worth a manual look, with their bonus.
# Ordered high→low intent; a URL gets the bonus for every distinct hit,
# but each keyword contributes at most once.
_PATH_HINTS: tuple[tuple[str, int, str], ...] = (
    (".env",        350, "env file"),
    ("/.git",       350, "git dir"),
    (".sql",        320, "sql dump"),
    ("backup",      300, "backup"),
    (".bak",        300, "backup"),
    ("actuator",    300, "spring actuator"),
    ("/debug",      260, "debug endpoint"),
    ("graphql",     260, "graphql"),
    ("swagger",     240, "api docs"),
    ("/api-docs",   240, "api docs"),
    ("/admin",      240, "admin"),
    ("phpmyadmin",  240, "db admin"),
    ("/upload",     220, "upload"),
    ("/config",     200, "config"),
    ("/login",      160, "login"),
    ("/auth",       160, "auth"),
    ("/api/",       150, "api"),
    ("/internal",   200, "internal"),
    ("/v1/",        120, "versioned api"),
    ("/v2/",        120, "versioned api"),
    ("token",       140, "token in path"),
    ("redirect",    140, "open-redirect candidate"),
    # misconfig_probe paths (tier "deep" only) — fire for free on any URL
    # merged from misconfig_urls.txt into all_urls.txt.
    ("/actuator/heapdump", 500, "heap dump"),
    ("/actuator/env",      380, "actuator env dump"),
    ("/script",            400, "jenkins script console"),
    ("/api/v1/namespaces", 350, "k8s api"),
    ("/v2/_catalog",       300, "docker registry catalog"),
    ("/api/v4/version",    150, "gitlab version"),
    ("adminer",            240, "db admin"),
)

_PARAM_SCORE = 300       # a URL carrying params = injection surface
_DIRSEARCH_SCORE = 220   # passed dirsearch's status filter = exists + interesting
_FFUF_SCORE = 220        # same signal from ffuf (auto-calibrated, so soft-404s are already gone)
_FORM_SCORE = 320        # a <form> = real input surface (arjun only sees GET params)

# misconfig_probe validates content, not just status — "high" confidence is
# a real fingerprint match (same trust level as a medium nuclei finding),
# "low" is status-code-only (Consul/Nexus ping, no strict validator) and
# scores like an info-level hit so it can't outrank a validated one.
_MISCONFIG_CONFIDENCE_SCORE: dict[str, int] = {"high": 400, "low": 15}

# Matches asm_report._CONFIDENCE["blanket_deny"] — demoted, not dropped, so
# the reason stays visible instead of the URL just vanishing from the report.
_BLANKET_DENY_MULT = 0.1
_BLANKET_HOST_REASON = "blanket-deny host (WAF/edge) — low confidence"
_NOISE_URL_REASON = "matches host's not-found shape — likely noise"


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _host_path(url: str) -> str:
    """``host + path``, query dropped.

    ``parameterized_urls.txt`` writes jsluice-mined URLs as a *template*
    (param names, values blanked — ``?limit=``) while the same URL got
    actually probed with real values (``?limit=100``) and lives under that
    form in ``alive_urls_detail.json``. Matching noise on the full URL
    string missed this pairing entirely on a real run (verified on
    ``outputs/dialogue.co``: the baseline fingerprint matched exactly, the
    exact-string lookup did not). Dropping the query is safe here because
    the noise signal itself — this host's not-found shape — is already
    proven to hold regardless of query on the same evidence: the baseline
    probe itself uses random, unrelated paths and still lands on the same
    shape as the real one.
    """
    try:
        p = urlsplit(url)
    except ValueError:
        return ""
    host = (p.hostname or "").lower()
    return f"{host}{p.path or '/'}" if host else ""


def _norm(url: str) -> str:
    """Trim whitespace; drop a trailing slash so ``/a`` and ``/a/`` merge."""
    u = (url or "").strip()
    if len(u) > 1 and u.endswith("/"):
        u = u[:-1]
    return u


def _add(bucket: dict[str, dict], url: str, score: int, reason: str) -> None:
    u = _norm(url)
    if not u or not u.startswith(("http://", "https://")):
        return
    slot = bucket.setdefault(u, {"url": u, "score": 0, "reasons": []})
    slot["score"] += score
    if reason and reason not in slot["reasons"]:
        slot["reasons"].append(reason)


def score_targets(
    *,
    nuclei_findings: list[dict] | None = None,
    secrets: list[dict] | None = None,
    forms: list[dict] | None = None,
    misconfig_findings: list[dict] | None = None,
    parameterized_urls: list[str] | None = None,
    dirsearch_urls: list[str] | None = None,
    ffuf_urls: list[str] | None = None,
    extra_urls: list[str] | None = None,
    blanket_hosts: set[str] | None = None,
    noise_urls: set[str] | None = None,
    limit: int = 200,
) -> list[dict]:
    """Rank URLs by manual-testing value. Pure — no I/O.

    Returns a list of ``{url, score, reasons}`` sorted by score desc then
    URL (stable), capped at ``limit``. A URL that appears in several
    sources accumulates their scores and collects each reason once.

    ``blanket_hosts`` (hostnames) and ``noise_urls`` (``host+path`` keys,
    see :func:`_host_path` — query dropped, since the same URL can reach
    this function two different ways: as the literal probed URL and as
    ``parameterized_urls.txt``'s value-stripped template of it) demote a
    slot's accumulated score by ``_BLANKET_DENY_MULT`` instead of dropping
    it. The caller (``build_priority_targets``) is the one that knows how
    to compute these from already-written run data; this function stays a
    pure function over whatever it is handed.
    """
    bucket: dict[str, dict] = {}

    for f in nuclei_findings or []:
        if not isinstance(f, dict):
            continue
        url = f.get("matched-at") or f.get("host") or ""
        sev = ((f.get("info") or {}).get("severity") or "info").lower()
        name = (f.get("info") or {}).get("name") or f.get("template-id") or "nuclei"
        _add(bucket, url, _SEV_SCORE.get(sev, 15), f"nuclei {sev}: {name}")

    for s in secrets or []:
        if not isinstance(s, dict):
            continue
        sev = (s.get("severity") or "info").lower()
        kind = s.get("kind") or "secret"
        _add(bucket, s.get("url") or "", _SEV_SCORE.get(sev, 15) + 100,
             f"secret ({kind})")

    for m in misconfig_findings or []:
        if not isinstance(m, dict):
            continue
        conf = (m.get("confidence") or "low").lower()
        service = m.get("service") or "misconfig"
        _add(bucket, m.get("url") or "",
             _MISCONFIG_CONFIDENCE_SCORE.get(conf, 15),
             f"misconfig ({service})")

    for f in forms or []:
        if not isinstance(f, dict):
            continue
        action = f.get("action") or f.get("url") or ""
        if not action:
            continue
        method = (f.get("method") or "GET").upper()
        params = [str(p).lower() for p in (f.get("parameters") or [])]
        enctype = (f.get("enctype") or "").lower()
        score = _FORM_SCORE
        tags: list[str] = []
        if method == "POST":
            score += 60                    # POST body params arjun never fuzzes
        if "multipart" in enctype:
            score += 150                   # file upload → RCE / path traversal
            tags.append("upload")
        if any("pass" in p for p in params):
            score += 80                     # login form → auth attack surface
            tags.append("login")
        if any(t in params for t in ("csrf", "authenticity_token", "_token", "token")):
            tags.append("csrf")
        label = f"form {method}"
        if tags:
            label += f" [{','.join(tags)}]"
        label += f" ({len(params)} fields)"
        _add(bucket, action, score, label)

    for u in parameterized_urls or []:
        _add(bucket, u, _PARAM_SCORE, "parameterized")

    for u in dirsearch_urls or []:
        _add(bucket, u, _DIRSEARCH_SCORE, "dirsearch hit")

    for u in ffuf_urls or []:
        _add(bucket, u, _FFUF_SCORE, "ffuf hit")

    for u in extra_urls or []:
        # extra_urls only contribute via their path hints, not a base score.
        _add(bucket, u, 0, "")

    # Path-keyword bonuses across everything collected so far.
    for url in list(bucket.keys()):
        lo = url.lower()
        slot = bucket[url]
        for needle, bonus, label in _PATH_HINTS:
            if needle in lo and label not in slot["reasons"]:
                slot["score"] += bonus
                slot["reasons"].append(label)

    # Demote — never drop — anything already known to be noise, so the
    # report keeps saying why instead of just agreeing with the WAF/SPA.
    for url, slot in bucket.items():
        reason = None
        if blanket_hosts and _host_of(url) in blanket_hosts:
            reason = _BLANKET_HOST_REASON
        elif noise_urls and _host_path(url) in noise_urls:
            reason = _NOISE_URL_REASON
        if reason:
            slot["score"] = round(slot["score"] * _BLANKET_DENY_MULT)
            if reason not in slot["reasons"]:
                slot["reasons"].insert(0, reason)

    # Drop slots that ended up with no score and no meaningful reason
    # (e.g. an extra_url with no path hint).
    ranked = [s for s in bucket.values() if s["score"] > 0]
    ranked.sort(key=lambda s: (-s["score"], s["url"]))
    return ranked[:limit]


def render(targets: list[dict], domain: str) -> str:
    """Render the ranked targets as the text of ``priority_targets.txt``."""
    lines = [
        f"# priority_targets.txt — {domain}",
        "# Ranked URLs worth manual testing (highest first).",
        "# format:  [score]  <url>  — <reasons>",
        "",
    ]
    for t in targets:
        reasons = "; ".join(t["reasons"][:4])
        lines.append(f"[{t['score']:>5}]  {t['url']}  — {reasons}")
    if not targets:
        lines.append("# (nothing scored — no findings/params/dirsearch hits)")
    return "\n".join(lines) + "\n"


def _noise_urls(output_dir: Path) -> set[str]:
    """``host+path`` keys (see :func:`_host_path`) whose real probed
    response matches their own host's not-found shape — SPA-fallback /
    blanket-WAF noise, regardless of which stage produced the URL
    (dirsearch, ffuf, or one jsluice mined out of a JS bundle: those are
    verified by ``jsluice_verify.py`` and merged into
    ``alive_urls_detail.json``, but never screened against a baseline the
    way dirsearch/ffuf's own hits are).
    """
    baselines = baseline.load_from_raw(output_dir)
    if not baselines:
        return set()
    rows = load_json(layout.path(output_dir, "alive_urls_detail.json")) or []
    if not isinstance(rows, list):
        return set()
    noise: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = row.get("url") or ""
        bl = baselines.get(_host_of(url))
        if bl and bl.consistent and bl.is_noise(baseline.row_to_behavior(row)):
            noise.add(_host_path(url))
    return noise


def build_priority_targets(output_dir: Path, domain: str, *, limit: int = 200) -> dict:
    """Read the canonical output files, rank, and write the report file.

    Output: ``report/priority_targets.txt`` (+ the ranked list in the
    result's ``extra`` for the caller to echo the top few to the console).
    """
    findings = output_dir / "findings"

    nuclei: list[dict] = []
    for kind in ("default", "endpoints", "dynamic"):
        data = load_json(findings / kind / "nuclei.json") or {}
        nuclei.extend(data.get("findings", []) if isinstance(data, dict) else [])

    secrets_data = load_json(findings / "jsluice_secrets.json") or {}
    secrets = secrets_data.get("findings", []) if isinstance(secrets_data, dict) else []

    misconfig_data = load_json(findings / "misconfig_probe.json") or {}
    misconfig = misconfig_data.get("findings", []) if isinstance(misconfig_data, dict) else []

    forms_data = load_json(layout.path(output_dir, "forms.json")) or {}
    forms = forms_data.get("forms", []) if isinstance(forms_data, dict) else []

    targets = score_targets(
        nuclei_findings=nuclei,
        secrets=secrets,
        misconfig_findings=misconfig,
        forms=forms,
        parameterized_urls=read_lines(layout.path(output_dir, "parameterized_urls.txt")),
        dirsearch_urls=read_lines(layout.path(output_dir, "dirsearch_urls.txt")),
        ffuf_urls=read_lines(layout.path(output_dir, "ffuf_urls.txt")),
        extra_urls=(read_lines(layout.path(output_dir, "jsluice_endpoints.txt"))
                    + read_lines(layout.path(output_dir, "jsluice_urls.txt"))),
        blanket_hosts=set(asm_report.detect_blanket_deny(output_dir)),
        noise_urls=_noise_urls(output_dir),
        limit=limit,
    )

    out_path = output_dir / "report" / "priority_targets.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(targets, domain), encoding="utf-8")

    return make_result(
        "priority_targets", "success", input_path=domain,
        outputs=[out_path], count=len(targets),
        extra={"targets": targets, "top": targets[:10]},
    )
