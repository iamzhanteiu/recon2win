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

Everything here is deterministic and unit-tested: ``score_targets`` is a
pure function over already-loaded data; ``build_priority_targets`` is the
thin I/O wrapper that reads the canonical files and writes the report.
"""
from __future__ import annotations

from pathlib import Path

from .utils import load_json, make_result, read_lines


# Severity → score for nuclei findings and jsluice secrets. ``info`` is
# deliberately low: an info finding alone shouldn't crowd the top.
_SEV_SCORE: dict[str, int] = {
    "critical": 1000,
    "high":      800,
    "medium":    400,
    "low":       120,
    "info":      15,
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
)

_PARAM_SCORE = 300       # a URL carrying params = injection surface
_DIRSEARCH_SCORE = 220   # passed dirsearch's status filter = exists + interesting
_FFUF_SCORE = 220        # same signal from ffuf (auto-calibrated, so soft-404s are already gone)


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
    parameterized_urls: list[str] | None = None,
    dirsearch_urls: list[str] | None = None,
    ffuf_urls: list[str] | None = None,
    extra_urls: list[str] | None = None,
    limit: int = 200,
) -> list[dict]:
    """Rank URLs by manual-testing value. Pure — no I/O.

    Returns a list of ``{url, score, reasons}`` sorted by score desc then
    URL (stable), capped at ``limit``. A URL that appears in several
    sources accumulates their scores and collects each reason once.
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


def build_priority_targets(output_dir: Path, domain: str, *, limit: int = 200) -> dict:
    """Read the canonical output files, rank, and write the report file.

    Output: ``report/priority_targets.txt`` (+ the ranked list in the
    result's ``extra`` for the caller to echo the top few to the console).
    """
    proc = output_dir / "processed"
    findings = output_dir / "findings"

    nuclei: list[dict] = []
    for kind in ("default", "endpoints", "dynamic"):
        data = load_json(findings / kind / "nuclei.json") or {}
        nuclei.extend(data.get("findings", []) if isinstance(data, dict) else [])

    secrets_data = load_json(findings / "jsluice_secrets.json") or {}
    secrets = secrets_data.get("findings", []) if isinstance(secrets_data, dict) else []

    targets = score_targets(
        nuclei_findings=nuclei,
        secrets=secrets,
        parameterized_urls=read_lines(proc / "parameterized_urls.txt"),
        dirsearch_urls=read_lines(proc / "dirsearch_urls.txt"),
        ffuf_urls=read_lines(proc / "ffuf_urls.txt"),
        extra_urls=(read_lines(proc / "jsluice_endpoints.txt")
                    + read_lines(proc / "jsluice_urls.txt")),
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
