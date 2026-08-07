"""asm_report — the final ASM report: raw scan output → actionable intelligence.

``modules/report.py`` already writes ``report/final_report.html`` — a faithful
dump of what every stage produced. Useful, but it answers "what did the scan
find?" rather than "what do I test first, and can I trust this?".

This module writes ``report/asm_report.html``: the same data, correlated and
ranked, in the shape a pentester / bug hunter actually works from. It reads
only files a completed run already wrote — it never scans, never fetches.

Design notes live in ``docs/report-design.md``. The four things this module
does that ``report.py`` does not:

  1. **Blanket-deny detection.** A host that answers every path with the same
     response is a WAF, not a discovery. On acronis.com, 4,097 of 4,099 ffuf
     hits on ``web-api-arp`` were an identical 403 — and ``.git/config`` there
     scored 770 in ``priority_targets.txt``. Those hits get confidence 0.1.
  2. **Scope gate.** ``elearning.unyp.cz`` appeared in acronis.com's priority
     list. Out-of-scope hosts are pulled out into their own section rather
     than silently ranked.
  3. **Multiplicative scoring.** ``score = BASE x CONFIDENCE x EXPOSURE x
     CONTEXT``, so a low-confidence or low-value signal cannot accumulate its
     way to the top the way additive scoring lets it.
  4. **Confidence surfacing.** A failed stage downgrades every metric it fed,
     everywhere — so "0 findings" never reads as "clean" when the scanner
     never finished.

Standalone::

    python3 -m modules.asm_report outputs/acronis.com
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from html import escape
from pathlib import Path
from typing import Any

from . import layout
from .utils import load_json, make_result, now_iso

# ----------------------------------------------------------------------
# Tunables
# ----------------------------------------------------------------------

# A host whose ffuf hits are >= this fraction identical is answering
# uniformly — a blanket deny/redirect, not a set of discoveries.
_BLANKET_RATIO = 0.5
_BLANKET_MIN_HITS = 10

# Strongest-signal base scores. Unlike priority.py these do NOT sum: the
# top signal sets the base, every other signal adds only 15% of its own
# value. Twenty weak keyword hits can no longer outrank one verified finding.
_BASE = {
    "nuclei_critical": 1000,
    "nuclei_high": 800,
    "secret_exploitable": 700,
    "nuclei_medium": 400,
    "form_auth": 450,
    "endpoint_api": 300,
    "param": 200,
    "content_hit": 150,
    "nuclei_low": 120,
    "nuclei_info": 15,
}
_SECONDARY_WEIGHT = 0.15

# Evidence quality. This is the factor that kills the blanket-deny FPs.
_CONFIDENCE = {
    "nuclei": 1.00,       # matcher fired, request+response captured
    "form": 0.90,         # parsed out of real HTML
    "endpoint_live": 0.70,
    "endpoint_static": 0.40,
    "content_hit": 0.60,
    "blanket_deny": 0.10,
}

# Business value of the host, by hostname shape. The 0.5 on docs/marketing
# is what stops a vendor's own product noun (Acronis + "backup") from
# flooding the ranking.
_CONTEXT: tuple[tuple[str, float, str], ...] = (
    (r"(^|[.\-])(internal|intranet|corp)", 1.5, "internal"),
    (r"(^|[.\-])(admin|adm)\d*[.\-]", 1.5, "admin"),
    (r"(^|[.\-])vpn", 1.5, "vpn"),
    (r"(^|[.\-])(dev|stag|staging|uat|qa|preprod|sandbox|test|beta)", 1.4, "dev/staging"),
    (r"(^|[.\-])(api|gateway|graphql)", 1.3, "api"),
    (r"(^|[.\-])(auth|sso|login|account|oauth|idp)", 1.3, "auth"),
    (r"(kibana|grafana|jenkins|gitlab|jira|console|portal|dashboard)", 1.4, "infra panel"),
    (r"(^|[.\-])(s3|storage|backup|upload|files|dl)", 1.2, "storage"),
    # Deliberately NOT downgraded: care/support/portal hold customer data.
    # Only genuine publishing surfaces get the penalty that neutralises a
    # vendor's own product noun (Acronis + "backup" → 189 KB articles).
    (r"(^|[.\-])(docs?|kb|blog|help|learn|academy|wiki|news|press)", 0.5, "docs/marketing"),
    (r"^www\d*\.", 0.8, "marketing"),
)

# Secrets are scored by their own severity, not a flat "it's a secret" base.
# A GCP browser key in client JS is by design; treating it as exploitable
# put two unverified keys above a confirmed nuclei finding.
_SECRET_BASE = {"critical": 900, "high": 700, "medium": 350, "low": 140, "info": 40}

# Exposure, from the observed HTTP response.
_EXPOSURE_BY_STATUS = {2: 1.0, 3: 0.6, 4: 0.8, 5: 0.3}

# Path keywords worth a look. Weight is IDF-scaled at runtime against the
# target's own URL corpus, so a vendor's product noun self-neutralises.
_PATH_HINTS: tuple[tuple[str, int, str], ...] = (
    (".env", 350, "env file"),
    ("/.git", 350, "git dir"),
    (".sql", 320, "sql dump"),
    ("actuator", 300, "spring actuator"),
    ("graphql", 300, "graphql"),
    ("/debug", 260, "debug endpoint"),
    ("swagger", 240, "api docs"),
    ("/api-docs", 240, "api docs"),
    ("/admin", 240, "admin"),
    ("phpmyadmin", 240, "db admin"),
    ("/upload", 220, "upload"),
    ("backup", 200, "backup"),
    (".bak", 200, "backup"),
    ("/internal", 200, "internal"),
    ("/config", 180, "config"),
    ("/login", 160, "login"),
    ("/auth", 160, "auth"),
    ("/api/", 150, "api"),
    ("token", 140, "token"),
    ("redirect", 140, "open-redirect candidate"),
    ("/v1/", 110, "versioned api"),
    ("/v2/", 110, "versioned api"),
)

# Stage -> which report areas depend on it, for the confidence panel.
_STAGE_FEEDS = {
    "subdomain": "Subdomain enumeration",
    "dnsx": "DNS resolution",
    "httpx_alive": "Host probing",
    "content_discovery": "Content discovery",
    "dirsearch": "Content discovery",
    "ffuf": "Content discovery",
    "waymore": "Content discovery",
    "httpx_urls": "URL probing",
    "jsluice": "JavaScript analysis",
    "xnlinkfinder": "Endpoint extraction",
    "arjun": "Parameter discovery",
    "nuclei_default": "Vulnerability scanning",
    "nuclei_endpoints": "Vulnerability scanning",
    "nuclei_dynamic": "Vulnerability scanning",
}

# Framework fingerprints, read off form field names. httpx's tech[] rarely
# carries a version, so form fields are often the sharper signal.
_FRAMEWORK_BY_FIELD = (
    ("__VIEWSTATE", "ASP.NET WebForms", "ViewState deserialization (check MAC + ViewStateUserKey)"),
    ("__RequestVerificationToken", "ASP.NET MVC", "CSRF token validation"),
    ("csrfmiddlewaretoken", "Django", "CSRF, user enumeration on login"),
    ("form_build_id", "Drupal", "Drupalgeddon, form cache poisoning"),
    ("authenticity_token", "Rails", "CSRF, mass assignment"),
    ("_token", "Laravel", "CSRF, debug mode exposure"),
)

# Includes nuclei's ``unknown`` (template with no severity declared) — the
# scan runs those templates, and ``_SEV_ORDER.index()`` sorts the issue
# cards, so a severity missing from this tuple is a ValueError mid-render.
_SEV_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


# ----------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------
def canon(url: str) -> str:
    """Canonical URL form, so joins and counts stop double-counting.

    Fixes seen in real output: ``/./Login.aspx`` and ``/Frames/../Login.aspx``
    ranked as two separate login pages on expenses.acronis.com.
    """
    u = (url or "").strip()
    if not u:
        return ""
    m = re.match(r"^(https?://)([^/]+)(.*)$", u, re.I)
    if not m:
        return u
    scheme, host, rest = m.group(1).lower(), m.group(2).lower(), m.group(3)
    host = re.sub(r":443$", "", host) if scheme == "https://" else re.sub(r":80$", "", host)
    path, _, query = rest.partition("?")
    while "/./" in path:
        path = path.replace("/./", "/")
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    if query:
        parts = sorted(query.split("&"))
        query = "&".join(parts)
        return f"{scheme}{host}{path}?{query}"
    return f"{scheme}{host}{path}"


def url_host(url: str) -> str:
    m = re.match(r"^https?://([^/:]+)", (url or "").strip(), re.I)
    return m.group(1).lower() if m else ""


def in_scope(host: str, domain: str) -> bool:
    """True when *host* belongs to the scanned domain."""
    h = (host or "").lower().rstrip(".")
    d = (domain or "").lower().rstrip(".")
    return bool(h) and (h == d or h.endswith("." + d))


def classify_context(host: str) -> tuple[float, str]:
    """Business-value multiplier for a hostname, plus its label."""
    h = (host or "").lower()
    best = (1.0, "standard")
    for pat, mult, label in _CONTEXT:
        if re.search(pat, h):
            # Highest multiplier wins, but an explicit downgrade (<1) only
            # applies when nothing more interesting matched.
            if mult > best[0] or (best[0] == 1.0 and mult < 1.0):
                best = (mult, label)
    return best


def exposure_factor(status: int | None, tech: list[str] | None, cdn: str | None) -> float:
    if not status:
        return 0.5
    f = _EXPOSURE_BY_STATUS.get(status // 100, 0.5)
    techs = " ".join(tech or []).lower()
    if "bot management" in techs or "bot manager" in techs:
        f *= 0.6   # bot protection in front = harder to reach, not safer
    elif not cdn or cdn == "none":
        f *= 1.2   # directly exposed origin
    return f


# ----------------------------------------------------------------------
# Loading + core analysis
# ----------------------------------------------------------------------
def _load(path: Path, default: Any = None) -> Any:
    try:
        if not path.exists():
            return default
        return load_json(path)
    except Exception:
        return default


def _lines(path: Path) -> list[str]:
    try:
        if not path.exists():
            return []
        with path.open(encoding="utf-8", errors="replace") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except Exception:
        return []


def detect_blanket_deny(target_dir: Path) -> dict[str, dict]:
    """Hosts whose content-discovery hits are one repeated response.

    Returns ``{host: {hits, dominant, share, status, words}}``. Every URL on
    such a host gets ``_CONFIDENCE['blanket_deny']`` — this is what drops a
    WAF's uniform 403 on ``/.git/config`` out of the ranking.
    """
    out: dict[str, dict] = {}
    ffuf_dir = target_dir / "raw" / "ffuf"
    if not ffuf_dir.is_dir():
        return out
    for f in sorted(ffuf_dir.glob("*.json")):
        data = _load(f, {}) or {}
        results = data.get("results") or []
        if len(results) < _BLANKET_MIN_HITS:
            continue
        sig = Counter((r.get("status"), r.get("words")) for r in results)
        (status, words), n = sig.most_common(1)[0]
        share = n / len(results)
        if share >= _BLANKET_RATIO:
            out[f.stem.lower()] = {
                "hits": len(results), "dominant": n, "share": share,
                "status": status, "words": words,
            }
    return out


def dedup_secrets(findings: list[dict]) -> list[dict]:
    """Collapse secret findings by their actual value.

    acronis.com reports 9 secrets that are 3 distinct GCP keys; discover.com
    reports 11 that are 3. The same JS bundle served from several hosts is
    one leak, not N.
    """
    groups: dict[str, dict] = {}
    for f in findings or []:
        key = json.dumps(f.get("data"), sort_keys=True)
        g = groups.setdefault(key, {
            "kind": f.get("kind"), "severity": f.get("severity"),
            "value": f.get("data"), "urls": [], "hosts": set(), "count": 0,
        })
        g["count"] += 1
        u = f.get("url") or ""
        if u not in g["urls"]:
            g["urls"].append(u)
        g["hosts"].add(url_host(u))
    for g in groups.values():
        g["hosts"] = sorted(h for h in g["hosts"] if h)
    return sorted(groups.values(), key=lambda g: -g["count"])


def stage_health(stages: list[dict]) -> dict:
    """Per-area confidence derived from stage outcomes."""
    areas: dict[str, dict] = defaultdict(lambda: {"ok": 0, "bad": 0, "notes": []})
    broken = []
    for st in stages or []:
        name = st.get("stage") or ""
        area = _STAGE_FEEDS.get(name)
        status = (st.get("status") or "").lower()
        err = st.get("error") or ""
        degraded = status != "success" or bool(err)
        if area:
            areas[area]["bad" if degraded else "ok"] += 1
            if degraded:
                areas[area]["notes"].append(f"{name}: {err or status}")
        if degraded:
            broken.append({"stage": name, "status": status, "error": err,
                           "elapsed": (st.get("extra") or {}).get("elapsed_seconds")})
    scored = {}
    for area, v in areas.items():
        total = v["ok"] + v["bad"]
        scored[area] = {
            "confidence": (v["ok"] / total) if total else 0.0,
            "notes": v["notes"],
        }
    overall = (sum(a["confidence"] for a in scored.values()) / len(scored)) if scored else 0.0
    return {"areas": scored, "broken": broken, "overall": overall}


def idf_weights(urls: list[str]) -> dict[str, float]:
    """Scale each path keyword by how rare it is in *this* target's corpus.

    A vendor whose product noun is "backup" should not have every KB article
    outrank real findings. Measured on acronis.com: "backup" appears in 5.1%
    of URLs, so its weight drops to ~43%.
    """
    n = max(len(urls), 1)
    blob = "\n".join(urls).lower()
    out = {}
    for kw, _, _ in _PATH_HINTS:
        df = blob.count(kw.lower())
        frac = min(max(df / n, 1e-4), 1.0)
        out[kw] = max(math.log(1.0 / frac) / math.log(1.0 / 1e-3), 0.1)
    return out


# ----------------------------------------------------------------------
# Model
# ----------------------------------------------------------------------
def build_model(target_dir: Path) -> dict:
    """Read every artefact a finished run left behind and correlate it."""
    target_dir = Path(target_dir)
    rep = target_dir / "report"
    find = target_dir / "findings"

    summary = _load(rep / "summary.json", {}) or {}
    meta = summary.get("meta") or {}
    domain = meta.get("domain") or target_dir.name

    stages = _load(target_dir / "logs" / "stages.json", []) or []
    health = stage_health(stages)

    hosts = _load(layout.path(target_dir, "alive_detail.json"), []) or []
    dns = _load(layout.path(target_dir, "resolved_detail.json"), []) or []
    urls_detail = _load(layout.path(target_dir, "alive_urls_detail.json"), []) or []
    forms = (_load(layout.path(target_dir, "forms.json"), {}) or {}).get("forms") or []
    params = _load(layout.path(target_dir, "jsluice_params.json"), []) or []
    js_verified = _load(layout.path(target_dir, "jsluice_alive_detail.json"), []) or []

    subdomains = _lines(layout.path(target_dir, "subdomains.txt"))
    all_urls = _lines(layout.path(target_dir, "all_urls.txt"))
    js_urls = _lines(layout.path(target_dir, "js_urls.txt"))
    endpoints = _lines(layout.path(target_dir, "jsluice_endpoints.txt")) + _lines(layout.path(target_dir, "xnlinkfinder_endpoints.txt"))
    param_urls = _lines(layout.path(target_dir, "parameterized_urls.txt"))
    ffuf_urls = _lines(layout.path(target_dir, "ffuf_urls.txt"))
    dirsearch_urls = _lines(layout.path(target_dir, "dirsearch_urls.txt"))

    nuclei: list[dict] = []
    for kind in ("default", "endpoints", "dynamic"):
        blob = _load(find / kind / "nuclei.json", {}) or {}
        for f in blob.get("findings") or []:
            f = dict(f)
            f["_source"] = kind
            nuclei.append(f)
    secrets_raw = (_load(find / "jsluice_secrets.json", {}) or {}).get("findings") or []

    blanket = detect_blanket_deny(target_dir)
    idf = idf_weights(all_urls or [h.get("url", "") for h in hosts])

    # ---- host index -------------------------------------------------
    hindex: dict[str, dict] = {}
    for h in hosts:
        name = (h.get("host") or url_host(h.get("url", ""))).lower()
        if not name:
            continue
        ctx_mult, ctx_label = classify_context(name)
        hindex[name] = {
            "host": name,
            "url": h.get("url"),
            "status": h.get("status_code"),
            "tech": h.get("tech") or [],
            "webserver": h.get("webserver"),
            "cdn": h.get("cdn_name"),
            "ip": h.get("host_ip"),
            "content_type": h.get("content_type"),
            "content_length": h.get("content_length"),
            "ctx_mult": ctx_mult, "ctx_label": ctx_label,
            "in_scope": in_scope(name, domain),
            "blanket": name in blanket,
            "urls": 0, "js": 0, "forms": 0, "endpoints": 0,
            "findings": 0, "secrets": 0,
        }

    def bump(host: str, field: str, n: int = 1) -> None:
        rec = hindex.get(host)
        if rec:
            rec[field] += n

    for u in _lines(layout.path(target_dir, "alive_urls.txt")):
        bump(url_host(u), "urls")
    for u in js_urls:
        bump(url_host(u), "js")
    for f in forms:
        bump(url_host(f.get("url") or ""), "forms")
    for f in nuclei:
        bump((f.get("host") or "").lower(), "findings")

    secrets = dedup_secrets(secrets_raw)
    for s in secrets:
        for h in s["hosts"]:
            bump(h, "secrets")

    # ---- out of scope -----------------------------------------------
    # all_urls.txt is already scope-filtered, so scanning only that finds
    # nothing. The leak seen in priority_targets.txt (elearning.unyp.cz on
    # acronis.com) came in via forms and content-discovery, which are not
    # filtered — so every source has to be checked.
    oos: Counter = Counter()
    oos_src: dict[str, set] = defaultdict(set)
    for label, seq in (
        ("urls", all_urls), ("forms", [f.get("url") or "" for f in forms]),
        ("form actions", [f.get("action") or "" for f in forms]),
        ("ffuf", ffuf_urls), ("dirsearch", dirsearch_urls),
        ("js", js_urls), ("params", [p.get("url") or "" for p in params]),
        ("nuclei", [f.get("matched-at") or f.get("url") or "" for f in nuclei]),
        ("secrets", [s.get("url") or "" for s in secrets_raw]),
    ):
        for u in seq:
            h = url_host(u)
            if h and not in_scope(h, domain):
                oos[h] += 1
                oos_src[h].add(label)

    # ---- JS duplicate ratio -----------------------------------------
    js_dir = target_dir / "raw" / "jsluice"
    js_files, js_dupes = 0, 0
    if js_dir.is_dir():
        by_hash: Counter = Counter()
        for p in js_dir.glob("*.js"):
            js_files += 1
            try:
                by_hash[hashlib.md5(p.read_bytes()).hexdigest()] += 1
            except Exception:
                continue
        js_dupes = sum(c - 1 for c in by_hash.values() if c > 1)

    return {
        "domain": domain, "meta": meta, "dir": str(target_dir),
        "summary": summary, "stages": stages, "health": health,
        "hosts": hosts, "hindex": hindex, "dns": dns,
        "urls_detail": urls_detail, "forms": forms, "params": params,
        "js_verified": js_verified,
        "subdomains": subdomains, "all_urls": all_urls, "js_urls": js_urls,
        "endpoints": endpoints, "param_urls": param_urls,
        "ffuf_urls": ffuf_urls, "dirsearch_urls": dirsearch_urls,
        "nuclei": nuclei, "secrets": secrets, "secrets_raw": secrets_raw,
        "blanket": blanket, "idf": idf, "oos": oos,
        "oos_src": {h: sorted(v) for h, v in oos_src.items()},
        "js_files": js_files, "js_dupes": js_dupes,
    }


# ----------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------
def score_targets(model: dict, limit: int = 25, per_host: int = 2) -> list[dict]:
    """Rank URLs worth manual testing: BASE x CONFIDENCE x EXPOSURE x CONTEXT."""
    domain = model["domain"]
    hindex = model["hindex"]
    blanket = model["blanket"]
    idf = model["idf"]
    bucket: dict[str, dict] = {}

    def add(url: str, base: int, conf: float, reason: str, verified: bool = False) -> None:
        u = canon(url)
        if not u:
            return
        host = url_host(u)
        if not in_scope(host, domain):
            return
        rec = bucket.setdefault(u, {
            "url": u, "host": host, "signals": [], "base": 0,
            "conf": 0.0, "extra": 0.0, "verified": False,
        })
        rec["signals"].append(reason)
        rec["verified"] = rec["verified"] or verified
        if base > rec["base"]:
            rec["extra"] += rec["base"] * _SECONDARY_WEIGHT
            rec["base"] = base
        else:
            rec["extra"] += base * _SECONDARY_WEIGHT
        rec["conf"] = max(rec["conf"], conf)

    # nuclei — the only fully verified signal
    for f in model["nuclei"]:
        sev = ((f.get("info") or {}).get("severity") or "info").lower()
        base = _BASE.get(f"nuclei_{sev}", _BASE["nuclei_info"])
        name = (f.get("info") or {}).get("name") or f.get("template-id") or "nuclei"
        add(f.get("matched-at") or f.get("url") or "", base, _CONFIDENCE["nuclei"],
            f"nuclei {sev}: {name}", verified=True)

    # secrets — value already deduped, scored by the secret's own severity
    for s in model["secrets"]:
        sev = (s.get("severity") or "low").lower()
        base = _SECRET_BASE.get(sev, _SECRET_BASE["low"])
        for u in s["urls"][:5]:
            add(u, base, _CONFIDENCE["nuclei"],
                f"secret in JS: {s['kind']} ({sev}, x{s['count']})")

    # forms — real input surface
    for f in model["forms"]:
        fields = f.get("parameters") or []
        has_pw = any("pass" in (p or "").lower() for p in fields)
        base = _BASE["form_auth"] if has_pw else int(_BASE["form_auth"] * 0.6)
        label = "login form" if has_pw else f"form {f.get('method', 'GET')}"
        add(f.get("url") or "", base, _CONFIDENCE["form"],
            f"{label} ({len(fields)} fields)")

    # parameterised URLs — injection surface
    for u in model["param_urls"][:4000]:
        add(u, _BASE["param"], _CONFIDENCE["endpoint_live"], "parameterized")

    # content-discovery hits — blanket-deny hosts get near-zero confidence
    for u in (model["ffuf_urls"] + model["dirsearch_urls"])[:8000]:
        h = url_host(u)
        conf = _CONFIDENCE["blanket_deny"] if h in blanket else _CONFIDENCE["content_hit"]
        note = "content hit (blanket-deny host)" if h in blanket else "content hit"
        add(u, _BASE["content_hit"], conf, note)

    # path keywords, IDF-scaled
    for u in list(bucket.keys()):
        low = u.lower()
        for kw, weight, label in _PATH_HINTS:
            if kw in low:
                scaled = int(weight * idf.get(kw, 1.0))
                if scaled >= 20:
                    add(u, scaled, bucket[u]["conf"] or 0.4, label)

    out = []
    for rec in bucket.values():
        h = hindex.get(rec["host"], {})
        ctx_mult = h.get("ctx_mult") or classify_context(rec["host"])[0]
        ctx_label = h.get("ctx_label") or classify_context(rec["host"])[1]
        expo = exposure_factor(h.get("status"), h.get("tech"), h.get("cdn"))
        conf = rec["conf"] or 0.4
        if rec["host"] in blanket:
            conf = min(conf, _CONFIDENCE["blanket_deny"])
        # A confirmed vulnerability is not less real because it sits on a
        # host the hostname heuristic considers low-value. Verified findings
        # never take the context penalty.
        if rec["verified"]:
            ctx_mult = max(ctx_mult, 1.0)
        score = (rec["base"] + rec["extra"]) * conf * expo * ctx_mult
        out.append({
            **rec, "score": round(score), "ctx": ctx_label,
            "conf_used": round(conf, 2), "expo": round(expo, 2),
            "ctx_mult": ctx_mult,
            "signals": sorted(set(rec["signals"]))[:6],
        })
    out.sort(key=lambda r: -r["score"])

    # Four near-identical login URLs on one host is one lead, not four.
    # Cap per host so the list spreads across the estate; the full ranking
    # is still available by passing per_host=0.
    if per_host:
        seen: Counter = Counter()
        capped, overflow = [], []
        for r in out:
            if seen[r["host"]] < per_host:
                seen[r["host"]] += 1
                capped.append(r)
            else:
                overflow.append(r)
        if capped:
            capped[0]["_suppressed"] = len(overflow)
        out = capped
    return out[:limit]


def rank_assets(model: dict, limit: int = 20) -> list[dict]:
    """Rank hosts by how much application there is to attack.

    Log-scaled on volume: a 12,000-URL marketing site should not bury a
    2-URL Kibana instance.
    """
    out = []
    for h in model["hindex"].values():
        if not h["in_scope"]:
            continue
        raw = (
            50 * math.log2(1 + h["urls"])
            + 40 * math.log2(1 + h["js"])
            + 120 * h["forms"]
            + 200 * h["findings"]
            + 150 * h["secrets"]
        )
        expo = exposure_factor(h["status"], h["tech"], h["cdn"])
        conf = _CONFIDENCE["blanket_deny"] if h["blanket"] else 1.0
        out.append({**h, "score": round(raw * h["ctx_mult"] * expo * conf)})
    out.sort(key=lambda r: -r["score"])
    return out[:limit]


def analyse_forms(model: dict) -> dict:
    """Auth/input surface, with the framework inferred from field names."""
    forms = model["forms"]
    fw: Counter = Counter()
    fw_hint: dict[str, str] = {}
    pw, post, upload = [], 0, 0
    for f in forms:
        fields = f.get("parameters") or []
        if (f.get("method") or "").upper() == "POST":
            post += 1
        if "multipart" in (f.get("enctype") or "").lower():
            upload += 1
        if any("pass" in (p or "").lower() for p in fields):
            pw.append(f)
        for marker, name, hint in _FRAMEWORK_BY_FIELD:
            if any(marker.lower() == (p or "").lower() for p in fields):
                fw[name] += 1
                fw_hint[name] = hint
    return {
        "total": len(forms), "post": post, "password": pw, "upload": upload,
        "frameworks": fw.most_common(), "hints": fw_hint,
        "fields": Counter(p for f in forms for p in (f.get("parameters") or [])).most_common(15),
    }


def analyse_endpoints(model: dict) -> dict:
    """API-shaped patterns in everything extracted from JavaScript."""
    pats = (
        ("graphql", r"graphql"), ("swagger/openapi", r"swagger|openapi|api-docs"),
        ("admin route", r"/admin"), ("upload", r"/upload"),
        ("oauth", r"/oauth"), ("token", r"/token"), ("jwt", r"/jwt"),
        ("debug", r"/debug"), ("internal", r"/internal"),
        ("health/metrics", r"/health|/metrics|actuator"),
    )
    blob = "\n".join(model["endpoints"]).lower()
    hits = {label: len(re.findall(rx, blob)) for label, rx in pats}
    versions = Counter(m for m in re.findall(r"/v(\d)/", blob))
    return {"patterns": {k: v for k, v in hits.items() if v},
            "versions": sorted(versions.items()),
            "total": len(model["endpoints"])}


def data_quality(model: dict) -> list[dict]:
    """The checks that decide whether the numbers above can be trusted."""
    out = []
    hosts = model["hosts"]
    n_hosts = len(hosts) or 1

    for host, b in sorted(model["blanket"].items(), key=lambda kv: -kv[1]["hits"]):
        out.append({
            "sev": "high", "check": "Blanket-deny content discovery",
            "detail": (f"{host}: {b['dominant']:,}/{b['hits']:,} hits ({b['share']:.0%}) "
                       f"identical (status {b['status']}, {b['words']} words)"),
            "impact": "Content discovery on this host found nothing. Its hits are "
                      "scored at 0.1 confidence and must not be read as discoveries.",
        })

    if model["oos"]:
        top = ", ".join(f"{h} ({n})" for h, n in model["oos"].most_common(5))
        out.append({
            "sev": "high", "check": "Out-of-scope hosts observed",
            "detail": f"{len(model['oos'])} host(s) outside {model['domain']}: {top}",
            "impact": "Excluded from all ranking. Confirm scope before testing — "
                      "third-party assets in a client report are a legal risk.",
        })

    for b in model["health"]["broken"]:
        out.append({
            "sev": "high" if b["status"] == "failed" else "medium",
            "check": f"Stage degraded: {b['stage']}",
            "detail": f"status={b['status']} elapsed={b['elapsed']}s error={b['error'][:120]}",
            "impact": f"{_STAGE_FEEDS.get(b['stage'], 'This area')} is incomplete. "
                      "Absence of results here is not evidence of absence.",
        })

    n404 = sum(1 for h in hosts if (h.get("status_code") or 0) == 404)
    if n404 / n_hosts > 0.6:
        out.append({
            "sev": "high", "check": "Most 'alive' hosts return 404",
            "detail": f"{n404}/{n_hosts} ({n404/n_hosts:.0%}) respond 404",
            "impact": "Likely wildcard DNS or a catch-all. The alive-host count "
                      "overstates the real attack surface.",
        })

    raw, uniq = len(model["secrets_raw"]), len(model["secrets"])
    if uniq and raw / uniq >= 2:
        out.append({
            "sev": "medium", "check": "Secret findings inflated by duplication",
            "detail": f"{raw} findings collapse to {uniq} distinct values ({raw/uniq:.1f}x)",
            "impact": "Report the distinct count. The same bundle served from "
                      "several hosts is one leak.",
        })

    if model["js_dupes"]:
        out.append({
            "sev": "low", "check": "Duplicate JavaScript bundles",
            "detail": f"{model['js_dupes']}/{model['js_files']} downloaded JS files "
                      f"are byte-identical copies",
            "impact": "Deduplicate by content hash before quoting JS volume.",
        })

    if model["blanket"]:
        polluted = sum(b["hits"] for b in model["blanket"].values())
        total = len(model["ffuf_urls"]) or 1
        if polluted / total > 0.3:
            out.append({
                "sev": "high", "check": "Content-discovery corpus polluted",
                "detail": f"{polluted:,}/{total:,} ({polluted/total:.0%}) of ffuf URLs "
                          "come from blanket-deny hosts",
                "impact": "URL counts and status distributions are inflated by this margin.",
            })

    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda r: order.get(r["sev"], 3))
    return out


# ----------------------------------------------------------------------
# HTML rendering
# ----------------------------------------------------------------------
_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#0a0a0c;color:#e8e8ec;
 font:14px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:#00d4ff;text-decoration:none}a:hover{text-decoration:underline}
code,pre{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:12.5px}
.wrap{max-width:1180px;margin:0 auto;padding:32px 24px 80px}
header.top{border-bottom:1px solid #26262c;padding-bottom:20px;margin-bottom:8px}
h1{font-size:26px;margin:0 0 6px;letter-spacing:-.3px}
h2{font-size:19px;margin:44px 0 14px;padding-top:14px;border-top:1px solid #26262c;
 letter-spacing:-.2px}
h3{font-size:15px;margin:24px 0 10px;color:#e8e8ec}
.sub{color:#9a9aa4;font-size:13px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin:18px 0}
.tile{background:#111114;border:1px solid #26262c;border-radius:10px;padding:14px 16px}
.tile .k{color:#9a9aa4;font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.tile .v{font-size:26px;font-weight:600;margin-top:4px;letter-spacing:-.5px}
.tile .d{color:#6b6b75;font-size:11.5px;margin-top:2px}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}
th{text-align:left;color:#9a9aa4;font-weight:500;font-size:11px;text-transform:uppercase;
 letter-spacing:.5px;border-bottom:1px solid #35353d;padding:8px 10px}
td{padding:7px 10px;border-bottom:1px solid #1c1c21;vertical-align:top}
tr:hover td{background:#141418}
.tw{overflow-x:auto;border:1px solid #26262c;border-radius:10px;background:#111114}
.tw table{margin:0}
.pill{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;font-weight:600}
.critical{background:#ff3b5c22;color:#ff3b5c}.high{background:#ff7a2f22;color:#ff7a2f}
.medium{background:#ffb80022;color:#ffb800}.low{background:#4ec9f522;color:#4ec9f5}
.info{background:#8b8b9622;color:#8b8b96}.unknown{background:#6b6b7522;color:#8b8b96}
.ok{background:#3ecf8e22;color:#3ecf8e}.warn{background:#ffb80022;color:#ffb800}
.bad{background:#ff3b5c22;color:#ff3b5c}.mut{color:#6b6b75}
.card{background:#111114;border:1px solid #26262c;border-left:3px solid #00d4ff;
 border-radius:10px;padding:16px 18px;margin:12px 0}
.card.crit{border-left-color:#ff3b5c}.card.hi{border-left-color:#ff7a2f}
.card.med{border-left-color:#ffb800}
.card h4{margin:0 0 4px;font-size:14px;font-weight:600}
.card .u{font-family:ui-monospace,monospace;font-size:12.5px;color:#00d4ff;
 word-break:break-all;display:block;margin-bottom:10px}
.why{margin:8px 0 0;padding-left:18px;color:#c8c8d0}.why li{margin:2px 0}
.meta{color:#6b6b75;font-size:11.5px;margin-top:10px;
 border-top:1px solid #1c1c21;padding-top:8px}
.bar{height:6px;background:#1c1c21;border-radius:3px;overflow:hidden;
 min-width:70px;display:inline-block;vertical-align:middle}
.bar i{display:block;height:100%;background:#00d4ff}
.bar i.w{background:#ffb800}.bar i.b{background:#ff3b5c}
.note{background:#111114;border:1px solid #26262c;border-left:3px solid #ffb800;
 border-radius:8px;padding:12px 16px;margin:14px 0;color:#c8c8d0;font-size:13px}
.note.bad{border-left-color:#ff3b5c}
.note strong{color:#e8e8ec}
pre.ev{background:#08080a;border:1px solid #26262c;border-radius:8px;padding:10px 12px;
 overflow-x:auto;color:#9a9aa4;margin:8px 0 0}
nav.toc{background:#111114;border:1px solid #26262c;border-radius:10px;padding:14px 18px;
 margin:20px 0;columns:2;column-gap:28px;font-size:13px}
nav.toc a{display:block;padding:2px 0;color:#c8c8d0}
nav.toc a:hover{color:#00d4ff}
.mono{font-family:ui-monospace,monospace;font-size:12px}
.tag{display:inline-block;background:#1c1c21;color:#9a9aa4;border-radius:4px;
 padding:1px 6px;font-size:11px;margin:0 3px 3px 0}
footer{margin-top:56px;padding-top:18px;border-top:1px solid #26262c;
 color:#6b6b75;font-size:12px}
@media(max-width:720px){nav.toc{columns:1}.wrap{padding:20px 14px 60px}}
"""


_PILL_NONE = '<span class="pill warn">none</span>'
_MUT_NO = '<span class="mut">no</span>'


def _bar(frac: float) -> str:
    cls = "" if frac >= 0.8 else ("w" if frac >= 0.5 else "b")
    return (f'<span class="bar"><i class="{cls}" style="width:{frac*100:.0f}%"></i></span>'
            f' <span class="mut">{frac*100:.0f}%</span>')


def _sev_idx(sev: str) -> int:
    """Sort key for a severity string — anything unrecognised sorts last
    instead of raising, so a new nuclei severity can't kill the render."""
    try:
        return _SEV_ORDER.index((sev or "info").lower())
    except ValueError:
        return len(_SEV_ORDER)


def _sev_pill(sev: str) -> str:
    s = (sev or "info").lower()
    return f'<span class="pill {s}">{escape(s.upper())}</span>'


def render_html(model: dict) -> str:
    d = model["domain"]
    meta = model["meta"]
    health = model["health"]
    hosts = model["hosts"]
    top = score_targets(model)
    assets = rank_assets(model)
    forms = analyse_forms(model)
    eps = analyse_endpoints(model)
    dq = data_quality(model)

    n_hosts = len(hosts)
    n_urls = len(model["all_urls"])
    sev_count: Counter = Counter(
        ((f.get("info") or {}).get("severity") or "info").lower() for f in model["nuclei"])
    status_dist = Counter(h.get("status_code") for h in hosts)
    tech_dist = Counter(t for h in hosts for t in (h.get("tech") or []))
    ctx_dist = Counter(h["ctx_label"] for h in model["hindex"].values() if h["in_scope"])

    conf = health["overall"]
    conf_label = ("HIGH" if conf >= 0.9 else "PARTIAL" if conf >= 0.6 else "LOW")
    conf_cls = "ok" if conf >= 0.9 else "warn" if conf >= 0.6 else "bad"

    P: list[str] = []
    a = P.append

    a(f'<header class="top"><h1>Attack Surface Report — {escape(d)}</h1>'
      f'<div class="sub">{escape(str(meta.get("scan_start", "?"))[:19])} → '
      f'{escape(str(meta.get("scan_end", "?"))[:19])} · '
      f'mode {escape(str(meta.get("scan_mode", "?")))} · '
      f'generated {now_iso()}</div></header>')

    # ---- confidence banner -----------------------------------------
    a(f'<div class="grid">'
      f'<div class="tile"><div class="k">Confidence</div>'
      f'<div class="v"><span class="pill {conf_cls}">{conf*100:.0f} / {conf_label}</span></div>'
      f'<div class="d">{len(health["broken"])} stage(s) degraded</div></div>'
      f'<div class="tile"><div class="k">Subdomains</div><div class="v">{len(model["subdomains"]):,}</div></div>'
      f'<div class="tile"><div class="k">Alive hosts</div><div class="v">{n_hosts:,}</div></div>'
      f'<div class="tile"><div class="k">URLs</div><div class="v">{n_urls:,}</div></div>'
      f'<div class="tile"><div class="k">Findings</div><div class="v">{len(model["nuclei"])}</div>'
      f'<div class="d">{sum(sev_count[s] for s in ("critical", "high"))} crit/high</div></div>'
      f'<div class="tile"><div class="k">Secrets</div><div class="v">{len(model["secrets"])}</div>'
      f'<div class="d">distinct of {len(model["secrets_raw"])}</div></div>'
      f'</div>')

    if health["broken"]:
        items = "".join(
            f'<li><code>{escape(b["stage"])}</code> — {escape(b["status"])}'
            + (f': {escape(str(b["error"])[:110])}' if b["error"] else "")
            + f' → <em>{escape(_STAGE_FEEDS.get(b["stage"], "affected area"))}</em> incomplete</li>'
            for b in health["broken"])
        a(f'<div class="note bad"><strong>Read the findings with this in mind.</strong> '
          f'{len(health["broken"])} stage(s) did not complete cleanly:'
          f'<ul class="why">{items}</ul>'
          f'Absence of results in these areas is not evidence of absence.</div>')

    # ---- TOC --------------------------------------------------------
    toc = [("s1", "1. Executive Summary"), ("s2", "2. Scan Confidence"),
           ("s3", "3. Attack Surface"), ("s4", "4. Top Manual Testing Targets"),
           ("s5", "5. Confirmed Findings"), ("s6", "6. Secret Exposure"),
           ("s7", "7. High-Value Assets"), ("s8", "8. Auth & Input Surface"),
           ("s9", "9. API & Endpoint Intelligence"), ("s10", "10. Technology Distribution"),
           ("s11", "11. Pentest Intelligence"), ("s12", "12. Data Quality & Anomalies"),
           ("s13", "13. Out-of-Scope Observed"), ("s14", "14. Coverage Gaps")]
    a('<nav class="toc">' + "".join(
        f'<a href="#{i}">{escape(t)}</a>' for i, t in toc) + '</nav>')

    # ---- 1. exec summary --------------------------------------------
    a('<h2 id="s1">1. Executive Summary</h2>')
    dev = ctx_dist.get("dev/staging", 0)
    infra = ctx_dist.get("infra panel", 0) + ctx_dist.get("vpn", 0) + ctx_dist.get("internal", 0)
    crit_hi = sum(sev_count[s] for s in ("critical", "high"))
    vuln_conf = (health["areas"].get("Vulnerability scanning") or {}).get("confidence", 1.0)
    a(f'<p>The scan mapped <strong>{len(model["subdomains"]):,} subdomains</strong>, of which '
      f'<strong>{n_hosts:,}</strong> serve live HTTP, exposing <strong>{n_urls:,} URLs</strong>.</p>')
    if vuln_conf == 0 and not model["nuclei"]:
        # guildwars2.com: all three nuclei stages timed out and salvaged
        # nothing. Reporting "0 findings" here without saying so would be
        # the single most misleading sentence the report could produce.
        a('<p><strong>Vulnerability scanning did not run to completion on this target.</strong> '
          'Every scanning stage failed or timed out and salvaged no results, so the finding '
          'count below is <strong>zero because nothing was scanned</strong> — not because '
          'nothing was found. Everything in this report comes from discovery and analysis '
          'stages only.</p>')
    else:
        verdict = ("no confirmed critical or high findings"
                   if not crit_hi else f"{crit_hi} confirmed critical/high finding(s)")
        a(f'<p>Automated scanning produced {verdict} across '
          f'{len(set(f.get("template-id") for f in model["nuclei"]))} distinct issue class(es).'
          + ('' if vuln_conf >= 1.0 else
             ' Scanning coverage was partial — see section 2.') + '</p>')
    if dev or infra:
        a(f'<p>The surface is fragmented: <strong>{dev}</strong> dev/staging/UAT hosts and '
          f'<strong>{infra}</strong> infrastructure or internal-labelled hosts are reachable '
          f'from the internet. These are usually less hardened than production and are the '
          f'fastest route in.</p>')
    if conf < 0.9:
        a(f'<p><strong>This is not a complete picture.</strong> Overall confidence is '
          f'{conf*100:.0f}%. Re-run the degraded stages before treating a low finding count '
          f'as a clean result.</p>')
    if top:
        a('<p><strong>Start here:</strong></p><ol class="why">')
        for t in top[:3]:
            a(f'<li><code>{escape(t["url"][:110])}</code> — {escape("; ".join(t["signals"][:2]))}</li>')
        a('</ol>')

    # ---- 2. confidence ----------------------------------------------
    a('<h2 id="s2">2. Scan Confidence by Area</h2>')
    a('<div class="tw"><table><tr><th>Area</th><th>Confidence</th><th>Notes</th></tr>')
    for area, v in sorted(health["areas"].items(), key=lambda kv: kv[1]["confidence"]):
        notes = "; ".join(v["notes"]) or "—"
        a(f'<tr><td>{escape(area)}</td><td>{_bar(v["confidence"])}</td>'
          f'<td class="mut">{escape(notes[:150])}</td></tr>')
    a('</table></div>')

    # ---- 3. attack surface ------------------------------------------
    a('<h2 id="s3">3. Attack Surface</h2>')
    a('<h3>Discovery funnel</h3><div class="tw"><table>'
      '<tr><th>Stage</th><th>Count</th><th>Retained</th></tr>')
    funnel = [("Subdomains", len(model["subdomains"])), ("Resolved", len(model["dns"])),
              ("Alive hosts", n_hosts), ("URLs discovered", n_urls),
              ("URLs alive", len(model["urls_detail"])),
              ("JS files", len(model["js_urls"])), ("Endpoints (JS)", len(model["endpoints"])),
              ("Parameterised", len(model["param_urls"])), ("Forms", forms["total"]),
              ("Findings", len(model["nuclei"]))]
    # Scale against the largest value, not the first: URL counts exceed the
    # subdomain count, so anchoring on stage one pinned every later row at
    # 100% and hid the funnel entirely.
    peak = max((n for _, n in funnel), default=1) or 1
    for name, n in funnel:
        a(f'<tr><td>{escape(name)}</td><td class="mono">{n:,}</td>'
          f'<td>{_bar(n / peak)}</td></tr>')
    a('</table></div>')

    a('<h3>Host status distribution</h3><div class="tw"><table>'
      '<tr><th>Status</th><th>Hosts</th><th>Share</th><th>Meaning</th></tr>')
    means = {200: "reachable content", 403: "auth-gated / WAF — worth probing",
             401: "auth required — credential surface", 404: "no content (possible wildcard)",
             503: "rate-limited — scan may be throttled", 500: "server error — worth a look"}
    for st, n in status_dist.most_common(8):
        a(f'<tr><td class="mono">{st}</td><td>{n:,}</td>'
          f'<td>{_bar(n / (n_hosts or 1))}</td>'
          f'<td class="mut">{escape(means.get(st, ""))}</td></tr>')
    a('</table></div>')

    if ctx_dist:
        a('<h3>Hosts by business context</h3><div class="tw"><table>'
          '<tr><th>Context</th><th>Hosts</th><th>Why it matters</th></tr>')
        why = {"dev/staging": "less hardened, often shares prod data",
               "api": "auth gaps, IDOR, mass assignment",
               "infra panel": "default credentials, exposed dashboards",
               "internal": "should not be internet-reachable",
               "vpn": "appliance CVEs, user enumeration",
               "auth": "brute force, OAuth flow flaws",
               "storage": "misconfigured buckets, path traversal",
               "admin": "highest-sensitivity surface",
               "docs/marketing": "low value — deprioritised in ranking"}
        for c, n in ctx_dist.most_common():
            a(f'<tr><td>{escape(c)}</td><td>{n}</td>'
              f'<td class="mut">{escape(why.get(c, ""))}</td></tr>')
        a('</table></div>')

    # ---- 4. top targets ---------------------------------------------
    a('<h2 id="s4">4. Top Manual Testing Targets</h2>')
    a('<p class="sub">score = base × confidence × exposure × context. '
      'Confidence &lt; 0.5 means the signal is weak, not that the target is safe.</p>')
    if not top:
        a('<div class="note">No ranked targets — no scoreable signal in this run.</div>')
    for i, t in enumerate(top[:15], 1):
        cls = "crit" if t["score"] >= 800 else "hi" if t["score"] >= 500 else "med"
        badge = ('<span class="pill ok">VERIFIED</span>' if t["verified"]
                 else '<span class="pill info">INFERRED</span>')
        a(f'<div class="card {cls}"><h4>#{i} · score {t["score"]} {badge} '
          f'<span class="tag">{escape(t["ctx"])}</span></h4>'
          f'<code class="u">{escape(t["url"][:200])}</code>'
          f'<ul class="why">'
          + "".join(f'<li>{escape(s)}</li>' for s in t["signals"]) +
          f'</ul><div class="meta">host <code>{escape(t["host"])}</code> · '
          f'confidence {t["conf_used"]} · exposure {t["expo"]} · context ×{t["ctx_mult"]}</div></div>')

    # ---- 5. findings -------------------------------------------------
    a('<h2 id="s5">5. Confirmed Findings</h2>')
    if not model["nuclei"]:
        msg = ("No findings — but the vulnerability-scanning stage was degraded, "
               "so this is not a clean result."
               if any(b["stage"].startswith("nuclei") for b in health["broken"])
               else "No findings reported by the scanner on the assets it reached.")
        a(f'<div class="note">{escape(msg)}</div>')
    else:
        byclass: dict[str, dict] = {}
        for f in model["nuclei"]:
            tid = f.get("template-id") or "?"
            info = f.get("info") or {}
            g = byclass.setdefault(tid, {
                "name": info.get("name") or tid, "sev": (info.get("severity") or "info").lower(),
                "desc": info.get("description") or "", "ref": info.get("reference") or [],
                "tags": info.get("tags") or [], "hosts": set(), "matched": [], "curl": None,
            })
            g["hosts"].add(f.get("host") or "")
            m = f.get("matched-at") or f.get("url") or ""
            if m and m not in g["matched"]:
                g["matched"].append(m)
            g["curl"] = g["curl"] or f.get("curl-command")
        a(f'<p class="sub">{len(model["nuclei"])} raw findings collapse to '
          f'<strong>{len(byclass)} issue class(es)</strong> — grouped so one problem on '
          f'N hosts reads as one problem.</p>')
        for tid, g in sorted(byclass.items(), key=lambda kv: _sev_idx(kv[1]["sev"])):
            cls = {"critical": "crit", "high": "hi"}.get(g["sev"], "med")
            a(f'<div class="card {cls}"><h4>{_sev_pill(g["sev"])} {escape(g["name"])}</h4>'
              f'<div class="sub"><code>{escape(tid)}</code> · '
              f'{len(g["hosts"])} host(s) affected</div>'
              f'<p style="color:#c8c8d0;margin:10px 0 6px">'
              f'{escape((g["desc"] or "").strip()[:340])}</p>'
              f'<div>' + "".join(f'<span class="tag">{escape(t)}</span>' for t in g["tags"][:8]) + '</div>'
              '<ul class="why">'
              + "".join(f'<li><code>{escape(m[:150])}</code></li>' for m in g["matched"][:6]) +
              '</ul>'
              + (f'<pre class="ev">{escape(g["curl"][:600])}</pre>' if g["curl"] else "")
              + '<div class="meta">Evidence: full request/response in '
                '<code>findings/*/nuclei.json</code></div></div>')

    # ---- 6. secrets ---------------------------------------------------
    a('<h2 id="s6">6. Secret Exposure</h2>')
    if not model["secrets"]:
        a('<div class="note">No secrets extracted from JavaScript.</div>')
    else:
        a(f'<p class="sub"><strong>{len(model["secrets"])} distinct value(s)</strong> from '
          f'{len(model["secrets_raw"])} raw findings — the same bundle served from several '
          f'hosts is one leak, not several.</p>')
        a('<div class="tw"><table><tr><th>Kind</th><th>Value (masked)</th><th>Occurrences</th>'
          '<th>Hosts</th><th>Verdict</th></tr>')
        for s in model["secrets"]:
            raw = json.dumps(s["value"])
            masked = raw[:14] + "…" + raw[-6:] if len(raw) > 26 else raw
            verdict = ("Browser key — in client JS by design. Risk depends entirely on API "
                       "restrictions; verify by calling from an unknown referrer."
                       if "gcp" in (s["kind"] or "").lower() or "AIza" in raw
                       else "Verify whether this credential is live and privileged.")
            a(f'<tr><td>{_sev_pill(s["severity"])} {escape(str(s["kind"]))}</td>'
              f'<td class="mono">{escape(masked)}</td><td>{s["count"]}</td>'
              f'<td class="mut">{escape(", ".join(s["hosts"][:3]) or "—")}</td>'
              f'<td class="mut">{escape(verdict)}</td></tr>')
        a('</table></div>')
        a('<div class="note">Not yet proven exploitable. A key present in client-side '
          'JavaScript is only a vulnerability if it is unrestricted or privileged — '
          'that requires manual verification.</div>')

    # ---- 7. assets ----------------------------------------------------
    a('<h2 id="s7">7. High-Value Assets</h2>')
    a('<p class="sub">Volume is log-scaled so a large marketing site cannot bury a small, '
      'sensitive host.</p>')
    a('<div class="tw"><table><tr><th>#</th><th>Host</th><th>Score</th><th>Context</th>'
      '<th>Status</th><th>URLs</th><th>JS</th><th>Forms</th><th>Find</th><th>Tech</th></tr>')
    for i, h in enumerate(assets, 1):
        flag = ' <span class="pill bad">BLANKET-DENY</span>' if h["blanket"] else ""
        a(f'<tr><td class="mut">{i}</td><td class="mono">{escape(h["host"])}{flag}</td>'
          f'<td><strong>{h["score"]:,}</strong></td>'
          f'<td><span class="tag">{escape(h["ctx_label"])}</span></td>'
          f'<td class="mono">{h["status"] or "—"}</td><td>{h["urls"]:,}</td><td>{h["js"]:,}</td>'
          f'<td>{h["forms"]}</td><td>{h["findings"]}</td>'
          f'<td class="mut">{escape(", ".join((h["tech"] or [])[:3]))}</td></tr>')
    a('</table></div>')

    # ---- 8. auth surface ----------------------------------------------
    a('<h2 id="s8">8. Authentication &amp; Input Surface</h2>')
    if not forms["total"]:
        a('<div class="note">No forms captured — the crawl stage produced no form data.</div>')
    else:
        a(f'<div class="grid">'
          f'<div class="tile"><div class="k">Forms</div><div class="v">{forms["total"]}</div></div>'
          f'<div class="tile"><div class="k">POST</div><div class="v">{forms["post"]}</div></div>'
          f'<div class="tile"><div class="k">Password field</div>'
          f'<div class="v">{len(forms["password"])}</div></div>'
          f'<div class="tile"><div class="k">File upload</div><div class="v">{forms["upload"]}</div>'
          f'</div></div>')
        if forms["frameworks"]:
            a('<h3>Framework inferred from form fields</h3>'
              '<p class="sub">Sharper than <code>tech[]</code>, which rarely carries a version.</p>'
              '<div class="tw"><table><tr><th>Framework</th><th>Forms</th>'
              '<th>Primary test direction</th></tr>')
            for name, n in forms["frameworks"]:
                a(f'<tr><td>{escape(name)}</td><td>{n}</td>'
                  f'<td class="mut">{escape(forms["hints"].get(name, ""))}</td></tr>')
            a('</table></div>')
        if forms["password"]:
            a('<h3>Login forms</h3><div class="tw"><table>'
              '<tr><th>URL</th><th>Method</th><th>Fields</th><th>CSRF token seen</th></tr>')
            seen = set()
            for f in forms["password"][:20]:
                u = canon(f.get("url") or "")
                if u in seen:
                    continue
                seen.add(u)
                flds = f.get("parameters") or []
                csrf = any(re.search(r"csrf|token|verification", (p or ""), re.I) for p in flds)
                a(f'<tr><td class="mono">{escape(u[:90])}</td>'
                  f'<td>{escape(f.get("method", ""))}</td><td>{len(flds)}</td>'
                  f'<td>{"yes" if csrf else _PILL_NONE}</td></tr>')
            a('</table></div>')
            a('<div class="note">Login forms without a CSRF token are worth testing for '
              'rate limiting and credential stuffing.</div>')

    # ---- 9. endpoints --------------------------------------------------
    a('<h2 id="s9">9. API &amp; Endpoint Intelligence</h2>')
    if not eps["total"]:
        a('<div class="note">No endpoints extracted.</div>')
    else:
        a(f'<p class="sub">{eps["total"]:,} endpoints extracted from JavaScript.</p>')
        if eps["patterns"]:
            a('<div class="tw"><table><tr><th>Pattern</th><th>Occurrences</th>'
              '<th>Why it matters</th></tr>')
            why = {"graphql": "introspection, query batching, depth attacks",
                   "swagger/openapi": "full API contract — often unauthenticated",
                   "admin route": "admin logic inside the app; server-side check may be missing",
                   "upload": "unrestricted upload, content-type bypass",
                   "oauth": "redirect_uri validation, state/PKCE handling",
                   "token": "token leakage, weak signing",
                   "jwt": "alg=none, key confusion",
                   "debug": "debug endpoint reachable in production",
                   "internal": "internal route exposed externally",
                   "health/metrics": "version and dependency disclosure"}
            for k, n in sorted(eps["patterns"].items(), key=lambda kv: -kv[1]):
                a(f'<tr><td>{escape(k)}</td><td>{n}</td>'
                  f'<td class="mut">{escape(why.get(k, ""))}</td></tr>')
            a('</table></div>')
        # Verified JS-mined URLs — the payoff of the jsluice_verify stage.
        jv = model["js_verified"]
        if jv:
            st = Counter(r.get("status_code") for r in jv)
            live_api = [r for r in jv
                        if (r.get("status_code") or 0) // 100 == 2
                        and "json" in (r.get("content_type") or "").lower()]
            auth = [r for r in jv if (r.get("status_code") or 0) in (401, 403)]
            a('<h3>Verified JS-mined URLs</h3>'
              '<p class="sub">Probed by the <code>jsluice_verify</code> stage. '
              'An endpoint mined from a bundle only matters once you know '
              'whether it answers.</p>')
            a(f'<div class="grid">'
              f'<div class="tile"><div class="k">Probed</div>'
              f'<div class="v">{len(jv):,}</div></div>'
              f'<div class="tile"><div class="k">Live JSON API</div>'
              f'<div class="v">{len(live_api):,}</div>'
              f'<div class="d">2xx + application/json</div></div>'
              f'<div class="tile"><div class="k">Auth-gated</div>'
              f'<div class="v">{len(auth):,}</div><div class="d">401 / 403</div></div>'
              f'</div>')
            a('<div class="tw"><table><tr><th>Status</th><th>URLs</th>'
              '<th>Share</th></tr>')
            for code, n in st.most_common(8):
                a(f'<tr><td class="mono">{code or "—"}</td><td>{n:,}</td>'
                  f'<td>{_bar(n / len(jv))}</td></tr>')
            a('</table></div>')
            if live_api:
                a('<div class="tw"><table><tr><th>Live JSON endpoint</th>'
                  '<th>Status</th><th>Length</th><th>Content-Type</th></tr>')
                for r in sorted(live_api,
                                key=lambda r: -(r.get("content_length") or 0))[:20]:
                    ct = (r.get("content_type") or "-").split(";")[0]
                    a(f'<tr><td class="mono">{escape((r.get("url") or "")[:88])}</td>'
                      f'<td class="mono">{r.get("status_code")}</td>'
                      f'<td class="mono">{r.get("content_length") or 0:,}</td>'
                      f'<td class="mut">{escape(ct)}</td></tr>')
                a('</table></div>')
                a('<div class="note">These answer with JSON and were reachable at '
                  'scan time — the highest-yield starting point for IDOR and '
                  'broken-access-control testing.</div>')
        elif model["js_urls"]:
            a('<div class="note">JS-mined URLs were not probed — the '
              '<code>jsluice_verify</code> stage did not run, so these '
              'endpoints have no status, length or content-type. '
              'They cannot be triaged from this report alone.</div>')

        if len(eps["versions"]) > 1:
            vs = ", ".join(f"v{v} ({n})" for v, n in eps["versions"])
            a(f'<div class="note"><strong>Multiple API versions live side by side:</strong> {escape(vs)}. '
              f'Re-test every endpoint found on the newest version against the older ones — '
              f'inconsistent authorisation between API versions is a common and easily '
              f'automated finding.</div>')

    # ---- 10. tech ------------------------------------------------------
    a('<h2 id="s10">10. Technology Distribution</h2>')
    a('<div class="tw"><table><tr><th>Technology</th><th>Hosts</th><th>Share</th>'
      '<th>Version known</th></tr>')
    for t, n in tech_dist.most_common(15):
        has_ver = ":" in t or re.search(r"\d+\.\d+", t)
        a(f'<tr><td>{escape(t)}</td><td>{n}</td><td>{_bar(n / (n_hosts or 1))}</td>'
          f'<td>{"yes" if has_ver else _MUT_NO}</td></tr>')
    a('</table></div>')
    unversioned = sum(1 for t, _ in tech_dist.most_common()
                      if not (":" in t or re.search(r"\d+\.\d+", t)))
    a(f'<div class="note">{unversioned} of {len(tech_dist)} detected technologies carry no '
      f'version, so <strong>CVE mapping is not possible</strong> from this data. Treat this '
      f'section as surface shape, not as a vulnerability assessment.</div>')

    # ---- 11. pentest intel ---------------------------------------------
    a('<h2 id="s11">11. Pentest Intelligence</h2>')
    a('<p class="sub">Test directions supported by observed evidence. '
      'No vulnerability is claimed.</p>')
    intel: list[tuple[str, str, str, str]] = []
    for name, n in forms["frameworks"]:
        if "WebForms" in name:
            intel.append(("Deserialization", f"__VIEWSTATE on {n} ASP.NET WebForms form(s)",
                          "high", "Check ViewState MAC and ViewStateUserKey"))
        if name in ("Django", "Drupal", "Rails", "Laravel"):
            intel.append(("Template injection / framework CVEs", f"{name} on {n} form(s)",
                          "low", f"Enumerate {name} version, check known CVEs"))
    if eps["patterns"].get("graphql"):
        intel.append(("GraphQL", f"{eps['patterns']['graphql']} graphql reference(s) in JS",
                      "high", "Introspection query, batching, query depth"))
    if eps["patterns"].get("upload"):
        intel.append(("File upload", f"{eps['patterns']['upload']} upload endpoint(s)",
                      "high", "Extension/content-type bypass, path traversal"))
    if eps["patterns"].get("oauth"):
        intel.append(("OAuth flow", f"{eps['patterns']['oauth']} oauth endpoint(s)",
                      "high", "redirect_uri validation, state parameter, PKCE"))
    if eps["patterns"].get("jwt") or eps["patterns"].get("token"):
        intel.append(("JWT", "token/jwt endpoints present",
                      "medium", "alg=none, key confusion, expiry handling"))
    if eps["patterns"].get("admin route"):
        intel.append(("Broken access control", f"{eps['patterns']['admin route']} /admin route(s) in JS",
                      "high", "Call admin routes directly — UI-only gating is common"))
    if len(eps["versions"]) > 1:
        intel.append(("API versioning gap", f"versions {', '.join('v'+v for v, _ in eps['versions'])}",
                      "high", "Replay newest-version endpoints against older versions"))
    if len(model["param_urls"]) > 50:
        note = "medium"
        extra = ""
        if any(b["stage"] == "arjun" for b in health["broken"]):
            extra = " (arjun failed — real parameter surface is larger)"
        intel.append(("Injection (SQLi / NoSQLi / SSTI)",
                      f"{len(model['param_urls']):,} parameterised URLs{extra}",
                      note, "Fuzz parameters; prioritise auth-adjacent endpoints"))
    if re.search(r"url=|uri=|redirect=|next=|return", "\n".join(model["param_urls"][:2000]), re.I):
        intel.append(("SSRF / Open redirect", "url/redirect/next parameters observed",
                      "medium", "Test internal addresses and external callbacks"))
    if any("vue" in t.lower() or "react" in t.lower() or "angular" in t.lower() for t in tech_dist):
        intel.append(("Prototype pollution / DOM XSS", "SPA framework detected",
                      "medium", "Audit client-side sinks in main bundles"))
    if tech_dist:
        intel.append(("CORS", f"{len(model['hindex'])} hosts, API surface present",
                      "medium", "Check Access-Control-Allow-Origin reflection"))

    if intel:
        a('<div class="tw"><table><tr><th>Class</th><th>Observed evidence</th>'
          '<th>Priority</th><th>How to test</th></tr>')
        order = {"high": 0, "medium": 1, "low": 2}
        for cls, ev, pri, how in sorted(intel, key=lambda r: order.get(r[2], 3)):
            a(f'<tr><td><strong>{escape(cls)}</strong></td><td class="mut">{escape(ev)}</td>'
              f'<td>{_sev_pill(pri)}</td><td class="mut">{escape(how)}</td></tr>')
        a('</table></div>')
    a('<div class="note">Security headers, TLS configuration and CSP could not be assessed — '
      'no stage in this pipeline captures response headers or TLS data.</div>')

    # ---- 12. data quality ------------------------------------------------
    a('<h2 id="s12">12. Data Quality &amp; Anomalies</h2>')
    if not dq:
        a('<div class="note">No data-quality problems detected.</div>')
    else:
        a('<div class="tw"><table><tr><th>Severity</th><th>Check</th><th>Detail</th>'
          '<th>Impact on this report</th></tr>')
        for r in dq:
            a(f'<tr><td>{_sev_pill(r["sev"])}</td><td>{escape(r["check"])}</td>'
              f'<td class="mono mut">{escape(r["detail"])}</td>'
              f'<td class="mut">{escape(r["impact"])}</td></tr>')
        a('</table></div>')

    # ---- 13. out of scope -------------------------------------------------
    a('<h2 id="s13">13. Out-of-Scope Observed</h2>')
    if not model["oos"]:
        a('<div class="note">All observed hosts are within scope.</div>')
    else:
        a(f'<p class="sub">{len(model["oos"])} host(s) outside <code>{escape(d)}</code> appeared '
          f'in the scan output. Excluded from all ranking — listed so scope can be '
          f'confirmed before anyone tests them.</p>')
        a('<div class="tw"><table><tr><th>Host</th><th>Times seen</th>'
          '<th>Leaked in via</th></tr>')
        for h, n in model["oos"].most_common(25):
            src = ", ".join(model["oos_src"].get(h, []))
            a(f'<tr><td class="mono">{escape(h)}</td><td>{n:,}</td>'
              f'<td class="mut">{escape(src)}</td></tr>')
        a('</table></div>')
        a('<div class="note bad">Third-party assets in a client-facing report are a legal '
          'risk, not just noise. Confirm ownership before any testing.</div>')

    # ---- 14. coverage gaps -------------------------------------------------
    a('<h2 id="s14">14. Coverage Gaps</h2>')
    a('<p class="sub">What this scan did <strong>not</strong> look at. '
      'Unscanned is not the same as secure.</p>')
    a('<div class="tw"><table><tr><th>Area</th><th>Status</th><th>To enable</th></tr>')
    for area, why, fix in [
        ("TLS configuration", "not collected", "add a tlsx stage"),
        ("Certificates / SAN", "not collected", "tlsx -san -cn (also yields new subdomains)"),
        ("Open ports", "80/443 only", "add naabu"),
        ("Response headers / CSP", "not captured", "httpx -irh"),
        ("Screenshots", "not captured", "httpx -screenshot"),
        ("CVE mapping", "blocked — versions unknown", "version-aware fingerprinting"),
        ("Redirect chains", "not captured", "httpx -location -chain"),
    ]:
        a(f'<tr><td>{escape(area)}</td><td><span class="pill warn">{escape(why)}</span></td>'
          f'<td class="mut">{escape(fix)}</td></tr>')
    a('</table></div>')

    a(f'<footer>Generated by <code>modules/asm_report.py</code> from '
      f'<code>{escape(model["dir"])}</code> · {now_iso()}<br>'
      f'Read-only: this report analyses existing scan output and performs no requests. '
      f'Methodology: <code>docs/report-design.md</code></footer>')

    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>ASM Report — {escape(d)}</title><style>{_CSS}</style></head>'
            f'<body><div class="wrap">{"".join(P)}</div></body></html>')


# ----------------------------------------------------------------------
# Entry points
# ----------------------------------------------------------------------
def build_asm_report(output_dir: Path | str) -> dict:
    """Write ``report/asm_report.html``. Returns a standard stage result."""
    output_dir = Path(output_dir)
    try:
        model = build_model(output_dir)
        html = render_html(model)
        out = output_dir / "report" / "asm_report.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        return make_result(
            "asm_report", "success", input_path=output_dir, outputs=[out], count=1,
            extra={
                "confidence": round(model["health"]["overall"], 3),
                "hosts": len(model["hosts"]),
                "findings": len(model["nuclei"]),
                "secrets_distinct": len(model["secrets"]),
                "blanket_deny_hosts": len(model["blanket"]),
                "out_of_scope_hosts": len(model["oos"]),
            },
        )
    except Exception as exc:  # never let the report kill a finished run
        return make_result("asm_report", "failed", input_path=output_dir,
                           count=0, error=str(exc))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: python3 -m modules.asm_report <output_dir> [<output_dir> ...]")
        return 2
    rc = 0
    for target in args:
        res = build_asm_report(Path(target))
        if res["status"] == "success":
            ex = res.get("extra") or {}
            print(f"[ok] {res['outputs'][0]}  "
                  f"confidence={ex.get('confidence')}  hosts={ex.get('hosts')}  "
                  f"findings={ex.get('findings')}  secrets={ex.get('secrets_distinct')}")
        else:
            print(f"[fail] {target}: {res.get('error')}")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
