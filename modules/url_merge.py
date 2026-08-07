"""url_merge — stage 5: merge + classify URLs from content discovery.

Inputs:
  processed/crawler_urls.txt
  processed/dirsearch_urls.txt
  processed/ffuf_urls.txt
  processed/waymore_urls.txt

Outputs:
  processed/all_urls.txt       — normalised + de-duped
  processed/all_urls.jsonl     — same list + which tool(s) produced each URL
  processed/js_urls.txt        — JS URLs only
  processed/dynamic_urls.txt   — likely-dynamic, static assets removed

The earlier ``all_urls_raw.txt`` intermediate was dropped in v2 — it
was just the input to the dedup step, and any caller that needs the
raw union can re-merge the three source files deterministically.

``all_urls.jsonl`` (added v3) exists because the merge used to be lossy in
the one way that mattered: it flattened sources of wildly different quality
into an anonymous list. On a real discover.com run, jsluice-mined URLs came
back 23.6%% HTTP 200 while ffuf's 44,431 hits were a near-pure wildcard-403
artefact — yet after the merge nothing downstream could tell them apart, so
``arjun.max_urls=200`` sliced its 200 URLs off the top of 57k and drew them
almost entirely from the ffuf noise. Provenance lets a capped consumer sort
before it cuts (see :func:`rank_urls_by_source`).

Pure helper functions (dedupe_urls, normalize_url, is_js_url, is_dynamic_url)
are exposed at module level so the unit tests can import them.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from . import layout
from .sensitive_ext import STATIC_EXT
from .utils import make_result, read_jsonl, read_lines, write_jsonl, write_lines


# ----------------------------------------------------------------------
# Provenance — which tool produced a URL.
# ----------------------------------------------------------------------
# Every producer writes ``processed/<name>_urls.txt``; the filename IS the
# provenance, we just have to stop throwing it away at merge time.
SOURCE_BY_FILE: dict[str, str] = {
    "crawler_urls.txt": "crawler",
    "dirsearch_urls.txt": "dirsearch",
    "ffuf_urls.txt": "ffuf",
    "waymore_urls.txt": "waymore",
    "xnlinkfinder_endpoints.txt": "xnlinkfinder",
    "xnlinkfinder_urls.txt": "xnlinkfinder",
    "jsluice_endpoints.txt": "jsluice",
    "jsluice_urls.txt": "jsluice",
    "apidocs_urls.txt": "apidocs",
}

# How much a source's output is worth to a *capped* consumer. Higher wins.
# Grounded in measured alive-rates from the discover.com run rather than
# taste: what fraction of each source's URLs came back HTTP 200.
#
#   apidocs       — parsed from a served OpenAPI document; the endpoints
#                   are declared by the target, not guessed.
#   jsluice       — AST-extracted from the app's own bundles: 23.6% 200.
#   xnlinkfinder  — same idea, regex instead of AST, so noisier.
#   crawler       — katana actually followed the link, so it existed.
#   waymore       — archived: real once, often 404 now.
#   dirsearch     — guessed; survives a status filter but wildcard-prone.
#   ffuf          — guessed, and the worst wildcard offender: 4,081
#                   identical "hits" per host across 11 hosts, ~0% 200.
#
# UNKNOWN_SOURCE_RANK sits above ffuf/dirsearch on purpose: a URL with no
# recorded provenance (an older run's file, a hand-added list) should not
# be sorted below known-noise.
SOURCE_QUALITY: dict[str, int] = {
    "apidocs": 100,
    "jsluice": 90,
    "xnlinkfinder": 70,
    "crawler": 60,
    "waymore": 40,
    "dirsearch": 20,
    "ffuf": 10,
}
UNKNOWN_SOURCE_RANK = 30

PROVENANCE_FILE = "all_urls.jsonl"


def source_label(path: Path | str) -> str:
    """Map a producer file to its source name (``"unknown"`` if unlisted)."""
    return SOURCE_BY_FILE.get(Path(path).name, "unknown")


def source_score(sources: Iterable[str]) -> int:
    """Quality of the BEST source that produced a URL.

    Best-of rather than sum/average: a URL found by both jsluice and ffuf is
    a real endpoint that ffuf also happened to stumble onto — the ffuf hit
    does not make it more suspect.
    """
    ranks = [SOURCE_QUALITY.get(s, UNKNOWN_SOURCE_RANK) for s in sources]
    return max(ranks) if ranks else UNKNOWN_SOURCE_RANK


def load_url_sources(output_dir: Path) -> dict[str, list[str]]:
    """``{url: [source, ...]}`` from ``processed/all_urls.jsonl``.

    Returns ``{}`` when the file is absent — every caller must stay
    functional on an output tree from before provenance existed, and on a
    ``--resume`` that never re-ran the merge.
    """
    out: dict[str, list[str]] = {}
    for row in read_jsonl(layout.path(output_dir, PROVENANCE_FILE)):
        if isinstance(row, dict) and row.get("url"):
            out[str(row["url"])] = [str(s) for s in (row.get("sources") or [])]
    return out


def rank_urls_by_source(
    urls: Iterable[str], sources: dict[str, list[str]],
) -> list[str]:
    """Order *urls* best-source-first, stable within a quality tier.

    For consumers that apply a hard cap (arjun's ``max_urls``, any batching
    limit): sorting before the cut is what turns "we scanned 200 random
    URLs" into "we scanned the 200 most likely to be real".
    """
    ranked = list(urls)
    ranked.sort(key=lambda u: -source_score(sources.get(u, ())))
    return ranked


def _write_provenance(
    output_dir: Path, urls: list[str], prov: dict[str, set[str]],
) -> int:
    """Write ``all_urls.jsonl`` parallel to ``all_urls.txt``, same order."""
    return write_jsonl(
        layout.path(output_dir, PROVENANCE_FILE),
        (
            {"url": u, "sources": sorted(prov.get(u) or {"unknown"})}
            for u in urls
        ),
    )


def _source_counts(
    urls: Iterable[str], prov: dict[str, set[str]],
) -> dict[str, int]:
    """``{source: how many surviving URLs it contributed}``, biggest first.

    Reported in the stage result so the run log answers "what is this
    corpus actually made of?" without anyone having to open the JSONL. A
    source at 76%% of the corpus is the shape of a wildcard blow-up.
    """
    counts: dict[str, int] = {}
    for u in urls:
        for s in prov.get(u) or ("unknown",):
            counts[s] = counts.get(s, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _collect_provenance(
    files: Iterable[Path], into: dict[str, set[str]] | None = None,
) -> dict[str, set[str]]:
    """Accumulate ``{normalised_url: {source, ...}}`` over producer files.

    Keyed on the NORMALISED URL because that is what lands in
    ``all_urls.txt``; two sources emitting ``http://x/`` and ``http://x``
    are the same URL and must merge into one record with both sources.
    """
    prov: dict[str, set[str]] = into if into is not None else {}
    for f in files:
        label = source_label(f)
        for raw in read_lines(f):
            n = normalize_url(raw)
            if n:
                prov.setdefault(n, set()).add(label)
    return prov


# ----------------------------------------------------------------------
# Pure helpers — no I/O, fully unit-testable.
# ----------------------------------------------------------------------
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "mc_cid", "mc_eid",
}


def normalize_url(url: str) -> str:
    """Light-touch normalisation: lowercased host, no trailing slash on path
    (unless the path is "/"), fragment stripped, default ports removed, common
    tracking params removed. Query strings are preserved.
    """
    if not url:
        return ""
    s = url.strip()
    try:
        sp = urlsplit(s)
    except ValueError:
        return s
    scheme = (sp.scheme or "http").lower()
    netloc = sp.netloc.lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    path = sp.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    query = sp.query
    if query:
        parts: list[str] = []
        for kv in query.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                if k.lower() in _TRACKING_PARAMS:
                    continue
                parts.append(f"{k}={v}")
            else:
                if kv.lower() in _TRACKING_PARAMS:
                    continue
                parts.append(kv)
        query = "&".join(parts)
    return urlunsplit((scheme, netloc, path, query, ""))


_JS_RE = re.compile(r"^https?://[^\s\"'<>]+\.js(?:[?#].*)?$", re.IGNORECASE)


def is_js_url(url: str) -> bool:
    return bool(url) and bool(_JS_RE.match(url.strip()))


_STATIC_LOWER = tuple(ext.lower() for ext in STATIC_EXT)


def is_dynamic_url(url: str) -> bool:
    """A URL is "dynamic" unless its path clearly ends with a static-asset
    extension. Default: True (assume dynamic)."""
    if not url:
        return False
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    for ext in _STATIC_LOWER:
        if path.endswith(ext):
            return False
    return True


def has_query_params(url: str) -> bool:
    """True if the URL already carries a non-empty query string (``?a=1``).

    These URLs are prime injection targets — they show their parameters
    right in the crawl/waymore output, no discovery needed.
    """
    if not url:
        return False
    try:
        return bool(urlsplit(url).query)
    except ValueError:
        return False


# ----------------------------------------------------------------------
# Scope filtering — keep in-scope + operator-declared related roots.
# ----------------------------------------------------------------------
def _host_of(url: str) -> str:
    """Lowercased hostname of a URL (``""`` when unparseable)."""
    s = (url or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        return (urlsplit(s).hostname or "").lower()
    except ValueError:
        return ""


def normalize_root(root: str) -> str:
    """Normalise a scope root to a bare registrable-ish host.

    Accepts ``foo.com``, ``.foo.com``, ``*.foo.com`` or a full URL and
    returns ``foo.com``. Empty/garbage → ``""`` (ignored by callers).
    """
    r = (root or "").strip().lower()
    if not r:
        return ""
    if "://" in r:
        r = _host_of(r)
    r = r.replace("*.", "")
    return r.strip().lstrip(".")


def _host_matches_root(host: str, root: str) -> bool:
    return bool(host) and bool(root) and (host == root or host.endswith("." + root))


def is_in_scope(url: str, root: str, related_roots: Iterable[str] = ()) -> bool:
    """True when ``url``'s host is the target root, a subdomain of it, or a
    subdomain of any operator-declared related root.

    ``root`` / ``related_roots`` may be passed in any accepted form
    (``foo.com`` / ``.foo.com`` / ``*.foo.com``) — they're normalised here.
    """
    host = _host_of(url)
    if not host:
        return False
    if _host_matches_root(host, normalize_root(root)):
        return True
    return any(_host_matches_root(host, normalize_root(r)) for r in related_roots)


def filter_in_scope(
    urls: Iterable[str], root: str, related_roots: Iterable[str] = (),
) -> list[str]:
    """Keep only in-scope + related-root URLs. Preserves input order."""
    related = list(related_roots or [])
    return [u for u in urls if is_in_scope(u, root, related)]


# ----------------------------------------------------------------------
# Param-template collapsing — one representative per (host, path, param
# shape), so a crawl that emits ``/e?id=1 … /e?id=999`` doesn't balloon the
# scan set. "Smart": a param value is kept distinct when it looks like a
# human keyword, folded only when it looks like a machine id.
# ----------------------------------------------------------------------
_HEXISH_RE = re.compile(r"^[0-9a-fA-F-]{8,}$")


def _is_meaningful_value(v: str) -> bool:
    """True when a param value looks like a human keyword worth keeping
    distinct (``delete``, ``admin``, ``true``), False when it looks like a
    machine id (number / uuid / hash / long blob) or is empty.

    Deliberately fails toward *meaningful* on ambiguous short alphabetic
    values — losing an ``?action=admin`` endpoint is far worse than keeping
    a couple of near-duplicates.
    """
    v = (v or "").strip()
    if not v:
        return False                # empty → nothing to distinguish
    if len(v) > 20:
        return False                # long → token / hash / encoded blob
    if v.isdigit():
        return False                # numeric id / page / epoch
    if _HEXISH_RE.match(v):
        return False                # hex id / uuid / md5-ish
    if not any(c.isalpha() for c in v):
        return False                # dates / symbols with no letters
    return True


def param_template_key(url: str) -> tuple:
    """Signature that collapses value-only variants of the same endpoint.

    Keyed on scheme + host + path + a *set* of ``(param_name, {keyword
    values})``. Using a set makes it order-independent (``?a=&b=`` ==
    ``?b=&a=``) and folds a repeated param name (``?p=a&p=b`` == ``?p=a``).
    Only keyword-like values (see ``_is_meaningful_value``) enter the key,
    so ``?id=1`` and ``?id=2`` share a key but ``?action=delete`` and
    ``?action=view`` do not.
    """
    try:
        sp = urlsplit(url)
    except ValueError:
        return (url,)
    occur: dict[str, list[str]] = {}
    for name, val in parse_qsl(sp.query, keep_blank_values=True):
        occur.setdefault(name, []).append(val)
    parts: list[tuple[str, str]] = []
    for name, vals in occur.items():
        # A single, keyword-like value is kept in the key (so
        # ``?action=delete`` and ``?action=view`` stay distinct). A repeated
        # param name (``?p=a&p=b``) or a machine-id value folds to name-only,
        # collapsing all such value-samples of the same endpoint into one.
        if len(vals) == 1 and _is_meaningful_value(vals[0]):
            parts.append((name, vals[0]))
        else:
            parts.append((name, ""))
    return (sp.scheme, sp.netloc.lower(), sp.path, frozenset(parts))


def collapse_param_shapes(urls: Iterable[str]) -> list[str]:
    """Keep one representative per ``param_template_key``. First-seen wins,
    so the output order is stable across runs. URLs with no query string are
    unaffected (their key is just scheme+host+path)."""
    seen: set[tuple] = set()
    out: list[str] = []
    for u in urls:
        if not u:
            continue
        k = param_template_key(u)
        if k in seen:
            continue
        seen.add(k)
        out.append(u)
    return out


def dedupe_urls(urls: Iterable[str]) -> list[str]:
    """De-duplicate URLs (case-insensitive on scheme+host, exact on path+query)."""
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if not u:
            continue
        s = str(u).strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# ----------------------------------------------------------------------
# Stage orchestration
# ----------------------------------------------------------------------
def _scope_params(domain: str, cfg: dict | None) -> tuple[bool, str, list[str]]:
    """Resolve (filter_on, root, related_roots) from config + domain.

    Filtering is only applied when it's enabled AND we actually know the
    root — filtering with an empty root would drop *everything*, so we
    treat "no domain" as "don't filter" (fail-open, never silently empty).
    """
    scope_cfg = (cfg or {}).get("scope") or {}
    filter_on = bool(scope_cfg.get("filter_urls", True))
    root = normalize_root(domain or "")
    related = [str(r) for r in (scope_cfg.get("related_roots") or [])]
    return (filter_on and bool(root)), root, related


def _collapse_enabled(cfg: dict | None) -> bool:
    return bool(((cfg or {}).get("url_dedup") or {}).get("collapse_params", True))


def merge(
    output_dir: Path,
    domain: str = "",
    cfg: dict | None = None,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    stage = "url_merge"
    layout.ensure_tree(output_dir)
    files = [
        layout.path(output_dir, "crawler_urls.txt"),
        layout.path(output_dir, "dirsearch_urls.txt"),
        layout.path(output_dir, "ffuf_urls.txt"),
        layout.path(output_dir, "waymore_urls.txt"),
    ]

    out_all = layout.path(output_dir, "all_urls.txt")
    out_js = layout.path(output_dir, "js_urls.txt")
    out_dyn = layout.path(output_dir, "dynamic_urls.txt")
    out_prov = layout.path(output_dir, PROVENANCE_FILE)

    if resume and all(p.exists() and p.stat().st_size > 0 for p in (out_all, out_js, out_dyn)):
        return make_result(
            stage, "success", input_path=",".join(str(f) for f in files),
            outputs=[out_all, out_js, out_dyn, out_prov],
            count=len(read_lines(out_all)),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=",".join(str(f) for f in files),
            outputs=[out_all, out_js, out_dyn, out_prov], count=0, error="dry-run",
        )

    all_lines: list[str] = []
    for f in files:
        all_lines.extend(read_lines(f))
    prov = _collect_provenance(files)

    normalised = [normalize_url(u) for u in dedupe_urls(all_lines)]
    normalised = [u for u in normalised if u]

    # js_urls is built from the FULL union — out-of-scope ``.js`` (the app's
    # own bundles served from a CDN/S3) is kept on purpose so xnLinkFinder +
    # jsluice can still mine endpoints out of it. Scope filtering only trims
    # all_urls.txt / dynamic_urls.txt, which feed httpx/arjun/nuclei.
    js_urls = [u for u in normalised if is_js_url(u)]
    n_js = write_lines(out_js, js_urls)

    filter_on, root, related = _scope_params(domain, cfg)
    in_scope = filter_in_scope(normalised, root, related) if filter_on else normalised
    dropped = len(normalised) - len(in_scope)

    # Collapse value-only param variants of the same endpoint (``/e?id=1`` …
    # ``/e?id=999`` → one URL) before writing the scan set.
    collapse_on = _collapse_enabled(cfg)
    kept_before = len(in_scope)
    if collapse_on:
        in_scope = collapse_param_shapes(in_scope)
    collapsed = kept_before - len(in_scope)

    # Dedupe explicitly rather than leaning on write_lines' internal dedup:
    # all_urls.jsonl must line up with all_urls.txt record-for-record, so
    # both writers have to see the same final list.
    final = dedupe_urls(in_scope)
    n_all = write_lines(out_all, final)
    _write_provenance(output_dir, final, prov)

    dyn_urls = [u for u in final if is_dynamic_url(u)]
    n_dyn = write_lines(out_dyn, dyn_urls)

    extra = {"js": n_js, "dynamic": n_dyn, "sources": _source_counts(final, prov)}
    if filter_on:
        extra["scope_dropped"] = dropped
        extra["scope_kept"] = n_all
    if collapse_on and collapsed:
        extra["param_collapsed"] = collapsed
    return make_result(
        stage, "success", input_path=",".join(str(f) for f in files),
        outputs=[out_all, out_js, out_dyn, out_prov],
        count=n_all, extra=extra,
    )


def append_urls(
    output_dir: Path,
    extra_files: list[Path],
    domain: str = "",
    cfg: dict | None = None,
) -> dict:
    """Re-merge after xnLinkFinder (stage 6.2) and re-classify.

    The spec says: "Merge xnLinkFinder URLs back into processed/all_urls.txt.
    Deduplicate again after merge." We do exactly that, and re-apply the same
    scope filter so JS-derived endpoints on third-party hosts don't leak back
    into the scan set. Out-of-scope ``.js`` stays in js_urls.txt (merged with
    whatever merge() already put there) so nothing that fed JS analysis is lost.
    """
    stage = "url_merge_append"
    out_all = layout.path(output_dir, "all_urls.txt")
    out_js = layout.path(output_dir, "js_urls.txt")
    out_dyn = layout.path(output_dir, "dynamic_urls.txt")
    out_prov = layout.path(output_dir, PROVENANCE_FILE)

    # Carry forward what merge() recorded, then layer the extras' sources on
    # top. Rebuilding from the producer files instead would lose the stage-5
    # sources, since ffuf/waymore/... are not in *extra_files*.
    prov: dict[str, set[str]] = {
        u: set(s) for u, s in load_url_sources(output_dir).items()
    }
    _collect_provenance(extra_files, into=prov)

    existing = read_lines(out_all)
    extra: list[str] = []
    for f in extra_files:
        extra.extend(read_lines(f))
    merged = [normalize_url(u) for u in dedupe_urls(existing + extra)]
    merged = [u for u in merged if u]

    # Preserve out-of-scope .js: union the existing js_urls.txt (which holds
    # the out-of-scope bundles from merge()) with any new .js in the extras,
    # rather than recomputing from the scope-filtered set.
    existing_js = read_lines(out_js)
    new_js = [normalize_url(u) for u in extra if is_js_url(u)]
    js_all = [u for u in dedupe_urls(existing_js + new_js) if u]
    n_js = write_lines(out_js, js_all)

    filter_on, root, related = _scope_params(domain, cfg)
    in_scope = filter_in_scope(merged, root, related) if filter_on else merged
    dropped = len(merged) - len(in_scope)

    collapse_on = _collapse_enabled(cfg)
    kept_before = len(in_scope)
    if collapse_on:
        in_scope = collapse_param_shapes(in_scope)
    collapsed = kept_before - len(in_scope)

    final = dedupe_urls(in_scope)
    n_all = write_lines(out_all, final)
    _write_provenance(output_dir, final, prov)
    n_dyn = write_lines(out_dyn, [u for u in final if is_dynamic_url(u)])

    extra_meta = {"js": n_js, "dynamic": n_dyn,
                  "sources": _source_counts(final, prov)}
    if filter_on:
        extra_meta["scope_dropped"] = dropped
        extra_meta["scope_kept"] = n_all
    if collapse_on and collapsed:
        extra_meta["param_collapsed"] = collapsed
    return make_result(
        stage, "success", input_path=",".join(str(f) for f in extra_files),
        outputs=[out_all, out_js, out_dyn, out_prov],
        count=n_all, extra=extra_meta,
    )


def extract_in_scope_hosts(urls: Iterable[str], root_domain: str) -> list[str]:
    """Unique in-scope hostnames from a list of URLs (sorted).

    A host is in scope if it equals ``root_domain`` or is a subdomain of it.
    Pure helper — used to mine subdomains out of collected URLs.
    """
    root = (root_domain or "").lower().strip().lstrip(".")
    if not root:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        s = (u or "").strip()
        if "://" not in s:
            s = "http://" + s
        try:
            host = (urlsplit(s).hostname or "").lower()
        except ValueError:
            continue
        if host and (host == root or host.endswith("." + root)) and host not in seen:
            seen.add(host)
            out.append(host)
    return sorted(out)


def derive_subdomains_from_urls(output_dir: Path, domain: str) -> dict:
    """Mine NEW in-scope subdomains out of the collected URLs.

    Archived + crawled URLs (waymore/gau/katana/JS) routinely reference
    hosts that passive subdomain enum (subfinder/amass/chaos) never found.
    This surfaces those: it extracts in-scope hosts from ``all_urls.txt``,
    drops the ones already in ``subdomains.txt``, and writes the remainder
    to ``processed/url_derived_subdomains.txt``.

    Informational only — these hosts are NOT merged into the resolved
    inventory (they weren't dnsx/httpx-verified this run). Feed the file
    into the next scan's input, or resolve them ad hoc. The count is echoed
    so the operator knows the discovery surface grew.
    """
    hosts = extract_in_scope_hosts(read_lines(layout.path(output_dir, "all_urls.txt")), domain)
    known = set(read_lines(layout.path(output_dir, "subdomains.txt")))
    new = [h for h in hosts if h not in known]
    out_path = layout.path(output_dir, "url_derived_subdomains.txt")
    write_lines(out_path, new)
    return make_result(
        "url_subdomains", "success", input_path=str(layout.path(output_dir, "all_urls.txt")),
        outputs=[out_path], count=len(new),
        extra={"in_scope_hosts": len(hosts), "new": len(new)},
    )


def seed_parameterized_urls(output_dir: Path) -> dict:
    """Seed ``parameterized_urls.txt`` with URLs that ALREADY carry params.

    ``parameterized_urls.txt`` is the hand-testing shortlist, built from
    arjun's discoveries + jsluice params. But URLs that already show
    ``?id=1`` in the crawl/waymore results are prime injection targets that
    land in it *only if arjun happens to re-discover them*. When arjun is
    skipped, capped (``max_urls``), or fails, those obvious param URLs are
    missing entirely — even though they were sitting in
    ``dynamic_urls.txt`` the whole time.

    This step reads ``dynamic_urls.txt``, keeps the ones with a query string,
    and merges them (deduped) into ``parameterized_urls.txt`` — independent
    of arjun. Runs right after arjun (stage 8), so the shortlist is::

        parameterized_urls.txt = {already-param URLs}
                               ∪ {arjun-discovered}
                               ∪ {jsluice params}

    Additive and safe: creates the file if missing, so even a run with
    ``--skip-arjun`` and no jsluice hits still surfaces the
    visible-param URLs.
    """
    dyn_file = layout.path(output_dir, "dynamic_urls.txt")
    target = layout.path(output_dir, "parameterized_urls.txt")

    existing = read_lines(target)
    existing_set = set(existing)
    seeded = [
        u for u in read_lines(dyn_file)
        if has_query_params(u) and u not in existing_set
    ]
    if seeded:
        write_lines(target, existing + seeded)

    return make_result(
        "param_seed", "success", input_path=str(dyn_file),
        outputs=[target], count=len(seeded),
        extra={"seeded": len(seeded), "total": len(existing) + len(seeded)},
    )


def append_param_urls(output_dir: Path, source: Path) -> dict:
    """Merge *source* into ``parameterized_urls.txt``, deduped.

    Generic version of :func:`seed_parameterized_urls` for producers that
    already emit finished ``?a=&b=`` URLs — currently the apidocs stage,
    whose params come from an OpenAPI document rather than from guessing.

    Unlike the seeder this does NOT require a query string: a spec path
    template like ``/users/{id}`` is a parameterised endpoint even though it
    carries no ``?``. Filtering those out would drop exactly the path-param
    endpoints that specs are best at revealing.

    Additive and safe: no-op (count 0) when *source* is missing or empty.
    """
    target = layout.path(output_dir, "parameterized_urls.txt")
    existing = read_lines(target)
    existing_set = set(existing)
    added = [u for u in read_lines(source) if u not in existing_set]
    if added:
        write_lines(target, existing + added)
    return make_result(
        "param_append", "success", input_path=str(source),
        outputs=[target], count=len(added),
        extra={"added": len(added), "total": len(existing) + len(added)},
    )
