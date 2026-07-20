"""url_merge — stage 5: merge + classify URLs from content discovery.

Inputs:
  processed/crawler_urls.txt
  processed/dirsearch_urls.txt
  processed/waymore_urls.txt

Outputs:
  processed/all_urls.txt       — normalised + de-duped
  processed/js_urls.txt        — JS URLs only
  processed/dynamic_urls.txt   — likely-dynamic, static assets removed

The earlier ``all_urls_raw.txt`` intermediate was dropped in v2 — it
was just the input to the dedup step, and any caller that needs the
raw union can re-merge the three source files deterministically.

Pure helper functions (dedupe_urls, normalize_url, is_js_url, is_dynamic_url)
are exposed at module level so the unit tests can import them.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

from .sensitive_ext import STATIC_EXT
from .utils import make_result, read_lines, write_lines


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
def merge(output_dir: Path, *, resume: bool = False, dry_run: bool = False) -> dict:
    stage = "url_merge"
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    files = [
        proc / "crawler_urls.txt",
        proc / "dirsearch_urls.txt",
        proc / "waymore_urls.txt",
    ]

    out_all = proc / "all_urls.txt"
    out_js = proc / "js_urls.txt"
    out_dyn = proc / "dynamic_urls.txt"

    if resume and all(p.exists() and p.stat().st_size > 0 for p in (out_all, out_js, out_dyn)):
        return make_result(
            stage, "success", input_path=",".join(str(f) for f in files),
            outputs=[out_all, out_js, out_dyn],
            count=len(read_lines(out_all)),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=",".join(str(f) for f in files),
            outputs=[out_all, out_js, out_dyn], count=0, error="dry-run",
        )

    all_lines: list[str] = []
    for f in files:
        all_lines.extend(read_lines(f))

    normalised = [normalize_url(u) for u in dedupe_urls(all_lines)]
    normalised = [u for u in normalised if u]
    n_all = write_lines(out_all, normalised)

    js_urls = [u for u in normalised if is_js_url(u)]
    n_js = write_lines(out_js, js_urls)

    dyn_urls = [u for u in normalised if is_dynamic_url(u)]
    n_dyn = write_lines(out_dyn, dyn_urls)

    return make_result(
        stage, "success", input_path=",".join(str(f) for f in files),
        outputs=[out_all, out_js, out_dyn],
        count=n_all, extra={"js": n_js, "dynamic": n_dyn},
    )


def append_urls(output_dir: Path, extra_files: list[Path]) -> dict:
    """Re-merge after xnLinkFinder (stage 6.2) and re-classify.

    The spec says: "Merge xnLinkFinder URLs back into processed/all_urls.txt.
    Deduplicate again after merge." We do exactly that.
    """
    stage = "url_merge_append"
    proc = output_dir / "processed"
    out_all = proc / "all_urls.txt"
    out_js = proc / "js_urls.txt"
    out_dyn = proc / "dynamic_urls.txt"

    existing = read_lines(out_all)
    extra: list[str] = []
    for f in extra_files:
        extra.extend(read_lines(f))
    merged = [normalize_url(u) for u in dedupe_urls(existing + extra)]
    merged = [u for u in merged if u]
    n_all = write_lines(out_all, merged)
    n_js = write_lines(out_js, [u for u in merged if is_js_url(u)])
    n_dyn = write_lines(out_dyn, [u for u in merged if is_dynamic_url(u)])
    return make_result(
        stage, "success", input_path=",".join(str(f) for f in extra_files),
        outputs=[out_all, out_js, out_dyn],
        count=n_all, extra={"js": n_js, "dynamic": n_dyn},
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
    proc = output_dir / "processed"
    hosts = extract_in_scope_hosts(read_lines(proc / "all_urls.txt"), domain)
    known = set(read_lines(proc / "subdomains.txt"))
    new = [h for h in hosts if h not in known]
    out_path = proc / "url_derived_subdomains.txt"
    write_lines(out_path, new)
    return make_result(
        "url_subdomains", "success", input_path=str(proc / "all_urls.txt"),
        outputs=[out_path], count=len(new),
        extra={"in_scope_hosts": len(hosts), "new": len(new)},
    )


def seed_parameterized_urls(output_dir: Path) -> dict:
    """Seed ``parameterized_urls.txt`` with URLs that ALREADY carry params.

    ``nuclei_dynamic`` scans only ``parameterized_urls.txt`` — which is
    built from arjun's discoveries + jsluice params. But URLs that already
    show ``?id=1`` in the crawl/waymore results are prime injection targets
    that reach the dynamic scan *only if arjun happens to re-discover them*.
    When arjun is skipped, capped (``max_urls``), or fails, those obvious
    param URLs get **zero** dynamic coverage — even though they were sitting
    in ``dynamic_urls.txt`` the whole time.

    This step reads ``dynamic_urls.txt``, keeps the ones with a query string,
    and merges them (deduped) into ``parameterized_urls.txt`` — independent
    of arjun. Runs between arjun (stage 7) and nuclei_dynamic (stage 8), so
    the final input is::

        parameterized_urls.txt = {already-param URLs}
                               ∪ {arjun-discovered}
                               ∪ {jsluice params}

    Additive and safe: creates the file if missing, so even a run with
    ``--skip-arjun`` and no jsluice hits still gives nuclei_dynamic the
    visible-param URLs to scan.
    """
    proc = output_dir / "processed"
    dyn_file = proc / "dynamic_urls.txt"
    target = proc / "parameterized_urls.txt"

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
