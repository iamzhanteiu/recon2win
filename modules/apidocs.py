"""apidocs — find the target's API documentation and turn it into endpoints.

An OpenAPI/Swagger document is the single highest-value artefact in web
recon: it hands you every route, every parameter, every auth scheme and
every request body the developers wrote down. One ``/v3/api-docs`` hit is
worth more than a day of directory brute-forcing.

Two independent sources, both optional and both fail-soft:

  1. **Active probe** — request a curated list of well-known spec paths on
     every alive host (``/openapi.json``, ``/v3/api-docs``, ``/swagger-ui``,
     ``/.well-known/openid-configuration``, …) with httpx. This is the
     reliable half: it stays inside the target's own scope.
  2. **External OSINT** — public Postman workspaces and (optionally)
     GitHub code search for specs the org leaked outside its perimeter.

Discovered routes are written as absolute URLs so the pipeline treats them
like any other discovered URL: they merge into ``all_urls.txt`` (→ httpx →
nuclei) and their parameters flow into ``parameterized_urls.txt``.

A note on precision, because it drove most of the design here: a 200 is
not a spec. Plenty of SPA hosts answer 200-with-index.html to *every*
path, so a status check alone would report a swagger doc on every host in
the run. Nothing counts as a find unless the body actually parses as
OpenAPI/Swagger — see :func:`parse_spec`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from . import console, runner
from .utils import make_result, raw_dir, read_lines, write_json, write_lines

# ----------------------------------------------------------------------
# Candidate paths. Ordered roughly by hit rate in the wild; the list is
# deliberately short — every entry costs one request per host, so a 60-path
# list against 500 hosts is already 30k requests.
# ----------------------------------------------------------------------
SPEC_PATHS: tuple[str, ...] = (
    # OpenAPI / Swagger — JSON
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api-docs", "/api-docs.json", "/apidocs.json",
    "/v2/api-docs", "/v3/api-docs", "/v3/api-docs/swagger-config",
    "/api/openapi.json", "/api/swagger.json", "/api/api-docs",
    "/api/v1/openapi.json", "/api/v1/swagger.json",
    "/api/v2/openapi.json", "/api/v2/swagger.json",
    "/api/v3/openapi.json",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger/docs/v1", "/swagger/docs/v2",
    "/docs/openapi.json", "/docs/swagger.json",
    "/static/openapi.json", "/static/swagger.json",
    "/spec/openapi.json", "/spec.json",
    # UI shells — no spec body, but they prove an API surface exists and
    # usually point at the real document.
    "/swagger-ui.html", "/swagger-ui/", "/swagger/", "/swagger/index.html",
    "/api-docs/", "/docs", "/docs/", "/redoc", "/redoc/",
    "/api/docs", "/api/documentation", "/documentation",
    "/scalar", "/rapidoc",
    # Framework-specific
    "/graphql", "/graphiql", "/altair", "/playground",     # GraphQL
    "/_openapi", "/__open_api", "/openapi",                # FastAPI variants
    "/api/schema", "/api/schema/",                         # DRF spectacular
    "/api.json", "/api/spec", "/api/v1/spec",
    "/wp-json", "/wp-json/wp/v2",                          # WordPress REST
    "/rest/api/2/serverInfo",                              # Jira
    "/actuator", "/actuator/mappings",                     # Spring Boot
    # Identity / discovery documents — not OpenAPI, but they leak the whole
    # auth surface (token endpoints, scopes, supported grants).
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
)

_UI_MARKERS = (
    "swagger-ui", "redoc", "swaggerui", "rapidoc", "graphiql",
    "openapi", "scalar-api-reference",
)


# ----------------------------------------------------------------------
# Spec parsing
# ----------------------------------------------------------------------
def parse_spec(text: str) -> Optional[dict]:
    """Return the parsed spec when *text* really is OpenAPI/Swagger.

    Returns ``None`` for anything else — that is the whole point. A host
    that answers 200-with-index.html on every path (every SPA does) would
    otherwise be reported as exposing a spec on all 60 candidate paths.

    Accepts JSON, and YAML when PyYAML is importable. Requires the
    ``openapi``/``swagger`` version key *and* a ``paths`` object, which is
    what distinguishes a spec from an arbitrary JSON document.
    """
    if not text or not text.strip():
        return None
    data: Any = None
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return None
    else:
        try:
            import yaml
            data = yaml.safe_load(text)
        except Exception:      # noqa: BLE001 — yaml missing or malformed
            return None
    if not isinstance(data, dict):
        return None
    if not (data.get("openapi") or data.get("swagger")):
        return None
    if not isinstance(data.get("paths"), dict):
        return None
    return data


def _spec_base_urls(spec: dict, doc_url: str) -> list[str]:
    """Absolute base URL(s) the spec's paths hang off.

    OpenAPI 3 uses ``servers[].url`` (may be relative); Swagger 2 uses
    ``host`` + ``basePath`` + ``schemes``. Both fall back to the URL the
    document itself was served from, which is right far more often than it
    is wrong.
    """
    bases: list[str] = []
    for srv in spec.get("servers") or []:
        if isinstance(srv, dict) and srv.get("url"):
            bases.append(urljoin(doc_url, str(srv["url"])))
    if not bases:
        host = spec.get("host")
        if host:
            scheme = (spec.get("schemes") or ["https"])[0]
            bases.append(f"{scheme}://{host}{spec.get('basePath', '') or ''}")
    if not bases:
        p = urlparse(doc_url)
        bases.append(f"{p.scheme}://{p.netloc}")
    # Normalise: no trailing slash, since paths always start with one.
    return [b.rstrip("/") for b in bases if b]


def spec_endpoints(spec: dict, doc_url: str) -> tuple[list[str], list[str]]:
    """Return ``(urls, param_urls)`` extracted from a parsed spec.

    ``urls`` are plain absolute endpoints. ``param_urls`` carry the spec's
    declared query parameters as ``?a=&b=`` so they land in the
    hand-testing shortlist — these are the best injection candidates in the
    entire run, because the developers documented exactly what each one
    takes.

    Path templates keep their ``{id}`` placeholders: rewriting them to a
    guessed value would fabricate URLs that were never observed. Leaving
    them intact makes it obvious to the operator that a value is needed.
    """
    urls: list[str] = []
    param_urls: list[str] = []
    bases = _spec_base_urls(spec, doc_url)
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return urls, param_urls

    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        for base in bases:
            urls.append(base + raw_path)
        if not isinstance(item, dict):
            continue
        # Query params can sit on the path item (shared) or per operation.
        names: list[str] = []
        sources = [item.get("parameters")]
        for method in ("get", "post", "put", "patch", "delete", "head"):
            op = item.get(method)
            if isinstance(op, dict):
                sources.append(op.get("parameters"))
        for plist in sources:
            if not isinstance(plist, list):
                continue
            for prm in plist:
                if not isinstance(prm, dict):
                    continue
                if prm.get("in") != "query":
                    continue
                nm = str(prm.get("name") or "").strip()
                if nm and nm not in names:
                    names.append(nm)
        if names:
            qs = "&".join(f"{n}=" for n in names)
            for base in bases:
                param_urls.append(f"{base}{raw_path}?{qs}")
    return urls, param_urls


def spec_summary(spec: dict, doc_url: str) -> dict:
    """Compact record for findings/api_docs.json + the report."""
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    comps = spec.get("components") if isinstance(spec.get("components"), dict) else {}
    schemes = comps.get("securitySchemes") or spec.get("securityDefinitions") or {}
    methods: dict[str, int] = {}
    for item in paths.values():
        if not isinstance(item, dict):
            continue
        for m in ("get", "post", "put", "patch", "delete"):
            if m in item:
                methods[m] = methods.get(m, 0) + 1
    return {
        "url": doc_url,
        "kind": "openapi" if spec.get("openapi") else "swagger",
        "version": str(spec.get("openapi") or spec.get("swagger") or ""),
        "title": str(info.get("title") or ""),
        "api_version": str(info.get("version") or ""),
        "paths": len(paths),
        "methods": methods,
        "security_schemes": sorted(schemes) if isinstance(schemes, dict) else [],
        "servers": _spec_base_urls(spec, doc_url),
    }


# ----------------------------------------------------------------------
# Active probe
# ----------------------------------------------------------------------
def build_candidates(hosts: list[str], paths: tuple[str, ...]) -> list[str]:
    """Cross hosts with candidate paths, order-preserving and deduped."""
    out: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        h = h.strip().rstrip("/")
        if not h.startswith(("http://", "https://")):
            continue
        for p in paths:
            u = h + p
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def _classify_hit(row: dict) -> Optional[str]:
    """``"spec"`` when the body parses as OpenAPI, ``"ui"`` for a docs UI.

    ``None`` means "200 but not actually API documentation" — the common
    case, and the reason this stage does not simply trust a status code.
    """
    body = row.get("body") or row.get("response") or ""
    if parse_spec(body):
        return "spec"
    ctype = str(row.get("content_type") or "").lower()
    low = body[:4000].lower()
    if any(m in low for m in _UI_MARKERS):
        return "ui"
    # A JSON discovery document (openid-configuration, jwks) is a real
    # finding even though it is not OpenAPI.
    if "json" in ctype:
        try:
            d = json.loads(body)
        except (ValueError, TypeError):
            return None
        if isinstance(d, dict) and (
            d.get("issuer") or d.get("keys") or d.get("token_endpoint")
        ):
            return "discovery"
    return None


# ----------------------------------------------------------------------
# External OSINT — Postman public workspaces
# ----------------------------------------------------------------------
_POSTMAN_URL = "https://www.postman.com/_api/ws/proxy"


def domain_tokens(domain: str) -> list[str]:
    """Distinctive words in a domain, for filtering OSINT noise.

    ``discover.com`` → ``["discover"]``. The TLD and common infrastructure
    words are dropped: matching on "com" or "api" would call every result
    a hit.
    """
    parts = re.split(r"[^a-z0-9]+", domain.lower())
    drop = {"com", "net", "org", "io", "co", "www", "api", "app", "dev",
            "cloud", "inc", "ltd", "gov", "edu", "uk", "de", "fr", "jp"}
    return [p for p in parts if p and len(p) >= 4 and p not in drop]


# Result kinds worth reporting. A single ``request`` named "discover users"
# inside somebody's unrelated collection is not a finding about the target —
# Postman scores those at ~0.01 and returns dozens per query.
_POSTMAN_KINDS = ("workspace", "collection")


def _postman_relevant(name: str, tokens: list[str]) -> bool:
    """Keep a Postman result only when it names one of the domain tokens.

    Score alone is useless: searching ``discover.com`` returns "Postman
    Public Workspace" at score 252 — above where a genuine hit for a small
    org would land (measured 2026-07-28).

    Matching is on WORD boundaries, not substrings. Against live Postman
    data the substring form let ``discover`` match "Bloomreach - Discovery
    Workspace", "Ticketmaster Discovery API" and "Postman Open Technologies
    - Discovery": 25 results, none of them the target. Word boundaries drop
    all three because ``discovery`` is not ``discover``.
    """
    words = set(re.split(r"[^a-z0-9]+", (name or "").lower()))
    return any(t in words for t in tokens)


def search_postman(domain: str, *, limit: int = 25,
                   timeout: int = 20) -> list[dict]:
    """Search public Postman workspaces/collections for *domain*.

    Uses Postman's public web-search backend (the same one the site's own
    search box calls). Unofficial and unversioned, so every failure mode —
    network error, shape change, HTML error page — is swallowed and
    reported as "no results" rather than breaking the stage.
    """
    try:
        import requests
    except ImportError:
        return []
    tokens = domain_tokens(domain)
    if not tokens:
        return []
    payload = {
        "service": "search",
        "method": "POST",
        "path": "/search-all",
        "body": {
            "queryIndices": ["collaboration.workspace", "runtime.collection"],
            "queryText": domain,
            "size": limit,
            "from": 0,
        },
    }
    try:
        r = requests.post(_POSTMAN_URL, json=payload, timeout=timeout,
                          headers={"Content-Type": "application/json"})
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:          # noqa: BLE001 — third-party, never fatal
        return []

    out: list[dict] = []
    blocks = (data or {}).get("data") or {}
    if not isinstance(blocks, dict):
        return []
    for kind, items in blocks.items():
        if not isinstance(items, list):
            continue
        if str(kind).lower() not in _POSTMAN_KINDS:
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            doc = it.get("document") or {}
            name = str(doc.get("name") or "")
            if not _postman_relevant(name, tokens):
                continue
            slug = doc.get("slug") or doc.get("publicHandle") or ""
            out.append({
                "source": "postman",
                "kind": str(kind),
                "name": name,
                "score": it.get("score"),
                "url": (f"https://www.postman.com/{slug}" if slug else ""),
                "id": str(doc.get("id") or ""),
            })
    return out


# ----------------------------------------------------------------------
# External OSINT — GitHub code search (needs a token)
# ----------------------------------------------------------------------
def search_github(domain: str, token: str, *, limit: int = 30,
                  timeout: int = 20) -> list[dict]:
    """Find spec files on GitHub mentioning *domain*.

    Requires a token: GitHub's code-search API rejects anonymous requests
    outright. Returns ``[]`` (never raises) without one, so the stage
    degrades to probe-only rather than failing.
    """
    if not token:
        return []
    try:
        import requests
    except ImportError:
        return []
    query = f'"{domain}" (filename:swagger.json OR filename:openapi.json OR filename:openapi.yaml)'
    try:
        r = requests.get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": min(limit, 100)},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=timeout,
        )
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:          # noqa: BLE001
        return []
    out: list[dict] = []
    for it in (data.get("items") or [])[:limit]:
        if not isinstance(it, dict):
            continue
        repo = (it.get("repository") or {}).get("full_name", "")
        out.append({
            "source": "github",
            "kind": "code",
            "name": f"{repo}/{it.get('path', '')}",
            "url": it.get("html_url", ""),
            "score": it.get("score"),
            "id": "",
        })
    return out


# ----------------------------------------------------------------------
# Stage entry point
# ----------------------------------------------------------------------
def _outputs_exist(output_dir: Path) -> bool:
    p = output_dir / "findings" / "api_docs.json"
    return p.exists() and p.stat().st_size > 0


def discover(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    domain: str = "",
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "apidocs"
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    findings = output_dir / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    urls_out = proc / "apidocs_urls.txt"
    params_out = proc / "apidocs_params.txt"
    json_out = findings / "api_docs.json"
    outputs = [urls_out, params_out, json_out]

    a_cfg = (cfg.get("apidocs") or {}) if isinstance(cfg, dict) else {}

    if skip:
        write_lines(urls_out, [])
        write_lines(params_out, [])
        write_json(json_out, {"specs": [], "ui": [], "osint": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="--skip-apidocs")
    if not a_cfg.get("enabled", True):
        write_lines(urls_out, [])
        write_lines(params_out, [])
        write_json(json_out, {"specs": [], "ui": [], "osint": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0,
                           error="disabled in config")
    if resume and _outputs_exist(output_dir):
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=len(read_lines(urls_out)))
    if dry_run:
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="dry-run")

    specs: list[dict] = []
    ui_hits: list[dict] = []
    discovery_hits: list[dict] = []
    all_urls: list[str] = []
    all_params: list[str] = []
    probe_stats: dict = {}

    # ---------------- 1. active probe ----------------
    if a_cfg.get("probe", True):
        hosts = read_lines(alive_file)
        max_hosts = int(a_cfg.get("max_hosts", 300) or 0)
        capped = 0
        if max_hosts and len(hosts) > max_hosts:
            capped = len(hosts) - max_hosts
            hosts = hosts[:max_hosts]
        paths = SPEC_PATHS
        extra_paths = a_cfg.get("extra_paths") or []
        if isinstance(extra_paths, list) and extra_paths:
            paths = paths + tuple(
                str(p) for p in extra_paths if str(p).startswith("/")
            )
        candidates = build_candidates(hosts, paths)
        probe_stats = {
            "hosts": len(hosts), "hosts_capped": capped,
            "paths": len(paths), "requests": len(candidates),
        }
        if candidates and runner.tool_available("httpx"):
            rows = _probe(candidates, output_dir, a_cfg)
            probe_stats["responses"] = len(rows)
            for row in rows:
                url = row.get("url") or ""
                kind = _classify_hit(row)
                if kind == "spec":
                    spec = parse_spec(row.get("body") or "")
                    if not spec:
                        continue
                    specs.append(spec_summary(spec, url))
                    u, p = spec_endpoints(spec, url)
                    all_urls.extend(u)
                    all_params.extend(p)
                elif kind == "ui":
                    ui_hits.append({"url": url,
                                    "status": row.get("status_code")})
                elif kind == "discovery":
                    discovery_hits.append({"url": url,
                                           "status": row.get("status_code")})
        elif candidates:
            probe_stats["error"] = "httpx binary not found"

    # ---------------- 2. external OSINT ----------------
    osint: list[dict] = []
    tgt = domain or output_dir.name
    if a_cfg.get("osint", True):
        if a_cfg.get("postman", True):
            osint.extend(search_postman(
                tgt, limit=int(a_cfg.get("postman_limit", 25))))
        gh_token = str(a_cfg.get("github_token") or "").strip()
        if gh_token:
            osint.extend(search_github(tgt, gh_token))

    # ---------------- 3. persist ----------------
    n_urls = write_lines(urls_out, _dedup(all_urls))
    n_params = write_lines(params_out, _dedup(all_params))
    write_json(json_out, {
        "specs": specs,
        "ui": ui_hits,
        "discovery": discovery_hits,
        "osint": osint,
        "probe": probe_stats,
    })

    total_paths = sum(s.get("paths", 0) for s in specs)
    if specs:
        print(console.phase_info_line(
            f"[{stage}] {len(specs)} spec(s) → {total_paths} documented "
            f"path(s), {n_params} with declared params"))
    if osint:
        print(console.phase_info_line(
            f"[{stage}] {len(osint)} external OSINT hit(s) "
            "(public Postman / GitHub)"))

    return make_result(
        stage, "success", input_path=alive_file, outputs=outputs,
        count=len(specs) + len(ui_hits) + len(discovery_hits) + len(osint),
        extra={
            "specs": len(specs), "ui": len(ui_hits),
            "discovery": len(discovery_hits), "osint": len(osint),
            "documented_paths": total_paths,
            "urls": n_urls, "param_urls": n_params,
            "probe": probe_stats,
        },
    )


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _probe(candidates: list[str], output_dir: Path, a_cfg: dict) -> list[dict]:
    """Run httpx over the candidate URLs and return the parsed JSONL rows.

    ``-irr`` (include response) is what makes the body available, and the
    body is the only thing that separates a real spec from a SPA's
    catch-all 200. ``-mc`` keeps the response set small.
    """
    raw = raw_dir(output_dir, "apidocs")
    in_file = raw / "candidates.txt"
    out_file = raw / "probe.jsonl"
    write_lines(in_file, candidates)
    if out_file.exists():
        out_file.unlink()

    cmd = [
        "httpx", "-l", str(in_file),
        "-json", "-silent", "-irr",
        "-mc", str(a_cfg.get("match_codes", "200,401,403")),
        "-threads", str(int(a_cfg.get("threads", 40))),
        "-timeout", str(int(a_cfg.get("http_timeout", 10))),
        "-retries", "1",
        "-o", str(out_file),
    ]
    runner.run(cmd, stage="apidocs", output_dir=output_dir,
               timeout=int(a_cfg.get("timeout", 1800)))

    rows: list[dict] = []
    if not out_file.exists():
        return rows
    for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except (ValueError, TypeError):
            continue
    return rows
