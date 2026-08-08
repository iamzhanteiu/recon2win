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
from typing import Any, Iterable, Optional
from urllib.parse import urljoin, urlparse

from . import console, fuzz_depth, fuzz_targets, layout, runner
from .utils import (
    load_json,
    make_result,
    raw_dir,
    read_lines,
    write_json,
    write_lines,
)

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
    "/swagger/v3/swagger.json",
    "/swagger/docs/v1", "/swagger/docs/v2",
    "/api-docs/v1", "/api-docs/v2",
    "/openapi/v3", "/openapi/v2",
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
    "/api/schema/swagger-ui/", "/api/schema/redoc/",       # DRF spectacular UI
    "/graphql/schema", "/graphql/schema.json",             # GraphQL SDL export
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

# Extra spec paths tried ONLY on hosts whose tech (httpx ``-td`` or
# confirmed-tech from a prior scan) matches the key — so a Spring host gets
# springdoc's paths and a Django host gets DRF's, instead of every host
# paying for every framework's convention. Keys are the same lowercase
# ``fuzz_depth._TECH_HINTS`` tokens used for tiering, so the tech signal is
# shared, not re-derived. Merged on top of ``SPEC_PATHS`` for that host.
TECH_SPEC_PATHS: dict[str, tuple[str, ...]] = {
    "spring": (
        "/v3/api-docs", "/v3/api-docs/swagger-config",
        "/swagger-ui/index.html", "/swagger-ui.html",
        "/actuator", "/actuator/mappings",
    ),
    "tomcat": ("/swagger-ui.html", "/v2/api-docs"),
    "wordpress": ("/wp-json", "/wp-json/wp/v2", "/?rest_route=/"),
    "jira": ("/rest/api/2/serverInfo", "/rest/api/latest/serverInfo"),
    "confluence": ("/rest/api/content", "/wiki/rest/api/content"),
    "gitlab": ("/api/v4/version", "/api/v4/metadata"),
    "kubernetes": ("/openapi/v2", "/openapi/v3", "/apis"),
    "consul": ("/v1/agent/self",),
}


def tech_spec_paths(tech_keys: Iterable[str]) -> tuple[str, ...]:
    """Extra spec paths for the tech keys seen on one host, deduped and
    order-stable. Keys with no entry contribute nothing — a host still gets
    the full ``SPEC_PATHS`` base set regardless."""
    out: list[str] = []
    seen: set[str] = set()
    for k in tech_keys:
        for p in TECH_SPEC_PATHS.get(k, ()):  # noqa: PERF401 — dedupe needed
            if p not in seen:
                seen.add(p)
                out.append(p)
    return tuple(out)


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
    # AsyncAPI: event-driven API contract. Same precision bar as OpenAPI —
    # the version key alone is not enough, it must also carry a ``channels``
    # object (AsyncAPI's equivalent of ``paths``), so an arbitrary JSON that
    # happens to have an ``asyncapi`` key is not mistaken for a spec.
    if data.get("asyncapi"):
        return data if isinstance(data.get("channels"), dict) else None
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
            url = str(srv["url"])
            # OpenAPI 3 server URLs can be templated (``https://{env}.x.com``);
            # fill each ``{var}`` with its declared default so the base is a
            # real URL rather than one carrying literal braces.
            variables = srv.get("variables")
            if isinstance(variables, dict):
                for name, meta in variables.items():
                    if isinstance(meta, dict) and meta.get("default") is not None:
                        url = url.replace("{%s}" % name, str(meta["default"]))
            bases.append(urljoin(doc_url, url))
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


def _resolve_ref(spec: dict, ref: str) -> Any:
    """Follow a LOCAL JSON-Pointer ``$ref`` (``#/components/parameters/Foo``).

    Only in-document refs are resolved — external files/URLs are never
    fetched (that would turn spec parsing into a fan-out crawler and open an
    SSRF-shaped hole). Returns ``None`` when the ref is external or dangling.
    """
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _deref(spec: dict, node: Any) -> Any:
    """Resolve *node* when it is a ``{"$ref": …}`` wrapper, else return it."""
    if isinstance(node, dict) and "$ref" in node:
        resolved = _resolve_ref(spec, str(node["$ref"]))
        if resolved is not None:
            return resolved
    return node


def _schema_prop_names(spec: dict, schema: Any, _depth: int = 0) -> list[str]:
    """Top-level property names of a (possibly ``$ref``/``allOf``) schema.

    These become the body-parameter names of a request body. Recursion is
    bounded (``_depth``) so a self-referential schema cannot loop forever.
    """
    if _depth > 5:
        return []
    schema = _deref(spec, schema)
    if not isinstance(schema, dict):
        return []
    names: list[str] = []
    props = schema.get("properties")
    if isinstance(props, dict):
        names.extend(str(k) for k in props)
    for sub in schema.get("allOf") or []:
        names.extend(_schema_prop_names(spec, sub, _depth + 1))
    return names


def _body_param_names(spec: dict, item: dict, ops: dict) -> list[str]:
    """Body/formData parameter names for one path item.

    Covers both spec dialects: OpenAPI 3 ``requestBody.content.*.schema``
    and Swagger 2 ``parameters`` with ``in: body`` / ``in: formData``. Body
    params are the surface a GET-only crawler never sees — the whole point of
    reading them out of the spec.
    """
    names: list[str] = []

    def _add(n: str) -> None:
        n = (n or "").strip()
        if n and n not in names:
            names.append(n)

    # Swagger 2 — body/formData live in the parameter list.
    param_lists = [item.get("parameters")]
    for op in ops.values():
        param_lists.append(op.get("parameters"))
    for plist in param_lists:
        if not isinstance(plist, list):
            continue
        for prm in plist:
            prm = _deref(spec, prm)
            if not isinstance(prm, dict):
                continue
            loc = prm.get("in")
            if loc == "formData":
                _add(str(prm.get("name") or ""))
            elif loc == "body":
                for bn in _schema_prop_names(spec, prm.get("schema")):
                    _add(bn)
    # OpenAPI 3 — requestBody per operation.
    for op in ops.values():
        rb = _deref(spec, op.get("requestBody"))
        if not isinstance(rb, dict):
            continue
        content = rb.get("content")
        if not isinstance(content, dict):
            continue
        for media in content.values():
            if isinstance(media, dict):
                for bn in _schema_prop_names(spec, media.get("schema")):
                    _add(bn)
    return names


def spec_endpoints(spec: dict, doc_url: str) -> tuple[list[str], list[str]]:
    """Return ``(urls, param_urls)`` extracted from a parsed spec.

    ``urls`` are plain absolute endpoints. ``param_urls`` carry the spec's
    declared parameters as ``?a=&b=`` so they land in the hand-testing
    shortlist — these are the best injection candidates in the entire run,
    because the developers documented exactly what each one takes.

    Three kinds of parameter feed the shortlist now, not just query:

      * **query** params (``in: query``) — as before;
      * **body/formData** params (OpenAPI ``requestBody`` + Swagger ``in:
        body``/``formData``) — the POST/PUT surface a GET-only crawler never
        sees, emitted the same ``?name=`` way jsluice's body params are so
        the downstream shortlist treats them uniformly;
      * **path-template** endpoints (``/users/{id}``) with no other param —
        the ``{id}`` itself is a parameter surface, so the templated URL is
        added to the shortlist even without a query string.

    Path templates keep their ``{id}`` placeholders: rewriting them to a
    guessed value would fabricate URLs that were never observed. Local
    ``$ref``s are resolved (:func:`_resolve_ref`); external ones are not.
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
        ops: dict[str, dict] = {}
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = item.get(method)
            if isinstance(op, dict):
                ops[method] = op
        # Query params: on the path item (shared) or per operation.
        query_names: list[str] = []
        for plist in [item.get("parameters")] + [op.get("parameters") for op in ops.values()]:
            if not isinstance(plist, list):
                continue
            for prm in plist:
                prm = _deref(spec, prm)
                if not isinstance(prm, dict) or prm.get("in") != "query":
                    continue
                nm = str(prm.get("name") or "").strip()
                if nm and nm not in query_names:
                    query_names.append(nm)
        body_names = [b for b in _body_param_names(spec, item, ops)
                      if b not in query_names]
        names = query_names + body_names
        if names:
            qs = "&".join(f"{n}=" for n in names)
            for base in bases:
                param_urls.append(f"{base}{raw_path}?{qs}")
        elif "{" in raw_path:
            for base in bases:
                param_urls.append(base + raw_path)
    return urls, param_urls


def spec_summary(spec: dict, doc_url: str) -> dict:
    """Compact record for findings/api_docs.json + the report."""
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    if spec.get("asyncapi"):
        # AsyncAPI keys its operations under ``channels``, not ``paths``.
        paths = spec.get("channels") if isinstance(spec.get("channels"), dict) else {}
    else:
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
    kind = ("asyncapi" if spec.get("asyncapi")
            else "openapi" if spec.get("openapi") else "swagger")
    return {
        "url": doc_url,
        "kind": kind,
        "version": str(spec.get("asyncapi") or spec.get("openapi")
                       or spec.get("swagger") or ""),
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


def build_candidates_tech(
    hosts: list[str],
    base_paths: tuple[str, ...],
    host_tech: dict[str, tuple[str, ...]] | None = None,
) -> list[str]:
    """Like :func:`build_candidates`, but each host also gets the extra spec
    paths its tech implies (:data:`TECH_SPEC_PATHS`).

    *host_tech* maps a host URL (exactly as it appears in *hosts*) to the
    lowercase tech keys seen on it. A host with no entry gets only
    *base_paths* — the tech paths are additive, never a replacement.
    """
    host_tech = host_tech or {}
    out: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        raw = h.strip()
        base = raw.rstrip("/")
        if not base.startswith(("http://", "https://")):
            continue
        paths = base_paths
        extra = tech_spec_paths(host_tech.get(raw, ()) or host_tech.get(base, ()))
        if extra:
            paths = base_paths + tuple(p for p in extra if p not in base_paths)
        for p in paths:
            u = base + p
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
# UI → spec chase. A docs UI (swagger-ui/redoc/scalar/…) is not a dead end:
# it always tells the browser where the real spec lives, either in a
# ``swagger-config`` document or inline in its own HTML. Following that
# pointer turns a "ui" hit — previously recorded and dropped — into a parsed
# spec with every route and parameter. This is the single biggest recall win
# in the stage.
# ----------------------------------------------------------------------
def swagger_config_paths(base: str) -> list[str]:
    """Well-known ``swagger-config`` URLs for a base origin.

    springdoc serves the list of real spec URLs at
    ``/v3/api-docs/swagger-config``; springfox at ``/swagger-resources``.
    Both are pointers, not specs — parsed by :func:`parse_swagger_config`.
    """
    base = base.rstrip("/")
    return [base + p for p in (
        "/v3/api-docs/swagger-config",
        "/swagger-config",
        "/api-docs/swagger-config",
        "/swagger-resources",
    )]


def parse_swagger_config(text: str, base: str) -> list[str]:
    """Absolute spec URLs a swagger-config / swagger-resources doc points at.

    Handles both shapes: an object with ``url`` / ``urls:[{url}]``
    (springdoc) and a bare list of ``{"url"|"location": …}`` (springfox).
    Relative values are resolved against *base*. Never raises.
    """
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[str] = []

    def _add(u: Any) -> None:
        if isinstance(u, str) and u.strip():
            u = u.strip()
            if not u.startswith(("http://", "https://")):
                u = urljoin(base.rstrip("/") + "/", u.lstrip("/"))
            if u not in out:
                out.append(u)

    if isinstance(data, dict):
        _add(data.get("url"))
        for it in data.get("urls") or []:
            if isinstance(it, dict):
                _add(it.get("url"))
    elif isinstance(data, list):
        for it in data:
            if isinstance(it, dict):
                _add(it.get("url") or it.get("location"))
    return out


# swagger-ui/redoc/scalar/rapidoc all point at their spec through one of a
# small set of attributes; catch each. Kept intentionally loose (any quoted
# value) and filtered afterwards by :func:`_looks_like_spec_url`, so a new
# UI framework's ``url:`` still gets picked up.
_UI_SPEC_PATTERNS = (
    re.compile(r"""["']?url["']?\s*:\s*["']([^"']+)["']"""),      # SwaggerUIBundle({url:"…"})
    re.compile(r"""spec-url\s*=\s*["']([^"']+)["']"""),            # <redoc spec-url="…">
    re.compile(r"""data-url\s*=\s*["']([^"']+)["']"""),            # scalar/rapidoc
    re.compile(r"""configUrl["']?\s*:\s*["']([^"']+)["']"""),      # swagger-ui configUrl
)


def _looks_like_spec_url(url: str) -> bool:
    low = url.lower().split("?")[0]
    return (
        low.endswith((".json", ".yaml", ".yml"))
        or "api-docs" in low
        or "openapi" in low
        or "swagger" in low
        or low.endswith("/swagger-config")
        or low.endswith("/swagger-resources")
    )


def spec_urls_from_ui(html: str, page_url: str) -> list[str]:
    """Candidate spec/config URLs referenced inside a docs-UI HTML page.

    Resolves relative references against *page_url* and keeps only values
    that look like a spec or a swagger-config pointer, so the chase does not
    re-fetch every ``.css``/``.js`` the page mentions.
    """
    if not html:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for pat in _UI_SPEC_PATTERNS:
        for m in pat.finditer(html):
            raw = (m.group(1) or "").strip()
            if not raw or raw.startswith(("data:", "#", "javascript:", "//")):
                continue
            full = urljoin(page_url, raw)
            if _looks_like_spec_url(full) and full not in seen:
                seen.add(full)
                out.append(full)
    return out


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


# A real workspace/collection name is a short product or org name. Longest
# genuine one seen so far is 38 chars; measured on dialogue.co, a domain
# token that happens to be a common word ("dialogue") let through "Divine
# Dialogue Reviews - David Riflin Manifestation Program Legit? What Are
# Users Saying? PDF Download!" (106 chars) — clickbait, not a real hit, and
# word-boundary matching alone cannot tell the two apart.
_MAX_NAME_LEN = 80


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
    if len(name or "") > _MAX_NAME_LEN:
        return False
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


def _iter_postman_requests(node: Any):
    """Yield every ``item.request`` in a Postman collection, recursively.

    Postman collections nest folders arbitrarily under ``item[]``; requests
    are leaf ``item`` entries carrying a ``request`` object.
    """
    if isinstance(node, dict):
        req = node.get("request")
        if isinstance(req, dict):
            yield req
        for child in node.get("item") or []:
            yield from _iter_postman_requests(child)
    elif isinstance(node, list):
        for child in node:
            yield from _iter_postman_requests(child)


def _postman_request_url(req: dict) -> str:
    """Reassemble the URL of one Postman request.

    ``request.url`` is either a raw string or a structured object
    (``{"raw": …, "host": [...], "path": [...]}``). Postman environment
    variables (``{{base_url}}``) are left as-is — filtered out later by
    scope, since they cannot be resolved without the environment.
    """
    url = req.get("url")
    if isinstance(url, str):
        return url.strip()
    if isinstance(url, dict):
        raw = url.get("raw")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        host = url.get("host")
        host_s = ".".join(host) if isinstance(host, list) else str(host or "")
        path = url.get("path")
        path_s = "/".join(str(p) for p in path) if isinstance(path, list) else str(path or "")
        if host_s:
            return f"https://{host_s}/{path_s}".rstrip("/")
    return ""


def fetch_postman_collection(collection_id: str, domain: str, *,
                             timeout: int = 20) -> list[str]:
    """In-scope request URLs from a public Postman collection.

    Turns an OSINT *hit* (a collection exists) into actual endpoints. Uses
    Postman's public collection endpoint; fail-soft like the rest of the
    OSINT half. Only URLs whose host is in scope for *domain* are returned —
    a public collection routinely mixes third-party APIs in.
    """
    if not collection_id:
        return []
    try:
        import requests
    except ImportError:
        return []
    try:
        r = requests.get(
            f"https://www.postman.com/_api/collection/{collection_id}",
            headers={"Accept": "application/json"}, timeout=timeout,
        )
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:          # noqa: BLE001 — third-party, never fatal
        return []
    coll = (data or {}).get("data") or data
    coll = coll.get("collection") if isinstance(coll, dict) and "collection" in coll else coll
    from . import url_merge          # local: avoid import cost when unused
    out: list[str] = []
    seen: set[str] = set()
    for req in _iter_postman_requests(coll):
        u = _postman_request_url(req)
        if not u.startswith(("http://", "https://")):
            continue
        if not url_merge.is_in_scope(u, domain):
            continue
        if u not in seen:
            seen.add(u)
            out.append(u)
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
def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _origin(url: str) -> str:
    """``scheme://netloc`` of a URL — the base spec paths hang off."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def _chase_specs(ui_rows: list[dict], output_dir: Path, a_cfg: dict,
                 record_spec) -> dict:
    """Follow docs-UI hits to the real spec (A1). Up to two extra probe rounds:

      round 2 — swagger-config well-knowns + spec URLs parsed out of the UI
                HTML. A response that IS a spec is recorded; one that is a
                swagger-config pointer feeds round 3.
      round 3 — the spec URLs a swagger-config pointed at.

    Bounded by the (small) number of UI hosts, so the extra cost is a couple
    of httpx runs, not another full sweep.
    """
    stats: dict = {"config_candidates": 0, "specs_found": 0, "rounds": 0}
    cand: list[str] = []
    seen: set[str] = set()
    for row in ui_rows:
        page_url = row.get("url") or ""
        origin = _origin(page_url)
        if not origin:
            continue
        body = row.get("body") or row.get("response") or ""
        for u in swagger_config_paths(origin) + spec_urls_from_ui(body, page_url):
            if u not in seen:
                seen.add(u)
                cand.append(u)
    if not cand:
        return stats
    stats["config_candidates"] = len(cand)
    stats["rounds"] = 1
    rows2 = _probe(cand, output_dir, a_cfg, tag="chase")
    stats["responses"] = len(rows2)
    round3: list[str] = []
    seen3: set[str] = set()
    for row in rows2:
        url = row.get("url") or ""
        body = row.get("body") or row.get("response") or ""
        spec = parse_spec(body)
        if spec:
            record_spec(spec, url, "ui-chase")
            stats["specs_found"] += 1
            continue
        for su in parse_swagger_config(body, _origin(url)):
            if su not in seen3:
                seen3.add(su)
                round3.append(su)
    if round3:
        stats["rounds"] = 2
        rows3 = _probe(round3, output_dir, a_cfg, tag="chase2")
        for row in rows3:
            spec = parse_spec(row.get("body") or row.get("response") or "")
            if spec:
                record_spec(spec, row.get("url") or "", "ui-chase")
                stats["specs_found"] += 1
    return stats


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
    layout.ensure_tree(output_dir)
    findings = output_dir / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    urls_out = layout.path(output_dir, "apidocs_urls.txt")
    params_out = layout.path(output_dir, "apidocs_params.txt")
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
    seen_spec_urls: set[str] = set()
    api_hosts: set[str] = set()      # hosts confirmed to expose an API surface

    def _record_spec(spec: dict, url: str, source: str) -> None:
        """Add one parsed spec + its endpoints/params, deduped by URL."""
        if not url or url in seen_spec_urls:
            return
        seen_spec_urls.add(url)
        summ = spec_summary(spec, url)
        summ["source"] = source
        specs.append(summ)
        u, p = spec_endpoints(spec, url)
        all_urls.extend(u)
        all_params.extend(p)
        host = _host_of(url)
        if host:
            api_hosts.add(host)

    # ---------------- 1. active probe ----------------
    if a_cfg.get("probe", True):
        hosts = read_lines(alive_file)
        # httpx detail (+ tech confirmed on a PRIOR scan) drives two things:
        # wildcard dedup and tech-aware path selection.
        detail = load_json(layout.path(output_dir, "alive_detail.json"))
        detail_rows = detail if isinstance(detail, list) else []
        detail_rows = fuzz_depth.merge_confirmed_tech(
            detail_rows, fuzz_depth.load_confirmed_tech(output_dir))

        max_hosts = int(a_cfg.get("max_hosts", 300) or 0)
        # Dedup wildcard duplicates BEFORE crossing with the path list —
        # probing /v3/api-docs on 200 hosts that serve one app is the same
        # waste fuzzing already avoids. Reuse fuzz_targets so both stages
        # agree on what "the same app" is.
        if a_cfg.get("dedup_targets", True):
            hosts, sel_stats = fuzz_targets.select_targets(
                hosts, detail_rows, max_hosts=max_hosts, dedup=True)
            if sel_stats.get("deduped") or sel_stats.get("capped"):
                probe_stats["selection"] = sel_stats
        elif max_hosts and len(hosts) > max_hosts:
            probe_stats["hosts_capped"] = len(hosts) - max_hosts
            hosts = hosts[:max_hosts]

        base_paths = SPEC_PATHS
        extra_paths = a_cfg.get("extra_paths") or []
        if isinstance(extra_paths, list) and extra_paths:
            base_paths = base_paths + tuple(
                str(p) for p in extra_paths if str(p).startswith("/")
            )

        # Tech-aware paths (A2): each host also gets the spec paths its tech
        # implies, on top of the base set.
        host_tech: dict[str, tuple[str, ...]] = {}
        if a_cfg.get("tech_aware_paths", True):
            by_url = {r["url"].strip(): r for r in detail_rows
                      if isinstance(r, dict) and r.get("url")}
            for h in hosts:
                keys = fuzz_depth._matched_tech_keys(by_url.get(h.strip(), {}) or {})
                if keys:
                    host_tech[h] = tuple(keys)
            candidates = build_candidates_tech(hosts, base_paths, host_tech)
        else:
            candidates = build_candidates(hosts, base_paths)

        probe_stats.update({
            "hosts": len(hosts),
            "paths": len(base_paths),
            "requests": len(candidates),
            "tech_hosts": len(host_tech),
        })
        if candidates and runner.tool_available("httpx"):
            rows = _probe(candidates, output_dir, a_cfg)
            probe_stats["responses"] = len(rows)
            ui_rows: list[dict] = []
            for row in rows:
                url = row.get("url") or ""
                kind = _classify_hit(row)
                if kind == "spec":
                    spec = parse_spec(row.get("body") or "")
                    if spec:
                        _record_spec(spec, url, "probe")
                elif kind == "ui":
                    ui_hits.append({"url": url, "status": row.get("status_code")})
                    ui_rows.append(row)
                    if _host_of(url):
                        api_hosts.add(_host_of(url))
                elif kind == "discovery":
                    discovery_hits.append({"url": url,
                                           "status": row.get("status_code")})
                    if _host_of(url):
                        api_hosts.add(_host_of(url))

            # UI → spec chase (A1): turn docs-UI dead-ends into parsed specs.
            if ui_rows and a_cfg.get("spec_chase", True):
                probe_stats["ui_chase"] = _chase_specs(
                    ui_rows, output_dir, a_cfg, _record_spec)
        elif candidates:
            probe_stats["error"] = "httpx binary not found"

    # ---------------- 2. external OSINT ----------------
    osint: list[dict] = []
    tgt = domain or output_dir.name
    if a_cfg.get("osint", True):
        if a_cfg.get("postman", True):
            pm = search_postman(tgt, limit=int(a_cfg.get("postman_limit", 25)))
            osint.extend(pm)
            # A collection HIT only says one exists; fetch it to turn the hit
            # into real in-scope endpoints (A5).
            if a_cfg.get("postman_fetch_collections", True):
                fetched = 0
                for hit in pm:
                    if str(hit.get("kind", "")).lower() != "collection":
                        continue
                    urls = fetch_postman_collection(hit.get("id", ""), tgt)
                    if urls:
                        all_urls.extend(urls)
                        all_params.extend(u for u in urls if "?" in u)
                        hit["endpoints"] = len(urls)
                        fetched += len(urls)
                if fetched:
                    probe_stats["postman_endpoints"] = fetched
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

    # Feedback for the NEXT scan's fuzzing: a host that exposed a spec/UI/
    # discovery doc is an API host — record it so fuzz_depth hands it the API
    # wordlist next run (same tech_confirmed.json mechanism misconfig_probe
    # uses). apidocs runs after fuzzing this run, so it only helps the next.
    if api_hosts:
        try:
            fuzz_depth.save_confirmed_tech(
                output_dir, {h: ["api"] for h in sorted(api_hosts)})
        except Exception:          # noqa: BLE001 — best-effort, never fatal
            pass

    total_paths = sum(s.get("paths", 0) for s in specs)
    chased_specs = sum(1 for s in specs if s.get("source") == "ui-chase")
    if specs:
        chase_note = (f" ({chased_specs} via UI→spec chase)"
                      if chased_specs else "")
        print(console.phase_info_line(
            f"[{stage}] {len(specs)} spec(s){chase_note} → {total_paths} "
            f"documented path(s), {n_params} with declared params"))
    if osint:
        print(console.phase_info_line(
            f"[{stage}] {len(osint)} external OSINT hit(s) "
            "(public Postman / GitHub)"))

    # Say WHY the outputs are empty, so a 0-line apidocs_urls.txt cannot be
    # misread as "this target publishes no API docs". On a discover.com run
    # every single probe came back 403 (Akamai answering for the origin) —
    # the stage succeeded and learned nothing, which is the opposite of a
    # clean result. Without this note the distinction only existed inside
    # findings/api_docs.json. Consumed by audit.build_manifest.
    empty_reason = None
    was_blocked = False
    if not specs:
        hits = ui_hits + discovery_hits
        refused = sum(1 for h in hits if h.get("status") in (401, 403))
        probed = probe_stats.get("responses")
        if probe_stats.get("error"):
            empty_reason = f"no specs parsed — {probe_stats['error']}"
        elif hits and refused == len(hits):
            was_blocked = True
            empty_reason = (
                f"no specs parsed — all {refused} candidate hit(s) returned "
                "401/403; the probe was refused, not answered"
            )
        elif not probed:
            empty_reason = "no specs parsed — no host answered the probe"
        else:
            empty_reason = f"no specs parsed from {probed} response(s)"

    return make_result(
        stage, "success", input_path=alive_file, outputs=outputs,
        count=len(specs) + len(ui_hits) + len(discovery_hits) + len(osint),
        error=empty_reason,
        extra={
            "blocked": was_blocked,
            "specs": len(specs), "ui": len(ui_hits),
            "specs_via_chase": chased_specs,
            "discovery": len(discovery_hits), "osint": len(osint),
            "api_hosts": len(api_hosts),
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


def _probe(candidates: list[str], output_dir: Path, a_cfg: dict,
           *, tag: str = "") -> list[dict]:
    """Run httpx over the candidate URLs and return the parsed JSONL rows.

    ``-irr`` (include response) is what makes the body available, and the
    body is the only thing that separates a real spec from a SPA's
    catch-all 200. ``-mc`` keeps the response set small.

    *tag* namespaces the on-disk artefacts (``candidates_<tag>.txt`` /
    ``probe_<tag>.jsonl``) so the UI-chase rounds don't clobber the first
    round's files.
    """
    raw = raw_dir(output_dir, "apidocs")
    suffix = f"_{tag}" if tag else ""
    in_file = raw / f"candidates{suffix}.txt"
    out_file = raw / f"probe{suffix}.jsonl"
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
