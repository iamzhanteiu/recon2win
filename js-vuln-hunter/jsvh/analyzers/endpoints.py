"""API endpoint extraction from JS.

recon2win's jsluice already mines endpoints with its own AST; we do *not*
re-mine the whole corpus. This analyzer complements it by resolving
**dynamically constructed** request URLs into structured endpoints — the
``fetch(base + "/users/" + id)`` case the mission calls out — and by
attaching method + auth hints + an "interesting" flag, which the flat
jsluice endpoint list does not carry.
"""

from __future__ import annotations

from typing import Any

from .. import ast_engine as A
from ..models import Endpoint
from . import patterns as P


def _auth_hint(node: Any) -> str | None:
    """Peek at a request's options object / nearby text for auth signals."""
    txt = ""
    for n in A.walk(node):
        v = A.string_value(n) if getattr(n, "type", None) in ("Literal", "TemplateLiteral") else None
        if v:
            txt += " " + v.lower()
        if getattr(n, "type", None) == "Identifier":
            txt += " " + n.name.lower()
    if "authorization" in txt or "bearer" in txt:
        return "bearer"
    if "x-api-key" in txt or "apikey" in txt or "api_key" in txt:
        return "apikey"
    if "cookie" in txt or "credentials" in txt:
        return "cookie"
    return None


def analyze(asset_id: str, pm: A.ParsedModule) -> list[Endpoint]:
    if not pm.ok:
        return []
    endpoints: list[Endpoint] = []
    counter = 0

    for node in A.walk(pm.ast):
        if getattr(node, "type", None) != "CallExpression":
            continue
        name = A.call_name(node) or ""
        base = name.rsplit(".", 1)[-1]
        args = list(getattr(node, "arguments", []) or [])
        if not args:
            continue

        method = None
        url_node = None
        kind = "rest"

        if name in P.NETWORK_CALLS or base in {k.rsplit(".", 1)[-1] for k in P.NETWORK_CALLS}:
            method = P.NETWORK_CALLS.get(name) or P.NETWORK_CALLS.get(base) or "GET"
            url_node = args[0]
            # $.ajax({url:...}) style — url is inside an object, skip precise here
        elif base == "open" and len(args) >= 2 and "xhr" in name.lower() or \
                (base == "open" and len(args) >= 2 and _looks_method(args[0])):
            method = (A.string_value(args[0]) or "GET").upper()
            url_node = args[1]
        elif "graphql" in name.lower():
            method = "POST"
            kind = "graphql"
            url_node = args[0]
        else:
            continue

        if url_node is None:
            continue
        url_tmpl = A.string_value(url_node)
        if url_tmpl is None:
            # entirely dynamic (a bare variable) — record as unresolved
            url_tmpl = "{" + A.member_name(url_node) + "}"
        dynamic = "{" in url_tmpl

        # skip obvious non-endpoints
        if not url_tmpl or url_tmpl in ("{expr}",):
            continue

        counter += 1
        params: list[str] = []
        if "?" in url_tmpl:
            q = url_tmpl.split("?", 1)[1]
            params = [kv.split("=", 1)[0] for kv in q.split("&") if kv]

        m = (method or "").upper()
        obj_ids = P.object_ids_in(url_tmpl, params)
        sensitive = bool(P.SENSITIVE_PATH.search(url_tmpl)) or m in P.MUTATING_METHODS
        endpoints.append(Endpoint(
            endpoint_id=f"{asset_id}-ep-{counter:03d}",
            asset_id=asset_id,
            method=m,
            url_template=url_tmpl,
            kind=kind,
            dynamic=dynamic,
            parameters=params,
            auth_hint=_auth_hint(node),
            interesting=bool(P.INTERESTING_PATH.search(url_tmpl)),
            object_ids=obj_ids,
            sensitive_op=sensitive,
            location=A.loc_of(node),
        ))
    return endpoints


def _looks_method(node: Any) -> bool:
    v = A.string_value(node)
    return isinstance(v, str) and v.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
