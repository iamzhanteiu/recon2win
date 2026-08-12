"""Client-side authorization analysis.

Mission rule: client-side ``isAdmin`` / ``role`` / ``permission`` checks
are **candidates for verification**, never automatically privilege
escalation. We surface them with a verification plan, because a UI gate
enforced only in JS is often re-enforced server-side (safe) — the whole
value is telling those two cases apart, which only a request can do.

We pair each authz identifier with the endpoint(s) referenced nearby, so
the verification step knows *which* API to replay without the client gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import ast_engine as A
from . import patterns as P


@dataclass
class AuthzFinding:
    identifier: str
    guards_endpoint: str | None
    location: dict | None
    evidence: str


def analyze(pm: A.ParsedModule) -> list[AuthzFinding]:
    if not pm.ok:
        return []
    out: list[AuthzFinding] = []
    seen: set[tuple] = set()

    for node in A.walk(pm.ast):
        t = getattr(node, "type", None)
        # if (isAdmin) {...}  /  user.role === 'admin'
        if t in ("IfStatement", "ConditionalExpression", "LogicalExpression"):
            test = getattr(node, "test", None) or node
            names = _authz_idents_in(test)
            for nm in names:
                ep = _nearby_endpoint(node)
                key = (nm, ep, (A.loc_of(node) or {}).get("line"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(AuthzFinding(
                    identifier=nm, guards_endpoint=ep,
                    location=A.loc_of(node),
                    evidence=f"client-side check on '{nm}'"))
    return out


def _authz_idents_in(node: Any) -> list[str]:
    names = []
    for n in A.walk(node):
        if getattr(n, "type", None) in ("Identifier", "MemberExpression"):
            nm = A.member_name(n)
            if P.AUTHZ_IDENTS.search(nm):
                names.append(nm)
    # dedupe preserve order, and drop a bare identifier when a fuller member
    # expression already covers it (`isAdmin` subsumed by `user.isAdmin`).
    seen, out = set(), []
    for n in names:
        if n in seen:
            continue
        if any(other != n and other.endswith("." + n) for other in names):
            continue
        seen.add(n)
        out.append(n)
    return out


def _nearby_endpoint(node: Any) -> str | None:
    """Any request URL string mentioned inside this guarded block."""
    for n in A.walk(node):
        if getattr(n, "type", None) == "CallExpression":
            name = A.call_name(n) or ""
            base = name.rsplit(".", 1)[-1]
            if name in P.NETWORK_CALLS or base in {k.rsplit('.', 1)[-1] for k in P.NETWORK_CALLS}:
                args = list(getattr(n, "arguments", []) or [])
                if args:
                    return A.string_value(args[0]) or None
    return None
