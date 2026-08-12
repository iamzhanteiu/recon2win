"""Source detection helpers.

Two entry points:
  * ``node_sources`` — every source reference inside an arbitrary
    expression node (used by the data-flow engine to test a sink's value).
  * ``collect`` — all source references in a module (for inventory/stats).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import ast_engine as A
from . import patterns as P


@dataclass
class SourceRef:
    name: str
    kind: str
    location: dict | None


def node_sources(node: Any) -> list[SourceRef]:
    """Source references reachable inside *node* (shallow expression walk)."""
    out: list[SourceRef] = []
    seen: set[str] = set()
    for n in A.walk(node):
        t = getattr(n, "type", None)
        if t in ("MemberExpression", "Identifier", "CallExpression"):
            name = A.member_name(n)
            kind = P.match_source(name)
            if kind and name not in seen:
                seen.add(name)
                out.append(SourceRef(name, kind, A.loc_of(n)))
    return out


def collect(pm: A.ParsedModule) -> list[SourceRef]:
    if not pm.ok:
        return []
    return node_sources(pm.ast)
