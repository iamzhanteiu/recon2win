"""Intra-file data-flow / taint engine — the core of the workspace.

For every sink hit we answer three questions the mission demands:

    SOURCE ─▶ TRANSFORMATION ─▶ VALIDATION/SANITIZATION ─▶ SINK

  1. attacker_controlled?  does an attacker-influenceable source reach the
     value flowing into this sink — directly, or through a tainted local?
  2. transforms            which functions wrapped the value on the way.
  3. sanitization          none / weak / known-safe / unknown.

Design: a pragmatic fixpoint taint propagation over the flat list of
assignments in a module. Full inter-procedural analysis is out of scope
(that's what manual verification is for); this deliberately favours
*recall with an honest confidence* over false precision — every flow is a
*candidate*, never a confirmed bug (mission §14).
"""

from __future__ import annotations

from typing import Any

from .. import ast_engine as A
from ..models import DataFlow
from . import patterns as P
from . import sinks as SINKS
from . import sources as SOURCES


def _collect_assignments(pm: A.ParsedModule) -> list[tuple[str, Any, dict | None]]:
    """Every `x = expr` / `var x = expr` as (target_name, value_node, node)."""
    out = []
    for node in A.walk(pm.ast):
        t = getattr(node, "type", None)
        if t == "VariableDeclarator" and getattr(node, "init", None) is not None:
            name = A.member_name(node.id) if getattr(node, "id", None) else None
            if name:
                out.append((name, node.init, node))
        elif t == "AssignmentExpression" and node.operator == "=":
            out.append((A.member_name(node.left), node.right, node))
    return out


# --- lexical scope indexing ------------------------------------------------
# Minified code reuses one-letter/`options` names across unrelated functions.
# Name-only taint therefore leaks between sibling functions and manufactures
# false "attacker-controlled" flows (a verified real-world FP). We key taint by
# (scope, name) so a variable tainted in one function is visible only in that
# function and its descendants (closures) — never in a sibling.
_FUNC_TYPES = {"FunctionDeclaration", "FunctionExpression",
               "ArrowFunctionExpression", "Program"}


def _index_scopes(root: Any) -> tuple[dict, dict]:
    """Map every node to its enclosing function scope, and each scope to its
    parent scope. Scopes are identified by ``id()`` of the function/Program."""
    node_scope: dict[int, int] = {}
    scope_parent: dict[int, int | None] = {id(root): None}
    stack = [(root, id(root))]
    while stack:
        node, cur = stack.pop()
        node_scope[id(node)] = cur
        for c in A._children(node):
            if getattr(c, "type", None) in _FUNC_TYPES:
                scope_parent[id(c)] = cur
                stack.append((c, id(c)))
            else:
                stack.append((c, cur))
    return node_scope, scope_parent


def _scope_chain(scope_id: int, scope_parent: dict) -> list[int]:
    chain, s = [], scope_id
    while s is not None:
        chain.append(s)
        s = scope_parent.get(s)
    return chain


def _lookup(tainted: dict, name: str, scope_id: int, scope_parent: dict):
    """Find a tainted var visible from *scope_id* (self + ancestor scopes)."""
    for s in _scope_chain(scope_id, scope_parent):
        info = tainted.get((s, name))
        if info is not None:
            return info
    return None


def _idents_in(node: Any) -> set[str]:
    """Base identifiers referenced inside a value node."""
    names: set[str] = set()
    for n in A.walk(node):
        if getattr(n, "type", None) == "Identifier":
            names.add(n.name)
    return names


def _calls_in(node: Any) -> list[str]:
    calls = []
    for n in A.walk(node):
        cn = A.call_name(n)
        if cn:
            calls.append(cn)
    return calls


def _classify_sanitization(transforms: list[str]) -> str:
    if not transforms:
        return "none"
    bases = {t.rsplit(".", 1)[-1] for t in transforms} | set(transforms)
    if bases & {b.rsplit(".", 1)[-1] for b in P.KNOWN_SAFE} or (set(transforms) & P.KNOWN_SAFE):
        # a genuinely safe sanitizer present — but only "known-safe" if it's
        # not merely a weak one masquerading (encodeURIComponent for HTML).
        strong = (set(transforms) & (P.KNOWN_SAFE - P.WEAK_SANITIZERS)) or \
                 (bases & {b.rsplit('.', 1)[-1] for b in (P.KNOWN_SAFE - P.WEAK_SANITIZERS)})
        return "known-safe" if strong else "weak"
    if bases & {b.rsplit(".", 1)[-1] for b in P.WEAK_SANITIZERS}:
        return "weak"
    return "unknown"


def analyze(asset_id: str, pm: A.ParsedModule) -> list[DataFlow]:
    """Return DataFlow records for every sink reached by a source."""
    if not pm.ok:
        return []

    assignments = _collect_assignments(pm)
    node_scope, scope_parent = _index_scopes(pm.ast)
    root_scope = id(pm.ast)

    # --- fixpoint taint propagation (scope-keyed) -----------------------
    # tainted: (scope_id, var_name) -> {"source", "kind", "transforms"}
    tainted: dict[tuple, dict] = {}
    for _ in range(6):  # small bound; converges fast in practice
        changed = False
        for target, value, anode in assignments:
            scope = node_scope.get(id(anode), root_scope)
            srcs = SOURCES.node_sources(value)
            ref_idents = _idents_in(value)
            calls = _calls_in(value)
            info = None
            if srcs:
                info = {"source": srcs[0].name, "kind": srcs[0].kind,
                        "transforms": list(calls)}
            else:
                for ident in ref_idents:
                    base = _lookup(tainted, ident, scope, scope_parent)
                    if base is not None:
                        info = {"source": base["source"], "kind": base["kind"],
                                "transforms": base["transforms"] + list(calls)}
                        break
            if info:
                key = (scope, target)
                prev = tainted.get(key)
                if prev is None or prev["source"] != info["source"] or \
                        len(info["transforms"]) < len(prev["transforms"]):
                    tainted[key] = info
                    changed = True
        if not changed:
            break

    # --- match sinks ----------------------------------------------------
    flows: list[DataFlow] = []
    counter = 0
    for hit in SINKS.collect(pm):
        value = hit.value_node
        sink_scope = node_scope.get(id(hit.node), root_scope)
        direct_srcs = SOURCES.node_sources(value)
        ref_idents = _idents_in(value)
        calls = _calls_in(value)

        source_name = source_kind = None
        transforms: list[str] = list(calls)
        attacker = "unknown"

        if direct_srcs:
            source_name = direct_srcs[0].name
            source_kind = direct_srcs[0].kind
            attacker = "yes"
        else:
            for ident in ref_idents:
                base = _lookup(tainted, ident, sink_scope, scope_parent)
                if base is not None:
                    source_name = base["source"]
                    source_kind = base["kind"]
                    transforms = base["transforms"] + list(calls)
                    attacker = "yes"
                    break

        if source_name is None:
            # sink with a non-source value — a candidate only if the value is
            # an identifier we couldn't resolve (unknown provenance).
            if ref_idents and not _is_literal(value):
                attacker = "unknown"
                source_name = "unresolved:" + sorted(ref_idents)[0]
                source_kind = "unknown"
            else:
                continue  # literal / constant sink — not interesting

        sanitization = _classify_sanitization(transforms)
        counter += 1
        flows.append(DataFlow(
            flow_id=f"{asset_id}-flow-{counter:03d}",
            asset_id=asset_id,
            source=source_name,
            source_kind=source_kind or "unknown",
            sink=hit.sink,
            sink_kind=hit.kind,
            transforms=_dedupe(transforms),
            attacker_controlled=attacker,
            sanitization=sanitization,
            sink_location=hit.location,
            evidence=_evidence(hit),
        ))
    return flows


def _is_literal(node: Any) -> bool:
    return getattr(node, "type", None) == "Literal"


def _dedupe(seq: list[str]) -> list[str]:
    seen, out = set(), []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _evidence(hit: SINKS.SinkHit) -> str:
    val = A.string_value(hit.value_node)
    if val is not None:
        return f"{hit.sink} <- \"{val[:80]}\""
    idents = sorted(_idents_in(hit.value_node))
    return f"{hit.sink} <- {', '.join(idents[:4])}"
