"""Sink collection.

A *sink hit* is a place where a value flows into a dangerous operation,
carrying the value expression node so the data-flow engine can decide
whether that value is attacker-controlled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import ast_engine as A
from . import patterns as P


@dataclass
class SinkHit:
    sink: str            # innerHTML / eval / document.write / ...
    kind: str            # dom-xss / code-injection / open-redirect / ...
    value_node: Any      # the expression flowing into the sink
    node: Any            # the sink node itself
    location: dict | None


def collect(pm: A.ParsedModule) -> list[SinkHit]:
    hits: list[SinkHit] = []
    if not pm.ok:
        return hits

    for node in A.walk(pm.ast):
        t = getattr(node, "type", None)

        # assignment sinks: x.y = value
        if t == "AssignmentExpression" and node.operator in ("=", "+="):
            target = A.member_name(node.left)
            kind = P.match_assign_sink(target)
            if kind:
                # refine: `.src` only dangerous on script/iframe-ish targets
                if target.rsplit(".", 1)[-1] == "src" and not _script_like(target):
                    continue
                hits.append(SinkHit(target, kind, node.right, node, A.loc_of(node)))

        # call sinks: f(value)
        elif t == "CallExpression":
            name = A.call_name(node) or ""
            spec = P.match_call_sink(name)
            if spec:
                kind, arg_idxs = spec
                args = list(getattr(node, "arguments", []) or [])
                for i in arg_idxs:
                    if i < len(args):
                        arg = args[i]
                        # setTimeout/setInterval are code-injection ONLY when
                        # arg0 is a string being evaluated. A function/arrow
                        # callback (the overwhelmingly common case, esp. in
                        # minified/bundled code) is safe — skip it, or we drown
                        # in false positives.
                        base = name.rsplit(".", 1)[-1]
                        if base in ("setTimeout", "setInterval") and not _is_stringish(arg):
                            continue
                        hits.append(SinkHit(name, kind, arg, node, A.loc_of(node)))
    return hits


def _script_like(target: str) -> bool:
    low = target.lower()
    return any(k in low for k in ("script", "iframe", "embed", "frame", "img", "source"))


def _is_stringish(arg) -> bool:
    """True if *arg* plausibly evaluates to a string (so setTimeout would
    eval it), False for function/arrow callbacks and bare identifiers."""
    t = getattr(arg, "type", None)
    if t in ("FunctionExpression", "ArrowFunctionExpression", "Identifier",
             "MemberExpression"):
        # a bare var/member could be a string, but in practice it is a
        # function reference far more often — treat as not-a-string to stay
        # high-signal. A string built inline (below) is the real risk.
        return False
    if t == "Literal":
        return isinstance(getattr(arg, "value", None), str)
    if t in ("TemplateLiteral", "BinaryExpression"):
        return True
    return False
