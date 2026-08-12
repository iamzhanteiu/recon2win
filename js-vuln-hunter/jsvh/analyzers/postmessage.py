"""postMessage security analysis.

Two dangerous shapes:
  1. **Receiver** — an ``addEventListener('message', handler)`` whose
     handler uses ``event.data`` without validating ``event.origin``,
     and worse, routes ``event.data`` into a DOM/eval/auth sink.
  2. **Sender** — ``target.postMessage(data, '*')`` posting to a wildcard
     origin (data leak / clickjacking-assisted).

Origin validation is detected structurally: does the handler body compare
``event.origin`` (or ``e.origin``) against anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import ast_engine as A
from . import patterns as P


@dataclass
class PostMessageFinding:
    role: str                 # receiver | sender
    origin_validated: bool
    wildcard_origin: bool
    reaches_sink: str | None  # sink kind if event.data flows to a sink
    location: dict | None
    evidence: str
    handler_uses_data: bool = False
    origin_check: str = "none"   # none | weak | strict  (§8)


def _handler_of_add_listener(node: Any) -> Any | None:
    if getattr(node, "type", None) != "CallExpression":
        return None
    name = A.call_name(node) or ""
    if name.rsplit(".", 1)[-1] != "addEventListener":
        return None
    args = list(getattr(node, "arguments", []) or [])
    if len(args) >= 2 and A.string_value(args[0]) == "message":
        return args[1]
    return None


# substring/prefix comparisons on origin are bypassable (evil-target.com,
# target.com.evil.com) — mission §8 wants these flagged as *weak*, not safe.
_WEAK_ORIGIN_OPS = ("indexOf", "startsWith", "endsWith", "includes", "search",
                    "match", "test")


def _origin_check_strength(handler: Any) -> str:
    """Classify origin validation: 'none' | 'weak' | 'strict' (§8).

    strict = origin used in an (in)equality comparison (=== / == / !== / !=).
    weak   = origin only fed to a substring/regex test (indexOf/startsWith/
             includes/match/RegExp.test) — bypassable.
    """
    def _mentions_origin(nd: Any) -> bool:
        for x in A.walk(nd):
            if getattr(x, "type", None) == "MemberExpression":
                nm = A.member_name(x)
                if nm.endswith(".origin") or nm.endswith(".originalEvent.origin"):
                    return True
        return False

    if not _mentions_origin(handler):
        return "none"

    def _is_direct_origin(nd: Any) -> bool:
        # the operand is *itself* the origin member (event.origin === X), not a
        # call that merely mentions origin (origin.indexOf(x) !== -1 is weak).
        if getattr(nd, "type", None) != "MemberExpression":
            return False
        nm = A.member_name(nd)
        return nm.endswith(".origin") or nm.endswith(".originalEvent.origin")

    strict = weak = False
    for n in A.walk(handler):
        t = getattr(n, "type", None)
        if t == "BinaryExpression" and getattr(n, "operator", None) in ("===", "==", "!==", "!="):
            if _is_direct_origin(n.left) or _is_direct_origin(n.right):
                strict = True
        elif t == "CallExpression":
            cn = A.call_name(n) or ""
            base = cn.rsplit(".", 1)[-1]
            if base in _WEAK_ORIGIN_OPS:
                # origin.indexOf(...) or someRegex.test(origin) / list.includes(origin)
                if _mentions_origin(n.callee) or any(_mentions_origin(a)
                                                     for a in getattr(n, "arguments", []) or []):
                    weak = True
    if strict:
        return "strict"
    if weak:
        return "weak"
    # origin referenced but no comparison we recognise — treat as weak (a
    # reference with no clear check is not trustworthy).
    return "weak"


def _data_reaches_sink(handler: Any) -> str | None:
    """Cheap check: is a *.data member used as a sink argument/RHS."""
    data_names = set()
    for n in A.walk(handler):
        if getattr(n, "type", None) == "MemberExpression":
            nm = A.member_name(n)
            if nm.endswith(".data"):
                data_names.add(nm.rsplit(".", 1)[0])  # the event var
    if not data_names:
        return None
    for n in A.walk(handler):
        t = getattr(n, "type", None)
        if t == "AssignmentExpression":
            if P.match_assign_sink(A.member_name(n.left)) and _mentions_data(n.right):
                return P.match_assign_sink(A.member_name(n.left))
        elif t == "CallExpression":
            spec = P.match_call_sink(A.call_name(n) or "")
            if spec and any(_mentions_data(a) for a in getattr(n, "arguments", []) or []):
                return spec[0]
    return None


def _mentions_data(node: Any) -> bool:
    for n in A.walk(node):
        if getattr(n, "type", None) == "MemberExpression" and A.member_name(n).endswith(".data"):
            return True
    return False


def _handler_uses_data(handler: Any) -> bool:
    for n in A.walk(handler):
        if getattr(n, "type", None) == "MemberExpression" and A.member_name(n).endswith(".data"):
            return True
    return False


def analyze(pm: A.ParsedModule) -> list[PostMessageFinding]:
    if not pm.ok:
        return []
    out: list[PostMessageFinding] = []
    for node in A.walk(pm.ast):
        handler = _handler_of_add_listener(node)
        if handler is not None:
            strength = _origin_check_strength(handler)
            out.append(PostMessageFinding(
                role="receiver",
                origin_validated=(strength == "strict"),
                origin_check=strength,
                wildcard_origin=False,
                reaches_sink=_data_reaches_sink(handler),
                location=A.loc_of(node),
                evidence=f"addEventListener('message', ...) origin-check={strength}",
                handler_uses_data=_handler_uses_data(handler),
            ))
        # window.onmessage = function(e){...}  (assignment-style handler)
        if getattr(node, "type", None) == "AssignmentExpression" and node.operator == "=":
            tgt = A.member_name(node.left)
            if tgt.rsplit(".", 1)[-1] == "onmessage":
                h = node.right
                strength = _origin_check_strength(h)
                out.append(PostMessageFinding(
                    role="receiver",
                    origin_validated=(strength == "strict"),
                    origin_check=strength,
                    wildcard_origin=False,
                    reaches_sink=_data_reaches_sink(h),
                    location=A.loc_of(node),
                    evidence=f"{tgt} = handler  origin-check={strength}",
                    handler_uses_data=_handler_uses_data(h),
                ))

        # sender: x.postMessage(data, '*')
        if getattr(node, "type", None) == "CallExpression":
            nm = A.call_name(node) or ""
            if nm.rsplit(".", 1)[-1] == "postMessage":
                args = list(getattr(node, "arguments", []) or [])
                wildcard = len(args) >= 2 and A.string_value(args[1]) == "*"
                if wildcard:
                    out.append(PostMessageFinding(
                        role="sender",
                        origin_validated=False,
                        wildcard_origin=True,
                        reaches_sink=None,
                        location=A.loc_of(node),
                        evidence="postMessage(data, '*')",
                    ))
    return out
