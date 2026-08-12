"""AST parsing + traversal built on esprima (pure-Python JS parser).

AST is the *primary* analysis method (mission §10). esprima parses plain
JavaScript — including the compiled/bundled output that makes up the vast
majority of production JS. Raw TS/JSX sources it cannot parse; for those
(and for parse failures generally) the analyzers fall back to a regex
scan of the raw text, so no asset is ever fully dropped.

This module owns three things:
  * ``parse``           bytes -> ParsedModule (ast + ok/error)
  * ``walk``            depth-first node iterator
  * member/argument helpers that turn AST fragments back into the strings
    analyzers reason about (``location.hash``, ``el.innerHTML``, a fetch
    URL rebuilt from ``base + "/x/" + id``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

import esprima

_SKIP_KEYS = {"type", "loc", "range", "leadingComments", "trailingComments"}


@dataclass
class ParsedModule:
    ok: bool
    ast: Any = None
    error: Optional[str] = None
    kind: str = "script"          # script|module
    text: str = ""                # original source (for regex fallback)


def parse(code: str) -> ParsedModule:
    """Parse JS text. Tries module then script; tolerant of minor errors."""
    opts = {"loc": True, "tolerant": True, "range": False}
    last_err = None
    for kind, fn in (("module", esprima.parseModule), ("script", esprima.parseScript)):
        try:
            ast = fn(code, opts)
            return ParsedModule(ok=True, ast=ast, kind=kind, text=code)
        except Exception as e:  # noqa: BLE001 — esprima raises many error types
            last_err = e
    return ParsedModule(ok=False, error=f"{type(last_err).__name__}: {last_err}", text=code)


def _children(node: Any) -> Iterator[Any]:
    d = getattr(node, "__dict__", None)
    if not d:
        return
    for k, v in d.items():
        if k in _SKIP_KEYS:
            continue
        if _is_node(v):
            yield v
        elif isinstance(v, list):
            for item in v:
                if _is_node(item):
                    yield item


def _is_node(v: Any) -> bool:
    return hasattr(v, "type") and hasattr(v, "__dict__")


def walk(node: Any) -> Iterator[Any]:
    """Depth-first pre-order traversal yielding every AST node."""
    if node is None:
        return
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        # push children (reversed so traversal is left-to-right-ish)
        kids = list(_children(cur))
        stack.extend(reversed(kids))


def loc_of(node: Any) -> Optional[dict]:
    loc = getattr(node, "loc", None)
    if loc and getattr(loc, "start", None):
        return {"line": loc.start.line, "col": loc.start.column}
    return None


def member_name(node: Any) -> str:
    """Flatten a MemberExpression/Identifier chain to a dotted string.

    location.hash          -> "location.hash"
    window.location.href   -> "window.location.href"
    a["b"].c               -> "a.b.c"
    el[dynamic]            -> "el.<computed>"
    """
    t = getattr(node, "type", None)
    if t == "Identifier":
        return node.name
    if t == "ThisExpression":
        return "this"
    if t == "MemberExpression":
        obj = member_name(node.object)
        if getattr(node, "computed", False):
            prop = node.property
            if getattr(prop, "type", None) == "Literal":
                return f"{obj}.{prop.value}"
            return f"{obj}.<computed>"
        return f"{obj}.{member_name(node.property)}"
    if t == "CallExpression":
        return f"{member_name(node.callee)}()"
    if t == "Literal":
        return str(getattr(node, "value", ""))
    return f"<{t}>"


def string_value(node: Any) -> Optional[str]:
    """Return the static string a node evaluates to, or None if dynamic.

    Resolves Literals, TemplateLiterals with no expressions, and simple
    string concatenations (BinaryExpression '+'). Dynamic parts become a
    ``{param}`` placeholder so a rebuilt URL stays recognizable.
    """
    t = getattr(node, "type", None)
    if t == "Literal":
        v = getattr(node, "value", None)
        return v if isinstance(v, str) else (str(v) if v is not None else None)
    if t == "TemplateLiteral":
        parts = []
        quasis = list(node.quasis)
        exprs = list(node.expressions)
        for i, q in enumerate(quasis):
            parts.append(q.value.cooked or "")
            if i < len(exprs):
                nm = _expr_placeholder(exprs[i])
                parts.append(nm)
        return "".join(parts)
    if t == "BinaryExpression" and node.operator == "+":
        left = string_value(node.left)
        right = string_value(node.right)
        if left is None:
            left = _expr_placeholder(node.left)
        if right is None:
            right = _expr_placeholder(node.right)
        return f"{left}{right}"
    return None


def _expr_placeholder(node: Any) -> str:
    """Render a dynamic expression as a readable ``{name}`` placeholder."""
    t = getattr(node, "type", None)
    if t in ("Identifier", "MemberExpression"):
        return "{" + member_name(node) + "}"
    if t == "Literal":
        v = getattr(node, "value", "")
        return str(v)
    if t == "CallExpression":
        return "{" + member_name(node.callee) + "()}"
    return "{expr}"


def call_name(node: Any) -> Optional[str]:
    """For a CallExpression node, the dotted callee name (e.g. 'fetch',
    'document.write', 'axios.get', '$.ajax')."""
    if getattr(node, "type", None) != "CallExpression":
        return None
    return member_name(node.callee)


@dataclass
class Assignment:
    target: str
    value_node: Any
    node: Any


def is_assignment_to(node: Any) -> Optional[Assignment]:
    """Recognise ``x.y = <value>`` assignments (for sink detection)."""
    if getattr(node, "type", None) == "AssignmentExpression" and node.operator == "=":
        return Assignment(member_name(node.left), node.right, node)
    return None
