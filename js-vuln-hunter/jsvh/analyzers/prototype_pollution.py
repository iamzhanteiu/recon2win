"""Prototype-pollution analysis.

Two evidence tiers:
  1. **Literal pollution** — code that literally writes ``__proto__`` /
     ``constructor.prototype`` keys.
  2. **Merge sink reachability** — a recursive/deep-merge style call
     (``merge`` / ``$.extend(true, …)`` / ``defaultsDeep`` / ``_.set``)
     whose input is attacker-influenceable (a source, or JSON parsed from
     a source). Only then is it a candidate; a merge of two literals is
     not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import ast_engine as A
from . import patterns as P
from . import sources as SOURCES


@dataclass
class ProtoFinding:
    kind: str            # literal-key | merge-sink
    sink: str            # merge / $.extend / assignment
    attacker_controlled: str
    location: dict | None
    evidence: str


def analyze(pm: A.ParsedModule) -> list[ProtoFinding]:
    if not pm.ok:
        return []
    out: list[ProtoFinding] = []

    for node in A.walk(pm.ast):
        t = getattr(node, "type", None)

        # literal __proto__ / constructor / prototype member writes
        if t == "MemberExpression":
            nm = A.member_name(node)
            last = nm.rsplit(".", 1)[-1]
            if last in P.POLLUTION_KEYS and getattr(node, "computed", False):
                out.append(ProtoFinding(
                    kind="literal-key", sink=nm, attacker_controlled="unknown",
                    location=A.loc_of(node), evidence=f"computed member {nm}"))

        # merge-style calls
        if t == "CallExpression":
            name = A.call_name(node) or ""
            base = name.rsplit(".", 1)[-1]
            merge_bases = {m.rsplit(".", 1)[-1] for m in P.MERGE_SINKS}
            if name in P.MERGE_SINKS or base in merge_bases:
                args = list(getattr(node, "arguments", []) or [])
                # Backbone/Marionette/Vue class factories use `.extend({...})`
                # for *prototype inheritance*, not object merging — a huge FP
                # source in bundled SPAs. Skip those outright.
                if base == "extend" and _is_class_extension(node, name, args):
                    continue
                # $.extend(true, ...) deep flag — deep merge is the dangerous one
                deep = any(A.string_value(a) in ("true", True) or
                           getattr(a, "value", None) is True for a in args[:1])
                attacker = "unknown"
                ev_src = None
                for a in args:
                    srcs = SOURCES.node_sources(a)
                    if srcs:
                        attacker = "yes"
                        ev_src = srcs[0].name
                        break
                # Only emit for names that specifically denote a *deep* merge
                # (the pollutable operation), OR when the call is deep-flagged,
                # OR when attacker data reaches it. Bare `set`/`assign`/`extend`
                # are far too common (Map.set, this.set, Object.assign of
                # literals) to emit unconditionally — that was the #1 FP source.
                dangerous_name = base in (
                    "merge", "mergeWith", "defaultsDeep", "deepMerge", "deepmerge")
                if dangerous_name or deep or attacker == "yes":
                    out.append(ProtoFinding(
                        kind="merge-sink", sink=name, attacker_controlled=attacker,
                        location=A.loc_of(node),
                        evidence=f"{name}(...)" + (f" <- {ev_src}" if ev_src else "")))
    return out


# framework class-factory tokens: `X.View.extend({...})` is inheritance, not a merge
_CLASS_TOKENS = ("view", "model", "collection", "router", "itemview", "layoutview",
                 "collectionview", "compositeview", "component", "backbone",
                 "marionette", "controller", "behavior", "region", "class", "mixin")
# object-literal keys that mark a class/prototype definition (not attacker data)
_CLASS_PROP_KEYS = {"initialize", "render", "template", "events", "defaults",
                    "tagName", "className", "el", "ui", "regions", "triggers",
                    "modelEvents", "collectionEvents", "childView", "constructor",
                    "props", "methods", "computed", "data", "components"}


def _is_class_extension(node: Any, name: str, args: list) -> bool:
    """True if this `.extend(...)` is framework prototype inheritance.

    Two independent signals (either suffices):
      * the callee chain names a class type — ``SomeView.extend`` / ``Backbone
        .Model.extend`` / ``e.Marionette.ItemView.extend``.
      * the (first non-flag) argument is an object literal whose keys look like
        a class/prototype definition (``initialize``/``render``/``events``…).
    jQuery/lodash/underscore/Object merges are explicitly NOT class extension.
    """
    low = name.lower()
    if any(tok in low for tok in ("$.extend", "jquery.extend", "_.extend",
                                  "lodash.extend", "underscore.extend",
                                  "angular.extend", "object.extend")):
        return False
    # callee object chain (strip the trailing `.extend`)
    chain = name.rsplit(".", 1)[0].lower()
    if any(tok in chain for tok in _CLASS_TOKENS):
        return True
    # object-literal argument that reads like a class definition
    for a in args:
        if getattr(a, "type", None) == "ObjectExpression":
            keys = set()
            for prop in getattr(a, "properties", []) or []:
                k = getattr(prop, "key", None)
                if k is not None:
                    keys.add(A.member_name(k).rsplit(".", 1)[-1])
            if len(keys & _CLASS_PROP_KEYS) >= 2:
                return True
    return False
