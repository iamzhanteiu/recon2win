"""Regex fallback scanner for files too large/minified to AST-parse cheaply.

Pure-Python esprima is O(n) but with a high constant; a 700KB minified
bundle can cost many seconds. Rather than hang (or drop the file), we run
a bounded regex scan that still yields *lower-confidence* candidates:
a DOM/eval sink that has an attacker source within a small window is a
real lead worth a verification plan. Confidence is deliberately capped
below the AST path so ranking prefers proven flows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import DataFlow
from . import patterns as P

_SINK_RX = re.compile(
    r"\.(innerHTML|outerHTML|insertAdjacentHTML)\b"
    r"|\b(document\.write|eval|setTimeout|setInterval|window\.open)\s*\(",
)
_SOURCE_RX = re.compile(
    r"location\.(hash|search|href|pathname)"
    r"|document\.(URL|referrer|cookie)"
    r"|window\.name|URLSearchParams|postMessage",
)
_WINDOW = 200  # chars between source and sink to call it a flow


def scan(asset_id: str, text: str) -> list[DataFlow]:
    flows: list[DataFlow] = []
    src_pos = [(m.start(), m.group(0)) for m in _SOURCE_RX.finditer(text)]
    if not src_pos:
        return flows
    counter = 0
    for sm in _SINK_RX.finditer(text):
        s = sm.start()
        near = None
        for pos, name in src_pos:
            if abs(pos - s) <= _WINDOW:
                near = name
                break
        if near is None:
            continue
        sink = sm.group(0).strip(".( ")
        kind = "code-injection" if sink in ("eval", "setTimeout", "setInterval") else "dom-xss"
        counter += 1
        flows.append(DataFlow(
            flow_id=f"{asset_id}-rx-{counter:03d}",
            asset_id=asset_id,
            source=near,
            source_kind="url",
            sink=sink,
            sink_kind=kind,
            transforms=[],
            attacker_controlled="unknown",   # regex can't prove the flow
            sanitization="unknown",
            evidence=f"regex: {near} within {_WINDOW}b of {sink}",
        ))
        if counter >= 25:   # cap noise from a single huge file
            break
    return flows
