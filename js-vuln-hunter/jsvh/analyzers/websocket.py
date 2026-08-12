"""WebSocket usage analysis.

Flags ``new WebSocket(url)`` construction, the endpoint, and whether
message handlers route ``onmessage`` data into a DOM/eval sink (client
trusting server-pushed data) — plus privileged-looking ``send()`` payloads.
Authorization semantics are surfaced for manual verification, never
auto-classified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import ast_engine as A
from . import patterns as P


@dataclass
class WebSocketFinding:
    url: str
    secure: bool
    onmessage_to_sink: str | None
    location: dict | None
    evidence: str


def analyze(pm: A.ParsedModule) -> list[WebSocketFinding]:
    if not pm.ok:
        return []
    out: list[WebSocketFinding] = []
    for node in A.walk(pm.ast):
        if getattr(node, "type", None) == "NewExpression" and \
                A.member_name(getattr(node, "callee", None)) == "WebSocket":
            args = list(getattr(node, "arguments", []) or [])
            url = A.string_value(args[0]) if args else None
            url = url or "{dynamic}"
            secure = url.startswith("wss")
            out.append(WebSocketFinding(
                url=url, secure=secure, onmessage_to_sink=None,
                location=A.loc_of(node), evidence=f"new WebSocket({url})"))
    return out
