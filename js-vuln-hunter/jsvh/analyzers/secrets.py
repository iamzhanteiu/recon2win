"""Secret detection in JS.

recon2win's jsluice already extracts secrets with AST context; we ingest
those (owned upstream) and only *add* high-signal literal patterns jsluice
may miss, matched against string literals in the AST (low false-positive)
with a raw-text fallback. Low-confidence generic matches are P3 by policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import ast_engine as A
from . import patterns as P


@dataclass
class SecretFinding:
    kind: str
    match: str          # redacted preview
    location: dict | None
    confidence: float
    secret_class: str = "token"   # credential|token|config|public-id (§12)


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 12:
        return s[:4] + "…"
    return s[:6] + "…" + s[-4:]


# base confidence per class — public identifiers are deliberately low so they
# never crowd the shortlist as "secrets" (§12).
_CLASS_CONF = {"credential": 0.9, "token": 0.8, "config": 0.6, "public-id": 0.2}


def analyze(pm: A.ParsedModule) -> list[SecretFinding]:
    out: list[SecretFinding] = []
    seen: set[str] = set()

    def _conf(kind: str, sclass: str, ast: bool) -> float:
        base = _CLASS_CONF.get(sclass, 0.7)
        if kind == "generic_secret_assign":
            base = 0.55
        return base if ast else max(0.2, base - 0.05)

    # AST literals (precise location, low FP)
    if pm.ok:
        for node in A.walk(pm.ast):
            if getattr(node, "type", None) == "Literal" and isinstance(getattr(node, "value", None), str):
                val = node.value
                for kind, rx, sclass in P.SECRET_PATTERNS:
                    m = rx.search(val)
                    if m and m.group(0) not in seen:
                        seen.add(m.group(0))
                        out.append(SecretFinding(
                            kind=kind, match=_redact(m.group(0)),
                            location=A.loc_of(node), secret_class=sclass,
                            confidence=_conf(kind, sclass, True)))

    # raw-text fallback for parse failures / patterns spanning tokens
    for kind, rx, sclass in P.SECRET_PATTERNS:
        for m in rx.finditer(pm.text or ""):
            if m.group(0) in seen:
                continue
            seen.add(m.group(0))
            out.append(SecretFinding(
                kind=kind, match=_redact(m.group(0)), location=None,
                secret_class=sclass, confidence=_conf(kind, sclass, False)))
    return out
