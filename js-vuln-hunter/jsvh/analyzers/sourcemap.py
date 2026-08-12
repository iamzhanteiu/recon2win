"""Source-map exposure intelligence (mission §13).

A published ``.map`` (or an inline ``data:`` source map with
``sourcesContent``) hands an attacker the *original* source of a minified
bundle: internal endpoints, ``webpack://`` module paths, debug functions,
comments, and occasionally security logic or secrets. We do not fetch by
default (that is recon2win's job / needs scope), so this analyzer works on
the bytes we already have:

  * external map — ``//# sourceMappingURL=app.min.js.map``  (a lead: the map
    is *probably* reachable next to the bundle; verify + mine it)
  * inline map  — ``//# sourceMappingURL=data:application/json;base64,...``
    with ``sourcesContent`` — the original source is embedded *right here*.

Only security-impacting exposure is prioritised (§13): an inline map, or a
map next to an app (non-third-party) bundle.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field

_SOURCEMAP = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
# webpack:// / internal path hints inside an inline map's sources[]
_INTERNAL_HINT = re.compile(
    r"(?:webpack://|/src/|/app/|/internal/|/admin/|node_modules/(?!\.)|"
    r"\.env|secret|apikey|api_key|password|token)",
    re.I)


@dataclass
class SourceMapFinding:
    kind: str                 # inline-map | external-map
    map_ref: str              # url or "data:..."
    inline: bool
    sources: list[str] = field(default_factory=list)   # original file names (inline only)
    interesting_sources: list[str] = field(default_factory=list)
    has_sources_content: bool = False
    evidence: str = ""


def analyze(data: bytes) -> list[SourceMapFinding]:
    out: list[SourceMapFinding] = []
    m = _SOURCEMAP.search(data[-4000:]) or _SOURCEMAP.search(data)
    if not m:
        return out
    ref = m.group(1).decode("ascii", "replace")

    if ref.startswith("data:"):
        finding = SourceMapFinding(kind="inline-map", map_ref=ref[:60] + "…",
                                   inline=True, evidence="inline data: source map")
        _decode_inline(ref, finding)
        out.append(finding)
    else:
        out.append(SourceMapFinding(
            kind="external-map", map_ref=ref, inline=False,
            evidence=f"sourceMappingURL={ref}"))
    return out


def _decode_inline(ref: str, finding: SourceMapFinding) -> None:
    try:
        meta, b64 = ref.split(",", 1)
        raw = base64.b64decode(b64) if "base64" in meta else base64.b64decode(b64 + "==")
        doc = json.loads(raw)
    except Exception:  # noqa: BLE001 — malformed inline map, keep the lead
        return
    srcs = doc.get("sources") or []
    finding.sources = [str(s) for s in srcs][:50]
    finding.has_sources_content = bool(doc.get("sourcesContent"))
    interesting = [s for s in finding.sources if _INTERNAL_HINT.search(str(s))]
    finding.interesting_sources = interesting[:20]
    finding.evidence = (f"inline map: {len(finding.sources)} sources"
                        + (", sourcesContent present" if finding.has_sources_content else ""))
