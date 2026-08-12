"""Output artifacts + reporting.

Writes the JSON artifacts under ``output/<target>/`` (mission §7) and a
high-signal ``Top Candidates`` console/markdown summary (§19). A full
bug-bounty finding template (§16) is emitted per candidate only on demand
(after a human verifies) via ``finding_template``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Candidate, JSAsset


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False))


def write_artifacts(out_dir: Path, assets: list[JSAsset], candidates: list[Candidate],
                    flows: list, endpoints: list, meta: dict,
                    attack_chains: list | None = None) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, Path] = {}

    def emit(name, obj):
        p = out_dir / name
        _write_json(p, obj)
        files[name] = p

    emit("javascript_inventory.json", {
        "meta": meta,
        "assets": [a.to_dict() for a in assets],
    })
    emit("endpoint_inventory.json", {"endpoints": endpoints})
    emit("dataflow.json", {"flows": flows})
    emit("vulnerability_candidates.json", {
        "meta": meta,
        "count": len(candidates),
        "candidates": [c.to_dict() for c in candidates],
    })
    emit("attack_chains.json", {
        "meta": {"target": meta.get("target"), "generated": meta.get("generated"),
                 "count": len(attack_chains or [])},
        "chains": [ch.to_dict() for ch in (attack_chains or [])],
    })
    # attack surface: compact host/framework rollup
    surface: dict = {}
    for a in assets:
        h = surface.setdefault(a.host, {"assets": 0, "frameworks": set(), "candidates": 0})
        h["assets"] += 1
        if a.framework:
            h["frameworks"].add(a.framework)
    for c in candidates:
        host = next((a.host for a in assets if a.asset_id == c.asset_id), None)
        if host and host in surface:
            surface[host]["candidates"] += 1
    emit("attack_surface.json", {
        h: {**v, "frameworks": sorted(v["frameworks"])} for h, v in surface.items()})
    # source/sink map
    ss: dict = {}
    for f in flows:
        key = f"{f['source_kind']}::{f['sink_kind']}"
        ss.setdefault(key, 0)
        ss[key] += 1
    emit("source_sink_map.json", ss)
    return files


def top_candidates_text(candidates: list[Candidate], limit: int = 15) -> str:
    lines = ["Top Candidates", "─" * 15, ""]
    if not candidates:
        return "Top Candidates\n" + "─" * 15 + "\n\n(no candidates generated)\n"
    for i, c in enumerate(candidates[:limit], 1):
        lines.append(f"{i}. {c.type}   [{c.priority}/{c.severity}]  score={c.rank_score:.0f}")
        lines.append(f"   Confidence: {c.confidence:.0%}")
        if c.source or c.sink:
            lines.append(f"   Source: {c.source}   Sink: {c.sink}")
        if c.endpoint:
            lines.append(f"   Endpoint: {c.endpoint}")
        lines.append(f"   Asset: {c.url}")
        lines.append(f"   Location: {c.location}    Verification: required")
        lines.append(f"   id: {c.id}")
        lines.append("")
    return "\n".join(lines)


def verification_queue_text(candidates: list[Candidate], attack_chains: list | None = None,
                            limit: int = 20) -> str:
    """Prioritized manual-testing queue (mission §17).

    Answers "what should I test first?" — attack chains lead (correlated,
    highest value), then the individual P1/P2 candidates, each with the one
    thing that makes it worth an hour and the concrete first step.
    """
    lines = ["VERIFICATION QUEUE", "═" * 18, ""]
    idx = 0

    for ch in (attack_chains or []):
        idx += 1
        lines.append(f"[{idx}] {ch.priority} - {ch.name}   (chain, conf {ch.confidence:.0%})")
        lines.append(f"    Impact: {ch.impact}")
        lines.append(f"    Observations: {', '.join(ch.observations)}")
        if ch.verification:
            lines.append(f"    First step: {ch.verification[0]}")
        lines.append("")

    worklist = [c for c in candidates if c.priority in ("P1", "P2")][: limit]
    for c in worklist:
        idx += 1
        ex = c.exploitability
        lines.append(f"[{idx}] {c.priority} - {c.type}   (conf {c.confidence:.0%}"
                     + (f", exploitability {ex.exploitability}" if ex else "") + ")")
        if c.source or c.sink:
            lines.append(f"    Source→Sink: {c.source} → {c.sink}")
        if c.endpoint:
            lines.append(f"    Endpoint: {c.method or ''} {c.endpoint}".rstrip())
        if ex and ex.why_interesting:
            lines.append(f"    Why: {ex.why_interesting}")
        if ex and ex.missing_evidence:
            lines.append(f"    Verify next: {ex.missing_evidence[0]}")
        lines.append(f"    Asset: {c.url}   id: {c.id}")
        lines.append("")

    if idx == 0:
        lines.append("(no P1/P2 candidates or chains to verify)")
    return "\n".join(lines)


def finding_template(c: Candidate) -> str:
    return f"""# Finding — {c.title}

- **Severity:** {c.severity}
- **Type:** {c.type}
- **Affected Asset:** {c.url}
- **Candidate id:** {c.id}   **Static confidence:** {c.confidence:.0%}

## Summary
<one paragraph: what, where, impact>

## Technical Description
- Source: `{c.source}`
- Sink: `{c.sink}`
- Data flow / evidence: `{c.evidence}`
- Sanitization observed: {c.sanitization}

## Root Cause
<why the sink receives attacker input unsafely>

## Attack Scenario
<how an attacker triggers it against a victim>

## Steps to Reproduce
1.
2.
3.

## Proof of Concept
```
<payload / request>
```

## Impact
<confidentiality/integrity/availability, who is affected>

## Evidence
- request: requests/
- response: responses/
- screenshots: screenshots/

## Remediation
<specific fix for this sink/source pair>

## References
- CWE / OWASP links
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
