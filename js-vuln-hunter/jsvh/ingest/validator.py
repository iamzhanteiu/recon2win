"""Validate the recon2win input contract.

Rule 17 of the mission: if upstream data is missing, report it *exactly*
— never silently regenerate it with a second recon pipeline. This module
turns the loader's findings into an actionable gap report.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .loader import ReconData


# The minimum recon2win needs to have produced for JS analysis to be useful.
# js_detail OR js_urls is enough to bootstrap the inventory.
_CRITICAL_ANY = [("js_detail", "js_urls")]
_RECOMMENDED = ["jsluice_endpoints", "jsluice_params", "all_urls_jsonl", "alive_urls_detail"]


@dataclass
class ValidationReport:
    ok: bool
    target: str
    js_url_count: int
    missing_upstream: list[str] = field(default_factory=list)   # blocking
    degraded: list[str] = field(default_factory=list)           # non-blocking
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [f"# recon2win input validation — {self.target}",
                 f"status: {'OK' if self.ok else 'BLOCKED'}",
                 f"JS URLs available: {self.js_url_count}"]
        if self.missing_upstream:
            lines.append("\nMissing upstream data:")
            for m in self.missing_upstream:
                lines.append(f"  - {m}")
        if self.degraded:
            lines.append("\nDegraded (analysis continues with reduced signal):")
            for d in self.degraded:
                lines.append(f"  - {d}")
        for n in self.notes:
            lines.append(f"note: {n}")
        return "\n".join(lines)


def validate(rd: ReconData) -> ValidationReport:
    missing: list[str] = []
    degraded: list[str] = []
    notes: list[str] = []

    for group in _CRITICAL_ANY:
        if all(k in rd.missing for k in group):
            missing.append(" or ".join(
                {"js_detail": "processed/js/jsluice_js_detail.json",
                 "js_urls": "processed/corpus/js_urls.txt"}[k] for k in group))

    for key in _RECOMMENDED:
        if key in rd.missing:
            degraded.append(key)

    js_count = len(rd.js_urls) or len(rd.js_detail)
    if js_count == 0 and not missing:
        notes.append("recon2win ran but discovered zero JS assets for this target.")

    return ValidationReport(
        ok=not missing,
        target=rd.target,
        js_url_count=js_count,
        missing_upstream=missing,
        degraded=degraded,
        notes=notes,
    )
