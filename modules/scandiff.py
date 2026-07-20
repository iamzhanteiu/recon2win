"""scandiff — "what's new since the last scan?".

Bug-bounty recon is run repeatedly against the same target. 95% of each
run's output is identical to last time; the 5% that changed — a new
subdomain, a freshly-exposed endpoint, a new nuclei finding — is what
actually matters. This module diffs the current run against the previous
one and writes ``report/delta.md`` so the operator reads "here's what's
new" instead of re-triaging thousands of unchanged URLs.

State lives in ``outputs/<domain>/.scan_state.json`` (a snapshot of the
key result sets). It persists across runs because ``create_output_structure``
never deletes — it only ``mkdir(exist_ok=True)``. Each run:

  1. snapshot the current results,
  2. diff against the saved previous snapshot (if any),
  3. write ``report/delta.md``,
  4. overwrite the state file with the current snapshot (new baseline).

``diff_snapshots`` is a pure function (unit-tested); the rest is thin I/O.
"""
from __future__ import annotations

from pathlib import Path

from .utils import load_json, make_result, read_lines, write_json


STATE_FILE = ".scan_state.json"

# Categories we track, mapped to the file they come from. ``findings`` is
# special (assembled from the two nuclei json files) and handled separately.
_URL_CAP = 100  # cap how many new URLs we list (findings/subs are never capped)


def _finding_keys(output_dir: Path) -> list[str]:
    """Stable ``<template>@<location>`` keys for every nuclei finding."""
    keys: list[str] = []
    for kind in ("default", "endpoints", "dynamic"):
        data = load_json(output_dir / "findings" / kind / "nuclei.json") or {}
        if not isinstance(data, dict):
            continue
        for f in data.get("findings", []):
            if not isinstance(f, dict):
                continue
            tid = (
                f.get("template-id")
                or (f.get("info") or {}).get("name")
                or "finding"
            )
            loc = f.get("matched-at") or f.get("host") or ""
            keys.append(f"{tid}@{loc}")
    return keys


def snapshot(output_dir: Path) -> dict:
    """Collect the current run's key result sets (deduped, sorted)."""
    proc = output_dir / "processed"
    return {
        "subdomains": sorted(set(read_lines(proc / "subdomains.txt"))),
        "alive": sorted(set(read_lines(proc / "alive.txt"))),
        "urls": sorted(set(read_lines(proc / "all_urls.txt"))),
        "findings": sorted(set(_finding_keys(output_dir))),
    }


def diff_snapshots(prev: dict, curr: dict) -> dict:
    """Pure diff. For each category return new items + counts.

    ``{category: {"new": [...], "removed": int, "total": int}}``. ``new``
    is sorted; items present in ``curr`` but not ``prev``. ``removed`` is
    just a count (gone since last time — rarely actionable, but worth a
    number).
    """
    out: dict[str, dict] = {}
    for key, cur_items in curr.items():
        prev_set = set(prev.get(key, []) or [])
        cur_set = set(cur_items or [])
        out[key] = {
            "new": sorted(cur_set - prev_set),
            "removed": len(prev_set - cur_set),
            "total": len(cur_set),
        }
    return out


def _section(title: str, info: dict, *, cap: int | None = None) -> list[str]:
    new = info["new"]
    head = f"## {title} — +{len(new)} new"
    if info["removed"]:
        head += f", -{info['removed']} gone"
    head += f" ({info['total']} total)"
    lines = [head, ""]
    if not new:
        lines.append("_none_")
        lines.append("")
        return lines
    shown = new if cap is None else new[:cap]
    for item in shown:
        lines.append(f"- {item}")
    if cap is not None and len(new) > cap:
        lines.append(f"- … and {len(new) - cap} more")
    lines.append("")
    return lines


def render(diff: dict, domain: str, *, first_run: bool) -> str:
    """Render ``delta.md``."""
    lines = [f"# Scan delta — {domain}", ""]
    if first_run:
        lines += [
            "_First scan — baseline established. Future runs will list "
            "what changed._",
            "",
            "| category | count |",
            "|---|---|",
            f"| subdomains | {diff['subdomains']['total']} |",
            f"| alive hosts | {diff['alive']['total']} |",
            f"| urls | {diff['urls']['total']} |",
            f"| nuclei findings | {diff['findings']['total']} |",
            "",
        ]
        return "\n".join(lines) + "\n"

    total_new = sum(len(diff[k]["new"]) for k in diff)
    if total_new == 0:
        lines.append("_No changes since the last scan._")
        lines.append("")
    # Findings first — the highest-signal delta.
    lines += _section("New nuclei findings", diff["findings"])
    lines += _section("New subdomains", diff["subdomains"])
    lines += _section("New alive hosts", diff["alive"])
    lines += _section("New URLs", diff["urls"], cap=_URL_CAP)
    return "\n".join(lines) + "\n"


def build_scan_diff(output_dir: Path, domain: str) -> dict:
    """Diff current run vs previous, write ``report/delta.md``, update state.

    Returns a result whose ``extra`` carries the per-category new-counts so
    the caller can print a one-line summary to the console.
    """
    state_path = output_dir / STATE_FILE
    prev = load_json(state_path)
    first_run = not isinstance(prev, dict)

    curr = snapshot(output_dir)
    diff = diff_snapshots(prev if isinstance(prev, dict) else {}, curr)

    out_path = output_dir / "report" / "delta.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(diff, domain, first_run=first_run), encoding="utf-8")

    # Update the baseline for next time.
    write_json(state_path, curr)

    new_counts = {k: len(v["new"]) for k, v in diff.items()}
    return make_result(
        "scan_diff", "success", input_path=domain,
        outputs=[out_path],
        count=0 if first_run else sum(new_counts.values()),
        extra={"first_run": first_run, "new": new_counts,
               "totals": {k: v["total"] for k, v in diff.items()}},
    )
