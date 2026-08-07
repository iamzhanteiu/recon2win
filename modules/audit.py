"""audit — make an output tree reviewable at a glance.

A finished run drops ~17 ``.txt`` files into ``processed/`` plus a large
``raw/`` tree, and most of ``processed/`` is *derived slices* of one master
list (``all_urls.txt``): ``dynamic_urls`` ⊆ ``all_urls``,
``parameterized_urls`` ⊆ ``dynamic_urls``, ``js_urls`` / ``ffuf_urls`` ⊆
``all_urls`` … They're all needed by the pipeline (each downstream stage
consumes its own slice), but when a human opens the folder to review, it's
impossible to tell which file to read first vs which is a machine artefact.

This module adds two things WITHOUT touching the pipeline:

  * ``build_index()`` — writes ``INDEX.md`` at the end of a run, grouping
    every file into 🎯 review / 🔧 intermediate / 📦 raw / ⚪ empty, with
    the known subset relationships spelled out. Fast: line counts only.

  * ``audit_overlap()`` — a standalone check (``python3 -m modules.audit
    <output_dir>``) that computes REAL pairwise overlap between the URL
    files, flags byte-identical duplicates, and lists empty (skipped-tool)
    files. Slower; run it by hand when you want the exact numbers.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from . import layout
from .utils import load_json, make_result, now_iso, write_json


# ----------------------------------------------------------------------
# Static catalogue. Each entry: (relative path, one-line role).
# ``subset_of`` records the design-level containment so INDEX can say
# "this is just a slice of X" without recomputing it every run.
# ----------------------------------------------------------------------
_REVIEW = [
    ("report/priority_targets.txt", "★ OPEN FIRST — ranked 'test these' list"),
    ("report/final_report.md",      "human-readable run summary"),
    ("findings/default/nuclei.json",   "nuclei — alive hosts"),
    ("findings/endpoints/nuclei.json", "nuclei — discovered endpoints"),
    ("findings/dynamic/nuclei.json",   "nuclei — param fuzzing"),
    ("findings/jsluice_secrets.json",  "secrets/keys mined from JS"),
    ("processed/subdomains.txt",       "all subdomains found"),
    ("processed/alive.txt",            "live root hosts"),
    ("processed/alive_urls.txt",       "live discovered URLs (verified)"),
    ("processed/alive_urls_table.txt", "live URLs as status|length|content-type table"),
    ("processed/parameterized_urls.txt", "injection candidates (has params)"),
    ("processed/forms.json",             "forms/inputs from crawl (POST/upload/login surface)"),
    ("processed/jsluice_endpoints.txt",  "endpoints mined from JS"),
    ("processed/jsluice_js_table.txt",   "JS files jsluice fetched, as status|length|content-type table"),
    ("responses/index.md",               "ffuf/dirsearch response previews (status/size/short body snippet)"),
]

# relative path -> (role, subset_of or None)
_INTERMEDIATE = [
    ("processed/all_urls.txt",     "MASTER url list (scope-filtered merge)", None),
    ("processed/crawler_urls.txt", "raw content-discovery merge (pre-filter)", None),
    ("processed/dynamic_urls.txt", "URLs deemed 'dynamic'", "all_urls.txt"),
    ("processed/js_urls.txt",      "JS bundle URLs (to fetch/parse)", "all_urls.txt"),
    ("processed/ffuf_urls.txt",    "ffuf hits", "all_urls.txt"),
    ("processed/jsluice_urls.txt", "URLs mined from JS", "all_urls.txt"),
    ("processed/resolved.txt",     "subdomains that resolved (DNS)", None),
    ("processed/url_derived_subdomains.txt", "new subs seen inside URLs", None),
]

# URL files whose real overlap we measure in audit_overlap().
_URL_FILES = [
    "processed/all_urls.txt",
    "processed/crawler_urls.txt",
    "processed/dynamic_urls.txt",
    "processed/parameterized_urls.txt",
    "processed/js_urls.txt",
    "processed/alive_urls.txt",
    "processed/ffuf_urls.txt",
    "processed/jsluice_urls.txt",
]


def _resolve(output_dir: Path, rel: str) -> tuple[Path, str]:
    """``(absolute path, path to display)`` for a catalogue entry.

    Catalogue entries name ``processed/`` files flat because that reads
    better than spelling out the group; ``modules.layout`` owns where they
    actually sit, and resolves to the pre-split flat path on an older
    output tree. Everything outside ``processed/`` is used as written.
    """
    if rel.startswith("processed/"):
        p = layout.path(output_dir, Path(rel).name)
        return p, str(p.relative_to(output_dir))
    return output_dir / rel, rel


def _count_and_size(path: Path) -> tuple[int, int]:
    """Return (line_count, bytes). Cheap: no full parse, just count \\n."""
    if not path.exists():
        return (-1, -1)
    size = path.stat().st_size
    if size == 0:
        return (0, 0)
    n = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            n += chunk.count(b"\n")
    return (n, size)


def _find_empty(output_dir: Path) -> list[str]:
    """Every 0-byte ``.txt`` under processed/ + raw/, relative to
    output_dir. A skipped/missing/empty-result tool leaves these behind;
    surfacing them all keeps INDEX and the audit command in agreement."""
    empties: list[str] = []
    for sub in ("processed", "raw"):
        d = output_dir / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.txt")):
            if p.is_file() and p.stat().st_size == 0:
                empties.append(str(p.relative_to(output_dir)))
    return empties


# ----------------------------------------------------------------------
# MANIFEST.json — why an artefact is empty
# ----------------------------------------------------------------------
# A 0-line file is the single most misread thing in an output tree. It has
# two opposite meanings that look identical on disk:
#
#   "the tool ran and the target genuinely has none of this"   → a result
#   "the tool was skipped / crashed / timed out"                → no data
#
# On a real discover.com run, ``apidocs_urls.txt`` and ``apidocs_params.txt``
# were both 0 bytes. The stage had run fine; every probe came back 403. That
# distinction lived only in ``findings/api_docs.json``, so anyone reading
# processed/ concluded "no API docs" when the truth was "we were blocked".
#
# The manifest writes the distinction down, next to the files, at the one
# moment it is knowable: end of run, with every stage result in hand.
MANIFEST_FILE = "MANIFEST.json"

# state -> what it means for a reader
_STATE_NOTE = {
    "ok":         "has data",
    "ran_empty":  "stage ran, found nothing — this IS a result",
    "blocked":    "stage ran but the target refused it — NOT a result",
    "truncated":  "stage hit its budget — partial or no data, NOT a result",
    "skipped":    "stage never ran — no data, says nothing about the target",
    "failed":     "stage failed — no data, says nothing about the target",
    "absent":     "never written",
}


def _stage_by_artifact(results: list[dict]) -> dict[str, dict]:
    """``{filename: stage result}`` from the stages' own ``outputs`` lists.

    Derived rather than hardcoded: a stage already declares what it wrote,
    so a new artefact is attributed correctly without touching this file.
    """
    owner: dict[str, dict] = {}
    for res in results or []:
        for out in res.get("outputs") or []:
            owner.setdefault(Path(str(out)).name, res)
    return owner


def _artifact_state(path: Path, lines: int, res: dict | None) -> tuple[str, str]:
    """``(state, reason)`` for one artefact — see ``_STATE_NOTE``."""
    if not path.exists():
        if res is None:
            return "absent", "no stage claimed this file"
        return "absent", str(res.get("error") or "stage wrote nothing")
    if lines > 0:
        return "ok", ""
    if res is None:
        return "ran_empty", "no stage claimed this file"

    extra = res.get("extra") or {}
    err = str(res.get("error") or "").strip()
    status = res.get("status")
    if extra.get("timed_out") or extra.get("deadline_hit"):
        return "truncated", err or "stage hit its time budget"
    # A stage that ran cleanly but was refused by the target (WAF/edge 401,
    # 403) learned nothing — the opposite of "found nothing". Stages declare
    # this with extra["blocked"]; we do not sniff it out of the error text.
    if extra.get("blocked"):
        return "blocked", err or "every request was refused (401/403)"
    if status == "skipped":
        return "skipped", err or "skipped"
    if status == "failed":
        return "failed", err or "failed"
    # status == success and 0 lines: a real "found nothing", unless the
    # stage left an error note explaining otherwise.
    return "ran_empty", err


def build_manifest(output_dir: Path, results: list[dict]) -> dict:
    """Write ``processed/MANIFEST.json``: per artefact, why it looks the way
    it does. Returns a standard stage-result dict."""
    output_dir = Path(output_dir)
    owner = _stage_by_artifact(results)

    artifacts: dict[str, dict] = {}
    counts: dict[str, int] = {}
    for group, names in layout.GROUPS.items():
        for name in names:
            p = layout.path(output_dir, name)
            n, b = _count_and_size(p)
            n = max(n, 0)
            res = owner.get(name)
            state, reason = _artifact_state(p, n, res)
            counts[state] = counts.get(state, 0) + 1
            entry = {
                "group": group,
                "path": str(p.relative_to(output_dir)) if p.exists() else None,
                "lines": n,
                "bytes": max(b, 0),
                "state": state,
                "means": _STATE_NOTE[state],
                "stage": (res or {}).get("stage"),
                "stage_status": (res or {}).get("status"),
            }
            if reason:
                entry["reason"] = reason
            artifacts[name] = entry

    out = layout.path(output_dir, MANIFEST_FILE)
    write_json(out, {
        "generated": now_iso(),
        "legend": _STATE_NOTE,
        "counts": counts,
        "artifacts": artifacts,
    })
    return make_result(
        "audit_manifest", "success", input_path=str(output_dir),
        outputs=[out], count=len(artifacts), extra={"states": counts},
    )


def load_manifest(output_dir: Path) -> dict[str, dict]:
    """``{filename: entry}`` from ``processed/MANIFEST.json`` (``{}`` if none)."""
    data = load_json(layout.path(Path(output_dir), MANIFEST_FILE)) or {}
    arts = data.get("artifacts")
    return arts if isinstance(arts, dict) else {}


def _sz(nbytes: int) -> str:
    """Simple, readable byte formatter."""
    if nbytes < 0:
        return "—"
    if nbytes < 1024:
        return f"{nbytes}B"
    if nbytes < 1024 ** 2:
        return f"{nbytes/1024:.0f}KB"
    if nbytes < 1024 ** 3:
        return f"{nbytes/1024**2:.1f}MB"
    return f"{nbytes/1024**3:.1f}GB"


# ----------------------------------------------------------------------
# INDEX.md — fast, written at end of run
# ----------------------------------------------------------------------
def build_index(output_dir: Path, domain: str) -> dict:
    """Write ``<output_dir>/INDEX.md`` grouping every artefact by review
    role. Returns a standard stage-result dict."""
    output_dir = Path(output_dir)
    out = output_dir / "INDEX.md"
    lines: list[str] = []
    empty = _find_empty(output_dir)

    def row(rel: str, note: str, subset_of: str | None = None) -> str:
        path, rel = _resolve(output_dir, rel)
        n, b = _count_and_size(path)
        if n < 0:
            cnt = "missing"
        elif n == 0:
            cnt = "empty"
        else:
            cnt = f"{n:,} lines · {_sz(b)}"
        tail = f" — *subset of `{subset_of}`*" if subset_of else ""
        return f"| `{rel}` | {cnt} | {note}{tail} |"

    lines.append(f"# Output index — {domain}")
    lines.append("")
    lines.append("Auto-generated map of this run's files, grouped by what to "
                 "read when reviewing. Open the 🎯 group first; everything in "
                 "🔧 is a machine-consumed slice of a master list (relationship "
                 "noted per row) and rarely needs a human.")
    lines.append("")

    lines.append("## 🎯 Review these")
    lines.append("| file | size | what |")
    lines.append("|------|------|------|")
    for rel, note in _REVIEW:
        lines.append(row(rel, note))
    lines.append("")

    lines.append("## 🔧 Intermediate (machine artefacts — skip when reviewing)")
    lines.append("| file | size | what |")
    lines.append("|------|------|------|")
    for rel, note, subset_of in _INTERMEDIATE:
        lines.append(row(rel, note, subset_of))
    lines.append("")
    lines.append("Containment (verify anytime with `python3 -m modules.audit "
                 "<output_dir>`):")
    lines.append("")
    lines.append("```")
    lines.append("all_urls.txt  ⊇  dynamic_urls.txt  ⊇  parameterized_urls.txt")
    lines.append("all_urls.txt  ⊇  js_urls.txt, ffuf_urls.txt, jsluice_urls.txt")
    lines.append("```")
    lines.append("")

    # raw/ summary — one collapsed line, never per-file (it's huge)
    raw = output_dir / "raw"
    if raw.is_dir():
        raw_files = list(raw.rglob("*"))
        raw_txt = [p for p in raw_files if p.is_file()]
        total = sum(p.stat().st_size for p in raw_txt)
        lines.append("## 📦 raw/ (provenance only — do not review by hand)")
        lines.append(f"{len(raw_txt)} files, {_sz(total)} total. Kept so every "
                     "URL can be traced to the tool that found it "
                     "(katana/urlfinder/ffuf/jsluice…).")
        lines.append("")

    if empty:
        # A 0-line file means either "we looked and there is none" or "we
        # never looked" — opposite conclusions, identical on disk. Pull the
        # answer out of MANIFEST.json rather than lumping them together.
        manifest = load_manifest(output_dir)
        lines.append("## ⚪ Empty (0 lines) — read the reason, not the file")
        lines.append("")
        lines.append("`ran_empty` is a **result** (we looked, there is none). "
                     "`skipped` / `failed` / `truncated` are **not** — they "
                     "say nothing about the target. Full detail in "
                     "`processed/MANIFEST.json`.")
        lines.append("")
        lines.append("| file | state | means | reason |")
        lines.append("|------|-------|-------|--------|")
        for rel in empty:
            e = manifest.get(Path(rel).name, {})
            state = e.get("state", "?")
            reason = str(e.get("reason") or "—").replace("|", "\\|")[:80]
            lines.append(
                f"| `{rel}` | `{state}` | {e.get('means', '—')} | {reason} |"
            )
        lines.append("")

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return make_result(
        "audit_index", "success", input_path=domain,
        outputs=[out], count=len(_REVIEW) + len(_INTERMEDIATE),
        extra={"empty_files": len(empty)},
    )


# ----------------------------------------------------------------------
# audit_overlap — slow, on-demand real numbers
# ----------------------------------------------------------------------
def _load_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {x.strip() for x in path.read_text(errors="ignore").splitlines()
            if x.strip()}


def audit_overlap(output_dir: Path) -> dict:
    """Print real overlap between URL files, byte-identical duplicates, and
    empty files. Returns a summary dict (also handy for tests)."""
    output_dir = Path(output_dir)
    print(f"# audit: {output_dir}\n")

    # 1. byte-identical duplicates — hash the catalogued files (deduped so
    #    a file listed in two catalogues isn't compared against itself).
    catalogued = list(dict.fromkeys(
        _URL_FILES + [r for r, _ in _REVIEW] + [r for r, _, _ in _INTERMEDIATE]
    ))
    hashes: dict[str, list[str]] = {}
    for rel in catalogued:
        p, shown = _resolve(output_dir, rel)
        if p.exists() and p.stat().st_size > 0:
            h = hashlib.md5(p.read_bytes()).hexdigest()
            hashes.setdefault(h, []).append(shown)
    dupes = [group for group in hashes.values() if len(group) > 1]
    print("\n## byte-identical duplicates")
    if dupes:
        for group in dupes:
            print("  IDENTICAL: " + " == ".join(group))
    else:
        print("  none")

    # 3. real overlap between URL files
    print("\n## URL-file containment (how much of A already lives in B)")
    sets = {rel: _load_set(_resolve(output_dir, rel)[0]) for rel in _URL_FILES}
    master = "processed/all_urls.txt"
    m = sets.get(master, set())
    for rel, s in sets.items():
        if rel == master or not s:
            continue
        inter = len(s & m)
        pct = 100 * inter / len(s)
        flag = "  ⊆ subset" if pct >= 99.0 else ""
        print(f"  {rel:38} {inter:>7}/{len(s):>7} ({pct:5.1f}% ⊆ all_urls){flag}")

    # 4. empties — scan ALL of processed/ + raw/, not just the catalogue,
    #    so a skipped tool's 0-byte output is always surfaced.
    empties = _find_empty(output_dir)
    print("\n## empty files (tool skipped / no result)")
    if empties:
        for rel in empties:
            print(f"  {rel}")
    else:
        print("  none")

    print(f"\nsummary: {len(dupes)} duplicate group(s), "
          f"{len(empties)} empty file(s)")
    return {"duplicates": dupes, "empty": empties}


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: python3 -m modules.audit <output_dir>")
        print("  e.g. python3 -m modules.audit outputs/acronis.com")
        return 2
    audit_overlap(Path(argv[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
