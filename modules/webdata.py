"""webdata — read-only data access for the web results browser (``web/app.py``).

Reads the plain-text table files (``alive_table.txt`` / ``alive_urls_table.txt``
— the same ``ST  LENGTH  CONTENT-TYPE  URL`` format the ``recon-surface`` skill
already relies on) and ``findings/default/nuclei.json`` that a scan already
writes. No new index, no database — pagination/filtering happens in Python on
each request.

That is a deliberate, scoped-down choice, not an oversight: a single local
user reading files already on disk pays maybe a few hundred ms even on the
largest table seen in practice (~470k lines). ``docs/architecture/decisions.md``
records the tradeoff and the SQLite-index alternative (already designed in
``docs/ui-design.md``) to switch to if this ever needs to serve more than one
person, or the file sizes grow enough to make per-request scans slow.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import dashboard, layout
from .utils import load_json


def resolve_target(outputs_root: Path, target_ref: str) -> Optional[dict]:
    """Resolve a URL path segment (``domain`` or ``project/domain``) to its
    on-disk target directory.

    Returns ``{"path": Path, "project": str | None, "domain": str}``, or
    ``None`` if *target_ref* doesn't resolve to a real target directory —
    covers both "not found" and path-traversal attempts (``..`` segments are
    stripped before the path is ever built, and the result must pass
    ``dashboard._is_target_dir`` — an arbitrary directory elsewhere on disk
    won't have that skeleton).
    """
    parts = [p for p in target_ref.split("/") if p not in ("", ".", "..")]
    if not (1 <= len(parts) <= 2):
        return None
    outputs_root = Path(outputs_root)
    path = outputs_root.joinpath(*parts)
    if not dashboard._is_target_dir(path):
        return None
    project = parts[0] if len(parts) == 2 else None
    domain = parts[-1]
    return {"path": path, "project": project, "domain": domain}


def list_targets(outputs_root: Path) -> list[dict]:
    """Every target, grouped by project, with the same summary
    ``modules.dashboard`` computes for ``outputs/dashboard.html`` — the
    ``/results`` landing page reuses it rather than recomputing anything."""
    outputs_root = Path(outputs_root)
    dashboard_path = outputs_root / "dashboard.html"
    refs = dashboard.discover_targets(outputs_root)
    targets = [
        dashboard.load_target(r["path"], dashboard_path, project=r["project"])
        for r in refs
    ]
    targets.sort(key=lambda t: t["risk_score"], reverse=True)
    return targets


def target_overview(target_dir: Path, project: Optional[str] = None) -> dict:
    """Single-target summary record — same shape as ``list_targets()``'s
    rows, for the target overview page.

    Ignore the returned ``report_rel``: it's computed against a plausible
    but not-necessarily-real dashboard.html location, because this call has
    no such shared page to link from. Build the actual "view report" link
    with ``url_for(...)`` in the route instead — see ``web/app.py``.
    """
    return dashboard.load_target(target_dir, target_dir.parent / "dashboard.html", project=project)


# ----------------------------------------------------------------------
# Paginated table reader — alive_table.txt / alive_urls_table.txt
# ----------------------------------------------------------------------
def paginate_table(
    path: Path, *, q: str = "", status: str = "", page: int = 1, limit: int = 100,
) -> dict:
    """Read a ``ST  LENGTH  CONTENT-TYPE  URL`` table file, filter, and slice
    one page.

    Returns ``{"rows": [{"status","length","content_type","url"}, ...],
    "total", "page", "pages", "limit"}``. A missing file (stage skipped, or
    never ran) yields an empty, valid result — not an error.
    """
    page = max(page, 1)
    limit = max(1, min(limit, 1000))
    q_lower = q.strip().lower()
    status = status.strip()

    rows: list[dict] = []
    if path.exists():
        for raw_line in path.read_text(errors="ignore").splitlines()[1:]:  # skip header
            line = raw_line.strip()
            if not line:
                continue
            fields = line.split(None, 3)
            if len(fields) < 4:
                continue
            st, length, ctype, url = fields
            if status and st != status:
                continue
            if q_lower and q_lower not in url.lower() and q_lower not in ctype.lower():
                continue
            rows.append({"status": st, "length": length, "content_type": ctype, "url": url})

    total = len(rows)
    pages = max(1, -(-total // limit))  # ceil division
    page = min(page, pages)
    start = (page - 1) * limit
    return {
        "rows": rows[start:start + limit],
        "total": total, "page": page, "pages": pages, "limit": limit,
    }


def hosts_table(target_dir: Path, **kw) -> dict:
    return paginate_table(layout.path(target_dir, "alive_table.txt"), **kw)


def urls_table(target_dir: Path, **kw) -> dict:
    return paginate_table(layout.path(target_dir, "alive_urls_table.txt"), **kw)


# ----------------------------------------------------------------------
# File browser — raw / processed / findings / logs / responses / report
# ----------------------------------------------------------------------
# Top-level subdirs of a target we expose in the Files browser. Everything a
# scan writes lives under one of these; anything else in the target dir
# (``.scan_state.json``, ``INDEX.md``, stray dot-files) is not recon output
# and stays hidden.
BROWSABLE_DIRS: tuple[str, ...] = (
    "findings", "report", "processed", "raw", "responses", "logs",
)

# Suffixes we render inline as text. Everything else is download-only.
_TEXT_EXTS: frozenset[str] = frozenset({
    ".txt", ".json", ".jsonl", ".ndjson", ".md", ".log", ".csv", ".tsv",
    ".html", ".htm", ".js", ".css", ".yaml", ".yml", ".xml", ".conf",
    ".ini", ".cfg", ".env", ".sh", ".py", ".har", ".mmd", ".text",
})

# Inline text-view cap. Larger files are still served whole via ?raw=1.
TEXT_PREVIEW_LIMIT = 2 * 1024 * 1024  # 2 MiB


def list_files(target_dir: Path) -> list[dict]:
    """Every recon file under a target's browsable subdirs, as flat records.

    Returns ``[{"rel","group","name","size","mtime","is_text"}, ...]`` sorted
    by group (in ``BROWSABLE_DIRS`` order) then relative path. ``rel`` is a
    POSIX path relative to *target_dir* — the same key the tree view renders
    and the file-serving route resolves. A missing subdir is simply skipped,
    so a partial (or in-progress) scan lists whatever exists.
    """
    target_dir = Path(target_dir)
    order = {g: i for i, g in enumerate(BROWSABLE_DIRS)}
    out: list[dict] = []
    for group in BROWSABLE_DIRS:
        base = target_dir / group
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            out.append({
                "rel": p.relative_to(target_dir).as_posix(),
                "group": group,
                "name": p.name,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "is_text": p.suffix.lower() in _TEXT_EXTS,
            })
    out.sort(key=lambda f: (order.get(f["group"], 99), f["rel"]))
    return out


def resolve_file(target_dir: Path, rel: str) -> Optional[Path]:
    """Resolve a browser-supplied relative path to a real file under a
    browsable subdir of *target_dir*, or ``None``.

    Path-traversal safe: ``..``/empty segments are stripped, the first
    segment must be a ``BROWSABLE_DIRS`` entry, and the fully resolved path
    must still live inside *target_dir* (guards symlinks that point outward).
    """
    target_dir = Path(target_dir).resolve()
    parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
    if not parts or parts[0] not in BROWSABLE_DIRS:
        return None
    candidate = target_dir.joinpath(*parts).resolve()
    try:
        candidate.relative_to(target_dir)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def read_text_preview(path: Path, limit: int = TEXT_PREVIEW_LIMIT) -> dict:
    """Read up to *limit* bytes of *path* as text for inline display.

    Returns ``{"text", "truncated", "size"}``. Decoding is UTF-8 with
    ``errors="replace"`` so a binary-ish file never raises — it just renders
    with replacement chars, and the caller already decides what is "text".
    """
    size = path.stat().st_size
    with path.open("rb") as fh:
        data = fh.read(limit)
    return {
        "text": data.decode("utf-8", errors="replace"),
        "truncated": size > len(data),
        "size": size,
    }


# ----------------------------------------------------------------------
# Findings — findings/default/nuclei.json
# ----------------------------------------------------------------------
def list_findings(
    target_dir: Path, *, severity: str = "", q: str = "", page: int = 1, limit: int = 100,
) -> dict:
    """Read ``findings/default/nuclei.json``, filter, and slice one page.

    Returns ``{"rows": [...raw nuclei finding dicts, trimmed to the fields
    the table needs...], "total", "page", "pages", "limit"}``.
    """
    page = max(page, 1)
    limit = max(1, min(limit, 1000))
    severity = severity.strip().lower()
    q_lower = q.strip().lower()

    data = load_json(target_dir / "findings" / "default" / "nuclei.json") or {}
    findings = data.get("findings") or []

    rows: list[dict] = []
    for f in findings:
        info = f.get("info") or {}
        sev = str(info.get("severity") or "unknown").lower()
        if severity and sev != severity:
            continue
        name = str(info.get("name") or "")
        matched_at = str(f.get("matched-at") or f.get("host") or "")
        template_id = str(f.get("template-id") or "")
        if q_lower and not any(
            q_lower in s.lower() for s in (name, matched_at, template_id)
        ):
            continue
        rows.append({
            "severity": sev,
            "name": name,
            "template_id": template_id,
            "matched_at": matched_at,
            "template_url": f.get("template-url"),
        })

    # Highest severity first, matching modules/dashboard.py's weighting order.
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    rows.sort(key=lambda r: _order.get(r["severity"], 9))

    total = len(rows)
    pages = max(1, -(-total // limit))
    page = min(page, pages)
    start = (page - 1) * limit
    return {
        "rows": rows[start:start + limit],
        "total": total, "page": page, "pages": pages, "limit": limit,
        "severity_count": data.get("severity_count") or {},
    }
