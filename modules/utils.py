"""utils — domain validation, IO helpers, result factory.

All other modules import `make_result` from here so the response shape stays
consistent with the spec.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional

# RFC 1035 / 1123 — pragmatic domain pattern, not a full parser.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$"
)


# ----------------------------------------------------------------------
# Validation
# ----------------------------------------------------------------------
def validate_domain(domain: str) -> str:
    """Return a cleaned lowercased domain or raise ValueError."""
    if domain is None:
        raise ValueError("domain is required")
    d = domain.strip().lower()
    # strip scheme / path if the user pastes a URL
    d = re.sub(r"^https?://", "", d)
    d = d.split("/", 1)[0]
    if not DOMAIN_RE.match(d):
        raise ValueError(f"invalid domain: {domain!r}")
    return d


# ----------------------------------------------------------------------
# Filesystem layout
# ----------------------------------------------------------------------
def create_output_structure(domain: str, root: str = "outputs") -> Path:
    """Create the standard folder tree under ``<root>/<domain>/``.

    Layout (v2 — grouped by stage for ``raw/`` and ``findings/``):

        <root>/<domain>/
            raw/                     # tool outputs grouped by stage
                subdomain/           # subfinder.txt, amass.txt, chaos.txt
                content_discovery/   # katana_urls.txt, urlfinder_urls.txt
                dirsearch/           # dirsearch_raw.txt, merged_wordlists.txt
                waymore/             # waymore_raw.txt
                arjun/               # input_subset.txt
            processed/               # cleaned + merged artefacts, flat
            findings/                # nuclei only, grouped by kind
                default/             # nuclei.json, nuclei.txt
                dynamic/             # nuclei.json, nuclei.txt
            logs/                    # commands.log, stages.json, <stage>.log
            tests_input/             # reserved for future sample inputs
            report/                  # final_report.{html,md,json}
    """
    base = Path(root) / domain
    for sub in (
        "raw",
        "raw/subdomain",
        "raw/content_discovery",
        "raw/dirsearch",
        "raw/waymore",
        "raw/arjun",
        "processed",
        "findings",
        "findings/default",
        "findings/dynamic",
        "logs",
        "tests_input",
        "report",
    ):
        (base / sub).mkdir(parents=True, exist_ok=True)
    return base


def raw_dir(output_dir: Path, stage: str) -> Path:
    """Return ``<output_dir>/raw/<stage>/`` and create it if missing.

    Centralises the per-stage raw subfolder convention so callers don't
    accidentally write to the old flat ``raw/`` root. Raises if *stage*
    is not a known subfolder (catches typos at write time).
    """
    valid = {"subdomain", "content_discovery", "dirsearch", "waymore", "arjun"}
    if stage not in valid:
        raise ValueError(
            f"unknown raw subfolder {stage!r} — valid options: {sorted(valid)}"
        )
    d = output_dir / "raw" / stage
    d.mkdir(parents=True, exist_ok=True)
    return d


def findings_dir(output_dir: Path, kind: str) -> Path:
    """Return ``<output_dir>/findings/<kind>/`` and create it if missing.

    ``kind`` is one of ``"default"`` or ``"dynamic"`` (the two nuclei
    scan modes).
    """
    valid = {"default", "dynamic"}
    if kind not in valid:
        raise ValueError(
            f"unknown findings subfolder {kind!r} — valid options: {sorted(valid)}"
        )
    d = output_dir / "findings" / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


# ----------------------------------------------------------------------
# IO helpers
# ----------------------------------------------------------------------
def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for ln in path.read_text(errors="ignore").splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def write_lines(path: Path, lines: Iterable[str]) -> int:
    """Write unique non-empty lines. Returns the number written."""
    seen: set[str] = set()
    cleaned: List[str] = []
    for ln in lines:
        if ln is None:
            continue
        s = str(ln).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(cleaned) + ("\n" if cleaned else ""), encoding="utf-8")
    return len(cleaned)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(errors="ignore") or "null")
    except json.JSONDecodeError:
        return None


def safe_append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")


# ----------------------------------------------------------------------
# Result factory — every stage must return a dict shaped like this.
# ----------------------------------------------------------------------
def make_result(
    stage: str,
    status: str,
    input_path: Optional[Path | str] = None,
    outputs: Optional[List[Path | str]] = None,
    count: int = 0,
    error: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    res: dict[str, Any] = {
        "stage": stage,
        "status": status,
        "input": str(input_path) if input_path else None,
        "outputs": [str(p) for p in (outputs or [])],
        "count": count,
        "error": error,
    }
    if extra:
        res["extra"] = extra
    return res


def now_iso() -> str:
    # timezone-aware UTC, ISO 8601 with trailing 'Z' for portability.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
