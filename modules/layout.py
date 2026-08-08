"""layout — the single source of truth for where a processed artefact lives.

``processed/`` used to be one flat directory of ~25 files that mixed three
completely different lifecycles: per-tool scratch output (``ffuf_urls.txt``),
the merged corpus everything downstream reads (``all_urls.txt``), and the
handful of files a human actually opens (``parameterized_urls.txt``,
``forms.json``). Opening the folder told you nothing about which was which,
and the naming was no help either — half the files are named after the tool
that made them and half after what they mean.

This module groups them into subfolders by lifecycle::

    processed/
        sources/    per-tool output, pre-merge — scratch
        corpus/     merged + classified URL sets — the pipeline's spine
        hosts/      subdomain / DNS / liveness inventory
        js/         everything mined out of JavaScript
        targets/    the hand-testing shortlist — open these first

Nothing else in the codebase should join a ``processed/`` path by hand.
Call :func:`path` and let the registry place the file.

Backward compatibility
----------------------
:func:`path` returns the legacy flat location when a file exists there and
not in its new group. That keeps ``--resume`` working against output trees
written before the split — the run reads and rewrites the tree it was given
rather than half-migrating it — while a fresh run lays everything out the
new way. A file that exists in neither place resolves to the new path, so
writers always create the grouped layout.
"""
from __future__ import annotations

from pathlib import Path

# ----------------------------------------------------------------------
# Registry. Adding a new processed artefact means adding it HERE — an
# unregistered name falls back to the flat root, which still works but
# gets none of the grouping.
# ----------------------------------------------------------------------
GROUPS: dict[str, tuple[str, ...]] = {
    # Raw per-tool output. Deliberately NOT deduped against each other:
    # keeping them separate is what makes provenance recoverable.
    "sources": (
        "crawler_urls.txt",
        "dirsearch_urls.txt",
        "ffuf_urls.txt",
        "waymore_urls.txt",
        "apidocs_urls.txt",
        "apidocs_params.txt",
        "misconfig_urls.txt",
        "fuzz_recurse_urls.txt",
    ),
    # The merged spine. all_urls.jsonl carries the provenance for
    # all_urls.txt line-for-line (see modules.url_merge).
    "corpus": (
        "all_urls.txt",
        "all_urls.jsonl",
        "dynamic_urls.txt",
        "js_urls.txt",
    ),
    # Host inventory, from passive enum through to liveness.
    "hosts": (
        "subdomains.txt",
        "resolved.txt",
        "resolved_detail.json",
        "alive.txt",
        "alive_detail.json",
        "alive_table.txt",
        "alive_urls.txt",
        "alive_urls_detail.json",
        "alive_urls_table.txt",
        "url_derived_subdomains.txt",
        "screenshots_index.json",
        "tech_confirmed.json",
    ),
    # Mined from JS — jsluice (AST) and xnLinkFinder (regex).
    "js": (
        "jsluice_endpoints.txt",
        "jsluice_urls.txt",
        "jsluice_params.json",
        "jsluice_alive.txt",
        "jsluice_alive_detail.json",
        "jsluice_alive_table.txt",
        "jsluice_js_detail.json",
        "jsluice_js_table.txt",
        "jsluice_method_check.json",
        "jsluice_method_check_table.txt",
        "xnlinkfinder_endpoints.txt",
        "xnlinkfinder_urls.txt",
    ),
    # What a human opens. Small on purpose.
    "targets": (
        "parameterized_urls.txt",
        "arjun_params.txt",
        "forms.json",
    ),
}

# filename -> group, built once.
_GROUP_OF: dict[str, str] = {
    name: group for group, names in GROUPS.items() for name in names
}


def group_of(name: str) -> str | None:
    """Which subfolder *name* belongs in (``None`` when unregistered)."""
    return _GROUP_OF.get(Path(name).name)


def legacy_path(output_dir: Path, name: str) -> Path:
    """Where this artefact lived before the split: ``processed/<name>``."""
    return Path(output_dir) / "processed" / Path(name).name


def grouped_path(output_dir: Path, name: str) -> Path:
    """Canonical new location, ignoring what happens to be on disk."""
    base = Path(output_dir) / "processed"
    group = group_of(name)
    return (base / group / Path(name).name) if group else (base / Path(name).name)


def path(output_dir: Path, name: str) -> Path:
    """Resolve *name* to the path this run should read AND write.

    One function for both directions on purpose — it makes the call sites
    uniform and it does the right thing in every case:

    * new file, nothing on disk    → grouped path (writers build the split)
    * grouped file exists          → grouped path
    * only the legacy flat file    → legacy path

    That last case is what keeps ``--resume`` honest on a pre-split tree:
    every artefact that already exists is read and rewritten where it sits,
    so the run does not scatter half the tree into new folders mid-scan.
    Resolution is per file, so an artefact with no legacy counterpart —
    ``all_urls.jsonl`` on a tree written before provenance — is still
    created in its group. That is the intended outcome: nothing moves, only
    genuinely new files use the new layout.

    The parent directory is created, matching ``utils.raw_dir`` /
    ``utils.findings_dir``. Several stages write with a bare
    ``Path.write_text()`` rather than ``utils.write_lines``, and making the
    directory their problem would just be a new way to fail late.
    """
    new = grouped_path(output_dir, name)
    if new.exists():
        return new
    old = legacy_path(output_dir, name)
    if old != new and old.exists():
        return old
    new.parent.mkdir(parents=True, exist_ok=True)
    return new


def ensure_tree(output_dir: Path) -> Path:
    """Create ``processed/`` and every group subfolder."""
    base = Path(output_dir) / "processed"
    for group in GROUPS:
        (base / group).mkdir(parents=True, exist_ok=True)
    return base


def iter_known(output_dir: Path):
    """Yield ``(name, group, resolved_path)`` for every registered artefact
    that exists, in registry order. Used by audit/report so they describe
    the tree by the registry rather than by re-globbing it.
    """
    for group, names in GROUPS.items():
        for name in names:
            p = path(output_dir, name)
            if p.exists():
                yield (name, group, p)
