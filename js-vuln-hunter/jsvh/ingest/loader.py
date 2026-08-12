"""Locate and read raw recon2win artifacts for a target.

This is the *only* module that knows recon2win's on-disk layout. Every
path recon2win might produce is declared here once; the rest of the
pipeline consumes typed Python objects. Paths follow recon2win's
``modules/layout.py`` v3 grouping, with a flat-layout fallback so older
output trees still load.

Detected contract (verified against real runs, see
``docs/recon2win-integration.md``):

  processed/corpus/js_urls.txt          newline JS URLs
  processed/js/jsluice_js_detail.json   [{url,status_code,content_type,content_length}]
  processed/js/jsluice_endpoints.txt    endpoints mined from JS (jsluice AST)
  processed/js/jsluice_urls.txt         URLs mined from JS
  processed/js/jsluice_params.json      [{url,method,queryParams,bodyParams}]
  processed/js/xnlinkfinder_endpoints.txt
  processed/js/xnlinkfinder_urls.txt
  processed/corpus/all_urls.jsonl       {url, sources:[tool,...]}  (provenance)
  processed/hosts/alive_detail.json     httpx host metadata incl tech[]
  processed/hosts/alive_urls_detail.json per-URL httpx metadata
  findings/jsluice_secrets.json         {findings:[...], severity_count:{}}
  report/priority_targets.txt           ranked hand-testing shortlist
  raw/jsluice/NNNN.js                    fetched JS bodies (index != URL map)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Relative paths inside a recon2win target dir. First existing wins.
_PATHS = {
    "js_urls": ["processed/corpus/js_urls.txt", "processed/js_urls.txt"],
    "js_detail": ["processed/js/jsluice_js_detail.json", "processed/jsluice_js_detail.json"],
    "jsluice_endpoints": ["processed/js/jsluice_endpoints.txt", "processed/jsluice_endpoints.txt"],
    "jsluice_urls": ["processed/js/jsluice_urls.txt", "processed/jsluice_urls.txt"],
    "jsluice_params": ["processed/js/jsluice_params.json", "processed/jsluice_params.json"],
    "xnlinkfinder_endpoints": ["processed/js/xnlinkfinder_endpoints.txt", "processed/xnlinkfinder_endpoints.txt"],
    "xnlinkfinder_urls": ["processed/js/xnlinkfinder_urls.txt", "processed/xnlinkfinder_urls.txt"],
    "all_urls_jsonl": ["processed/corpus/all_urls.jsonl", "processed/all_urls.jsonl"],
    "alive_detail": ["processed/hosts/alive_detail.json", "processed/alive_detail.json"],
    "alive_urls_detail": ["processed/hosts/alive_urls_detail.json", "processed/alive_urls_detail.json"],
    "jsluice_secrets": ["findings/jsluice_secrets.json"],
    "priority_targets": ["report/priority_targets.txt"],
    "manifest": ["processed/MANIFEST.json"],
}


def _first_existing(base: Path, rels: list[str]) -> Path | None:
    for rel in rels:
        p = base / rel
        if p.exists():
            return p
    return None


def _read_lines(p: Path | None) -> list[str]:
    if not p or not p.exists():
        return []
    out = []
    for line in p.read_text(errors="replace").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def _read_json(p: Path | None) -> Any:
    if not p or not p.exists():
        return None
    try:
        return json.loads(p.read_text(errors="replace") or "null")
    except json.JSONDecodeError:
        return None


def _read_jsonl(p: Path | None) -> list[dict]:
    if not p or not p.exists():
        return []
    rows = []
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


@dataclass
class ReconData:
    """Everything ingested from one recon2win target dir."""
    target: str
    base_dir: Path
    resolved_paths: dict[str, Path] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)

    js_urls: list[str] = field(default_factory=list)
    js_detail: list[dict] = field(default_factory=list)
    jsluice_endpoints: list[str] = field(default_factory=list)
    jsluice_urls: list[str] = field(default_factory=list)
    jsluice_params: list[dict] = field(default_factory=list)
    xnlinkfinder_endpoints: list[str] = field(default_factory=list)
    xnlinkfinder_urls: list[str] = field(default_factory=list)
    provenance: dict[str, list[str]] = field(default_factory=dict)  # url -> sources
    alive_hosts: list[dict] = field(default_factory=list)
    alive_urls: list[dict] = field(default_factory=list)
    jsluice_secrets: dict = field(default_factory=dict)
    priority_targets: list[str] = field(default_factory=list)


def load(target: str, base_dir: Path) -> ReconData:
    """Read every known recon2win artifact under *base_dir*."""
    rd = ReconData(target=target, base_dir=base_dir)

    resolved: dict[str, Path] = {}
    for key, rels in _PATHS.items():
        p = _first_existing(base_dir, rels)
        if p:
            resolved[key] = p
        else:
            rd.missing.append(key)
    rd.resolved_paths = resolved

    rd.js_urls = _read_lines(resolved.get("js_urls"))
    rd.js_detail = _read_json(resolved.get("js_detail")) or []
    rd.jsluice_endpoints = _read_lines(resolved.get("jsluice_endpoints"))
    rd.jsluice_urls = _read_lines(resolved.get("jsluice_urls"))
    rd.jsluice_params = _read_json(resolved.get("jsluice_params")) or []
    rd.xnlinkfinder_endpoints = _read_lines(resolved.get("xnlinkfinder_endpoints"))
    rd.xnlinkfinder_urls = _read_lines(resolved.get("xnlinkfinder_urls"))
    rd.alive_hosts = _read_json(resolved.get("alive_detail")) or []
    rd.alive_urls = _read_json(resolved.get("alive_urls_detail")) or []
    secrets = _read_json(resolved.get("jsluice_secrets"))
    rd.jsluice_secrets = secrets if isinstance(secrets, dict) else {}
    rd.priority_targets = _read_lines(resolved.get("priority_targets"))

    for row in _read_jsonl(resolved.get("all_urls_jsonl")):
        u = row.get("url")
        if u:
            rd.provenance[u] = row.get("sources", []) or []

    return rd
