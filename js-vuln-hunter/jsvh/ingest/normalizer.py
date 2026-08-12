"""Normalize + deduplicate JS assets and assign stable ids.

Dedup key is the canonical URL (scheme+host+path+query, fragment dropped,
default ports removed). recon2win may surface the same file under both a
crawler hit and a jsluice mine; we collapse those and union provenance.

Asset ids are assigned in canonical-URL sort order so a given target
produces stable ``js_000001`` ids across re-ingests (important for the
candidate ids that reference them).
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from ..models import JSAsset


_DEFAULT_PORTS = {"http": "80", "https": "443"}


def canonical_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    port = parts.port
    netloc = host
    if port and str(port) != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def normalize(assets: list[JSAsset]) -> list[JSAsset]:
    merged: dict[str, JSAsset] = {}
    for a in assets:
        key = canonical_url(a.url)
        if key in merged:
            existing = merged[key]
            # union provenance; prefer a row that carries HTTP detail
            prov = set(existing.provenance) | set(a.provenance)
            existing.provenance = sorted(prov)
            if existing.status_code is None and a.status_code is not None:
                existing.status_code = a.status_code
                existing.content_type = a.content_type
                existing.content_length = a.content_length
        else:
            a.provenance = sorted(set(a.provenance))
            merged[key] = a

    ordered = sorted(merged.values(), key=lambda x: canonical_url(x.url))
    for i, a in enumerate(ordered, start=1):
        a.asset_id = f"js_{i:06d}"
    return ordered
