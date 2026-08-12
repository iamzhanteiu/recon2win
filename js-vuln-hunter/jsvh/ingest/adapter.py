"""Map recon2win rows onto the internal JSAsset schema.

recon2win gives us two overlapping views of the JS surface:

  * ``jsluice_js_detail.json`` — every JS URL it *fetched*, with HTTP
    status/content-type/length. Authoritative, already HTTP-verified.
  * ``js_urls.txt`` — every JS URL it *discovered*. Superset; some never
    got fetched (dead, out of budget).

We seed the inventory from js_detail (richest) and top it up with any
js_urls.txt entry not already present, so nothing discovered is dropped.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..models import JSAsset
from .loader import ReconData


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.split("@")[-1].split(":")[0]
    except ValueError:
        return ""


def _looks_like_js(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith((".js", ".mjs", ".jsx", ".ts", ".tsx"))


def to_assets(rd: ReconData) -> list[JSAsset]:
    """Produce one JSAsset per distinct JS URL recon2win knows about."""
    by_url: dict[str, JSAsset] = {}

    # 1. authoritative fetched detail
    for row in rd.js_detail:
        url = row.get("url")
        if not url:
            continue
        by_url.setdefault(url, JSAsset(
            asset_id="",  # assigned by normalizer
            target=rd.target,
            host=_host_of(url),
            url=url,
            status_code=row.get("status_code"),
            content_type=row.get("content_type"),
            content_length=row.get("content_length"),
            provenance=list(rd.provenance.get(url, [])),
        ))

    # 2. discovered-but-not-in-detail JS URLs
    for url in rd.js_urls:
        if url in by_url or not _looks_like_js(url):
            continue
        by_url[url] = JSAsset(
            asset_id="",
            target=rd.target,
            host=_host_of(url),
            url=url,
            provenance=list(rd.provenance.get(url, [])),
        )

    return list(by_url.values())
