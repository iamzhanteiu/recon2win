"""JavaScript acquisition.

We download JS **only from recon2win-provided URLs** — this is not a
crawler and never discovers new URLs. Supports HTTPS/redirects/gzip. Each
body is hashed (sha256) and written to ``targets/<t>/raw/<asset_id>.js``.

Acquisition is best-effort: a JS file we can't fetch simply contributes no
AST, and its asset is marked ``error`` with the reason. recon2win already
fetched most of these once; we re-fetch so analysis works on the exact
bytes we hash, and so source maps / non-200 assets can be revisited.
"""

from __future__ import annotations

import concurrent.futures as cf
import gzip
import io
import urllib.error
import urllib.request
import zlib
from pathlib import Path

from .config import Config
from .models import JSAsset, sha256_hex


def _decompress(data: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    try:
        if enc == "gzip":
            return gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        if enc == "deflate":
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        return data
    return data


def _fetch_one(asset: JSAsset, cfg: Config) -> JSAsset:
    req = urllib.request.Request(
        asset.url,
        headers={"User-Agent": cfg.user_agent, "Accept-Encoding": "gzip, deflate"},
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            raw = resp.read(cfg.max_bytes)
            data = _decompress(raw, resp.headers.get("Content-Encoding", ""))
            asset.status_code = resp.status
            asset.content_type = (resp.headers.get("Content-Type", "") or "").split(";")[0].strip() or asset.content_type
    except urllib.error.HTTPError as e:
        asset.status_code = e.code
        asset.analysis_status = "error"
        asset.parse_error = f"http {e.code}"
        return asset
    except Exception as e:  # noqa: BLE001 — DNS/TLS/timeout
        asset.analysis_status = "error"
        asset.parse_error = f"fetch: {type(e).__name__}"
        return asset

    asset.size = len(data)
    asset.sha256 = sha256_hex(data)
    path = cfg.raw_js_dir / f"{asset.asset_id}.js"
    try:
        path.write_bytes(data)
        asset.local_path = str(path.relative_to(cfg.workspace))
        asset.analysis_status = "acquired"
    except OSError as e:
        asset.analysis_status = "error"
        asset.parse_error = f"write: {e}"
    return asset


def acquire_all(assets: list[JSAsset], cfg: Config) -> tuple[int, int]:
    """Download every asset. Returns (ok, failed)."""
    cfg.ensure_dirs()
    ok = failed = 0
    # only attempt things that plausibly return a body
    targets = [a for a in assets if a.status_code in (None,) or 200 <= (a.status_code or 0) < 400]
    with cf.ThreadPoolExecutor(max_workers=cfg.workers) as pool:
        for a in pool.map(lambda x: _fetch_one(x, cfg), targets):
            if a.analysis_status == "acquired":
                ok += 1
            else:
                failed += 1
    return ok, failed


def from_recon_raw(assets: list[JSAsset], recon_dir: Path, js_detail: list[dict],
                   cfg: Config) -> int:
    """Reuse the JS bodies recon2win already downloaded (no re-fetch).

    recon2win writes each successfully-fetched JS body to
    ``raw/jsluice/NNNN.js`` in the order of the fetched (2xx/3xx-with-body)
    rows of ``jsluice_js_detail.json``. We reconstruct that URL→file map
    (validated by content_length) and copy the bytes into our workspace.
    This is the zero-duplication path (mission §5): the exact bytes
    recon2win analysed, never a second download.
    """
    raw_dir = recon_dir / "raw" / "jsluice"
    if not raw_dir.is_dir():
        return 0
    raw_files = sorted(p for p in raw_dir.glob("*.js"))
    ok_rows = [r for r in js_detail
               if 200 <= (r.get("status_code") or 0) < 400 and (r.get("content_length") or 0) > 0]

    # positional zip, guarded by a content_length match to stay correct even
    # if counts drift by a few (recursive fetches, races).
    url_to_path: dict[str, Path] = {}
    for row, path in zip(ok_rows, raw_files):
        try:
            if path.stat().st_size == row.get("content_length"):
                url_to_path[row["url"]] = path
        except OSError:
            continue
    # fall back to a pure content_length index for the unmatched remainder
    by_len: dict[int, list[Path]] = {}
    for p in raw_files:
        try:
            by_len.setdefault(p.stat().st_size, []).append(p)
        except OSError:
            pass

    cfg.ensure_dirs()
    from .ingest.normalizer import canonical_url
    canon = {canonical_url(u): u for u in url_to_path}
    used = 0
    for a in assets:
        if a.analysis_status in ("acquired", "analyzed"):
            continue
        src = url_to_path.get(a.url) or url_to_path.get(canon.get(canonical_url(a.url), ""))
        if src is None and a.content_length in by_len and by_len[a.content_length]:
            src = by_len[a.content_length][0]
        if src is None or not src.exists():
            continue
        data = src.read_bytes()
        a.size = len(data)
        a.sha256 = sha256_hex(data)
        dest = cfg.raw_js_dir / f"{a.asset_id}.js"
        dest.write_bytes(data)
        a.local_path = str(dest.relative_to(cfg.workspace))
        a.analysis_status = "acquired"
        a.source = "recon2win-raw"
        used += 1
    return used


def local_bytes(asset: JSAsset, cfg: Config) -> bytes | None:
    if not asset.local_path:
        return None
    p = cfg.workspace / asset.local_path
    if p.exists():
        return p.read_bytes()
    return None
