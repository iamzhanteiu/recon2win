# recon2win Integration Contract

This document records the **detected** input contract between recon2win
(the upstream reconnaissance engine) and this JavaScript Vulnerability
Research Workspace. It was derived by reading real recon2win output on
disk (`outputs/omnicell.com/`, `outputs/lacity.gov/`, …), not from
assumptions.

> recon2win owns **recon metadata**. This workspace owns **analysis
> metadata**. We never regenerate recon data (mission §3/§17).

## 1. Where recon2win writes

Per target, recon2win creates `outputs/<domain>/` (or, with `-p`,
`outputs/<project>/<domain>/`). This workspace resolves both shapes
(`jsvh/config.py::resolve_target_dir`). The v3 grouped layout is preferred;
a pre-v3 flat layout is accepted as a fallback (`jsvh/ingest/loader.py`).

## 2. Files this workspace consumes

| Purpose | Path (relative to target dir) | Shape |
|---|---|---|
| **JS URLs discovered** | `processed/corpus/js_urls.txt` | newline URLs |
| **JS fetch detail (authoritative)** | `processed/js/jsluice_js_detail.json` | `[{url,status_code,content_type,content_length}]` |
| **JS bodies already downloaded** | `raw/jsluice/NNNN.js` | raw bytes, one file per fetched JS |
| **Endpoints mined from JS (jsluice AST)** | `processed/js/jsluice_endpoints.txt` | newline endpoints |
| **URLs mined from JS** | `processed/js/jsluice_urls.txt` | newline URLs |
| **Params mined from JS** | `processed/js/jsluice_params.json` | `[{url,method,queryParams,bodyParams}]` |
| **Endpoints mined (xnLinkFinder regex)** | `processed/js/xnlinkfinder_endpoints.txt` | newline |
| **URL provenance** | `processed/corpus/all_urls.jsonl` | `{url, sources:[tool,…]}` per line |
| **Host HTTP metadata** | `processed/hosts/alive_detail.json` | httpx rows incl `tech[]`, `webserver`, `title`, `status_code` |
| **Per-URL HTTP metadata** | `processed/hosts/alive_urls_detail.json` | httpx rows per URL |
| **Secrets found in JS** | `findings/jsluice_secrets.json` | `{findings:[…], severity_count:{}}` |
| **Ranked hand-testing shortlist** | `report/priority_targets.txt` | `[score] url — reasons` |
| **Artefact completeness** | `processed/MANIFEST.json` | per-artefact state (ok/ran_empty/blocked/…) |

Only `jsluice_js_detail.json` **or** `js_urls.txt` is strictly required;
everything else degrades gracefully (`jsvh/ingest/validator.py`).

## 3. Authoritative JS inventory input

`processed/js/jsluice_js_detail.json` is the richest input — one row per
JS URL recon2win actually fetched, already HTTP-verified:

```json
{
  "url": "https://ebc.omnicell.com/Static/dist/carousels.js",
  "status_code": 200,
  "content_type": "text/javascript",
  "content_length": 8807
}
```

We seed the inventory from it and top up with any `js_urls.txt` entry not
present (discovered-but-not-fetched), so nothing is dropped
(`jsvh/ingest/adapter.py`).

## 4. Reusing recon2win's downloaded JS (zero duplication)

recon2win already downloads each successfully-fetched JS body to
`raw/jsluice/NNNN.js`. **The `NNNN` index is the position of the fetched
(2xx/3xx-with-body) rows of `jsluice_js_detail.json`, in order.** Verified
empirically: `raw/jsluice/0000.js` size == first ok row's `content_length`
== `carousels.js`, and so on.

The workspace reconstructs that URL→file map (validated by
`content_length`) and **reuses those bytes** rather than re-downloading —
this is the zero-duplication path of mission §5
(`jsvh/acquire.py::from_recon_raw`). Network fetch is opt-in (`--net`) and
used only for the discovered-but-not-cached long tail, because production
targets (Akamai/Cloudflare/etc.) often 403 an unbranded client while
recon2win's cached copy is already on disk.

## 5. Provenance / quality signal

`processed/corpus/all_urls.jsonl` carries `{"url":…, "sources":[tool,…]}`.
recon2win's own docs note that source quality varies wildly (jsluice-mined
URLs are far more likely to be live than raw ffuf wildcard hits). We union
provenance onto each asset so ranking can weight it later.

## 6. What we deliberately do NOT read / regenerate

Out of scope — consumed as-is or ignored, never re-run:
subdomain/DNS/port/crawl/httpx/nuclei/dirsearch/ffuf/waymore. If any of the
required JS inputs is missing, the workspace reports it verbatim
(`Missing upstream data: …`) and stops — it never substitutes a second
recon pipeline (mission §17).

## 7. Internal normalized schema (what we emit)

Each recon2win JS reference becomes a `JSAsset` (`jsvh/models.py`) with a
strict split:

```json
{
  "asset_id": "js_000123",
  "target": "omnicell.com",
  "host": "ebc.omnicell.com",
  "url": "https://ebc.omnicell.com/Static/dist/global.js",
  "source": "recon2win-raw",
  "provenance": ["crawler", "jsluice"],
  "status_code": 200,
  "content_type": "text/javascript",
  "content_length": 61421,

  "sha256": "…",              // analysis metadata below this line
  "framework": "jQuery",
  "bundler": "Webpack",
  "source_map": false,
  "analysis_status": "analyzed"
}
```

Fields above the blank line mirror recon2win; fields below are owned by
this workspace. See `docs/data-model.md`.
