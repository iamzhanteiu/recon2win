# ingest/ — recon2win ingestion

> The runnable ingestion code lives in the package at
> `jsvh/ingest/` (`loader.py`, `adapter.py`, `validator.py`,
> `normalizer.py`). This directory documents that layer; it is the
> conceptual `ingest/recon2win/` from the mission spec.

```
recon2win output
      ↓  loader      locate + read raw artifacts (the only layout-aware module)
      ↓  validator   assert the input contract; report gaps verbatim
      ↓  adapter     map recon2win rows → internal JSAsset schema
      ↓  normalizer  canonical-URL dedupe + provenance union + stable ids
internal schema → analysis pipeline
```

## Responsibilities

| Module | Responsibility |
|---|---|
| `jsvh/ingest/loader.py` | Knows every recon2win path (v3 grouped + flat fallback). Reads `js_urls`, `jsluice_js_detail`, `jsluice_{endpoints,urls,params}`, `xnlinkfinder_*`, `all_urls.jsonl` provenance, `alive_detail`, `alive_urls_detail`, `jsluice_secrets`, `priority_targets`, `MANIFEST`. |
| `jsvh/ingest/validator.py` | Requires `jsluice_js_detail.json` **or** `js_urls.txt`; everything else degrades. Emits `Missing upstream data: …` and blocks when the JS surface is absent. |
| `jsvh/ingest/adapter.py` | Seeds assets from the authoritative fetched-detail rows, tops up with discovered-but-unfetched JS URLs. |
| `jsvh/ingest/normalizer.py` | Canonical-URL dedupe (drop fragment, default ports), union provenance, assign stable `js_000001` ids in sort order. |

## Internal normalized record

See `docs/data-model.md` and `schemas/asset.json`. Example:

```json
{
  "asset_id": "js_000123",
  "target": "omnicell.com",
  "host": "ebc.omnicell.com",
  "url": "https://ebc.omnicell.com/Static/dist/global.js",
  "type": "javascript",
  "source": "recon2win",
  "status_code": 200,
  "content_type": "text/javascript"
}
```

## Rule

recon2win owns recon metadata; this layer only **references** it
(asset_id, source, url, hash, analysis_status). It never re-discovers JS.
