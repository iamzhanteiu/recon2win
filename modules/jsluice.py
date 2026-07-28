"""jsluice — stage 6.3: AST-based JavaScript analysis (endpoints + secrets).

Unlike xnLinkFinder (stage 6.2, regex-based), jsluice parses each JS file
into a tree-sitter AST, so it resolves URLs that are *built* dynamically
(``BASE + "/api/" + id``, template literals) and extracts secrets with
context. This catches endpoints regex misses and surfaces API keys/tokens.

jsluice does **not** fetch JS itself — it reads local source files. So we:

  1. Download every URL in ``js_urls.txt`` into ``raw/jsluice/NNNN.js``
     (concurrent, size-capped, dependency-free via urllib).
  2. Run ``jsluice urls  <files...>``  → JSONL of discovered URLs/params.
  3. Run ``jsluice secrets <files...>`` → JSONL of detected secrets.
  4. Resolve relative URLs against each file's *original* URL (jsluice
     reports the source ``filename``, which we map back to the URL), then
     scope-filter to the target domain to drop CDN/third-party noise.

Outputs (processed/, findings/):
  processed/jsluice_urls.txt        absolute in-scope URLs (fed to all_urls)
  processed/jsluice_endpoints.txt   paths (/api/..)         (fed to all_urls)
  processed/jsluice_params.json     [{url, method, queryParams, bodyParams}]
  findings/jsluice_secrets.json     {findings:[...], severity_count:{...}}

The urls/endpoints are merged back into ``all_urls.txt`` by stage 6.post
(``url_merge.append_urls``) exactly like xnLinkFinder's output, so they get
httpx-probed; any that carry query params flow on to arjun and the
parameterised shortlist. The two JS tools run in parallel and complement
each other (xnLinkFinder = broad/regex, jsluice = deep/AST).
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import runner
from .telegram import notify as _tg_notify
from .utils import (
    ensure_dir,
    load_json,
    make_result,
    read_lines,
    write_json,
    write_lines,
)


# A browser-ish UA — some CDNs 403 the default python-urllib agent.
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
# Cap per-file download so a single huge bundle can't blow memory/disk.
_MAX_JS_BYTES = 5 * 1024 * 1024  # 5 MB
# jsluice emits this placeholder where a dynamic expression sits
# (e.g. ``/users?id=`` + variable → ``/users?id=EXPR``). Neutralise it
# so downstream URLs stay clean while queryParams still records ``id``.
_EXPR = "EXPR"


# ----------------------------------------------------------------------
# Pure helpers (unit-tested)
# ----------------------------------------------------------------------
def _iter_jsonl(text: str):
    """Yield dict objects from jsluice's JSONL stdout, skipping junk."""
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def _in_scope(host: str, domain: str) -> bool:
    """True if *host* is the target domain or a subdomain of it."""
    if not domain:
        return True
    host = host.lower()
    return host == domain or host.endswith("." + domain)


def _resolve_urls(records, fname_to_url: dict, domain: str):
    """Resolve + classify jsluice ``urls`` records.

    Returns ``(urls, endpoints, params)``:
      * ``urls``      — sorted absolute, in-scope URLs
      * ``endpoints`` — sorted URL paths (``/api/..``)
      * ``params``    — [{url, method, queryParams, bodyParams}] for URLs
                        that carry query/body params (drives arjun/nuclei)

    Relative URLs are joined against their source JS file's original URL
    (jsluice reports the source ``filename``). Out-of-scope hosts are
    dropped so CDN/tracker links don't pollute ``all_urls.txt``.
    """
    urls: set[str] = set()
    endpoints: set[str] = set()
    params: list[dict] = []
    seen_param: set[str] = set()

    for rec in records:
        raw = (rec.get("url") or "").strip()
        if not raw or raw == _EXPR:
            continue
        raw = raw.replace("=" + _EXPR, "=")
        src = fname_to_url.get(rec.get("filename", ""), "")

        if raw.startswith(("http://", "https://")):
            absu = raw
        elif raw.startswith("//"):
            absu = "https:" + raw
        elif src:
            # relative (``/api/x`` or ``x/y``) → join against source URL
            absu = urljoin(src, raw)
        else:
            # relative but source unknown — keep the path as an endpoint
            if raw.startswith("/"):
                endpoints.add(raw)
            continue

        host = urlsplit(absu).netloc
        if not _in_scope(host, domain):
            continue

        urls.add(absu)
        path = urlsplit(absu).path
        if path and path != "/":
            endpoints.add(path)

        q = [p for p in (rec.get("queryParams") or []) if p]
        b = [p for p in (rec.get("bodyParams") or []) if p]
        if q or b:
            key = absu + "|" + (rec.get("method") or "")
            if key not in seen_param:
                seen_param.add(key)
                params.append({
                    "url": absu,
                    "method": rec.get("method") or "",
                    "queryParams": q,
                    "bodyParams": b,
                })

    return sorted(urls), sorted(endpoints), params


def _parse_secrets(records, fname_to_url: dict):
    """Parse jsluice ``secrets`` records → (findings, severity_count)."""
    out: list[dict] = []
    sev: dict[str, int] = {}
    for rec in records:
        severity = (rec.get("severity") or "info").lower()
        url = fname_to_url.get(rec.get("filename", ""), rec.get("filename", ""))
        out.append({
            "kind": rec.get("kind") or "unknown",
            "severity": severity,
            "url": url,
            "data": rec.get("data"),
            "context": rec.get("context"),
        })
        sev[severity] = sev.get(severity, 0) + 1
    return out, sev


# ----------------------------------------------------------------------
# JS fetch (concurrent, dependency-free)
# ----------------------------------------------------------------------
def _fetch_js(urls: list[str], dest_dir: Path, *, timeout: int,
              max_workers: int = 12) -> dict:
    """Download each URL into ``dest_dir/NNNN.js``.

    Returns ``{local_path: source_url}`` for the files that fetched OK.
    Failures (timeout, 404, TLS) are skipped silently — a JS file we
    can't fetch just contributes nothing, it doesn't fail the stage.
    """
    ensure_dir(dest_dir)
    mapping: dict[str, str] = {}

    def _one(item):
        idx, url = item
        path = dest_dir / f"{idx:04d}.js"
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read(_MAX_JS_BYTES)
        except Exception:  # noqa: BLE001 — any fetch error → skip this file
            return None
        try:
            path.write_bytes(data)
        except OSError:
            return None
        return str(path), url

    with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for res in pool.map(_one, enumerate(urls)):
            if res:
                mapping[res[0]] = res[1]
    return mapping


# ----------------------------------------------------------------------
# Stage entry point
# ----------------------------------------------------------------------
def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "jsluice_urls.txt"
    return p.exists() and p.stat().st_size > 0


def scan(
    js_urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "jsluice"
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    url_out = proc / "jsluice_urls.txt"
    ep_out = proc / "jsluice_endpoints.txt"
    params_out = proc / "jsluice_params.json"
    secrets_out = output_dir / "findings" / "jsluice_secrets.json"

    def _empty(status: str, error: str | None = None) -> dict:
        url_out.write_text("")
        ep_out.write_text("")
        write_json(params_out, [])
        write_json(secrets_out, {"findings": [], "severity_count": {}})
        return make_result(
            stage, status, input_path=js_urls_file,
            outputs=[url_out, ep_out, params_out, secrets_out],
            count=0, error=error,
        )

    j_cfg = cfg.get("jsluice", {}) if isinstance(cfg, dict) else {}

    if skip:
        return _empty("skipped", "--skip-jsluice")
    if not j_cfg.get("enabled", True):
        return _empty("skipped", "disabled in config")
    if resume and _outputs_exist(output_dir):
        return make_result(
            stage, "success", input_path=js_urls_file,
            outputs=[url_out, ep_out, params_out, secrets_out],
            count=len(read_lines(url_out)) + len(read_lines(ep_out)),
        )
    if dry_run:
        return make_result(
            stage, "skipped", input_path=js_urls_file,
            outputs=[url_out, ep_out, params_out, secrets_out],
            count=0, error="dry-run",
            extra={"planned_cmd": ["jsluice", "urls", "<fetched js files>"]},
        )
    if not runner.tool_available("jsluice"):
        return _empty("skipped", "jsluice binary not found (optional, skipped)")

    js_lines = read_lines(js_urls_file)
    if not js_lines:
        return _empty("skipped", "no JS URLs to analyse")

    timeout = int(j_cfg.get("timeout", 1200))
    fetch_timeout = int(j_cfg.get("fetch_timeout", 10))
    max_js = int(j_cfg.get("max_js", 500))
    modes = j_cfg.get("mode") or ["urls", "secrets"]
    domain = output_dir.name  # outputs/<domain> → the scan target

    if max_js and len(js_lines) > max_js:
        js_lines = js_lines[:max_js]

    raw_js_dir = output_dir / "raw" / "jsluice"
    fname_to_url = _fetch_js(js_lines, raw_js_dir, timeout=fetch_timeout)
    files = list(fname_to_url.keys())
    if not files:
        return _empty("failed", "could not fetch any JS file")

    urls: list[str] = []
    endpoints: list[str] = []
    params: list[dict] = []
    secrets: list[dict] = []
    sev: dict[str, int] = {}

    if "urls" in modes:
        r = runner.run(
            ["jsluice", "urls", *files],
            stage=stage, log_name=stage, output_dir=output_dir, timeout=timeout,
        )
        if r["success"]:
            urls, endpoints, params = _resolve_urls(
                _iter_jsonl(r["stdout"]), fname_to_url, domain,
            )
        elif not r["missing_binary"]:
            print(f"[{stage}] urls mode failed: {(r['stderr'] or '')[:200]}")

    if "secrets" in modes:
        r = runner.run(
            ["jsluice", "secrets", *files],
            stage=stage, log_name=stage, output_dir=output_dir, timeout=timeout,
        )
        if r["success"]:
            secrets, sev = _parse_secrets(_iter_jsonl(r["stdout"]), fname_to_url)
        elif not r["missing_binary"]:
            print(f"[{stage}] secrets mode failed: {(r['stderr'] or '')[:200]}")

    n_url = write_lines(url_out, urls)
    n_ep = write_lines(ep_out, endpoints)
    write_json(params_out, params)
    write_json(secrets_out, {"findings": secrets, "severity_count": sev})

    # Telegram — one alert if any secrets were found (opt-in via telegram.enabled).
    tg = cfg.get("telegram") or {}
    if secrets and tg.get("enabled"):
        kinds = ", ".join(sorted({s["kind"] for s in secrets})[:8])
        _tg_notify(
            f"🔑 *jsluice* found `{len(secrets)}` secret(s) in JS on "
            f"`{domain}` — {kinds}",
            tg,
        )

    return make_result(
        stage, "success", input_path=js_urls_file,
        outputs=[url_out, ep_out, params_out, secrets_out],
        count=n_url + n_ep,
        extra={
            "urls": n_url,
            "endpoints": n_ep,
            "params": len(params),
            "secrets": len(secrets),
            "secrets_by_severity": sev,
            "js_fetched": len(files),
            "js_total": len(read_lines(js_urls_file)),
        },
    )


# ----------------------------------------------------------------------
# Feed jsluice's param intel into the parameterised shortlist
# ----------------------------------------------------------------------
def build_param_urls(params: list[dict]) -> list[str]:
    """Turn jsluice ``params`` records into fuzzable URLs for nuclei.

    Each record is ``{url, method, queryParams, bodyParams}``. We attach
    **all** discovered params — query *and* body — to the URL as a query
    string (``base?p1=&p2=``), because:

      * arjun only fuzzes what looks dynamic in the URL (``?x=``) and is
        GET-only + capped at ``max_urls`` — so POST/JSON endpoints and
        anything past the cap never reach the shortlist.
      * jsluice extracted the real param names from the AST, so the
        shortlist carries precise targets instead of guesses.

    Existing query strings on the URL are rebuilt from ``queryParams`` so
    the output is deduped and free of jsluice's ``EXPR`` placeholders.
    Records with no params are skipped (nothing to fuzz). Order-preserving
    dedupe.
    """
    out: list[str] = []
    seen: set[str] = set()
    for rec in params or []:
        if not isinstance(rec, dict):
            continue
        url = (rec.get("url") or "").strip()
        if not url:
            continue
        base = url.split("?", 1)[0]
        names: list[str] = []
        for n in (rec.get("queryParams") or []) + (rec.get("bodyParams") or []):
            n = str(n).strip()
            if n and n not in names:
                names.append(n)
        if not names:
            continue
        built = base + "?" + "&".join(f"{n}=" for n in names)
        if built not in seen:
            seen.add(built)
            out.append(built)
    return out


def merge_params_into_nuclei_input(output_dir: Path) -> dict:
    """Append jsluice's param-rich URLs to ``parameterized_urls.txt``.

    Runs right after arjun (stage 8). Reads
    ``processed/jsluice_params.json``, builds fuzzable URLs via
    :func:`build_param_urls`, and merges them (deduped) into
    ``processed/parameterized_urls.txt`` — the hand-testing shortlist that
    also feeds the report and priority_targets.txt.

    This is additive and safe when arjun was skipped/failed: the target
    file is created if missing, so jsluice params alone can populate the
    shortlist. No-op (count 0) when jsluice found no params.
    """
    proc = output_dir / "processed"
    params_json = proc / "jsluice_params.json"
    target = proc / "parameterized_urls.txt"

    data = load_json(params_json)
    built = build_param_urls(data if isinstance(data, list) else [])

    existing = read_lines(target)
    existing_set = set(existing)
    added = [u for u in built if u not in existing_set]
    if added:
        write_lines(target, existing + added)

    return make_result(
        "jsluice_params_merge", "success", input_path=params_json,
        outputs=[target], count=len(added),
        extra={"jsluice_param_urls": len(built),
               "added": len(added),
               "total": len(existing) + len(added)},
    )
