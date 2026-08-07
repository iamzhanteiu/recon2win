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
  5. Recurse: any *discovered* URL that itself looks like a JS file
     (webpack chunks, lazy-loaded bundles — common on SPAs where the
     entrypoint only references a handful of chunk names statically)
     gets fetched into ``raw/jsluice/rN/`` and fed back through steps
     2-4. By default the walk runs **to exhaustion** — it keeps going
     until no unseen JS URL is left — which is how we reach endpoints and
     params that only exist inside chunks the initial crawl never listed.

     Unfetched JS lives in a persistent queue, not a per-round frontier,
     so a URL trimmed by a budget in one round is picked up in the next
     instead of being lost. Cycles (``a.js`` ↔ ``b.js``) terminate because
     every *attempted* fetch — success or failure — is recorded.

     Three independent bounds keep an unbounded walk honest:
     ``max_js_recurse`` (files, 0 = unlimited), ``recurse_time_budget``
     (wall clock) and ``js_recurse_depth`` (rounds, -1 = unlimited). When
     any of them cuts the walk short the stage reports
     ``js_recurse_exhausted: false`` plus ``js_pending_unfetched``, so a
     truncated walk is never mistaken for "no more JS found".

Outputs (processed/, findings/):
  processed/jsluice_urls.txt        absolute in-scope URLs (fed to all_urls)
  processed/jsluice_endpoints.txt   paths (/api/..)         (fed to all_urls)
  processed/jsluice_params.json     [{url, method, queryParams, bodyParams}]
  processed/jsluice_js_detail.json  [{url, status_code, content_type, content_length}]
                                     one row per JS file jsluice *attempted*
                                     to fetch (initial + every recursion
                                     round), including 4xx/5xx — so a
                                     404'd chunk is visible, not silently
                                     dropped.
  processed/jsluice_js_table.txt    same data as a greppable
                                     "status | length | content-type | url"
                                     table (companion to httpx's *_table.txt)
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
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import layout, runner
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

# Hard stop for unbounded (``js_recurse_depth < 0``) recursion. Each round
# costs a jsluice subprocess, so a graph that yields exactly one new chunk
# per round must not spin forever. ``max_js_recurse`` is the real budget;
# this only catches that degenerate shape.
_MAX_RECURSE_ROUNDS = 50


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


def _is_js_url(url: str) -> bool:
    """True if *url*'s path looks like a JS file (``.js`` / ``.mjs``)."""
    return urlsplit(url).path.lower().endswith((".js", ".mjs"))


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
              max_workers: int = 12) -> tuple[dict, list[dict]]:
    """Download each URL into ``dest_dir/NNNN.js``.

    Returns ``(mapping, detail)``:

      * ``mapping`` — ``{local_path: source_url}`` for files that fetched
        a usable JS body (2xx/3xx with content). This is what jsluice
        actually analyses, same as before.
      * ``detail``  — one ``{url, status_code, content_type,
        content_length}`` row per URL we got *any* HTTP response for,
        including 4xx/5xx — so a report can show the full status/
        length/content-type picture of every JS reference, not just the
        ones that happened to succeed. Keys match ``alive_detail.json``
        so the report's existing httpx-table helpers work unmodified.

    Connection-level failures (timeout, DNS, TLS) produce neither a
    mapping entry nor a detail row — there's no HTTP status to report,
    and a JS file we can't fetch just contributes nothing to analysis.
    """
    ensure_dir(dest_dir)
    mapping: dict[str, str] = {}
    detail: list[dict] = []

    def _one(item):
        idx, url = item
        path = dest_dir / f"{idx:04d}.js"
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read(_MAX_JS_BYTES)
                status = resp.status
                ctype = resp.headers.get("Content-Type", "") or ""
        except urllib.error.HTTPError as e:
            # Got a response, just not a happy one (404/403/500...) — still
            # worth reporting the status rather than silently dropping it.
            status = e.code
            ctype = (e.headers.get("Content-Type", "") if e.headers else "") or ""
            data = b""
        except Exception:  # noqa: BLE001 — DNS/timeout/TLS: no status to give
            return None

        row = {
            "url": url,
            "status_code": status,
            "content_type": ctype.split(";")[0].strip() or "-",
            "content_length": len(data),
        }
        if 200 <= status < 400 and data:
            try:
                path.write_bytes(data)
            except OSError:
                return row
            return row, str(path)
        return row

    with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for res in pool.map(_one, enumerate(urls)):
            if res is None:
                continue
            if isinstance(res, tuple):
                row, path = res
                detail.append(row)
                mapping[path] = row["url"]
            else:
                detail.append(res)
    return mapping, detail


def _write_js_table(detail: list[dict], table_path: Path) -> int:
    """Write a human-readable ``status | length | content-type | url`` table
    for every JS file jsluice attempted to fetch (initial + recursive
    rounds) — the same eyeball format as ``httpx``'s ``*_table.txt``, so a
    404'd chunk or a WAF-blocked bundle is visible instead of just vanishing.
    """
    entries = sorted(
        ((r.get("status_code") or 0, r.get("content_length") or 0,
          r.get("content_type") or "-", r.get("url") or "")
         for r in detail if r.get("url")),
        key=lambda e: (e[0], -e[1]),
    )
    lines = [f"{'ST':>3}  {'LENGTH':>9}  {'CONTENT-TYPE':<24}  URL"]
    lines += [f"{st:>3}  {ln:>9}  {ct[:24]:<24}  {url}"
              for st, ln, ct, url in entries]
    table_path.parent.mkdir(parents=True, exist_ok=True)
    table_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(entries)


def _analyze(
    files: list[str], modes: list[str], fname_to_url: dict, domain: str,
    *, stage: str, output_dir: Path, timeout: int,
):
    """Run ``jsluice urls``/``secrets`` over *files* and parse the output.

    Shared by the initial pass and every recursion round in :func:`scan`.
    """
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

    return urls, endpoints, params, secrets, sev


# ----------------------------------------------------------------------
# Stage entry point
# ----------------------------------------------------------------------
def _outputs_exist(out_dir: Path) -> bool:
    p = layout.path(out_dir, "jsluice_urls.txt")
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
    layout.ensure_tree(output_dir)
    url_out = layout.path(output_dir, "jsluice_urls.txt")
    ep_out = layout.path(output_dir, "jsluice_endpoints.txt")
    params_out = layout.path(output_dir, "jsluice_params.json")
    secrets_out = output_dir / "findings" / "jsluice_secrets.json"
    js_detail_out = layout.path(output_dir, "jsluice_js_detail.json")
    js_table_out = layout.path(output_dir, "jsluice_js_table.txt")

    def _empty(status: str, error: str | None = None,
               detail: list[dict] | None = None) -> dict:
        url_out.write_text("")
        ep_out.write_text("")
        write_json(params_out, [])
        write_json(secrets_out, {"findings": [], "severity_count": {}})
        write_json(js_detail_out, detail or [], compact=True)
        _write_js_table(detail or [], js_table_out)
        return make_result(
            stage, status, input_path=js_urls_file,
            outputs=[url_out, ep_out, params_out, secrets_out,
                     js_detail_out, js_table_out],
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
            outputs=[url_out, ep_out, params_out, secrets_out,
                     js_detail_out, js_table_out],
            count=len(read_lines(url_out)) + len(read_lines(ep_out)),
        )
    if dry_run:
        return make_result(
            stage, "skipped", input_path=js_urls_file,
            outputs=[url_out, ep_out, params_out, secrets_out,
                     js_detail_out, js_table_out],
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
    fname_to_url, detail = _fetch_js(js_lines, raw_js_dir, timeout=fetch_timeout)
    files = list(fname_to_url.keys())
    all_detail = list(detail)
    if not files:
        return _empty("failed", "could not fetch any JS file", detail=all_detail)

    urls, endpoints, params, secrets, sev = _analyze(
        files, modes, fname_to_url, domain,
        stage=stage, output_dir=output_dir, timeout=timeout,
    )

    # Recurse into discovered URLs that are themselves JS (webpack chunks,
    # lazy-loaded bundles) — the initial JS crawl often only lists the
    # entrypoint, so the bulk of a SPA's endpoints/params live one hop
    # deeper. Each round fetches only *new* JS URLs, re-runs jsluice on
    # just those files, and merges the result in; stops when there's
    # nothing new, the depth budget is spent, or the recursion budget is used.
    #
    # Recursion gets its OWN budget rather than sharing max_js. Sharing made
    # the whole feature a no-op on exactly the targets that need it: round 0
    # takes js_lines[:max_js], so on any target with >= max_js JS URLs the
    # remaining budget was 0 and the loop broke before fetching anything.
    # Measured against the stored runs — 3,956 / 815 / 4,961 JS URLs against
    # a 500 cap — that is every real target.
    # ``js_recurse_depth``: 0 disables recursion, a negative value runs to
    # exhaustion (keep going until no unseen JS URL is left), N caps at N
    # rounds. Exhaustion is the useful default — a webpack graph is however
    # deep it is, and guessing a depth either stops early or costs nothing.
    js_recurse_depth = int(j_cfg.get("js_recurse_depth", -1))
    max_js_recurse = int(j_cfg.get("max_js_recurse", 0))
    # Running to exhaustion needs a wall clock, not just a file count: the
    # stage ``timeout`` only bounds each individual jsluice subprocess, so
    # without this the loop could fetch for hours and the run would look
    # hung rather than budgeted.
    recurse_time_budget = int(j_cfg.get("recurse_time_budget", 900))
    recurse_started = time.monotonic()
    all_urls = set(urls)
    all_endpoints = set(endpoints)
    all_params = list(params)
    all_secrets = list(secrets)
    all_sev = dict(sev)
    # Every URL we've already attempted an HTTP fetch for (success OR
    # failure) — not just successes — so a 404'd chunk referenced twice
    # doesn't get fetched twice. Also what breaks A.js <-> B.js cycles.
    attempted_urls = {d["url"] for d in detail}

    # A persistent work queue, not a moving frontier. The previous version
    # set ``frontier = r_urls`` each round, so any JS URL the fetch budget
    # trimmed was dropped for good and the loop could never converge —
    # "until no JS is left" was unreachable by construction. Pending keeps
    # every unfetched JS URL until it is actually fetched or the budget ends.
    pending: set[str] = {u for u in urls if _is_js_url(u)} - attempted_urls
    n_rounds = 0
    recursed_attempted = 0
    unbounded = js_recurse_depth < 0

    while pending and (unbounded or n_rounds < js_recurse_depth):
        # Runaway guard for the unbounded case: a pathological graph that
        # yields one new chunk per round would otherwise spawn a jsluice
        # subprocess per round indefinitely. max_js_recurse is the real
        # bound; this only catches the degenerate shape.
        if unbounded and n_rounds >= _MAX_RECURSE_ROUNDS:
            break
        if (recurse_time_budget
                and time.monotonic() - recurse_started > recurse_time_budget):
            break
        budget = (max_js_recurse - recursed_attempted) if max_js_recurse else None
        if budget is not None and budget <= 0:
            break

        batch = sorted(pending)
        if budget is not None:
            batch = batch[:budget]
        pending -= set(batch)
        recursed_attempted += len(batch)

        n_rounds += 1
        new_map, new_detail = _fetch_js(
            batch, raw_js_dir / f"r{n_rounds}", timeout=fetch_timeout,
        )
        all_detail.extend(new_detail)
        attempted_urls.update(d["url"] for d in new_detail)
        # A round where every fetch failed is not a reason to stop: other
        # JS URLs may still be queued behind it.
        if not new_map:
            continue
        fname_to_url.update(new_map)

        r_urls, r_eps, r_params, r_secrets, r_sev = _analyze(
            list(new_map.keys()), modes, fname_to_url, domain,
            stage=stage, output_dir=output_dir, timeout=timeout,
        )
        all_urls.update(r_urls)
        all_endpoints.update(r_eps)
        all_params.extend(r_params)
        all_secrets.extend(r_secrets)
        for k, v in r_sev.items():
            all_sev[k] = all_sev.get(k, 0) + v
        pending |= {u for u in r_urls if _is_js_url(u)} - attempted_urls

    seen_param: set[str] = set()
    params = []
    for p in all_params:
        key = p["url"] + "|" + p.get("method", "")
        if key not in seen_param:
            seen_param.add(key)
            params.append(p)

    urls = sorted(all_urls)
    endpoints = sorted(all_endpoints)
    secrets = all_secrets
    sev = all_sev

    n_url = write_lines(url_out, urls)
    n_ep = write_lines(ep_out, endpoints)
    write_json(params_out, params)
    write_json(secrets_out, {"findings": secrets, "severity_count": sev})
    write_json(js_detail_out, all_detail, compact=True)
    _write_js_table(all_detail, js_table_out)

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
        outputs=[url_out, ep_out, params_out, secrets_out,
                 js_detail_out, js_table_out],
        count=n_url + n_ep,
        extra={
            "urls": n_url,
            "endpoints": n_ep,
            "params": len(params),
            "secrets": len(secrets),
            "secrets_by_severity": sev,
            "js_fetched": len(fname_to_url),
            "js_attempted": len(attempted_urls),
            "js_total": len(read_lines(js_urls_file)),
            "js_recursed_rounds": n_rounds,
            "js_recursed_fetched": len(fname_to_url) - len(files),
            # Did the walk actually converge, or did a budget cut it short?
            # Without this, "no more JS found" and "ran out of budget" look
            # identical in the report — the same clean-vs-broken trap the
            # rest of the pipeline already got wrong once.
            "js_recurse_exhausted": not pending,
            "js_pending_unfetched": len(pending),
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
    params_json = layout.path(output_dir, "jsluice_params.json")
    target = layout.path(output_dir, "parameterized_urls.txt")

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
