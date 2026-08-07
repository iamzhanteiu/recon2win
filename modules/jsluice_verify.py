"""jsluice_verify — probe the URLs jsluice mined out of JavaScript.

The gap this closes
===================

``httpx_urls`` (stage 6) probes ``all_urls.txt`` and writes
``alive_urls.txt`` + ``alive_urls_detail.json``. ``jsluice`` (stage 7) runs
*after* it, and its output is appended to ``all_urls.txt`` by
``url_merge_append`` — after the probe has already been and gone.

Net effect, measured on ``outputs/acronis.com``::

    jsluice_urls.txt   6,306 URLs
      already probed      41
      never probed     6,265   ← extracted, merged, never verified

Those 6,265 URLs reached the report as bare strings: no status code, no
length, no content type. An endpoint mined from a JS bundle is only
interesting once you know whether it answers — ``/api/v1/admin/config``
returning 200 with ``application/json`` is a lead, the same path returning
404 is noise, and nothing downstream could tell the two apart.

This stage probes them and produces the same
``status | length | content-type | url`` view every other probed surface
gets, then merges the verified rows back into ``alive_urls*`` so the
report, the priority ranking and the ASM report all see them.

Endpoints vs URLs
-----------------

``jsluice_endpoints.txt`` holds *paths* (``/api/v1/users``), not URLs, so
it looks like it needs expanding against a host list. It does not: every
path in it is the path component of a URL already in ``jsluice_urls.txt``
(``_resolve_urls`` adds both from the same record). Verified on real
output — 3,154 endpoints, 3,154 covered, 0 orphans. Probing
``jsluice_urls.txt`` therefore covers the endpoint list too, and avoids a
``paths x hosts`` cartesian product that would have been 170k requests.

Outputs
-------

``processed/jsluice_alive.txt``          verified-live URLs
``processed/jsluice_alive_detail.json``  full httpx records
``processed/jsluice_alive_table.txt``    ST | LENGTH | CONTENT-TYPE | URL

A second stage in this module, ``verify_methods``, closes a related gap:
the GET probe above is blind to the fact that a POST-only login endpoint or
a DELETE-only admin route was never going to answer GET in the first place.
``jsluice_params.json`` already recorded the method the source code itself
used (``fetch(url, {method: "PUT"})`` → parsed via AST, not guessed), so
re-probing with THAT method — plus a short body preview — tells you whether
the endpoint is actually alive instead of reading as a false 404/405.

``processed/jsluice_method_check.json``       [{url, method, status,
                                                content_length, content_type,
                                                body_preview, get_status,
                                                get_content_length}]
``processed/jsluice_method_check_table.txt``  METHOD | ST | LENGTH |
                                                CONTENT-TYPE | GET-ST | URL
"""
from __future__ import annotations

from pathlib import Path

from . import console, layout, runner
from .httpx import _parse_httpx_jsonl, _write_alive_table
from .utils import load_json, make_result, read_lines, write_json, write_lines

# Probing every JS-mined URL on a large target can rival the main URL
# probe. Capped independently of httpx.max_url_check so tuning one does
# not silently blow up the other.
_DEFAULT_MAX_VERIFY = 20000

# Method-check is a second, smaller pass (one request-list per distinct
# method), so its own cap is far lower than the GET pass above.
_DEFAULT_METHOD_CHECK_MAX = 300


def _clean(text: str, limit: int) -> str:
    """Collapse whitespace so a body preview fits one table cell / JSON
    value, and neutralise chars that would break a Markdown table."""
    if not text:
        return ""
    flat = " ".join(text.split())
    flat = flat.replace("|", "¦").replace("`", "'")
    return flat[:limit]


def _detail_index(detail_json: Path) -> dict[str, dict]:
    """``{url: httpx_row}`` from an existing detail file, if any."""
    rows = load_json(detail_json) or []
    if not isinstance(rows, list):
        return {}
    return {r.get("url"): r for r in rows if isinstance(r, dict) and r.get("url")}


def _merge_into_alive(output_dir: Path, new_rows: list[dict]) -> int:
    """Fold verified rows into ``alive_urls*`` so downstream stages see them.

    Without this the verification is a dead-end artefact: the report, the
    priority ranking and the ASM report all read ``alive_urls*``.
    """
    alive_txt = layout.path(output_dir, "alive_urls.txt")
    detail_json = layout.path(output_dir, "alive_urls_detail.json")

    existing = load_json(detail_json) or []
    if not isinstance(existing, list):
        existing = []
    seen = {r.get("url") for r in existing if isinstance(r, dict)}

    added = [r for r in new_rows if r.get("url") and r["url"] not in seen]
    if not added:
        return 0

    merged = existing + added
    write_json(detail_json, merged, compact=True)
    write_lines(alive_txt, [r["url"] for r in merged if r.get("url")])
    _write_alive_table(merged, layout.path(output_dir, "alive_urls_table.txt"))
    return len(added)


def verify(
    js_urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    """Probe ``jsluice_urls.txt`` and record status / length / content-type.

    Signature follows the ``(input_path, output_dir, cfg, ...)`` convention
    every other stage uses, so ``_run_stage`` can pick up output_dir and cfg
    positionally.
    """
    stage = "jsluice_verify"
    src = Path(js_urls_file)
    alive_txt = layout.path(output_dir, "jsluice_alive.txt")
    detail_json = layout.path(output_dir, "jsluice_alive_detail.json")
    table_txt = layout.path(output_dir, "jsluice_alive_table.txt")
    outputs = [alive_txt, detail_json, table_txt]

    if not src.exists() or src.stat().st_size == 0:
        return make_result(
            stage, "skipped", input_path=src, outputs=outputs, count=0,
            error="no jsluice_urls.txt (jsluice found nothing or was skipped)",
        )

    if resume and alive_txt.exists() and alive_txt.stat().st_size > 0:
        return make_result(
            stage, "success", input_path=src, outputs=outputs,
            count=len(read_lines(alive_txt)), extra={"resumed": True},
        )

    if dry_run:
        return make_result(stage, "skipped", input_path=src, outputs=outputs,
                           count=0, error="dry-run")

    if not runner.tool_available("httpx"):
        return make_result(stage, "skipped", input_path=src, outputs=outputs,
                           count=0, error="httpx binary not found")

    jcfg = (cfg.get("jsluice") or {}).get("verify") or {}
    hcfg = cfg.get("httpx") or {}
    threads = int(jcfg.get("threads", hcfg.get("threads", 50)))
    timeout = int(jcfg.get("timeout", hcfg.get("timeout", 600)))
    max_verify = int(jcfg.get("max_urls", _DEFAULT_MAX_VERIFY))
    body_preview_bytes = int(jcfg.get("body_preview_bytes", 200))

    candidates = [u for u in read_lines(src) if u.startswith(("http://", "https://"))]
    total = len(candidates)

    # Anything the main URL probe already covered is reused rather than
    # re-requested — same data, no extra traffic against the target.
    known = _detail_index(layout.path(output_dir, "alive_urls_detail.json"))
    reused = [known[u] for u in candidates if u in known]
    todo = [u for u in candidates if u not in known]

    capped = False
    if len(todo) > max_verify:
        todo = todo[:max_verify]
        capped = True

    print(console.phase_info_line(
        f"[{stage}] {total} JS-mined URL(s): {len(reused)} already probed, "
        f"{len(todo)} to verify" + (f" (capped at {max_verify})" if capped else "")))

    fresh: list[dict] = []
    timed_out = False
    if todo:
        scan_file = output_dir / "raw" / "jsluice" / "verify_input.txt"
        scan_file.parent.mkdir(parents=True, exist_ok=True)
        write_lines(scan_file, todo)
        raw_out = scan_file.with_name("verify_httpx.jsonl")

        cmd = [
            "httpx", "-l", str(scan_file),
            "-json", "-silent",
            "-threads", str(threads),
            "-timeout", "10",
            "-retries", "2",
            # body-preview only: httpx returns the first ~N chars of the
            # body (field ``body_preview``), never the full response — a
            # bare status/length can't tell a real login form from a
            # generic soft-404 template answering the same 200.
            "-bp", str(max(1, body_preview_bytes)),
            "-o", str(raw_out),
        ]
        r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)
        timed_out = r.get("timed_out", False)
        if not r["success"] and not r["missing_binary"] and not timed_out:
            return make_result(
                stage, "failed", input_path=src, outputs=outputs, count=0,
                error=(r["stderr"] or "")[:300],
            )
        # httpx streams to -o, so a timeout still leaves real verified rows.
        fresh = _parse_httpx_jsonl(raw_out)
        for row in fresh:
            row["body_preview"] = _clean(row.get("body_preview") or "",
                                         body_preview_bytes)

    rows: list[dict] = []
    seen: set[str] = set()
    for row in reused + fresh:
        u = row.get("url")
        if not u or u in seen:
            continue
        seen.add(u)
        rows.append(row)

    write_json(detail_json, rows, compact=True)
    write_lines(alive_txt, [r["url"] for r in rows if r.get("url")])
    _write_alive_table(rows, table_txt)
    merged = _merge_into_alive(output_dir, fresh)

    extra = {
        "input_urls": total,
        "reused_from_httpx_urls": len(reused),
        "newly_probed": len(todo),
        "alive": len(rows),
        "merged_into_alive_urls": merged,
        "capped": capped,
    }

    if timed_out:
        return make_result(
            stage, "failed", input_path=src, outputs=outputs, count=len(rows),
            error=(f"timeout after {timeout}s — salvaged {len(fresh)} verified "
                   f"row(s) from partial output"),
            extra=extra,
        )
    return make_result(stage, "success", input_path=src, outputs=outputs,
                       count=len(rows), extra=extra)


def _load_method_candidates(params_json: Path) -> dict[str, str]:
    """``{url: METHOD}`` for every jsluice-observed endpoint whose method is
    not GET/empty — the one signal in the whole run that says which verb an
    endpoint actually expects, taken straight from the ``fetch()`` /
    ``axios()`` call jsluice's AST parsed it out of, not guessed.
    """
    rows = load_json(params_json) or []
    if not isinstance(rows, list):
        return {}
    out: dict[str, str] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or "").strip()
        method = str(r.get("method") or "").strip().upper()
        if (url and method and method != "GET"
                and url.startswith(("http://", "https://"))):
            out[url] = method
    return out


def _is_method_bypass(row: dict) -> bool:
    """True when the real method got further than the blind GET did — the
    row worth surfacing first."""
    st = row.get("status")
    get_st = row.get("get_status")
    return (isinstance(st, int) and 200 <= st < 400
            and (get_st is None or get_st in (401, 403, 404, 405)))


def _write_method_check_table(rows: list[dict], path: Path) -> None:
    lines = [f"{'METHOD':<7}{'ST':>4}  {'LENGTH':>9}  {'CONTENT-TYPE':<24}  "
             f"{'GET-ST':>6}  URL"]
    for r in rows:
        st = r.get("status")
        ln = r.get("content_length")
        ct = (r.get("content_type") or "-")[:24]
        get_st = r.get("get_status")
        lines.append(
            f"{r.get('method',''):<7}"
            f"{st if st is not None else '-':>4}  "
            f"{ln if ln is not None else '-':>9}  "
            f"{ct:<24}  "
            f"{get_st if get_st is not None else '-':>6}  "
            f"{r.get('url', '')}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_methods(
    params_json: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    """Re-probe JS-extracted endpoints with the HTTP method the JS itself
    used, not a blind GET.

    ``verify()`` above GETs everything in ``jsluice_urls.txt`` — exactly
    the wrong request for a POST-only login endpoint or a DELETE-only admin
    route, which answers 404/405 to a method it never expected and reads as
    dead when it is live. ``jsluice_params.json`` already recorded the verb
    the source code used; this stage spends that intel — grouping URLs by
    method and re-requesting each group with ``httpx -x <METHOD>`` — and
    records status, length, content-type AND a short body preview per
    request, plus the original GET status for comparison so a method that
    reveals more than GET did (``get_status`` 401/403/404/405 vs. a 2xx/3xx
    here) is easy to spot.
    """
    stage = "jsluice_method_check"
    src = Path(params_json)
    out_json = layout.path(output_dir, "jsluice_method_check.json")
    out_table = layout.path(output_dir, "jsluice_method_check_table.txt")
    outputs = [out_json, out_table]

    if not src.exists() or src.stat().st_size == 0:
        return make_result(
            stage, "skipped", input_path=src, outputs=outputs, count=0,
            error="no jsluice_params.json (jsluice found no param/method records)",
        )

    if resume and out_json.exists() and out_json.stat().st_size > 0:
        existing = load_json(out_json) or []
        return make_result(
            stage, "success", input_path=src, outputs=outputs,
            count=len(existing) if isinstance(existing, list) else 0,
            extra={"resumed": True},
        )

    if dry_run:
        return make_result(stage, "skipped", input_path=src, outputs=outputs,
                           count=0, error="dry-run")

    candidates = _load_method_candidates(src)
    if not candidates:
        write_json(out_json, [])
        out_table.write_text("", encoding="utf-8")
        return make_result(
            stage, "skipped", input_path=src, outputs=outputs, count=0,
            error="every recorded endpoint used GET or an unlabeled method",
        )

    if not runner.tool_available("httpx"):
        return make_result(stage, "skipped", input_path=src, outputs=outputs,
                           count=0, error="httpx binary not found")

    mcfg = (cfg.get("jsluice") or {}).get("method_check") or {}
    hcfg = cfg.get("httpx") or {}
    threads = int(mcfg.get("threads", hcfg.get("threads", 50)))
    timeout = int(mcfg.get("timeout", 300))
    max_urls = int(mcfg.get("max_urls", _DEFAULT_METHOD_CHECK_MAX))
    body_preview_bytes = int(mcfg.get("body_preview_bytes", 200))

    items = sorted(candidates.items())
    capped = len(items) > max_urls
    if capped:
        items = items[:max_urls]

    by_method: dict[str, list[str]] = {}
    for url, method in items:
        by_method.setdefault(method, []).append(url)

    print(console.phase_info_line(
        f"[{stage}] {len(candidates)} method-tagged endpoint(s): testing "
        f"{len(items)} with their recorded verb "
        f"({', '.join(sorted(by_method))})"
        + (f" (capped at {max_urls})" if capped else "")))

    # Baseline GET facts (from the main URL probe or the jsluice GET-verify
    # pass above), for the "did the real method reveal something a blind
    # GET missed" comparison. Best-effort — a miss just means no baseline.
    baseline = _detail_index(layout.path(output_dir, "alive_urls_detail.json"))
    for u, row in _detail_index(
            layout.path(output_dir, "jsluice_alive_detail.json")).items():
        baseline.setdefault(u, row)

    raw_root = output_dir / "raw" / "jsluice"
    raw_root.mkdir(parents=True, exist_ok=True)
    # One request-list per distinct method — httpx applies ``-x`` to the
    # whole list it's given, so URLs expecting different verbs can't share
    # a single call. Splitting the overall budget keeps a target with many
    # verbs from starving the last group of its timeout.
    per_group_timeout = max(30, timeout // max(1, len(by_method)))

    rows: list[dict] = []
    group_errors: list[str] = []
    for method, urls in by_method.items():
        scan_file = raw_root / f"method_check_{method.lower()}.txt"
        write_lines(scan_file, urls)
        raw_out = scan_file.with_name(f"method_check_{method.lower()}_httpx.jsonl")
        cmd = [
            "httpx", "-l", str(scan_file),
            "-x", method,
            "-json", "-silent",
            "-threads", str(threads),
            "-timeout", "10",
            "-retries", "1",
            "-bp", str(max(1, body_preview_bytes)),
            "-o", str(raw_out),
        ]
        r = runner.run(cmd, stage=stage, log_name=stage,
                       output_dir=output_dir, timeout=per_group_timeout)
        # httpx streams to -o, so a per-group timeout still leaves whatever
        # it finished as real, usable rows — same salvage logic as verify().
        # A hard failure on one method group doesn't sink the others.
        if not r["success"] and not r["missing_binary"] and not r.get("timed_out"):
            group_errors.append(f"{method}: {(r['stderr'] or '')[:120]}")
        for obj in _parse_httpx_jsonl(raw_out):
            u = obj.get("url") or obj.get("input") or ""
            if not u:
                continue
            b = baseline.get(u) or {}
            rows.append({
                "url": u,
                "method": method,
                "status": obj.get("status_code"),
                "content_length": obj.get("content_length"),
                "content_type": (obj.get("content_type") or "").split(";")[0].strip(),
                "body_preview": _clean(obj.get("body_preview") or "",
                                       body_preview_bytes),
                "get_status": b.get("status_code"),
                "get_content_length": b.get("content_length"),
            })

    rows.sort(key=lambda r: (0 if _is_method_bypass(r) else 1, r["url"]))
    write_json(out_json, rows, compact=True)
    _write_method_check_table(rows, out_table)

    bypass_count = sum(1 for r in rows if _is_method_bypass(r))
    extra = {
        "candidates": len(candidates),
        "tested": len(items),
        "methods": sorted(by_method),
        "capped": capped,
        "method_reveals_more_than_get": bypass_count,
    }
    if group_errors and not rows:
        return make_result(
            stage, "failed", input_path=src, outputs=outputs, count=0,
            error="; ".join(group_errors), extra=extra,
        )
    if group_errors:
        extra["group_errors"] = group_errors
    return make_result(stage, "success", input_path=src, outputs=outputs,
                       count=len(rows), extra=extra)
