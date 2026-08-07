"""graphql_probe — confirm GraphQL introspection instead of just flagging it.

A ``/graphql`` endpoint sitting in ``all_urls.txt`` (via ``classify_url`` in
``report.py``) tells an operator an API surface exists — it does not tell
them anything about it. Most GraphQL servers that haven't explicitly turned
introspection off will answer a single POST with the entire schema: every
query, every mutation, every type and field the developers wrote. That is
the single highest-ROI request in this whole pipeline when it lands: one
request, often the whole attack surface of the API back.

Candidates come from two places:
  1. **Curated paths** crossed with every alive host (``/graphql``,
     ``/graphiql``, ``/altair``, ``/playground``, …) — catches GraphQL
     backends a GET-only crawl never reached, because a lot of them 404/405
     a bare GET and only answer POST.
  2. **Already-discovered URLs** whose path mentions graphql/gql — catches
     non-standard mount points (``/internal/graphql-api``) the curated list
     would miss.

Nothing here mutates any state on the target — introspection is a read-only
query, same risk class as fetching a Swagger doc.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from . import console, layout, runner
from .apidocs import build_candidates
from .utils import load_json, make_result, raw_dir, read_lines, write_json, write_lines

# One entry per mount point actually seen in the wild; kept short since
# every path costs one request per alive host.
CANDIDATE_PATHS: tuple[str, ...] = (
    "/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphiql", "/altair", "/playground", "/query", "/gql",
)

# Compact introspection query — root query/mutation/subscription fields +
# every type name/kind. Deliberately skips the deep TypeRef fragments a
# full GraphQL client needs to build requests; this is for triage, not
# codegen, and the shorter body is cheaper per-host at scale.
INTROSPECTION_QUERY = (
    "query IntrospectionProbe { __schema { "
    "queryType { name fields { name } } "
    "mutationType { name fields { name } } "
    "subscriptionType { name fields { name } } "
    "types { name kind } } }"
)

_URL_MARKERS = ("graphql", "graphiql", "/gql", "altair", "playground")


def _url_looks_like_graphql(url: str) -> bool:
    u = (url or "").lower()
    return any(m in u for m in _URL_MARKERS)


def _outputs_exist(json_out: Path) -> bool:
    return json_out.exists() and json_out.stat().st_size > 0


def _probe(candidates: list[str], output_dir: Path, g_cfg: dict) -> list[dict]:
    """POST the introspection query at every candidate URL in one batch."""
    raw = raw_dir(output_dir, "graphql_probe")
    in_file = raw / "candidates.txt"
    out_file = raw / "probe.jsonl"
    write_lines(in_file, candidates)
    if out_file.exists():
        out_file.unlink()

    body = json.dumps({"query": INTROSPECTION_QUERY})
    cmd = [
        "httpx", "-l", str(in_file),
        "-x", "POST", "-body", body,
        "-H", "Content-Type: application/json",
        "-json", "-silent", "-irr",
        "-threads", str(int(g_cfg.get("threads", 20))),
        "-timeout", str(int(g_cfg.get("http_timeout", 10))),
        "-retries", "1",
        "-o", str(out_file),
    ]
    runner.run(cmd, stage="graphql_probe", output_dir=output_dir,
               timeout=int(g_cfg.get("timeout", 900)))

    rows: list[dict] = []
    if not out_file.exists():
        return rows
    for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except (ValueError, TypeError):
            continue
    return rows


def parse_schema(body: str) -> Optional[dict]:
    """Parse an introspection response body.

    Returns ``None`` for anything that isn't a live ``__schema`` — a 404
    HTML page, introspection explicitly disabled (``{"errors": [...]}`` or
    ``{"data": {"__schema": null}}``), or a non-GraphQL endpoint that just
    happened to match a candidate path. Only a real schema counts as a hit,
    same precision bar apidocs.py holds specs to.
    """
    if not body or not body.strip():
        return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    top = data.get("data")
    schema = top.get("__schema") if isinstance(top, dict) else None
    if not isinstance(schema, dict):
        return None

    def _field_names(root: object) -> list[str]:
        if not isinstance(root, dict):
            return []
        fields = root.get("fields") or []
        return sorted({
            f.get("name") for f in fields
            if isinstance(f, dict) and f.get("name")
        })

    types = schema.get("types") or []
    type_names = sorted({
        t.get("name") for t in types
        if isinstance(t, dict) and t.get("name")
        and not str(t.get("name")).startswith("__")
    })
    return {
        "query_fields": _field_names(schema.get("queryType")),
        "mutation_fields": _field_names(schema.get("mutationType")),
        "subscription_fields": _field_names(schema.get("subscriptionType")),
        "type_count": len(type_names),
        "types": type_names,
    }


def discover(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "graphql_probe"
    layout.ensure_tree(output_dir)
    findings = output_dir / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    json_out = findings / "graphql_schema.json"
    outputs = [json_out]

    g_cfg = (cfg.get("graphql_probe") or {}) if isinstance(cfg, dict) else {}

    if skip:
        write_json(json_out, {"targets": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="--skip-graphql-probe")
    if not g_cfg.get("enabled", True):
        write_json(json_out, {"targets": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="disabled in config")
    if resume and _outputs_exist(json_out):
        existing = load_json(json_out) or {}
        targets = existing.get("targets", []) if isinstance(existing, dict) else []
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=len(targets))
    if dry_run:
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="dry-run")
    if not runner.tool_available("httpx"):
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="httpx binary not found")

    # ---- build candidates ----
    hosts = read_lines(alive_file)
    max_hosts = int(g_cfg.get("max_hosts", 300) or 0)
    if max_hosts and len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]
    candidates = build_candidates(hosts, CANDIDATE_PATHS)

    for fname in ("all_urls.txt", "jsluice_urls.txt", "jsluice_endpoints.txt",
                  "xnlinkfinder_urls.txt", "apidocs_urls.txt"):
        for u in read_lines(layout.path(output_dir, fname)):
            if _url_looks_like_graphql(u) and u not in candidates:
                candidates.append(u)

    if not candidates:
        write_json(json_out, {"targets": []})
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=0,
                           error="no candidate GraphQL endpoints")

    rows = _probe(candidates, output_dir, g_cfg)

    targets: list[dict] = []
    for row in rows:
        schema = parse_schema(row.get("body") or "")
        if not schema:
            continue
        targets.append({
            "url": row.get("url") or "",
            "status_code": row.get("status_code"),
            **schema,
        })

    write_json(json_out, {"targets": targets, "probed": len(candidates)})

    if targets:
        total_mutations = sum(len(t["mutation_fields"]) for t in targets)
        print(console.phase_info_line(
            f"[{stage}] introspection ON at {len(targets)} endpoint(s) — "
            f"{total_mutations} mutation(s) exposed"))

    return make_result(
        stage, "success", input_path=alive_file, outputs=outputs,
        count=len(targets),
        error=None if targets else f"introspection closed/absent on all {len(candidates)} candidate(s)",
        extra={"probed": len(candidates), "introspectable": len(targets)},
    )
