"""graphgen — auto-generate a provenance graph linking the run's outputs.

Every recon run funnels data through a fixed pipeline: domain → subdomains
→ live hosts → URLs → parameters → nuclei findings → report. The topology
never changes; only the *counts* do. This module walks the canonical output
files, reads how many rows each stage produced, and emits a graph that shows
the whole funnel at a glance with real numbers on every node.

Two artefacts are written under ``report/``:

  * ``graph.mmd`` — Mermaid flowchart source. Plain text, so it diffs cleanly
    across scans and renders anywhere (GitHub, mermaid.live, IDE plugins).
  * an inline ``<svg>`` section injected into ``final_report.html`` — fully
    self-contained (no JS, no CDN) so the report stays offline-openable.

Layout is a generic longest-path layered DAG: only ``solid`` edges set a
node's row. The loop-backs — JS-mined URLs re-merged into ``all_urls`` and
URL-derived subdomains fed back to ``subdomains`` — plus the ``seed`` edge are
drawn dashed and excluded from layering so they don't distort the funnel.

Everything here is deterministic: ``build_model`` is a pure read over the
canonical files; ``build_output_graph`` is the thin I/O wrapper that writes
the two artefacts.
"""
from __future__ import annotations

from html import escape
from pathlib import Path

from .utils import load_json, make_result, read_lines


# ----------------------------------------------------------------------
# Node kinds → fill colour. Findings are coloured by severity instead
# (see ``_SEV_FILL``) so a critical hit reads red at a glance.
# ----------------------------------------------------------------------
_KIND_FILL = {
    "src":     "#6b4de6",  # domain / scope seed
    "proc":    "#0f7d84",  # URL / host list under processed/
    "json":    "#b26a00",  # structured intel (jsluice_params.json)
    "finding": "#9aa4ae",  # nuclei / secrets — overridden by severity
    "report":  "#1f6f43",  # the final deliverable
}
_SEV_FILL = {
    "critical": "#c0392b",
    "high":     "#c0392b",
    "medium":   "#b26a00",
    "low":      "#1976d2",
    "info":     "#1976d2",
}
_SEV_SHORT = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# Longest-path layering places nodes by their deepest solid-edge ancestor.
# ``waymore`` pulls from the domain (not from ``alive``), so it lands on row 1
# and its edge to ``all_urls`` would cross the whole discovery band. Pin it to
# the discovery row so the four sources sit together and the graph reads clean.
_LAYER_OVERRIDE = {"waymore": 4}


# ----------------------------------------------------------------------
# Counting helpers
# ----------------------------------------------------------------------
def _lines(path: Path) -> int:
    return len(read_lines(path))


def _json_len(path: Path) -> int:
    d = load_json(path)
    return len(d) if isinstance(d, list) else 0


def _finding_stats(path: Path) -> tuple[int, dict[str, int]]:
    """Return ``(total, severity_count)`` for a nuclei/secrets JSON file."""
    d = load_json(path) or {}
    if not isinstance(d, dict):
        return 0, {}
    sc = {k: int(v) for k, v in (d.get("severity_count") or {}).items()}
    findings = d.get("findings") or []
    total = len(findings) if findings else sum(sc.values())
    return total, sc


def _top_sev(sc: dict[str, int]) -> str | None:
    for sev in _SEV_ORDER:
        if sc.get(sev):
            return sev
    return None


def _sev_sub(sc: dict[str, int]) -> str | None:
    """Compact severity breakdown, e.g. ``2C 1H`` (highest first)."""
    parts = [f"{sc[s]}{_SEV_SHORT[s]}" for s in _SEV_ORDER if sc.get(s)]
    return " ".join(parts) or None


def _fmt(n: int | None) -> str:
    if n is None:
        return ""
    if n >= 1000:
        return f"{n / 1000:.1f}k".replace(".0k", "k")
    return str(n)


# ----------------------------------------------------------------------
# Model — nodes + edges with real counts from disk
# ----------------------------------------------------------------------
# Edge styles: "solid" = main stage→stage flow (drives layering);
# "seed" = additive forward feed (dashed); "append"/"feedback" = loop-back
# (dashed, excluded from layering).
def build_model(output_dir: Path, domain: str) -> tuple[list[dict], list[tuple[str, str, str]]]:
    proc = output_dir / "processed"
    find = output_dir / "findings"

    nodes: list[dict] = []

    def add(nid: str, label: str, kind: str, count: int | None,
            *, sub: str | None = None, sev: str | None = None) -> None:
        nodes.append({"id": nid, "label": label, "kind": kind,
                      "count": count, "sub": sub, "sev": sev})

    def L(name: str) -> int:
        return _lines(proc / name)

    add("domain", domain, "src", None)
    add("subdomains", "subdomains", "proc", L("subdomains.txt"))
    add("resolved", "resolved", "proc", L("resolved.txt"))
    add("alive", "alive hosts", "proc", L("alive.txt"))
    add("crawler", "crawler_urls", "proc", L("crawler_urls.txt"))
    add("dirsearch", "dirsearch", "proc", L("dirsearch_urls.txt"))
    add("ffuf", "ffuf", "proc", L("ffuf_urls.txt"))
    add("waymore", "waymore", "proc", L("waymore_urls.txt"))
    add("all_urls", "all_urls", "proc", L("all_urls.txt"))
    add("url_subs", "url-derived subs", "proc", L("url_derived_subdomains.txt"))
    add("js_urls", "js_urls", "proc", L("js_urls.txt"))
    add("dynamic_urls", "dynamic_urls", "proc", L("dynamic_urls.txt"))
    add("alive_urls", "alive_urls", "proc", L("alive_urls.txt"))
    add("xnlinkfinder", "xnlinkfinder", "proc",
        L("xnlinkfinder_endpoints.txt") + L("xnlinkfinder_urls.txt"))
    add("jsluice", "jsluice urls", "proc",
        L("jsluice_endpoints.txt") + L("jsluice_urls.txt"))
    add("jsluice_params", "jsluice_params", "json",
        _json_len(proc / "jsluice_params.json"))
    add("arjun", "arjun params", "proc", L("arjun_params.txt"))
    add("parameterized", "parameterized_urls", "proc", L("parameterized_urls.txt"))

    for kind, nid, label in (
        ("default", "nuclei_default", "nuclei default"),
        ("endpoints", "nuclei_endpoints", "nuclei endpoints"),
        ("dynamic", "nuclei_dynamic", "nuclei dynamic"),
    ):
        total, sc = _finding_stats(find / kind / "nuclei.json")
        add(nid, label, "finding", total, sub=_sev_sub(sc), sev=_top_sev(sc))

    stot, ssc = _finding_stats(find / "jsluice_secrets.json")
    add("secrets", "JS secrets", "finding", stot, sub=_sev_sub(ssc), sev=_top_sev(ssc))

    add("report", "final report", "report", None)

    edges: list[tuple[str, str, str]] = [
        ("domain", "subdomains", "solid"),
        ("subdomains", "resolved", "solid"),
        ("resolved", "alive", "solid"),
        ("alive", "crawler", "solid"),
        ("alive", "dirsearch", "solid"),
        ("alive", "ffuf", "solid"),
        ("alive", "nuclei_default", "solid"),
        ("domain", "waymore", "solid"),
        ("crawler", "all_urls", "solid"),
        ("dirsearch", "all_urls", "solid"),
        ("ffuf", "all_urls", "solid"),
        ("waymore", "all_urls", "solid"),
        ("all_urls", "js_urls", "solid"),
        ("all_urls", "dynamic_urls", "solid"),
        ("all_urls", "alive_urls", "solid"),
        ("all_urls", "url_subs", "solid"),
        ("js_urls", "xnlinkfinder", "solid"),
        ("js_urls", "jsluice", "solid"),
        ("js_urls", "jsluice_params", "solid"),
        ("js_urls", "secrets", "solid"),
        ("dynamic_urls", "arjun", "solid"),
        ("arjun", "parameterized", "solid"),
        ("jsluice_params", "parameterized", "solid"),
        ("alive_urls", "nuclei_endpoints", "solid"),
        ("parameterized", "nuclei_dynamic", "solid"),
        ("nuclei_default", "report", "solid"),
        ("nuclei_endpoints", "report", "solid"),
        ("nuclei_dynamic", "report", "solid"),
        ("secrets", "report", "solid"),
        # additive / loop-back edges — dashed, excluded from layering
        ("dynamic_urls", "parameterized", "seed"),
        ("xnlinkfinder", "all_urls", "append"),
        ("jsluice", "all_urls", "append"),
        ("url_subs", "subdomains", "feedback"),
    ]
    return nodes, edges


# ----------------------------------------------------------------------
# Layered layout — longest path over solid edges only
# ----------------------------------------------------------------------
def _layers(nodes: list[dict], edges: list[tuple[str, str, str]]) -> dict[str, int]:
    solid_preds: dict[str, list[str]] = {n["id"]: [] for n in nodes}
    for src, dst, style in edges:
        if style == "solid":
            solid_preds[dst].append(src)

    memo: dict[str, int] = {}

    def depth(nid: str) -> int:
        if nid in memo:
            return memo[nid]
        preds = solid_preds.get(nid, [])
        memo[nid] = 0 if not preds else 1 + max(depth(p) for p in preds)
        return memo[nid]

    layer = {n["id"]: depth(n["id"]) for n in nodes}
    for nid, forced in _LAYER_OVERRIDE.items():
        if nid in layer:
            layer[nid] = max(layer[nid], forced)
    return layer


# ----------------------------------------------------------------------
# Mermaid source
# ----------------------------------------------------------------------
def render_mermaid(nodes: list[dict], edges: list[tuple[str, str, str]]) -> str:
    by_id = {n["id"]: n for n in nodes}
    lines = ["flowchart TB"]
    for n in nodes:
        cnt = _fmt(n["count"])
        label = n["label"]
        if cnt:
            label = f"{label}<br/>{cnt}"
        if n["sub"]:
            label = f"{label} ({n['sub']})"
        if n["kind"] == "src":
            lines.append(f'  {n["id"]}(["{label}"]):::{n["kind"]}')
        else:
            lines.append(f'  {n["id"]}["{label}"]:::{n["kind"]}')
    lines.append("")
    arrow = {"solid": "-->", "seed": "-. seed .->",
             "append": "-. append .->", "feedback": "-. new subs .->"}
    for src, dst, style in edges:
        if src in by_id and dst in by_id:
            lines.append(f"  {src} {arrow[style]} {dst}")
    lines.append("")
    lines.append("  classDef src fill:#6b4de6,stroke:#4a32b0,color:#fff;")
    lines.append("  classDef proc fill:#0f7d84,stroke:#0a565b,color:#fff;")
    lines.append("  classDef json fill:#b26a00,stroke:#7d4a00,color:#fff;")
    lines.append("  classDef finding fill:#c0392b,stroke:#8f2a20,color:#fff;")
    lines.append("  classDef report fill:#1f6f43,stroke:#144d2e,color:#fff;")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------
# Inline SVG (self-contained, no JS)
# ----------------------------------------------------------------------
_BOX_W = 158
_BOX_H = 50
_H_GAP = 30
_V_GAP = 46
_MARGIN = 34


def render_svg(nodes: list[dict], edges: list[tuple[str, str, str]]) -> str:
    layer = _layers(nodes, edges)
    order = [n["id"] for n in nodes]
    by_id = {n["id"]: n for n in nodes}

    # Group node ids by layer, preserving insertion order within a layer.
    rows: dict[int, list[str]] = {}
    for nid in order:
        rows.setdefault(layer[nid], []).append(nid)

    max_row_n = max(len(v) for v in rows.values())
    canvas_w = max_row_n * _BOX_W + (max_row_n - 1) * _H_GAP + 2 * _MARGIN
    n_layers = max(rows) + 1
    canvas_h = _MARGIN + n_layers * (_BOX_H + _V_GAP) - _V_GAP + _MARGIN + 26

    # Assign pixel positions: each row centred horizontally.
    pos: dict[str, tuple[float, float]] = {}
    for row, ids in rows.items():
        n = len(ids)
        total = n * _BOX_W + (n - 1) * _H_GAP
        start_x = (canvas_w - total) / 2
        y = _MARGIN + row * (_BOX_H + _V_GAP)
        for i, nid in enumerate(ids):
            pos[nid] = (start_x + i * (_BOX_W + _H_GAP), y)

    parts: list[str] = []
    parts.append(
        f'<svg viewBox="0 0 {canvas_w:.0f} {canvas_h:.0f}" '
        f'width="100%" style="max-width:{canvas_w:.0f}px;font-family:'
        "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif\" "
        'role="img" aria-label="recon output provenance graph">'
    )
    parts.append(
        '<defs><marker id="ah" markerWidth="8" markerHeight="8" refX="6" '
        'refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#8a94a0"/>'
        '</marker><marker id="ahd" markerWidth="8" markerHeight="8" refX="6" '
        'refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#c08a3e"/>'
        "</marker></defs>"
    )

    # Edges first so boxes draw on top.
    for src, dst, style in edges:
        if src not in pos or dst not in pos:
            continue
        sx, sy = pos[src]
        dx, dy = pos[dst]
        x1, y1 = sx + _BOX_W / 2, sy + _BOX_H
        x2, y2 = dx + _BOX_W / 2, dy
        back = dy <= sy  # loop-back edge points upward
        if back:
            # Route the feedback edge out to the side so it doesn't cross boxes.
            x1, y1 = sx, sy + _BOX_H / 2
            x2, y2 = dx, dy + _BOX_H / 2
            cx = min(x1, x2) - 60
            path = f"M{x1:.0f},{y1:.0f} C{cx:.0f},{y1:.0f} {cx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}"
        else:
            my = (y1 + y2) / 2
            path = f"M{x1:.0f},{y1:.0f} C{x1:.0f},{my:.0f} {x2:.0f},{my:.0f} {x2:.0f},{y2:.0f}"
        dashed = style != "solid"
        stroke = "#c08a3e" if dashed else "#8a94a0"
        marker = "ahd" if dashed else "ah"
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        parts.append(
            f'<path d="{path}" fill="none" stroke="{stroke}" stroke-width="1.5"'
            f'{dash} marker-end="url(#{marker})"/>'
        )

    # Boxes.
    for nid in order:
        n = by_id[nid]
        x, y = pos[nid]
        if n["kind"] == "finding":
            fill = _SEV_FILL.get(n["sev"], "#9aa4ae")
        else:
            fill = _KIND_FILL[n["kind"]]
        rx = _BOX_H / 2 if n["kind"] in ("src", "report") else 8
        parts.append(
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{_BOX_W}" height="{_BOX_H}" '
            f'rx="{rx:.0f}" fill="{fill}"/>'
        )
        cx = x + _BOX_W / 2
        cnt = _fmt(n["count"])
        if cnt:
            parts.append(
                f'<text x="{cx:.0f}" y="{y + 19:.0f}" text-anchor="middle" '
                f'fill="#fff" font-size="12">{escape(n["label"])}</text>'
            )
            val = cnt + (f"  ({escape(n['sub'])})" if n["sub"] else "")
            parts.append(
                f'<text x="{cx:.0f}" y="{y + 37:.0f}" text-anchor="middle" '
                f'fill="#fff" font-size="14" font-weight="700">{val}</text>'
            )
        else:
            parts.append(
                f'<text x="{cx:.0f}" y="{y + 31:.0f}" text-anchor="middle" '
                f'fill="#fff" font-size="14" font-weight="700">'
                f'{escape(n["label"])}</text>'
            )

    # Legend.
    ly = canvas_h - 14
    legend = [("#6b4de6", "scope"), ("#0f7d84", "URL/host list"),
              ("#b26a00", "intel JSON"), ("#c0392b", "findings"),
              ("#1f6f43", "report")]
    lx = _MARGIN
    for color, text in legend:
        parts.append(
            f'<rect x="{lx}" y="{ly - 10:.0f}" width="12" height="12" rx="3" '
            f'fill="{color}"/>'
        )
        parts.append(
            f'<text x="{lx + 17}" y="{ly:.0f}" font-size="12" fill="#5a6672">'
            f'{text}</text>'
        )
        lx += 34 + len(text) * 7
    parts.append(
        f'<text x="{lx + 6}" y="{ly:.0f}" font-size="12" fill="#c08a3e">'
        "- - loop-back / seed</text>"
    )

    parts.append("</svg>")
    return "".join(parts)


def _html_section(svg: str) -> str:
    return (
        '<h2>13. Output Graph</h2>\n'
        '<p class="small">Auto-generated provenance graph — how many rows each '
        "stage produced and where they flow. Dashed edges are loop-backs "
        "(JS-mined URLs re-merged, URL-derived subdomains) and the arjun-"
        "independent seed. Source: <code>report/graph.mmd</code>.</p>\n"
        '<div style="overflow-x:auto;background:#fff;border:1px solid #e5e5ea;'
        'border-radius:6px;padding:12px;">\n' + svg + "\n</div>\n"
    )


def _inject_into_report(html_path: Path, section: str) -> bool:
    """Insert the graph section just before the report container closes.

    Returns True when the file was patched. Idempotent: a second run replaces
    the existing section instead of stacking a duplicate.
    """
    if not html_path.exists():
        return False
    html = html_path.read_text(encoding="utf-8", errors="ignore")

    import re
    # Drop any previously-injected section so re-runs stay clean.
    html = re.sub(
        r"<h2>13\. Output Graph</h2>.*?(?=<h2>|\n</div>\n<script)",
        "", html, count=1, flags=re.DOTALL,
    )

    anchor = "\n</div>\n<script"
    if anchor in html:
        html = html.replace(anchor, "\n" + section + anchor, 1)
    elif "</body>" in html:
        html = html.replace("</body>", section + "</body>", 1)
    else:
        html = html + section
    html_path.write_text(html, encoding="utf-8")
    return True


# ----------------------------------------------------------------------
# I/O wrapper — the stage entrypoint
# ----------------------------------------------------------------------
def build_output_graph(output_dir: Path, domain: str) -> dict:
    """Write ``report/graph.mmd`` and inject an inline SVG graph into the
    HTML report. Called after the report/priority/delta stages.
    """
    nodes, edges = build_model(output_dir, domain)

    report_dir = output_dir / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    mmd_path = report_dir / "graph.mmd"
    mmd_path.write_text(render_mermaid(nodes, edges), encoding="utf-8")

    svg = render_svg(nodes, edges)
    injected = _inject_into_report(report_dir / "final_report.html", _html_section(svg))

    outputs = [mmd_path]
    node_total = sum(n["count"] for n in nodes if n["count"])
    return make_result(
        "output_graph", "success",
        input_path=output_dir, outputs=outputs, count=len(nodes),
        extra={"nodes": len(nodes), "edges": len(edges),
               "injected_html": injected, "row_total": node_total,
               "mmd": str(mmd_path)},
    )
