"""web/app.py — minimal Flask server to run recon2win from a browser.

Endpoints
=========

``GET  /``                      — single-page UI (form + xterm.js terminal)
``POST /api/run``               — start a scan, return ``scan_id``
``GET  /api/stream/<scan_id>``  — Server-Sent Events stream of stdout
``GET  /api/status/<scan_id>``  — JSON: status + accumulated output
``GET  /api/scans``              — JSON: list of known scan_ids

``GET  /results``                                  — target list, grouped by project
``GET  /results/<target_ref>``                      — target overview (KPIs + links)
``GET  /results/<target_ref>/hosts``                — paginated/filterable host table
``GET  /results/<target_ref>/urls``                 — paginated/filterable URL table
``GET  /results/<target_ref>/findings``             — paginated/filterable findings table
``GET  /results/<target_ref>/files``                — full recon file tree, grouped by dir
``GET  /results/<target_ref>/file/<rel>``           — view (text, inline) / download one file
``GET  /results/<target_ref>/report/<filename>``    — serves report/* files directly
  (``target_ref`` is ``domain`` or ``project/domain`` — see modules/webdata.py)

Run with::

    python3 web/app.py            # http://localhost:5000

The UI is intentionally minimal — no auth, no persistence, no fancy
analytics. The point is "run recon2win from a browser and browse/watch
results". For real-world usage, run behind a reverse proxy (or a tunnel)
that handles auth — this app does not implement any itself.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import yaml
from flask import (
    Flask, Response, abort, jsonify, render_template, request,
    send_from_directory, stream_with_context,
)


# ----------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------
# web/app.py lives at recon2win/web/app.py; main.py is one level up.
REPO_ROOT = Path(__file__).resolve().parent.parent
MAIN_PY = REPO_ROOT / "main.py"
CONFIG_YML = REPO_ROOT / "config.yml"

if not MAIN_PY.exists():
    raise RuntimeError(f"main.py not found at {MAIN_PY}")

# Make ``modules.*`` importable when running ``python3 web/app.py``
# (Python prepends the script's directory, not the parent). Doing
# this BEFORE we import validate_domain below.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Imported once after the path fix so the smoke-test server works
# without the user manually setting PYTHONPATH.
from modules import webdata  # noqa: E402
from modules.utils import validate_domain  # noqa: E402


def _output_root() -> Path:
    """``output_root`` from config.yml (same key main.py reads), default
    "outputs". Re-read on every call — config.yml can change between
    requests on a long-running dev server, and this is cheap."""
    root = "outputs"
    if CONFIG_YML.exists():
        try:
            cfg = yaml.safe_load(CONFIG_YML.read_text(encoding="utf-8")) or {}
            root = cfg.get("output_root", "outputs")
        except yaml.YAMLError:
            pass
    p = Path(root)
    return p if p.is_absolute() else REPO_ROOT / p


# ----------------------------------------------------------------------
# In-memory scan store
# ----------------------------------------------------------------------
# scan_id → dict(proc, domain, args, started, status, output, lock)
# Single-process Flask dev server is the only target — this dict
# is wiped on restart and not shared across workers.
SCANS: dict[str, dict[str, Any]] = {}
_SCANS_LOCK = threading.Lock()


def _new_scan(domain: str, args: list[str]) -> dict[str, Any]:
    """Spawn the recon2win subprocess and register it."""
    cmd = [sys.executable, str(MAIN_PY), "-d", domain]
    if args:
        cmd.extend(args)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # merge stderr into stdout (one stream)
        bufsize=1,                 # line-buffered
        text=True,
        cwd=str(REPO_ROOT),
    )
    scan_id = uuid.uuid4().hex[:12]
    scan = {
        "proc": proc,
        "domain": domain,
        "args": args,
        "started": time.time(),
        "status": "running",
        "returncode": None,
        "output": [],       # list[str] — each line of stdout
        "lock": threading.Lock(),
    }
    with _SCANS_LOCK:
        SCANS[scan_id] = scan

    # Background thread: read stdout line by line, append to buffer,
    # wait for the process to exit, mark status.
    def _reader():
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                with scan["lock"]:
                    scan["output"].append(line)
        finally:
            proc.wait()
            with scan["lock"]:
                scan["returncode"] = proc.returncode
                scan["status"] = "done" if proc.returncode == 0 else "failed"

    threading.Thread(target=_reader, daemon=True, name=f"scan-{scan_id}").start()
    return scan_id


def _scan_or_404(scan_id: str) -> dict | tuple[dict, int]:
    """Return the scan dict for *scan_id*, or a 404 JSON response."""
    with _SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if scan is None:
        return jsonify({"error": f"scan {scan_id!r} not found"}), 404
    return scan


# ----------------------------------------------------------------------
# Flask app
# ----------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")


# ``results_report_file`` and ``results_file_view`` are structurally identical
# rules (``<path:target_ref>/<literal>/<path:...>``). Werkzeug's greedy path
# matching would let the report route swallow a ``.../file/report/x`` URL by
# absorbing ``/file`` into ``target_ref`` — so constrain a target_ref to 1-2
# segments whose final segment is not a reserved sub-route name. Real targets
# are ``domain`` or ``project/domain``; none is named ``file``/``report``/etc.
from werkzeug.routing import PathConverter  # noqa: E402


class TargetRefConverter(PathConverter):
    regex = (
        r"(?:[^/]+/)?"
        r"(?!(?:file|files|hosts|urls|findings|report)(?:/|$))"
        r"[^/]+"
    )


app.url_map.converters["tref"] = TargetRefConverter


@app.template_filter("ts")
def _fmt_ts(value: float | None) -> str:
    """Epoch seconds → ``YYYY-MM-DD HH:MM`` for file-listing mtimes."""
    if not value:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value))


@app.context_processor
def _inject_nav_active() -> dict:
    """Which top-nav link is "active", inferred from the endpoint name —
    so a new /results/* route doesn't need to remember to pass it."""
    ep = request.endpoint or ""
    if ep.startswith("results_") or ep == "results_index":
        active = "results"
    elif ep == "index":
        active = "run"
    else:
        active = None
    return {"active": active}


@app.route("/")
def index():
    """Render the single-page UI."""
    return render_template("index.html")


@app.route("/api/run", methods=["POST"])
def api_run():
    """Start a new scan. Body: ``{"domain": str, "args": list[str]}``.

    Returns ``{"scan_id": str, "domain": str, "started": float}``.
    """
    body = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower()
    args = body.get("args") or []
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    if not isinstance(args, list):
        return jsonify({"error": "args must be a list of strings"}), 400
    # Coerce args to strings — protects against weird JSON shapes.
    args = [str(a) for a in args]

    # Domain validation mirrors main.py — keep both in sync.
    try:
        domain = validate_domain(domain)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    scan_id = _new_scan(domain, args)
    return jsonify({
        "scan_id": scan_id,
        "domain": domain,
        "args": args,
        "started": SCANS[scan_id]["started"],
    })


@app.route("/api/stream/<scan_id>")
def api_stream(scan_id: str):
    """Server-Sent Events stream of stdout for *scan_id*.

    Each ``data:`` line is one stdout line (newline included). The
    stream ends with an ``event: end`` event so the client knows
    when to close the EventSource.
    """
    result = _scan_or_404(scan_id)
    if isinstance(result, tuple):  # 404
        return result
    scan = result

    @stream_with_context
    def generate():
        last_idx = 0
        # Heartbeat keeps the connection alive across proxies.
        while True:
            with scan["lock"]:
                new_lines = scan["output"][last_idx:]
                last_idx = len(scan["output"])
                status = scan["status"]
                rc = scan["returncode"]
            for line in new_lines:
                # SSE requires \n\n terminator; escape any embedded
                # newlines so the client gets exactly one event per
                # stdout line.
                safe = line.rstrip("\n").replace("\n", "\\n")
                yield f"data: {safe}\n\n"
            if status in ("done", "failed"):
                yield f"event: end\ndata: {status} (exit {rc})\n\n"
                return
            # Keep the connection alive; xterm.js handles idle fine.
            yield ": heartbeat\n\n"
            time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/status/<scan_id>")
def api_status(scan_id: str):
    """JSON snapshot of a scan: status, returncode, accumulated output."""
    result = _scan_or_404(scan_id)
    if isinstance(result, tuple):
        return result
    scan = result
    with scan["lock"]:
        return jsonify({
            "scan_id": scan_id,
            "domain": scan["domain"],
            "args": scan["args"],
            "status": scan["status"],
            "returncode": scan["returncode"],
            "started": scan["started"],
            "elapsed": time.time() - scan["started"],
            "output_lines": len(scan["output"]),
        })


@app.route("/api/scans")
def api_scans():
    """List all known scan_ids (in-memory only)."""
    with _SCANS_LOCK:
        return jsonify({
            "scans": [
                {"scan_id": sid, "domain": s["domain"], "status": s["status"]}
                for sid, s in SCANS.items()
            ],
        })


# ----------------------------------------------------------------------
# Results browser — read-only, all data via modules/webdata.py
# ----------------------------------------------------------------------
def _resolve_or_404(target_ref: str) -> dict:
    """``webdata.resolve_target()`` or Flask 404 — one place to call from
    every /results/<target_ref>... route."""
    ref = webdata.resolve_target(_output_root(), target_ref)
    if ref is None:
        abort(404, description=f"no such target: {target_ref!r}")
    return ref


def _page_args() -> tuple[str, str, int, int]:
    """Common query-string args every table route accepts."""
    q = request.args.get("q", "")
    status = request.args.get("status", "")
    page = request.args.get("page", "1")
    limit = request.args.get("limit", "100")
    try:
        page = int(page)
    except ValueError:
        page = 1
    try:
        limit = int(limit)
    except ValueError:
        limit = 100
    return q, status, page, limit


@app.route("/results")
def results_index():
    """Target list, grouped by project — the results-browsing landing page."""
    targets = webdata.list_targets(_output_root())
    groups: dict[str | None, list[dict]] = {}
    for t in targets:
        groups.setdefault(t["project"], []).append(t)
    # Ungrouped (None) first, then projects alphabetically. Risk-score order
    # from list_targets() is preserved within each group.
    ordered_groups = sorted(groups.items(), key=lambda kv: (kv[0] is not None, kv[0] or ""))
    return render_template("results.html", groups=ordered_groups, total=len(targets))


@app.route("/results/<path:target_ref>")
def results_target(target_ref: str):
    """Target overview: KPIs + links to Hosts/URLs/Findings + full report."""
    ref = _resolve_or_404(target_ref)
    summary = webdata.target_overview(ref["path"], project=ref["project"])
    return render_template(
        "target.html", target_ref=target_ref, summary=summary,
        has_final_report=(ref["path"] / "report" / "final_report.html").exists(),
        has_asm_report=(ref["path"] / "report" / "asm_report.html").exists(),
    )


@app.route("/results/<path:target_ref>/hosts")
def results_hosts(target_ref: str):
    ref = _resolve_or_404(target_ref)
    q, status, page, limit = _page_args()
    data = webdata.hosts_table(ref["path"], q=q, status=status, page=page, limit=limit)
    return render_template(
        "table.html", target_ref=target_ref, view="hosts", title="Hosts",
        q=q, status=status, columns=["status", "length", "content_type", "url"],
        **data,
    )


@app.route("/results/<path:target_ref>/urls")
def results_urls(target_ref: str):
    ref = _resolve_or_404(target_ref)
    q, status, page, limit = _page_args()
    data = webdata.urls_table(ref["path"], q=q, status=status, page=page, limit=limit)
    return render_template(
        "table.html", target_ref=target_ref, view="urls", title="URLs",
        q=q, status=status, columns=["status", "length", "content_type", "url"],
        **data,
    )


@app.route("/results/<path:target_ref>/findings")
def results_findings(target_ref: str):
    ref = _resolve_or_404(target_ref)
    q, _status, page, limit = _page_args()
    severity = request.args.get("severity", "")
    data = webdata.list_findings(ref["path"], q=q, severity=severity, page=page, limit=limit)
    return render_template(
        "findings.html", target_ref=target_ref, q=q, severity=severity, **data,
    )


@app.route("/results/<path:target_ref>/files")
def results_files(target_ref: str):
    """Full file tree of a target's recon output — every artefact under
    ``raw/`` ``processed/`` ``findings/`` ``report/`` ``responses/`` ``logs/``,
    grouped by directory so you can browse what a scan actually produced."""
    ref = _resolve_or_404(target_ref)
    files = webdata.list_files(ref["path"])
    # Group by parent directory (POSIX), preserving the sorted order from
    # list_files() — dirs appear in BROWSABLE_DIRS order, files within a dir
    # alphabetically. Each group is one collapsible section in the template.
    dirs: dict[str, list[dict]] = {}
    for f in files:
        parent = f["rel"].rsplit("/", 1)[0] if "/" in f["rel"] else f["group"]
        dirs.setdefault(parent, []).append(f)
    return render_template(
        "files.html", target_ref=target_ref, dirs=list(dirs.items()),
        total=len(files),
    )


@app.route("/results/<path:target_ref>/file/<path:rel>")
def results_file_view(target_ref: str, rel: str):
    """View or download a single recon file.

    Text files render inline (capped) unless ``?raw=1`` is passed; everything
    else is served for download. Path-traversal is handled in
    ``webdata.resolve_file`` — an escaping or non-browsable path 404s.
    """
    ref = _resolve_or_404(target_ref)
    path = webdata.resolve_file(ref["path"], rel)
    if path is None:
        abort(404, description=f"no such file: {rel!r}")

    raw = request.args.get("raw") == "1"
    is_text = path.suffix.lower() in webdata._TEXT_EXTS
    if raw or not is_text:
        # send_from_directory re-validates the path against the directory,
        # so this stays traversal-safe even though resolve_file already ran.
        as_download = request.args.get("dl") == "1" or not is_text
        return send_from_directory(
            ref["path"], path.relative_to(ref["path"]).as_posix(),
            as_attachment=as_download,
        )

    preview = webdata.read_text_preview(path)
    return render_template(
        "file_view.html", target_ref=target_ref, rel=rel, name=path.name,
        **preview,
    )


@app.route("/results/<tref:target_ref>/report/<path:filename>")
def results_report_file(target_ref: str, filename: str):
    """Serve report/* files (final_report.html, asm_report.html, ...)
    directly — the existing rich static reports stay one click away
    instead of duplicating what they already render well."""
    ref = _resolve_or_404(target_ref)
    report_dir = ref["path"] / "report"
    return send_from_directory(report_dir, filename)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main() -> int:
    import argparse
    p = argparse.ArgumentParser(prog="recon2win-web",
                                 description="Web UI for recon2win")
    p.add_argument("--host", default="127.0.0.1",
                   help="Bind host (default 127.0.0.1; use 0.0.0.0 for LAN)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true",
                   help="Flask debug mode (auto-reload, verbose errors)")
    args = p.parse_args()
    print(f"recon2win web UI → http://{args.host}:{args.port}", flush=True)
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())