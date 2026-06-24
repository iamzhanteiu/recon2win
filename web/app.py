"""web/app.py — minimal Flask server to run recon2win from a browser.

Endpoints
=========

``GET  /``                      — single-page UI (form + xterm.js terminal)
``POST /api/run``               — start a scan, return ``scan_id``
``GET  /api/stream/<scan_id>``  — Server-Sent Events stream of stdout
``GET  /api/status/<scan_id>``  — JSON: status + accumulated output
``GET  /api/scans``              — JSON: list of known scan_ids

Run with::

    python3 web/app.py            # http://localhost:5000

The UI is intentionally minimal — no auth, no persistence, no fancy
analytics. The point is "run recon2win from a browser and watch the
terminal". For real-world usage, run behind a reverse proxy with auth.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from flask import (
    Flask, Response, jsonify, render_template, request, stream_with_context,
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
from modules.utils import validate_domain  # noqa: E402


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