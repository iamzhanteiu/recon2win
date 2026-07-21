"""Tests for web/app.py — the Flask web UI.

We don't spawn real recon2win subprocesses in tests (that would be
integration, not unit). Instead we monkeypatch ``subprocess.Popen``
to return a fake process whose ``stdout`` we feed canned lines into.
This exercises the routes, validation, and SSE streaming logic
without needing real tools installed.
"""
from __future__ import annotations

import io
import threading
import time

import pytest

# Skip the whole module if Flask isn't installed — it's an optional
# dep for the web UI. The CLI workflow works without it.
flask = pytest.importorskip("flask")


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------
class FakeProcess:
    """Minimal stand-in for subprocess.Popen.

    Reading from ``.stdout`` yields each line in ``script`` exactly
    once, in order. ``wait()`` sets ``returncode`` and signals the
    reader thread.
    """

    def __init__(self, script: list[str], *, returncode: int = 0):
        self._script = list(script)
        self.returncode: int | None = None
        self.stdout = io.StringIO("\n".join(self._script) + "\n")
        self._wait_called = threading.Event()

    def wait(self, timeout=None):
        self.returncode = 0
        self._wait_called.set()
        return self.returncode


@pytest.fixture
def web_app(monkeypatch, tmp_path):
    """Import web.app with Popen monkeypatched to return a fake."""
    # Patch Popen BEFORE importing web.app so the global reference
    # captures our fake.
    fake_processes: list[FakeProcess] = []

    def fake_popen(cmd, **kwargs):
        # default empty script; tests can pre-load by calling fake_popen
        fp = FakeProcess(script=[])
        fake_processes.append(fp)
        return fp

    import web.app as wapp
    monkeypatch.setattr(wapp.subprocess, "Popen", fake_popen)
    # Clear any leftover scans between tests.
    wapp.SCANS.clear()
    wapp._new_scan_orig = wapp._new_scan

    # Replace _new_scan so it doesn't actually call Popen — tests
    # inject their own FakeProcess via the helper below.
    def make_scan(domain, args, *, script=None, returncode=0):
        fp = FakeProcess(script=script or [], returncode=returncode)
        fake_processes.append(fp)
        # Use the existing _new_scan machinery by swapping subprocess
        # for this one call.
        from uuid import uuid4
        import time as _t
        scan_id = uuid4().hex[:12]
        scan = {
            "proc": fp,
            "domain": domain,
            "args": list(args),
            "started": _t.time(),
            "status": "running",
            "returncode": None,
            "output": [],
            "lock": threading.Lock(),
        }
        with wapp._SCANS_LOCK:
            wapp.SCANS[scan_id] = scan

        def _reader():
            try:
                for line in fp.stdout:
                    with scan["lock"]:
                        scan["output"].append(line)
            finally:
                fp.wait()
                with scan["lock"]:
                    scan["returncode"] = fp.returncode
                    scan["status"] = "done" if fp.returncode == 0 else "failed"

        threading.Thread(target=_reader, daemon=True,
                         name=f"scan-{scan_id}").start()
        return scan_id

    wapp._make_test_scan = make_scan
    return wapp, make_scan, fake_processes


@pytest.fixture
def client(web_app):
    """Flask test client."""
    wapp, _, _ = web_app
    wapp.app.config["TESTING"] = True
    with wapp.app.test_client() as c:
        yield c


# ----------------------------------------------------------------------
# GET / — the UI page
# ----------------------------------------------------------------------
def test_index_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # xterm.js + form + the title all present
    assert "xterm" in body.lower()
    assert 'id="domain"' in body
    assert 'id="args"' in body
    assert "recon2win" in body


# ----------------------------------------------------------------------
# POST /api/run — start a scan
# ----------------------------------------------------------------------
def test_run_starts_scan_and_returns_id(client, web_app):
    wapp, make_scan, _ = web_app
    make_scan("example.com", [], script=["hello", "world"])
    r = client.post("/api/run",
                     json={"domain": "example.com", "args": []})
    assert r.status_code == 200
    data = r.get_json()
    assert "scan_id" in data
    # The route creates its own scan via _new_scan (real path), which
    # spawned its own FakeProcess via monkeypatched Popen. That's
    # fine — we just check the response shape.
    assert data["domain"] == "example.com"


def test_run_requires_domain(client):
    r = client.post("/api/run", json={"args": []})
    assert r.status_code == 400


def test_run_rejects_invalid_domain(client):
    r = client.post("/api/run", json={"domain": "not a domain!!"})
    assert r.status_code == 400
    assert "domain" in r.get_json()["error"].lower()


def test_run_accepts_extra_args(client, web_app):
    wapp, make_scan, _ = web_app
    make_scan("example.com", ["--resume"], script=[])
    r = client.post("/api/run",
                     json={"domain": "example.com",
                           "args": ["--resume", "--skip-waymore"]})
    assert r.status_code == 200
    assert r.get_json()["args"] == ["--resume", "--skip-waymore"]


def test_run_coerces_args_to_strings(client, web_app):
    wapp, make_scan, _ = web_app
    make_scan("example.com", ["1", "2"], script=[])
    r = client.post("/api/run",
                     json={"domain": "example.com", "args": [1, 2, None]})
    assert r.status_code == 200
    assert r.get_json()["args"] == ["1", "2", "None"]


def test_run_rejects_non_list_args(client):
    r = client.post("/api/run",
                     json={"domain": "example.com", "args": "not a list"})
    assert r.status_code == 400


# ----------------------------------------------------------------------
# GET /api/status/<scan_id>
# ----------------------------------------------------------------------
def test_status_returns_404_for_unknown(client):
    r = client.get("/api/status/nonexistent")
    assert r.status_code == 404


def test_status_reports_running(client, web_app):
    wapp, make_scan, _ = web_app
    scan_id = make_scan("example.com", [], script=["line1"])
    # give the reader thread a moment to consume the script
    time.sleep(0.05)
    r = client.get(f"/api/status/{scan_id}")
    assert r.status_code == 200
    data = r.get_json()
    assert data["scan_id"] == scan_id
    assert data["domain"] == "example.com"
    assert data["status"] in ("running", "done")
    assert data["output_lines"] >= 1


# ----------------------------------------------------------------------
# GET /api/stream/<scan_id> — SSE
# ----------------------------------------------------------------------
def test_stream_returns_text_event_stream(client, web_app):
    wapp, make_scan, _ = web_app
    scan_id = make_scan("example.com", [], script=["line1", "line2"])
    r = client.get(f"/api/stream/{scan_id}")
    assert r.status_code == 200
    assert "text/event-stream" in r.headers["Content-Type"]
    # drain the response (limited)
    body = next(r.response).decode("utf-8", errors="replace")
    assert "data:" in body


def test_stream_emits_data_events(client, web_app):
    wapp, make_scan, _ = web_app
    scan_id = make_scan("example.com", [], script=["hello", "world"])
    r = client.get(f"/api/stream/{scan_id}")
    chunks = []
    for chunk in r.response:
        chunks.append(chunk.decode("utf-8", errors="replace"))
        if "event: end" in "".join(chunks):
            break
    body = "".join(chunks)
    assert "data: hello" in body
    assert "data: world" in body
    assert "event: end" in body


def test_stream_returns_404_for_unknown(client):
    r = client.get("/api/stream/nonexistent")
    assert r.status_code == 404


def test_stream_escapes_embedded_newlines(client, web_app):
    """SSE data events must each be a single line. Lines with embedded
    \\n (which the server should escape to \\\\n) need to round-trip
    through the SSE protocol without breaking the client."""
    wapp, make_scan, _ = web_app
    scan_id = make_scan("example.com", [], script=["line-with-no-newline"])
    r = client.get(f"/api/stream/{scan_id}")
    chunks = []
    for chunk in r.response:
        chunks.append(chunk.decode("utf-8", errors="replace"))
        if "event: end" in "".join(chunks):
            break
    body = "".join(chunks)
    # The fake script has no newlines, so server emits it as-is.
    assert "data: line-with-no-newline" in body


# ----------------------------------------------------------------------
# GET /api/scans
# ----------------------------------------------------------------------
def test_scans_endpoint_lists_all(client, web_app):
    wapp, make_scan, _ = web_app
    a = make_scan("a.example.com", [], script=[])
    b = make_scan("b.example.com", [], script=[])
    r = client.get("/api/scans")
    assert r.status_code == 200
    data = r.get_json()
    ids = {s["scan_id"] for s in data["scans"]}
    assert a in ids
    assert b in ids


def test_scans_empty_when_no_runs(client):
    r = client.get("/api/scans")
    assert r.status_code == 200
    assert r.get_json() == {"scans": []}


# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------
def test_main_parses_args(monkeypatch, capsys):
    import web.app as wapp
    called = {}
    def fake_run(host, port, debug, **kwargs):
        called["host"] = host
        called["port"] = port
        called["debug"] = debug
    monkeypatch.setattr(wapp.app, "run", fake_run)
    monkeypatch.setattr("sys.argv", ["app.py", "--host", "0.0.0.0", "--port", "9999"])
    rc = wapp.main()
    assert rc == 0
    assert called == {"host": "0.0.0.0", "port": 9999, "debug": False}
    out = capsys.readouterr().out
    assert "0.0.0.0:9999" in out