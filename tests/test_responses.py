"""Tests for modules.responses — short body preview for ffuf/dirsearch hits.

Re-requests each ffuf + dirsearch hit with httpx -bp (body-preview only, no
full body), then writes responses/index.md + preview.json. These tests mock
runner.run so no real HTTP happens.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import layout, responses
from modules.utils import create_output_structure, read_lines, write_lines


def _seed_hits(base: Path, ffuf=None, dirsearch=None):
    if ffuf is not None:
        write_lines(layout.path(base, "ffuf_urls.txt"), ffuf)
    if dirsearch is not None:
        write_lines(layout.path(base, "dirsearch_urls.txt"), dirsearch)


def _fake_httpx(rows: list[dict]):
    """runner.run stand-in: writes `rows` as JSONL to the -o path, records argv."""
    captured: dict = {}

    def _run(cmd, **kw):
        captured["cmd"] = cmd
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        # only emit rows whose url is in the input file (realistic)
        wanted = set(read_lines(Path(cmd[cmd.index("-l") + 1])))
        lines = [json.dumps(r) for r in rows if r.get("url") in wanted]
        out.write_text("\n".join(lines) + ("\n" if lines else ""))
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stderr": ""}
    return _run, captured


def test_skips_when_no_hits(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    res = responses.collect(base, {"responses": {}})
    assert res["status"] == "skipped"
    assert "no ffuf/dirsearch hits" in res["error"]


def test_skips_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    _seed_hits(base, ffuf=["https://x.com/a"])
    res = responses.collect(base, {"responses": {"enabled": False}})
    assert res["status"] == "skipped"
    assert "disabled" in res["error"]


def test_skips_when_httpx_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: False)
    base = create_output_structure("x.com", root=str(tmp_path))
    _seed_hits(base, ffuf=["https://x.com/a"])
    res = responses.collect(base, {"responses": {}})
    assert res["status"] == "skipped"
    assert "httpx" in res["error"]


def test_fetches_merges_and_writes_preview(tmp_path, monkeypatch):
    rows = [
        {"url": "https://x.com/admin", "status_code": 200, "content_length": 12,
         "content_type": "text/html; charset=utf-8", "title": "Admin",
         "body_preview": "  <html>  secret\npanel </html> "},
        {"url": "https://x.com/robots.txt", "status_code": 200, "content_length": 5,
         "content_type": "text/plain", "title": "", "body_preview": "deny"},
    ]
    fake, captured = _fake_httpx(rows)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base = create_output_structure("x.com", root=str(tmp_path))
    _seed_hits(base, ffuf=["https://x.com/admin"],
               dirsearch=["https://x.com/robots.txt", "https://x.com/admin"])

    res = responses.collect(base, {"responses": {"snippet_bytes": 100}})
    assert res["status"] == "success"
    assert res["count"] == 2

    # httpx invoked with body-preview (no full-body / store flags)
    assert "-bp" in captured["cmd"]
    assert "-srd" not in captured["cmd"]
    assert "-irr" not in captured["cmd"]

    prev = json.loads((base / "responses" / "preview.json").read_text())
    urls = {p["url"] for p in prev["previews"]}
    assert urls == {"https://x.com/admin", "https://x.com/robots.txt"}

    # /admin found by BOTH tools → both sources recorded, and it ranks first
    # (sensitive path) so preview[0] is admin
    admin = prev["previews"][0]
    assert admin["url"].endswith("/admin")
    assert sorted(admin["sources"]) == ["dirsearch", "ffuf"]
    # snippet is whitespace-collapsed body preview, capped
    assert admin["snippet"] == "<html> secret panel </html>"
    # no stored full-body path is kept
    assert "stored_path" not in admin

    # index.md is a Markdown table (status + snippet), no store link column
    md = (base / "responses" / "index.md").read_text()
    assert "| status |" in md
    assert "| snippet |" in md
    assert "store/" not in md


def test_caps_to_max_urls_keeping_sensitive_first(tmp_path, monkeypatch):
    rows = [
        {"url": "https://x.com/admin", "status_code": 200, "content_length": 1,
         "body_preview": "a"},
    ]
    fake, captured = _fake_httpx(rows)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base = create_output_structure("x.com", root=str(tmp_path))
    _seed_hits(base, ffuf=[
        "https://x.com/blog/1", "https://x.com/blog/2", "https://x.com/admin",
    ])
    res = responses.collect(base, {"responses": {"max_urls": 1}})

    # only 1 URL sent to httpx, and it's the sensitive /admin one
    sent = read_lines(Path(captured["cmd"][captured["cmd"].index("-l") + 1]))
    assert sent == ["https://x.com/admin"]
    assert res["extra"]["capped"] == 2


def test_skip_flag(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    _seed_hits(base, ffuf=["https://x.com/a"])
    res = responses.collect(base, {"responses": {}}, skip=True)
    assert res["status"] == "skipped"
    assert (base / "responses" / "preview.json").exists()
