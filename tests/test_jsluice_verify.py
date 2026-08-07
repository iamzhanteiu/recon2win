"""Tests for modules.jsluice_verify — probing the URLs jsluice mined from JS.

httpx_urls runs before jsluice, so jsluice's output reached the report with
no status / length / content-type. On outputs/acronis.com that was 6,265 of
6,306 JS-mined URLs. This stage probes them and folds the live ones back
into alive_urls* so downstream consumers can see them.

httpx is not invoked here — runner.run is patched, and the JSONL it would
have written is placed on disk, matching the real httpx -json -o contract.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules import jsluice_verify, layout
from modules.utils import load_json, write_json


CFG = {"httpx": {"threads": 10, "timeout": 60}}


def _target(tmp_path: Path) -> Path:
    out = tmp_path / "acme.com"
    (out / "processed").mkdir(parents=True)
    (out / "raw" / "jsluice").mkdir(parents=True)
    return out


def _row(url: str, status: int = 200, length: int = 100,
         ctype: str = "application/json") -> dict:
    return {"url": url, "status_code": status, "content_length": length,
            "content_type": ctype, "host": url.split("/")[2]}


def _fake_httpx(rows: list[dict]):
    """Patch runner.run to write *rows* as JSONL to the -o path, like httpx."""
    def _run(cmd, **kwargs):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}
    return _run


# ----------------------------------------------------------------------
# Guard rails
# ----------------------------------------------------------------------
def test_skips_when_no_jsluice_output(tmp_path):
    out = _target(tmp_path)
    res = jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    assert res["status"] == "skipped"
    assert "jsluice_urls" in (res["error"] or "")


def test_dry_run_does_not_probe(tmp_path, monkeypatch):
    out = _target(tmp_path)
    src = layout.path(out, "jsluice_urls.txt")
    src.write_text("https://a.acme.com/x\n", encoding="utf-8")
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run",
                        lambda *a, **k: pytest.fail("must not run httpx"))
    res = jsluice_verify.verify(src, out, CFG, dry_run=True)
    assert res["status"] == "skipped"


def test_skips_when_httpx_missing(tmp_path, monkeypatch):
    out = _target(tmp_path)
    src = layout.path(out, "jsluice_urls.txt")
    src.write_text("https://a.acme.com/x\n", encoding="utf-8")
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: False)
    res = jsluice_verify.verify(src, out, CFG)
    assert res["status"] == "skipped"
    assert "httpx" in (res["error"] or "")


# ----------------------------------------------------------------------
# Core behaviour
# ----------------------------------------------------------------------
def test_writes_status_length_content_type_table(tmp_path, monkeypatch):
    out = _target(tmp_path)
    src = layout.path(out, "jsluice_urls.txt")
    src.write_text("https://a.acme.com/api/v1/users\n", encoding="utf-8")
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run", _fake_httpx(
        [_row("https://a.acme.com/api/v1/users", 200, 4096, "application/json")]))

    res = jsluice_verify.verify(src, out, CFG)
    assert res["status"] == "success"

    table = (layout.path(out, "jsluice_alive_table.txt")).read_text()
    header, row = table.splitlines()[0], table.splitlines()[1]
    assert "ST" in header and "LENGTH" in header and "CONTENT-TYPE" in header
    assert "200" in row and "4096" in row and "application/json" in row
    assert "https://a.acme.com/api/v1/users" in row


def test_reuses_rows_already_probed_by_httpx_urls(tmp_path, monkeypatch):
    """A URL the main probe already covered must not be requested again."""
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text(
        "https://a.acme.com/known\nhttps://a.acme.com/new\n", encoding="utf-8")
    write_json(layout.path(out, "alive_urls_detail.json"), [_row("https://a.acme.com/known")])
    (layout.path(out, "alive_urls.txt")).write_text("https://a.acme.com/known\n", encoding="utf-8")

    probed: list[list[str]] = []

    def _run(cmd, **kwargs):
        listed = Path(cmd[cmd.index("-l") + 1]).read_text().split()
        probed.append(listed)
        out_p = Path(cmd[cmd.index("-o") + 1])
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(_row("https://a.acme.com/new")), encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run", _run)

    res = jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    assert probed == [["https://a.acme.com/new"]], "only the unprobed URL"
    assert res["extra"]["reused_from_httpx_urls"] == 1
    assert res["extra"]["newly_probed"] == 1
    # both end up in the jsluice-scoped view
    assert res["count"] == 2


def test_merges_verified_rows_into_alive_urls(tmp_path, monkeypatch):
    """Without this the verification is a dead-end artefact."""
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text("https://a.acme.com/new\n", encoding="utf-8")
    write_json(layout.path(out, "alive_urls_detail.json"), [_row("https://a.acme.com/old")])
    (layout.path(out, "alive_urls.txt")).write_text("https://a.acme.com/old\n", encoding="utf-8")

    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run",
                        _fake_httpx([_row("https://a.acme.com/new")]))

    res = jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    assert res["extra"]["merged_into_alive_urls"] == 1

    alive = (layout.path(out, "alive_urls.txt")).read_text().split()
    assert "https://a.acme.com/old" in alive
    assert "https://a.acme.com/new" in alive
    detail = load_json(layout.path(out, "alive_urls_detail.json"))
    assert len(detail) == 2
    # the companion table is regenerated too
    assert "https://a.acme.com/new" in (layout.path(out, "alive_urls_table.txt")).read_text()


def test_merge_is_idempotent(tmp_path, monkeypatch):
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text("https://a.acme.com/x\n", encoding="utf-8")
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run",
                        _fake_httpx([_row("https://a.acme.com/x")]))

    jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    first = load_json(layout.path(out, "alive_urls_detail.json"))
    jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    assert load_json(layout.path(out, "alive_urls_detail.json")) == first


def test_timeout_salvages_partial_rows(tmp_path, monkeypatch):
    """httpx streams to -o, so a timeout still leaves real verified rows."""
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text(
        "https://a.acme.com/1\nhttps://a.acme.com/2\n", encoding="utf-8")

    def _run(cmd, **kwargs):
        p = Path(cmd[cmd.index("-o") + 1])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(_row("https://a.acme.com/1")), encoding="utf-8")
        return {"success": False, "missing_binary": False, "timed_out": True,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run", _run)

    res = jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    assert res["status"] == "failed"
    assert res["count"] == 1, "the salvaged row is kept"
    assert "salvaged" in res["error"]


def test_hard_failure_reports_failed(tmp_path, monkeypatch):
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text("https://a.acme.com/1\n", encoding="utf-8")
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run", lambda *a, **k: {
        "success": False, "missing_binary": False, "timed_out": False,
        "stdout": "", "stderr": "boom"})
    res = jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    assert res["status"] == "failed"
    assert "boom" in res["error"]


def test_respects_max_urls_cap(tmp_path, monkeypatch):
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text(
        "\n".join(f"https://a.acme.com/{i}" for i in range(10)), encoding="utf-8")
    seen: list[int] = []

    def _run(cmd, **kwargs):
        seen.append(len(Path(cmd[cmd.index("-l") + 1]).read_text().split()))
        p = Path(cmd[cmd.index("-o") + 1])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run", _run)

    cfg = {"httpx": {}, "jsluice": {"verify": {"max_urls": 3}}}
    res = jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, cfg)
    assert seen == [3]
    assert res["extra"]["capped"] is True


def test_ignores_non_http_lines(tmp_path, monkeypatch):
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text(
        "/api/v1/users\nhttps://a.acme.com/ok\nfoo\n", encoding="utf-8")
    seen: list[list[str]] = []

    def _run(cmd, **kwargs):
        seen.append(Path(cmd[cmd.index("-l") + 1]).read_text().split())
        p = Path(cmd[cmd.index("-o") + 1])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run", _run)
    jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG)
    assert seen == [["https://a.acme.com/ok"]]


def test_resume_skips_reprobe(tmp_path, monkeypatch):
    out = _target(tmp_path)
    (layout.path(out, "jsluice_urls.txt")).write_text("https://a.acme.com/x\n", encoding="utf-8")
    (layout.path(out, "jsluice_alive.txt")).write_text("https://a.acme.com/x\n", encoding="utf-8")
    monkeypatch.setattr(jsluice_verify.runner, "run",
                        lambda *a, **k: pytest.fail("must not re-probe"))
    res = jsluice_verify.verify(layout.path(out, "jsluice_urls.txt"), out, CFG, resume=True)
    assert res["status"] == "success"
    assert res["extra"]["resumed"] is True


def test_verify_captures_body_preview(tmp_path, monkeypatch):
    """The GET-verify pass now asks httpx for -bp so a status/length row
    also carries a short body snippet — the earlier version threw it away."""
    out = _target(tmp_path)
    src = layout.path(out, "jsluice_urls.txt")
    src.write_text("https://a.acme.com/api/v1/users\n", encoding="utf-8")
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)

    def _run(cmd, **kwargs):
        assert "-bp" in cmd
        out_p = Path(cmd[cmd.index("-o") + 1])
        out_p.parent.mkdir(parents=True, exist_ok=True)
        row = _row("https://a.acme.com/api/v1/users")
        row["body_preview"] = "  {\"users\":  [] }  \n"
        out_p.write_text(json.dumps(row), encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "run", _run)
    jsluice_verify.verify(src, out, CFG)
    detail = load_json(layout.path(out, "jsluice_alive_detail.json"))
    assert detail[0]["body_preview"] == '{"users": [] }'


# ----------------------------------------------------------------------
# verify_methods — re-probe with the recorded method, not a blind GET
# ----------------------------------------------------------------------
def _params_row(url: str, method: str, q=None, b=None) -> dict:
    return {"url": url, "method": method,
            "queryParams": q or [], "bodyParams": b or []}


def test_method_check_skips_when_no_params_file(tmp_path):
    out = _target(tmp_path)
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, CFG)
    assert res["status"] == "skipped"
    assert "jsluice_params" in (res["error"] or "")


def test_method_check_skips_when_every_method_is_get(tmp_path):
    out = _target(tmp_path)
    write_json(layout.path(out, "jsluice_params.json"),
              [_params_row("https://a.acme.com/x", "GET"),
               _params_row("https://a.acme.com/y", "")])
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, CFG)
    assert res["status"] == "skipped"
    assert "GET" in (res["error"] or "")


def test_method_check_groups_urls_by_method(tmp_path, monkeypatch):
    """Different verbs can't share one httpx -x call, so each method gets
    its own request list."""
    out = _target(tmp_path)
    write_json(layout.path(out, "jsluice_params.json"), [
        _params_row("https://a.acme.com/login", "POST", b=["email", "password"]),
        _params_row("https://a.acme.com/session", "DELETE"),
        _params_row("https://a.acme.com/upload", "POST"),
    ])
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)

    seen_calls: list[tuple[str, list[str]]] = []

    def _run(cmd, **kwargs):
        method = cmd[cmd.index("-x") + 1]
        urls = Path(cmd[cmd.index("-l") + 1]).read_text().split()
        seen_calls.append((method, urls))
        out_p = Path(cmd[cmd.index("-o") + 1])
        out_p.parent.mkdir(parents=True, exist_ok=True)
        rows = [dict(_row(u), method=method) for u in urls]
        out_p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "run", _run)
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, CFG)

    assert res["status"] == "success"
    methods_called = {m for m, _ in seen_calls}
    assert methods_called == {"POST", "DELETE"}
    post_urls = next(u for m, u in seen_calls if m == "POST")
    assert set(post_urls) == {"https://a.acme.com/login", "https://a.acme.com/upload"}

    detail = load_json(layout.path(out, "jsluice_method_check.json"))
    assert {r["url"] for r in detail} == {
        "https://a.acme.com/login", "https://a.acme.com/session",
        "https://a.acme.com/upload"}
    assert all(r["method"] in ("POST", "DELETE") for r in detail)


def test_method_check_flags_a_bypass_over_the_get_baseline(tmp_path, monkeypatch):
    """A route that 404s to GET but answers 200 to its real method (POST)
    is exactly the finding this stage exists to surface."""
    out = _target(tmp_path)
    write_json(layout.path(out, "jsluice_params.json"),
              [_params_row("https://a.acme.com/api/v2/session", "POST")])
    write_json(layout.path(out, "alive_urls_detail.json"),
              [_row("https://a.acme.com/api/v2/session", status=404, length=0)])
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)

    def _run(cmd, **kwargs):
        out_p = Path(cmd[cmd.index("-o") + 1])
        out_p.parent.mkdir(parents=True, exist_ok=True)
        row = _row("https://a.acme.com/api/v2/session", status=200, length=512)
        row["method"] = "POST"
        row["body_preview"] = "{\"token\":\"...\"}"
        out_p.write_text(json.dumps(row), encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "run", _run)
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, CFG)

    assert res["extra"]["method_reveals_more_than_get"] == 1
    detail = load_json(layout.path(out, "jsluice_method_check.json"))
    row = detail[0]
    assert row["status"] == 200
    assert row["get_status"] == 404
    assert row["body_preview"] == '{"token":"..."}'

    table = (layout.path(out, "jsluice_method_check_table.txt")).read_text()
    assert "POST" in table and "200" in table and "404" in table


def test_method_check_respects_max_urls_cap(tmp_path, monkeypatch):
    out = _target(tmp_path)
    write_json(layout.path(out, "jsluice_params.json"), [
        _params_row(f"https://a.acme.com/{i}", "POST") for i in range(10)
    ])
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    seen: list[int] = []

    def _run(cmd, **kwargs):
        seen.append(len(Path(cmd[cmd.index("-l") + 1]).read_text().split()))
        out_p = Path(cmd[cmd.index("-o") + 1])
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text("", encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "run", _run)
    cfg = {"httpx": {}, "jsluice": {"method_check": {"max_urls": 3}}}
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, cfg)
    assert seen == [3]
    assert res["extra"]["capped"] is True


def test_method_check_resume_skips_reprobe(tmp_path, monkeypatch):
    out = _target(tmp_path)
    write_json(layout.path(out, "jsluice_params.json"),
              [_params_row("https://a.acme.com/x", "POST")])
    write_json(layout.path(out, "jsluice_method_check.json"),
              [{"url": "https://a.acme.com/x", "method": "POST", "status": 200}])
    monkeypatch.setattr(jsluice_verify.runner, "run",
                        lambda *a, **k: pytest.fail("must not re-probe"))
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, CFG, resume=True)
    assert res["status"] == "success"
    assert res["extra"]["resumed"] is True


def test_method_check_one_group_failing_does_not_sink_the_others(tmp_path, monkeypatch):
    """POST group hard-fails; DELETE group still succeeds — the stage
    reports what it got rather than throwing the DELETE rows away."""
    out = _target(tmp_path)
    write_json(layout.path(out, "jsluice_params.json"), [
        _params_row("https://a.acme.com/login", "POST"),
        _params_row("https://a.acme.com/session", "DELETE"),
    ])
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)

    def _run(cmd, **kwargs):
        method = cmd[cmd.index("-x") + 1]
        if method == "POST":
            return {"success": False, "missing_binary": False,
                    "timed_out": False, "stdout": "", "stderr": "boom"}
        out_p = Path(cmd[cmd.index("-o") + 1])
        out_p.parent.mkdir(parents=True, exist_ok=True)
        row = dict(_row("https://a.acme.com/session"), method=method)
        out_p.write_text(json.dumps(row), encoding="utf-8")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": ""}

    monkeypatch.setattr(jsluice_verify.runner, "run", _run)
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, CFG)

    assert res["status"] == "success"
    assert res["count"] == 1
    assert "POST: boom" in res["extra"]["group_errors"][0]
    detail = load_json(layout.path(out, "jsluice_method_check.json"))
    assert detail[0]["url"] == "https://a.acme.com/session"


def test_method_check_all_groups_failing_reports_failed(tmp_path, monkeypatch):
    out = _target(tmp_path)
    write_json(layout.path(out, "jsluice_params.json"),
              [_params_row("https://a.acme.com/login", "POST")])
    monkeypatch.setattr(jsluice_verify.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(jsluice_verify.runner, "run", lambda *a, **k: {
        "success": False, "missing_binary": False, "timed_out": False,
        "stdout": "", "stderr": "boom"})
    res = jsluice_verify.verify_methods(
        layout.path(out, "jsluice_params.json"), out, CFG)
    assert res["status"] == "failed"
    assert "boom" in res["error"]
