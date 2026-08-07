"""Tests for xnLinkFinder scope handling.

The scope filter (-sf) must be the TARGET ROOT DOMAIN so in-scope links
from JS served on ANY subdomain are kept — not just the first JS URL's
host (the old bug silently dropped links from other subdomains).
"""
from __future__ import annotations


from modules import layout, xnlinkfinder as xf
from modules.utils import create_output_structure, write_lines


def _fake_run(captured: list):
    def _run(cmd, **kw):
        captured.clear()
        captured.extend(cmd)
        return {"returncode": 0, "stdout": "", "stderr": "", "success": True,
                "missing_binary": False, "timed_out": False,
                "stdout_path": "", "stderr_path": "", "log_path": "", "duration": 1}
    return _run


def test_scope_is_target_root_domain_not_first_js_host(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run(captured))

    base = create_output_structure("vulnweb.com", root=str(tmp_path))
    js = layout.path(base, "js_urls.txt")
    # JS served from TWO different subdomains
    write_lines(js, [
        "http://rest.vulnweb.com/a.js",
        "http://testasp.vulnweb.com/b.js",
    ])
    res = xf.scan(js, base, {}, skip=False)
    assert res["status"] == "success"
    i = captured.index("-sf")
    # root domain → xnLinkFinder regex keeps *.vulnweb.com (both subdomains),
    # NOT just rest.vulnweb.com (the first JS host)
    assert captured[i + 1] == "vulnweb.com"
    assert captured[i + 1] != "rest.vulnweb.com"


def test_scope_uses_output_dir_name(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run(captured))

    base = create_output_structure("example.org", root=str(tmp_path))
    js = layout.path(base, "js_urls.txt")
    write_lines(js, ["https://cdn.example.org/app.js"])
    xf.scan(js, base, {}, skip=False)
    assert captured[captured.index("-sf") + 1] == "example.org"


def test_skips_when_no_js_urls(tmp_path, monkeypatch):
    called = {"run": False}

    def _run(cmd, **kw):
        called["run"] = True
        return {"returncode": 0, "stdout": "", "success": True,
                "missing_binary": False, "timed_out": False,
                "stdout_path": "", "stderr_path": "", "log_path": "", "duration": 1}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _run)

    base = create_output_structure("x.com", root=str(tmp_path))
    js = layout.path(base, "js_urls.txt")
    write_lines(js, [])
    res = xf.scan(js, base, {}, skip=False)
    assert res["status"] == "skipped"
    assert not called["run"]  # xnLinkFinder not invoked with an empty scope


def test_classify_url_vs_endpoint():
    assert xf._classify("https://x.com/api") == "url"
    assert xf._classify("/api/v1/users") == "endpoint"
    assert xf._classify("not a link") is None
    assert xf._classify("") is None
