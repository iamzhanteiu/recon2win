"""Tests for modules/httpx.py alive_check() — the httpx_alive stage.

``-td`` (passive tech-detection) is the precondition for fuzz_depth's
tech-based tiering: without it, alive_detail.json rows never carry a
``tech`` field and a host running Jenkins/Spring under a generic hostname
is indistinguishable from any other host.
"""
from __future__ import annotations

import json

from modules import httpx as httpx_mod, layout
from modules.utils import create_output_structure, write_lines


def test_alive_check_passes_td_flag(tmp_path, monkeypatch):
    base = create_output_structure("example.com", root=str(tmp_path))
    hosts = layout.path(base, "subdomains.txt")
    write_lines(hosts, ["https://example.com"])

    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w") as fh:
            fh.write(json.dumps({"url": "https://example.com",
                                 "status_code": 200}) + "\n")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(httpx_mod.runner, "tool_available", lambda b: True)
    monkeypatch.setattr(httpx_mod.runner, "run", fake_run)

    httpx_mod.alive_check(hosts, base, {})

    assert "-td" in captured["cmd"]
