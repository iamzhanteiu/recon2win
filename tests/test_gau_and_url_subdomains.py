"""Tests for gau (content discovery) + URL-derived subdomains (url_merge)."""
from __future__ import annotations

from pathlib import Path

from modules import content_discovery as cd
from modules.url_merge import derive_subdomains_from_urls, extract_in_scope_hosts
from modules.utils import create_output_structure, read_lines, write_lines


# ----------------------------------------------------------------------
# gau in content_discovery
# ----------------------------------------------------------------------
def _fake_cd_run(captured: list):
    def _run(cmd, **kw):
        captured.append(list(cmd))
        # emulate the tool writing its -o/-output file
        for flag in ("-o", "--o", "-output"):
            if flag in cmd:
                p = Path(cmd[cmd.index(flag) + 1])
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.write_text("")
        return {"returncode": 0, "stdout": "", "stderr": "", "success": True,
                "missing_binary": False, "timed_out": False,
                "stdout_path": "", "stderr_path": "", "log_path": "", "duration": 1}
    return _run


def test_gau_invoked_with_subs_and_root_domain(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_cd_run(captured))

    base = create_output_structure("vulnweb.com", root=str(tmp_path))
    write_lines(base / "processed" / "alive.txt", ["https://vulnweb.com"])
    # only enable gau to keep the assertion focused
    cfg = {"content_discovery": {"katana": {"enabled": False},
                                 "urlfinder": {"enabled": False},
                                 "gau": {"enabled": True}}}
    cd.crawl(base / "processed" / "alive.txt", base, cfg,
             resume=False, dry_run=False)

    gau_cmds = [c for c in captured if c and c[0] == "gau"]
    assert gau_cmds, "gau was not invoked"
    cmd = gau_cmds[0]
    assert "--subs" in cmd
    assert cmd[-1] == "vulnweb.com"          # root domain as the target
    assert (base / "raw" / "content_discovery" / "gau_urls.txt").exists()


def test_gau_disabled_writes_empty_and_no_call(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_cd_run(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    write_lines(base / "processed" / "alive.txt", ["https://x.com"])
    cfg = {"content_discovery": {"katana": {"enabled": False},
                                 "urlfinder": {"enabled": False},
                                 "gau": {"enabled": False}}}
    cd.crawl(base / "processed" / "alive.txt", base, cfg,
             resume=False, dry_run=False)
    assert not [c for c in captured if c and c[0] == "gau"]
    assert (base / "raw" / "content_discovery" / "gau_urls.txt").exists()


# ----------------------------------------------------------------------
# extract_in_scope_hosts — pure
# ----------------------------------------------------------------------
def test_extract_in_scope_hosts_filters_and_dedupes():
    urls = [
        "https://a.example.com/x",
        "https://a.example.com/y",       # dup host
        "https://b.example.com/z",
        "https://example.com/",          # apex
        "https://evil.com/out",          # out of scope
        "https://notexample.com/",       # lookalike, not a subdomain
    ]
    hosts = extract_in_scope_hosts(urls, "example.com")
    assert hosts == ["a.example.com", "b.example.com", "example.com"]


def test_extract_in_scope_hosts_handles_bare_and_empty():
    assert extract_in_scope_hosts(["a.x.com"], "x.com") == ["a.x.com"]
    assert extract_in_scope_hosts(["https://a.x.com"], "") == []
    assert extract_in_scope_hosts([], "x.com") == []


# ----------------------------------------------------------------------
# derive_subdomains_from_urls — new-only
# ----------------------------------------------------------------------
def test_derive_writes_only_new_subdomains(tmp_path):
    base = create_output_structure("x.com", root=str(tmp_path))
    write_lines(base / "processed" / "all_urls.txt", [
        "https://known.x.com/a",
        "https://new1.x.com/b",
        "https://new2.x.com/c",
        "https://cdn.other.com/z",       # out of scope → ignored
    ])
    write_lines(base / "processed" / "subdomains.txt", ["known.x.com", "x.com"])

    res = derive_subdomains_from_urls(base, "x.com")
    assert res["count"] == 2
    out = read_lines(base / "processed" / "url_derived_subdomains.txt")
    assert out == ["new1.x.com", "new2.x.com"]
    assert "known.x.com" not in out       # already known → excluded


def test_derive_noop_when_all_known(tmp_path):
    base = create_output_structure("x.com", root=str(tmp_path))
    write_lines(base / "processed" / "all_urls.txt", ["https://a.x.com/1"])
    write_lines(base / "processed" / "subdomains.txt", ["a.x.com"])
    res = derive_subdomains_from_urls(base, "x.com")
    assert res["count"] == 0
