"""Tests for nuclei.endpoints_scan — scanning discovered live endpoints.

Closes the coverage gap where nuclei_default only saw the root hosts.
endpoints_scan runs after discovery on alive_urls.txt and writes to
findings/endpoints/.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import nuclei as nuclei_mod
from modules.nuclei import _filter_endpoint_urls
from modules.utils import create_output_structure, read_lines, write_lines


def _fake_run_writes_json(captured: list):
    """Return a runner.run stand-in that records argv and writes a finding
    to the ``-o`` JSONL path so _run's parser has something to read."""
    def _fake(cmd, **kw):
        captured.clear()
        captured.extend(cmd)
        jpath = Path(cmd[cmd.index("-o") + 1])
        jpath.parent.mkdir(parents=True, exist_ok=True)
        jpath.write_text(json.dumps(
            {"template-id": "backup-file",
             "info": {"name": "Backup", "severity": "medium"},
             "matched-at": "https://x.com/backup.zip"},
        ) + "\n")
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "", "duration": 1}
    return _fake


def test_endpoints_scan_writes_to_endpoints_findings_dir(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run_writes_json(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/backup.zip", "https://x.com/a"])

    res = nuclei_mod.endpoints_scan(alive_urls, base, {}, skip=False)
    assert res["status"] == "success"
    assert res["stage"] == "nuclei_endpoints"
    # output must land in findings/endpoints/, not default/dynamic
    assert (base / "findings" / "endpoints" / "nuclei.json").exists()
    assert res["count"] == 1
    # default severity is critical,high,medium (no info/low noise)
    sev = captured[captured.index("-severity") + 1]
    assert sev == "critical,high,medium"


def test_endpoints_scan_respects_custom_severity(tmp_path, monkeypatch):
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run_writes_json(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/a"])

    cfg = {"nuclei": {"endpoints": {"severity": ["critical", "high"]}}}
    nuclei_mod.endpoints_scan(alive_urls, base, cfg, skip=False)
    assert captured[captured.index("-severity") + 1] == "critical,high"


def test_endpoints_scan_disabled_in_config(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/a"])

    cfg = {"nuclei": {"endpoints": {"enabled": False}}}
    res = nuclei_mod.endpoints_scan(alive_urls, base, cfg, skip=False)
    assert res["status"] == "skipped"
    assert "disabled" in (res["error"] or "")


def test_endpoints_scan_skip_flag(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, ["https://x.com/a"])

    res = nuclei_mod.endpoints_scan(alive_urls, base, {}, skip=True)
    assert res["status"] == "skipped"
    # skip still writes empty artefacts so downstream readers don't crash
    assert (base / "findings" / "endpoints" / "nuclei.json").exists()


# ----------------------------------------------------------------------
# _filter_endpoint_urls — pure helper, no requirement for a query param
# (unlike _filter_param_urls, which only exists to feed dynamic_scan)
# ----------------------------------------------------------------------
def test_filter_endpoint_urls_dedups_same_host_path(tmp_path):
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, [
        "https://x.com/a?ref=1",
        "https://x.com/a?ref=2",   # same host+path, different query → dedup
        "https://x.com/b",
    ])
    scan_file, stats = _filter_endpoint_urls(inp, tmp_path)

    assert stats["deduped"] == 1
    assert stats["selected"] == 2
    assert read_lines(scan_file) == ["https://x.com/a?ref=1", "https://x.com/b"]


def test_filter_endpoint_urls_noop_when_nothing_to_change(tmp_path):
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, ["https://x.com/a", "https://x.com/b"])
    scan_file, stats = _filter_endpoint_urls(inp, tmp_path)

    assert stats["deduped"] == 0
    assert stats["capped"] == 0
    assert scan_file == inp
    assert not (tmp_path / "raw" / "nuclei_endpoints" / "endpoint_urls.txt").exists()


def test_filter_endpoint_urls_caps_keeping_high_value(tmp_path):
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    write_lines(inp, [
        "https://x.com/blog/post-1",     # low value
        "https://x.com/api/v1/user",     # high value (api hint)
        "https://x.com/blog/post-2",     # low value
    ])
    scan_file, stats = _filter_endpoint_urls(inp, tmp_path, max_urls=1)

    assert stats["capped"] == 2
    assert stats["selected"] == 1
    assert read_lines(scan_file) == ["https://x.com/api/v1/user"]


def test_endpoints_scan_caps_large_url_list(tmp_path, monkeypatch):
    """10k+ discovered URLs must not all be handed to nuclei uncapped —
    the exact failure mode that walled a real scan at its 7200s timeout
    with 0 findings (see logs/stages.json from that run)."""
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run_writes_json(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    alive_urls = base / "processed" / "alive_urls.txt"
    write_lines(alive_urls, [f"https://x.com/p{i}" for i in range(20)])

    cfg = {"nuclei": {"endpoints": {"max_urls": 5}}}
    res = nuclei_mod.endpoints_scan(alive_urls, base, cfg, skip=False)

    scanned = read_lines(Path(captured[captured.index("-l") + 1]))
    assert len(scanned) == 5
    assert res["extra"]["url_filter"]["capped"] == 15


# ----------------------------------------------------------------------
# per-host cap — the endpoints scan's real budget lever
#
# A global max_urls cut ranks every URL against every other, so one host
# with a big crawled surface takes the whole list. Measured on a real
# discover.com run: the top-2000 global selection gave 1907 slots (95%) to
# apps.discover.com and left 44 other hosts with 0-24 URLs between them —
# and contained only 13 URLs that returned 200.
# ----------------------------------------------------------------------
def _detail(base, rows: list[tuple[str, int]]) -> None:
    """Write the httpx probe detail the filter reads status codes from."""
    proc = base / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "alive_urls_detail.json").write_text(json.dumps(
        [{"url": u, "status_code": sc} for u, sc in rows]))


def test_filter_endpoint_urls_caps_per_host(tmp_path):
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    urls = [f"https://big.x.com/p{i}" for i in range(50)]
    urls += [f"https://small.x.com/q{i}" for i in range(3)]
    write_lines(inp, urls)

    scan_file, stats = _filter_endpoint_urls(inp, tmp_path, max_per_host=5)

    kept = read_lines(scan_file)
    hosts = [u.split("/")[2] for u in kept]
    assert hosts.count("big.x.com") == 5      # capped
    assert hosts.count("small.x.com") == 3    # untouched, under the cap
    assert stats["per_host_capped"] == 45
    assert stats["selected"] == 8


def test_per_host_cap_applies_before_max_urls(tmp_path):
    """Order matters: capping globally first lets one host eat every slot,
    which is exactly the failure the per-host cap exists to prevent."""
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    urls = [f"https://big.x.com/p{i}" for i in range(100)]
    urls += [f"https://other{i}.x.com/a" for i in range(6)]
    write_lines(inp, urls)

    _, stats = _filter_endpoint_urls(
        inp, tmp_path, max_urls=10, max_per_host=2)

    assert stats["per_host_capped"] == 98     # big.x.com 100 → 2
    assert stats["selected"] == 8             # 2 + 6, under max_urls


def test_blanket_403_host_gets_the_tighter_cap(tmp_path):
    """A host whose edge answers every path — including paths that do not
    exist — is one target, not N. It keeps a sample, not the full list."""
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    waf = [f"https://waf.x.com/p{i}" for i in range(40)]
    real = [f"https://app.x.com/q{i}" for i in range(40)]
    write_lines(inp, waf + real)
    _detail(tmp_path, [(u, 403) for u in waf] + [(u, 200) for u in real])

    scan_file, stats = _filter_endpoint_urls(
        inp, tmp_path, max_per_host=20, waf_host_max=3)

    hosts = [u.split("/")[2] for u in read_lines(scan_file)]
    assert hosts.count("waf.x.com") == 3       # tighter cap
    assert hosts.count("app.x.com") == 20      # normal cap
    assert stats["waf_hosts"] == ["waf.x.com"]


def test_blanket_403_detection_needs_a_big_enough_sample(tmp_path):
    """Three 403s could just be three protected paths — that is a real
    signal about the origin, not a WAF answering for it."""
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    urls = [f"https://x.com/p{i}" for i in range(4)]
    write_lines(inp, urls)
    _detail(tmp_path, [(u, 403) for u in urls])

    _, stats = _filter_endpoint_urls(
        inp, tmp_path, max_per_host=20, waf_host_max=1)

    assert "waf_hosts" not in stats            # sample under the threshold


def test_401_is_not_treated_as_blanket_blocked(tmp_path):
    """401 means the app answered "authenticate" — informative, worth
    scanning. Only 403/406/429 in bulk mean the edge never forwarded."""
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    urls = [f"https://auth.x.com/p{i}" for i in range(30)]
    write_lines(inp, urls)
    _detail(tmp_path, [(u, 401) for u in urls])

    _, stats = _filter_endpoint_urls(
        inp, tmp_path, max_per_host=20, waf_host_max=1)

    assert "waf_hosts" not in stats


def test_missing_probe_detail_degrades_to_no_waf_hosts(tmp_path):
    """No alive_urls_detail.json (httpx died, older output dir) must cost
    scan time, never coverage."""
    inp = tmp_path / "processed" / "alive_urls.txt"
    inp.parent.mkdir(parents=True)
    urls = [f"https://x.com/p{i}" for i in range(30)]
    write_lines(inp, urls)

    scan_file, stats = _filter_endpoint_urls(
        inp, tmp_path, max_per_host=20, waf_host_max=1)

    assert "waf_hosts" not in stats
    assert len(read_lines(scan_file)) == 20    # plain per-host cap still applies


def test_endpoints_scan_spreads_budget_across_hosts(tmp_path, monkeypatch):
    """End-to-end shape of the discover.com regression: one WAF-blocked
    host owns 95% of the crawl, and used to own 95% of the scan budget."""
    captured: list = []
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake_run_writes_json(captured))

    base = create_output_structure("x.com", root=str(tmp_path))
    alive = base / "processed" / "alive_urls.txt"
    waf = [f"https://apps.x.com/p{i}" for i in range(400)]
    real = [f"https://real{i}.x.com/a" for i in range(20)]
    write_lines(alive, waf + real)
    _detail(base, [(u, 403) for u in waf] + [(u, 200) for u in real])

    cfg = {"nuclei": {"endpoints": {
        "max_urls": 0, "max_per_host": 100, "waf_host_max": 25}}}
    res = nuclei_mod.endpoints_scan(alive, base, cfg, skip=False)

    scanned = read_lines(Path(captured[captured.index("-l") + 1]))
    hosts = [u.split("/")[2] for u in scanned]
    assert hosts.count("apps.x.com") == 25     # was 400
    assert len(scanned) == 45                  # 25 + 20 real hosts
    assert res["extra"]["url_filter"]["waf_hosts"] == ["apps.x.com"]
