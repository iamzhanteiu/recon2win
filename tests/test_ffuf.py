"""Tests for the ffuf stage (4.3).

Covers:
  * normalize_targets() — alive.txt → fuzzable base URLs
  * report_name()       — per-target JSON filename sanitisation
  * parse_report()      — ffuf JSON → (status, url), incl. garbage input
  * _build_cmd()        — -ac/-ach, recursion, matchers, extensions
  * scan()              — skip / disabled / empty-input short circuits
"""
from pathlib import Path

from modules import ffuf
from modules.ffuf import (
    _build_cmd,
    _fmt_ext,
    normalize_targets,
    parse_report,
    report_name,
)


# ----------------------------------------------------------------------
# normalize_targets
# ----------------------------------------------------------------------
def test_normalize_targets_strips_path_and_dedupes():
    out = normalize_targets([
        "https://a.example.com/login",
        "https://a.example.com/admin?x=1",
        "https://b.example.com",
    ])
    assert out == ["https://a.example.com", "https://b.example.com"]


def test_normalize_targets_keeps_port_and_scheme():
    out = normalize_targets(["http://a.example.com:8080/x"])
    assert out == ["http://a.example.com:8080"]


def test_normalize_targets_adds_scheme_to_bare_host():
    assert normalize_targets(["a.example.com"]) == ["https://a.example.com"]


def test_normalize_targets_skips_blanks_and_junk():
    assert normalize_targets(["", "   ", "https://"]) == []


# ----------------------------------------------------------------------
# report_name
# ----------------------------------------------------------------------
def test_report_name_sanitises_scheme_and_port():
    assert report_name("https://api.example.com:8443") == "api.example.com_8443.json"


def test_report_name_is_unique_per_scheme_host_pair():
    a = report_name("https://a.example.com")
    b = report_name("http://a.example.com:8080")
    assert a != b


# ----------------------------------------------------------------------
# parse_report
# ----------------------------------------------------------------------
def test_parse_report_extracts_status_and_url():
    text = """
    {"results": [
        {"url": "https://a.example.com/admin", "status": 200, "input": {"FUZZ": "admin"}},
        {"url": "https://a.example.com/api/v1/", "status": 301, "input": {"FUZZ": "api"}}
    ]}
    """
    assert parse_report(text) == [
        (200, "https://a.example.com/admin"),
        (301, "https://a.example.com/api/v1/"),
    ]


def test_parse_report_handles_empty_and_truncated_json():
    # A host killed by the per-host timeout leaves a half-written report.
    assert parse_report("") == []
    assert parse_report("   ") == []
    assert parse_report('{"results": [{"url": "https://a.example.com/x"') == []
    assert parse_report("[1, 2, 3]") == []


def test_parse_report_skips_entries_without_a_usable_url():
    text = '{"results": [{"status": 200}, {"url": "ftp://x/y", "status": 200}]}'
    assert parse_report(text) == []


def test_parse_report_defaults_unparseable_status_to_zero():
    text = '{"results": [{"url": "https://a.example.com/x", "status": "?"}]}'
    assert parse_report(text) == [(0, "https://a.example.com/x")]


# ----------------------------------------------------------------------
# _fmt_ext
# ----------------------------------------------------------------------
def test_fmt_ext_normalises_dotted_and_bare():
    assert _fmt_ext(["php", ".bak", " old "]) == ".php,.bak,.old"


def test_fmt_ext_drops_empties():
    assert _fmt_ext(["", ".", "php"]) == ".php"


# ----------------------------------------------------------------------
# _build_cmd
# ----------------------------------------------------------------------
def _cmd(**kw) -> list[str]:
    return _build_cmd(
        "https://a.example.com", Path("/tmp/a.json"), Path("/tmp/wl.txt"),
        threads=40, **kw,
    )


def test_build_cmd_appends_fuzz_keyword_to_url():
    assert "-u" in _cmd()
    assert _cmd()[_cmd().index("-u") + 1] == "https://a.example.com/FUZZ"


def test_build_cmd_does_not_double_the_slash():
    cmd = _build_cmd("https://a.example.com/", Path("/tmp/a.json"), None, threads=1)
    assert cmd[cmd.index("-u") + 1] == "https://a.example.com/FUZZ"


def test_build_cmd_emits_ac_and_ach_by_default():
    cmd = _cmd()
    assert "-ac" in cmd
    assert "-ach" in cmd


def test_build_cmd_per_host_alone_still_emits_ac():
    # -ach implies -ac inside ffuf; we emit both so the logged argv is explicit.
    cmd = _cmd(autocalibration=False, autocalibration_per_host=True)
    assert "-ac" in cmd and "-ach" in cmd


def test_build_cmd_autocalibration_can_be_disabled():
    cmd = _cmd(autocalibration=False, autocalibration_per_host=False)
    assert "-ac" not in cmd and "-ach" not in cmd


def test_build_cmd_autocalibration_strategy():
    cmd = _cmd(autocalibration_strategy="advanced")
    assert cmd[cmd.index("-acs") + 1] == "advanced"


def test_build_cmd_recursion_flags():
    cmd = _cmd(recursion=True, recursion_depth=3)
    assert "-recursion" in cmd
    assert cmd[cmd.index("-recursion-depth") + 1] == "3"


def test_build_cmd_recursion_strategy_only_when_set():
    assert "-recursion-strategy" not in _cmd()
    cmd = _cmd(recursion_strategy="greedy")
    assert cmd[cmd.index("-recursion-strategy") + 1] == "greedy"


def test_build_cmd_recursion_off_drops_depth():
    cmd = _cmd(recursion=False)
    assert "-recursion" not in cmd and "-recursion-depth" not in cmd


def test_build_cmd_matchers_and_filters():
    cmd = _cmd(match_status=[200, 403], filter_status=[404])
    assert cmd[cmd.index("-mc") + 1] == "200,403"
    assert cmd[cmd.index("-fc") + 1] == "404"


def test_build_cmd_empty_matchers_are_omitted():
    cmd = _cmd(match_status=[], filter_status=[])
    assert "-mc" not in cmd and "-fc" not in cmd


def test_build_cmd_rate_zero_is_omitted():
    assert "-rate" not in _cmd(rate=0)
    assert _cmd(rate=50)[_cmd(rate=50).index("-rate") + 1] == "50"


def test_build_cmd_follow_redirects_off_by_default():
    # -r defeats recursion (ffuf needs to see the redirect itself).
    assert "-r" not in _cmd()
    assert "-r" in _cmd(follow_redirects=True)


def test_build_cmd_extensions():
    cmd = _cmd(extensions=["bak", ".old"])
    assert cmd[cmd.index("-e") + 1] == ".bak,.old"


def test_build_cmd_json_output_and_noninteractive():
    cmd = _cmd()
    assert cmd[cmd.index("-of") + 1] == "json"
    assert cmd[cmd.index("-o") + 1] == "/tmp/a.json"
    assert "-noninteractive" in cmd


def test_build_cmd_without_wordlist_omits_dash_w():
    cmd = _build_cmd("https://a.example.com", Path("/tmp/a.json"), None, threads=1)
    assert "-w" not in cmd


# ----------------------------------------------------------------------
# scan() short circuits
# ----------------------------------------------------------------------
def _alive(tmp_path: Path, body: str = "") -> tuple[Path, Path]:
    out_dir = tmp_path / "out"
    (out_dir / "processed").mkdir(parents=True)
    alive = out_dir / "processed" / "alive.txt"
    alive.write_text(body)
    return alive, out_dir


def test_scan_skip_flag(tmp_path: Path):
    alive, out_dir = _alive(tmp_path, "https://a.example.com\n")
    res = ffuf.scan(alive, out_dir, {}, skip=True)
    assert res["status"] == "skipped"
    assert res["error"] == "--skip-ffuf"
    assert (out_dir / "processed" / "ffuf_urls.txt").read_text() == ""


def test_scan_disabled_in_config(tmp_path: Path):
    alive, out_dir = _alive(tmp_path, "https://a.example.com\n")
    res = ffuf.scan(alive, out_dir, {"ffuf": {"enabled": False}})
    assert res["status"] == "skipped"
    assert res["error"] == "disabled in config"


def test_scan_empty_alive_file_short_circuits(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    alive, out_dir = _alive(tmp_path, "")
    res = ffuf.scan(alive, out_dir, {})
    assert res["status"] == "skipped"
    assert res["error"] == "no alive hosts to scan"


def test_scan_missing_binary_is_skipped_not_failed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: False)
    alive, out_dir = _alive(tmp_path, "https://a.example.com\n")
    res = ffuf.scan(alive, out_dir, {})
    assert res["status"] == "skipped"
    assert "not found" in res["error"]


def test_scan_dry_run_reports_planned_cmd(tmp_path: Path):
    alive, out_dir = _alive(tmp_path, "https://a.example.com\n")
    res = ffuf.scan(alive, out_dir, {"ffuf": {}}, dry_run=True)
    assert res["status"] == "skipped"
    cmd = res["extra"]["planned_cmd"]
    assert cmd[0] == "ffuf"
    assert "https://a.example.com/FUZZ" in cmd
    assert res["extra"]["targets"] == 1


def test_scan_resume_reuses_existing_output(tmp_path: Path):
    alive, out_dir = _alive(tmp_path, "https://a.example.com\n")
    (out_dir / "processed" / "ffuf_urls.txt").write_text(
        "https://a.example.com/admin\nhttps://a.example.com/api\n"
    )
    res = ffuf.scan(alive, out_dir, {}, resume=True)
    assert res["status"] == "success"
    assert res["count"] == 2


def test_scan_merges_hits_from_every_target(tmp_path: Path, monkeypatch):
    """End-to-end with ffuf stubbed: each target writes its own report."""
    alive, out_dir = _alive(
        tmp_path, "https://a.example.com\nhttps://b.example.com\n",
    )
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")

    def fake_run(cmd, **kwargs):
        report = Path(cmd[cmd.index("-o") + 1])
        host = cmd[cmd.index("-u") + 1].replace("/FUZZ", "")
        report.write_text(
            '{"results": [{"url": "%s/admin", "status": 200}]}' % host
        )
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)

    res = ffuf.scan(alive, out_dir, {"ffuf": {"wordlists": [str(wl)]}})
    assert res["status"] == "success"
    assert res["count"] == 2
    urls = (out_dir / "processed" / "ffuf_urls.txt").read_text().split()
    assert urls == ["https://a.example.com/admin", "https://b.example.com/admin"]
    raw = (out_dir / "raw" / "ffuf" / "ffuf_raw.txt").read_text()
    assert "200 https://a.example.com/admin" in raw


def test_scan_caps_targets_at_max_hosts(tmp_path: Path, monkeypatch):
    alive, out_dir = _alive(
        tmp_path, "\n".join(f"https://h{i}.example.com" for i in range(10)),
    )
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    calls: list[str] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd[cmd.index("-u") + 1])
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)

    res = ffuf.scan(
        alive, out_dir,
        {"ffuf": {"wordlists": [str(wl)], "max_hosts": 3, "concurrency": 1}},
    )
    assert len(calls) == 3
    assert res["extra"]["targets"] == 3
    assert res["extra"]["targets_total"] == 10


def test_scan_one_dead_target_does_not_fail_the_stage(tmp_path: Path, monkeypatch):
    alive, out_dir = _alive(
        tmp_path, "https://a.example.com\nhttps://b.example.com\n",
    )
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")

    def fake_run(cmd, **kwargs):
        url = cmd[cmd.index("-u") + 1]
        if "b.example.com" in url:
            return {"success": False, "stderr": "timeout", "missing_binary": False}
        Path(cmd[cmd.index("-o") + 1]).write_text(
            '{"results": [{"url": "https://a.example.com/admin", "status": 200}]}'
        )
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)

    res = ffuf.scan(
        alive, out_dir, {"ffuf": {"wordlists": [str(wl)], "concurrency": 1}},
    )
    assert res["status"] == "success"
    assert res["count"] == 1
    assert res["extra"]["failed_targets"] == 1


def test_scan_all_targets_failing_is_a_failure(tmp_path: Path, monkeypatch):
    alive, out_dir = _alive(tmp_path, "https://a.example.com\n")
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        ffuf.runner, "run",
        lambda cmd, **kw: {"success": False, "stderr": "boom",
                           "missing_binary": False},
    )
    res = ffuf.scan(alive, out_dir, {"ffuf": {"wordlists": [str(wl)]}})
    assert res["status"] == "failed"
    assert "boom" in res["error"]
