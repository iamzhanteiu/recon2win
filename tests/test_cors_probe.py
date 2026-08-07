from __future__ import annotations

import json
from pathlib import Path

from modules import cors_probe, layout
from modules.utils import write_lines

TEST_ORIGIN = "https://recon2win-cors-test.invalid"


# ----------------------------------------------------------------------
# classify — pure logic, no I/O
# ----------------------------------------------------------------------
def test_classify_reflects_with_credentials_is_critical():
    hit = cors_probe.classify(
        "https://x.com",
        {"access_control_allow_origin": TEST_ORIGIN,
         "access_control_allow_credentials": "true"},
        TEST_ORIGIN,
    )
    assert hit is not None
    assert hit["severity"] == "critical"


def test_classify_reflects_without_credentials_is_medium():
    hit = cors_probe.classify(
        "https://x.com",
        {"access_control_allow_origin": TEST_ORIGIN},
        TEST_ORIGIN,
    )
    assert hit is not None
    assert hit["severity"] == "medium"


def test_classify_wildcard_with_credentials_flagged():
    hit = cors_probe.classify(
        "https://x.com",
        {"access_control_allow_origin": "*",
         "access_control_allow_credentials": "true"},
        TEST_ORIGIN,
    )
    assert hit is not None
    assert hit["severity"] == "medium"


def test_classify_bare_wildcard_is_not_a_finding():
    """ACAO: * with no credentials is normal, intentional public-API CORS."""
    hit = cors_probe.classify(
        "https://x.com", {"access_control_allow_origin": "*"}, TEST_ORIGIN,
    )
    assert hit is None


def test_classify_fixed_allowlist_origin_is_not_a_finding():
    """A server that only ever allows its own known origin is correct
    behaviour, not a bug — must not fire just because *a* CORS header exists."""
    hit = cors_probe.classify(
        "https://x.com",
        {"access_control_allow_origin": "https://trusted-partner.example"},
        TEST_ORIGIN,
    )
    assert hit is None


def test_classify_no_cors_header_is_not_a_finding():
    assert cors_probe.classify("https://x.com", {}, TEST_ORIGIN) is None
    assert cors_probe.classify("https://x.com", None, TEST_ORIGIN) is None


# ----------------------------------------------------------------------
# discover — config gating + end-to-end with a faked runner
# ----------------------------------------------------------------------
def _make_alive(tmp_path: Path, hosts: list[str]) -> Path:
    (tmp_path / "processed").mkdir(parents=True, exist_ok=True)
    (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
    alive = layout.path(tmp_path, "alive.txt")
    write_lines(alive, hosts)
    return alive


def test_discover_enabled_by_default(tmp_path: Path, monkeypatch):
    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("")
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 0.1}
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    alive = _make_alive(tmp_path, ["https://x.com"])
    res = cors_probe.discover(alive, tmp_path, cfg={}, resume=False, dry_run=False)
    assert res["status"] == "success"
    assert (tmp_path / "findings" / "cors.json").exists()


def test_discover_disabled_via_config(tmp_path: Path):
    alive = _make_alive(tmp_path, ["https://x.com"])
    cfg = {"cors_probe": {"enabled": False}}
    res = cors_probe.discover(alive, tmp_path, cfg=cfg, resume=False, dry_run=False)
    assert res["status"] == "skipped"
    assert "disabled" in res["error"]


def test_discover_skip_flag(tmp_path: Path):
    alive = _make_alive(tmp_path, ["https://x.com"])
    res = cors_probe.discover(alive, tmp_path, cfg={}, resume=False,
                              dry_run=False, skip=True)
    assert res["status"] == "skipped"
    assert "skip-cors-probe" in res["error"]


def test_discover_end_to_end_with_fake_httpx(tmp_path: Path, monkeypatch):
    rows = [
        {"url": "https://vuln.example", "header": {
            "access_control_allow_origin": TEST_ORIGIN,
            "access_control_allow_credentials": "true"}},
        {"url": "https://safe.example", "header": {
            "access_control_allow_origin": "https://safe.example"}},
    ]

    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(json.dumps(r) for r in rows))
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 0.1}

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    alive = _make_alive(tmp_path, ["https://vuln.example", "https://safe.example"])
    res = cors_probe.discover(alive, tmp_path, cfg={}, resume=False, dry_run=False)

    assert res["status"] == "success"
    assert res["count"] == 1
    data = json.loads((tmp_path / "findings" / "cors.json").read_text())
    assert len(data["findings"]) == 1
    assert data["findings"][0]["url"] == "https://vuln.example"
    assert data["findings"][0]["severity"] == "critical"
