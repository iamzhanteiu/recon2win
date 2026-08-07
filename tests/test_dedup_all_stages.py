"""Bước chọn target phải áp cho MỌI stage nhận alive.txt, không chỉ fuzzing.

katana crawl 200 host wildcard cùng phục vụ một app lãng phí y như fuzz
chúng. nuclei thì khác — dedup ở đó là đánh đổi coverage nên mặc định tắt.
"""
import json
from pathlib import Path

from modules import content_discovery, layout, nuclei


def _setup(tmp_path: Path, n: int = 20):
    out = tmp_path / "out"
    urls = [f"https://h{i}.example.com" for i in range(n)]
    (layout.path(out, "alive.txt")).write_text("\n".join(urls) + "\n")
    (layout.path(out, "alive_detail.json")).write_text(json.dumps([
        {"url": u, "status_code": 200, "words": 27, "lines": 1,
         "title": "Home", "webserver": "nginx"} for u in urls]))
    return layout.path(out, "alive.txt"), out


def test_katana_crawls_deduped_target_list(tmp_path: Path, monkeypatch):
    alive, out = _setup(tmp_path)
    seen: list[str] = []

    def fake_run(cmd, **kw):
        if cmd[0] == "katana":
            seen.append(cmd[cmd.index("-list") + 1])
            Path(cmd[cmd.index("-output") + 1]).write_text("")
        return {"success": True, "stderr": "", "stdout": "",
                "missing_binary": False}

    monkeypatch.setattr(
        content_discovery.runner, "tool_available",
        lambda b: b == "katana")
    monkeypatch.setattr(content_discovery.runner, "run", fake_run)
    res = content_discovery.crawl(alive, out, {})
    assert seen[0].endswith("targets.txt")
    assert len(Path(seen[0]).read_text().split()) == 1     # 20 → 1
    assert res["extra"]["selection"]["deduped"] == 19


def test_katana_dedup_can_be_disabled(tmp_path: Path, monkeypatch):
    alive, out = _setup(tmp_path)
    seen: list[str] = []

    def fake_run(cmd, **kw):
        if cmd[0] == "katana":
            seen.append(cmd[cmd.index("-list") + 1])
            Path(cmd[cmd.index("-output") + 1]).write_text("")
        return {"success": True, "stderr": "", "stdout": "",
                "missing_binary": False}

    monkeypatch.setattr(
        content_discovery.runner, "tool_available", lambda b: b == "katana")
    monkeypatch.setattr(content_discovery.runner, "run", fake_run)
    content_discovery.crawl(
        alive, out, {"content_discovery": {"dedup_targets": False}})
    assert seen[0].endswith("alive.txt")
    assert len(Path(seen[0]).read_text().split()) == 20


def test_nuclei_scans_every_host_by_default(tmp_path: Path, monkeypatch):
    """Mặc định KHÔNG dedup: bỏ sót một finding đắt hơn vài phút quét thừa."""
    alive, out = _setup(tmp_path)
    seen: list[str] = []

    def fake_run(cmd, **kw):
        if "-l" in cmd:
            seen.append(cmd[cmd.index("-l") + 1])
        return {"success": True, "stderr": "", "stdout": "",
                "missing_binary": False}

    monkeypatch.setattr(nuclei.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(nuclei.runner, "run", fake_run)
    nuclei.default_scan(alive, out, {})
    assert seen and seen[0].endswith("alive.txt")
    assert len(Path(seen[0]).read_text().split()) == 20


def test_nuclei_dedup_is_opt_in(tmp_path: Path, monkeypatch):
    alive, out = _setup(tmp_path)
    seen: list[str] = []

    def fake_run(cmd, **kw):
        if "-l" in cmd:
            seen.append(cmd[cmd.index("-l") + 1])
        return {"success": True, "stderr": "", "stdout": "",
                "missing_binary": False}

    monkeypatch.setattr(nuclei.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(nuclei.runner, "run", fake_run)
    nuclei.default_scan(
        alive, out, {"nuclei": {"default": {"dedup_targets": True}}})
    assert seen and seen[0].endswith("targets.txt")
    assert len(Path(seen[0]).read_text().split()) == 1
