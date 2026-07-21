"""Ngân sách thời gian cho hai stage fuzzing.

Vấn đề gốc: ``timeout`` của ffuf là per-host và không có trần tổng — worst
case 50/3 × 1800s = 8.5 giờ. dirsearch thì ngược lại, một con số cố định
chia đều cho mọi host: 3600s / 50 host = 72s/host.
"""
import json
from pathlib import Path

from modules import dirsearch, ffuf


def _setup(tmp_path: Path, n_hosts: int = 1):
    out = tmp_path / "out"
    proc = out / "processed"
    proc.mkdir(parents=True)
    urls = [f"https://h{i}.example.com" for i in range(n_hosts)]
    (proc / "alive.txt").write_text("\n".join(urls) + "\n")
    # words khác nhau → không host nào bị gom, giữ đủ số target để test cap
    (proc / "alive_detail.json").write_text(json.dumps([
        {"url": u, "status_code": 200, "words": i, "lines": 1,
         "title": f"t{i}", "webserver": "nginx"} for i, u in enumerate(urls)]))
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    return proc / "alive.txt", out, wl


# ----------------------------------------------------------------------
# ffuf — trần tổng cho cả stage
# ----------------------------------------------------------------------
def test_ffuf_stops_launching_targets_when_budget_is_gone(
    tmp_path: Path, monkeypatch,
):
    alive, out, wl = _setup(tmp_path, n_hosts=5)
    launched: list[str] = []

    clock = {"t": 0.0}
    monkeypatch.setattr(ffuf.time, "monotonic", lambda: clock["t"])

    def fake_run(cmd, **kw):
        launched.append(cmd[cmd.index("-u") + 1])
        clock["t"] += 40          # mỗi target ngốn 40s
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)

    res = ffuf.scan(alive, out, {"ffuf": {
        "wordlists": [str(wl)], "concurrency": 1, "budget_seconds": 100}})
    # 100s ngân sách / 40s mỗi target → chạy 3, bỏ 2
    assert len(launched) == 3
    assert res["extra"]["skipped_over_budget"] == 2


def test_ffuf_per_host_timeout_clamped_to_remaining_budget(
    tmp_path: Path, monkeypatch,
):
    alive, out, wl = _setup(tmp_path, n_hosts=1)
    seen: list[int] = []
    clock = {"t": 0.0}
    monkeypatch.setattr(ffuf.time, "monotonic", lambda: clock["t"])

    def fake_run(cmd, **kw):
        seen.append(kw["timeout"])
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)
    ffuf.scan(alive, out, {"ffuf": {
        "wordlists": [str(wl)], "timeout": 1800, "budget_seconds": 120}})
    # per-host 1800s nhưng chỉ còn 120s ngân sách
    assert seen[0] == 120


def test_ffuf_budget_zero_means_no_cap(tmp_path: Path, monkeypatch):
    alive, out, wl = _setup(tmp_path, n_hosts=3)
    seen: list[int] = []

    def fake_run(cmd, **kw):
        seen.append(kw["timeout"])
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)
    ffuf.scan(alive, out, {"ffuf": {
        "wordlists": [str(wl)], "timeout": 900, "budget_seconds": 0}})
    assert seen == [900, 900, 900]


def test_targets_skipped_for_budget_are_not_counted_as_failures(
    tmp_path: Path, monkeypatch,
):
    """Bỏ vì hết giờ là quyết định có chủ ý, không phải lỗi."""
    alive, out, wl = _setup(tmp_path, n_hosts=3)
    clock = {"t": 0.0}
    monkeypatch.setattr(ffuf.time, "monotonic", lambda: clock["t"])

    def fake_run(cmd, **kw):
        clock["t"] += 100
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)
    res = ffuf.scan(alive, out, {"ffuf": {
        "wordlists": [str(wl)], "concurrency": 1, "budget_seconds": 50}})
    assert res["status"] == "success"
    assert res["extra"]["skipped_over_budget"] == 2


# ----------------------------------------------------------------------
# dirsearch — timeout phải theo số target
# ----------------------------------------------------------------------
def test_dirsearch_timeout_scales_with_target_count(tmp_path: Path, monkeypatch):
    alive, out, wl = _setup(tmp_path, n_hosts=4)
    seen: list[int] = []
    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        dirsearch.runner, "run",
        lambda cmd, **kw: seen.append(kw["timeout"]) or {
            "success": True, "stderr": "", "stdout": "", "missing_binary": False},
    )
    dirsearch.scan(alive, out, {"dirsearch": {
        "wordlists": [str(wl)], "timeout_per_host": 100, "timeout": 9999}})
    assert seen[0] == 400          # 4 target × 100s


def test_dirsearch_timeout_respects_ceiling(tmp_path: Path, monkeypatch):
    alive, out, wl = _setup(tmp_path, n_hosts=10)
    seen: list[int] = []
    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        dirsearch.runner, "run",
        lambda cmd, **kw: seen.append(kw["timeout"]) or {
            "success": True, "stderr": "", "stdout": "", "missing_binary": False},
    )
    dirsearch.scan(alive, out, {"dirsearch": {
        "wordlists": [str(wl)], "timeout_per_host": 300, "timeout": 600}})
    assert seen[0] == 600          # 10×300 = 3000 nhưng trần là 600


def test_dirsearch_single_target_does_not_wait_for_full_ceiling(
    tmp_path: Path, monkeypatch,
):
    """Sau dedup thường chỉ còn vài target — không nên giữ nguyên trần 3600s."""
    alive, out, wl = _setup(tmp_path, n_hosts=1)
    seen: list[int] = []
    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        dirsearch.runner, "run",
        lambda cmd, **kw: seen.append(kw["timeout"]) or {
            "success": True, "stderr": "", "stdout": "", "missing_binary": False},
    )
    dirsearch.scan(alive, out, {"dirsearch": {"wordlists": [str(wl)]}})
    assert seen[0] == 300          # 1 target × 300s, không phải 3600s


# ----------------------------------------------------------------------
# dirsearch — rate limit (đối xứng với ffuf.rate)
# ----------------------------------------------------------------------
def test_dirsearch_emits_max_rate(tmp_path: Path, monkeypatch):
    alive, out, wl = _setup(tmp_path, n_hosts=1)
    seen: list = []
    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        dirsearch.runner, "run",
        lambda cmd, **kw: seen.append(cmd) or {
            "success": True, "stderr": "", "stdout": "", "missing_binary": False},
    )
    dirsearch.scan(alive, out, {"dirsearch": {
        "wordlists": [str(wl)], "max_rate": 25}})
    assert "--max-rate=25" in seen[0]


def test_dirsearch_rate_zero_is_omitted(tmp_path: Path, monkeypatch):
    alive, out, wl = _setup(tmp_path, n_hosts=1)
    seen: list = []
    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        dirsearch.runner, "run",
        lambda cmd, **kw: seen.append(cmd) or {
            "success": True, "stderr": "", "stdout": "", "missing_binary": False},
    )
    dirsearch.scan(alive, out, {"dirsearch": {
        "wordlists": [str(wl)], "max_rate": 0, "delay": 0}})
    assert not any(c.startswith("--max-rate") for c in seen[0])
    assert not any(c.startswith("--delay") for c in seen[0])


def test_dirsearch_delay_flag(tmp_path: Path, monkeypatch):
    alive, out, wl = _setup(tmp_path, n_hosts=1)
    seen: list = []
    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        dirsearch.runner, "run",
        lambda cmd, **kw: seen.append(cmd) or {
            "success": True, "stderr": "", "stdout": "", "missing_binary": False},
    )
    dirsearch.scan(alive, out, {"dirsearch": {
        "wordlists": [str(wl)], "delay": 0.5}})
    assert "--delay=0.5" in seen[0]
