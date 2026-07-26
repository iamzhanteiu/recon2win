"""Ngân sách thời gian cho hai stage fuzzing.

Vấn đề gốc: ``timeout`` của ffuf là per-host và không có trần tổng — worst
case 50/3 × 1800s = 8.5 giờ. dirsearch thì ngược lại, một con số cố định
chia đều cho mọi host: 3600s / 50 host = 72s/host.
"""
import json
from pathlib import Path

from modules import dirsearch, ffuf
from modules.utils import read_lines


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


def test_ffuf_host_killed_by_budget_cap_is_not_a_failure(
    tmp_path: Path, monkeypatch,
):
    """Một host bị cắt timeout vì hết ngân sách rồi chết đúng ở cái timeout
    đã cắt đó là hệ quả của quyết định ngân sách, không phải target hỏng.

    Run thật 2026-07-25: 3 host báo ``TimeoutExpired after 30s`` và bị đếm
    thành lỗi, trong khi 30s đó là do code cũ dùng ``max(30, remaining)``
    — vừa vượt ngân sách vừa chắc chắn chết.
    """
    alive, out, wl = _setup(tmp_path, n_hosts=2)
    clock = {"t": 0.0}
    monkeypatch.setattr(ffuf.time, "monotonic", lambda: clock["t"])
    seen: list[int] = []

    def fake_run(cmd, **kw):
        seen.append(kw["timeout"])
        clock["t"] += kw["timeout"]
        if kw["timeout"] < 900:          # host thứ 2 bị cắt ngắn → chết
            return {"success": False, "stderr": "TimeoutExpired",
                    "missing_binary": False, "timed_out": True}
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False,
                "timed_out": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)
    res = ffuf.scan(alive, out, {"ffuf": {
        "wordlists": [str(wl)], "timeout": 900, "concurrency": 1,
        "budget_seconds": 1000}})

    # Không host nào được cấp quá phần ngân sách còn lại (900 rồi 100),
    # và cái chết vì bị cắt không bị tính là failure.
    assert seen == [900, 100]
    assert res["extra"]["skipped_over_budget"] == 1
    assert res["extra"]["failed_targets"] == 0


def test_ffuf_real_failure_still_counted_as_failure(tmp_path: Path, monkeypatch):
    """Ngược lại: host chết khi vẫn còn dư ngân sách là lỗi thật."""
    alive, out, wl = _setup(tmp_path, n_hosts=1)

    def fake_run(cmd, **kw):
        return {"success": False, "stderr": "connection refused",
                "missing_binary": False, "timed_out": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)
    res = ffuf.scan(alive, out, {"ffuf": {
        "wordlists": [str(wl)], "timeout": 900, "budget_seconds": 0}})

    assert res["extra"]["skipped_over_budget"] == 0
    assert res["extra"]["failed_targets"] == 1


# ----------------------------------------------------------------------
# dirsearch — ngân sách suy ra từ khối lượng request thật
# ----------------------------------------------------------------------
def test_dirsearch_budget_derives_from_request_volume(tmp_path: Path):
    """Chính con số của run acronis.com 2026-07-25: 50 target × 13,799 từ
    ở 30 req/s là 6.4 giờ, không phải 6000s mà config cũ tưởng."""
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(f"w{i}" for i in range(13799)) + "\n")

    timeout, budget = dirsearch._plan_budget(
        targets=50, wordlist=wl, extensions=None,
        max_rate=30, per_host=120, ceiling=6000,
    )
    assert budget["requests"] == 50 * 13799
    assert budget["wanted"] > 20000          # ~6.4h + slack, KHÔNG phải 6000
    assert budget["over_ceiling"] is True
    assert timeout == 6000                   # vẫn bị trần chặn, nhưng có cảnh báo

    # Ở 200 req/s thì vừa trần.
    timeout, budget = dirsearch._plan_budget(
        targets=50, wordlist=wl, extensions=None,
        max_rate=200, per_host=120, ceiling=6000,
    )
    assert budget["over_ceiling"] is False
    assert timeout == budget["wanted"] < 6000


def test_dirsearch_budget_counts_extension_multiplier(tmp_path: Path):
    """``-e`` nhân số request lên: mỗi từ thử thêm một lần mỗi extension."""
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nbackup\n")
    _, plain = dirsearch._plan_budget(
        targets=10, wordlist=wl, extensions=None,
        max_rate=100, per_host=120, ceiling=99999)
    _, with_ext = dirsearch._plan_budget(
        targets=10, wordlist=wl, extensions=[".bak", ".sql", ".zip"],
        max_rate=100, per_host=120, ceiling=99999)
    assert plain["requests"] == 20
    assert with_ext["requests"] == 20 * 4     # 1 trần + 3 extension


def test_dirsearch_budget_falls_back_to_per_host_without_rate(tmp_path: Path):
    """max_rate=0 → không suy ra được rps, quay về cách tính cũ theo host."""
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    timeout, budget = dirsearch._plan_budget(
        targets=4, wordlist=wl, extensions=None,
        max_rate=0, per_host=120, ceiling=99999,
    )
    assert timeout == 480
    assert "4 host × 120s" in budget["basis"]


def test_dirsearch_salvages_partial_results_on_timeout(tmp_path: Path, monkeypatch):
    """dirsearch ghi report ``-o`` dần dần, nên một run bị kill ở timeout
    vẫn để lại đúng những gì nó đã tìm được. Code cũ return failed/count=0
    mà không hề mở file → vứt sạch kết quả thật."""
    alive, out, wl = _setup(tmp_path, n_hosts=2)

    def fake_run(cmd, **kw):
        # ghi 2 hit rồi "bị kill"
        Path(cmd[cmd.index("-o") + 1]).write_text(
            "200    26B   https://h0.example.com/robots.txt\n"
            "403    12B   https://h1.example.com/admin\n"
        )
        return {"success": False, "stdout": "",
                "stderr": "TimeoutExpired after 6000s",
                "missing_binary": False, "timed_out": True}

    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(dirsearch.runner, "run", fake_run)
    res = dirsearch.scan(alive, out, {"dirsearch": {"wordlists": [str(wl)]}})

    assert res["status"] == "success"
    assert res["count"] == 2
    assert res["extra"]["timed_out"] is True
    assert "salvaged 2" in res["error"]
    assert len(read_lines(out / "processed" / "dirsearch_urls.txt")) == 2


def test_dirsearch_fails_only_when_nothing_salvaged(tmp_path: Path, monkeypatch):
    alive, out, wl = _setup(tmp_path, n_hosts=1)

    def fake_run(cmd, **kw):
        return {"success": False, "stdout": "", "stderr": "boom",
                "missing_binary": False, "timed_out": False}

    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(dirsearch.runner, "run", fake_run)
    res = dirsearch.scan(alive, out, {"dirsearch": {"wordlists": [str(wl)]}})
    assert res["status"] == "failed"
    assert res["count"] == 0
