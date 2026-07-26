"""Tests for dirsearch chunking (dirsearch.chunk_size).

The regression this exists to prevent: the stage used to call dirsearch
EXACTLY ONCE over the whole target list. dirsearch walks targets
sequentially, so a kill at the stage timeout meant every host that hadn't
come up yet was never scanned at all. Measured on a real acronis.com run —
50 targets selected, results only from targets #1, #3 and #9, i.e. ~82% of
the selected hosts never touched. discover.com had the same shape (4/43).

A better budget estimate does not fix that: both runs died at exactly the
``wanted`` value _plan_budget computed for them (4484s, 3856s) even with
_BUDGET_SLACK 1.3 applied, because the real rate never reaches ``max_rate``.
Chunking is what bounds the loss.
"""
from __future__ import annotations

from pathlib import Path

from modules import dirsearch as ds
from modules.utils import create_output_structure, read_lines, write_lines


def _fake_run_factory(timeouts=None, hits_per_call=1):
    """runner.run stand-in: writes ``hits_per_call`` dirsearch-format hits
    to the ``-o`` path, mirroring the real incremental report."""
    timeouts = timeouts or set()
    state = {"calls": 0, "targets": [], "timeouts": []}

    def _fake(cmd, **kw):
        i = state["calls"]
        state["calls"] += 1
        tfile = Path(cmd[cmd.index("-l") + 1])
        chunk = read_lines(tfile)
        state["targets"].append(chunk)
        state["timeouts"].append(kw.get("timeout"))
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("".join(
            f"200    26B   {h}/hit{i}\n" for h in chunk[:hits_per_call]))
        to = i in timeouts
        return {"returncode": 0 if not to else 1, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": to, "success": not to,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 1}
    return _fake, state


def _base(tmp_path, n_hosts, wordlist_words=10):
    base = create_output_structure("x.com", root=str(tmp_path))
    alive = base / "processed" / "alive.txt"
    write_lines(alive, [f"https://h{i}.x.com" for i in range(n_hosts)])
    wl = tmp_path / "wl.txt"
    write_lines(wl, [f"w{i}" for i in range(wordlist_words)])
    return base, alive, wl


def _cfg(wl, **over):
    d = {"wordlists": [str(wl)], "max_hosts": 0, "dedup_targets": False,
         "max_rate": 10, "timeout": 100000, "chunk_size": 4}
    d.update(over)
    return {"dirsearch": d}


def test_chunking_splits_targets_across_invocations(tmp_path, monkeypatch):
    fake, state = _fake_run_factory()
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive, wl = _base(tmp_path, 10)
    res = ds.scan(alive, base, _cfg(wl), skip=False)

    assert [len(c) for c in state["targets"]] == [4, 4, 2]
    # every selected host reached dirsearch exactly once
    assert sum(len(c) for c in state["targets"]) == 10
    assert res["extra"]["chunks"]["run"] == 3
    assert res["extra"]["chunks"]["unrun"] == 0


def test_chunk_size_zero_keeps_the_single_run_behaviour(tmp_path, monkeypatch):
    fake, state = _fake_run_factory()
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive, wl = _base(tmp_path, 10)
    res = ds.scan(alive, base, _cfg(wl, chunk_size=0), skip=False)

    assert state["calls"] == 1
    assert len(state["targets"][0]) == 10
    assert "chunks" not in res["extra"]


def test_a_timed_out_chunk_does_not_lose_the_earlier_ones(tmp_path, monkeypatch):
    """The whole point. Chunk 0 succeeds, chunk 1 dies — chunk 0's hits must
    still be on disk, and the remaining hosts still get scanned."""
    fake, state = _fake_run_factory(timeouts={1})
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive, wl = _base(tmp_path, 12)
    res = ds.scan(alive, base, _cfg(wl), skip=False)

    assert res["count"] > 0
    assert res["extra"]["timed_out"] is True
    # a partial stage is still success — the finished chunks are real results
    assert res["status"] == "success"
    # and it did NOT stop at the timeout
    assert state["calls"] >= 3


def test_chunk_halves_after_a_timeout(tmp_path, monkeypatch):
    fake, state = _fake_run_factory(timeouts={0})
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive, wl = _base(tmp_path, 16)
    res = ds.scan(alive, base, _cfg(wl, chunk_size=8, chunk_min_size=1),
                  skip=False)

    assert [len(c) for c in state["targets"]] == [8, 4, 4]
    assert res["extra"]["chunks"]["resized"] is True
    assert res["extra"]["chunks"]["initial_size"] == 8
    assert res["extra"]["chunks"]["size"] == 4


def test_timeout_raises_per_host_budget_not_just_shrinks_the_chunk(
        tmp_path, monkeypatch):
    """The defect this guards. ``per_timeout`` is derived from len(chunk),
    so halving the chunk ALSO halves its budget — same seconds per host,
    so a chunk that timed out because the rate assumption was optimistic
    would time out again at half size, forever. A timeout means the RATE
    was wrong, so the rate estimate has to come down with it.

    (nuclei does not have this problem: its batch_timeout is a constant
    independent of batch size, so halving genuinely doubles per-URL time.)
    """
    fake, state = _fake_run_factory(timeouts={0})
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    # Wordlist phải đủ lớn để ngân sách thoát khỏi sàn max(60, …) của
    # _plan_budget — nếu cả hai chunk đều bị kẹp về 60s thì test pass kể
    # cả khi backoff bị tắt, tức là không kiểm gì cả.
    base, alive, wl = _base(tmp_path, 16, wordlist_words=2000)
    ds.scan(alive, base, _cfg(wl, chunk_size=8, chunk_min_size=1), skip=False)

    hosts0, budget0 = len(state["targets"][0]), state["timeouts"][0]
    assert budget0 > 60 and state["timeouts"][1] > 60, "ngan sach dinh san 60s"
    hosts1, budget1 = len(state["targets"][1]), state["timeouts"][1]
    assert hosts1 == hosts0 // 2                      # chunk did halve
    # ...but the budget must NOT halve with it: per-host time goes UP
    per_host0 = budget0 / hosts0
    per_host1 = budget1 / hosts1
    assert per_host1 > per_host0 * 1.5, (
        f"moi host chi duoc {per_host1:.0f}s sau timeout, truoc do "
        f"{per_host0:.0f}s — thich ung khong co tac dung")


def test_chunk_resize_stops_at_min_size(tmp_path, monkeypatch):
    fake, state = _fake_run_factory(timeouts=set(range(20)))
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive, wl = _base(tmp_path, 24)
    ds.scan(alive, base, _cfg(wl, chunk_size=8, chunk_min_size=4), skip=False)

    assert min(len(c) for c in state["targets"]) == 4


def test_stage_ceiling_bounds_the_chunked_run(tmp_path, monkeypatch):
    """``timeout`` is the ceiling for the WHOLE stage, chunked or not."""
    now = {"t": 0.0}
    monkeypatch.setattr(ds.time, "monotonic", lambda: now["t"])
    base_fake, state = _fake_run_factory()

    def fake(cmd, **kw):
        now["t"] += 400.0
        return base_fake(cmd, **kw)

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive, wl = _base(tmp_path, 40)
    res = ds.scan(alive, base, _cfg(wl, chunk_size=4, timeout=1000),
                  skip=False)

    assert state["calls"] == 3          # 400+400+200 exhausts 1000s
    assert res["extra"]["deadline_hit"] is True
    assert res["extra"]["chunks"]["unrun"] == 28
    assert "ngân sách stage" in res["error"]


def test_per_chunk_timeout_is_clamped_to_the_remaining_budget(tmp_path, monkeypatch):
    now = {"t": 0.0}
    monkeypatch.setattr(ds.time, "monotonic", lambda: now["t"])
    base_fake, state = _fake_run_factory()

    def fake(cmd, **kw):
        now["t"] += 700.0
        return base_fake(cmd, **kw)

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive, wl = _base(tmp_path, 12)
    ds.scan(alive, base, _cfg(wl, chunk_size=4, timeout=1000), skip=False)

    # 2nd chunk may not be handed more than the 300s left of the stage
    assert state["timeouts"][1] <= 300
