"""Tests for nuclei batched scanning (nuclei.batch_size).

nuclei streams findings to ``-jsonl -o`` incrementally, so a run killed at
its timeout still leaves the findings it had already made on disk (the
``-json-export`` / ``-jsonl-export`` flags buffer and write once at exit,
so a killed run leaves those empty). Batching splits the input so each
batch is separately bounded and persisted — a later timeout never wipes
the earlier results.

Covers:
  * batch_size=0 → single run, original behaviour (no batch_* files)
  * batch_size splits the input and feeds each chunk to nuclei
  * findings from every batch are merged (and deduped across batches)
  * a timed-out batch is persisted + the scan continues (continue mode)
  * batch_on_timeout=stop halts after the first timed-out batch
  * results are written incrementally (present after each batch)
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import layout, nuclei as nuclei_mod
from modules.utils import create_output_structure, read_lines, write_lines


def _finding(tid: str, url: str, severity: str = "high") -> dict:
    return {"template-id": tid, "info": {"name": tid, "severity": severity},
            "matched-at": url}


def _fake_run_factory(per_batch_findings, timeouts=None):
    """Return a runner.run stand-in.

    ``per_batch_findings``: list keyed by call index → findings to write to
    that call's ``-o`` JSONL path. ``timeouts``: set of call indices that
    should report timed_out=True. Timed-out calls still write their
    findings, mirroring the real incremental ``-jsonl -o`` stream.
    """
    timeouts = timeouts or set()
    state = {"calls": 0, "inputs": []}

    def _fake(cmd, **kw):
        i = state["calls"]
        state["calls"] += 1
        state["inputs"].append(read_lines(Path(cmd[cmd.index("-l") + 1])))
        jpath = Path(cmd[cmd.index("-o") + 1])
        jpath.parent.mkdir(parents=True, exist_ok=True)
        data = per_batch_findings[i] if i < len(per_batch_findings) else []
        jpath.write_text("".join(json.dumps(d) + "\n" for d in data))
        to = i in timeouts
        return {"returncode": 0 if not to else 1, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": to,
                "success": not to, "stdout_path": "", "stderr_path": "",
                "log_path": "", "duration": 1}
    return _fake, state


def _base(tmp_path, urls):
    base = create_output_structure("x.com", root=str(tmp_path))
    alive = layout.path(base, "alive.txt")
    write_lines(alive, urls)
    return base, alive


def test_batch_off_runs_once_no_batch_files(tmp_path, monkeypatch):
    fake, state = _fake_run_factory([[_finding("t1", "https://x.com/a")]])
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(10)])
    # No batch_size → single run
    res = nuclei_mod.default_scan(alive, base, {"nuclei": {}}, skip=False)

    assert state["calls"] == 1
    assert res["count"] == 1
    # no batch_* scratch files created
    assert not list((base / "raw" / "nuclei_default").glob("batch_*"))
    assert "batches" not in (res.get("extra") or {})


def test_batch_splits_input_and_merges_findings(tmp_path, monkeypatch):
    # 10 URLs, batch_size 4 → 3 batches (4,4,2)
    fake, state = _fake_run_factory([
        [_finding("t1", "https://x.com/a")],
        [_finding("t2", "https://x.com/b")],
        [_finding("t3", "https://x.com/c")],
    ])
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(10)])
    cfg = {"nuclei": {"batch_autotune": False, "batch_size": 4}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert state["calls"] == 3
    assert [len(x) for x in state["inputs"]] == [4, 4, 2]
    assert res["count"] == 3           # all three batches merged
    assert res["extra"]["batches"]["total"] == 3
    assert res["extra"]["batches"]["run"] == 3

    # final nuclei.json holds all three findings
    saved = json.loads((base / "findings" / "default" / "nuclei.json").read_text())
    assert len(saved["findings"]) == 3


def test_batch_dedups_findings_across_batches(tmp_path, monkeypatch):
    # same (template-id, matched-at) reported in two batches → counted once
    dup = _finding("t1", "https://x.com/same")
    fake, state = _fake_run_factory([[dup], [dup, _finding("t2", "https://x.com/other")]])
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"batch_autotune": False, "batch_size": 4}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert res["count"] == 2           # dup collapsed


def test_batch_continues_past_timed_out_batch(tmp_path, monkeypatch):
    # batch 0 times out (but wrote a finding), batch 1 succeeds → both kept
    fake, state = _fake_run_factory(
        [[_finding("t1", "https://x.com/a")], [_finding("t2", "https://x.com/b")]],
        timeouts={0},
    )
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"batch_autotune": False,
                      "batch_size": 4, "batch_on_timeout": "continue"}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert state["calls"] == 2         # did NOT stop at the timeout
    assert res["count"] == 2
    # a timed-out batch is a partial result, not a dead stage
    assert res["status"] == "success"
    assert res["extra"]["timed_out"] is True
    assert res["extra"]["batches"]["stopped_early"] is False


def test_batch_stop_mode_halts_after_first_timeout(tmp_path, monkeypatch):
    fake, state = _fake_run_factory(
        [[_finding("t1", "https://x.com/a")], [_finding("t2", "https://x.com/b")]],
        timeouts={0},
    )
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"batch_autotune": False,
                      "batch_size": 4, "batch_on_timeout": "stop"}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert state["calls"] == 1         # stopped after the first (timed-out) batch
    assert res["count"] == 1           # ...but kept that batch's finding
    assert res["extra"]["batches"]["stopped_early"] is True


def test_every_batch_timing_out_still_keeps_findings(tmp_path, monkeypatch):
    """The regression this whole design exists to prevent.

    A real acronis.com run had ALL SIX batches time out. nuclei had found
    real issues and streamed them out, but the stage reported "salvaged 0
    partial findings" — because the parser read the ``-json-export`` file,
    which nuclei only writes at exit and so was never created. Batching
    alone does not help when no batch finishes; reading the incremental
    ``-jsonl -o`` stream does.
    """
    fake, state = _fake_run_factory(
        [[_finding("t1", "https://x.com/a")],
         [_finding("t2", "https://x.com/b")]],
        timeouts={0, 1},          # nothing completes
    )
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"batch_autotune": False,
                      "batch_size": 4, "batch_on_timeout": "continue"}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert res["count"] == 2                  # NOT 0 — findings survived
    assert res["extra"]["timed_out"] is True
    canon = base / "findings" / "default" / "nuclei.json"
    assert len(json.loads(canon.read_text())["findings"]) == 2


def test_single_run_timeout_salvages_findings(tmp_path, monkeypatch):
    """Same guarantee without batching: an un-batched run that walls at
    its timeout still reports what nuclei streamed before the kill."""
    fake, state = _fake_run_factory(
        [[_finding("t1", "https://x.com/a")]], timeouts={0},
    )
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(5)])
    res = nuclei_mod.default_scan(
        alive, base, {"nuclei": {}}, skip=False)

    assert state["calls"] == 1                # single run, no batching
    assert res["count"] == 1                  # salvaged, not lost
    assert "salvaged 1 partial findings" in res["error"]


def test_stale_jsonl_from_previous_run_is_not_reported(tmp_path, monkeypatch):
    """The output dir of a re-run usually still holds the timed-out
    previous attempt's stream. Since we read that file back, it must be
    truncated first or old findings resurface as new ones."""
    def fake(cmd, **kw):
        # nuclei finds nothing this time and writes nothing.
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 1}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, ["https://x.com/p1"])
    stale = base / "raw" / "nuclei_default" / "scan.jsonl"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text(json.dumps(_finding("old", "https://x.com/gone")) + "\n")

    res = nuclei_mod.default_scan(
        alive, base, {"nuclei": {}}, skip=False)

    assert res["count"] == 0


def test_truncated_final_jsonl_line_is_skipped(tmp_path, monkeypatch):
    """Killing nuclei mid-write can cut the last JSONL line in half. That
    is now the normal end state of a timed-out run, so the parser must
    drop the fragment and keep every complete finding before it."""
    def fake(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(_finding("t1", "https://x.com/a")) + "\n"
            + json.dumps(_finding("t2", "https://x.com/b")) + "\n"
            + '{"template-id": "t3", "info": {"sev'   # killed mid-line
        )
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": True, "success": False,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 1}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, ["https://x.com/p1"])
    res = nuclei_mod.default_scan(
        alive, base, {"nuclei": {}}, skip=False)

    assert res["count"] == 2      # the two intact findings, not a crash


def test_batch_persists_incrementally_after_each_batch(tmp_path, monkeypatch):
    """After the first batch runs, nuclei.json must already hold its
    finding — proving results survive a kill before later batches run."""
    snapshots = []

    def fake(cmd, **kw):
        jpath = Path(cmd[cmd.index("-o") + 1])
        jpath.parent.mkdir(parents=True, exist_ok=True)
        # each batch writes exactly one finding named after its input size
        jpath.write_text(json.dumps(_finding("t", "https://x.com/a")) + "\n")
        # snapshot the canonical output file as it stands right now
        canon = jpath.parent.parent.parent / "findings" / "default" / "nuclei.json"
        snapshots.append(canon.exists() and
                         len(json.loads(canon.read_text())["findings"]))
        return {"returncode": 0, "stdout": "", "stderr": "", "missing_binary": False,
                "timed_out": False, "success": True, "stdout_path": "",
                "stderr_path": "", "log_path": "", "duration": 1}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"batch_autotune": False, "batch_size": 4}}
    nuclei_mod.default_scan(alive, base, cfg, skip=False)

    # At the moment batch 2 started, batch 1's finding was already on disk.
    # (findings dedupe by key, so both batches share one → second snapshot
    # still reads 1, but crucially it is > 0: the file existed and had data.)
    assert snapshots[0] is False or snapshots[0] == 0   # nothing before batch 0 wrote
    assert snapshots[1] == 1                            # batch 0 persisted before batch 1


def test_complete_flag_true_only_when_every_batch_finished(tmp_path, monkeypatch):
    """nuclei.json carries ``complete: true`` only for a scan that got
    through its whole input. ``--resume`` keys on this (see
    nuclei._outputs_exist), so a partial run must not look finished."""
    fake, _ = _fake_run_factory([
        [_finding("t1", "https://x.com/a")],
        [_finding("t2", "https://x.com/b")],
    ])
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"batch_autotune": False, "batch_size": 4}}
    nuclei_mod.default_scan(alive, base, cfg, skip=False)

    saved = json.loads((base / "findings" / "default" / "nuclei.json").read_text())
    assert saved["complete"] is True
    assert nuclei_mod._outputs_exist(base, "default") is True


def test_complete_flag_false_when_a_batch_times_out(tmp_path, monkeypatch):
    """The real acronis.com failure: 5 of 6 batches walled at
    batch_timeout. The findings that DID stream are kept, but the scan
    covered only part of its input — resuming on it would silently skip
    the rescan, so ``complete`` must stay false."""
    fake, _ = _fake_run_factory(
        [[_finding("t1", "https://x.com/a")], []], timeouts={1})
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"batch_autotune": False, "batch_size": 4}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert res["count"] == 1                      # partial findings kept
    saved = json.loads((base / "findings" / "default" / "nuclei.json").read_text())
    assert saved["complete"] is False
    assert len(saved["findings"]) == 1
    assert nuclei_mod._outputs_exist(base, "default") is False


def test_complete_flag_false_when_scan_skipped(tmp_path, monkeypatch):
    """--skip-nuclei writes empty outputs; a later --resume without the
    skip flag must still run the scan."""
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    base, alive = _base(tmp_path, ["https://x.com/p1"])
    nuclei_mod.default_scan(
        alive, base, {"nuclei": {}}, skip=True)

    assert nuclei_mod._outputs_exist(base, "default") is False


# ----------------------------------------------------------------------
# adaptive resize — a timed-out batch truncates the TEMPLATE list for every
# URL in it (nuclei walks template-by-template across all targets), not the
# tail of its URL list. Template order isn't random, so the same tail is
# lost every time. Smaller batches each get through the full set.
# ----------------------------------------------------------------------
def test_batch_halves_size_after_timeout(tmp_path, monkeypatch):
    fake, state = _fake_run_factory([[]] * 10, timeouts={0})
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    # 16 URLs, batch 8 → batch 0 (8 urls) times out → remaining 8 run at 4
    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(16)])
    cfg = {"nuclei": {"batch_autotune": False,
                      "batch_size": 8, "batch_min_size": 1}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert [len(x) for x in state["inputs"]] == [8, 4, 4]
    assert res["extra"]["batches"]["resized"] is True
    assert res["extra"]["batches"]["initial_size"] == 8
    assert res["extra"]["batches"]["size"] == 4
    # every URL still got scanned exactly once
    assert sum(len(x) for x in state["inputs"]) == 16


def test_batch_resize_stops_at_min_size(tmp_path, monkeypatch):
    """Halving must not spiral into one-URL batches — each batch pays a
    fresh template load (~10-30s), so the floor is what keeps that cost
    bounded when a target is simply too slow to finish any batch."""
    fake, state = _fake_run_factory([[]] * 20, timeouts=set(range(20)))
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(24)])
    cfg = {"nuclei": {"batch_autotune": False,
                      "batch_size": 8, "batch_min_size": 4}}
    nuclei_mod.default_scan(alive, base, cfg, skip=False)

    # 8 → 4 → floor; never smaller even though every batch timed out
    assert min(len(x) for x in state["inputs"]) == 4
    assert [len(x) for x in state["inputs"]] == [8, 4, 4, 4, 4]


def test_no_resize_when_batches_complete(tmp_path, monkeypatch):
    fake, state = _fake_run_factory([[]] * 4)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(12)])
    cfg = {"nuclei": {"batch_autotune": False, "batch_size": 4}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert [len(x) for x in state["inputs"]] == [4, 4, 4]
    assert res["extra"]["batches"]["resized"] is False
    assert res["extra"]["batches"]["size"] == 4


# ----------------------------------------------------------------------
# stage deadline — ``timeout`` used to bound only the un-batched path, so a
# batched scan ran for batches × batch_timeout with nothing capping it. A
# real discover.com run spent 4h in a nuclei stage under a nominal 3h
# ``timeout``.
# ----------------------------------------------------------------------
def _clock(monkeypatch, step: float):
    """Freeze time and advance it ``step`` seconds per nuclei invocation."""
    now = {"t": 0.0}
    monkeypatch.setattr(nuclei_mod.time, "monotonic", lambda: now["t"])
    return now


def test_stage_timeout_bounds_the_batched_path(tmp_path, monkeypatch):
    now = _clock(monkeypatch, 0)
    base_fake, state = _fake_run_factory([[]] * 20)

    def fake(cmd, **kw):
        now["t"] += 400.0          # each batch burns 400s of the budget
        return base_fake(cmd, **kw)

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    # 40 URLs / batch 4 → 10 batches wanted, but only 1000s of budget
    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(40)])
    cfg = {"nuclei": {"batch_autotune": False, "default": {"timeout": 1000},
                      "batch_size": 4, "batch_timeout": 900}}
    res = nuclei_mod.default_scan(alive, base, cfg, skip=False)

    # 400 + 400 + 200 exhausts the 1000s budget; the 4th batch never starts
    assert state["calls"] == 3
    assert res["extra"]["deadline_hit"] is True
    assert res["extra"]["batches"]["unscanned_urls"] == 28
    assert "stage budget" in res["error"]
    # a stage that stopped short is NOT complete → --resume re-runs it
    saved = json.loads((base / "findings" / "default" / "nuclei.json").read_text())
    assert saved["complete"] is False
    assert nuclei_mod._outputs_exist(base, "default") is False


def test_batch_timeout_is_clamped_to_remaining_stage_budget(tmp_path, monkeypatch):
    """The last batch must not be handed a timeout that overruns the stage
    ceiling — that is how the old code turned a 3h budget into 4h."""
    now = _clock(monkeypatch, 0)
    seen: list = []
    base_fake, _ = _fake_run_factory([[]] * 20)

    def fake(cmd, **kw):
        seen.append(kw["timeout"])
        now["t"] += 700.0
        return base_fake(cmd, **kw)

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(12)])
    cfg = {"nuclei": {"batch_autotune": False, "default": {"timeout": 1000},
                      "batch_size": 4, "batch_timeout": 900}}
    nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert seen == [900, 300]      # 2nd batch clamped to what's left, not 900


def test_stage_timeout_does_not_touch_the_single_run_path(tmp_path, monkeypatch):
    """Un-batched runs already got the full ``timeout``; keep it that way."""
    seen: list = []
    base_fake, _ = _fake_run_factory([[]])

    def fake(cmd, **kw):
        seen.append(kw["timeout"])
        return base_fake(cmd, **kw)

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(3)])
    cfg = {"nuclei": {"default": {"timeout": 1234}}}
    nuclei_mod.default_scan(alive, base, cfg, skip=False)

    assert seen == [1234]
