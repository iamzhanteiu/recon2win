"""Tests for nuclei batched scanning (nuclei.batch_size).

``-json-export`` is written once at process exit, so a single huge run
that walls at its timeout persists nothing. Batching splits the input so
each batch runs to completion and its findings are persisted before the
next starts — a later timeout never wipes the earlier results.

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

from modules import nuclei as nuclei_mod
from modules.utils import create_output_structure, read_lines, write_lines


def _finding(tid: str, url: str, severity: str = "high") -> dict:
    return {"template-id": tid, "info": {"name": tid, "severity": severity},
            "matched-at": url}


def _fake_run_factory(per_batch_findings, timeouts=None):
    """Return a runner.run stand-in.

    ``per_batch_findings``: list keyed by call index → findings to write to
    that call's -json-export path. ``timeouts``: set of call indices that
    should report timed_out=True.
    """
    timeouts = timeouts or set()
    state = {"calls": 0, "inputs": []}

    def _fake(cmd, **kw):
        i = state["calls"]
        state["calls"] += 1
        state["inputs"].append(read_lines(Path(cmd[cmd.index("-l") + 1])))
        jpath = Path(cmd[cmd.index("-json-export") + 1])
        jpath.parent.mkdir(parents=True, exist_ok=True)
        data = per_batch_findings[i] if i < len(per_batch_findings) else []
        jpath.write_text(json.dumps(data))
        to = i in timeouts
        return {"returncode": 0 if not to else 1, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": to,
                "success": not to, "stdout_path": "", "stderr_path": "",
                "log_path": "", "duration": 1}
    return _fake, state


def _base(tmp_path, urls):
    base = create_output_structure("x.com", root=str(tmp_path))
    alive = base / "processed" / "alive_urls.txt"
    write_lines(alive, urls)
    return base, alive


def test_batch_off_runs_once_no_batch_files(tmp_path, monkeypatch):
    fake, state = _fake_run_factory([[_finding("t1", "https://x.com/a")]])
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(10)])
    # No batch_size → single run
    res = nuclei_mod.endpoints_scan(alive, base, {"nuclei": {}}, skip=False)

    assert state["calls"] == 1
    assert res["count"] == 1
    # no batch_* scratch files created
    assert not list((base / "raw" / "nuclei_endpoints").glob("batch_*"))
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
    cfg = {"nuclei": {"endpoints": {"max_urls": 0}, "batch_size": 4}}
    res = nuclei_mod.endpoints_scan(alive, base, cfg, skip=False)

    assert state["calls"] == 3
    assert [len(x) for x in state["inputs"]] == [4, 4, 2]
    assert res["count"] == 3           # all three batches merged
    assert res["extra"]["batches"]["total"] == 3
    assert res["extra"]["batches"]["run"] == 3

    # final nuclei.json holds all three findings
    saved = json.loads((base / "findings" / "endpoints" / "nuclei.json").read_text())
    assert len(saved["findings"]) == 3


def test_batch_dedups_findings_across_batches(tmp_path, monkeypatch):
    # same (template-id, matched-at) reported in two batches → counted once
    dup = _finding("t1", "https://x.com/same")
    fake, state = _fake_run_factory([[dup], [dup, _finding("t2", "https://x.com/other")]])
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"endpoints": {"max_urls": 0}, "batch_size": 4}}
    res = nuclei_mod.endpoints_scan(alive, base, cfg, skip=False)

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
    cfg = {"nuclei": {"endpoints": {"max_urls": 0},
                      "batch_size": 4, "batch_on_timeout": "continue"}}
    res = nuclei_mod.endpoints_scan(alive, base, cfg, skip=False)

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
    cfg = {"nuclei": {"endpoints": {"max_urls": 0},
                      "batch_size": 4, "batch_on_timeout": "stop"}}
    res = nuclei_mod.endpoints_scan(alive, base, cfg, skip=False)

    assert state["calls"] == 1         # stopped after the first (timed-out) batch
    assert res["count"] == 1           # ...but kept that batch's finding
    assert res["extra"]["batches"]["stopped_early"] is True


def test_batch_persists_incrementally_after_each_batch(tmp_path, monkeypatch):
    """After the first batch runs, nuclei.json must already hold its
    finding — proving results survive a kill before later batches run."""
    snapshots = []

    def fake(cmd, **kw):
        jpath = Path(cmd[cmd.index("-json-export") + 1])
        jpath.parent.mkdir(parents=True, exist_ok=True)
        # each batch writes exactly one finding named after its input size
        jpath.write_text(json.dumps([_finding("t", "https://x.com/a")]))
        # snapshot the canonical output file as it stands right now
        canon = jpath.parent.parent.parent / "findings" / "endpoints" / "nuclei.json"
        snapshots.append(canon.exists() and
                         len(json.loads(canon.read_text())["findings"]))
        return {"returncode": 0, "stdout": "", "stderr": "", "missing_binary": False,
                "timed_out": False, "success": True, "stdout_path": "",
                "stderr_path": "", "log_path": "", "duration": 1}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", fake)

    base, alive = _base(tmp_path, [f"https://x.com/p{i}" for i in range(8)])
    cfg = {"nuclei": {"endpoints": {"max_urls": 0}, "batch_size": 4}}
    nuclei_mod.endpoints_scan(alive, base, cfg, skip=False)

    # At the moment batch 2 started, batch 1's finding was already on disk.
    # (findings dedupe by key, so both batches share one → second snapshot
    # still reads 1, but crucially it is > 0: the file existed and had data.)
    assert snapshots[0] is False or snapshots[0] == 0   # nothing before batch 0 wrote
    assert snapshots[1] == 1                            # batch 0 persisted before batch 1
