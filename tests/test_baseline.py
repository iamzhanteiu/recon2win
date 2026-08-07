"""Tests for the baseline probe — modules/baseline.py.

The probe answers "what does this host do with a path that isn't there?",
which is the question the pipeline needed to ask before fuzzing and never
did. Two consequences on the discover.com run: ffuf spent its whole 3,600s
budget on 11 hosts that answer everything identically, and target dedup
grouped by home page — so those 11, having distinct home pages, were never
grouped despite behaving the same everywhere else.
"""
from __future__ import annotations

import json

import pytest

from modules import baseline, behavior, fuzz_targets

pytestmark = pytest.mark.baseline


def _row(url, status, *, words=13, lines=11, length=378, ctype="text/html"):
    return json.dumps({
        "url": url, "input": url, "status_code": status,
        "content_length": length, "words": words, "lines": lines,
        "content_type": ctype,
    })


def _fake_httpx(rows_for):
    """Fake runner.run that answers each probe URL via *rows_for(url)*."""
    def run(cmd, **kw):
        urls = [ln.strip() for ln in
                open(cmd[cmd.index("-l") + 1]).read().splitlines() if ln.strip()]
        out = "\n".join(r for r in (rows_for(u) for u in urls) if r)
        outfile = cmd[cmd.index("-o") + 1]
        open(outfile, "w").write(out)
        return {"success": True, "stdout": out, "stderr": "",
                "missing_binary": False, "timed_out": False}
    return run


# ----------------------------------------------------------------------
# probe_paths
# ----------------------------------------------------------------------
def test_probe_paths_vary_in_shape_and_length():
    paths = baseline.probe_paths(3)
    assert len(paths) == 3
    assert all(p.startswith("/") for p in paths)
    # Different shapes on purpose: a block page echoing the path yields a
    # different byte length for each, which must not read as "they differ".
    assert len({p.count("/") for p in paths}) > 1
    assert any("." in p for p in paths)


def test_probe_paths_are_unique_per_call():
    assert baseline.probe_paths(3) != baseline.probe_paths(3)


# ----------------------------------------------------------------------
# measure
# ----------------------------------------------------------------------
def test_a_host_answering_everything_alike_is_consistent(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: True)
    # Length varies per path (the echo), words/lines do not.
    monkeypatch.setattr(baseline.runner, "run", _fake_httpx(
        lambda u: _row(u, 403, length=370 + len(u) % 10)))

    got, stats = baseline.measure(["https://blocked.com"], tmp_path, {})
    bl = got["https://blocked.com"]
    assert bl.consistent is True
    assert stats["consistent"] == 1


def test_a_normal_host_is_not_consistent(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: True)
    seq = iter([404, 404, 200])
    monkeypatch.setattr(baseline.runner, "run", _fake_httpx(
        lambda u: _row(u, next(seq), words=hash(u) % 500)))

    bl = baseline.measure(["https://ok.com"], tmp_path, {})[0]["https://ok.com"]
    assert bl.consistent is False


def test_a_consistent_404_is_healthy_and_must_be_fuzzed(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(baseline.runner, "run", _fake_httpx(
        lambda u: _row(u, 404)))
    bl = baseline.measure(["https://ok.com"], tmp_path, {})[0]["https://ok.com"]

    # Giving a proper "not found" IS the proof that a host can tell real
    # paths from fake ones. It is the one consistent answer that means keep.
    assert bl.is_blanket() is False


@pytest.mark.parametrize("status", [200, 301, 401, 403, 500, 503])
def test_any_other_consistent_answer_is_a_blanket(tmp_path, monkeypatch, status):
    """The test is "did it 404?", not "is it in the tool's match list".

    Keying on match_status was wrong in both directions on the real target:
    mapi.discover.com answers 503 to everything, 503 is not in ffuf's match
    list, so the host passed the check — and ffuf then reported 3,715 hits
    on it.
    """
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(baseline.runner, "run", _fake_httpx(
        lambda u: _row(u, status)))
    bl = baseline.measure(["https://x.com"], tmp_path, {})[0]["https://x.com"]
    assert bl.is_blanket() is True


def test_measure_fails_open_without_httpx(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: False)
    got, stats = baseline.measure(["https://a.com"], tmp_path, {})
    assert got["https://a.com"].probed is False
    assert "error" in stats


def test_measure_reads_stdout_when_httpx_writes_no_file(tmp_path, monkeypatch):
    # Same httpx quirk that made the responses stage report fetched: 0.
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: True)

    def run(cmd, **kw):
        urls = [ln.strip() for ln in
                open(cmd[cmd.index("-l") + 1]).read().splitlines() if ln.strip()]
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stderr": "", "stdout": "\n".join(_row(u, 403) for u in urls)}

    monkeypatch.setattr(baseline.runner, "run", run)
    bl = baseline.measure(["https://b.com"], tmp_path, {})[0]["https://b.com"]
    assert bl.probed and bl.consistent


# ----------------------------------------------------------------------
# is_noise / dedup_key
# ----------------------------------------------------------------------
def test_a_hit_shaped_like_the_baseline_is_noise():
    bl = baseline.Baseline("https://h.com")
    bl.responses = [behavior.Behavior(url="https://h.com/xyz", status=403,
                                      length=378, words=13, lines=11)]
    bl.shape = behavior.fingerprint(bl.responses[0])

    same = behavior.Behavior(url="https://h.com/admin", status=403,
                             length=999, words=13, lines=11)
    other = behavior.Behavior(url="https://h.com/real", status=200,
                              length=999, words=800, lines=40)
    assert bl.is_noise(same) is True
    assert bl.is_noise(other) is False


def test_unprobed_hosts_get_distinct_dedup_keys():
    a, b = baseline.Baseline("https://a.com"), baseline.Baseline("https://b.com")
    assert a.dedup_key() != b.dedup_key()


# ----------------------------------------------------------------------
# Integration with target selection
# ----------------------------------------------------------------------
def test_blanket_hosts_are_dropped_before_fuzzing():
    blocked = {}
    for host in ("https://a.com", "https://b.com"):
        bl = baseline.Baseline(host)
        bl.responses = [behavior.Behavior(url=host + "/x", status=403,
                                          words=13, lines=11)]
        bl.shape = behavior.fingerprint(bl.responses[0])
        blocked[host] = bl
    ok = baseline.Baseline("https://c.com")
    ok.responses = [behavior.Behavior(url="https://c.com/x", status=404,
                                      words=99, lines=9)]
    ok.shape = behavior.fingerprint(ok.responses[0])
    blocked["https://c.com"] = ok

    targets, stats = fuzz_targets.select_targets(
        list(blocked), baselines=blocked, match_status=[200, 403],
    )
    assert targets == ["https://c.com"]
    assert stats["blanket_skipped"] == 2


def test_hosts_with_the_same_not_found_shape_are_deduped():
    # The dedup home-page fingerprint could never do this: these hosts are
    # only identical on paths that do not exist.
    bls = {}
    for host in ("https://a.com", "https://b.com", "https://c.com"):
        bl = baseline.Baseline(host)
        bl.responses = [behavior.Behavior(url=host + "/x", status=404,
                                          words=42, lines=7)]
        bl.shape = behavior.fingerprint(bl.responses[0])
        bls[host] = bl

    targets, stats = fuzz_targets.select_targets(
        list(bls), baselines=bls, match_status=[200, 403],
    )
    assert len(targets) == 1
    assert stats["deduped"] == 2


def test_an_unprobed_host_is_never_dropped():
    # Failing to measure is not evidence against a host.
    bls = {"https://a.com": baseline.Baseline("https://a.com")}
    targets, stats = fuzz_targets.select_targets(
        ["https://a.com"], baselines=bls, match_status=[200, 403],
    )
    assert targets == ["https://a.com"]
    assert not stats.get("blanket_skipped")


def test_concurrent_stages_do_not_share_probe_files(tmp_path, monkeypatch):
    """Stage 4 runs dirsearch, ffuf and content_discovery at the same time.

    They all call measure(), so sharing one probe_urls.txt / probe.jsonl pair
    means they overwrite each other mid-flight — and the damage is silent:
    url_owner matches nothing, every host reads back unprobed, and the
    blanket hosts get fuzzed exactly as if the feature were off. That is what
    happened on a real discover.com run.
    """
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: True)
    seen: list[str] = []

    def run(cmd, **kw):
        in_file = cmd[cmd.index("-l") + 1]
        out_file = cmd[cmd.index("-o") + 1]
        seen.extend([in_file, out_file])
        urls = [ln.strip() for ln in open(in_file).read().splitlines() if ln.strip()]
        open(out_file, "w").write("\n".join(_row(u, 403) for u in urls))
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}

    monkeypatch.setattr(baseline.runner, "run", run)
    for stage in ("ffuf", "dirsearch", "content_discovery"):
        got, _ = baseline.measure(["https://a.com"], tmp_path, {}, stage=stage)
        assert got["https://a.com"].consistent, stage

    assert len(seen) == len(set(seen)), f"probe files collide: {seen}"


def test_ffuf_stage_probes_with_ffuf_not_httpx(tmp_path, monkeypatch):
    """The probe must be subject to the same treatment as the fuzzer.

    Akamai Bot Manager fingerprints ffuf specifically: on discover.com httpx
    got a clean 404 from webapp.src.discover.com while ffuf got a 403 block
    page for every path. Probing with httpx therefore cleared a host that
    ffuf could learn nothing from, and ffuf spent its budget on it.
    """
    from modules import fuzz_targets as ft

    seen: list[str] = []
    monkeypatch.setattr(baseline, "measure",
                        lambda targets, out, cfg=None, **kw: (
                            seen.append(kw.get("client")) or ({}, {})))

    (tmp_path / "processed").mkdir(parents=True, exist_ok=True)
    from modules import layout
    layout.path(tmp_path, "alive.txt").write_text("https://a.com\n")

    for stage, expected in [("ffuf", "ffuf"), ("dirsearch", "httpx"),
                            ("content_discovery", "httpx")]:
        seen.clear()
        ft.load_targets(layout.path(tmp_path, "alive.txt"), tmp_path,
                        cfg={"baseline": {"enabled": True}}, stage=stage)
        assert seen == [expected], f"{stage} probed with {seen}"


def test_a_timed_out_probe_says_so_instead_of_going_quiet(tmp_path, monkeypatch):
    """A starved probe skips nothing — that must not read like a clean run.

    Measured: dirsearch's httpx probe hit its 180s budget because ffuf's
    probe and scan were saturating the same hosts. Target selection fell
    back to home-page dedup, no blanket host was skipped, and no line
    anywhere said the feature had switched itself off.
    """
    monkeypatch.setattr(baseline.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(baseline.runner, "run", lambda cmd, **kw: {
        "success": False, "stdout": "", "stderr": "TimeoutExpired after 600s",
        "missing_binary": False, "timed_out": True,
    })

    got, stats = baseline.measure(["https://a.com"], tmp_path, {})
    assert stats["timed_out"] is True
    assert "timed out" in stats["error"]
    assert got["https://a.com"].is_blanket() is False   # fail-open, keep it


def test_summary_line_surfaces_a_broken_probe():
    line = fuzz_targets.summary_line({
        "input": 154, "selected": 50, "deduped": 92,
        "baseline": {"error": "probe timed out after 600s"},
    })
    assert "HỎNG" in line and "timed out" in line


# ----------------------------------------------------------------------
# load_from_raw — reconstructing baselines after stage 4 has finished
# ----------------------------------------------------------------------
def test_load_from_raw_rebuilds_baseline_from_httpx_jsonl(tmp_path):
    rdir = tmp_path / "raw" / "baseline"
    rdir.mkdir(parents=True)
    (rdir / "probe_dirsearch.jsonl").write_text("\n".join([
        _row("https://spa.x.com/ab12cd34", 200, words=900, lines=40),
        _row("https://spa.x.com/ab12cd34/ab12cd34", 200, words=900, lines=40),
        _row("https://spa.x.com/ab12cd34.html", 200, words=900, lines=40),
    ]), encoding="utf-8")

    baselines = baseline.load_from_raw(tmp_path)
    bl = baselines["spa.x.com"]
    assert bl.consistent is True
    assert bl.is_noise(behavior.Behavior(
        url="https://spa.x.com/patients/me/encounters", status=200,
        words=900, lines=40, content_type="text/html",
    )) is True


def test_load_from_raw_parses_ffuf_client_reports(tmp_path):
    rdir = tmp_path / "raw" / "baseline"
    rdir.mkdir(parents=True)
    (rdir / "probe_ffuf.json").write_text(json.dumps({"results": [
        {"url": f"https://waf.x.com/p{i}", "status": 403, "words": 20}
        for i in range(3)
    ]}), encoding="utf-8")

    baselines = baseline.load_from_raw(tmp_path)
    assert baselines["waf.x.com"].consistent is True


def test_load_from_raw_is_empty_without_a_baseline_dir(tmp_path):
    assert baseline.load_from_raw(tmp_path) == {}
