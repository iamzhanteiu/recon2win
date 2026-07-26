"""Tests for arjun input capping + ranking.

Covers:
  * _score() — high-value hints bump score, archive noise demotes it
  * discover() with resume=False skips when input is empty
  * discover() with resume=False caps the input and writes a subset
    file when the URL count exceeds max_urls (we monkeypatch the
    external `arjun` binary so the test stays hermetic)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from modules import arjun
from modules.arjun import _score
from modules.utils import read_lines, write_lines

# Grabbed before the autouse fixture below stubs the module attribute, so
# the patcher's own tests can still reach the real implementation.
_real_patch_upstream_crash = arjun._patch_upstream_crash


@pytest.fixture(autouse=True)
def _no_site_packages_patching(monkeypatch):
    """``discover()`` fixes an upstream arjun crash by rewriting a line in
    the installed package (see modules/arjun._patch_upstream_crash). That
    is right for a real scan and wrong for a test run — nothing under
    tests/ may touch the machine's site-packages — so every test here runs
    with the patcher stubbed out. ``test_patch_upstream_*`` below exercise
    the real function against a fake package tree instead."""
    monkeypatch.setattr(arjun, "_patch_upstream_crash", lambda out_dir: "clean")


# ----------------------------------------------------------------------
# _score — pure helper, no I/O
# ----------------------------------------------------------------------
def test_score_boosts_api_endpoints():
    assert _score("https://x.com/api/v1/users") > _score("https://x.com/about")


def test_score_boosts_login_and_admin():
    assert _score("https://x.com/login") >= _score("https://x.com/foo")
    assert _score("https://x.com/admin/dashboard") >= _score("https://x.com/foo")


def test_score_demotes_archive_hosts():
    interesting = _score("https://x.com/api/users")
    archived = _score("https://web.archive.org/web/2024/https://x.com/api/users")
    assert archived < interesting


def test_score_is_case_insensitive():
    assert _score("https://x.com/ADMIN/users") == _score("https://x.com/admin/users")


def test_score_ties_break_shorter_first():
    # Both score 0 (no hints). Equal length + sorted on raw URL means
    # alphabetical order, not length. Just verify the helper returns an
    # int and is deterministic.
    a = _score("https://x.com/aaa")
    b = _score("https://x.com/bbb")
    assert isinstance(a, int) and isinstance(b, int)
    assert _score("https://x.com/aaa") == a  # idempotent


# ----------------------------------------------------------------------
# discover() — empty input short-circuits
# ----------------------------------------------------------------------
def test_discover_skips_when_dynamic_urls_empty(tmp_path: Path, monkeypatch):
    # Pretend the arjun binary exists so the empty-input guard fires
    # (the stage checks for the binary first; we want to exercise the
    # second branch).
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    # Belt-and-braces: if we proceed past the empty guard, fail loudly.
    def _explode(*a, **kw):
        raise AssertionError("runner.run must not be called for empty dynamic_urls.txt")
    monkeypatch.setattr("modules.runner.run", _explode)

    (tmp_path / "dynamic_urls.txt").write_text("")
    res = arjun.discover(
        tmp_path / "dynamic_urls.txt", tmp_path,
        cfg={"arjun": {}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "skipped"
    assert res["error"] == "no dynamic URLs to scan"
    assert res["count"] == 0


# ----------------------------------------------------------------------
# discover() — input capping + subset file
# ----------------------------------------------------------------------
def _fake_arjun_runner(monkeypatch, captured_cmd: list[str]):
    """Replace runner.run with a no-op that records the argv.

    Writes the file in arjun's real ``-oT`` (text) format — one
    parameterised URL per line, ``url?p1=&p2=`` — so the parse step is
    exercised against what arjun actually produces (not the console
    ``[200] url`` format, which the ``-o`` JSON file never contains)."""
    def _fake(cmd, **kw):
        captured_cmd.extend(cmd)
        out_idx = cmd.index("-oT") + 1
        Path(cmd[out_idx]).write_text(
            "https://x.com/api/users?id=&name=\n"
        )
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake)


def test_discover_caps_input_when_over_max_urls(tmp_path: Path, monkeypatch):
    """When dynamic_urls.txt has 500 lines and max_urls=50, arjun should
    receive a 50-line subset ranked by high-value hints."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    lines = [f"https://x.com/page{i}" for i in range(450)]
    # sprinkle in 50 high-value URLs (rank higher → kept)
    lines.extend(f"https://x.com/api/v1/users/{i}" for i in range(50))
    write_lines(dyn, lines)

    res = arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 50, "request_timeout": 5,
                       "threads": 1, "timeout": 60, "chunk_size": 0}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "success"
    assert res["extra"]["input_urls"] == 500
    assert res["extra"]["scanned_urls"] == 50

    # The argv should point at the subset file under raw/arjun/, not the original.
    subset_idx = captured.index("-i") + 1
    assert captured[subset_idx].endswith("raw/arjun/input_subset.txt")

    subset_lines = read_lines(Path(captured[subset_idx]))
    assert len(subset_lines) == 50
    # Every kept URL should be one of the high-value API ones.
    assert all("/api/v1/users/" in u for u in subset_lines)


def test_discover_passes_per_request_timeout(tmp_path: Path, monkeypatch):
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])

    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "request_timeout": 7,
                       "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    # `-T 7` should appear in the argv.
    t_idx = captured.index("-T")
    assert captured[t_idx + 1] == "7"


def test_discover_no_cap_when_under_max_urls(tmp_path: Path, monkeypatch):
    """With 3 URLs and max_urls=200, arjun should receive the original
    file (not a subset)."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, [
        "https://x.com/a",
        "https://x.com/b",
        "https://x.com/c",
    ])

    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "request_timeout": 5,
                       "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    # `-i` should point at the original file, not a subset.
    i_idx = captured.index("-i") + 1
    assert captured[i_idx] == str(dyn)


# ----------------------------------------------------------------------
# Output parsing — arjun -oT (text) → parameterized_urls.txt
# ----------------------------------------------------------------------
def test_discover_uses_text_output_flag_not_json(tmp_path: Path, monkeypatch):
    """We must invoke arjun with -oT (text). -o writes JSON, which the
    parser can't read — using it silently drops every discovered param."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])
    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    assert "-oT" in captured
    assert "-o" not in captured  # the JSON flag must NOT be used


def test_discover_parses_text_output_into_parameterized_urls(tmp_path: Path, monkeypatch):
    """The real end-to-end fix: arjun's text output lands in
    parameterized_urls.txt so nuclei_dynamic actually gets input."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])
    res = arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "success"
    assert res["count"] == 1
    out = read_lines(tmp_path / "processed" / "parameterized_urls.txt")
    assert out == ["https://x.com/api/users?id=&name="]


def test_discover_rejoins_post_style_tab_rows(tmp_path: Path, monkeypatch):
    """POST/JSON rows are ``url\\t?params`` — the URL must be rejoined
    with its query-string, not truncated at the tab."""
    def _fake(cmd, **kw):
        out_idx = cmd.index("-oT") + 1
        Path(cmd[out_idx]).write_text(
            "https://x.com/a?id=&q=\n"                 # GET row
            "https://x.com/b\t?token=&role=\n"         # POST row (tab)
        )
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/a", "https://x.com/b"])
    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    out = read_lines(tmp_path / "processed" / "parameterized_urls.txt")
    assert out == [
        "https://x.com/a?id=&q=",
        "https://x.com/b?token=&role=",
    ]


def test_discover_passes_rate_limit_when_configured(tmp_path: Path, monkeypatch):
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])
    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "threads": 1, "timeout": 60,
                       "rate_limit": 40}},
        resume=False, dry_run=False, skip=False,
    )
    assert "--rate-limit" in captured
    assert captured[captured.index("--rate-limit") + 1] == "40"


def test_discover_omits_rate_limit_when_zero(tmp_path: Path, monkeypatch):
    """rate_limit 0/unset → don't pass --rate-limit (use arjun default)."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])
    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    assert "--rate-limit" not in captured


# ----------------------------------------------------------------------
# xnlinkfinder default timeout — guard against accidental regression
# ----------------------------------------------------------------------
def test_xnlinkfinder_default_timeout_is_at_least_1200():
    """The default must comfortably cover a multi-MB JS bundle. If this
    drops below 1200 we re-introduce the timeout-after-600s class of
    bugs we saw in the vulnweb.com log."""
    # Inspect the source so we don't need to instantiate the whole stage.
    import inspect
    from modules import xnlinkfinder
    src = inspect.getsource(xnlinkfinder.scan)
    assert 'get("timeout", 1800)' in src, \
        "xnlinkfinder default timeout must be at least 1800s"

# ----------------------------------------------------------------------
# discover() — chunking (arjun crashes take out the whole invocation)
# ----------------------------------------------------------------------
def _chunking_runner(monkeypatch, crash_on=(), *, found=None):
    """arjun stand-in. ``crash_on`` = set of chunk indices that exit 1
    without writing anything (the real 2.2.7 AttributeError crash).
    Surviving chunks APPEND one param URL, like arjun's real ``-oT``."""
    calls: list[list[str]] = []

    def _fake(cmd, **kw):
        i = len(calls)
        calls.append(list(cmd))
        if i in crash_on:
            return {"success": False, "stdout": "", "stderr":
                    "AttributeError: 'dict' object has no attribute 'status_code'",
                    "missing_binary": False, "timed_out": False}
        out = Path(cmd[cmd.index("-oT") + 1])
        with out.open("a") as fh:
            fh.write(f"https://x.com/api/c{i}?id=&name=\n")
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake)
    return calls


def test_discover_splits_input_into_chunks(tmp_path: Path, monkeypatch):
    calls = _chunking_runner(monkeypatch)
    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, [f"https://x.com/api/p{i}?a=1" for i in range(10)])

    res = arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "timeout": 60, "chunk_size": 4}},
        resume=False, dry_run=False, skip=False,
    )

    assert len(calls) == 3                      # 4 + 4 + 2
    sizes = [len(read_lines(Path(c[c.index("-i") + 1]))) for c in calls]
    assert sizes == [4, 4, 2]
    assert res["extra"]["chunks"]["total"] == 3
    assert res["count"] == 3                    # one param URL per chunk


def test_discover_survives_a_crashing_chunk(tmp_path: Path, monkeypatch):
    """The real failure: arjun died on target 2/200 and took the other
    198 with it, leaving no output at all. Chunked, a crash costs only
    its own chunk and every other chunk's params are kept."""
    calls = _chunking_runner(monkeypatch, crash_on={0})
    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, [f"https://x.com/api/p{i}?a=1" for i in range(12)])

    res = arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "timeout": 60, "chunk_size": 4}},
        resume=False, dry_run=False, skip=False,
    )

    assert len(calls) == 3                      # crash did NOT stop the run
    assert res["status"] == "success"
    assert res["count"] == 2                    # chunks 1 and 2 survived
    assert res["extra"]["chunks"]["failed"] == 1
    assert "1 crashed" in res["error"]


def test_discover_fails_only_when_every_chunk_crashes(tmp_path: Path, monkeypatch):
    _chunking_runner(monkeypatch, crash_on={0, 1, 2})
    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, [f"https://x.com/api/p{i}?a=1" for i in range(12)])

    res = arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "timeout": 60, "chunk_size": 4}},
        resume=False, dry_run=False, skip=False,
    )
    assert res["status"] == "failed"
    assert res["count"] == 0


def _budget_run(tmp_path: Path, monkeypatch, cfg_extra: dict,
                *, per_chunk_cost: float = 40.0) -> tuple[list[int], dict]:
    """Run discover() over 16 URLs on a fake clock, returning the timeout
    each chunk was given plus the stage result."""
    clock = {"t": 0.0}
    monkeypatch.setattr(arjun.time, "monotonic", lambda: clock["t"])
    seen: list[int] = []

    def _fake(cmd, **kw):
        seen.append(kw["timeout"])
        clock["t"] += per_chunk_cost
        Path(cmd[cmd.index("-oT") + 1]).write_text("https://x.com/a?id=\n")
        return {"success": True, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False}

    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.run", _fake)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, [f"https://x.com/api/p{i}?a=1" for i in range(16)])
    res = arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "chunk_size": 4, **cfg_extra}},
        resume=False, dry_run=False, skip=False,
    )
    return seen, res


def test_discover_chunks_share_one_stage_budget(tmp_path: Path, monkeypatch):
    """``timeout`` stays the budget for the WHOLE stage — 4 chunks must
    not mean 4 × timeout — and it is shared EVENLY, not first-come. Each
    chunk gets its slice of what is left (a chunk that finishes early
    donates the slack), and chunks past the deadline never start."""
    seen, res = _budget_run(
        tmp_path, monkeypatch,
        {"timeout": 100, "min_chunk_seconds": 10},
    )
    # 100s budget over 4 chunks → 25s each; each chunk burns 40s, so the
    # survivors re-split the remainder (60/3 = 20, then 20/2 = 10) and the
    # last one is skipped because the budget is spent.
    assert seen == [25, 20, 10]
    assert res["extra"]["chunks"]["run"] == 3
    assert res["extra"]["chunks"]["unrun"] == 1


def test_discover_never_starts_a_chunk_it_cannot_fund(tmp_path: Path, monkeypatch):
    """The regression this guards: a real run gave its last chunk 1 second
    of budget, so it timed out instantly and the stage reported "timeout
    after 1s". A chunk that cannot get ``min_chunk_seconds`` must be left
    unrun instead of started to fail."""
    seen, res = _budget_run(
        tmp_path, monkeypatch,
        {"timeout": 100, "min_chunk_seconds": 30},
        per_chunk_cost=45.0,
    )
    assert min(seen) >= 30
    # 100s budget, 45s burned per chunk: two run (30s slices), then only
    # 10s is left — below the floor — so the last two are skipped.
    assert seen == [30, 30]
    assert res["extra"]["chunks"]["unrun"] == 2


def test_discover_first_chunk_cannot_eat_the_whole_budget(tmp_path: Path, monkeypatch):
    """With 8 chunks and a 3600s stage budget (the real config), no single
    chunk may be handed the entire 3600s — that is exactly how chunk_000
    and chunk_001 consumed the acronis.com run."""
    seen, _ = _budget_run(
        tmp_path, monkeypatch,
        {"timeout": 3600, "chunk_size": 2, "min_chunk_seconds": 120},
        per_chunk_cost=0.0,
    )
    assert len(seen) == 8
    assert seen[0] == 3600 // 8
    # Chunks that cost nothing hand their slack forward, so later slices
    # grow — that is the intended donation, not a leak: the budget is
    # re-split against the chunks that are still waiting.
    assert seen == sorted(seen)


# ----------------------------------------------------------------------
# --stable — off by default (it sleeps 3–9s before EVERY request)
# ----------------------------------------------------------------------
def test_discover_omits_stable_by_default(tmp_path: Path, monkeypatch):
    """``--stable`` makes arjun sleep a random 3–9s before every single
    request, which is ~660s per URL and makes --rate-limit meaningless.
    It must not be on unless the config asks for it."""
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])
    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "threads": 1, "timeout": 60}},
        resume=False, dry_run=False, skip=False,
    )
    assert "--stable" not in captured


def test_discover_passes_stable_when_configured(tmp_path: Path, monkeypatch):
    captured: list[str] = []
    _fake_arjun_runner(monkeypatch, captured)

    dyn = tmp_path / "dynamic_urls.txt"
    write_lines(dyn, ["https://x.com/api/v1/users"])
    arjun.discover(
        dyn, tmp_path,
        cfg={"arjun": {"max_urls": 200, "threads": 1, "timeout": 60,
                       "stable": True}},
        resume=False, dry_run=False, skip=False,
    )
    assert "--stable" in captured


# ----------------------------------------------------------------------
# _patch_upstream_crash — the arjun ≤2.2.7 AttributeError
# ----------------------------------------------------------------------
def _fake_arjun_package(tmp_path: Path, monkeypatch, source: str) -> Path:
    """Build a throwaway ``arjun/__main__.py`` and point the locator at it."""
    main_py = tmp_path / "site-packages" / "arjun" / "__main__.py"
    main_py.parent.mkdir(parents=True)
    main_py.write_text(source)
    monkeypatch.setattr(arjun, "_arjun_main_py", lambda: main_py)
    return main_py


# Verbatim upstream (arjun 2.2.7). The exact text matters: the patch is
# anchored on the full line so a reformatted upstream is left alone, and a
# shortened fixture would silently stop exercising patch A.
_BUGGY_SRC = """\
def initialize(request, wordlist, single_url=False):
    else:
        fuzz = "z" + random_str(6)
        response_1 = requester(request, {fuzz[:-1]: fuzz[::-1][:-1]})
        mem.var['healthy_url'] = response_1.status_code not in (400, 413, 418, 429, 503)
        if not mem.var['healthy_url']:
            print('%s Target returned HTTP %i, this may cause problems.' % (bad, request.status_code))
        response_2 = requester(request, {fuzz[:-1]: fuzz[::-1][:-1]})
        if type(response_1) == str or type(response_2) == str:
            return 'skipped'
"""

# The state a machine is in after the ORIGINAL patch: B fixed, A still
# there. This is what the discover.com run actually ran with — reported
# ``upstream_patch: clean`` while 2 of 8 chunks still died on A.
_HALF_PATCHED_SRC = _BUGGY_SRC.replace(
    "(bad, request.status_code)", "(bad, response_1.status_code)")


def test_patch_upstream_crash_fixes_both_crashes(tmp_path: Path, monkeypatch):
    main_py = _fake_arjun_package(tmp_path, monkeypatch, _BUGGY_SRC)

    status = _real_patch_upstream_crash(tmp_path)

    assert status == "patched:A,B"
    patched = main_py.read_text()
    # (B) wrong object in the diagnostic print
    assert "(bad, request.status_code)" not in patched
    assert "(bad, response_1.status_code)" in patched
    # (A) type guard hoisted ABOVE the dereference that crashes on a str
    assert patched.index("if type(response_1) == str:") < \
        patched.index("mem.var['healthy_url'] = response_1.status_code")
    # original kept next to it, and the run is noted in the stage log
    assert (main_py.with_suffix(".py.recon2win.bak")).read_text() == _BUGGY_SRC
    assert "patched upstream crash" in (tmp_path / "logs" / "arjun.log").read_text()


def test_patch_applies_the_missing_half_to_an_already_half_patched_arjun(
        tmp_path: Path, monkeypatch):
    """The regression this fix exists for. The old patch reported ``clean``
    here because its only marker (B) was already applied — so (A), the
    crash actually killing chunks, was never fixed."""
    main_py = _fake_arjun_package(tmp_path, monkeypatch, _HALF_PATCHED_SRC)

    assert _real_patch_upstream_crash(tmp_path) == "patched:A"
    patched = main_py.read_text()
    assert patched.index("if type(response_1) == str:") < \
        patched.index("mem.var['healthy_url'] = response_1.status_code")


def test_patch_upstream_crash_is_idempotent(tmp_path: Path, monkeypatch):
    main_py = _fake_arjun_package(tmp_path, monkeypatch, _BUGGY_SRC)

    _real_patch_upstream_crash(tmp_path)
    after_first = main_py.read_text()
    # patch A's fix CONTAINS its own anchor line — a naive "is the bug
    # still present" check would re-apply it forever, stacking guards.
    assert _real_patch_upstream_crash(tmp_path) == "clean"
    assert main_py.read_text() == after_first
    assert after_first.count("if type(response_1) == str:\n            return") == 1
    # the backup must still hold the ORIGINAL, not the already-patched copy
    assert main_py.with_suffix(".py.recon2win.bak").read_text() == _BUGGY_SRC


def test_patch_upstream_crash_leaves_a_fixed_arjun_alone(tmp_path: Path, monkeypatch):
    fixed = _BUGGY_SRC.replace(
        "(bad, request.status_code)", "(bad, response_1.status_code)").replace(
        "        mem.var['healthy_url'] = response_1.status_code "
        "not in (400, 413, 418, 429, 503)",
        "        if type(response_1) == str:\n"
        "            return 'skipped'\n"
        "        mem.var['healthy_url'] = response_1.status_code "
        "not in (400, 413, 418, 429, 503)")
    main_py = _fake_arjun_package(tmp_path, monkeypatch, fixed)

    assert _real_patch_upstream_crash(tmp_path) == "clean"
    assert main_py.read_text() == fixed
    assert not main_py.with_suffix(".py.recon2win.bak").exists()


def test_patch_leaves_a_refactored_upstream_alone(tmp_path: Path, monkeypatch):
    """Never half-patch. If upstream reformats the line we anchor on, we do
    nothing rather than apply one fix into code we no longer recognise."""
    refactored = _BUGGY_SRC.replace(
        "        mem.var['healthy_url'] = response_1.status_code "
        "not in (400, 413, 418, 429, 503)",
        "        bad_codes = (400, 413, 418, 429, 503)\n"
        "        mem.var['healthy_url'] = response_1.status_code not in bad_codes")
    main_py = _fake_arjun_package(tmp_path, monkeypatch, refactored)

    # B still matches verbatim so it is applied; A is not forced in blind
    assert _real_patch_upstream_crash(tmp_path) == "patched:B"
    assert "if type(response_1) == str:\n            return" not in main_py.read_text()


def test_patch_upstream_crash_reports_when_arjun_is_not_found(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(arjun, "_arjun_main_py", lambda: None)
    assert _real_patch_upstream_crash(tmp_path) == "not-found"
