"""End-to-end tests for main._run_stage().

We exercise the per-stage runner to make sure it:
  * prints the phase header, status line, AND output paths
  * sends a telegram notification (if configured) per phase
  * extracts output_dir + cfg from the positional arg list

The mocked stage function returns a realistic make_result() dict so
we don't have to install any of the real tools.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


from main import _run_stage
from modules.utils import make_result


def _fake_stage(
    input_path,
    output_dir: Path,
    cfg: dict,
    *,
    count: int = 5,
    status: str = "success",
    outputs: list | None = None,
    extra: dict | None = None,
):
    """Build a fake stage function that returns a realistic result dict."""
    if outputs is None:
        outputs = [output_dir / "processed" / "result.txt",
                  output_dir / "raw" / "stage" / "out.txt"]
    # make_result() filters out output paths that don't exist on disk, so a
    # realistic stage must actually create its files. Touch them here so the
    # paths survive into the result and get printed/notified.
    for p in outputs:
        p = Path(p)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()
    return make_result(
        "fake_stage", status,
        input_path=input_path,
        outputs=outputs,
        count=count,
        extra=extra or {},
    )


def test_run_stage_prints_output_paths(capsys, tmp_path: Path):
    """The phase output paths must appear under the status line so
    operators can see "where did this stage write?" at a glance."""
    output_dir = tmp_path / "out"
    cfg = {"telegram": {"enabled": False}}

    _run_stage("fake_stage", _fake_stage,
               Path("/in"), output_dir, cfg)

    captured = capsys.readouterr()
    # Status line printed
    assert "fake_stage" in captured.out
    assert "5 results" in captured.out or "5" in captured.out
    # Output paths printed (relative to output_dir)
    assert "processed/result.txt" in captured.out
    assert "raw/stage/out.txt" in captured.out


def test_run_stage_does_not_print_paths_when_no_outputs(capsys, tmp_path: Path):
    """A stage with no outputs shouldn't print a stray "→" line."""
    output_dir = tmp_path / "out"
    cfg = {"telegram": {"enabled": False}}

    def no_outputs(input_path, output_dir, cfg):
        return make_result("empty", "success", count=0, outputs=[])
    _run_stage("empty", no_outputs, Path("/in"), output_dir, cfg)

    captured = capsys.readouterr()
    assert "→" not in captured.out


def test_run_stage_sends_telegram_when_per_phase_enabled(capsys, tmp_path: Path):
    """With telegram.per_phase: true, every successful stage triggers
    a notification containing the count + paths."""
    output_dir = tmp_path / "out"
    cfg = {"telegram": {
        "enabled": True, "bot_token": "T", "chat_id": "C",
        "per_phase": True,
    }}

    with patch("modules.telegram._post") as post:
        post.return_value = True
        _run_stage("fake_stage", _fake_stage,
                   Path("/in"), output_dir, cfg)

        # Exactly one telegram message was sent
        post.assert_called_once()
        msg = post.call_args[0][2]
        assert "fake_stage" in msg
        assert "5" in msg  # count


def test_run_stage_does_not_send_telegram_when_per_phase_disabled(
    capsys, tmp_path: Path
):
    output_dir = tmp_path / "out"
    cfg = {"telegram": {
        "enabled": True, "bot_token": "T", "chat_id": "C",
        "per_phase": False,  # default
    }}

    with patch("modules.telegram._post") as post:
        _run_stage("fake_stage", _fake_stage,
                   Path("/in"), output_dir, cfg)
        post.assert_not_called()


def test_run_stage_skips_telegram_on_failure(capsys, tmp_path: Path):
    """Failed stages don't get per-phase notifications — the milestone
    summary covers them."""
    output_dir = tmp_path / "out"
    cfg = {"telegram": {
        "enabled": True, "bot_token": "T", "chat_id": "C",
        "per_phase": True,
    }}

    def failing(input_path, output_dir, cfg):
        return make_result("failed", "failed", count=0, error="boom")

    with patch("modules.telegram._post") as post:
        _run_stage("failed", failing, Path("/in"), output_dir, cfg)
        post.assert_not_called()


def test_run_stage_includes_elapsed_seconds_in_extra(tmp_path: Path):
    """The stage runner always records elapsed time in result.extra
    so the report can use it for timing breakdowns."""
    output_dir = tmp_path / "out"
    cfg = {"telegram": {"enabled": False}}

    captured: dict = {}

    def capturing_stage(input_path, output_dir, cfg):
        result = _fake_stage(input_path, output_dir, cfg, count=3)
        captured["result"] = result
        return result

    _run_stage("captured", capturing_stage, Path("/in"), output_dir, cfg)

    assert "elapsed_seconds" in captured["result"]["extra"]
    assert captured["result"]["extra"]["elapsed_seconds"] >= 0


def test_run_stage_dry_run_prints_planned_command(capsys, tmp_path: Path):
    """When a stage sets extra['planned_cmd'], _run_stage echoes it
    so the operator can sanity-check the argv."""
    output_dir = tmp_path / "out"
    cfg = {"telegram": {"enabled": False}}

    def with_plan(input_path, output_dir, cfg):
        return make_result(
            "planned", "skipped", count=0,
            error="dry-run",
            extra={"planned_cmd": ["fake-tool", "--flag", "value"]},
        )

    _run_stage("planned", with_plan, Path("/in"), output_dir, cfg)
    captured = capsys.readouterr()
    assert "fake-tool --flag value" in captured.out