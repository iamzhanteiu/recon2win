"""Shared test fixtures.

The one rule enforced here: **no test reaches the network by accident.**
"""
from __future__ import annotations

import pytest

from modules import baseline


@pytest.fixture(autouse=True)
def _no_baseline_probe(monkeypatch, request):
    """Stub out the baseline probe for every test that doesn't ask for it.

    ``fuzz_targets.load_targets`` probes each host with nonexistent paths
    before fuzzing (see modules/baseline.py). That is real httpx traffic, and
    it runs inside ``ffuf.scan`` / ``dirsearch.scan`` — so without this every
    fuzzing test would either hit the network or crash inside its own fake
    ``runner.run``, which is written to expect a ffuf argv and not an httpx
    one. Neither failure would be telling us anything about the code.

    Returns no baselines, which is exactly what ``measure`` returns when the
    probe cannot run — so the stubbed path is a real, supported one rather
    than a fiction that only exists in tests.

    Opt back in with ``@pytest.mark.baseline`` when the probe *is* the
    subject under test.
    """
    if request.node.get_closest_marker("baseline"):
        return
    monkeypatch.setattr(
        baseline, "measure",
        lambda targets, output_dir, cfg=None, **kw: (
            {t: baseline.Baseline(t) for t in targets},
            {"targets": len(targets), "error": "stubbed in tests"},
        ),
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "baseline: test exercises the real baseline probe path",
    )
