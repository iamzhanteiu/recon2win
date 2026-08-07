"""baseline — ask each host what a *nonexistent* path looks like, first.

Content discovery is a comparison, and the pipeline never established what
it was comparing against. Two things went wrong on the discover.com run
because of that:

1. **We fuzzed hosts that cannot be fuzzed.** Eleven hosts answered every
   single request with the same Akamai block page. ffuf spent its whole
   3,600s budget producing 44,230 copies of it. One probe per host, three
   requests each, would have cost about a second and skipped all eleven.

2. **We deduplicated on the wrong signal.** ``fuzz_targets`` grouped hosts
   by their *home page* (``alive_detail.json`` is the response to ``/``).
   But what decides whether a host is worth fuzzing is how it answers a path
   that isn't there. Those eleven hosts had distinct home pages — so they
   were never grouped — while behaving identically everywhere else.

Both are the same measurement: request a few paths that certainly do not
exist and look at what comes back.

* All the answers identical **and** matching what the fuzzer counts as a
  hit ⇒ the host cannot distinguish real paths from fake ones. Skip it.
* Otherwise the shared answer is this host's "not found" shape, and any
  later hit wearing that shape is noise (see :func:`Baseline.is_noise`).
* The shape is also a far better dedup key than the home page.

One httpx call covers every target at once, so the whole thing costs one
extra probe round for the stage, not one per host.
"""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import behavior, runner
from .utils import make_result, raw_dir, write_lines

# Paths that cannot plausibly exist. Deliberately varied in length and
# shape: a block page that echoes the requested path produces a different
# byte count for each of these, which is exactly the property that must not
# fool us into thinking the responses differ.
_PROBE_SHAPES = (
    "{r}",
    "{r}/{r}",
    "{r}.{ext}",
)
_PROBE_EXTS = ("html", "json", "php")

# The only answers that prove a host distinguishes real paths from fake ones.
_NOT_FOUND_STATUS = frozenset({404, 410})


def probe_paths(n: int = 3, *, rand=None) -> list[str]:
    """*n* paths that will not exist, in deliberately different shapes."""
    gen = rand or (lambda: secrets.token_hex(8))
    out: list[str] = []
    for i in range(max(1, n)):
        shape = _PROBE_SHAPES[i % len(_PROBE_SHAPES)]
        out.append("/" + shape.format(
            r=gen(), ext=_PROBE_EXTS[i % len(_PROBE_EXTS)],
        ))
    return out


@dataclass
class Baseline:
    """What one host does with paths that do not exist."""

    target: str
    responses: list[behavior.Behavior] = field(default_factory=list)
    # The single shape every probe came back as, or None when they differed.
    shape: tuple | None = None

    @property
    def probed(self) -> bool:
        return bool(self.responses)

    @property
    def consistent(self) -> bool:
        """Every nonexistent path produced the same response."""
        return self.shape is not None

    def is_blanket(self, match_status: set[int] | None = None) -> bool:
        """The host cannot tell a real path from a fake one.

        The test is simply: *did it give a proper "not found"?* A host that
        consistently 404s (or 410s) is healthy and **must** be fuzzed. Any
        other consistent answer — 403 behind an edge deny, 200 from an SPA
        catch-all, 301 to a fixed landing page, 503 from a host that is
        simply down — means every word in the wordlist will look like a hit.

        This used to be keyed on the caller's ``match_status`` instead, which
        was wrong in both directions on the real target: ``mapi.discover.com``
        answers 503 to everything (not in ffuf's match list, so it passed the
        check) and ffuf then produced 3,715 "hits" on it. ``match_status`` is
        still accepted and ignored so existing callers keep working.
        """
        if not self.consistent:
            return False
        return self.responses[0].status not in _NOT_FOUND_STATUS

    def is_noise(self, b: behavior.Behavior, *, length_tolerance: int = 16) -> bool:
        """True when *b* looks exactly like this host's not-found answer."""
        if not self.consistent:
            return False
        return behavior.fingerprint(
            b, length_tolerance=length_tolerance) == self.shape

    def dedup_key(self) -> tuple:
        """Group hosts that behave identically on nonexistent paths.

        Replaces the home-page fingerprint. Hosts with no usable probe get a
        key of their own (keyed on the target) so a failed measurement never
        silently collapses two different hosts into one.
        """
        return self.shape if self.consistent else ("unprobed", self.target)


def _shape_of(responses: list[behavior.Behavior],
              length_tolerance: int) -> tuple | None:
    keys = {behavior.fingerprint(r, length_tolerance=length_tolerance)
            for r in responses}
    return next(iter(keys)) if len(keys) == 1 else None


def row_to_behavior(row: dict) -> behavior.Behavior:
    return behavior.Behavior(
        url=str(row.get("url") or ""),
        status=int(row.get("status_code") or 0),
        length=int(row.get("content_length") or 0),
        words=int(row.get("words", behavior.UNKNOWN)),
        lines=int(row.get("lines", behavior.UNKNOWN)),
        content_type=str(row.get("content_type") or ""),
        location=str(row.get("location") or ""),
    )


def _probe_ffuf(
    targets: list[str], paths: list[str], rdir: Path, slug: str,
    output_dir: Path, stage: str, *, threads: int, rate: int, timeout: int,
) -> tuple[list[behavior.Behavior], str]:
    """Probe with **ffuf itself**, one process for every target.

    This exists because probing with a different client measures a different
    target. Measured on discover.com: httpx got a clean ``404 26b`` from
    ``webapp.src.discover.com`` — a perfectly healthy, fuzzable host — while
    ffuf got a 403 block page for every request, because Akamai Bot Manager
    fingerprints ffuf specifically. The httpx-based baseline therefore passed
    the host as fine and ffuf then burned its budget producing 4,082 copies
    of the block page. A probe is only worth anything if it is subject to the
    same treatment as the thing it is predicting.

    ``clusterbomb`` over two wordlists (hosts × probe paths) covers every
    target in a single ffuf run, so the whole probe costs one process rather
    than one per host.
    """
    hosts_wl = rdir / f"probe_hosts_{slug}.txt"
    paths_wl = rdir / f"probe_paths_{slug}.txt"
    write_lines(hosts_wl, [t.rstrip("/") for t in targets])
    write_lines(paths_wl, [p.lstrip("/") for p in paths])
    out_file = rdir / f"probe_{slug}.json"

    cmd = [
        "ffuf", "-u", "HOSTW/PATHW",
        "-w", f"{hosts_wl}:HOSTW", "-w", f"{paths_wl}:PATHW",
        "-mode", "clusterbomb",
        # Record EVERY response. The default matcher hides 404s, which are
        # exactly the answers that prove a host is healthy.
        "-mc", "all",
        "-o", str(out_file), "-of", "json",
        "-t", str(threads), "-noninteractive", "-s",
    ]
    if rate > 0:
        cmd.extend(["-rate", str(rate)])
    runner.run(cmd, stage=stage, log_name=stage,
               output_dir=output_dir, timeout=timeout)
    if not out_file.exists():
        return [], "ffuf wrote no probe report"
    from . import ffuf as ffuf_mod          # local: ffuf imports baseline
    return ffuf_mod.parse_report(out_file.read_text(errors="ignore")), ""


def measure(
    targets: list[str],
    output_dir: Path,
    cfg: dict | None = None,
    *,
    stage: str = "baseline",
    client: str = "httpx",
) -> tuple[dict[str, Baseline], dict]:
    """Probe every target with nonexistent paths. Returns ``(by_target, stats)``.

    ``client`` selects **which HTTP client does the probing**, and it must be
    the one that will do the fuzzing — see :func:`_probe_ffuf` for the
    measured reason. ``"httpx"`` is the default and is right for stages whose
    own client is httpx-like; ``"ffuf"`` probes with ffuf.

    Fails open on purpose: a missing binary, a crash, or a timeout yields
    empty baselines, and every caller then behaves exactly as it did before
    this module existed. Being unable to measure must never cost us targets.
    """
    b_cfg = (cfg or {}).get("baseline") or {}
    n_probes = int(b_cfg.get("probes", 3))
    tolerance = int(b_cfg.get("length_tolerance", 16))
    timeout = int(b_cfg.get("timeout", 600))
    threads = int(b_cfg.get("threads", 40))

    by_target: dict[str, Baseline] = {t: Baseline(t) for t in targets}
    stats: dict = {"targets": len(targets), "probes": n_probes, "client": client}
    if not targets:
        return by_target, stats
    if not runner.tool_available(client):
        stats["error"] = f"{client} binary not found"
        return by_target, stats

    paths = probe_paths(n_probes)

    # Per-stage filenames, NOT shared ones. Stage 4 runs dirsearch, ffuf and
    # content_discovery concurrently, and each calls measure(); with one
    # ``probe_urls.txt`` / ``probe.jsonl`` pair between them they overwrite
    # each other mid-flight. Observed on a real discover.com run: ffuf's
    # results were replaced by dirsearch's, so ``url_owner`` matched nothing,
    # every host came back unprobed, and 68 blanket hosts were fuzzed anyway
    # — the failure looked exactly like the feature being switched off.
    rdir = raw_dir(output_dir, "baseline")
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", stage) or "baseline"

    if client == "ffuf":
        hits, err = _probe_ffuf(
            targets, paths, rdir, slug, output_dir, stage,
            threads=threads, rate=int(b_cfg.get("rate", 0) or 0),
            timeout=timeout,
        )
        if err:
            stats["error"] = err
            return by_target, stats
        prefixes = sorted(((t.rstrip("/"), t) for t in targets),
                          key=lambda kv: -len(kv[0]))
        for b in hits:
            owner = next((t for pre, t in prefixes if b.url.startswith(pre)), None)
            if owner is not None:
                by_target[owner].responses.append(b)
    else:
        urls: list[str] = []
        url_owner: dict[str, str] = {}
        for t in targets:
            for p in paths:
                u = t.rstrip("/") + p
                urls.append(u)
                url_owner[u] = t

        in_file = rdir / f"probe_urls_{slug}.txt"
        write_lines(in_file, urls)
        out_file = rdir / f"probe_{slug}.jsonl"

        r = runner.run(
            ["httpx", "-l", str(in_file), "-json", "-silent", "-no-color",
             "-threads", str(threads), "-timeout", "10",
             "-o", str(out_file)],
            stage=stage, log_name=stage, output_dir=output_dir, timeout=timeout,
        )
        # httpx writes JSONL to -o, but has been seen to leave the file absent
        # while still emitting on stdout — read whichever we actually got.
        text = ""
        if out_file.exists():
            text = out_file.read_text(errors="ignore")
        if not text.strip():
            text = r.get("stdout") or ""
        if not text.strip():
            # Say WHICH failure. A timeout here is not "the target has no
            # baseline" — it is the probe being starved, and it degrades the
            # whole feature to nothing. On a real discover.com run the httpx
            # probe hit its 180s budget because ffuf's own probe and scan
            # were hammering the same 154 hosts at that moment; target
            # selection then silently fell back to home-page dedup and no
            # blanket host was skipped at all.
            stats["error"] = ("probe timed out after "
                              f"{timeout}s — no baseline, nothing skipped"
                              if r.get("timed_out") else "no probe responses")
            stats["timed_out"] = bool(r.get("timed_out"))
            return by_target, stats

        for ln in text.splitlines():
            ln = ln.strip()
            if not ln or not ln.startswith("{"):
                continue
            try:
                row = json.loads(ln)
            except ValueError:
                continue
            owner = url_owner.get(str(row.get("input") or row.get("url") or ""))
            if owner is None:
                continue
            by_target[owner].responses.append(row_to_behavior(row))

    for bl in by_target.values():
        bl.shape = _shape_of(bl.responses, tolerance)

    stats["responded"] = sum(1 for b in by_target.values() if b.probed)
    stats["consistent"] = sum(1 for b in by_target.values() if b.consistent)
    return by_target, stats


def split_fuzzable(
    baselines: dict[str, Baseline], match_status: set[int],
) -> tuple[list[str], list[str]]:
    """``(worth_fuzzing, blanket)``.

    A target we could not measure stays in ``worth_fuzzing``: an unusable
    probe is not evidence against a host, and the post-hoc screen in
    :func:`behavior.screen` still covers us if it turns out to be blanket.
    """
    fuzzable: list[str] = []
    blanket: list[str] = []
    for target, bl in baselines.items():
        (blanket if bl.is_blanket(match_status) else fuzzable).append(target)
    return fuzzable, blanket


def summary(stats: dict, blanket: list[str]) -> dict:
    """Stage-result ``extra`` block for the caller."""
    out = dict(stats)
    out["blanket_hosts"] = len(blanket)
    if blanket:
        out["blanket_sample"] = blanket[:5]
    return out


def result(output_dir: Path, stats: dict, blanket: list[str]) -> dict:
    """Standalone stage-result, for callers that log the probe separately."""
    return make_result(
        "baseline", "success", input_path=str(output_dir),
        count=stats.get("responded", 0), extra=summary(stats, blanket),
    )


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def load_from_raw(output_dir: Path, *, length_tolerance: int = 16) -> dict[str, Baseline]:
    """Reconstruct per-host not-found baselines from the raw probe files
    stage 4 already wrote — no new requests.

    ``measure()`` runs once per content-discovery stage (dirsearch, ffuf,
    content_discovery) and leaves its raw probe output in
    ``raw/baseline/probe_<stage>.jsonl`` (httpx client) or
    ``raw/baseline/probe_<stage>.json`` (ffuf client, one clusterbomb report
    for every target). A stage that never goes through
    :func:`split_fuzzable` at all — jsluice-mined URLs are verified by
    ``jsluice_verify.py``, never fuzzed — has no other way to ask "is this
    host's real response noise?" without probing again. This answers it
    from what is already on disk.

    Fails open like the rest of this module: no ``raw/baseline`` directory
    (baseline disabled, or nothing ever wrote one) yields ``{}``, and every
    caller then treats every host as unknown rather than noise.
    """
    rdir = output_dir / "raw" / "baseline"
    if not rdir.is_dir():
        return {}

    by_host: dict[str, list[behavior.Behavior]] = {}

    for jf in sorted(rdir.glob("probe_*.jsonl")):
        for ln in jf.read_text(errors="ignore").splitlines():
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                row = json.loads(ln)
            except ValueError:
                continue
            host = _host_of(str(row.get("input") or row.get("url") or ""))
            if host:
                by_host.setdefault(host, []).append(row_to_behavior(row))

    for jf in sorted(rdir.glob("probe_*.json")):
        from . import ffuf as ffuf_mod   # local: ffuf imports baseline
        try:
            hits = ffuf_mod.parse_report(jf.read_text(errors="ignore"))
        except Exception:                # noqa: BLE001 — malformed report, skip
            continue
        for b in hits:
            host = _host_of(b.url)
            if host:
                by_host.setdefault(host, []).append(b)

    out: dict[str, Baseline] = {}
    for host, responses in by_host.items():
        bl = Baseline(host, responses=responses)
        bl.shape = _shape_of(responses, length_tolerance)
        out[host] = bl
    return out
