"""arjun — stage 7: parameter discovery on dynamic URLs."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import layout, runner, url_merge
from .utils import make_result, raw_dir, read_lines, safe_append, write_lines


# Heuristics for "this URL is worth fuzzing" — we sort dynamic URLs by
# these markers and keep only the top ``arjun.max_urls`` so the stage
# finishes in a predictable amount of time even on a 5k+ URL target.
# Without this cap, arjun will happily spend an hour fuzzing every
# archived URL waymore collected from the Wayback Machine.
_HIGH_VALUE_HINTS = (
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/query",
    "/search", "/login", "/admin", "/user", "/account",
    "/order", "/product", "/cart", "/checkout", "/payment",
    "/reset", "/forgot", "/signup", "/register",
    "?", "id=", "q=", "page=", "token=",
)


def _source_mix(
    urls: list[str], sources: dict[str, list[str]],
) -> dict[str, int]:
    """``{source: count}`` for the URLs that actually survived the cap.

    Recorded in the stage result so "arjun found 3 params" can be read
    against what it was pointed at. Three params off 200 jsluice endpoints
    means something; three off 200 ffuf wildcard hits means nothing.
    """
    mix: dict[str, int] = {}
    for u in urls:
        for s in sources.get(u) or ("unknown",):
            mix[s] = mix.get(s, 0) + 1
    return dict(sorted(mix.items(), key=lambda kv: -kv[1]))


def _score(url: str) -> int:
    """Higher = more interesting to fuzz. Ties break on URL length
    (shorter URLs first so we keep canonical endpoints)."""
    lo = url.lower()
    score = sum(2 if h in lo else 0 for h in _HIGH_VALUE_HINTS)
    # demote obvious archive cruft — waymore / waybackmachine noise
    if "web.archive.org" in lo or "webcache.googleusercontent" in lo:
        score -= 5
    return score


# ----------------------------------------------------------------------
# Upstream crash patch (arjun ≤ 2.2.7)
# ----------------------------------------------------------------------
# ``arjun/__main__.py`` (initialize()) probes the target like this:
#
#     response_1 = requester(request, {...})
#     mem.var['healthy_url'] = response_1.status_code not in (400,…,503)   # (A)
#     if not mem.var['healthy_url']:
#         print('... HTTP %i ...' % (bad, request.status_code))            # (B)
#     ...
#     response_2 = requester(request, {...})
#     if type(response_1) == str or type(response_2) == str:               # (C)
#         return 'skipped'
#
# TWO separate crashes live in there, and they need DIFFERENT fixes:
#
#   (B) ``request`` is the plain dict arjun built the request from, so the
#       moment a target answers 400/413/418/429/503 to the probe:
#           AttributeError: 'dict' object has no attribute 'status_code'
#       The intended value is obviously ``response_1.status_code``.
#
#   (A) ``requester()`` returns a plain STRING on a connection-level error
#       — upstream knows this, that is exactly what check (C) is for. But
#       (A) dereferences ``response_1`` several lines BEFORE (C) runs:
#           AttributeError: 'str' object has no attribute 'status_code'
#       Fixing (B) alone does not help; (A) crashes first and is the one
#       actually killing chunks. Measured on the discover.com run: 2 of 8
#       chunks died here (195s) AFTER (B) had already been patched — see
#       logs/arjun.log, ``upstream_patch: clean`` yet ``failed: 2``.
#
# Neither is an edge case: (B) fires on any WAF / rate limiter / endpoint
# that 400s an unknown query param, (A) on any host that refuses or drops
# the connection. A real acronis.com run lost 2 chunks (44 minutes) to it.
#
# Fix for (A) is to hoist upstream's OWN check (C) above the dereference —
# same behaviour it already chose for a string response, just reached
# before crashing instead of after. We rewrite these expressions in the
# installed package, keeping a ``.recon2win.bak`` next to it. Each patch is
# independently idempotent, is a no-op on an arjun that already fixed the
# bug, and never touches a line that doesn't match verbatim — so a future
# upstream refactor is left alone rather than half-patched.

# (B) — wrong object dereferenced in the diagnostic print.
_BUG_B = "(bad, request.status_code)"
_FIX_B = "(bad, response_1.status_code)"

# (A) — dereference before the type guard. Anchored on the full line so a
# reformatted upstream is left untouched rather than half-patched.
_BUG_A = (
    "        mem.var['healthy_url'] = response_1.status_code "
    "not in (400, 413, 418, 429, 503)"
)
_FIX_A = (
    "        if type(response_1) == str:\n"
    "            return 'skipped'\n"
) + _BUG_A

# (bug, fix) applied in order. ``fix`` doubles as the already-applied
# marker, so a patch whose fix CONTAINS its bug (like A) stays idempotent.
_PATCHES = [("A", _BUG_A, _FIX_A), ("B", _BUG_B, _FIX_B)]


def _arjun_main_py() -> Optional[Path]:
    """Locate ``arjun/__main__.py`` for the interpreter that actually runs
    the ``arjun`` binary on $PATH.

    We ask that interpreter instead of importing arjun ourselves: the
    pipeline usually runs from ``.venv`` while arjun lives in the user
    site-packages of the system python, so a plain ``import arjun`` here
    would find nothing (or, worse, a different copy than the one the
    stage is about to execute)."""
    exe = runner.which("arjun")
    if not exe:
        return None
    interp = sys.executable
    try:
        first_line = Path(exe).read_text(errors="ignore").splitlines()[0]
    except (OSError, IndexError):
        first_line = ""
    if first_line.startswith("#!"):
        cand = first_line[2:].strip().split(" ")[0]
        if cand and Path(cand).exists():
            interp = cand
    try:
        proc = subprocess.run(
            [interp, "-c",
             "import arjun, os; print(os.path.dirname(arjun.__file__))"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    main_py = Path(proc.stdout.strip()) / "__main__.py"
    return main_py if main_py.is_file() else None


def _patch_upstream_crash(output_dir: Path) -> str:
    """Fix the two ``status_code`` crashes in the installed arjun.

    Returns a short status for the stage log: ``patched:<ids>`` (which
    patches we just applied, e.g. ``patched:A``), ``clean`` (nothing to fix
    — already patched or a newer arjun), ``not-found`` (couldn't locate the
    package) or ``failed: <reason>``.

    Each patch is checked independently, so an install that already carries
    one fix still gets the other — the exact state the discover.com run was
    in (B applied, A missing, chunks still dying).
    """
    main_py = _arjun_main_py()
    if main_py is None:
        return "not-found"
    try:
        src = main_py.read_text(errors="ignore")
    except OSError as exc:
        return f"failed: {exc}"

    original = src
    applied: list[str] = []
    for name, bug, fix in _PATCHES:
        if fix in src:
            continue          # already carries this fix
        if bug not in src:
            continue          # upstream refactored it — leave alone
        src = src.replace(bug, fix)
        applied.append(name)

    if not applied:
        return "clean"
    try:
        backup = main_py.with_suffix(".py.recon2win.bak")
        if not backup.exists():
            backup.write_text(original)
        main_py.write_text(src)
    except OSError as exc:
        # Read-only site-packages (system install, root-owned). Chunking
        # still bounds the damage, so this is a warning, not a failure.
        return f"failed: {exc}"
    safe_append(
        output_dir / "logs" / "arjun.log",
        f"[recon2win] patched upstream crash(es) {','.join(applied)} in "
        f"{main_py}; backup at {backup.name}",
    )
    return f"patched:{','.join(applied)}"


def _outputs_exist(out_dir: Path) -> bool:
    p = layout.path(out_dir, "arjun_params.txt")
    return p.exists() and p.stat().st_size > 0


def _write_input_subset(output_dir: Path, urls: list[str]) -> Path:
    """Write the prioritised subset to ``raw/arjun/input_subset.txt`` so
    arjun reads only those. Returns the path to the subset file.

    The subset lives under ``raw/`` (not ``processed/``) because it's
    a derived input to the tool, not a cleaned output of the stage.
    """
    subset = raw_dir(output_dir, "arjun") / "input_subset.txt"
    write_lines(subset, urls)
    return subset


def discover(
    dynamic_urls_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "arjun"
    layout.ensure_tree(output_dir)
    params_out = layout.path(output_dir, "arjun_params.txt")
    urls_out = layout.path(output_dir, "parameterized_urls.txt")

    if skip:
        params_out.write_text("")
        urls_out.write_text("")
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0, error="--skip-arjun",
        )

    if resume and _outputs_exist(output_dir):
        return make_result(
            stage, "success", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=len(read_lines(urls_out)),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0, error="dry-run",
        )

    if not runner.tool_available("arjun"):
        params_out.write_text("")
        urls_out.write_text("")
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0,
            error="arjun binary not found (optional, skipped)",
        )

    a_cfg = cfg.get("arjun", {})
    threads = int(a_cfg.get("threads", 5))
    timeout = int(a_cfg.get("timeout", 3600))
    max_urls = int(a_cfg.get("max_urls", 200))
    # Per-request timeout (arjun -T). Default is 15s, which is too generous
    # for archive noise — lower it so a single hung URL can't blow the
    # whole stage budget.
    request_timeout = int(a_cfg.get("request_timeout", 10))
    # arjun --rate-limit is requests **per second** (default 9999). 0/None
    # means "don't pass it" (use arjun's default).
    rate_limit = int(a_cfg.get("rate_limit", 0) or 0)
    # ``--stable`` is NOT a mild "be careful" switch: arjun's requester
    # does ``mem.var['delay'] = random.choice(range(3, 10))`` and sleeps
    # that long before EVERY request (arjun/core/requester.py). With a
    # 100-word wordlist split into ~103 chunks that is ~11 minutes per
    # URL, and it makes --rate-limit meaningless (the sleep dominates).
    # A measured acronis.com run spent 1325s on 3 URLs with it on.
    # Off by default; turn it on only for a target that rate-limits us
    # (arjun prints "try --stable switch" when it detects one).
    stable = bool(a_cfg.get("stable", False))

    # Fix the upstream crash before the first invocation — see
    # _patch_upstream_crash. Config escape hatch for anyone who does not
    # want the pipeline writing into site-packages.
    patch_status = "disabled"
    if a_cfg.get("patch_upstream", True):
        patch_status = _patch_upstream_crash(output_dir)

    urls = read_lines(dynamic_urls_file)
    if not urls:
        params_out.write_text("")
        urls_out.write_text("")
        return make_result(
            stage, "skipped", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0, error="no dynamic URLs to scan",
        )

    # Cap and prioritise. Without this cap, an aggressive crawler + waymore
    # can produce 5k+ dynamic URLs and arjun will sit fuzzing them for
    # hours before timing out at the 3600s mark.
    #
    # WHICH urls survive the cap matters more than the cap itself. Provenance
    # is the strongest available signal and it outranks the keyword
    # heuristics: on discover.com the corpus was 76% ffuf wildcard-403 noise,
    # so an unsorted top-200 was ~200 URLs that could never yield a param no
    # matter how promising their paths looked. Sorting by source first put
    # jsluice/apidocs endpoints (23.6% alive) at the head of the list.
    original_count = len(urls)
    sources = url_merge.load_url_sources(output_dir)
    if len(urls) > max_urls:
        ranked = sorted(
            urls,
            key=lambda u: (
                -url_merge.source_score(sources.get(u, ())),
                -_score(u),
                len(u),
                u,
            ),
        )
        urls = ranked[:max_urls]
    input_file = dynamic_urls_file if len(urls) == original_count \
        else _write_input_subset(output_dir, urls)

    # ------------------------------------------------------------------
    # Output flag: arjun's ``-o`` writes JSON ({url: {params, method}}),
    # NOT the ``[200] url`` text you see on the console. We want a flat
    # list of parameterised URLs for the shortlist, so we use
    # ``-oT`` (text) which writes exactly ``https://site/page?id=&q=``
    # (one per line; POST/JSON rows are ``url\t<params>``).
    #
    # ``-oT`` opens the file in append mode, so a leftover file from a
    # previous partial run would accumulate stale lines — delete it first.
    # ------------------------------------------------------------------
    if params_out.exists():
        params_out.unlink()

    def _cmd(chunk_input: Path) -> list[str]:
        c = [
            "arjun", "-i", str(chunk_input),
            "-oT", str(params_out),
            "-t", str(threads),
            "-T", str(request_timeout),
        ]
        if stable:
            c.append("--stable")
        if rate_limit > 0:
            c.extend(["--rate-limit", str(rate_limit)])
        return c

    # ------------------------------------------------------------------
    # Chunking. arjun crashes outright on some targets and takes every
    # REMAINING target with it — a real acronis.com run died at target
    # 2/200 with
    #     AttributeError: 'dict' object has no attribute 'status_code'
    #     (arjun/__main__.py:135, arjun 2.2.7)
    # which is arjun printing ``request.status_code`` on a non-2xx answer
    # where ``request`` is a plain dict. The URL that triggered it was an
    # ordinary OAuth endpoint. 198 targets were never scanned, 22 minutes
    # were spent, and arjun_params.txt was never created.
    #
    # ``_patch_upstream_crash`` above fixes that specific bug in place, but
    # chunking stays: arjun has other ways to die on a hostile target (the
    # error handler sets a global kill flag on 503/timeouts), so we bound
    # the blast radius anyway. We feed it ``chunk_size`` URLs per
    # invocation, so one poisoned URL costs its own chunk instead of the
    # stage. ``-oT`` appends, so each chunk's findings land in the same
    # file as they are discovered — nothing is lost when a later chunk
    # dies.
    #
    # ``chunk_size <= 0`` restores the original single-invocation behaviour.
    # ------------------------------------------------------------------
    chunk_size = int(a_cfg.get("chunk_size", 25) or 0)
    if chunk_size > 0 and len(urls) > chunk_size:
        chunks = [urls[i:i + chunk_size]
                  for i in range(0, len(urls), chunk_size)]
    else:
        chunks = [urls]
    single = len(chunks) == 1

    # ``timeout`` stays the budget for the WHOLE stage, not per chunk —
    # otherwise 8 chunks × 3600s would run 8 hours. Chunks share one
    # deadline and we stop starting new ones once it passes.
    deadline = time.monotonic() + timeout if timeout > 0 else None
    # ...but they must share it FAIRLY. Handing each chunk "everything
    # that is left" lets the first slow chunk eat the stage: the real run
    # went chunk_000 crash (1325s) → chunk_001 timeout (2274s, all that
    # remained) → chunk_002 started with 1s and died instantly, so 5 of 8
    # chunks never ran and the stage reported "timeout after 1s". Each
    # chunk now gets an even slice of what's left (a chunk that finishes
    # early donates its slack to the rest), and a chunk that cannot get at
    # least ``min_chunk_seconds`` is skipped outright rather than started
    # to fail.
    min_chunk = int(a_cfg.get("min_chunk_seconds", 120) or 0)
    # The floor can never exceed the stage budget itself, or a stage
    # configured to run for less than min_chunk_seconds would skip every
    # chunk and do nothing at all.
    floor = min(min_chunk, timeout) if timeout > 0 else min_chunk

    chunks_run = 0
    failed_chunks = 0
    any_timeout = False
    unrun = 0
    last_err = ""
    rawd = raw_dir(output_dir, stage)

    for idx, chunk in enumerate(chunks):
        per_timeout = timeout
        if deadline is not None:
            # Rounded, not truncated: the first chunk starts microseconds
            # after the deadline was set, and 59.999 must not read as
            # "less than the 60s budget" and skip the whole stage.
            remaining = round(deadline - time.monotonic())
            if remaining < floor:
                # Too little left to be worth starting: a chunk given a
                # few seconds only buys a guaranteed timeout.
                unrun = len(chunks) - idx
                break
            # Fair share of what is left, but never a sliver: floored at
            # ``floor`` and capped at what the budget actually holds.
            share = int(remaining / (len(chunks) - idx))
            per_timeout = max(1, min(max(share, floor), int(remaining)))

        if single:
            chunk_input = input_file
        else:
            chunk_input = rawd / f"chunk_{idx:03d}.txt"
            write_lines(chunk_input, chunk)

        r = runner.run(_cmd(chunk_input), stage=stage, log_name=stage,
                       output_dir=output_dir, timeout=per_timeout)
        chunks_run += 1
        if r.get("timed_out"):
            any_timeout = True
        if not r["success"] and not r["missing_binary"]:
            failed_chunks += 1
            last_err = (r["stderr"] or "").strip()[:300]

    # A stage only fails when NOTHING ran cleanly. Otherwise we fall
    # through and parse whatever the surviving chunks appended — the
    # whole point of chunking is that a crash is partial, not total.
    if chunks_run and failed_chunks == chunks_run and not params_out.exists():
        return make_result(
            stage, "failed", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0,
            error=last_err or "every arjun chunk failed",
            extra={"input_urls": original_count, "scanned_urls": len(urls),
                   "upstream_patch": patch_status,
                   "chunks": {"total": len(chunks), "run": chunks_run,
                              "size": chunk_size, "failed": failed_chunks,
                              "unrun": unrun}},
        )

    # arjun -oT text format, one URL per line:
    #   GET   → "https://example.com/api?id=&x="
    #   POST  → "https://example.com/api\t?id=&x="   (url TAB query-string)
    #   JSON  → "https://example.com/api\t{...}"     (url TAB json body)
    # For the URL list we want the full parameterised GET-style URL, so we
    # rejoin ``url`` + query-string when the second column looks like one.
    parameterized: list[str] = []
    if params_out.exists():
        for ln in params_out.read_text(errors="ignore").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split("\t")
            url = parts[0]
            if len(parts) > 1 and parts[1] and parts[1][0] in "?&":
                url = url + parts[1]
            parameterized.append(url)
    n = write_lines(urls_out, parameterized)
    extra: dict = {"input_urls": original_count, "scanned_urls": len(urls),
                   "upstream_patch": patch_status,
                   "scanned_sources": _source_mix(urls, sources)}
    error = None
    if not single:
        extra["chunks"] = {
            "total": len(chunks), "run": chunks_run,
            "size": chunk_size, "failed": failed_chunks, "unrun": unrun,
        }
    if failed_chunks or unrun or any_timeout:
        # Report as success-with-a-note: the params we DID collect are
        # real and the shortlist downstream should use them.
        error = (f"{chunks_run}/{len(chunks)} chunks run, "
                 f"{failed_chunks} crashed, {unrun} skipped (stage budget)")
    return make_result(
        stage, "success", input_path=dynamic_urls_file,
        outputs=[params_out, urls_out], count=n,
        error=error, extra=extra,
    )
