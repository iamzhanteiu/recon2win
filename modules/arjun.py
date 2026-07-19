"""arjun — stage 7: parameter discovery on dynamic URLs."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from . import runner
from .utils import make_result, raw_dir, read_lines, write_lines


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


def _score(url: str) -> int:
    """Higher = more interesting to fuzz. Ties break on URL length
    (shorter URLs first so we keep canonical endpoints)."""
    lo = url.lower()
    score = sum(2 if h in lo else 0 for h in _HIGH_VALUE_HINTS)
    # demote obvious archive cruft — waymore / waybackmachine noise
    if "web.archive.org" in lo or "webcache.googleusercontent" in lo:
        score -= 5
    return score


def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "arjun_params.txt"
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
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    params_out = proc / "arjun_params.txt"
    urls_out = proc / "parameterized_urls.txt"

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
    original_count = len(urls)
    if len(urls) > max_urls:
        ranked = sorted(urls, key=lambda u: (-_score(u), len(u), u))
        urls = ranked[:max_urls]
    input_file = dynamic_urls_file if len(urls) == original_count \
        else _write_input_subset(output_dir, urls)

    # ------------------------------------------------------------------
    # Output flag: arjun's ``-o`` writes JSON ({url: {params, method}}),
    # NOT the ``[200] url`` text you see on the console. We want a flat
    # list of parameterised URLs to feed nuclei_dynamic, so we use
    # ``-oT`` (text) which writes exactly ``https://site/page?id=&q=``
    # (one per line; POST/JSON rows are ``url\t<params>``).
    #
    # ``-oT`` opens the file in append mode, so a leftover file from a
    # previous partial run would accumulate stale lines — delete it first.
    # ------------------------------------------------------------------
    if params_out.exists():
        params_out.unlink()

    cmd = [
        "arjun", "-i", str(input_file),
        "-oT", str(params_out),
        "-t", str(threads),
        "-T", str(request_timeout),
        "--stable",
    ]
    if rate_limit > 0:
        cmd.extend(["--rate-limit", str(rate_limit)])

    r = runner.run(cmd, stage=stage, output_dir=output_dir, timeout=timeout)
    if not r["success"] and not r["missing_binary"]:
        return make_result(
            stage, "failed", input_path=dynamic_urls_file,
            outputs=[params_out, urls_out], count=0,
            error=(r["stderr"] or "")[:300],
            extra={"input_urls": original_count, "scanned_urls": len(urls)},
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
    return make_result(
        stage, "success", input_path=dynamic_urls_file,
        outputs=[params_out, urls_out], count=n,
        extra={"input_urls": original_count, "scanned_urls": len(urls)},
    )
