"""dirsearch — stage 4.2: fuzz endpoints with wordlists and/or extensions.

Two modes, controlled by config:

  * **wordlist mode**  (default when ``dirsearch.wordlists`` is non-empty)
        Each entry in ``wordlists`` is either a single ``.txt`` file or a
        directory (recursively expanded to every ``*.txt`` inside, sorted).
        ``_merge_wordlists()`` then combines the resolved files into ONE
        single deduped file because **dirsearch only accepts a single
        ``-w`` flag** — multiple ``-w`` flags are silently dropped on
        most versions (only the first is honoured). ``-e`` is appended
        too only when ``combine: true`` is set.

  * **extension mode** (legacy behaviour — fallback when no wordlists)
        Pass the curated sensitive-extension list via ``-e``.

dirsearch prints lines like:
    200  10KB  https://example.com/.env

We normalize those to URL-only, one per line, in the form:
    https://example.com/.env
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Iterable

from . import behavior, console, fuzz_depth, fuzz_targets, layout, runner
from .sensitive_ext import SENSITIVE_EXT, to_dirsearch_flag, to_wordlist_lines
from .utils import load_json, make_result, raw_dir, read_lines, write_lines


# Matches "<status>  <len>  <url>" or "<status>  <len>B  <url> [-> <redirect>]".
# Non-greedy URL + optional redirect suffix so redirect lines still produce
# the original (source) URL.
#
# dirsearch's real ``plain`` report (lib/reports/plain_text_report.py) writes
# the redirect suffix as ``    -> REDIRECTS TO: <url>`` — NOT a bare
# ``-> <url>``. Both spellings are accepted here so redirect entries aren't
# silently dropped (which they were when only ``-> <url>`` was matched).
LINE_RE = re.compile(
    r"^\s*(\d{3})\s+\S+\s+(https?://\S+?)"
    r"(?:\s*->\s*(?:REDIRECTS TO:\s*)?https?://\S+)?\s*$"
)

# Same line, but keeping the two columns ``normalize_output`` throws away:
# the size and the redirect target. Both are needed to tell a real hit from
# a host answering everything the same way — dirsearch reports no words,
# lines, or content-type, so size and redirect destination are the whole of
# the signal available here.
HIT_RE = re.compile(
    r"^\s*(\d{3})\s+(\S+)\s+(https?://\S+?)"
    r"(?:\s*->\s*(?:REDIRECTS TO:\s*)?(https?://\S+))?\s*$"
)

_SIZE_RE = re.compile(r"^([\d.]+)\s*([KMG]?B)?$", re.IGNORECASE)
_SIZE_MULT = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def parse_size(text: str) -> int:
    """``"198B"`` → 198, ``"10KB"`` → 10240. ``UNKNOWN`` when unparseable.

    dirsearch rounds to two significant figures once it reaches KB, so the
    resolution here is coarse — which is fine for spotting "every response
    is the same size" and useless for spotting a 3-byte difference. That
    coarseness is why :func:`behavior.fingerprint` buckets length rather
    than comparing it exactly.
    """
    m = _SIZE_RE.match((text or "").strip())
    if not m:
        return behavior.UNKNOWN
    try:
        value = float(m.group(1))
    except ValueError:
        return behavior.UNKNOWN
    return int(value * _SIZE_MULT.get((m.group(2) or "B").upper(), 1))


def parse_hits(raw_lines: Iterable[str]) -> list[behavior.Behavior]:
    """Full response shape per hit, for :func:`behavior.screen_by_host`."""
    out: list[behavior.Behavior] = []
    for ln in raw_lines:
        m = HIT_RE.match(ln)
        if not m:
            continue
        status, size, url, redirect = m.groups()
        out.append(behavior.Behavior(
            url=url.strip(),
            status=int(status),
            length=parse_size(size),
            content_type="",          # dirsearch does not report it
            location=(redirect or "").strip(),
        ))
    return out


# ----------------------------------------------------------------------
# Pure helpers — no I/O beyond Path.stat(), fully unit-testable.
# ----------------------------------------------------------------------
def normalize_output(raw_lines: Iterable[str]) -> list[str]:
    """Reduce dirsearch stdout to a list of clean URLs."""
    out: list[str] = []
    for ln in raw_lines:
        m = LINE_RE.match(ln)
        if m:
            out.append(m.group(2).strip())
        else:
            s = ln.strip()
            if s.startswith("http://") or s.startswith("https://"):
                out.append(s)
    seen: set[str] = set()
    deduped: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def _resolve_wordlists(
    paths: Iterable[str | Path],
    *,
    missing_callback=None,
) -> list[Path]:
    """Expand a list of paths into a flat list of wordlist files.

    Rules:
      * ``~`` is expanded.
      * Non-existent paths are skipped (and reported via ``missing_callback``).
      * A directory path is recursively expanded to every ``*.txt`` inside it
        (sorted for deterministic command-line order).
      * Regular files are kept as-is.
    """
    resolved: list[Path] = []
    for raw in paths:
        if raw is None:
            continue
        p = Path(raw).expanduser()
        if not p.exists():
            if missing_callback:
                missing_callback(f"[dirsearch] wordlist not found: {p}")
            continue
        if p.is_dir():
            # Recursively pick up every .txt under the directory.
            for f in sorted(p.rglob("*.txt")):
                if f.is_file():
                    resolved.append(f)
        else:
            resolved.append(p)
    return resolved


def _merge_wordlists(
    wordlists: list[Path],
    merged_path: Path,
) -> tuple[Path, int, int]:
    """Merge multiple wordlist files into a single deduped file.

    Why this exists: dirsearch only accepts a single ``-w`` flag —
    multiple ``-w`` flags are silently dropped on most versions (only
    the first is honoured), and on others they trigger an argparse
    error. The two valid workarounds are:
      1. Merge into one file (this function — chosen by default
         because it is one process / one timeout window).
      2. Run dirsearch once per wordlist (not implemented; can be
         approximated by repeating the stage via ``--resume`` with
         different configs).

    Lines starting with ``#`` are treated as comments and dropped,
    matching the behaviour of ``read_lines()`` elsewhere in the
    framework. Duplicates are deduped case-sensitively; the first
    occurrence wins (preserves the ordering from the first wordlist
    that contributed the entry).

    Returns ``(merged_path, lines_in, lines_out)`` so the caller can
    log the dedup ratio.
    """
    seen: set[str] = set()
    lines_in = 0
    lines_out = 0
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    with merged_path.open("w", encoding="utf-8") as out:
        for wl in wordlists:
            if not wl.exists() or not wl.is_file():
                continue
            for raw_line in wl.read_text(errors="ignore").splitlines():
                s = raw_line.strip()
                if not s or s.startswith("#"):
                    continue
                lines_in += 1
                if s in seen:
                    continue
                seen.add(s)
                out.write(s + "\n")
                lines_out += 1
    return merged_path, lines_in, lines_out


def _build_cmd(
    alive_file: Path,
    raw_out: Path,
    wordlist: Path | None,
    extensions: list[str] | None,
    *,
    threads: int,
    recursive: bool,
    combine: bool,
    follow_redirects: bool = True,
    include_status: list[str] | None = None,
    exclude_status: list[str] | None = None,
    max_rate: int = 0,
    delay: float = 0,
) -> list[str]:
    """Build the dirsearch argv.

    ``wordlist`` is a *single* merged file (or ``None``). Callers with
    multiple input wordlists should run ``_merge_wordlists()`` first —
    dirsearch does not accept multiple ``-w`` flags.

    Precedence:
      1. If wordlist is set → ``-w <path>``. Extensions are added too
         only when ``combine`` is True (extremely noisy — opt-in).
      2. Else → fall back to extensions via ``-e``.

    Status-code filtering (dirsearch v3.x ``-i`` / ``-x``):
      * ``include_status`` — only show these codes (empty = show all).
      * ``exclude_status`` — hide these codes (applied after include).
      * ``follow_redirects`` — ``--follow-redirects`` flag; when True,
        3xx responses are followed and the FINAL status is reported
        (so ``/admin → 302 → /login (200)`` shows up as a 200).
    """
    cmd = [
        "dirsearch",
        "-l", str(alive_file),
        # Format is inferred from the output file extension — ``-o foo.txt``
        # produces plain text, ``-o foo.json`` produces JSON. The legacy
        # dirsearch (pre-1.0, the version most bug-bounty boxes ship) does
        # NOT accept ``--format``; dirsearch 1.x accepts it but ignores
        # it when the extension is unambiguous. Don't pass ``--format``
        # here so we work on both versions.
        "-o", str(raw_out),
        "-t", str(threads),
    ]
    if recursive:
        cmd.append("-r")
    if follow_redirects:
        cmd.append("--follow-redirects")

    # Ghì tốc độ. Không có cái này thì ffuf bị giới hạn 30 req/s còn dirsearch
    # 30 thread bắn tự do vào cùng target — ghì một nửa thì vẫn ăn ban.
    # Cả hai cờ đã xác minh trên dirsearch 0.4.3: `--max-rate=RATE` (req/s)
    # và `--delay=DELAY` (giây giữa các request).
    if max_rate and int(max_rate) > 0:
        cmd.append(f"--max-rate={int(max_rate)}")
    if delay and float(delay) > 0:
        cmd.append(f"--delay={delay}")

    # Status-code filtering. Both flags are optional — empty lists mean
    # "no filter". -i / -x are comma-separated status codes
    # (e.g. ``-i 200,403``). dirsearch's pre-1.0 versions don't accept
    # these flags; if we detect they're unsupported (rare on modern
    # bug-bounty boxes) the operator should leave both empty.
    if include_status:
        clean = [str(s).strip() for s in include_status if str(s).strip()]
        if clean:
            cmd.extend(["-i", ",".join(clean)])
    if exclude_status:
        clean = [str(s).strip() for s in exclude_status if str(s).strip()]
        if clean:
            cmd.extend(["-x", ",".join(clean)])

    if wordlist:
        cmd.extend(["-w", str(wordlist)])
        if combine and extensions:
            cmd.extend(["-e", to_dirsearch_flag(extensions)])
    elif extensions:
        cmd.extend(["-e", to_dirsearch_flag(extensions)])

    return cmd


def _count_words(wordlist: Path | None) -> int:
    """Số dòng thật sự được gửi đi từ một wordlist (bỏ dòng trống/comment)."""
    if wordlist is None or not wordlist.exists():
        return 0
    n = 0
    for raw in wordlist.read_text(errors="ignore").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            n += 1
    return n


# Dự phòng cho khởi động, retry, redirect và phần chờ không phải request —
# đo trên run thật thì thời gian thực luôn nhỉnh hơn ``request / rate`` thuần.
_BUDGET_SLACK = 1.3

# Không mở chunk mới khi ngân sách stage còn ít hơn ngần này: dirsearch
# mất vài chục giây nạp wordlist trước request đầu tiên, nên một lát mỏng
# chỉ mua thêm đúng một lần timeout.
_MIN_CHUNK_BUDGET = 60

# Hạ ước lượng tốc độ sau mỗi chunk timeout.
#
# ĐÂY LÀ CHỖ KHÁC nuclei và rất dễ làm sai. Ở nuclei, ``batch_timeout`` là
# hằng số độc lập với batch_size, nên chia đôi batch là mỗi URL được gấp
# đôi thời gian — tự nó đã sửa được. Ở đây ``per_timeout`` lại SUY RA TỪ
# len(chunk), nên chia đôi chunk cũng chia đôi ngân sách ⇒ vẫn đúng ngần
# ấy giây mỗi host ⇒ chunk sau timeout y hệt. Cơ chế thích ứng thành vô
# tác dụng trước đúng cái nó sinh ra để chống.
#
# Một chunk timeout không có nghĩa chunk quá to, mà nghĩa là tốc độ thật
# thấp hơn ``max_rate`` ta tưởng (đo ở nuclei: 194 → 113 rps trong 2 phút
# khi bị CDN bóp; dirsearch acronis/discover đều chết đúng bằng ``wanted``).
# Đặt bằng đúng hệ số chia đôi chunk để wall-clock mỗi chunk giữ nguyên
# còn thời gian mỗi host tăng gấp đôi.
_RATE_BACKOFF = 0.5


def _plan_budget(
    *,
    targets: int,
    wordlist: Path | None,
    extensions: list[str] | None,
    max_rate: int,
    per_host: int,
    ceiling: int,
) -> tuple[int, dict]:
    """Tính timeout cho stage TỪ KHỐI LƯỢNG REQUEST THẬT.

    Cách cũ là ``timeout_per_host × số target`` — một con số bịa, không hề
    đối chiếu với việc thực sự phải gửi bao nhiêu request, nên config tự
    tin ghi "120s × 50 host = 6000s, không bao giờ bị cắt giữa chừng nữa"
    trong khi run acronis.com 2026-07-25 chết đúng ở trần 6000s:

        50 target × 13,799 từ           = 689,950 request
        ở --max-rate=30 (giới hạn TOÀN CỤC) = 22,998s = 6.4 giờ

    tức là ngân sách thiếu gần 4 lần. ``per_host`` không có cách nào biết
    điều đó; ``request ÷ rate`` thì có.

    Trả về ``(timeout, thông_tin_ngân_sách)``. Khi không đặt ``max_rate``
    (0 = không ghì tốc độ) thì không suy ra được rps nên rơi về cách tính
    theo host cũ — vẫn tốt hơn là không có gì.
    """
    words = _count_words(wordlist)
    # ``-e`` nhân số request lên: mỗi từ được thử thêm một lần cho mỗi
    # extension (``admin`` → ``admin.bak``, ``admin.sql``, …).
    ext_mult = 1 + len(extensions) if extensions else 1
    requests = targets * words * ext_mult

    if requests > 0 and max_rate > 0:
        wanted = int(requests / max_rate * _BUDGET_SLACK)
        basis = (f"{targets} host × {words} từ × {ext_mult} = {requests:,} "
                 f"request ÷ {max_rate} req/s")
    else:
        wanted = per_host * max(1, targets)
        basis = f"{targets} host × {per_host}s"

    timeout = max(60, min(ceiling, wanted))
    return timeout, {
        "requests": requests, "words": words, "targets": targets,
        "max_rate": max_rate, "wanted": wanted, "ceiling": ceiling,
        "timeout": timeout, "over_ceiling": wanted > ceiling, "basis": basis,
    }


# ----------------------------------------------------------------------
# Resume / dry-run helpers
# ----------------------------------------------------------------------
def _outputs_exist(out_dir: Path) -> bool:
    p = layout.path(out_dir, "dirsearch_urls.txt")
    return p.exists() and p.stat().st_size > 0


def _dedup(items: list[str]) -> list[str]:
    """Order-preserving dedup for combining two tiers' URL lists."""
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ----------------------------------------------------------------------
# Stage entrypoint
# ----------------------------------------------------------------------
def scan(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "dirsearch"
    raw_ds = raw_dir(output_dir, "dirsearch")
    layout.ensure_tree(output_dir)
    raw_out = raw_ds / "dirsearch_raw.txt"
    merged_wl_path = raw_ds / "merged_wordlists.txt"
    proc_out = layout.path(output_dir, "dirsearch_urls.txt")

    if skip:
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0, error="--skip-dirsearch",
        )

    if resume and _outputs_exist(output_dir):
        existing = read_lines(proc_out)
        return make_result(
            stage, "success", input_path=alive_file,
            outputs=[raw_out, proc_out], count=len(existing),
        )

    if dry_run:
        d_cfg = cfg.get("dirsearch", {}) if isinstance(cfg, dict) else {}
        wl_paths = _resolve_wordlists(
            d_cfg.get("wordlists", []) or [], missing_callback=print,
        )
        # If multiple wordlists were resolved, dry-run still won't
        # create the merged file on disk — we only need to know what
        # the argv *would* look like. Report the planned merge path
        # in the extra so the operator can see it.
        planned_wordlist: Path | None = None
        planned_merge: dict | None = None
        if len(wl_paths) == 1:
            planned_wordlist = wl_paths[0]
        elif wl_paths:
            planned_wordlist = merged_wl_path
            planned_merge = {"files": len(wl_paths),
                             "path": str(planned_wordlist)}
        cmd = _build_cmd(
            alive_file, raw_out, planned_wordlist,
            extensions=d_cfg.get("extensions"),
            threads=int(d_cfg.get("threads", 30)),
            recursive=bool(d_cfg.get("recursive", True)),
            combine=bool(d_cfg.get("combine", False)),
            follow_redirects=bool(d_cfg.get("follow_redirects", True)),
            include_status=d_cfg.get("include_status") or [],
            exclude_status=d_cfg.get("exclude_status") or [],
            max_rate=int(d_cfg.get("max_rate", 0) or 0),
            delay=float(d_cfg.get("delay", 0) or 0),
        )
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0, error="dry-run",
            extra={
                "planned_cmd": cmd,
                "wordlists": [str(p) for p in wl_paths],
                "merge": planned_merge,
            },
        )

    if not runner.tool_available("dirsearch"):
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="dirsearch binary not found (optional, skipped)",
        )

    # Nothing alive to scan → skip without spawning dirsearch. dirsearch
    # exits non-zero on an empty -l file which we would otherwise
    # misinterpret as a real failure.
    if not alive_file.exists() or alive_file.stat().st_size == 0:
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="no alive hosts to scan",
        )

    d_cfg = cfg.get("dirsearch", {})

    # Cùng bước chọn target với ffuf: gom host trả về response giống hệt nhau
    # (wildcard DNS), xếp hạng, rồi cap. dirsearch nhận ``-l <file>`` nên ta
    # ghi tập đã chọn ra đĩa thay vì đưa thẳng alive.txt.
    targets, sel_stats = fuzz_targets.load_targets(
        alive_file, output_dir,
        max_hosts=int(d_cfg.get("max_hosts", 50)),
        dedup=bool(d_cfg.get("dedup_targets", True)),
        skip_waf=bool(d_cfg.get("skip_waf", False)),
        cfg=cfg,
        # dirsearch's -i is the same idea as ffuf's -mc: the statuses it
        # will report. A host that answers those to a path that is not
        # there will "find" every word in the list.
        match_status=[int(s) for s in (d_cfg.get("include_status") or [])
                      if str(s).isdigit()],
        stage=stage,
    )
    # Tập rỗng nghĩa là bộ lọc đã loại hết (vd skip_waf=true và mọi host đều
    # sau WAF) — phải dừng, KHÔNG được rơi về alive_file gốc. Fallback kiểu đó
    # làm ngược đúng ý operator: bật skip_waf lại thành scan sạch mọi host WAF.
    if not targets:
        raw_out.write_text("")
        proc_out.write_text("")
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error="không còn target sau khi lọc (dedup/skip_waf/max_hosts)",
            extra={"selection": sel_stats},
        )
    alive_file = fuzz_targets.write_target_file(targets, raw_ds / "targets.txt")
    if sel_stats.get("deduped") or sel_stats.get("capped"):
        print(console.phase_info_line(
            f"[dirsearch] {fuzz_targets.summary_line(sel_stats)}"))

    # Adaptive fuzz depth: which of the selected hosts get the expensive
    # extras (bigger wordlist, its own time slice). Never re-filters/re-caps
    # — that stays fuzz_targets' job.
    depth_cfg = cfg.get("fuzz_depth", {}) if isinstance(cfg, dict) else {}
    if depth_cfg.get("enabled", True):
        detail_rows = load_json(layout.path(output_dir, "alive_detail.json"))
        detail_rows = detail_rows if isinstance(detail_rows, list) else []
        # Tech confirmed by misconfig_probe on a PRIOR scan of this same
        # target (this run's own probe hasn't run yet — see fuzz_depth
        # module docstring) enriches the tier + tech-aware wordlist call.
        detail_rows = fuzz_depth.merge_confirmed_tech(
            detail_rows, fuzz_depth.load_confirmed_tech(output_dir))
        tiers, depth_stats = fuzz_depth.tier_targets(targets, detail_rows, cfg)
    else:
        tiers, depth_stats = {"deep": [], "standard": targets, "light": []}, {}
    if depth_stats.get("deep"):
        print(console.phase_info_line(
            f"[dirsearch] {fuzz_depth.summary_line(depth_stats)}"))

    threads = int(d_cfg.get("threads", 30))
    recursive = bool(d_cfg.get("recursive", True))
    combine = bool(d_cfg.get("combine", False))
    extensions = d_cfg.get("extensions")  # if None we fall back to SENSITIVE_EXT

    wl_paths = _resolve_wordlists(
        d_cfg.get("wordlists", []) or [], missing_callback=print,
    )

    # Fallback khi chưa cấu hình gì: dùng CẢ HAI kênh.
    #   * ``-e <SENSITIVE_EXT>``  → admin.bak, admin.sql, …
    #   * ``-w <SENSITIVE_FILES>`` → /.env, /.git/config, /docker-compose.yml
    # Trước đây chỉ có ``-e`` và cả tên file cũng bị nhét vào đó, nên dirsearch
    # đi thử ``admin..env`` còn ``/.env`` thì không bao giờ được chạm tới.
    fallback_wordlist: Path | None = None
    if not wl_paths and not extensions:
        extensions = SENSITIVE_EXT
        fallback_wordlist = raw_ds / "sensitive_files.txt"
        write_lines(fallback_wordlist, to_wordlist_lines())

    # dirsearch accepts only one ``-w`` flag. If we resolved multiple
    # wordlists (very common — one big raft-small-directories.txt
    # plus 50 service-specific files), merge them into a single
    # deduped file under raw/dirsearch/merged_wordlists.txt. A
    # single wordlist is used as-is to avoid an unnecessary
    # round-trip through disk.
    wordlist_file: Path | None = None
    merge_stats: dict | None = None
    if wl_paths:
        if len(wl_paths) == 1:
            wordlist_file = wl_paths[0]
        else:
            merged_path, lines_in, lines_out = _merge_wordlists(
                wl_paths, merged_wl_path,
            )
            wordlist_file = merged_path
            merge_stats = {
                "files": len(wl_paths),
                "lines_in": lines_in,
                "lines_out": lines_out,
                "path": str(merged_path),
            }
            print(
                console.phase_info_line(
                    f"merged {len(wl_paths)} wordlists "
                    f"({lines_in} lines → {lines_out} unique) into {merged_path}"
                )
            )

    # Ở chế độ fallback, ``-w`` là danh sách file nhạy cảm và ``-e`` là
    # extension — cần cả hai cùng lúc, nên combine phải bật.
    if fallback_wordlist is not None:
        wordlist_file = fallback_wordlist
        combine = True

    # Host tier "deep" được cấp thêm wordlist merge trên NỀN wordlist chuẩn
    # (bao gồm cả trường hợp fallback sensitive_files ở trên) — chỉ tính khi
    # có ít nhất 1 host "deep" VÀ có cấu hình wordlist bổ sung, để không tốn
    # công merge một cách vô ích.
    deep_wordlist_file: Path | None = wordlist_file
    deep_wl_paths: list[Path] = []
    deep_merge_stats: dict | None = None
    if tiers.get("deep"):
        # Static config additions PLUS auto-detected tech (fuzz_depth maps
        # tech actually seen on this run's deep-tier hosts — e.g. "jenkins"
        # — to its dedicated SecLists file; see TECH_WORDLIST_MAP). Order
        # preserved, deduped, so an explicit config entry and an auto-picked
        # one that happen to match don't get resolved twice.
        extra_wl = list(depth_cfg.get("deep_wordlists") or [])
        if depth_cfg.get("tech_aware_wordlists", True):
            extra_wl += depth_stats.get("deep_tech_wordlists") or []
        extra_wl = list(dict.fromkeys(extra_wl))
        if extra_wl and wordlist_file is not None:
            resolved_extra = _resolve_wordlists(extra_wl, missing_callback=print)
            if resolved_extra:
                merged_path, lines_in, lines_out = _merge_wordlists(
                    [wordlist_file] + resolved_extra,
                    raw_ds / "merged_wordlists_deep.txt",
                )
                deep_wordlist_file = merged_path
                deep_wl_paths = resolved_extra
                deep_merge_stats = {
                    "files": len(resolved_extra) + 1,
                    "lines_in": lines_in, "lines_out": lines_out,
                    "path": str(merged_path),
                }

    max_rate = int(d_cfg.get("max_rate", 0) or 0)
    stage_ceiling = int(d_cfg.get("timeout", 3600))
    chunk_size = int(d_cfg.get("chunk_size", 10) or 0)
    min_chunk = max(1, int(d_cfg.get("chunk_min_size", 3) or 1))
    screen_cfg = d_cfg.get("screen") or {}
    screen_on = bool(screen_cfg.get("enabled", True))
    follow_redirects = bool(d_cfg.get("follow_redirects", True))
    include_status = d_cfg.get("include_status") or []
    exclude_status = d_cfg.get("exclude_status") or []
    delay = float(d_cfg.get("delay", 0) or 0)
    per_host = int(d_cfg.get("timeout_per_host", 300))

    # ------------------------------------------------------------------
    # CHIA THEO HOST. Trước đây stage này gọi dirsearch ĐÚNG MỘT LẦN trên
    # cả danh sách target, nên timeout là mất gần hết: dirsearch duyệt
    # target tuần tự, bị kill ở giây thứ N thì những host chưa tới lượt
    # KHÔNG HỀ được quét. Đo trên run acronis.com: 50 target được chọn,
    # kết quả chỉ đến từ target #1, #3, #9 → ~82% host chưa từng chạm tới.
    # discover.com cùng hình dạng (4/43).
    #
    # Ước lượng ngân sách chuẩn hơn KHÔNG cứu được chuyện này — một run
    # đơn vẫn là được ăn cả ngã về không. Và ngân sách không thể chuẩn:
    # cả hai run đều chết đúng bằng ``wanted`` mà _plan_budget tự tính
    # (4484s và 3856s), kể cả khi đã nhân _BUDGET_SLACK 1.3 — tốc độ thật
    # không bao giờ đạt ``max_rate`` (cùng hiện tượng RPS tụt dần đo được
    # ở nuclei: 194 → 113 trong 2 phút khi bị CDN bóp).
    #
    # Nên chia nhỏ, y như nuclei: mỗi chunk có ngân sách riêng tính từ
    # chính số host của nó, chạy xong ghi kết quả ngay, và một chunk chết
    # chỉ tốn đúng chunk đó. ``chunk_size <= 0`` giữ hành vi một-lần cũ.
    #
    # THÊM TIER: host tier "deep" không chỉ được cấp wordlist to hơn mà còn
    # chạy TÁCH RIÊNG khỏi nhóm "standard"+"light", mỗi nhóm một phần ngân
    # sách stage (``fuzz_depth.deep_time_share``) — logic chunk/backoff dưới
    # đây được TRÍCH Y NGUYÊN từ bản gốc một-nhóm, chỉ tham số hoá phần khác
    # nhau giữa 2 nhóm (wordlist/extensions/ceiling/thư mục raw) để không
    # phải viết lại công thức ngân sách/backoff hai lần.
    # ------------------------------------------------------------------
    def _run_group(
        group_targets: list[str],
        group_wordlist: Path | None,
        group_extensions: list[str] | None,
        group_combine: bool,
        ceiling: int,
        group_raw_ds: Path,
        group_raw_out: Path,
        prior_urls: list[str],
        group_label: str,
    ) -> tuple[list[str], dict]:
        group_raw_ds.mkdir(parents=True, exist_ok=True)
        chunked = chunk_size > 0 and len(group_targets) > chunk_size
        timeout, budget = _plan_budget(
            targets=len(group_targets), wordlist=group_wordlist,
            extensions=group_extensions if group_combine else None,
            max_rate=max_rate, per_host=per_host, ceiling=ceiling,
        )
        if budget["over_ceiling"]:
            print(console.phase_info_line(
                f"[dirsearch:{group_label}] {budget['basis']} ≈ {budget['wanted']}s "
                f"vượt trần {budget['ceiling']}s → sẽ bị cắt ở {timeout}s (kết quả "
                f"một phần vẫn được giữ). Tăng max_rate/timeout, hoặc giảm "
                f"max_hosts/wordlist."))

        def _run_one(target_file: Path, out_file: Path, per_timeout: int) -> dict:
            cmd = _build_cmd(
                target_file, out_file, group_wordlist,
                extensions=group_extensions,
                threads=threads,
                recursive=recursive,
                combine=group_combine,
                follow_redirects=follow_redirects,
                include_status=include_status,
                exclude_status=exclude_status,
                max_rate=max_rate,
                delay=delay,
            )
            return runner.run(cmd, stage=stage, output_dir=output_dir,
                              timeout=per_timeout)

        screen_dropped = 0
        blanket_hosts: list[str] = []

        started = time.monotonic()
        pending = list(group_targets)
        cur_size = chunk_size if chunked else 0
        rate_factor = 1.0
        # MEASURED throughput, req/s. ``rate_factor`` alone only ever learns
        # from a chunk that already died — it costs a full chunk budget per
        # lesson, which is why the discover.com run burned its 6000s ceiling
        # after 5 of 14 chunks. A chunk that COMPLETES is a free, exact
        # measurement: requests_planned ÷ elapsed. Use it, and the nominal
        # ``max_rate`` (which the target never actually grants) stops
        # driving the budget after the first chunk.
        #
        # Only completions update it. A timed-out chunk sent an unknown
        # number of requests ≤ planned, so planned÷elapsed would OVERSTATE
        # the rate — the one direction that must never happen. Timeouts
        # keep using the conservative halving instead.
        measured_rps: float | None = None
        chunk_words = _count_words(group_wordlist)
        chunk_ext_mult = 1 + len(group_extensions) if (group_extensions and group_combine) else 1
        idx = 0
        raw_files: list[Path] = []
        chunks_run = 0
        any_timeout = False
        deadline_hit = False
        resized = False
        hard_failed = 0
        last_err = ""
        urls: list[str] = []
        n = 0

        while pending:
            chunk = pending[:cur_size] if cur_size > 0 else pending
            pending = pending[len(chunk):]

            if chunked:
                c_targets = fuzz_targets.write_target_file(
                    chunk, group_raw_ds / f"chunk_{idx:03d}_targets.txt")
                c_raw = group_raw_ds / f"chunk_{idx:03d}.txt"
                remaining = ceiling - (time.monotonic() - started)
                if remaining <= _MIN_CHUNK_BUDGET:
                    deadline_hit = True
                    pending = chunk + pending          # chưa chạy, trả lại
                    break
                # Ngân sách chunk tính từ chính số host của nó, NHƯNG theo
                # tốc độ đã học được (rate_factor), không phải max_rate danh
                # nghĩa. Xem chú thích ở _RATE_BACKOFF: thiếu chỗ này thì
                # việc chia đôi chunk hoàn toàn vô tác dụng.
                eff_rate = (max(1, int(measured_rps)) if measured_rps
                            else max(1, int(max_rate * rate_factor)))
                per_timeout, _ = _plan_budget(
                    targets=len(chunk), wordlist=group_wordlist,
                    extensions=group_extensions if group_combine else None,
                    max_rate=eff_rate,
                    per_host=per_host,
                    ceiling=int(remaining),
                )
            else:
                c_targets = fuzz_targets.write_target_file(
                    group_targets, group_raw_ds / "targets.txt")
                c_raw, per_timeout = group_raw_out, timeout
            idx += 1

            chunk_started = time.monotonic()
            r = _run_one(c_targets, c_raw, per_timeout)
            chunk_elapsed = time.monotonic() - chunk_started
            chunks_run += 1
            raw_files.append(c_raw)

            if chunked and not r.get("timed_out") and chunk_elapsed > 1:
                planned = len(chunk) * chunk_words * chunk_ext_mult
                if planned > 0:
                    sample = planned / chunk_elapsed
                    # Even weighting: throughput drifts down as a CDN
                    # tightens, so the newest chunk must move the estimate
                    # quickly, while keeping some memory guards against one
                    # anomalous chunk.
                    measured_rps = (sample if measured_rps is None
                                    else (measured_rps + sample) / 2)

            # SALVAGE FIRST. dirsearch's ``-o`` plain report is written
            # INCREMENTALLY (one line per hit, as it finds them) — unlike
            # nuclei's ``-json-export``, a run killed at its timeout still
            # leaves every hit it had already made on disk. Parse first,
            # decide status after.
            lines: list[str] = []
            for p in raw_files:
                if p.exists():
                    lines.extend(p.read_text(errors="ignore").splitlines())
            if not lines:
                lines = (r.get("stdout") or "").splitlines()
            # Behavioural screen, same idea as ffuf's — but here the only
            # signals dirsearch reports are status, size and redirect
            # target, so the fingerprint leans on a bucketed length.
            hits = parse_hits(lines)
            kept_hits, screen_verdicts = behavior.screen_by_host(
                hits,
                min_cluster=int(screen_cfg.get("min_cluster", 25)),
                min_share=float(screen_cfg.get("min_share", 0.5)),
                length_tolerance=int(screen_cfg.get("length_tolerance", 16)),
            ) if screen_on and hits else (hits, {})
            screen_dropped = len(hits) - len(kept_hits)
            blanket_hosts = sorted(h for h, v in screen_verdicts.items() if v.blanket)

            # Fall back to the URL-only parse when the screen has nothing to
            # say (screen disabled, or no line matched HIT_RE) so a parsing
            # change can never silently shrink the stage's output.
            urls = ([b.url for b in kept_hits] if screen_on and hits
                    else normalize_output(lines))
            # ghi sau MỖI chunk — kèm urls của (các) nhóm chạy trước, để
            # proc_out luôn phản ánh MỌI kết quả đã cứu được tính tới lúc
            # này, kể cả khi tiến trình chết giữa nhóm thứ hai.
            n = write_lines(proc_out, prior_urls + urls)

            if r.get("timed_out"):
                any_timeout = True
                if chunked:
                    # Một chunk timeout nghĩa là GIẢ ĐỊNH TỐC ĐỘ SAI, không
                    # phải chunk quá to. Hạ ước lượng rate đúng bằng hệ số ta
                    # chia đôi chunk, nên wall-clock mỗi chunk giữ nguyên còn
                    # thời gian MỖI HOST tăng gấp đôi — đó mới là thứ sửa
                    # được lỗi.
                    rate_factor *= _RATE_BACKOFF
                    if measured_rps:
                        measured_rps *= _RATE_BACKOFF
                    if cur_size > min_chunk:
                        cur_size = max(min_chunk, cur_size // 2)
                        resized = True
            elif not r["success"] and not r["missing_binary"]:
                hard_failed += 1
                last_err = (r["stderr"] or "").strip()

        if chunked and raw_files:
            # Gộp lại thành group_raw_out để consumer cũ (report/audit)
            # không đổi.
            group_raw_out.write_text("\n".join(
                p.read_text(errors="ignore") for p in raw_files if p.exists()))

        if measured_rps:
            # The gap between what we asked for and what we got is the
            # whole reason this stage kept blowing its ceiling — put it in
            # the log.
            budget = dict(budget)
            budget["measured_rps"] = round(measured_rps, 1)
            budget["nominal_rps"] = max_rate

        extra_partial: dict = {
            "budget": budget,
            "screen": {"enabled": screen_on, "dropped": screen_dropped,
                       "kept": n, "blanket_hosts": blanket_hosts},
            "timeout": timeout, "ceiling": ceiling, "chunked": chunked,
            "any_timeout": any_timeout, "deadline_hit": deadline_hit,
            "hard_failed": hard_failed, "chunks_run": chunks_run,
            "last_err": last_err, "pending_left": len(pending),
            "resized": resized, "chunk_size": chunk_size, "cur_size": cur_size,
            "n": n,
        }
        if chunked:
            left = -(-len(pending) // cur_size) if pending and cur_size else \
                (1 if pending else 0)
            extra_partial["chunks"] = {
                "total": chunks_run + left, "run": chunks_run,
                "size": cur_size, "initial_size": chunk_size,
                "resized": resized, "failed": hard_failed,
                "unrun": len(pending),
            }
        return urls, extra_partial

    deep_targets = tiers.get("deep") or []
    standard_targets = (tiers.get("standard") or []) + (tiers.get("light") or [])

    extra: dict = {
        "wordlists": [str(p) for p in wl_paths],
        "merge": merge_stats,
        "selection": sel_stats,
        "depth": depth_stats,
        "deep_wordlists": [str(p) for p in deep_wl_paths],
        "deep_merge": deep_merge_stats,
        "mode": "wordlist" if wl_paths else "extension",
    }

    if deep_targets:
        deep_time_share = min(max(float(depth_cfg.get("deep_time_share", 0.35) or 0), 0.0), 1.0)
        deep_ceiling = max(60, int(stage_ceiling * deep_time_share))
        standard_ceiling = max(60, stage_ceiling - deep_ceiling)
        deep_raw_out = raw_ds / "dirsearch_raw_deep.txt"
        standard_raw_out = raw_ds / "dirsearch_raw_standard.txt"

        # Tech-implied extensions (B2) apply to the deep group only. In
        # wordlist mode dirsearch honours ``-e`` only with ``--combine`` on,
        # so enable it for this group when there are extra extensions to fuzz
        # (bounded: few deep hosts × a 2–4 entry ext list).
        deep_extensions = extensions
        deep_combine = combine
        deep_exts = ([e for e in (depth_stats.get("deep_tech_exts") or [])]
                     if depth_cfg.get("tech_aware_extensions", True) else [])
        if deep_exts:
            base_exts = list(extensions) if isinstance(extensions, list) else []
            deep_extensions = base_exts + [e for e in deep_exts if e not in base_exts]
            if wordlist_file is not None:
                deep_combine = True

        deep_urls, deep_extra = _run_group(
            deep_targets, deep_wordlist_file, deep_extensions, deep_combine,
            deep_ceiling, raw_ds / "deep", deep_raw_out, [], "deep",
        )
        standard_urls, standard_extra = _run_group(
            standard_targets, wordlist_file, extensions, combine,
            standard_ceiling, raw_ds / "standard", standard_raw_out, deep_urls, "standard",
        )
        urls = _dedup(deep_urls + standard_urls)
        n = write_lines(proc_out, urls)
        raw_out.write_text(
            (deep_raw_out.read_text(errors="ignore") if deep_raw_out.exists() else "")
            + (standard_raw_out.read_text(errors="ignore") if standard_raw_out.exists() else "")
        )

        extra["groups"] = {"deep": deep_extra, "standard": standard_extra}
        hard_failed_total = deep_extra["hard_failed"] + standard_extra["hard_failed"]
        chunks_run_total = deep_extra["chunks_run"] + standard_extra["chunks_run"]
        any_timeout = deep_extra["any_timeout"] or standard_extra["any_timeout"]
        deadline_hit = deep_extra["deadline_hit"] or standard_extra["deadline_hit"]
        last_err = standard_extra["last_err"] or deep_extra["last_err"]

        if hard_failed_total == chunks_run_total and chunks_run_total and not urls:
            return make_result(
                stage, "failed", input_path=alive_file,
                outputs=[raw_out, proc_out], count=0,
                error=last_err[:300] or "every dirsearch chunk failed", extra=extra,
            )

        error = None
        if any_timeout or deadline_hit:
            extra["timed_out"] = True
            if deadline_hit:
                extra["deadline_hit"] = True
            error = (
                f"deep: {'hết ngân sách' if deep_extra['deadline_hit'] else ('timeout, chạy tiếp qua chunk' if deep_extra['any_timeout'] else 'xong')}; "
                f"standard: {'hết ngân sách' if standard_extra['deadline_hit'] else ('timeout, chạy tiếp qua chunk' if standard_extra['any_timeout'] else 'xong')}; "
                f"giữ {n} kết quả"
            )
        elif hard_failed_total:
            error = f"{last_err[:200] or 'failed'} — salvaged {n} results"
        return make_result(
            stage, "success", input_path=alive_file,
            outputs=[raw_out, proc_out], count=n, error=error, extra=extra,
        )

    # Không có host tier "deep" trong run này: MỘT nhóm với TOÀN BỘ ngân
    # sách, ghi thẳng vào raw_out — hành vi BYTE-IDENTICAL với trước khi có
    # fuzz_depth (không chia nhóm, không đổi đường dẫn file, không đổi câu
    # thông báo lỗi).
    urls, se = _run_group(
        standard_targets, wordlist_file, extensions, combine,
        stage_ceiling, raw_ds, raw_out, [], "standard",
    )
    extra["budget"] = se["budget"]
    extra["screen"] = se["screen"]
    if "chunks" in se:
        extra["chunks"] = se["chunks"]

    chunked = se["chunked"]
    ceiling = se["ceiling"]
    timeout = se["timeout"]
    chunks_run = se["chunks_run"]
    cur_size = se["cur_size"]
    chunk_size_initial = se["chunk_size"]
    resized = se["resized"]
    n = se["n"]
    hard_failed = se["hard_failed"]
    last_err = se["last_err"]
    pending_left = se["pending_left"]
    any_timeout = se["any_timeout"]
    deadline_hit = se["deadline_hit"]

    # Only a failure that salvaged NOTHING is a dead stage.
    if hard_failed == chunks_run and chunks_run and not urls:
        return make_result(
            stage, "failed", input_path=alive_file,
            outputs=[raw_out, proc_out], count=0,
            error=last_err[:300] or "every dirsearch chunk failed", extra=extra,
        )

    error = None
    if any_timeout or deadline_hit:
        extra["timed_out"] = True
        if deadline_hit:
            extra["deadline_hit"] = True
        if not chunked:
            error = f"timeout after {timeout}s — salvaged {n} partial results"
        else:
            note = (f"hết ngân sách stage {ceiling}s, còn {pending_left} host"
                    if deadline_hit else "chạy tiếp qua chunk timeout")
            if resized:
                note += f"; chunk {chunk_size_initial}→{cur_size}"
            error = (f"{chunks_run}/{extra['chunks']['total']} chunk chạy, "
                     f"{note}; giữ {n} kết quả")
    elif hard_failed:
        error = f"{last_err[:200] or 'failed'} — salvaged {n} results"
    return make_result(
        stage, "success", input_path=alive_file,
        outputs=[raw_out, proc_out], count=n, error=error, extra=extra,
    )