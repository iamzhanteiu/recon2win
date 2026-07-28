#!/usr/bin/env python3
"""Sổ cái sức khoẻ + coverage của một run recon2win.

In ra dạng gọn (vài KB) để nạp vào context — KHÔNG dump stages.json thô.

    python3 .claude/skills/recon-health/audit.py outputs/<domain>

Vì sao cần: ``status`` của stage nói dối. Trong logs/stages.json thật,
``dirsearch`` và các stage nuclei đều mang ``status: success`` trong khi
một cái timeout ở 4484s còn cái kia timeout toàn bộ batch — thông tin đó chỉ
nằm ở ``error`` và ``extra.timed_out``. Một run "26/26 success" có thể đã bỏ
qua 88% bề mặt mà không dòng nào nói ra.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Các cặp (input → thực sự xử lý) nằm rải rác trong extra tuỳ stage.
# key extra → (tên field input, tên field đã xử lý, nhãn)
COVERAGE_SHAPES = [
    ("url_filter",   "input",      "selected",     "URL"),
    ("param_filter", "input",      "selected",     "URL"),
    ("selection",    "input",      "selected",     "host"),
    ("chunks",       "total",      "run",          "chunk"),
    ("batches",      "total",      "run",          "batch"),
]


def _stages(run: Path) -> list[dict]:
    d = json.loads((run / "logs" / "stages.json").read_text())
    st = d if isinstance(d, list) else d.get("stages", d)
    return [s for s in st if isinstance(s, dict)]


# Không phải mọi phần bị cắt đều là coverage đã mất. Tách làm hai loại:
#   REDUNDANT — bỏ bản sao / bỏ thứ chắc chắn vô ích. Không mất gì.
#   UNSEEN    — cắt vì hết ngân sách. Đây mới là bề mặt chưa từng nhìn.
# Thiếu phân biệt này thì một bộ lọc chọn lọc tốt bị chấm điểm như một vụ
# cắt xén: một bản sửa cũ hạ 2000 → 482 URL nhưng số URL trả 200
# tăng 13 → 177; nhìn riêng phần trăm thì tưởng là bước lùi.
REDUNDANT_FIELDS = ("deduped", "per_host_capped", "dropped_no_param",
                    "waf_skipped", "param_collapsed")
UNSEEN_FIELDS = ("capped", "unrun")


def _coverage(s: dict) -> list[tuple[str, int, int, str, str, int]]:
    """[(nguồn, input, đã xử lý, đơn vị, ghi chú, số bị cắt vì ngân sách)]."""
    e = s.get("extra") or {}
    out = []

    def _note(blk: dict) -> tuple[str, int]:
        parts, unseen = [], 0
        for f in REDUNDANT_FIELDS:
            if isinstance(blk.get(f), int) and blk[f]:
                parts.append(f"-{blk[f]} {f}")
        for f in UNSEEN_FIELDS:
            if isinstance(blk.get(f), int) and blk[f]:
                parts.append(f"-{blk[f]} {f}!")
                unseen += blk[f]
        if blk.get("waf_hosts"):
            parts.append(f"waf:{len(blk['waf_hosts'])}")
        return " ".join(parts), unseen

    for key, fin, fout, unit in COVERAGE_SHAPES:
        blk = e.get(key)
        if isinstance(blk, dict) and isinstance(blk.get(fin), int):
            got = blk.get(fout)
            if isinstance(got, int):
                note, unseen = _note(blk)
                out.append((key, blk[fin], got, unit, note, unseen))
    # arjun dùng tên phẳng thay vì một block con
    if isinstance(e.get("input_urls"), int) and isinstance(e.get("scanned_urls"), int):
        gap = e["input_urls"] - e["scanned_urls"]
        out.append(("input_urls", e["input_urls"], e["scanned_urls"], "URL",
                    f"-{gap} capped!" if gap > 0 else "", max(0, gap)))
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    run = Path(sys.argv[1])
    try:
        stages = _stages(run)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"KHONG DOC DUOC stages.json: {exc}")
        return 1

    degraded, silent, budget_bugs, cov_rows, slow = [], [], [], [], []

    for s in stages:
        name = s.get("stage", "?")
        status = s.get("status")
        err = s.get("error")
        e = s.get("extra") or {}
        flags = [k for k in ("timed_out", "deadline_hit") if e.get(k)]
        elapsed = e.get("elapsed_seconds")

        if status != "success":
            degraded.append((name, status, err, flags, elapsed))
        elif err or flags:
            # Cái nguy hiểm nhất: success nhưng thực chất cụt.
            silent.append((name, status, err, flags, elapsed))

        # "timeout after Ns" với N vô lý so với thời gian chạy thật.
        if err and "timeout after" in str(err):
            try:
                claimed = int(str(err).split("timeout after")[1].split("s")[0].strip())
                if isinstance(elapsed, (int, float)) and elapsed > max(60, claimed * 5):
                    budget_bugs.append((name, claimed, elapsed, err))
            except (ValueError, IndexError):
                pass

        for src, cin, cout, unit, note, unseen in _coverage(s):
            if cin > 0:
                cov_rows.append((name, src, cin, cout, unit,
                                 100.0 * cout / cin, note, unseen))

        if isinstance(elapsed, (int, float)) and elapsed >= 600:
            slow.append((name, elapsed, s.get("count", 0)))

    ok = len(stages) - len(degraded) - len(silent)
    print(f"# {run.name} — {len(stages)} stage: "
          f"{ok} lanh, {len(silent)} cut-nhung-bao-success, {len(degraded)} that bai\n")

    if degraded:
        print("## Stage that bai / bo qua")
        for n, st, err, fl, el in degraded:
            t = f" [{el:.0f}s]" if isinstance(el, (int, float)) else ""
            print(f"  {n:22} {st:8}{t} {''.join('!'+f for f in fl)} {str(err)[:110]}")
        print()

    if silent:
        print("## success NHUNG CUT  <- nguy hiem nhat, khong doc error thi khong thay")
        for n, st, err, fl, el in silent:
            t = f" [{el:.0f}s]" if isinstance(el, (int, float)) else ""
            print(f"  {n:22} {'+'.join(fl) or 'error':14}{t} {str(err)[:110]}")
        print()

    if budget_bugs:
        print("## Ngan sach vo ly (thong bao timeout khong khop thoi gian chay)")
        for n, claimed, el, err in budget_bugs:
            print(f"  {n:22} bao 'timeout after {claimed}s' nhung chay that {el:.0f}s")
        print()

    if cov_rows:
        print("## So cai coverage — '!' = cat vi HET NGAN SACH (be mat chua tung nhin)")
        print("   phan cat khong co '!' la bo trung lap / bo thu chac chan vo ich")
        cov_rows.sort(key=lambda r: r[5])
        for n, src, cin, cout, unit, pct, note, _ in cov_rows:
            bar = "#" * int(pct / 5) + "." * (20 - int(pct / 5))
            print(f"  {n:22} {src:12} {cout:>6}/{cin:<7} {unit:5} "
                  f"{bar} {pct:5.1f}%  {note}")
        print()

    if slow:
        print("## Thoi gian di dau (>=600s)")
        slow.sort(key=lambda r: -r[1])
        for n, el, c in slow:
            print(f"  {n:22} {el/3600:5.2f}h  -> count={c}")
        print()

    # Chấm theo phần bị cắt VÌ NGÂN SÁCH, không theo phần trăm thô: một bộ
    # lọc bỏ bản sao có thể kéo phần trăm xuống rất thấp mà không mất gì.
    unseen = [(n, src, u, cin) for n, src, cin, _c, _u, _p, _nt, u in cov_rows if u]
    worst_pct, worst_at = 0.0, ""
    for n, src, u, cin in unseen:
        p = 100.0 * u / cin
        if p > worst_pct:
            worst_pct, worst_at = p, f"{n}/{src} bo qua {u}/{cin}"

    if degraded or budget_bugs:
        v = "VO NGHIA / KHONG TIN DUOC — co stage that bai hoac ngan sach hong"
    elif silent:
        v = ("MOT PHAN — co stage cut nhung bao success; "
             "ket qua 0-finding KHONG the ket luan la sach")
    elif worst_pct >= 50:
        v = (f"MOT PHAN — {worst_pct:.0f}% be mat chua tung duoc nhin "
             f"({worst_at}); 0-finding chi ap dung cho phan da quet")
    else:
        v = (f"TIN DUOC — moi stage chay tron, phan cat vi ngan sach "
             f"cao nhat {worst_pct:.0f}%")
    print(f"## Ket luan\n  {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
