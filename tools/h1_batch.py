#!/usr/bin/env python3
"""h1_batch — recon HackerOne programs in bulk, one root at a time.

Two phases (mirrors the plan the operator approved):

  catalog  Pha 0 — chỉ gọi H1 API. Duyệt các program ``submission_state==open``,
           giữ những program có ít nhất một in-scope root URL/WILDCARD được
           ``eligible_for_bounty``. Ghi ``outputs/_h1/catalog.json`` (đầy đủ) và
           ``outputs/_h1/queue.txt`` (hàng đợi ``handle<TAB>root``, đã bỏ target
           đã quét). Không quét gì cả — an toàn để duyệt trước.

  run      Pha 1 — đọc queue, gọi ``main.py`` tuần tự cho từng root với các stage
           nhẹ (skip dirsearch/ffuf/waymore), resume được (bỏ target đã có
           outputs), ghi ``outputs/_h1/progress.log``.

Scope an toàn: chỉ những asset H1 gắn ``eligible_for_submission`` (đã lọc trong
``modules.hackerone``) mới lọt vào; ``catalog`` siết thêm ``eligible_for_bounty``.

Usage:
  python3 tools/h1_batch.py catalog
  python3 tools/h1_batch.py run --dry-run
  python3 tools/h1_batch.py run --limit 10
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Chạy được từ bất cứ đâu: thêm repo root vào sys.path để import modules/.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from modules import hackerone as h1  # noqa: E402

H1_DIR_NAME = "_h1"
SKIP_FLAGS = ["--skip-dirsearch", "--skip-ffuf", "--skip-waymore"]

try:
    import tldextract
    def _registrable(host: str) -> str:
        e = tldextract.extract(host)
        return f"{e.domain}.{e.suffix}" if e.suffix and e.domain else host
    def _has_suffix(host: str) -> bool:
        return bool(tldextract.extract(host).suffix)
except Exception:  # pragma: no cover - fallback nếu thiếu tldextract
    def _registrable(host: str) -> str:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    def _has_suffix(host: str) -> bool:
        return host.count(".") >= 1


def _clean_wildcard_base(host: str) -> str:
    """Rút một asset WILDCARD về base enumerate được, hoặc "" nếu không hợp lệ.

    ``_asset_to_host`` đã bỏ ``*.`` ở đầu. Nếu vẫn còn glob (``topaz*.x.com``,
    ``api.aboutyou.*``) thì bỏ các label chứa ``*`` — giữ nesting hợp lệ
    (``*.sub.x.com`` → ``sub.x.com``). Trả "" nếu phần còn lại không còn suffix
    thật (``edited.*`` → "" vì TLD bị mất).
    """
    if "*" in host:
        host = ".".join(l for l in host.split(".") if "*" not in l)
    host = host.strip(".")
    if host and "." in host and _has_suffix(host):
        return host
    return ""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _h1_dir(output_root: Path) -> Path:
    d = output_root / H1_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def _valid_host(host: str) -> bool:
    """Một hostname đơn hợp lệ để làm target recon (đã lọc glob/rác)."""
    if not host or len(host) > 253 or "." not in host:
        return False
    if any(c in host for c in " /,*"):
        return False
    # Mỗi label: 1-63 ký tự, không mở đầu/kết thúc bằng '-' (sai DNS, và '-' đầu
    # còn bị argparse của main.py hiểu nhầm là flag).
    return all(0 < len(lbl) <= 63 and lbl[0] != "-" and lbl[-1] != "-"
               for lbl in host.split("."))


def _already_scanned(output_root: Path, handle: str, root: str) -> bool:
    """True nếu root này đã được quét (project layout hoặc flat layout cũ)."""
    try:
        for p in (output_root / handle / root, output_root / root):
            if p.is_dir() and any(p.iterdir()):
                return True
    except OSError:
        return False
    return False


# ----------------------------------------------------------------------
# Pha 0 — catalog
# ----------------------------------------------------------------------
def cmd_catalog(args: argparse.Namespace) -> int:
    output_root = Path(args.output_root)
    h1_dir = _h1_dir(output_root)

    try:
        user, token = h1.get_credentials()
    except h1.H1Error as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    print(f"[*] {_now()} liệt kê programs…")
    try:
        programs = h1.list_programs(user, token)
    except h1.H1Error as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    open_progs = [p for p in programs if p.get("submission_state") == "open"]
    print(f"[*] {len(programs)} program, {len(open_progs)} open — "
          f"lấy scope từng cái (eligible_for_bounty)…")

    # Cache raw scope theo handle → rerun không gọi lại API (điền dần các
    # program bị 429 ở lần trước). Xoá file cache để buộc fetch lại một program.
    cache_dir = h1_dir / "scopes_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    def _scopes(handle: str) -> list[dict] | None:
        cf = cache_dir / f"{handle}.json"
        if cf.exists():
            try:
                return json.loads(cf.read_text(encoding="utf-8"))
            except Exception:
                pass
        last = None
        for attempt in range(5):  # retry backoff khi 429
            try:
                raw = h1.get_structured_scopes(user, token, handle)
                cf.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
                return raw
            except h1.H1Error as e:
                last = e
                if "429" in str(e) and attempt < 4:
                    time.sleep(args.delay + 3 * (attempt + 1))
                    continue
                break
        print(f"  [!] {handle}: {last}", file=sys.stderr)
        return None

    catalog: list[dict] = []
    fetched = 0
    for i, pr in enumerate(open_progs, 1):
        handle = pr["handle"]
        cached = (cache_dir / f"{handle}.json").exists()
        raw = _scopes(handle)
        if raw is None:
            continue
        if not cached:
            fetched += 1
            time.sleep(args.delay)
        bounty_scopes = [s for s in h1.parse_scopes(raw)
                         if s.get("eligible_for_bounty")]

        # Tách theo asset_type — quyết định cách recon:
        #   WILDCARD  → apex, được phép enumerate subdomain (mode "wildcard").
        #   URL host  → đúng host đó, KHÔNG brute (mode "host").
        wildcards: set[str] = set()
        hosts: set[str] = set()
        for s in bounty_scopes:
            atype = s.get("asset_type")
            if atype not in h1.DOMAIN_ASSET_TYPES:
                continue
            # Một số program nhồi nhiều host vào một identifier (phân tách bằng
            # dấu phẩy / khoảng trắng) — tách ra xử lý từng cái.
            raw_ident = s.get("asset_identifier", "") or ""
            for piece in re.split(r"[,\s]+", raw_ident):
                piece = piece.strip()
                if not piece:
                    continue
                host = h1._asset_to_host(atype, piece)
                if atype == "WILDCARD":
                    base = _clean_wildcard_base(host)
                    if _valid_host(base):
                        wildcards.add(base)
                elif _valid_host(host):  # host cụ thể (loại glob/rác)
                    hosts.add(host)

        # Host nằm dưới một wildcard apex đã có → thừa (wildcard sẽ tự tìm ra).
        wc_reg = {_registrable(w) for w in wildcards}
        hosts = {h for h in hosts
                 if _registrable(h) not in wc_reg and h not in wildcards}

        if wildcards or hosts:
            catalog.append({
                "handle": handle,
                "name": pr["name"],
                "wildcards": sorted(wildcards),
                "hosts": sorted(hosts),
            })
            print(f"  [{i}/{len(open_progs)}] {handle}: "
                  f"{len(wildcards)} wildcard, {len(hosts)} host")
        if i % 50 == 0:
            print(f"[*] …{i}/{len(open_progs)} program (fetch mới: {fetched})")

    catalog.sort(key=lambda c: c["handle"])
    (h1_dir / "catalog.json").write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")

    # Hàng đợi 3 cột: handle<TAB>target<TAB>mode (wildcard|host). Wildcard xếp
    # trước host trong mỗi program vì nó phủ rộng hơn.
    n_wc = n_host = new = 0
    queue_lines: list[str] = []
    for entry in catalog:
        for target in entry["wildcards"]:
            n_wc += 1
            if not _already_scanned(output_root, entry["handle"], target):
                new += 1
                queue_lines.append(f"{entry['handle']}\t{target}\twildcard")
        for target in entry["hosts"]:
            n_host += 1
            if not _already_scanned(output_root, entry["handle"], target):
                new += 1
                queue_lines.append(f"{entry['handle']}\t{target}\thost")
    (h1_dir / "queue.txt").write_text(
        ("\n".join(queue_lines) + "\n") if queue_lines else "", encoding="utf-8")

    print(f"\n[✓] {len(catalog)} program: {n_wc} wildcard + {n_host} host "
          f"= {n_wc + n_host} target ({new} mới vào queue).")
    print(f"    catalog: {h1_dir / 'catalog.json'}")
    print(f"    queue  : {h1_dir / 'queue.txt'}")
    print("    Duyệt queue rồi chạy: python3 tools/h1_batch.py run --dry-run")
    return 0


# ----------------------------------------------------------------------
# Pha 1 — run
# ----------------------------------------------------------------------
def _read_queue(h1_dir: Path) -> list[tuple[str, str, str]]:
    qf = h1_dir / "queue.txt"
    if not qf.exists():
        print(f"[!] chưa có {qf} — chạy `catalog` trước.", file=sys.stderr)
        return []
    out: list[tuple[str, str, str]] = []
    for line in qf.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        handle, target = parts[0], parts[1]
        mode = parts[2] if len(parts) > 2 else "wildcard"
        if handle and target:
            out.append((handle, target, mode))
    return out


def cmd_run(args: argparse.Namespace) -> int:
    output_root = Path(args.output_root)
    h1_dir = _h1_dir(output_root)
    queue = _read_queue(h1_dir)
    if not queue:
        return 2

    progress = h1_dir / "progress.log"
    done = ran = failed = skipped = 0
    seen_programs: list[str] = []  # thứ tự program đã đụng tới (cho --programs)

    def _log(msg: str) -> None:
        with progress.open("a", encoding="utf-8") as fh:
            fh.write(f"{_now()}\t{msg}\n")

    print(f"[*] {len(queue)} target trong queue"
          + (f" | limit {args.limit} target" if args.limit else "")
          + (f" | {args.programs} program đầu" if args.programs else "")
          + (" [DRY-RUN]" if args.dry_run else ""))

    try:
        for handle, target, mode in queue:
            # Giới hạn theo số program (thứ tự xuất hiện trong queue).
            if args.programs:
                if handle not in seen_programs:
                    if len(seen_programs) >= args.programs:
                        break
                    seen_programs.append(handle)
            if args.limit and ran >= args.limit:
                break
            if not args.force and _already_scanned(output_root, handle, target):
                skipped += 1
                continue
            cmd = [sys.executable, "main.py", "-d", target,
                   "--project", handle, *SKIP_FLAGS]
            if mode == "host":
                cmd.append("--no-subdomain")  # scope-limited: không brute sub
            if args.dry_run:
                print(f"  DRY [{mode:8}]", " ".join(cmd))
                ran += 1
                continue
            print(f"\n[{ran + 1}] {_now()} → {handle} / {target} ({mode})")
            _log(f"START\t{handle}\t{target}\t{mode}")
            t0 = time.time()
            try:
                rc = subprocess.run(cmd, cwd=str(REPO_ROOT),
                                    timeout=args.timeout).returncode
            except subprocess.TimeoutExpired:
                rc = -1
                print(f"  [!] TIMEOUT sau {args.timeout}s")
            dt = int(time.time() - t0)
            ran += 1
            if rc == 0:
                done += 1
                _log(f"DONE\t{handle}\t{target}\t{dt}s")
            else:
                failed += 1
                _log(f"FAIL\trc={rc}\t{handle}\t{target}\t{dt}s")
                print(f"  [!] rc={rc} ({dt}s)")
    except KeyboardInterrupt:
        print("\n[!] dừng bởi người dùng (Ctrl-C). Chạy lại `run` để tiếp tục.")

    print(f"\n[✓] ran={ran} done={done} fail={failed} skipped={skipped}")
    print(f"    log: {progress}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output-root", default="outputs",
                   help="thư mục gốc outputs (mặc định: outputs)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("catalog", help="Pha 0: build catalog + queue từ H1 API")
    pc.add_argument("--delay", type=float, default=0.6,
                    help="giây nghỉ giữa các call API (mặc định 0.6, tránh 429)")
    pc.set_defaults(func=cmd_catalog)

    pr = sub.add_parser("run", help="Pha 1: quét tuần tự từng root trong queue")
    pr.add_argument("--programs", type=int, default=0,
                    help="chỉ chạy N program đầu tiên (theo thứ tự queue)")
    pr.add_argument("--limit", type=int, default=0, help="chỉ chạy N target")
    pr.add_argument("--timeout", type=int, default=7200,
                    help="timeout mỗi target, giây (mặc định 7200)")
    pr.add_argument("--dry-run", action="store_true",
                    help="in lệnh sẽ chạy, không quét")
    pr.add_argument("--force", action="store_true",
                    help="quét lại cả target đã có outputs")
    pr.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
