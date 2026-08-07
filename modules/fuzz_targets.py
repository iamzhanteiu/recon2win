"""fuzz_targets — chọn host để fuzz, dùng chung cho dirsearch (4.2) + ffuf (4.3).

Vì sao cần: wildcard DNS là chuyện thường trên bug-bounty. ``*.example.com``
resolve về cùng một load balancer, httpx báo 200 cho cả 200 host, và cả hai
stage fuzzing bắn nguyên wordlist vào từng cái — 200 lần cùng một ứng dụng.
Với wordlist 20k từ thì đó là 4 triệu request để lấy về đúng một tập kết quả.

httpx đã đưa cho ta thứ cần để phát hiện: ``alive_detail.json`` chứa
``status_code`` / ``title`` / ``webserver`` / ``words`` / ``lines`` cho từng
host. Host nào trả về *cùng một response* thì gần như chắc chắn là cùng một
app — fuzz một cái đại diện là đủ.

Hai bước, theo thứ tự:

  1. **Gom nhóm theo response** (``response_fingerprint``) — mỗi nhóm giữ
     đúng một đại diện. Đây là chỗ cắt được nhiều nhất.
  2. **Xếp hạng rồi cắt** (``score_subdomain`` có sẵn trong utils) — ``admin.``
     / ``api.`` / ``staging.`` lên trước ``cdn-assets-3.``, rồi mới cap.

Thứ tự này quan trọng: cap trước khi dedup thì 50 slot có thể bị 50 bản sao
của cùng một trang chiếm sạch.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from . import baseline, layout
from .utils import load_json, read_lines, score_subdomain, write_lines


def _host_of(url: str) -> str:
    """Hostname của một URL (rỗng nếu không parse được)."""
    s = (url or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s
    try:
        return (urlsplit(s).hostname or "").lower()
    except ValueError:
        return ""


def response_fingerprint(row: dict) -> tuple | None:
    """Định danh *thứ host phục vụ*, không phải tên của nó.

    Cố tình KHÔNG dùng ``content_length``: chỉ cần một nonce CSRF hay một
    timestamp trong HTML là byte count lệch nhau, gom nhóm chính xác sẽ hỏng.
    ``words``/``lines`` chịu được nhiễu đó — cùng một template thì cùng số từ
    và số dòng kể cả khi vài ký tự bên trong đổi.

    Trả về ``None`` khi thiếu tín hiệu để kết luận; caller phải coi những
    host đó là **duy nhất** (thà fuzz thừa còn hơn bỏ sót một app thật).
    """
    if not isinstance(row, dict):
        return None
    status = row.get("status_code")
    words = row.get("words")
    lines = row.get("lines")
    # Không có cả words lẫn lines thì không đủ cơ sở gom nhóm.
    if status is None or (words is None and lines is None):
        return None
    return (
        int(status),
        words,
        lines,
        (row.get("title") or "").strip(),
        (row.get("webserver") or "").strip(),
    )


def is_waf(row: dict) -> bool:
    """Host có nằm sau WAF không (httpx ``cdn_type: waf``).

    Đáng biết vì hai lý do: fuzz mạnh vào WAF thì ăn ban, và kết quả trả về
    thường vô nghĩa (403 cho mọi path). Mặc định KHÔNG bỏ qua — phần lớn
    chương trình bug bounty đứng sau Cloudflare, bỏ WAF là bỏ hết target.
    """
    return isinstance(row, dict) and (row.get("cdn_type") or "").lower() == "waf"


def _pick_representative(urls: list[str]) -> str:
    """Chọn host đại diện cho một nhóm response giống nhau.

    Ưu tiên điểm ``score_subdomain`` cao nhất (apex và các tiền tố giá trị
    như ``admin``/``api`` thắng), hoà điểm thì lấy hostname ngắn nhất — thường
    là tên canonical chứ không phải bí danh sinh tự động.
    """
    return sorted(
        urls, key=lambda u: (-score_subdomain(_host_of(u)), len(_host_of(u)), u),
    )[0]


def select_targets(
    urls: Iterable[str],
    detail_rows: list[dict] | None = None,
    *,
    max_hosts: int = 50,
    dedup: bool = True,
    skip_waf: bool = False,
    baselines: dict[str, Any] | None = None,
    match_status: Iterable[int] | None = None,
) -> tuple[list[str], dict]:
    """Rút danh sách alive host xuống tập đáng fuzz.

    ``detail_rows`` là ``alive_detail.json`` của httpx. Thiếu nó thì vẫn chạy
    được — chỉ mất bước gom nhóm, phần xếp hạng + cap vẫn có tác dụng.

    ``baselines`` (``modules.baseline.measure``) là tín hiệu TỐT HƠN cho cả
    hai việc, và khi có thì nó thay thế ``detail_rows`` ở bước gom nhóm:

      * **Bỏ host không fuzz được.** Host trả cùng một response cho path
        không tồn tại — và response đó nằm trong ``match_status`` — sẽ "tìm
        thấy" nguyên wordlist. Đo trên discover.com: 11 host như vậy, ffuf
        đốt trọn 3.600s để sinh 44.230 bản sao trang chặn.
      * **Gom nhóm đúng thứ.** ``response_fingerprint`` gom theo TRANG CHỦ,
        nhưng thứ quyết định giá trị fuzz là cách host trả lời path không có
        thật. Đúng 11 host nói trên có trang chủ khác nhau nên không bao giờ
        bị gom, dù hành xử y hệt nhau ở mọi path khác.

    Trả về ``(targets, stats)``; ``stats`` đi thẳng vào ``extra`` của stage
    result nên operator nhìn báo cáo là biết đã cắt được bao nhiêu.
    """
    all_urls = [u.strip() for u in urls if u and u.strip()]
    by_url: dict[str, dict] = {}
    for row in detail_rows or []:
        if isinstance(row, dict) and row.get("url"):
            by_url[row["url"].strip()] = row

    stats: dict[str, Any] = {
        "input": len(all_urls),
        "deduped": 0,
        "waf_skipped": 0,
        "selected": 0,
    }

    candidates = all_urls
    if by_url:
        stats["waf_seen"] = sum(1 for u in candidates if is_waf(by_url.get(u, {})))
        if skip_waf:
            kept = [u for u in candidates if not is_waf(by_url.get(u, {}))]
            stats["waf_skipped"] = len(candidates) - len(kept)
            candidates = kept

    if baselines:
        wanted = set(match_status or ())
        blanket = [u for u in candidates
                   if u in baselines and baselines[u].is_blanket(wanted)]
        if blanket:
            drop = set(blanket)
            candidates = [u for u in candidates if u not in drop]
            stats["blanket_skipped"] = len(blanket)
            stats["blanket_sample"] = blanket[:5]

    # Mốc để tính ``deduped``. Phải lấy SAU khi bỏ WAF và blanket, nếu không
    # một con số lại tính cả phần của con số kia và tổng không khớp đầu vào.
    before_dedup = len(candidates)

    if dedup and (baselines or by_url):
        groups: dict[tuple, list[str]] = {}
        unique: list[str] = []          # không đủ dữ liệu để gom → giữ nguyên
        for u in candidates:
            # Baseline shape is the better key, but a host we could not probe
            # must still get the home-page grouping rather than none at all —
            # otherwise a failed probe silently turns dedup off and we go back
            # to fuzzing 200 copies of one app.
            bl = (baselines or {}).get(u)
            fp = bl.shape if (bl is not None and bl.consistent) else None
            if fp is None:
                fp = response_fingerprint(by_url.get(u, {}))
            if fp is None:
                unique.append(u)
            else:
                groups.setdefault(fp, []).append(u)
        collapsed = [_pick_representative(g) for g in groups.values()]
        # Giữ thứ tự xuất hiện ban đầu để kết quả ổn định giữa các lần chạy.
        keep = set(collapsed) | set(unique)
        candidates = [u for u in candidates if u in keep]
        stats["deduped"] = before_dedup - len(candidates)
        stats["groups"] = len(groups)
        biggest = max((len(g) for g in groups.values()), default=0)
        if biggest > 1:
            stats["largest_group"] = biggest

    ranked = sorted(candidates, key=lambda u: -score_subdomain(_host_of(u)))
    targets = ranked[:max_hosts] if max_hosts and max_hosts > 0 else ranked
    stats["selected"] = len(targets)
    stats["capped"] = len(ranked) - len(targets)
    return targets, stats


def load_targets(
    alive_file: Path,
    output_dir: Path,
    *,
    max_hosts: int = 50,
    dedup: bool = True,
    skip_waf: bool = False,
    cfg: dict | None = None,
    match_status: Iterable[int] | None = None,
    stage: str = "baseline",
) -> tuple[list[str], dict]:
    """``select_targets`` nhưng đọc sẵn alive.txt + alive_detail.json từ đĩa.

    Chạy luôn baseline probe (``baseline.measure``) trừ khi tắt trong config.
    Chi phí: ``số host × baseline.probes`` request — 154 × 3 = 462 trên
    discover.com, so với 690.000 request của chính stage fuzzing. Mỗi stage
    tự probe thay vì dùng chung, vì stage 4 chạy song song và một cache chung
    sẽ thành race; giá phải trả là vài trăm request, đổi lại không có trạng
    thái chia sẻ nào giữa các stage.
    """
    urls = read_lines(alive_file)
    detail = load_json(layout.path(output_dir, "alive_detail.json"))
    rows = detail if isinstance(detail, list) else []

    # The probe is real network I/O, so it happens only when the caller
    # actually hands over a config. A caller with no ``cfg`` cannot have
    # configured the probe and is either a unit test or legacy code — both
    # want the old, purely-on-disk behaviour rather than a surprise round of
    # requests from a function called "load".
    baselines: dict[str, Any] | None = None
    probe_stats: dict = {}
    b_cfg = (cfg or {}).get("baseline") or {}
    if cfg is not None and urls and b_cfg.get("enabled", True):
        # Probe with the client that will do the fuzzing. Probing ffuf's
        # targets with httpx measures a different target: on discover.com
        # httpx got a clean 404 from webapp.src while ffuf got a 403 bot-block
        # for every path, so the probe cleared a host that ffuf could learn
        # nothing from. ``baseline.client`` can pin this; "auto" follows the
        # stage.
        client = str(b_cfg.get("client", "auto")).lower()
        if client == "auto":
            client = "ffuf" if stage == "ffuf" else "httpx"
        baselines, probe_stats = baseline.measure(
            urls, output_dir, cfg, stage=stage, client=client,
        )

    targets, stats = select_targets(
        urls, rows, max_hosts=max_hosts, dedup=dedup, skip_waf=skip_waf,
        baselines=baselines, match_status=match_status,
    )
    if probe_stats:
        stats["baseline"] = probe_stats
    return targets, stats


def write_target_file(targets: list[str], path: Path) -> Path:
    """Ghi danh sách target ra đĩa cho tool nhận ``-l <file>`` (dirsearch)."""
    write_lines(path, targets)
    return path


def summary_line(stats: dict) -> str:
    """Một dòng cho console: đã cắt được gì so với đầu vào."""
    parts = [f"{stats.get('input', 0)} alive"]
    # A failed probe must never be invisible: without it nothing gets
    # skipped, and the line would otherwise read exactly like a run where
    # the target simply had no blanket hosts.
    probe_err = (stats.get("baseline") or {}).get("error")
    if probe_err:
        parts.append(f"[baseline HỎNG: {probe_err}]")
    if stats.get("blanket_skipped"):
        parts.append(f"-{stats['blanket_skipped']} trả như nhau mọi path")
    if stats.get("deduped"):
        parts.append(f"-{stats['deduped']} trùng response")
    if stats.get("waf_skipped"):
        parts.append(f"-{stats['waf_skipped']} sau WAF")
    if stats.get("capped"):
        parts.append(f"-{stats['capped']} quá cap")
    return f"{' '.join(parts)} → {stats.get('selected', 0)} target"
