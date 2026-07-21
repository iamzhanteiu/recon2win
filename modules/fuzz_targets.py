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
) -> tuple[list[str], dict]:
    """Rút danh sách alive host xuống tập đáng fuzz.

    ``detail_rows`` là ``alive_detail.json`` của httpx. Thiếu nó thì vẫn chạy
    được — chỉ mất bước gom nhóm, phần xếp hạng + cap vẫn có tác dụng.

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

    if dedup and by_url:
        groups: dict[tuple, list[str]] = {}
        unique: list[str] = []          # không đủ dữ liệu để gom → giữ nguyên
        for u in candidates:
            fp = response_fingerprint(by_url.get(u, {}))
            if fp is None:
                unique.append(u)
            else:
                groups.setdefault(fp, []).append(u)
        collapsed = [_pick_representative(g) for g in groups.values()]
        # Giữ thứ tự xuất hiện ban đầu để kết quả ổn định giữa các lần chạy.
        keep = set(collapsed) | set(unique)
        candidates = [u for u in candidates if u in keep]
        stats["deduped"] = len(all_urls) - len(candidates) - stats["waf_skipped"]
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
) -> tuple[list[str], dict]:
    """``select_targets`` nhưng đọc sẵn alive.txt + alive_detail.json từ đĩa."""
    urls = read_lines(alive_file)
    detail = load_json(output_dir / "processed" / "alive_detail.json")
    rows = detail if isinstance(detail, list) else []
    return select_targets(
        urls, rows, max_hosts=max_hosts, dedup=dedup, skip_waf=skip_waf,
    )


def write_target_file(targets: list[str], path: Path) -> Path:
    """Ghi danh sách target ra đĩa cho tool nhận ``-l <file>`` (dirsearch)."""
    write_lines(path, targets)
    return path


def summary_line(stats: dict) -> str:
    """Một dòng cho console: đã cắt được gì so với đầu vào."""
    parts = [f"{stats.get('input', 0)} alive"]
    if stats.get("deduped"):
        parts.append(f"-{stats['deduped']} trùng response")
    if stats.get("waf_skipped"):
        parts.append(f"-{stats['waf_skipped']} sau WAF")
    if stats.get("capped"):
        parts.append(f"-{stats['capped']} quá cap")
    return f"{' '.join(parts)} → {stats.get('selected', 0)} target"
