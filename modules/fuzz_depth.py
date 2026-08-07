"""fuzz_depth — xếp mỗi host đã chọn fuzz vào 1 trong 3 tier: deep/standard/light.

``fuzz_targets`` đã quyết định CÓ fuzz host này không (wildcard dedup, WAF/
blanket-deny skip, cap theo ``score_subdomain``). Module này quyết định
KHÔNG PHẢI mọi host sống sót qua bộ lọc đó đáng đào sâu như nhau — dùng đúng
2 tín hiệu đã có sẵn trong codebase:

  1. ``utils.score_subdomain(host)`` — điểm theo hostname (apex, prefix giá
     trị cao như ``api``/``admin``, tech nổi tiếng trong TÊN host).
  2. ``tech``/``webserver``/``title`` trong ``alive_detail.json`` (httpx
     ``-td``) — tín hiệu từ NỘI DUNG response, bắt được cả những host tên
     chung chung (``app3.example.com``) nhưng đang chạy Jenkins/Spring/k8s.

Tier "deep" được ``dirsearch``/``ffuf`` cấp thêm wordlist, và
``misconfig_probe`` chỉ chạy trên đúng tập host này. Tier "light" (khớp
``_SUBDOMAIN_NOISE``) KHÔNG bị loại khỏi fuzzing — chỉ là không được cấp
phần mở rộng tốn kém, giống triết lý "demote, đừng drop" của
``fuzz_targets``.

Nguồn tech thứ 3 — CONFIRMED, không phải đoán: ``misconfig_probe`` tự xác
nhận tech bằng cách đọc NỘI DUNG response (Spring actuator/env trả đúng
``propertySources``, Jenkins ``/script`` có chữ "script console", ...) —
đáng tin hơn nhiều so với httpx đoán qua title/header. Ghi lại vào
``processed/tech_confirmed.json`` (``load_confirmed_tech``/
``save_confirmed_tech``, tích luỹ qua nhiều lần scan cùng target — KHÔNG bị
ghi đè mỗi run như ``alive_detail.json``) rồi merge vào tín hiệu tech ở
trên (``merge_confirmed_tech``) trước khi tier — ``load_tiers`` tự làm việc
này; ``dirsearch``/``ffuf`` gọi thẳng ``tier_targets`` nên tự merge lấy.

THỨ TỰ CHẠY TRONG MỘT LẦN SCAN: dirsearch/ffuf (stage 4) chạy TRƯỚC
misconfig_probe (stage 6+), nên ``tech_confirmed.json`` của CHÍNH LẦN SCAN
NÀY chưa tồn tại lúc dirsearch/ffuf tier — không có vòng lặp ngược. Giá trị
thật nằm ở lần scan SAU của cùng target (``outputs/<domain>/`` giữ nguyên
giữa các lần chạy, đúng mô hình scandiff/dashboard đã có): tech xác nhận ở
lần trước làm tier + tech-aware wordlist ở lần sau chính xác hơn.
"""
from __future__ import annotations

from pathlib import Path

from . import layout
from .fuzz_targets import _host_of
from .utils import load_json, read_lines, score_subdomain, write_json

# keyword → nhãn hiển thị. Khớp trên NỘI DUNG response (tech/webserver/title),
# không phải hostname — cố tình không tái dùng utils._SUBDOMAIN_BOUNTY_TECH
# (khớp trên CHUỖI hostname) vì đây là hai tín hiệu độc lập và bổ sung cho
# nhau: một host tên chung chung vẫn lộ ra qua nội dung nó trả về.
_TECH_HINTS: dict[str, str] = {
    "spring": "Spring Boot (actuator surface)",
    "tomcat": "Tomcat (manager app surface)",
    "jenkins": "Jenkins (script console RCE)",
    "gitlab": "GitLab (API version/metrics)",
    "grafana": "Grafana (default creds / API)",
    "prometheus": "Prometheus (open metrics)",
    "kubernetes": "Kubernetes (API/dashboard)",
    "docker": "Docker registry (_catalog)",
    "elastic": "Elasticsearch (open indices)",
    "kibana": "Kibana",
    "wordpress": "WordPress (wp-json/xmlrpc)",
    "phpmyadmin": "phpMyAdmin",
    "adminer": "Adminer",
    "jira": "Jira",
    "confluence": "Confluence",
    "consul": "Consul",
    "nexus": "Nexus/Artifactory",
    "artifactory": "Nexus/Artifactory",
}

# keyword (subset of _TECH_HINTS) → SecLists wordlist path, repo-root-
# relative, same convention as dirsearch.wordlists / ffuf.wordlists in
# config.yml. This is what makes tech DETECTION (above) turn into tech
# AWARE FUZZING: a host is only handed the Jenkins/GitLab/WordPress list
# when that tech was actually seen in ITS OWN response, never the ~50-file
# ``Service-Specific/`` directory blanket-loaded onto every host (the
# anti-pattern README used to flag as a TODO — see dirsearch.wordlists /
# ffuf.wordlists comments in config.yml for why that was expensive).
#
# Deliberately partial: only mapped where SecLists has a small, DEDICATED
# file for that exact tech. A key with no entry here still tiers "deep"
# and still benefits from misconfig_probe.py's own curated endpoint list
# (actuator/, script console, ...) — it just gets no extra wordlist.
# Every path verified to exist in SecLists as of 2026-08-02.
TECH_WORDLIST_MAP: dict[str, str] = {
    "jenkins": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Jenkins-Hudson.txt",
    "gitlab": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/GitLab.txt",
    "grafana": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Grafana.txt",
    "prometheus": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Prometheus-Alertmanager.txt",
    "kubernetes": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Kubernetes.txt",
    "docker": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Docker-API.txt",
    "elastic": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Elasticsearch-Kibana.txt",
    "kibana": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/Elasticsearch-Kibana.txt",
    "confluence": "wordlists/SecLists/Discovery/Web-Content/Service-Specific/confluence-administration.txt",
    "consul": "wordlists/SecLists/Discovery/Web-Content/hashicorp-consul-api.txt",
    "tomcat": "wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
    "spring": "wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt",
    "wordpress": "wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
}

_DEFAULT_DEEP_THRESHOLD = 1000
_DEFAULT_LIGHT_THRESHOLD = -500
_DEFAULT_DEEP_MAX_HOSTS = 15


def _tech_blob(row: dict) -> str:
    tech = row.get("tech")
    tech_str = " ".join(str(t) for t in tech) if isinstance(tech, list) else ""
    return " ".join([
        tech_str,
        str(row.get("webserver") or ""),
        str(row.get("title") or ""),
    ]).lower()


def _matched_tech_keys(row: dict) -> list[str]:
    """Raw ``_TECH_HINTS`` keys matched in *row* — same signal
    ``classify_depth`` uses for its ``"tech: ..."`` reasons, but returned as
    lookup keys (``"jenkins"``) instead of display labels
    (``"Jenkins (script console RCE)"``) so ``TECH_WORDLIST_MAP`` can use
    them directly."""
    blob = _tech_blob(row)
    return [kw for kw in _TECH_HINTS if kw in blob]


def tech_wordlists_for(tech_hits: dict[str, int]) -> list[str]:
    """``TECH_WORDLIST_MAP`` paths for every key in *tech_hits*, deduped and
    sorted for a deterministic merge order. Keys with no mapped file (not
    every tech in ``_TECH_HINTS`` has a good dedicated SecLists list) are
    silently skipped — that host still tiers "deep", it just gets no extra
    wordlist beyond whatever ``deep_wordlists`` configures."""
    paths = {TECH_WORDLIST_MAP[k] for k in tech_hits if k in TECH_WORDLIST_MAP}
    return sorted(paths)


def classify_depth(
    host: str,
    row: dict | None = None,
    *,
    deep_threshold: int = _DEFAULT_DEEP_THRESHOLD,
    light_threshold: int = _DEFAULT_LIGHT_THRESHOLD,
) -> tuple[str, list[str]]:
    """Xếp một host vào ``"deep"``/``"standard"``/``"light"``. Pure, không I/O.

    ``row`` là dòng ``alive_detail.json`` tương ứng (có thể ``None``/rỗng —
    ``-td`` có thể chưa bật, hoặc host không có dòng detail). Không bao giờ
    raise.

    Thứ tự ưu tiên: tín hiệu tech/response THẮNG điểm hostname — một host
    tên chung chung đang chạy Jenkins vẫn phải vào "deep".
    """
    row = row or {}
    blob = _tech_blob(row)
    tech_hits = [label for kw, label in _TECH_HINTS.items() if kw in blob]
    if tech_hits:
        # dedupe giữ thứ tự (nhiều keyword có thể trỏ cùng nhãn, vd nexus/artifactory)
        seen: set[str] = set()
        reasons = []
        for label in tech_hits:
            if label not in seen:
                seen.add(label)
                reasons.append(f"tech: {label}")
        return "deep", reasons

    hscore = score_subdomain(host)
    if hscore >= deep_threshold:
        return "deep", [f"hostname score {hscore}"]
    if hscore <= light_threshold:
        return "light", [f"hostname score {hscore} (noise pattern)"]
    return "standard", []


def tier_targets(
    targets: list[str],
    detail_rows: list[dict] | None,
    cfg: dict | None = None,
) -> tuple[dict[str, list[str]], dict]:
    """Chia ``targets`` (URL, không phải hostname trần) thành 3 tier.

    ``detail_rows`` là ``alive_detail.json`` đã load (list of dict khớp theo
    ``url``). Giữ nguyên thứ tự xuất hiện trong mỗi tier.

    Trần ``deep_max_hosts``: vượt trần thì host điểm ``score_subdomain``
    thấp hơn bị HẠ về "standard" — không bao giờ bị loại khỏi target list
    (loại hẳn là việc của ``fuzz_targets``, không phải module này).
    """
    d_cfg = (cfg or {}).get("fuzz_depth") or {}
    deep_threshold = int(d_cfg.get("deep_score_threshold", _DEFAULT_DEEP_THRESHOLD))
    light_threshold = int(d_cfg.get("light_score_threshold", _DEFAULT_LIGHT_THRESHOLD))
    cap = int(d_cfg.get("deep_max_hosts", _DEFAULT_DEEP_MAX_HOSTS) or 0)

    by_url: dict[str, dict] = {}
    for row in detail_rows or []:
        if isinstance(row, dict) and row.get("url"):
            by_url[row["url"].strip()] = row

    buckets: dict[str, list[str]] = {"deep": [], "standard": [], "light": []}
    reasons_map: dict[str, list[str]] = {}
    for t in targets:
        u = (t or "").strip()
        if not u:
            continue
        host = _host_of(u)
        row = by_url.get(u)
        tier, reasons = classify_depth(
            host, row, deep_threshold=deep_threshold, light_threshold=light_threshold,
        )
        buckets[tier].append(u)
        reasons_map[u] = reasons

    demoted = 0
    if cap and len(buckets["deep"]) > cap:
        ranked = sorted(buckets["deep"], key=lambda u: -score_subdomain(_host_of(u)))
        keep, demote = ranked[:cap], ranked[cap:]
        buckets["deep"] = keep
        # giữ nguyên thứ tự demote lên đầu standard (mới bị hạ, đáng chú ý hơn
        # phần standard "thường" ở dưới).
        buckets["standard"] = demote + buckets["standard"]
        demoted = len(demote)

    # Tech đã phát hiện trên tập "deep" CUỐI CÙNG (sau demote) — một host bị
    # demote không còn đáng nhận wordlist tốn kém, kể cả khi nó có tech
    # signal (demote chỉ xét hostname score, không phân biệt lý do vào deep).
    tech_hits: dict[str, int] = {}
    for u in buckets["deep"]:
        for key in _matched_tech_keys(by_url.get(u) or {}):
            tech_hits[key] = tech_hits.get(key, 0) + 1

    stats = {
        "deep": len(buckets["deep"]),
        "standard": len(buckets["standard"]),
        "light": len(buckets["light"]),
        "demoted": demoted,
        "reasons": reasons_map,
        "deep_tech_hits": tech_hits,
        "deep_tech_wordlists": tech_wordlists_for(tech_hits),
    }
    return buckets, stats


_TECH_CONFIRMED_FILE = "tech_confirmed.json"


def load_confirmed_tech(output_dir: Path) -> dict[str, list[str]]:
    """``{host: [tech_key, ...]}`` xác nhận bởi probe (misconfig_probe, ...)
    ở lần scan này HOẶC các lần trước — file này KHÔNG bị ghi đè mỗi run,
    xem ``save_confirmed_tech``. Chưa từng có finding nào → ``{}``, không
    lỗi (đúng hợp đồng "missing = None found", không phải exception, mà
    mọi thứ khác trong module này theo)."""
    data = load_json(layout.path(output_dir, _TECH_CONFIRMED_FILE))
    if not isinstance(data, dict):
        return {}
    return {
        str(host): [str(t) for t in techs]
        for host, techs in data.items()
        if isinstance(techs, list)
    }


def save_confirmed_tech(output_dir: Path, host_tech: dict[str, list[str]]) -> dict[str, list[str]]:
    """Merge *host_tech* (mới xác nhận ở lần scan này) vào
    ``tech_confirmed.json`` đã có — union theo host, không ghi đè, để tech
    xác nhận ở lần scan trước không mất khi lần này không probe lại đúng
    endpoint đó (host offline tạm thời, hoặc bị bỏ khỏi tier "deep" lần
    này). Trả về kết quả đã merge để caller log/test mà không phải đọc lại
    đĩa."""
    existing = load_confirmed_tech(output_dir)
    merged = {h: list(v) for h, v in existing.items()}
    for host, techs in host_tech.items():
        if not techs:
            continue
        cur = merged.setdefault(host, [])
        for t in techs:
            if t not in cur:
                cur.append(t)
    if merged != existing:
        write_json(layout.path(output_dir, _TECH_CONFIRMED_FILE), merged)
    return merged


def merge_confirmed_tech(
    detail_rows: list[dict] | None, confirmed: dict[str, list[str]],
) -> list[dict]:
    """Cộng tech đã xác nhận (key trong ``_TECH_HINTS``, vd ``"jenkins"``)
    vào field ``tech`` của dòng ``alive_detail.json`` khớp host — sau đó
    ``_tech_blob``/``_matched_tech_keys`` tự bắt được, KHÔNG cần sửa gì ở
    logic phân loại: key đã là chính xác chuỗi cần khớp, chỉ cần có mặt
    trong blob đã lowercase.

    Không mutate ``detail_rows`` gốc. Host có tech xác nhận nhưng KHÔNG có
    dòng httpx detail nào (hiếm — host rớt khỏi ``alive_detail.json`` giữa
    hai lần scan) vẫn được tạo một dòng tối giản, để tech xác nhận không
    bao giờ bị "quên" chỉ vì thiếu phần httpx.
    """
    if not confirmed:
        return list(detail_rows or [])
    merged: list[dict] = []
    seen_hosts: set[str] = set()
    for row in detail_rows or []:
        if not isinstance(row, dict):
            continue
        host = _host_of(str(row.get("url") or ""))
        seen_hosts.add(host)
        extra = confirmed.get(host)
        if extra:
            row = dict(row)
            existing = row.get("tech")
            existing_list = list(existing) if isinstance(existing, list) else []
            row["tech"] = existing_list + [t for t in extra if t not in existing_list]
        merged.append(row)
    for host, techs in confirmed.items():
        if host not in seen_hosts and techs:
            merged.append({"url": f"https://{host}", "tech": list(techs)})
    return merged


def load_tiers(
    alive_file: Path,
    output_dir: Path,
    cfg: dict | None = None,
) -> tuple[dict[str, list[str]], dict]:
    """``tier_targets`` nhưng tự đọc ``alive.txt``/``alive_detail.json`` từ đĩa.

    Dùng cho caller không có sẵn target list đã chọn trong tay (vd
    ``misconfig_probe``, vốn độc lập với dirsearch/ffuf và tự tính tier
    riêng thay vì phụ thuộc trạng thái đang chạy của hai stage đó).

    Tự merge ``tech_confirmed.json`` vào detail rows — xem module
    docstring phần "Nguồn tech thứ 3".
    """
    targets = read_lines(alive_file)
    detail = load_json(layout.path(output_dir, "alive_detail.json"))
    rows = detail if isinstance(detail, list) else []
    rows = merge_confirmed_tech(rows, load_confirmed_tech(output_dir))
    return tier_targets(targets, rows, cfg)


def summary_line(stats: dict) -> str:
    """Một dòng cho console, cùng phong cách với ``fuzz_targets.summary_line``."""
    counts = [f"{stats.get('deep', 0)} deep", f"{stats.get('standard', 0)} standard",
              f"{stats.get('light', 0)} light"]
    line = " / ".join(counts)
    notes = []
    if stats.get("demoted"):
        notes.append(f"({stats['demoted']} hạ về standard vì vượt deep_max_hosts)")
    tech_hits = stats.get("deep_tech_hits") or {}
    if tech_hits:
        techs = ", ".join(sorted(tech_hits))
        notes.append(f"tech: {techs}")
    if notes:
        line += " " + " ".join(notes)
    return line
