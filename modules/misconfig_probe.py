"""misconfig_probe — server/microservice misconfig probe, tier "deep" only.

``apidocs.py`` đã quét mọi host cho OpenAPI/Swagger + một số path discovery
document (bare ``/actuator``, ``/wp-json``, ``/.well-known/*``). Module này
đi xa hơn — các sub-path NHẠY CẢM của từng loại service cụ thể (Spring
actuator, Jenkins script console, GitLab API, Kubernetes API server, phpMyAdmin,
Prometheus, ...) — nhưng CHỈ chạy trên host tier "deep" (``fuzz_depth``), vì
đây là loại probe tốn kém hơn và có mục tiêu hẹp hơn nhiều so với apidocs.

Tự tính tier riêng qua ``fuzz_depth.load_tiers`` — không phụ thuộc trạng thái
đang chạy của dirsearch/ffuf, module độc lập, test được riêng.

Cùng nguyên tắc precision với ``apidocs.parse_spec``: một 200 không phải là
bằng chứng (vấn đề SPA catch-all vẫn xảy ra ở đây) — mỗi họ dịch vụ có một
validator riêng kiểm tra NỘI DUNG response, không chỉ status code. Khi không
có validator đủ mạnh (Consul, Nexus ping), chấp nhận theo status nhưng gắn
``confidence: "low"`` để report/priority phân biệt được.

CỐ TÌNH KHÔNG có: bất kỳ kiểu SSRF/cloud-metadata-qua-target nào — chỉ dùng
request trực tiếp, thụ động, cùng nguyên tắc với mọi probe khác trong repo.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from . import console, fuzz_depth, layout, runner
from .apidocs import build_candidates
from .fuzz_targets import _host_of
from .utils import make_result, raw_dir, read_lines, write_json, write_lines

# ----------------------------------------------------------------------
# Candidate paths, grouped by service family. Deliberately non-overlapping
# with apidocs.SPEC_PATHS (bare /actuator, /actuator/mappings, /wp-json,
# /rest/api/2/serverInfo, /.well-known/*).
# ----------------------------------------------------------------------
MISCONFIG_PATHS: tuple[str, ...] = (
    # Spring Boot actuator — sensitive sub-endpoints, not the bare index.
    "/actuator/env", "/actuator/heapdump", "/actuator/beans",
    "/actuator/httptrace", "/actuator/threaddump", "/actuator/loggers",
    "/actuator/shutdown",
    # Jenkins
    "/script", "/manage", "/asynchPeople", "/systemInfo", "/whoAmI/api/json",
    # GitLab
    "/api/v4/version", "/-/metrics",
    # Kubernetes API server
    "/api/v1/namespaces", "/apis", "/version",
    # Docker registry
    "/v2/_catalog",
    # Consul
    "/v1/catalog/services", "/v1/agent/self",
    # Elasticsearch / Kibana
    "/_cluster/health", "/_cat/indices?v",
    # Nexus / Artifactory
    "/service/rest/v1/status", "/artifactory/api/system/ping",
    # phpMyAdmin / Adminer
    "/phpmyadmin/", "/pma/", "/adminer.php",
    # Prometheus
    "/metrics", "/api/v1/status/config",
    # Eureka
    "/eureka/apps",
)


def _json(body: str) -> Optional[dict]:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _path_of(url: str) -> str:
    # Không cần urlsplit đầy đủ — mọi candidate được build_candidates() ghép
    # bằng host + path nguyên bản trong MISCONFIG_PATHS, nên khớp hậu tố là đủ.
    for p in MISCONFIG_PATHS:
        if url.endswith(p):
            return p
    return ""


def classify_hit(row: dict) -> Optional[dict]:
    """``{"service", "confidence", "status", "tech"}`` khi hit là misconfig
    thật, ``None`` khi không đủ bằng chứng — cùng hợp đồng với
    ``apidocs._classify_hit``: một 200 không phải là bằng chứng.

    ``tech`` là key trong ``fuzz_depth._TECH_HINTS`` (vd ``"jenkins"``,
    ``"spring"``) — CONFIRMED bằng nội dung response, không phải đoán qua
    title/header như httpx ``-td``. Rỗng khi service này chưa có key tương
    ứng trong ``_TECH_HINTS`` (vd Eureka). Đây là thứ ``discover()`` dùng để
    ghi vào ``tech_confirmed.json`` — xem ``fuzz_depth.save_confirmed_tech``.
    """
    url = row.get("url") or ""
    status = row.get("status_code")
    body = row.get("body") or row.get("response") or ""
    ctype = str(row.get("content_type") or "").lower()
    path = _path_of(url)
    if not path:
        return None

    def hit(service: str, confidence: str, tech: str = "") -> dict:
        return {"url": url, "service": service, "confidence": confidence,
                "status": status, "tech": tech}

    if path == "/actuator/env":
        d = _json(body)
        if d and ("propertySources" in d or "activeProfiles" in d):
            return hit("Spring Boot actuator/env", "high", "spring")
        return None
    if path == "/actuator/heapdump":
        if "octet-stream" in ctype and len(body) > 1024:
            return hit("Spring Boot actuator/heapdump", "high", "spring")
        return None
    if path in ("/actuator/beans", "/actuator/httptrace", "/actuator/threaddump",
               "/actuator/loggers"):
        d = _json(body)
        if d:
            return hit(f"Spring Boot actuator ({path.rsplit('/', 1)[-1]})", "high", "spring")
        return None
    if path == "/actuator/shutdown":
        # POST-only endpoint; a plain GET usually 405s, but any JSON body at
        # all (even an error) confirms the endpoint exists and is wired up.
        if _json(body) is not None:
            return hit("Spring Boot actuator/shutdown", "low", "spring")
        return None
    if path == "/whoAmI/api/json":
        d = _json(body)
        if d and "id" in d and "fullName" in d:
            return hit("Jenkins whoAmI", "high", "jenkins")
        return None
    if path == "/script":
        low = body[:2000].lower()
        if "script console" in low or "groovy" in low:
            return hit("Jenkins script console", "high", "jenkins")
        return None
    if path in ("/manage", "/asynchPeople", "/systemInfo"):
        low = body[:2000].lower()
        if "jenkins" in low:
            return hit(f"Jenkins ({path.lstrip('/')})", "low", "jenkins")
        return None
    if path == "/api/v4/version":
        d = _json(body)
        if d and "version" in d and "revision" in d:
            return hit("GitLab API version", "high", "gitlab")
        return None
    if path == "/-/metrics":
        if "# TYPE" in body or "# HELP" in body:
            return hit("GitLab metrics", "high", "gitlab")
        return None
    if path == "/version":
        d = _json(body)
        if d and "major" in d and "minor" in d:
            return hit("Kubernetes API version", "high", "kubernetes")
        return None
    if path == "/api/v1/namespaces":
        d = _json(body)
        if d and d.get("kind") in ("NamespaceList", "Status"):
            return hit("Kubernetes API (namespaces)", "high", "kubernetes")
        return None
    if path == "/apis":
        d = _json(body)
        if d and d.get("kind") == "APIGroupList":
            return hit("Kubernetes API (apis)", "high", "kubernetes")
        return None
    if path == "/v2/_catalog":
        d = _json(body)
        if d and "repositories" in d:
            return hit("Docker registry catalog", "high", "docker")
        return None
    if path == "/_cluster/health":
        d = _json(body)
        if d and "cluster_name" in d and "status" in d:
            return hit("Elasticsearch cluster health", "high", "elastic")
        return None
    if path == "/_cat/indices?v":
        low = body[:500].lower()
        if "health status index" in low or ("green " in low or "yellow " in low):
            return hit("Elasticsearch indices", "high", "elastic")
        return None
    if path in ("/phpmyadmin/", "/pma/"):
        if "phpmyadmin" in body[:4000].lower():
            return hit("phpMyAdmin", "high", "phpmyadmin")
        return None
    if path == "/adminer.php":
        if "adminer" in body[:4000].lower():
            return hit("Adminer", "high", "adminer")
        return None
    if path == "/api/v1/status/config":
        d = _json(body)
        if d and d.get("status") == "success" and "data" in d:
            return hit("Prometheus config", "high", "prometheus")
        return None
    if path == "/metrics":
        if "# TYPE" in body or "# HELP" in body:
            return hit("Prometheus/exporter metrics", "high", "prometheus")
        return None
    if path == "/eureka/apps":
        low = body[:500].lower()
        if "<applications" in low or '"applications"' in low:
            # No "eureka" key in fuzz_depth._TECH_HINTS yet — a real finding,
            # just nothing to propagate into tech_confirmed.json.
            return hit("Eureka service registry", "high")
        return None
    # Weak/no validator (Consul, Nexus/Artifactory ping) — accept on status
    # alone but flag low confidence so it never outranks a validated hit.
    if path in ("/v1/catalog/services", "/v1/agent/self"):
        if status in (200, 401, 403):
            return hit(f"unverified ({path})", "low", "consul")
        return None
    if path in ("/service/rest/v1/status", "/artifactory/api/system/ping"):
        if status in (200, 401, 403):
            tech = "nexus" if path.startswith("/service/rest") else "artifactory"
            return hit(f"unverified ({path})", "low", tech)
        return None
    return None


# ----------------------------------------------------------------------
# Stage entry point
# ----------------------------------------------------------------------
def _outputs_exist(output_dir: Path) -> bool:
    p = output_dir / "findings" / "misconfig_probe.json"
    return p.exists() and p.stat().st_size > 0


def _probe(candidates: list[str], output_dir: Path, m_cfg: dict) -> list[dict]:
    raw = raw_dir(output_dir, "misconfig_probe")
    in_file = raw / "candidates.txt"
    out_file = raw / "probe.jsonl"
    write_lines(in_file, candidates)
    if out_file.exists():
        out_file.unlink()

    cmd = [
        "httpx", "-l", str(in_file),
        "-json", "-silent", "-irr",
        "-mc", str(m_cfg.get("match_codes", "200,401,403")),
        "-threads", str(int(m_cfg.get("threads", 20))),
        "-timeout", str(int(m_cfg.get("http_timeout", 10))),
        "-retries", "1",
        "-o", str(out_file),
    ]
    runner.run(cmd, stage="misconfig_probe", output_dir=output_dir,
               timeout=int(m_cfg.get("timeout", 900)))

    rows: list[dict] = []
    if not out_file.exists():
        return rows
    for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except (ValueError, TypeError):
            continue
    return rows


def discover(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    domain: str = "",
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "misconfig_probe"
    layout.ensure_tree(output_dir)
    findings = output_dir / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    urls_out = layout.path(output_dir, "misconfig_urls.txt")
    json_out = findings / "misconfig_probe.json"
    outputs = [urls_out, json_out]

    m_cfg = (cfg.get("misconfig_probe") or {}) if isinstance(cfg, dict) else {}

    if skip:
        write_lines(urls_out, [])
        write_json(json_out, {"findings": [], "hosts_probed": 0})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="--skip-misconfig-probe")
    if not m_cfg.get("enabled", True):
        write_lines(urls_out, [])
        write_json(json_out, {"findings": [], "hosts_probed": 0})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="disabled in config")
    if resume and _outputs_exist(output_dir):
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=len(read_lines(urls_out)))
    if dry_run:
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="dry-run")

    tiers, _ = fuzz_depth.load_tiers(alive_file, output_dir, cfg)
    hosts = tiers.get("deep") or []
    if not hosts:
        write_lines(urls_out, [])
        write_json(json_out, {"findings": [], "hosts_probed": 0})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0,
                           error="no deep-tier hosts this run")

    candidates = build_candidates(hosts, MISCONFIG_PATHS)
    findings_list: list[dict] = []
    all_urls: list[str] = []
    probe_stats = {"hosts": len(hosts), "paths": len(MISCONFIG_PATHS),
                   "requests": len(candidates)}

    if candidates and runner.tool_available("httpx"):
        rows = _probe(candidates, output_dir, m_cfg)
        probe_stats["responses"] = len(rows)
        for row in rows:
            hit = classify_hit(row)
            if hit:
                findings_list.append(hit)
                all_urls.append(hit["url"])
    elif candidates:
        probe_stats["error"] = "httpx binary not found"

    # Feed CONFIRMED tech (validated by response content, not guessed from
    # title/header) back into tech_confirmed.json — fuzz_depth reads it on
    # the NEXT scan of this target to tier + pick tech-aware wordlists more
    # accurately than httpx -td alone. See fuzz_depth module docstring for
    # why this run's own dirsearch/ffuf can't use it (they already ran).
    confirmed_tech: dict[str, list[str]] = {}
    for f in findings_list:
        tech = f.get("tech")
        if not tech:
            continue
        host = _host_of(f["url"])
        if tech not in confirmed_tech.setdefault(host, []):
            confirmed_tech[host].append(tech)
    if confirmed_tech:
        fuzz_depth.save_confirmed_tech(output_dir, confirmed_tech)

    n_urls = write_lines(urls_out, sorted(set(all_urls)))
    write_json(json_out, {"findings": findings_list, "hosts_probed": len(hosts),
                          "probe": probe_stats})

    if findings_list:
        high = sum(1 for f in findings_list if f.get("confidence") == "high")
        print(console.phase_info_line(
            f"[{stage}] {len(findings_list)} hit(s) on {len(hosts)} deep-tier "
            f"host(s) ({high} high-confidence)"))
        if confirmed_tech:
            techs = sorted({t for ts in confirmed_tech.values() for t in ts})
            print(console.phase_info_line(
                f"[{stage}] confirmed tech saved for next scan: {', '.join(techs)}"))

    empty_reason = None
    if not findings_list:
        probed = probe_stats.get("responses")
        if probe_stats.get("error"):
            empty_reason = f"no misconfig confirmed — {probe_stats['error']}"
        elif not probed:
            empty_reason = "no misconfig confirmed — no host answered the probe"
        else:
            empty_reason = f"no misconfig confirmed from {probed} response(s)"

    return make_result(
        stage, "success", input_path=alive_file, outputs=outputs,
        count=len(findings_list), error=empty_reason,
        extra={"hosts_probed": len(hosts), "findings": len(findings_list),
               "urls": n_urls, "probe": probe_stats,
               "confirmed_tech": confirmed_tech},
    )
