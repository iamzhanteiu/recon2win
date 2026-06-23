#!/usr/bin/env python3
"""mock_report — generate a final report from a fake-but-realistic output tree.

Use this to preview what `main.py` would produce without running any of the
external tools. Useful for:
  * reviewing the report format
  * screenshotting the HTML for a portfolio / proposal
  * testing downstream tooling that consumes `summary.json`
  * debugging the report module with reproducible data

Usage:
  python3 tools/mock_report.py                       # writes to outputs/mock/
  python3 tools/mock_report.py --out outputs/demo/   # custom output folder
  python3 tools/mock_report.py --domain acme.io      # custom domain
  python3 tools/mock_report.py --open                # open the HTML when done
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Allow running as a script from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.report import build_report  # noqa: E402


# ----------------------------------------------------------------------
# Realistic mock data
# ----------------------------------------------------------------------
DOMAIN = "mock-target.example"

CONFIG_YAML = """\
# ============================================================
#  recon-agent configuration used for this mock run
# ============================================================
output_root: outputs
subdomain:
  tools: [subfinder, amass, chaos]
  chaos_api_key: ""
  timeout: 900
dnsx:
  threads: 100
  timeout: 600
httpx:
  threads: 50
  timeout: 600
content_discovery:
  katana:    { enabled: true, depth: 3 }
  urlfinder: { enabled: true }
dirsearch:
  enabled: true
  threads: 30
  timeout: 3600
  recursive: true
  wordlists:
    - ~/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt
    - ~/wordlists/SecLists/Discovery/Web-Content/Service-Specific
nuclei:
  default: { enabled: true, severity: [critical, high, medium, low, info] }
  dynamic: { enabled: true, tags: [sqli, xss, lfi, rce, ssrf, ssti, idor] }
telegram:
  enabled: false
  bot_token: ""
  chat_id: ""
"""


# ----------------------------------------------------------------------
# Data builders
# ----------------------------------------------------------------------
def _subdomains() -> list[str]:
    return [
        f"www.{DOMAIN}",
        f"api.{DOMAIN}",
        f"admin.{DOMAIN}",
        f"staging.{DOMAIN}",
        f"dev.{DOMAIN}",
        f"mail.{DOMAIN}",
        f"blog.{DOMAIN}",
        f"docs.{DOMAIN}",
        f"jenkins.{DOMAIN}",
        f"grafana.{DOMAIN}",
        f"vpn.{DOMAIN}",
        f"auth.{DOMAIN}",
        f"cdn.{DOMAIN}",
        f"app.{DOMAIN}",
    ]


def _dns_records(subs: list[str]) -> list[dict]:
    asns = [
        ("AS13335", "Cloudflare, Inc."),
        ("AS16509", "Amazon.com, Inc."),
        ("AS15169", "Google LLC"),
        ("AS14061", "DigitalOcean LLC"),
        ("AS8075",  "Microsoft Corporation"),
    ]
    out = []
    for i, s in enumerate(subs):
        asn_code, asn_name = asns[i % len(asns)]
        out.append({
            "subdomain": s,
            "ip": f"{(10 + i) % 256}.{(20 + i) % 256}.{(30 + i) % 256}.{(40 + i) % 256}",
            "aaaa": None,
            "cname": f"edge-{i % 3}.{DOMAIN}" if i % 4 == 0 else None,
            "asn": {"asn": asn_code, "name": asn_name},
        })
    return out


def _httpx_assets(subs: list[str]) -> list[dict]:
    titles = {
        "www":     "Welcome — Example",
        "api":     "API Documentation",
        "admin":   "Admin Panel",
        "staging": "Staging Environment",
        "dev":     "Dev Sandbox",
        "blog":    "Engineering Blog",
        "docs":    "Docs — Example",
        "jenkins": "Jenkins Dashboard",
        "grafana": "Grafana",
        "vpn":     "VPN Portal",
        "auth":    "Sign in — Example",
        "cdn":     "CDN",
        "app":     "Dashboard",
        "mail":    "Webmail",
    }
    techs = {
        "www":     "PHP, Nginx, jQuery",
        "api":     "Node.js, Express, Swagger",
        "admin":   "PHP, Laravel, jQuery",
        "staging": "Ruby, Rails",
        "dev":     "Python, Django",
        "blog":    "Ghost, Node.js",
        "docs":    "Docusaurus, React",
        "jenkins": "Jenkins",
        "grafana": "Grafana, Go",
        "vpn":     "Apache, PHP",
        "auth":    "Keycloak, Java",
        "cdn":     "Nginx",
        "app":     "Next.js, React",
        "mail":    "Roundcube, PHP",
    }
    rows = []
    for s in subs:
        name = s.split(".", 1)[0]
        scheme = "https"
        rows.append({
            "url": f"{scheme}://{s}",
            "input": s,
            "status_code": random.choice([200, 200, 200, 200, 301, 302, 401, 403, 500]),
            "title": titles.get(name, name.title()),
            "content_type": "text/html; charset=utf-8",
            "content_length": random.randint(2_000, 250_000),
            "webserver": random.choice(["nginx/1.25.1", "Apache/2.4.57", "cloudflare"]),
            "tech": techs.get(name, "Unknown"),
            "host": s,
        })
    # manually pin a few important statuses for a believable report
    for row in rows:
        if "admin" in row["url"]:
            row["status_code"] = 200
        elif "api" in row["url"]:
            row["status_code"] = 200
    return rows


def _crawler_urls() -> list[str]:
    return [
        f"https://{DOMAIN}/",
        f"https://{DOMAIN}/login",
        f"https://{DOMAIN}/admin",
        f"https://{DOMAIN}/admin/dashboard",
        f"https://{DOMAIN}/admin/users",
        f"https://{DOMAIN}/api/v1/users",
        f"https://{DOMAIN}/api/v1/orders",
        f"https://{DOMAIN}/api/v2/products",
        f"https://{DOMAIN}/graphql",
        f"https://{DOMAIN}/graphql/query",
        f"https://{DOMAIN}/swagger/index.html",
        f"https://{DOMAIN}/swagger/v1/swagger.json",
        f"https://{DOMAIN}/api/health",
        f"https://{DOMAIN}/forgot-password",
        f"https://{DOMAIN}/signup",
        f"https://{DOMAIN}/uploads/avatar.png",
        f"https://{DOMAIN}/static/app.js",
        f"https://{DOMAIN}/static/vendor.js",
        f"https://{DOMAIN}/assets/main.css",
    ]


def _js_urls() -> list[str]:
    return [
        f"https://{DOMAIN}/static/app.js",
        f"https://{DOMAIN}/static/vendor.js",
        f"https://{DOMAIN}/static/admin.js",
        f"https://{DOMAIN}/static/auth.js",
    ]


def _dirsearch_urls() -> list[str]:
    return [
        f"https://{DOMAIN}/.env",
        f"https://{DOMAIN}/.env.local",
        f"https://{DOMAIN}/.env.production",
        f"https://{DOMAIN}/.git/HEAD",
        f"https://{DOMAIN}/.git/config",
        f"https://{DOMAIN}/.svn/entries",
        f"https://{DOMAIN}/wp-config.php.bak",
        f"https://{DOMAIN}/config.yaml",
        f"https://{DOMAIN}/backup.zip",
        f"https://{DOMAIN}/db.sql",
        f"https://{DOMAIN}/phpinfo.php",
        f"https://{DOMAIN}/server-status",
    ]


def _waymore_urls() -> list[str]:
    return [
        f"https://{DOMAIN}/old/login",
        f"https://{DOMAIN}/legacy/admin",
        f"https://{DOMAIN}/archive/api/v1",
        f"https://{DOMAIN}/js/old-app.js",
    ]


def _xnlinkfinder() -> tuple[list[str], list[str]]:
    endpoints = [
        "/api/v1/login",
        "/api/v1/register",
        "/api/v1/users",
        "/api/v1/users/:id",
        "/api/v1/orders",
        "/api/v2/products",
        "/api/v2/cart",
        "/api/v2/checkout",
        "/graphql/query",
        "/graphql/mutation",
        "/auth/oauth/callback",
        "/auth/refresh",
        "/admin/dashboard",
        "/admin/users",
        "/admin/settings",
        "/internal/health",
        "/internal/metrics",
    ]
    urls = [
        f"https://{DOMAIN}/api/v1/login",
        f"https://{DOMAIN}/api/v1/users",
        f"https://{DOMAIN}/api/v2/products",
        f"https://{DOMAIN}/graphql/query",
    ]
    return endpoints, urls


def _nuclei_default() -> list[dict]:
    return [
        {
            "template-id": "tech-detect",
            "info": {"name": "Nginx", "severity": "info", "tags": ["tech"]},
            "matched-at": f"https://www.{DOMAIN}",
            "matcher-name": "nginx",
        },
        {
            "template-id": "exposed-env-file",
            "info": {"name": "Exposed .env file", "severity": "high",
                     "tags": ["exposure", "config"]},
            "matched-at": f"https://{DOMAIN}/.env",
            "matcher-name": "env-file",
            "extracted-results": ["DB_HOST=internal-db.example.com",
                                  "DB_PASS=REDACTED"],
        },
        {
            "template-id": "git-config-exposure",
            "info": {"name": "Git Config Exposed", "severity": "medium",
                     "tags": ["exposure", "git"]},
            "matched-at": f"https://{DOMAIN}/.git/config",
            "matcher-name": "git-config",
            "extracted-results": ["[remote \"origin\"]"],
        },
        {
            "template-id": "phpinfo-exposure",
            "info": {"name": "phpinfo() page detected", "severity": "low",
                     "tags": ["exposure", "php"]},
            "matched-at": f"https://{DOMAIN}/phpinfo.php",
        },
        {
            "template-id": "wordpress-config-backup",
            "info": {"name": "WordPress Config Backup", "severity": "high",
                     "tags": ["wordpress", "exposure"]},
            "matched-at": f"https://{DOMAIN}/wp-config.php.bak",
            "extracted-results": ["DB_PASSWORD=hunter2"],
        },
    ]


def _nuclei_dynamic() -> list[dict]:
    return [
        {
            "template-id": "sqli-error-based",
            "info": {"name": "SQL Error Detected", "severity": "critical",
                     "tags": ["sqli", "fuzzing"]},
            "matched-at": f"https://{DOMAIN}/api/v1/users?id=1'",
            "matcher-name": "sql-error",
            "extracted-results": ["You have an error in your SQL syntax"],
        },
        {
            "template-id": "xss-reflected",
            "info": {"name": "Reflected XSS", "severity": "high",
                     "tags": ["xss"]},
            "matched-at": f"https://{DOMAIN}/search?q=<script>",
        },
        {
            "template-id": "open-redirect",
            "info": {"name": "Open Redirect", "severity": "low",
                     "tags": ["redirect"]},
            "matched-at": f"https://{DOMAIN}/login?next=//evil.com",
        },
    ]


def _arjun_params() -> tuple[list[str], list[str]]:
    raw = [
        f"[200] https://{DOMAIN}/login?username=&password=",
        f"[200] https://{DOMAIN}/search?q=&page=",
        f"[200] https://{DOMAIN}/api/v1/users?limit=&offset=",
        f"[200] https://{DOMAIN}/api/v1/orders?id=&status=",
        f"[200] https://{DOMAIN}/admin/dashboard?tab=&filter=",
    ]
    # Each line is "[STATUS] URL" — strip the bracketed status and the
    # following space to recover the URL.
    import re
    param_urls = [re.sub(r"^\[\d+\]\s+", "", line) for line in raw]
    return raw, param_urls


def _stage_results() -> list[dict]:
    return [
        {"stage": "subdomain",      "status": "success", "count": 14, "error": None,
         "extra": {"elapsed_seconds": 12.3}},
        {"stage": "dnsx",           "status": "success", "count": 14, "error": None,
         "extra": {"elapsed_seconds": 4.1}},
        {"stage": "httpx_alive",    "status": "success", "count": 14, "error": None,
         "extra": {"elapsed_seconds": 8.7}},
        {"stage": "content_discovery", "status": "success", "count": 19, "error": None,
         "extra": {"elapsed_seconds": 25.4, "js_urls": 4}},
        {"stage": "dirsearch",      "status": "success", "count": 12, "error": None,
         "extra": {"elapsed_seconds": 31.0, "mode": "wordlist"}},
        {"stage": "waymore",        "status": "skipped", "count": 0,
         "error": "waymore binary not found (optional, skipped)"},
        {"stage": "nuclei_default", "status": "success", "count": 5, "error": None,
         "extra": {
             "severity_count": {"critical": 0, "high": 2, "medium": 1, "low": 1, "info": 1},
             "elapsed_seconds": 88.2,
         }},
        {"stage": "url_merge",      "status": "success", "count": 30, "error": None,
         "extra": {"js": 4, "dynamic": 22}},
        {"stage": "httpx_urls",     "status": "success", "count": 28, "error": None,
         "extra": {"elapsed_seconds": 19.0}},
        {"stage": "xnlinkfinder",   "status": "success", "count": 21, "error": None,
         "extra": {"endpoints": 17, "urls": 4, "elapsed_seconds": 5.5}},
        {"stage": "arjun",          "status": "success", "count": 5, "error": None,
         "extra": {"elapsed_seconds": 41.6}},
        {"stage": "nuclei_dynamic", "status": "success", "count": 3, "error": None,
         "extra": {
             "severity_count": {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0},
             "elapsed_seconds": 60.0,
         }},
        {"stage": "report",         "status": "success", "count": 3, "error": None},
    ]


# ----------------------------------------------------------------------
# Populate an output tree
# ----------------------------------------------------------------------
def populate(output_dir: Path, domain: str) -> dict:
    raw = output_dir / "raw"
    proc = output_dir / "processed"
    findings = output_dir / "findings"
    logs = output_dir / "logs"
    for d in (raw, proc, findings, logs):
        d.mkdir(parents=True, exist_ok=True)

    subs = _subdomains()
    subs_simple = [s.replace(f".{domain}", "") for s in subs]

    # raw
    (raw / "subfinder.txt").write_text("\n".join(subs[:8]) + "\n")
    (raw / "amass.txt").write_text("\n".join(subs[5:]) + "\n")
    (raw / "chaos.txt").write_text("\n".join(subs[::2]) + "\n")
    (raw / "katana_urls.txt").write_text("\n".join(_crawler_urls()[:10]) + "\n")
    (raw / "urlfinder_urls.txt").write_text("\n".join(_crawler_urls()[10:]) + "\n")
    (raw / "dirsearch_raw.txt").write_text("\n".join(
        f"200  {random.randint(10, 200)}B  {u}" for u in _dirsearch_urls()) + "\n")
    (raw / "waymore_raw.txt").write_text("\n".join(_waymore_urls()) + "\n")

    # processed — subdomains
    (proc / "subdomains.txt").write_text("\n".join(subs) + "\n")
    (proc / "resolved.txt").write_text("\n".join(subs) + "\n")
    (proc / "resolved_detail.json").write_text(json.dumps(_dns_records(subs), indent=2))
    # alive
    assets = _httpx_assets(subs)
    alive_urls = [a["url"] for a in assets]
    (proc / "alive.txt").write_text("\n".join(alive_urls) + "\n")
    (proc / "alive_detail.json").write_text(json.dumps(assets, indent=2))
    # alive_detail.csv
    csv_lines = ["url,input,status_code,content_length,content_type,webserver,tech"]
    for a in assets:
        csv_lines.append(
            f"{a['url']},{a['input']},{a['status_code']},"
            f"{a['content_length']},{a['content_type']},{a['webserver']},{a['tech']}"
        )
    (proc / "alive_detail.csv").write_text("\n".join(csv_lines) + "\n")
    # crawler
    (proc / "crawler_urls.txt").write_text("\n".join(_crawler_urls()) + "\n")
    (proc / "js_urls_from_crawler.txt").write_text("\n".join(_js_urls()) + "\n")
    # dirsearch / waymore
    (proc / "dirsearch_urls.txt").write_text("\n".join(_dirsearch_urls()) + "\n")
    (proc / "waymore_urls.txt").write_text("\n".join(_waymore_urls()) + "\n")
    # merged
    all_urls = list({*_crawler_urls(), *_dirsearch_urls(), *_waymore_urls()})
    (proc / "all_urls_raw.txt").write_text("\n".join(all_urls) + "\n")
    (proc / "all_urls.txt").write_text("\n".join(all_urls) + "\n")
    (proc / "js_urls.txt").write_text("\n".join(_js_urls()) + "\n")
    # dynamic = everything that is not a static asset
    dynamic = [
        u for u in all_urls
        if not u.split("?")[0].lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff",
             ".woff2", ".ico", ".mp4", ".mp3")
        )
    ]
    (proc / "dynamic_urls.txt").write_text("\n".join(dynamic) + "\n")
    # xnlinkfinder
    ep, xu = _xnlinkfinder()
    (proc / "xnlinkfinder_endpoints.txt").write_text("\n".join(ep) + "\n")
    (proc / "xnlinkfinder_urls.txt").write_text("\n".join(xu) + "\n")
    # alive_urls (httpx on the union) — reuse the assets
    (proc / "alive_urls.txt").write_text("\n".join(alive_urls) + "\n")
    (proc / "alive_urls_detail.json").write_text(json.dumps(assets, indent=2))
    # arjun
    raw_arjun, param_urls = _arjun_params()
    (proc / "arjun_params.txt").write_text("\n".join(raw_arjun) + "\n")
    (proc / "parameterized_urls.txt").write_text("\n".join(param_urls) + "\n")

    # findings
    n_def = _nuclei_default()
    n_dyn = _nuclei_dynamic()
    (findings / "nuclei_default.txt").write_text(
        "\n".join(f["matched-at"] for f in n_def) + "\n")
    (findings / "nuclei_default.json").write_text(json.dumps({
        "findings": n_def,
        "severity_count": {
            "critical": sum(1 for f in n_def if f["info"]["severity"] == "critical"),
            "high":     sum(1 for f in n_def if f["info"]["severity"] == "high"),
            "medium":   sum(1 for f in n_def if f["info"]["severity"] == "medium"),
            "low":      sum(1 for f in n_def if f["info"]["severity"] == "low"),
            "info":     sum(1 for f in n_def if f["info"]["severity"] == "info"),
        },
    }, indent=2))
    (findings / "nuclei_dynamic.txt").write_text(
        "\n".join(f["matched-at"] for f in n_dyn) + "\n")
    (findings / "nuclei_dynamic.json").write_text(json.dumps({
        "findings": n_dyn,
        "severity_count": {
            "critical": sum(1 for f in n_dyn if f["info"]["severity"] == "critical"),
            "high":     sum(1 for f in n_dyn if f["info"]["severity"] == "high"),
            "medium":   sum(1 for f in n_dyn if f["info"]["severity"] == "medium"),
            "low":      sum(1 for f in n_dyn if f["info"]["severity"] == "low"),
            "info":     sum(1 for f in n_dyn if f["info"]["severity"] == "info"),
        },
    }, indent=2))

    # logs
    cmd_lines = [
        f"[2026-06-23T10:00:00Z] [subdomain] subfinder -d {domain} -all -silent -o raw/subfinder.txt",
        f"[2026-06-23T10:00:05Z] [subdomain] amass enum -passive -d {domain} -o raw/amass.txt",
        f"[2026-06-23T10:00:10Z] [dnsx] dnsx -l processed/subdomains.txt -json -resp -o processed/resolved_detail.json",
        f"[2026-06-23T10:00:14Z] [httpx_alive] httpx -l processed/resolved.txt -json -o processed/alive_detail.json",
        f"[2026-06-23T10:00:22Z] [content_discovery_katana] katana -list processed/alive.txt -depth 3 -silent",
        f"[2026-06-23T10:00:47Z] [content_discovery_urlfinder] urlfinder -i processed/alive.txt -o raw/urlfinder_urls.txt",
        f"[2026-06-23T10:01:18Z] [dirsearch] dirsearch -l processed/alive.txt -e bak,old,zip,env,git",
        f"[2026-06-23T10:01:49Z] [nuclei_default] nuclei -l processed/alive.txt -severity critical,high,medium,low,info",
        f"[2026-06-23T10:03:17Z] [url_merge] merging crawler + dirsearch + waymore into processed/all_urls.txt",
        f"[2026-06-23T10:03:25Z] [httpx_urls] httpx -l processed/all_urls.txt -json",
        f"[2026-06-23T10:03:30Z] [xnlinkfinder] xnlinkfinder -i https://{domain}/static/app.js",
        f"[2026-06-23T10:04:15Z] [arjun] arjun -i processed/dynamic_urls.txt -o processed/arjun_params.txt",
        f"[2026-06-23T10:04:56Z] [nuclei_dynamic] nuclei -l processed/parameterized_urls.txt -tags sqli,xss,ssrf",
    ]
    (logs / "commands.log").write_text("\n".join(cmd_lines) + "\n")

    return {
        "subs_count": len(subs),
        "alive_count": len(assets),
        "all_urls_count": len(all_urls),
        "high_count": len(_dirsearch_urls()) + len([u for u in all_urls
            if any(kw in u.lower() for kw in ("admin", "login", "graphql", "/api/", ".env"))]),
    }


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(
        prog="mock_report",
        description="Generate a final report from a fake-but-realistic output tree",
    )
    p.add_argument("--out", default="outputs/mock",
                   help="output folder (default: outputs/mock)")
    p.add_argument("--domain", default=DOMAIN,
                   help="target domain to embed in the report")
    p.add_argument("--open", action="store_true",
                   help="open final_report.html in the default browser")
    args = p.parse_args()

    out = Path(args.out)
    print(f"[*] building mock output tree at {out}/")
    populate(out, args.domain)

    print("[*] generating report ...")
    scan_start = datetime(2026, 6, 23, 10, 0, 0)
    scan_end = scan_start + timedelta(seconds=296.8)
    info = build_report(
        out, args.domain, {},
        cfg_path="config.yml",
        cfg_text=CONFIG_YAML,
        scan_start=scan_start,
        scan_end=scan_end,
        tool_versions={
            "subfinder":   "v2.14.0",
            "amass":       "v5.1.1",
            "dnsx":        "v1.2.0",
            "httpx":       "v1.6.0",
            "katana":      "v1.2.0",
            "nuclei":      "v3.8.0",
            "dirsearch":   "0.4.3",
            "xnlinkfinder":"v1.0.0",
            "arjun":       "0.9",
            "python3":     "Python 3.14.5",
        },
        stage_results=_stage_results(),
        scan_mode="mock",
    )

    print()
    print("=" * 60)
    print("MOCK REPORT GENERATED")
    print("=" * 60)
    print(f"  HTML      : {info['html']}")
    print(f"  Markdown  : {info['md']}")
    print(f"  JSON      : {info['json']}")
    print()

    # print a tiny summary from the JSON
    j = json.loads(Path(info["json"]).read_text())
    c = j["counts"]
    print("Counts:")
    for k in ("subdomains", "resolved", "alive_hosts", "all_urls", "js_urls",
              "dynamic_urls", "parameterized_urls", "nuclei_default_findings",
              "nuclei_dynamic_findings"):
        print(f"  {k:<28} {c.get(k, 0):>6,}")
    print()
    print(f"High-value targets  : {len(j['high_value_targets'])}")
    print(f"Interesting APIs    : {len(j['interesting_api_paths'])}")
    print(f"Failed stages       : {len(j['stages'].get('failed', []))}")
    print(f"Skipped stages      : {len(j['stages'].get('skipped', []))}")
    print(f"Missing tools       : {j['missing_tools']}")
    print()

    if args.open:
        try:
            subprocess.run(["open", info["html"]], check=False)
        except FileNotFoundError:
            try:
                subprocess.run(["xdg-open", info["html"]], check=False)
            except FileNotFoundError:
                print(f"[!] open it manually: {info['html']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
