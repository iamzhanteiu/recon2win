"""content_discovery — stage 4.1: katana + urlfinder crawling.

The output is split:
  * raw/content_discovery/katana_urls.txt, raw/content_discovery/urlfinder_urls.txt  — raw tool output
  * processed/crawler_urls.txt                    — deduped union
  * processed/js_urls.txt                         — *.js URLs found while crawling
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from . import console, fuzz_targets, runner
from .telegram import notify_stage_result
from .utils import (
    make_result,
    raw_dir,
    read_lines,
    write_json,
    write_lines,
)


JS_RE = re.compile(r"https?://[^\s\"'<>]+\.js(?:[?#][^\s\"'<>]*)?", re.IGNORECASE)


def _hosts_from_urls(url_lines: list[str]) -> list[str]:
    """Reduce a list of full URLs (httpx alive output) to unique bare hosts.

    urlfinder's ``-list`` expects domains/hosts, not full ``scheme://host/path``
    URLs, so we strip everything but the hostname (port dropped) and dedupe
    while preserving first-seen order.
    """
    seen: set[str] = set()
    hosts: list[str] = []
    for ln in url_lines:
        s = ln.strip()
        if not s:
            continue
        if "://" not in s:
            s = "http://" + s  # bare host — give urlsplit a scheme to parse
        host = urlsplit(s).hostname or ""
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
    return hosts


def _outputs_exist(out_dir: Path) -> bool:
    p = out_dir / "processed" / "crawler_urls.txt"
    return p.exists() and p.stat().st_size > 0


def _extract_katana_jsonl(jsonl_path: Path, urls_out: Path,
                          forms_out: Path) -> tuple[int, int]:
    """Split katana ``-jsonl -fx`` output into two files:

      * ``urls_out``  — plain URL list (one per line), so every downstream
        consumer that read the old ``katana_urls.txt`` keeps working.
      * ``forms_out`` — ``{"forms": [...]}`` where each form is
        ``{url, action, method, enctype, parameters:[names]}`` — the
        POST/upload/login attack surface arjun's GET-param scan never sees.

    Parses defensively: a partial file from a timed-out crawl still yields
    whatever completed. Returns ``(url_count, form_count)``.
    """
    import json

    urls: list[str] = []
    forms: list[dict] = []
    seen_form: set[tuple] = set()
    for ln in jsonl_path.read_text(errors="ignore").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        req = obj.get("request") or {}
        url = req.get("endpoint") or ""
        if url:
            urls.append(url)
        resp = obj.get("response") or {}
        for f in resp.get("forms") or []:
            if not isinstance(f, dict):
                continue
            action = f.get("action") or url
            method = (f.get("method") or "GET").upper()
            params = [p for p in (f.get("parameters") or []) if p]
            key = (method, action, tuple(sorted(params)))
            if key in seen_form:
                continue
            seen_form.add(key)
            forms.append({
                "url": url, "action": action, "method": method,
                "enctype": f.get("enctype") or "", "parameters": params,
            })
    n_urls = write_lines(urls_out, urls)   # write_lines dedups
    write_json(forms_out, {"forms": forms, "count": len(forms)})
    return n_urls, len(forms)


def crawl(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
) -> dict:
    stage = "content_discovery"
    raw_cd = raw_dir(output_dir, "content_discovery")
    proc = output_dir / "processed"
    proc.mkdir(parents=True, exist_ok=True)

    if resume and _outputs_exist(output_dir):
        return make_result(
            stage, "success", input_path=alive_file,
            outputs=[proc / "crawler_urls.txt", proc / "js_urls.txt"],
            count=len(read_lines(proc / "crawler_urls.txt")),
        )

    if dry_run:
        return make_result(
            stage, "skipped", input_path=alive_file,
            outputs=[raw_cd / "katana_urls.txt", raw_cd / "urlfinder_urls.txt",
                     proc / "crawler_urls.txt", proc / "js_urls.txt"],
            count=0, error="dry-run",
        )

    cd_cfg = cfg.get("content_discovery", {})
    outputs: list[Path] = []
    all_urls: list[str] = []

    # Cùng bước chọn target với hai stage fuzzing: crawl 200 host wildcard
    # cùng phục vụ một app cũng lãng phí y như fuzz chúng. Tắt bằng
    # ``content_discovery.dedup_targets: false``.
    sel_stats: dict = {}
    if cd_cfg.get("dedup_targets", True):
        targets, sel_stats = fuzz_targets.load_targets(
            alive_file, output_dir,
            max_hosts=int(cd_cfg.get("max_hosts", 0)),   # 0 = không cap
            dedup=True,
            skip_waf=bool(cd_cfg.get("skip_waf", False)),
        )
        if targets and sel_stats.get("deduped"):
            alive_file = fuzz_targets.write_target_file(
                targets, raw_cd / "targets.txt")
            print(console.phase_info_line(
                f"[content_discovery] {fuzz_targets.summary_line(sel_stats)}"))

    # 4.1.a — katana
    if cd_cfg.get("katana", {}).get("enabled", True):
        out = raw_cd / "katana_urls.txt"
        forms_out = proc / "forms.json"
        if runner.tool_available("katana"):
            depth = int(cd_cfg.get("katana", {}).get("depth", 3))
            to = int(cd_cfg.get("katana", {}).get("timeout", 1800))
            fx = bool(cd_cfg.get("katana", {}).get("form_extraction", True))
            # -do (-display-out-scope): also emit external endpoints found
            # while crawling in-scope pages — e.g. JS/assets served from a
            # CDN / S3 / static host. These out-of-scope JS URLs feed the
            # JS-analysis stages (xnLinkFinder + jsluice), which parse them
            # for the app's own API endpoints.
            base_cmd = ["katana", "-list", str(alive_file), "-do",
                        "-depth", str(depth), "-silent"]
            if fx:
                # -fx extracts form/input/textarea/select into the jsonl.
                # -ob (omit body) + -or (omit raw request/response) keep the
                # jsonl lean — it carries ONLY the endpoint + parsed forms,
                # no bodies and no raw HTTP headers (~70% smaller). We split
                # it back into a plain URL list (downstream stays unchanged) +
                # processed/forms.json, then delete the jsonl since both
                # useful pieces are now persisted. Same single crawl — no
                # extra requests to the target.
                jsonl = raw_cd / "katana.jsonl"
                r = runner.run(
                    base_cmd + ["-jsonl", "-fx", "-ob", "-or",
                                "-output", str(jsonl)],
                    stage="content_discovery_katana", log_name=stage,
                    output_dir=output_dir, timeout=to,
                )
                if not r["success"] and not r["missing_binary"]:
                    print(f"[{stage}] katana failed: {r['stderr'][:200]}")
                if jsonl.exists() and jsonl.stat().st_size > 0:
                    n_u, n_f = _extract_katana_jsonl(jsonl, out, forms_out)
                    if n_f:
                        print(console.phase_info_line(
                            f"[{stage}] katana form-extraction: {n_f} form(s) "
                            f"→ processed/forms.json"))
                    # URL + forms are now in katana_urls.txt / forms.json;
                    # the intermediate jsonl is dead weight — drop it.
                    try:
                        jsonl.unlink()
                    except OSError:
                        pass
                else:
                    out.write_text("")
                    write_json(forms_out, {"forms": [], "count": 0})
            else:
                r = runner.run(
                    base_cmd + ["-output", str(out)],
                    stage="content_discovery_katana", log_name=stage,
                    output_dir=output_dir, timeout=to,
                )
                if not r["success"] and not r["missing_binary"]:
                    print(f"[{stage}] katana failed: {r['stderr'][:200]}")
                write_json(forms_out, {"forms": [], "count": 0})
        else:
            print(f"[{stage}] katana not installed — skipping")
            out.write_text("")
            write_json(forms_out, {"forms": [], "count": 0})
        outputs.append(out)
        all_urls.extend(read_lines(out))
    else:
        (raw_cd / "katana_urls.txt").write_text("")
        (proc / "forms.json").write_text('{"forms": [], "count": 0}')
        outputs.append(raw_cd / "katana_urls.txt")

    # 4.1.b — urlfinder (projectdiscovery/urlfinder). ``-list`` takes a file of
    # *domains/hosts* (not full URLs), so we feed it hostnames extracted from
    # the httpx alive list. ``-d`` is for a literal domain string and would
    # silently do nothing when handed a file path — that was the old bug.
    if cd_cfg.get("urlfinder", {}).get("enabled", True):
        out = raw_cd / "urlfinder_urls.txt"
        if runner.tool_available("urlfinder"):
            to = int(cd_cfg.get("urlfinder", {}).get("timeout", 1800))
            hosts = _hosts_from_urls(read_lines(alive_file))
            if hosts:
                # Temp host list — not persisted (keeps the output tree lean).
                tmp = tempfile.NamedTemporaryFile(
                    "w", suffix=".txt", prefix="urlfinder_hosts_",
                    delete=False, encoding="utf-8",
                )
                try:
                    tmp.write("\n".join(hosts) + "\n")
                    tmp.close()
                    r = runner.run(
                        ["urlfinder", "-list", tmp.name, "-o", str(out), "-silent"],
                        stage="content_discovery_urlfinder", log_name=stage,
                        output_dir=output_dir, timeout=to,
                    )
                    if not r["success"] and not r["missing_binary"]:
                        print(f"[{stage}] urlfinder failed: {r['stderr'][:200]}")
                finally:
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
            else:
                print(f"[{stage}] no alive hosts for urlfinder — skipping")
                out.write_text("")
        else:
            print(f"[{stage}] urlfinder not installed — skipping")
            out.write_text("")
        outputs.append(out)
        all_urls.extend(read_lines(out))
    else:
        (raw_cd / "urlfinder_urls.txt").write_text("")
        outputs.append(raw_cd / "urlfinder_urls.txt")

    # 4.1.c — gau (archived URLs from wayback / commoncrawl / otx / urlscan).
    # Complements waymore (different provider mix + faster) and, with
    # ``--subs``, pulls URLs across every subdomain of the target — often
    # surfacing endpoints and hosts passive enum + active crawl both miss.
    if cd_cfg.get("gau", {}).get("enabled", True):
        out = raw_cd / "gau_urls.txt"
        if runner.tool_available("gau"):
            to = int(cd_cfg.get("gau", {}).get("timeout", 600))
            threads = int(cd_cfg.get("gau", {}).get("threads", 5))
            r = runner.run(
                ["gau", "--subs", "--threads", str(threads),
                 "--o", str(out), output_dir.name],
                stage="content_discovery_gau", log_name=stage,
                output_dir=output_dir, timeout=to,
            )
            if not r["success"] and not r["missing_binary"]:
                print(f"[{stage}] gau failed: {r['stderr'][:200]}")
        else:
            print(f"[{stage}] gau not installed — skipping")
            out.write_text("")
        outputs.append(out)
        all_urls.extend(read_lines(out))
    else:
        (raw_cd / "gau_urls.txt").write_text("")
        outputs.append(raw_cd / "gau_urls.txt")

    crawler_txt = proc / "crawler_urls.txt"
    js_txt = proc / "js_urls.txt"
    n_crawl = write_lines(crawler_txt, all_urls)
    # ``js_urls.txt`` is the only JS-URL file now — ``js_urls_from_crawler.txt``
    # was dropped because it's just a subset of the union produced by
    # the later url_merge stage. Other stages (crawler-derived JS) get
    # folded in by url_merge.
    n_js = write_lines(js_txt, [u for u in all_urls if JS_RE.match(u)])

    result = make_result(
        stage, "success", input_path=alive_file,
        outputs=outputs + [crawler_txt, js_txt],
        count=n_crawl, extra={"js_urls": n_js, "selection": sel_stats},
    )

    # stage-complete summary — only fires when URLs > 0
    notify_stage_result(stage, result, cfg.get("telegram") or {})

    return result
