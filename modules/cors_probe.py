"""cors_probe — confirm CORS misconfiguration instead of just noting the
API surface exists.

asm_report.py already flags CORS as worth checking whenever hosts + API
surface are present, but nothing ever sent the one request that actually
answers the question: does this host reflect an arbitrary ``Origin`` back
in ``Access-Control-Allow-Origin`` — and if it also sends
``Access-Control-Allow-Credentials: true``, any page on the internet can
read this host's authenticated responses cross-origin. That combination is
the single most common CORS bug bounty programs still pay for, and it costs
one GET per host on top of a probe that already ran.

Empirically verified against a local test server (this docstring's claims
about httpx's JSON shape are not guesses): with ``-irh``, httpx's JSON
output carries a ``"header"`` dict whose keys are the response header
names **lower-cased with hyphens turned to underscores** — so
``Access-Control-Allow-Origin`` shows up as
``header["access_control_allow_origin"]``.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import console, layout, runner
from .utils import load_json, make_result, raw_dir, read_lines, write_json, write_lines

_ACAO_KEY = "access_control_allow_origin"
_ACAC_KEY = "access_control_allow_credentials"


def _outputs_exist(json_out: Path) -> bool:
    return json_out.exists() and json_out.stat().st_size > 0


def classify(url: str, header: dict, test_origin: str) -> dict | None:
    """Return a finding dict, or ``None`` when nothing worth reporting.

    ``header`` is the httpx ``"header"`` dict (already lower_snake_case
    keyed — see module docstring).
    """
    if not isinstance(header, dict):
        return None
    acao = str(header.get(_ACAO_KEY) or "").strip()
    if not acao:
        return None
    acac = str(header.get(_ACAC_KEY) or "").strip().lower() == "true"

    reflects = acao == test_origin
    wildcard = acao == "*"
    if not reflects and not (wildcard and acac):
        # A fixed allow-list origin, or a bare "*" with no credentials —
        # neither is a bug on its own.
        return None

    if reflects and acac:
        severity, note = "critical", (
            "reflects arbitrary Origin AND allows credentials — any site "
            "can read this host's authenticated responses cross-origin")
    elif reflects:
        severity, note = "medium", (
            "reflects arbitrary Origin (no credentials allowed — lower "
            "impact, but still worth checking what the response carries)")
    else:  # wildcard + credentials — invalid per spec, but some servers do it
        severity, note = "medium", (
            "sends Access-Control-Allow-Origin: * together with "
            "Access-Control-Allow-Credentials: true — invalid per the CORS "
            "spec (most browsers reject it) but signals a misconfigured stack")

    return {"url": url, "acao": acao, "acac": acac,
            "severity": severity, "note": note}


def discover(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "cors_probe"
    layout.ensure_tree(output_dir)
    findings = output_dir / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    json_out = findings / "cors.json"
    outputs = [json_out]

    c_cfg = (cfg.get("cors_probe") or {}) if isinstance(cfg, dict) else {}
    test_origin = str(c_cfg.get("test_origin") or
                      "https://recon2win-cors-test.invalid")

    if skip:
        write_json(json_out, {"findings": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="--skip-cors-probe")
    if not c_cfg.get("enabled", True):
        write_json(json_out, {"findings": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="disabled in config")
    if resume and _outputs_exist(json_out):
        existing = load_json(json_out) or {}
        findings_list = existing.get("findings", []) if isinstance(existing, dict) else []
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=len(findings_list))
    if dry_run:
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="dry-run")
    if not runner.tool_available("httpx"):
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="httpx binary not found")

    hosts = read_lines(alive_file)
    max_hosts = int(c_cfg.get("max_hosts", 500) or 0)
    capped = 0
    if max_hosts and len(hosts) > max_hosts:
        capped = len(hosts) - max_hosts
        hosts = hosts[:max_hosts]
    if not hosts:
        write_json(json_out, {"findings": []})
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=0, error="no alive hosts")

    raw = raw_dir(output_dir, "cors_probe")
    in_file = raw / "hosts.txt"
    out_file = raw / "probe.jsonl"
    write_lines(in_file, hosts)
    if out_file.exists():
        out_file.unlink()

    cmd = [
        "httpx", "-l", str(in_file),
        "-H", f"Origin: {test_origin}",
        "-json", "-silent", "-irh", "-duc",
        "-threads", str(int(c_cfg.get("threads", 30))),
        "-timeout", str(int(c_cfg.get("http_timeout", 10))),
        "-retries", "1",
        "-o", str(out_file),
    ]
    runner.run(cmd, stage=stage, output_dir=output_dir,
              timeout=int(c_cfg.get("timeout", 900)))

    rows: list[dict] = []
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except (ValueError, TypeError):
                continue

    findings_list: list[dict] = []
    for row in rows:
        hit = classify(row.get("url") or "", row.get("header") or {}, test_origin)
        if hit:
            findings_list.append(hit)
    findings_list.sort(key=lambda f: 0 if f["severity"] == "critical" else 1)

    write_json(json_out, {"findings": findings_list, "probed": len(rows),
                          "test_origin": test_origin})

    if findings_list:
        crit = sum(1 for f in findings_list if f["severity"] == "critical")
        print(console.phase_info_line(
            f"[{stage}] {len(findings_list)} CORS misconfig(s) "
            f"({crit} critical: reflect + credentials)"))

    return make_result(
        stage, "success", input_path=alive_file, outputs=outputs,
        count=len(findings_list),
        extra={"hosts_capped": capped, "probed": len(rows)},
    )
