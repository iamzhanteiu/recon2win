#!/usr/bin/env python3
"""Gộp tín hiệu "có thể là bug thật" của một run recon2win thành một view nén.

    python3 .claude/skills/bug-hunter/collect.py outputs/<domain>

Vì sao cần: ``findings/*/nuclei.json`` mang theo ``request``/``response``/
``curl-command`` đầy đủ cho mỗi finding — hữu ích để verify một finding cụ
thể (xem SKILL.md Phase 2), nhưng đọc thẳng cả file để có bức tranh tổng
quan là lãng phí token nặng (mỗi finding có thể vài KB request/response).
Script này chỉ giữ lại phần đủ để quyết định finding nào đáng verify trước:
``severity``, ``name``, ``host``, ``matched-at``, ``template-id``, ``tags``.

Số file/profile nuclei thay đổi theo config (``nuclei_default`` hiện tại,
từng có thêm ``nuclei_endpoints``/``nuclei_dynamic``) nên dùng glob thay vì
tên cố định.

Gộp thêm ``report/priority_targets.txt`` (top N, đã nhỏ sẵn) và
``findings/jsluice_secrets.json`` (chỉ khi không rỗng) để một lệnh là có đủ
input cho Phase 1 của SKILL.md — không cần tự mở từng file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get((sev or "unknown").lower(), 5)


def collect_nuclei(root: Path) -> list[dict]:
    findings: list[dict] = []
    for f in sorted(root.glob("findings/*/nuclei.json")):
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        profile = f.parent.name
        for item in data.get("findings", []):
            info = item.get("info") or {}
            findings.append(
                {
                    "profile": profile,
                    "severity": info.get("severity", "unknown"),
                    "name": info.get("name", ""),
                    "template-id": item.get("template-id", ""),
                    "host": item.get("host", ""),
                    "matched-at": item.get("matched-at", ""),
                    "tags": info.get("tags", []),
                }
            )
    findings.sort(key=lambda x: (_sev_rank(x["severity"]), x["host"]))
    return findings


def find_file(root: Path, name: str) -> Path | None:
    hits = list(root.glob(f"processed/**/{name}"))
    return hits[0] if hits else None


def collect_priority(root: Path, top: int = 30) -> list[str]:
    p = root / "report" / "priority_targets.txt"
    if not p.exists():
        return []
    lines = [ln.rstrip("\n") for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    return lines[:top]


def collect_secrets(root: Path) -> list[dict]:
    p = root / "findings" / "jsluice_secrets.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return data.get("findings", [])


def collect_post_forms(root: Path) -> list[dict]:
    p = find_file(root, "forms.json")
    if p is None:
        return []
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    forms = data.get("forms", []) if isinstance(data, dict) else data
    return [
        {"action": f.get("action", ""), "parameters": f.get("parameters", [])}
        for f in forms
        if str(f.get("method", "")).upper() == "POST"
    ]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} outputs/<domain>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    if not root.is_dir():
        print(f"khong tim thay thu muc: {root}", file=sys.stderr)
        return 2

    nuclei = collect_nuclei(root)
    priority = collect_priority(root)
    secrets = collect_secrets(root)
    post_forms = collect_post_forms(root)

    print(f"=== nuclei findings ({len(nuclei)}, xep theo severity) ===")
    for f in nuclei:
        tags = ",".join(f["tags"])
        print(f"[{f['severity']:>8}] {f['host']:<35} {f['name']}  ({f['template-id']}; tags={tags})")
        print(f"           matched-at: {f['matched-at']}  profile={f['profile']}")

    print(f"\n=== priority_targets.txt (top {len(priority)}) ===")
    for ln in priority:
        print(ln)

    print(f"\n=== jsluice_secrets ({len(secrets)}) ===")
    for s in secrets:
        print(f"[{s.get('severity', '?')}] {s.get('kind', '?')}  {s.get('url', '?')}")

    print(f"\n=== POST forms ({len(post_forms)}) ===")
    for form in post_forms:
        params = ",".join(form["parameters"])
        print(f"POST {form['action']}  [{params}]")

    if not nuclei and not priority and not secrets and not post_forms:
        print("\n(khong co tin hieu nao — kiem tra run bang skill recon-health truoc)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
