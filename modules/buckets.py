"""buckets — cloud storage bucket enumeration (S3 / GCS), off by default.

Two candidate sources:
  1. **Extracted** — literal ``*.s3.amazonaws.com`` / ``s3://…`` /
     ``storage.googleapis.com/…`` / ``gs://…`` references already sitting in
     the JS/URL corpus (jsluice, xnLinkFinder, the crawler). These are
     observed, not guessed, and are always probed regardless of config —
     a bucket name the target's own JS already reveals isn't "guessing".
  2. **Permutation** — ``<domain-token>`` crossed with common suffixes
     (``-prod``, ``-backup``, ``-assets``, …), the standard technique every
     bucket-finder tool uses. Gated by ``buckets.permutations`` since this
     is the "guessing" half and sends requests for names that may not exist.

Azure Blob references are extracted and recorded (still useful — it tells
you the target uses Azure storage) but NOT probed for public listing: doing
that properly needs a container name, not just the account host, and
guessing container names is a whole second permutation dimension this pass
doesn't take on. Recorded honestly as "reference only", not silently
dropped.

A hit only counts as PUBLIC when the response body actually parses as an
S3/GCS bucket-listing XML document (``<ListBucketResult>``) — a bare 200 is
not a listing (plenty of buckets 200 a custom error page), same precision
bar ``apidocs.parse_spec`` holds OpenAPI specs to.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from . import console, layout, runner
from .utils import load_json, make_result, raw_dir, write_json, write_lines

# ----------------------------------------------------------------------
# Extraction — bucket/container names already observed in the corpus.
# ----------------------------------------------------------------------
_S3_HOST_RE = re.compile(
    r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com",
    re.IGNORECASE)
_S3_PATH_RE = re.compile(
    r"s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])",
    re.IGNORECASE)
_S3_URI_RE = re.compile(r"s3://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])", re.IGNORECASE)

_GCS_HOST_RE = re.compile(
    r"([a-z0-9][a-z0-9_\-.]{1,61}[a-z0-9])\.storage\.googleapis\.com",
    re.IGNORECASE)
_GCS_PATH_RE = re.compile(
    r"storage\.googleapis\.com/([a-z0-9][a-z0-9_\-.]{1,61}[a-z0-9])",
    re.IGNORECASE)
_GCS_URI_RE = re.compile(r"gs://([a-z0-9][a-z0-9_\-.]{1,61}[a-z0-9])", re.IGNORECASE)

_AZURE_RE = re.compile(r"([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.IGNORECASE)


def extract_bucket_refs(texts: list[str]) -> dict[str, list[str]]:
    """Pull S3/GCS/Azure bucket names out of already-collected URL text.

    ``texts`` is the raw content of the corpus files (join lines yourself),
    not a URL list — regexes run over the whole blob so path-style and
    ``s3://``/``gs://`` URIs match too, not just one URL per line.
    """
    blob = "\n".join(texts)
    s3 = {m.group(1).lower() for m in _S3_HOST_RE.finditer(blob)}
    s3 |= {m.group(1).lower() for m in _S3_PATH_RE.finditer(blob)}
    s3 |= {m.group(1).lower() for m in _S3_URI_RE.finditer(blob)}
    gcs = {m.group(1).lower() for m in _GCS_HOST_RE.finditer(blob)}
    gcs |= {m.group(1).lower() for m in _GCS_PATH_RE.finditer(blob)}
    gcs |= {m.group(1).lower() for m in _GCS_URI_RE.finditer(blob)}
    azure = {m.group(1).lower() for m in _AZURE_RE.finditer(blob)}
    return {"s3": sorted(s3), "gcs": sorted(gcs), "azure": sorted(azure)}


# ----------------------------------------------------------------------
# Permutation — the standard bucket-finder wordlist technique.
# ----------------------------------------------------------------------
_SUFFIXES = (
    "", "-prod", "-production", "-dev", "-development", "-staging", "-stage",
    "-test", "-testing", "-qa", "-backup", "-backups", "-assets", "-static",
    "-media", "-uploads", "-upload", "-data", "-logs", "-log", "-config",
    "-secrets", "-files", "-cdn", "-public", "-private", "-internal", "-web",
    "-app", "-api", "-images", "-img", "-content", "-storage", "-archive",
)
_PREFIXES = ("", "www-", "cdn-", "assets-", "static-")


def domain_token(domain: str) -> str:
    """``sub.example.com`` -> ``example`` — the registrable-domain label,
    which is what real bucket names get built from far more often than the
    full FQDN or the apex including its TLD."""
    labels = [lbl for lbl in (domain or "").lower().split(".") if lbl]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else ""


def generate_candidates(domain: str, max_candidates: int) -> list[str]:
    token = domain_token(domain)
    if not token:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for suf in _SUFFIXES:
        for pre in _PREFIXES:
            name = f"{pre}{token}{suf}"
            if name not in seen:
                seen.add(name)
                out.append(name)
            if max_candidates and len(out) >= max_candidates:
                return out
    return out


# ----------------------------------------------------------------------
# Probing — one GET per (bucket, provider), classified by body signature.
# ----------------------------------------------------------------------
_PROVIDER_URL = {
    "s3": "https://{bucket}.s3.amazonaws.com/",
    "gcs": "https://storage.googleapis.com/{bucket}/",
}


def classify_hit(status: Optional[int], body: str) -> Optional[dict]:
    """S3 and GCS's XML API share the same bucket-listing/error shape, so
    one classifier covers both. ``None`` means "not a finding" — anything
    that isn't unambiguously a listing or an access-denied-on-a-real-bucket
    is left alone rather than guessed at.
    """
    b = (body or "").lower()
    if status == 200 and "<listbucketresult" in b:
        return {"state": "public-listing", "severity": "critical"}
    if status == 403 and "accessdenied" in b:
        return {"state": "exists-private", "severity": "info"}
    return None


def _probe(candidates: list[tuple[str, str, str]], output_dir: Path,
          b_cfg: dict) -> list[dict]:
    """``candidates`` is ``[(url, bucket, provider), …]``. Returns httpx rows."""
    if not candidates:
        return []
    raw = raw_dir(output_dir, "buckets")
    in_file = raw / "candidates.txt"
    out_file = raw / "probe.jsonl"
    write_lines(in_file, [c[0] for c in candidates])
    if out_file.exists():
        out_file.unlink()

    cmd = [
        "httpx", "-l", str(in_file),
        "-json", "-silent", "-irr", "-duc",
        "-threads", str(int(b_cfg.get("threads", 20))),
        "-timeout", str(int(b_cfg.get("http_timeout", 10))),
        "-retries", "1",
        "-o", str(out_file),
    ]
    runner.run(cmd, stage="buckets", output_dir=output_dir,
              timeout=int(b_cfg.get("timeout", 900)))

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


def _outputs_exist(json_out: Path) -> bool:
    return json_out.exists() and json_out.stat().st_size > 0


def discover(
    output_dir: Path,
    domain: str,
    cfg: dict,
    *,
    resume: bool = False,
    dry_run: bool = False,
    skip: bool = False,
) -> dict:
    stage = "buckets"
    layout.ensure_tree(output_dir)
    findings = output_dir / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    json_out = findings / "buckets.json"
    outputs = [json_out]

    b_cfg = (cfg.get("buckets") or {}) if isinstance(cfg, dict) else {}

    if skip:
        write_json(json_out, {"findings": [], "azure_references": []})
        return make_result(stage, "skipped", outputs=outputs, count=0,
                           error="--skip-buckets")
    if not b_cfg.get("enabled", False):
        write_json(json_out, {"findings": [], "azure_references": []})
        return make_result(stage, "skipped", outputs=outputs, count=0,
                           error="disabled in config (opt-in: buckets.enabled)")
    if resume and _outputs_exist(json_out):
        existing = load_json(json_out) or {}
        f = existing.get("findings", []) if isinstance(existing, dict) else []
        return make_result(stage, "success", outputs=outputs, count=len(f))
    if dry_run:
        return make_result(stage, "skipped", outputs=outputs, count=0, error="dry-run")
    if not runner.tool_available("httpx"):
        return make_result(stage, "skipped", outputs=outputs, count=0,
                           error="httpx binary not found")

    # ---- extraction (always runs — these names are observed, not guessed) ----
    corpus_files = ("all_urls.txt", "js_urls.txt", "jsluice_urls.txt",
                    "jsluice_endpoints.txt", "xnlinkfinder_urls.txt")
    texts = []
    for fname in corpus_files:
        p = layout.path(output_dir, fname)
        if p.exists():
            texts.append(p.read_text(errors="ignore"))
    refs = extract_bucket_refs(texts)

    # ---- permutation (opt-in second layer) ----
    guessed: list[str] = []
    if b_cfg.get("permutations", True):
        max_candidates = int(b_cfg.get("max_candidates", 200) or 0)
        guessed = generate_candidates(domain, max_candidates)

    # ---- build (url, bucket, provider) work list, S3+GCS only ----
    names = sorted(set(refs["s3"]) | set(refs["gcs"]) | set(guessed))
    candidates: list[tuple[str, str, str]] = []
    seen_urls: set[str] = set()
    for name in names:
        for provider, tmpl in _PROVIDER_URL.items():
            url = tmpl.format(bucket=name)
            if url not in seen_urls:
                seen_urls.add(url)
                candidates.append((url, name, provider))

    rows = _probe(candidates, output_dir, b_cfg)
    by_url = {r.get("url"): r for r in rows if isinstance(r, dict)}

    findings_list: list[dict] = []
    for url, bucket, provider in candidates:
        row = by_url.get(url)
        if not row:
            continue
        hit = classify_hit(row.get("status_code"), row.get("body") or "")
        if hit:
            findings_list.append({
                "bucket": bucket, "provider": provider, "url": url,
                **hit,
            })
    findings_list.sort(key=lambda f: 0 if f["severity"] == "critical" else 1)

    write_json(json_out, {
        "findings": findings_list,
        "azure_references": refs["azure"],
        "extracted": {"s3": refs["s3"], "gcs": refs["gcs"]},
        "guessed_count": len(guessed),
        "probed": len(candidates),
    })

    if findings_list:
        public = sum(1 for f in findings_list if f["state"] == "public-listing")
        print(console.phase_info_line(
            f"[{stage}] {len(findings_list)} bucket hit(s) — "
            f"{public} publicly listable"))
    if refs["azure"]:
        print(console.phase_info_line(
            f"[{stage}] {len(refs['azure'])} Azure Blob reference(s) found "
            "(recorded, not probed — needs a container name to check listing)"))

    return make_result(
        stage, "success", outputs=outputs, count=len(findings_list),
        extra={"probed": len(candidates), "guessed": len(guessed),
               "extracted_s3": len(refs["s3"]), "extracted_gcs": len(refs["gcs"]),
               "azure_references": len(refs["azure"])},
    )
