from __future__ import annotations

import json
from pathlib import Path

from modules import buckets, layout


# ----------------------------------------------------------------------
# extract_bucket_refs — pure regex logic
# ----------------------------------------------------------------------
def test_extract_s3_virtual_hosted():
    refs = buckets.extract_bucket_refs([
        "https://my-app-uploads.s3.amazonaws.com/file.png\n"
        "https://other-bucket.s3.us-east-1.amazonaws.com/x\n"
    ])
    assert "my-app-uploads" in refs["s3"]
    assert "other-bucket" in refs["s3"]


def test_extract_s3_path_style_and_uri():
    refs = buckets.extract_bucket_refs([
        "see https://s3.amazonaws.com/legacy-bucket/key.txt and s3://cli-bucket/x\n"
    ])
    assert "legacy-bucket" in refs["s3"]
    assert "cli-bucket" in refs["s3"]


def test_extract_gcs_all_forms():
    refs = buckets.extract_bucket_refs([
        "https://my-gcs-bucket.storage.googleapis.com/x\n"
        "https://storage.googleapis.com/other-gcs/x\n"
        "gs://cli-gcs-bucket/x\n"
    ])
    assert "my-gcs-bucket" in refs["gcs"]
    assert "other-gcs" in refs["gcs"]
    assert "cli-gcs-bucket" in refs["gcs"]


def test_extract_azure_reference():
    refs = buckets.extract_bucket_refs([
        "https://myaccount.blob.core.windows.net/container/file\n"
    ])
    assert "myaccount" in refs["azure"]


def test_extract_finds_nothing_in_clean_corpus():
    refs = buckets.extract_bucket_refs(["https://example.com/about\n"])
    assert refs == {"s3": [], "gcs": [], "azure": []}


# ----------------------------------------------------------------------
# domain_token / generate_candidates
# ----------------------------------------------------------------------
def test_domain_token_strips_subdomain_and_tld():
    assert buckets.domain_token("example.com") == "example"
    assert buckets.domain_token("api.example.com") == "example"
    assert buckets.domain_token("example.co.uk") == "co"  # documented limitation: no PSL


def test_generate_candidates_includes_base_token_first():
    cands = buckets.generate_candidates("example.com", max_candidates=10)
    assert "example" in cands
    assert cands[0] == "example"  # no prefix, no suffix — the obvious guess


def test_generate_candidates_respects_cap():
    cands = buckets.generate_candidates("example.com", max_candidates=5)
    assert len(cands) == 5


def test_generate_candidates_empty_domain():
    assert buckets.generate_candidates("", max_candidates=10) == []


# ----------------------------------------------------------------------
# classify_hit — empirically verified against real S3/GCS responses
# (see module docstring / conversation for the live curl checks)
# ----------------------------------------------------------------------
def test_classify_public_listing():
    body = ("<?xml version='1.0'?><ListBucketResult "
            "xmlns='http://doc.s3.amazonaws.com/2006-03-01'>"
            "<Name>bucket</Name></ListBucketResult>")
    hit = buckets.classify_hit(200, body)
    assert hit == {"state": "public-listing", "severity": "critical"}


def test_classify_exists_private():
    body = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
    hit = buckets.classify_hit(403, body)
    assert hit == {"state": "exists-private", "severity": "info"}


def test_classify_not_found_is_not_a_finding():
    body = "<Error><Code>NoSuchBucket</Code></Error>"
    assert buckets.classify_hit(404, body) is None


def test_classify_bare_200_without_listing_marker_is_not_a_finding():
    """A 200 with a custom index page (static-website-hosted bucket) is not
    a listing — only the real XML marker counts."""
    assert buckets.classify_hit(200, "<html>Welcome</html>") is None


# ----------------------------------------------------------------------
# discover — config gating + end-to-end with a faked runner
# ----------------------------------------------------------------------
def test_discover_disabled_by_default(tmp_path: Path):
    res = buckets.discover(tmp_path, "example.com", cfg={}, resume=False, dry_run=False)
    assert res["status"] == "skipped"
    assert "opt-in" in res["error"]


def test_discover_skip_flag(tmp_path: Path):
    res = buckets.discover(tmp_path, "example.com", cfg={"buckets": {"enabled": True}},
                           resume=False, dry_run=False, skip=True)
    assert res["status"] == "skipped"
    assert "skip-buckets" in res["error"]


def test_discover_end_to_end_with_fake_httpx(tmp_path: Path, monkeypatch):
    (tmp_path / "processed").mkdir(parents=True, exist_ok=True)
    (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
    # a literal S3 reference already in the corpus — always probed
    layout.path(tmp_path, "all_urls.txt").write_text(
        "https://example-uploads.s3.amazonaws.com/x\n"
        "https://acct1.blob.core.windows.net/container/x\n"
    )

    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        in_file = Path(cmd[cmd.index("-l") + 1])
        urls = [u for u in in_file.read_text().splitlines() if u.strip()]
        rows = []
        for u in urls:
            if u == "https://example-uploads.s3.amazonaws.com/":
                rows.append({"url": u, "status_code": 200,
                            "body": "<ListBucketResult></ListBucketResult>"})
            else:
                rows.append({"url": u, "status_code": 404,
                            "body": "<Error><Code>NoSuchBucket</Code></Error>"})
        out.write_text("\n".join(json.dumps(r) for r in rows))
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 0.1}

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    cfg = {"buckets": {"enabled": True, "permutations": False}}
    res = buckets.discover(tmp_path, "example.com", cfg=cfg, resume=False, dry_run=False)

    assert res["status"] == "success"
    assert res["count"] == 1
    data = json.loads((tmp_path / "findings" / "buckets.json").read_text())
    assert data["findings"][0]["bucket"] == "example-uploads"
    assert data["findings"][0]["state"] == "public-listing"
    # Azure is recorded as a reference, never actively probed for listing
    assert data["azure_references"] == ["acct1"]
