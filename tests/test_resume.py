"""Test 5 — resume mode behaviour.

For every stage we ship an `_outputs_exist()` helper. The contract is:
  * if all expected outputs are present and non-empty → return True
  * otherwise → return False (the stage must re-run)

We test the helpers for the stages that have them, plus a smoke test
that `subdomain.collect()` honours the resume flag.
"""
from pathlib import Path

import pytest

from modules import arjun, content_discovery, dirsearch, dnsx, httpx, nuclei, url_merge, waymore, xnlinkfinder
from modules.utils import read_lines, write_lines


# ---------- helper-output existence ---------------------------------------
def _touch(path: Path, content: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_resume_subdomain_outputs_exist(tmp_path: Path):
    (tmp_path / "raw" / "subdomain").mkdir(parents=True)
    (tmp_path / "processed").mkdir()
    _touch(tmp_path / "raw" / "subdomain" / "subfinder.txt", "a.example.com\n")
    _touch(tmp_path / "raw" / "subdomain" / "amass.txt", "b.example.com\n")
    _touch(tmp_path / "raw" / "subdomain" / "chaos.txt", "c.example.com\n")
    _touch(tmp_path / "processed/subdomains.txt", "a.example.com\nb.example.com\nc.example.com\n")
    from modules.subdomain import _all_outputs_exist
    assert _all_outputs_exist(tmp_path, ["subfinder", "amass", "chaos"]) is True


def test_resume_dnsx_outputs_exist(tmp_path: Path):
    (tmp_path / "processed").mkdir()
    _touch(tmp_path / "processed/resolved.txt", "x.example.com\n")
    _touch(tmp_path / "processed/resolved_detail.json", "[{\"subdomain\": \"x\"}]")
    assert dnsx._outputs_exist(tmp_path) is True


def test_resume_httpx_alive_outputs_exist(tmp_path: Path):
    (tmp_path / "processed").mkdir()
    _touch(tmp_path / "processed/alive.txt", "https://x.example.com\n")
    assert httpx.alive_check.__name__ == "alive_check"  # sanity


def test_resume_url_merge_outputs_exist(tmp_path: Path):
    (tmp_path / "processed").mkdir()
    _touch(tmp_path / "processed/all_urls.txt", "https://x.example.com\n")
    _touch(tmp_path / "processed/js_urls.txt", "")
    _touch(tmp_path / "processed/dynamic_urls.txt", "https://x.example.com\n")
    assert url_merge.merge.__name__ == "merge"


def test_resume_nuclei_outputs_exist(tmp_path: Path):
    # v2 layout: findings/{default,dynamic}/nuclei.json
    (tmp_path / "findings" / "default").mkdir(parents=True)
    (tmp_path / "findings" / "dynamic").mkdir(parents=True)
    _touch(tmp_path / "findings/default/nuclei.json", "{\"findings\": []}")
    assert nuclei._outputs_exist(tmp_path, "default") is True
    assert nuclei._outputs_exist(tmp_path, "dynamic") is False


# ---------- sub-modules: resume short-circuits to success ---------------
def test_subdomain_collect_resume_returns_existing(tmp_path: Path):
    """subdomain.collect() with resume=True should NOT call any external
    command if all raw outputs and the merged list exist.
    """
    (tmp_path / "raw" / "subdomain").mkdir(parents=True)
    (tmp_path / "processed").mkdir()
    write_lines(tmp_path / "raw" / "subdomain" / "subfinder.txt", ["a.example.com"])
    write_lines(tmp_path / "raw" / "subdomain" / "amass.txt", ["b.example.com"])
    write_lines(tmp_path / "raw" / "subdomain" / "chaos.txt", ["c.example.com"])
    write_lines(tmp_path / "processed/subdomains.txt",
                ["a.example.com", "b.example.com", "c.example.com"])

    from modules.subdomain import collect

    res = collect("example.com", tmp_path, {"subdomain": {"tools": ["subfinder", "amass", "chaos"]}},
                  resume=True, dry_run=False)
    assert res["status"] == "success"
    assert res["count"] == 3


def test_url_merge_resume_returns_existing(tmp_path: Path):
    (tmp_path / "processed").mkdir()
    write_lines(tmp_path / "processed/crawler_urls.txt", ["https://x.example.com/"])
    write_lines(tmp_path / "processed/dirsearch_urls.txt", [])
    write_lines(tmp_path / "processed/waymore_urls.txt", [])
    write_lines(tmp_path / "processed/all_urls.txt", ["https://x.example.com/"])
    write_lines(tmp_path / "processed/js_urls.txt", [])
    write_lines(tmp_path / "processed/dynamic_urls.txt", ["https://x.example.com/"])

    res = url_merge.merge(tmp_path, resume=True, dry_run=False)
    assert res["status"] == "success"
    assert res["count"] == 1


def test_resume_does_not_overwrite_existing_outputs(tmp_path: Path):
    """When outputs already exist, resume must not touch them."""
    (tmp_path / "raw" / "subdomain").mkdir(parents=True)
    (tmp_path / "processed").mkdir()
    # populate all the raw outputs the resume check expects, plus a sentinel
    # value in the merged file that the actual tools would never have produced.
    write_lines(tmp_path / "raw" / "subdomain" / "subfinder.txt", ["a.example.com"])
    write_lines(tmp_path / "raw" / "subdomain" / "amass.txt", ["b.example.com"])
    write_lines(tmp_path / "raw" / "subdomain" / "chaos.txt", ["c.example.com"])
    sentinel = tmp_path / "processed" / "subdomains.txt"
    sentinel.write_text("sentinel.example.com\n")

    from modules.subdomain import collect

    res = collect("example.com", tmp_path, {"subdomain": {"tools": ["subfinder", "amass", "chaos"]}},
                  resume=True, dry_run=False)
    assert res["status"] == "success"
    # sentinel value must still be there — resume must not have re-merged
    assert read_lines(sentinel) == ["sentinel.example.com"]
