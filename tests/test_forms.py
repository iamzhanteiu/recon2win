"""Tests for katana form-extraction → forms.json and its priority scoring.

_extract_katana_jsonl splits katana -jsonl -fx output into a plain URL list
(backward-compat) + forms.json. priority.score_targets then ranks form
endpoints (POST/upload/login surface arjun's GET-param scan misses).
"""
from __future__ import annotations

import json
from pathlib import Path

from modules.content_discovery import _extract_katana_jsonl
from modules import priority
from modules.utils import read_lines


def _jsonl(path: Path, rows: list[dict]):
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def test_extract_splits_urls_and_forms(tmp_path):
    src = tmp_path / "katana.jsonl"
    _jsonl(src, [
        {"request": {"method": "GET", "endpoint": "https://x.com/"},
         "response": {"status_code": 200, "forms": [
             {"method": "POST", "action": "https://x.com/login",
              "enctype": "application/x-www-form-urlencoded",
              "parameters": ["user", "pass"]},
         ]}},
        {"request": {"method": "GET", "endpoint": "https://x.com/page2"},
         "response": {"status_code": 200}},   # no forms
    ])
    n_u, n_f = _extract_katana_jsonl(src, tmp_path / "urls.txt", tmp_path / "forms.json")

    assert n_u == 2
    assert read_lines(tmp_path / "urls.txt") == ["https://x.com/", "https://x.com/page2"]
    assert n_f == 1
    forms = json.loads((tmp_path / "forms.json").read_text())
    f = forms["forms"][0]
    assert f["action"] == "https://x.com/login"
    assert f["method"] == "POST"
    assert f["parameters"] == ["user", "pass"]


def test_extract_dedups_identical_forms(tmp_path):
    """The same form on two crawled pages collapses to one entry."""
    src = tmp_path / "katana.jsonl"
    form = {"method": "GET", "action": "https://x.com/search",
            "enctype": "", "parameters": ["q"]}
    _jsonl(src, [
        {"request": {"endpoint": "https://x.com/a"}, "response": {"forms": [form]}},
        {"request": {"endpoint": "https://x.com/b"}, "response": {"forms": [form]}},
    ])
    _, n_f = _extract_katana_jsonl(src, tmp_path / "u.txt", tmp_path / "f.json")
    assert n_f == 1


def test_extract_survives_malformed_lines(tmp_path):
    src = tmp_path / "katana.jsonl"
    src.write_text('not json\n{"request":{"endpoint":"https://x.com/ok"}}\n\n')
    n_u, n_f = _extract_katana_jsonl(src, tmp_path / "u.txt", tmp_path / "f.json")
    assert n_u == 1 and n_f == 0


# ----------------------------------------------------------------------
# priority scoring of forms
# ----------------------------------------------------------------------
def test_upload_form_outranks_plain_form():
    targets = priority.score_targets(forms=[
        {"action": "https://x.com/upload", "method": "POST",
         "enctype": "multipart/form-data", "parameters": ["file"]},
        {"action": "https://x.com/newsletter", "method": "POST",
         "enctype": "application/x-www-form-urlencoded", "parameters": ["email"]},
    ])
    by_url = {t["url"]: t for t in targets}
    assert by_url["https://x.com/upload"]["score"] > by_url["https://x.com/newsletter"]["score"]
    assert any("upload" in r for r in by_url["https://x.com/upload"]["reasons"])


def test_login_form_flagged_and_scored():
    targets = priority.score_targets(forms=[
        {"action": "https://x.com/login", "method": "POST",
         "enctype": "application/x-www-form-urlencoded",
         "parameters": ["username", "password", "csrf"]},
    ])
    t = targets[0]
    assert t["url"] == "https://x.com/login"
    reasons = " ".join(t["reasons"])
    assert "login" in reasons and "csrf" in reasons and "POST" in reasons


def test_form_score_accumulates_with_other_signals():
    """A form action that's also a parameterized URL stacks both scores."""
    url = "https://x.com/search?q=1"
    targets = priority.score_targets(
        forms=[{"action": url, "method": "GET", "parameters": ["q"]}],
        parameterized_urls=[url],
    )
    t = next(x for x in targets if x["url"] == url)
    # form base (320) + param (300) → well above either alone
    assert t["score"] >= 600
