"""Test 4 — dirsearch output normalization.

`normalize_output()` reduces the noisy dirsearch stdout to clean
URL-only lines. The output format must be:
    https://domain.com/endpoint
regardless of which status / size / colour codes dirsearch prints.
"""
from modules.dirsearch import normalize_output


def test_normalize_typical_dirsearch_lines():
    raw = [
        "  _|.'_ _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _|",
        "",
        "  _|. _ _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _  _|",
        "",
        "Target: https://example.com",
        "",
        "200   123B   https://example.com/.env",
        "200   45KB   https://example.com/.git/config",
        "301   0B     https://example.com/admin -> https://example.com/admin/",
        "403   210B   https://example.com/.htaccess",
        "500   9001B  https://example.com/.svn/entries",
    ]
    out = normalize_output(raw)
    assert out == [
        "https://example.com/.env",
        "https://example.com/.git/config",
        "https://example.com/admin",
        "https://example.com/.htaccess",
        "https://example.com/.svn/entries",
    ]


def test_normalize_handles_url_only_lines():
    raw = [
        "https://example.com/wp-config.php.bak",
        "https://example.com/.env",
    ]
    out = normalize_output(raw)
    assert out == [
        "https://example.com/wp-config.php.bak",
        "https://example.com/.env",
    ]


def test_normalize_dedupes():
    raw = [
        "200  10B  https://example.com/.env",
        "200  10B  https://example.com/.env",
        "200  10B  https://example.com/.git/config",
    ]
    out = normalize_output(raw)
    assert out == [
        "https://example.com/.env",
        "https://example.com/.git/config",
    ]


def test_normalize_skips_blank_and_garbage_lines():
    raw = [
        "",
        "   ",
        "Target: https://example.com",
        "[*] Starting dirsearch",
        "200  10B  https://example.com/.env",
        "Errors: 0",
    ]
    out = normalize_output(raw)
    assert out == ["https://example.com/.env"]


def test_normalize_returns_empty_for_empty_input():
    assert normalize_output([]) == []


def test_normalize_handles_redirect_marker():
    # Some dirsearch versions print "URL -> REDIRECT" with an arrow
    raw = ["301  0B  https://example.com/admin/ -> https://example.com/admin/index.php"]
    out = normalize_output(raw)
    # we only keep the original (first) URL, not the redirect target
    assert out == ["https://example.com/admin/"]
