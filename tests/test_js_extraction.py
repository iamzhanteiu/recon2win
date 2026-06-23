"""Test 2 — JS URL extraction.

`is_js_url()` is the single source of truth. It must:
  * accept http and https
  * accept query strings / fragments
  * accept paths with multiple dots
  * reject non-JS extensions and non-http schemes
"""
import pytest

from modules.url_merge import is_js_url


# ---- positive cases ----
@pytest.mark.parametrize("url", [
    "https://example.com/app.js",
    "http://example.com/app.js",
    "https://example.com/path/to/bundle.min.js",
    "https://example.com/static/js/main.abc123.js",
    "https://example.com/app.js?v=123",
    "https://example.com/app.js#section",
    "https://example.com/app.JS",          # case-insensitive
    "HTTPS://EXAMPLE.COM/app.js",
])
def test_is_js_url_accepts_js(url):
    assert is_js_url(url) is True


# ---- negative cases ----
@pytest.mark.parametrize("url", [
    "",
    "https://example.com/app.json",
    "https://example.com/app.css",
    "https://example.com/app.jsx",         # not strictly .js
    "https://example.com/",                # root
    "https://example.com",                 # no path
    "ftp://example.com/app.js",            # wrong scheme
    "javascript:alert(1)",
    "/app.js",                             # relative — not a full URL
    "example.com/app.js",                  # no scheme
])
def test_is_js_url_rejects_non_js(url):
    assert is_js_url(url) is False


def test_is_js_url_does_not_crash_on_garbage():
    # urlsplit is forgiving but we still want predictable behaviour
    assert is_js_url("\x00\x01") is False
    assert is_js_url("not a url at all") is False
