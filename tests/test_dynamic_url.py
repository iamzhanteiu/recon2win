"""Test 3 — dynamic URL filtering.

`is_dynamic_url()` returns True unless the path clearly ends with a
static-asset extension (per the spec: .png .jpg .jpeg .gif .svg .css
.woff .woff2 .ico .mp4 .mp3).

True → keep in processed/dynamic_urls.txt
False → exclude (static asset)
"""
import pytest

from modules.url_merge import is_dynamic_url


# ---- dynamic URLs that should be kept ----
@pytest.mark.parametrize("url", [
    "https://example.com/api/users",
    "https://example.com/api/users?id=1",
    "https://example.com/",
    "https://example.com/login",
    "https://example.com/admin/dashboard?tab=users",
    "https://example.com/page.html",
    "https://example.com/page.php",
    "https://example.com/data.json",
    "https://example.com/path?ref=foo",
    "https://example.com",
])
def test_is_dynamic_url_keeps_dynamic(url):
    assert is_dynamic_url(url) is True


# ---- static assets that should be excluded ----
@pytest.mark.parametrize("url", [
    "https://example.com/img/logo.png",
    "https://example.com/img/photo.JPG",          # case-insensitive
    "https://example.com/img/photo.jpeg",
    "https://example.com/img/anim.gif",
    "https://example.com/img/icon.svg",
    "https://example.com/static/style.css",
    "https://example.com/fonts/arial.woff",
    "https://example.com/fonts/arial.woff2",
    "https://example.com/favicon.ico",
    "https://example.com/videos/intro.mp4",
    "https://example.com/audio/track.mp3",
    "https://cdn.example.com/a/b/c.png?v=1",     # static with query string
])
def test_is_dynamic_url_rejects_static(url):
    assert is_dynamic_url(url) is False


def test_is_dynamic_url_rejects_empty():
    assert is_dynamic_url("") is False
    assert is_dynamic_url(None) is False  # type: ignore[arg-type]


def test_is_dynamic_url_path_only_static_extension():
    # path ends in .png, even if there is a query string, the URL is static
    assert is_dynamic_url("https://example.com/pic.png?w=100") is False
    # but a static extension in a folder component is fine — the path
    # doesn't *end* with it
    assert is_dynamic_url("https://example.com/png/about") is True
