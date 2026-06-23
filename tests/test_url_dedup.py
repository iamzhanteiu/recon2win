"""Test 1 — URL deduplication.

We exercise both:
  * `dedupe_urls()` — order-preserving, exact-match dedupe
  * `normalize_url()` — case, tracking-param, fragment, default-port handling
"""
from modules.url_merge import dedupe_urls, normalize_url


def test_dedupe_exact_duplicates():
    urls = [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/a",  # exact dup
        "https://example.com/a",  # exact dup
    ]
    out = dedupe_urls(urls)
    assert out == [
        "https://example.com/a",
        "https://example.com/b",
    ]


def test_dedupe_preserves_first_seen():
    urls = [
        "https://example.com/a?utm_source=x",
        "https://example.com/a",  # different query — kept
        "https://example.com/b",
    ]
    out = dedupe_urls(urls)
    assert len(out) == 3
    assert out[0] == "https://example.com/a?utm_source=x"


def test_dedupe_strips_blanks():
    urls = ["", "  ", None, "https://example.com/x"]  # type: ignore[list-item]
    out = dedupe_urls(urls)  # type: ignore[arg-type]
    assert out == ["https://example.com/x"]


def test_dedupe_returns_empty_for_empty_input():
    assert dedupe_urls([]) == []
    assert dedupe_urls(["", "  "]) == []


def test_normalize_lowercases_scheme_and_host():
    out = normalize_url("HTTPS://EXAMPLE.COM/Path")
    assert out == "https://example.com/Path"


def test_normalize_strips_default_ports():
    assert normalize_url("https://example.com:443/a") == "https://example.com/a"
    assert normalize_url("http://example.com:80/a") == "http://example.com/a"
    # non-default ports are preserved
    assert normalize_url("https://example.com:8443/a") == "https://example.com:8443/a"


def test_normalize_drops_trailing_slash_but_keeps_root():
    assert normalize_url("https://example.com/") == "https://example.com/"
    assert normalize_url("https://example.com/a/") == "https://example.com/a"
    assert normalize_url("https://example.com/a/b/") == "https://example.com/a/b"


def test_normalize_strips_tracking_params():
    url = "https://example.com/page?id=1&utm_source=tw"
    assert normalize_url(url) == "https://example.com/page?id=1"


def test_normalize_strips_fragment_but_keeps_query():
    url = "https://example.com/page?id=1#section"
    assert normalize_url(url) == "https://example.com/page?id=1"


def test_normalize_dedupes_combined_with_dedupe_urls():
    urls = [
        "https://EXAMPLE.com/a?utm_source=x",
        "https://example.com/a",
        "https://example.com/a",
    ]
    normalised = [normalize_url(u) for u in dedupe_urls(urls)]
    # both inputs collapse to the same canonical form — dedupe_urls then collapses them
    final = dedupe_urls(normalised)
    assert final == ["https://example.com/a"]


def test_normalize_keeps_non_tracking_query_params():
    url = "https://example.com/search?q=hello&page=2"
    assert normalize_url(url) == "https://example.com/search?q=hello&page=2"
