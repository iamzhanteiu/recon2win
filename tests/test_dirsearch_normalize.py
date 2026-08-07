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
    # Bare-arrow spelling (some builds / our own convenience form).
    raw = ["301  0B  https://example.com/admin/ -> https://example.com/admin/index.php"]
    out = normalize_output(raw)
    # we only keep the original (first) URL, not the redirect target
    assert out == ["https://example.com/admin/"]


def test_normalize_handles_real_dirsearch_redirect_format():
    # dirsearch's actual ``plain`` report (lib/reports/plain_text_report.py)
    # writes the redirect as "    -> REDIRECTS TO: <url>". This MUST be
    # parsed to the source URL — previously it was silently dropped
    # (LINE_RE only knew the bare "-> <url>" arrow).
    raw = [
        "301   0B     https://example.com/admin    -> REDIRECTS TO: https://example.com/admin/",
        "302   0B     https://example.com/old       -> REDIRECTS TO: https://example.com/new",
    ]
    out = normalize_output(raw)
    assert out == [
        "https://example.com/admin",
        "https://example.com/old",
    ]


# ----------------------------------------------------------------------
# parse_hits / parse_size — the behavioural columns normalize_output drops
# ----------------------------------------------------------------------
def test_parse_size_handles_the_units_dirsearch_prints():
    from modules.dirsearch import parse_size
    from modules.behavior import UNKNOWN

    assert parse_size("198B") == 198
    assert parse_size("10KB") == 10240
    assert parse_size("1.5KB") == 1536
    assert parse_size("2MB") == 2 * 1024 ** 2
    assert parse_size("0B") == 0
    assert parse_size("weird") == UNKNOWN


def test_parse_hits_keeps_status_size_and_redirect_target():
    from modules.dirsearch import parse_hits

    hits = parse_hits([
        "200   198B   https://x.com/robots.txt",
        "302   0B     https://x.com/admin    -> REDIRECTS TO: https://x.com/login",
    ])
    assert [(h.status, h.length) for h in hits] == [(200, 198), (302, 0)]
    assert hits[0].location == ""
    assert hits[1].location == "https://x.com/login"


def test_parse_hits_ignores_banner_and_blank_lines():
    from modules.dirsearch import parse_hits

    assert parse_hits(["# Dirsearch started ...", "", "not a hit"]) == []


def test_screen_collapses_a_host_that_403s_every_path():
    # qa.ops.src.apis.discover.com on the real run: 230 hits, every one of
    # them the same {"message":"Forbidden"} — including the .bak paths that
    # looked like findings.
    from modules import behavior
    from modules.dirsearch import parse_hits

    lines = [f"403   23B   https://qa.x.com/{name}"
             for name in [f"p{i}.bak" for i in range(230)]]
    kept, verdicts = behavior.screen_by_host(parse_hits(lines))
    assert kept == []
    assert verdicts["qa.x.com"].blanket is True
