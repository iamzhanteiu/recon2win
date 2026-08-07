"""Tests for the behavioural screen — modules/behavior.py.

Sized against the measured discover.com failure: ffuf reported 44,442 hits,
44,230 of which were one Akamai block page repeated across 11 hosts. ffuf's
own ``-ac`` was enabled and could not see it, because the block page echoes
the requested path and so has a different byte length every time while its
word count never changes.
"""
from __future__ import annotations

import pytest

from modules import behavior
from modules.behavior import Behavior


def _block_page(host, path, *, length):
    """The shape that defeated -ac: constant words, varying length."""
    return Behavior(url=f"https://{host}{path}", status=403, length=length,
                    words=13, lines=11, content_type="text/html")


# ----------------------------------------------------------------------
# content_family / redirect_shape
# ----------------------------------------------------------------------
def test_content_family_strips_charset_and_vendor_prefix():
    assert behavior.content_family("application/json; charset=utf-8") == "json"
    assert behavior.content_family("application/vnd.api+json") == "json"
    assert behavior.content_family("text/html") == "html"
    assert behavior.content_family("") == ""


def test_redirect_shape_distinguishes_the_three_cases():
    req = "https://x.com/admin"
    assert behavior.redirect_shape("", req) == ""
    assert behavior.redirect_shape("https://x.com/admin/", req) == "self"
    assert behavior.redirect_shape("https://x.com/login", req) == "path:/login"
    assert behavior.redirect_shape("https://evil.net/a", req) == "host:evil.net"


def test_redirect_shape_ignores_the_echoed_query():
    # ?next=<the path you asked for> would otherwise make every redirect
    # unique — the same echo problem that defeats byte length.
    a = behavior.redirect_shape("https://x.com/login?next=/a", "https://x.com/a")
    b = behavior.redirect_shape("https://x.com/login?next=/b", "https://x.com/b")
    assert a == b == "path:/login"


def test_redirect_shape_collapses_hash_router_echo():
    # Measured on a real target: account.acronis.com 302-redirects every
    # unmatched word to /#/<word>&email= (client-side-router catch-all).
    # Every one of these must fingerprint identically so the blanket gets
    # recognised as ONE shape, not one per made-up word.
    a = behavior.redirect_shape(
        "https://x.com/#/get_file&email=", "https://x.com/get_file")
    b = behavior.redirect_shape(
        "https://x.com/#/getconfig&email=", "https://x.com/getconfig")
    c = behavior.redirect_shape(
        "https://x.com/#/get-file&email=", "https://x.com/get-file")
    assert a == b == c == "path:/:echo"


def test_redirect_shape_distinguishes_genuine_hash_routes():
    # A FIXED hash destination that does NOT echo the request is a real,
    # distinguishable behaviour — #/login and #/dashboard are not the same
    # thing just because both happen to omit a path.
    login = behavior.redirect_shape("https://x.com/#/login", "https://x.com/xyz123")
    dash = behavior.redirect_shape("https://x.com/#/dashboard", "https://x.com/xyz123")
    assert login == "path:/:/login"
    assert dash == "path:/:/dashboard"
    assert login != dash


# ----------------------------------------------------------------------
# fingerprint
# ----------------------------------------------------------------------
def test_length_is_ignored_when_words_are_available():
    # THE bug: 4,082 responses, 50 distinct lengths, one actual response.
    a = _block_page("h.com", "/a", length=374)
    b = _block_page("h.com", "/bbbbbbbbb", length=383)
    assert behavior.fingerprint(a) == behavior.fingerprint(b)


def test_length_carries_the_key_when_words_are_missing():
    # dirsearch reports no words/lines, so length has to do the work.
    a = Behavior(url="https://h.com/a", status=403, length=200)
    b = Behavior(url="https://h.com/b", status=403, length=204)
    c = Behavior(url="https://h.com/c", status=403, length=9000)
    assert behavior.fingerprint(a) == behavior.fingerprint(b)
    assert behavior.fingerprint(a) != behavior.fingerprint(c)


def test_different_status_never_shares_a_fingerprint():
    a = Behavior(url="https://h.com/a", status=200, length=100)
    b = Behavior(url="https://h.com/b", status=403, length=100)
    assert behavior.fingerprint(a) != behavior.fingerprint(b)


# ----------------------------------------------------------------------
# cluster
# ----------------------------------------------------------------------
def test_cluster_collapses_the_echoing_block_page():
    hits = [_block_page("h.com", f"/{'a' * i}", length=374 + i % 10)
            for i in range(200)]
    groups = behavior.cluster(hits)
    assert len(groups) == 1
    assert len(next(iter(groups.values()))) == 200


def test_cluster_merges_neighbouring_length_buckets():
    # Length-only hits straddling a bucket edge must stay one behaviour.
    hits = [Behavior(url=f"https://h.com/{i}", status=403, length=374 + i)
            for i in range(20)]
    groups = behavior.cluster(hits, length_tolerance=16)
    assert len(groups) == 1


# ----------------------------------------------------------------------
# screen — the decision
# ----------------------------------------------------------------------
def test_screen_drops_a_dominant_cluster():
    hits = [_block_page("h.com", f"/{i}", length=374 + i % 10) for i in range(100)]
    v = behavior.screen(hits)
    assert v.kept == []
    assert v.n_dropped == 100
    assert v.blanket is True


def test_screen_keeps_everything_when_hits_are_varied():
    # A host with genuinely different responses must survive untouched.
    hits = [Behavior(url=f"https://h.com/{i}", status=200, length=100 * i,
                     words=10 * i, lines=i) for i in range(1, 60)]
    v = behavior.screen(hits)
    assert v.n_dropped == 0
    assert v.blanket is False


def test_a_big_cluster_that_is_not_dominant_survives():
    # 30 identical error pages among 300 varied hits is a repeated template,
    # not a host that answers everything the same way.
    noise = [_block_page("h.com", f"/n{i}", length=374) for i in range(30)]
    real = [Behavior(url=f"https://h.com/r{i}", status=200, length=i,
                     words=i, lines=i) for i in range(300)]
    v = behavior.screen(noise + real)
    assert v.n_dropped == 0


def test_small_clusters_are_never_dropped_however_dominant():
    # Three identical hits on a host with only three hits is not evidence
    # of a blanket — it is a host with three hits.
    hits = [_block_page("h.com", f"/{i}", length=374) for i in range(3)]
    v = behavior.screen(hits)
    assert v.n_dropped == 0


def test_blanket_requires_nothing_to_have_survived():
    # app.discover.com: 84 of 89 hits were one redirect-to-apex cluster, but
    # 5 were real. It has told us those 5 things and must not be written off.
    noise = [Behavior(url=f"https://h.com/n{i}", status=307, length=0, words=1,
                      lines=1, location="https://apex.com/")
             for i in range(84)]
    real = [Behavior(url=f"https://h.com/r{i}", status=200, length=500 * i,
                     words=50 * i, lines=i) for i in range(1, 6)]
    v = behavior.screen(noise + real)
    assert v.n_dropped == 84
    assert len(v.kept) == 5
    assert v.blanket is False


def test_screen_of_nothing_is_not_a_blanket():
    v = behavior.screen([])
    assert (v.kept, v.dropped, v.blanket) == ([], [], False)


# ----------------------------------------------------------------------
# screen_by_host
# ----------------------------------------------------------------------
def test_hosts_are_screened_independently():
    # One blanket host must not drag a healthy host's hits down with it,
    # which is exactly what screening the whole pool at once would do.
    blocked = [_block_page("blocked.com", f"/{i}", length=374 + i % 10)
               for i in range(500)]
    healthy = [Behavior(url=f"https://ok.com/{i}", status=200, length=100 * i,
                        words=10 * i, lines=i) for i in range(1, 40)]
    kept, verdicts = behavior.screen_by_host(blocked + healthy)

    assert {b.url for b in kept} == {b.url for b in healthy}
    assert verdicts["blocked.com"].blanket is True
    assert verdicts["ok.com"].blanket is False


@pytest.mark.parametrize("status", [200, 403, 302])
def test_any_status_can_be_the_blanket(status):
    # It is never about which code — a 200 SPA catch-all is the same
    # problem as a 403 edge deny.
    hits = [Behavior(url=f"https://h.com/{i}", status=status, length=500,
                     words=42, lines=7) for i in range(80)]
    assert behavior.screen(hits).blanket is True
