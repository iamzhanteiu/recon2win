"""behavior — describe what a response *is*, not what it says it is.

Content discovery decides "does this path exist?" from the response, and
every naive answer to that is wrong on a real target:

* **status** alone — an edge that answers 403 to everything makes ``-mc 403``
  match the entire wordlist. Measured on discover.com: 44,248 of 44,442 ffuf
  hits were 403, 44,230 of them from 11 hosts.
* **length** alone — Akamai echoes the requested path into its block page, so
  one single response shows up as *50 distinct lengths* (374–383 bytes)
  across 4,082 requests. This is why ffuf's ``-ac`` could not fire even
  though it was enabled.
* **words / lines** — stable across exactly that noise: those same 4,082
  responses had ``words == 13`` without exception. This is the signal the
  pipeline used to throw away (``parse_report`` returned only status,
  length, url).
* **redirect target** — 300 paths that all 302 to ``/login`` are one
  behaviour, not 300 findings.

So a response is fingerprinted on the whole shape — status, content-type
family, where a redirect points, and the size measured in words/lines
rather than bytes. Two responses with the same fingerprint are the same
response no matter which path produced them.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

# Tools differ in what they report. ffuf gives words+lines; dirsearch gives
# only a byte size. UNKNOWN marks "this tool did not tell us".
UNKNOWN = -1


@dataclass(frozen=True)
class Behavior:
    """One response, described by shape rather than by path."""

    url: str = ""
    status: int = 0
    length: int = UNKNOWN
    words: int = UNKNOWN
    lines: int = UNKNOWN
    content_type: str = ""
    location: str = ""          # raw redirect target, "" when not a redirect

    @property
    def has_size_signal(self) -> bool:
        """True when the tool reported words/lines — the echo-proof size."""
        return self.words != UNKNOWN or self.lines != UNKNOWN


def content_family(content_type: str) -> str:
    """``"application/json; charset=utf-8"`` → ``"json"``.

    Only the family matters for grouping; the charset and vendor prefixes
    are noise that would split one behaviour into several.
    """
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if not ct:
        return ""
    sub = ct.split("/", 1)[-1]
    # application/vnd.api+json → json ; text/html → html
    if "+" in sub:
        sub = sub.split("+")[-1]
    return sub.strip()


def redirect_shape(location: str, request_url: str = "") -> str:
    """Where a redirect *goes*, normalised so identical destinations match.

    Returns ``""`` for a non-redirect. Otherwise one of:

    * ``"self"``          — points back at the requested path (trailing-slash
      canonicalisation; not evidence of anything)
    * ``"path:/login"``   — a fixed path on the same host. **The blanket
      case**: a login wall answering every URL redirects them all here.
    * ``"path:/:echo"``   — a client-side-router catch-all: destination path
      is empty (everything lives in the URL FRAGMENT, the SPA hash-routing
      convention) and the fragment contains the REQUESTED path verbatim, so
      it's a blanket redirect wearing a different fragment per request, not
      a distinct destination — see below.
    * ``"path:/:/login"`` — a fragment-only (hash) redirect to a FIXED route
      that does not echo the request — a real, distinguishable destination
      (``#/login`` vs ``#/dashboard`` are different behaviours, same as two
      different ``path:`` values would be).
    * ``"host:example.com"`` — off to another host entirely.

    The destination path is kept but its query string dropped: a redirect
    carrying ``?next=/the/path/you/asked/for`` would otherwise look unique
    per request, which is the same echo problem that defeats byte-length.

    The fragment gets the same treatment for the same reason, measured on a
    real target: ``account.acronis.com`` 302-redirects every unmatched word
    to ``/#/<word>&email=`` — a hash-router catch-all — so a NAIVE "just
    read the fragment too" fix would make ``/get_file`` and ``/getconfig``
    look like different destinations (each echoing its own request), which
    is worse than ignoring the fragment entirely: two nonexistent paths
    would fingerprint as two DIFFERENT behaviours instead of clustering as
    one blanket shape. Only a fragment that does NOT contain the requested
    path is treated as a genuine distinguishing destination.
    """
    loc = (location or "").strip()
    if not loc:
        return ""
    try:
        dest = urlsplit(loc)
    except ValueError:
        return "path:" + loc.split("?", 1)[0]

    req_host = req_path = ""
    if request_url:
        try:
            req = urlsplit(request_url)
            req_host, req_path = (req.hostname or "").lower(), req.path or "/"
        except ValueError:
            pass

    dest_host = (dest.hostname or "").lower()
    if dest_host and req_host and dest_host != req_host:
        return "host:" + dest_host

    path = dest.path or "/"

    frag_suffix = ""
    frag = (dest.fragment or "").split("?", 1)[0].split("&", 1)[0]
    if frag:
        req_stub = req_path.strip("/").lower()
        if req_stub and req_stub in frag.lower():
            frag_suffix = ":echo"
        else:
            frag_suffix = ":" + frag

    if req_path and path.rstrip("/") == req_path.rstrip("/") and not frag_suffix:
        return "self"
    return "path:" + path + frag_suffix


def fingerprint(b: Behavior, *, length_tolerance: int = 16) -> tuple:
    """The grouping key: same key ⇒ same response.

    Byte length is deliberately absent whenever ``words``/``lines`` are
    available, because a body that echoes the request path changes length on
    every request while its word count does not.

    When a tool reports only a byte size (dirsearch), length has to carry the
    load — so it enters the key *bucketed* by ``length_tolerance``, which
    absorbs a short echoed path. Bucketing can still split one behaviour
    across a bucket boundary; :func:`cluster` closes that gap.
    """
    head = (b.status, content_family(b.content_type),
            redirect_shape(b.location, b.url))
    if b.has_size_signal:
        return head + (b.words, b.lines)
    tol = max(1, length_tolerance)
    return head + ("len", b.length // tol if b.length >= 0 else UNKNOWN)


def cluster(
    behaviors: list[Behavior], *, length_tolerance: int = 16,
) -> dict[tuple, list[Behavior]]:
    """Group responses by :func:`fingerprint`, biggest group first.

    Length-bucketed keys (the dirsearch case) are merged with their
    neighbouring bucket, so a behaviour straddling a bucket edge — lengths
    374–383 with a 16-byte bucket land in both 23 and 24 — stays one group
    instead of looking like two unremarkable ones.
    """
    groups: dict[tuple, list[Behavior]] = {}
    for b in behaviors:
        groups.setdefault(fingerprint(b, length_tolerance=length_tolerance),
                          []).append(b)

    # Merge adjacent length buckets into the larger neighbour.
    merged: dict[tuple, list[Behavior]] = {}
    for key in sorted(groups, key=lambda k: -len(groups[k])):
        if len(key) >= 5 and key[3] == "len" and isinstance(key[4], int):
            target = next(
                (k for k in merged
                 if len(k) >= 5 and k[3] == "len" and isinstance(k[4], int)
                 and k[:3] == key[:3] and abs(k[4] - key[4]) <= 1),
                None,
            )
            if target is not None:
                merged[target].extend(groups[key])
                continue
        merged[key] = list(groups[key])
    return dict(sorted(merged.items(), key=lambda kv: -len(kv[1])))


@dataclass
class Verdict:
    """Result of screening one host's hits."""

    kept: list[Behavior]
    dropped: list[Behavior]
    clusters: list[str]      # human lines for the clusters that were dropped
    blanket: bool            # the host answered ~everything the same way

    @property
    def n_dropped(self) -> int:
        return len(self.dropped)


def screen(
    behaviors: list[Behavior],
    *,
    min_cluster: int = 25,
    min_share: float = 0.5,
    length_tolerance: int = 16,
) -> Verdict:
    """Drop hit clusters that are one response wearing many paths.

    A cluster is discarded when it is **both** large in absolute terms
    (``min_cluster``) and dominant for this host (``min_share``). Both
    conditions matter: a big cluster on a host with far more varied hits is
    a genuine repeated template (an error page, a paginated section) and is
    worth keeping, while a host whose every answer is identical has told us
    nothing regardless of how the count looks.

    Sized against the measured failure: 4,082 hits on ``mapi.discover.com``,
    100% of them one cluster. Sized against the good hosts too —
    ``app.discover.com`` produced 89 hits with no cluster near dominance,
    and must survive untouched.
    """
    total = len(behaviors)
    if not total:
        return Verdict([], [], [], False)

    groups = cluster(behaviors, length_tolerance=length_tolerance)
    kept: list[Behavior] = []
    dropped: list[Behavior] = []
    lines: list[str] = []
    for key, members in groups.items():
        n = len(members)
        if n >= min_cluster and n / total >= min_share:
            dropped.extend(members)
            lines.append(describe(key, n))
        else:
            kept.extend(members)

    # "Blanket" is about the host, not the cluster, and it means one specific
    # thing downstream: this host never answered a real question, so its
    # silence is not evidence of a clean target. That requires nothing to
    # have survived — a host like app.discover.com, where 84 of 89 hits were
    # one redirect-to-apex cluster but 5 were real, has told us those 5
    # things and must not be written off.
    blanket = bool(dropped) and not kept
    return Verdict(kept, dropped, lines, blanket)


def screen_by_host(
    behaviors: list[Behavior], **kw,
) -> tuple[list[Behavior], dict[str, Verdict]]:
    """:func:`screen` applied per host. Returns ``(kept, verdict_by_host)``.

    Screening the whole run as one pool would be wrong in both directions:
    one blanket host's thousands of identical answers would swamp every
    other host's genuine hits, and a template shared across several hosts
    could look dominant without any single host being useless.
    """
    by_host: dict[str, list[Behavior]] = {}
    for b in behaviors:
        try:
            host = (urlsplit(b.url).hostname or "").lower()
        except ValueError:
            host = ""
        by_host.setdefault(host, []).append(b)

    kept: list[Behavior] = []
    verdicts: dict[str, Verdict] = {}
    for host, hits in by_host.items():
        v = screen(hits, **kw)
        verdicts[host] = v
        kept.extend(v.kept)
    return kept, verdicts


def describe(key: tuple, n: int) -> str:
    """One human line for a cluster — used in stage logs and reports."""
    status, family, redirect = key[0], key[1], key[2]
    bits = [f"{n}× status {status}"]
    if family:
        bits.append(family)
    if redirect:
        bits.append(f"→ {redirect}")
    if len(key) >= 5 and key[3] != "len":
        bits.append(f"{key[3]}w/{key[4]}l")
    return " ".join(bits)
