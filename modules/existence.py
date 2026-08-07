"""existence — classify a fuzzed hit as a real route or noise, from
*behavior* rather than from HTTP status code alone.

Status code alone lies in both directions:

* A blanket edge/WAF answers ``403``/``400`` to every single word in the
  wordlist — the status says "exists" 40,000 times over on a host with one
  real route. ``modules/behavior.py`` already handles this at the CLUSTER
  level (drop the dominant repeated shape); this module handles it at the
  SINGLE-HIT level, by comparing the hit against this host's own measured
  not-found shape (``modules/baseline.py``) instead of a fixed status list.
* A JSON API answering ``404 {"error": "user not found"}`` for a *specific*
  resource ID is not evidence the ROUTE doesn't exist — the opposite: routing
  and business logic both ran, only fixture data was missing. A blank
  webserver-default 404 page proves nothing ran at all. Same status code,
  opposite meaning; only the body tells them apart.

So a hit is classified from three independent signals, combined:

1. **Baseline shape** (``baseline_is_noise``) — does this hit's response
   fingerprint (status + content-type + redirect target + words/lines, see
   ``behavior.fingerprint``) match what THIS host already returns for a path
   guaranteed not to exist? Reused straight from ``modules/baseline.py`` —
   no new requests, ``raw/baseline/probe_*.json*`` is already on disk from
   whichever content-discovery stage measured it.
2. **Body signals** (``SIGNAL_PATTERNS``) — keyword/phrase families that only
   show up once a request reached routing, parsing or business logic:
   validation errors, request-parsing errors, auth/authz errors, business-
   logic errors ("X not found" naming a RESOURCE, not a route), and
   framework-specific error shapes (Spring/ASP.NET/Laravel/Django/FastAPI/
   Express). Matched against the short body preview ``responses.py``
   already captures for every ffuf/dirsearch hit
   (``responses/preview.json``) — no full bodies read or stored.
3. **Status family** (``_STRONG_STATUS`` / ``_WEAK_STATUS``) — status codes
   that structurally imply the request passed routing before failing
   (``405/406/415/422`` — the server had to know the route to reject the
   METHOD or MEDIA TYPE) count as their own signal even with no body text,
   because ffuf/dirsearch report status even when ``responses.max_urls``
   capped a hit out of the body-preview run.

None of this needs new HTTP requests: baseline shapes and body previews are
both already written to disk by stages that ran earlier in the same scan.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

CONFIRMED = "confirmed"
LIKELY = "likely"
UNKNOWN = "unknown"
NOT_FOUND = "not_found"

# category -> compiled regex patterns, matched case-insensitively against the
# body preview. Deliberately phrase-level (not single words like "error") so
# a generic error page doesn't light up every category.
_RAW_PATTERNS: dict[str, list[str]] = {
    "validation": [
        r"missing required parameter", r"required field",
        r"validation failed", r"invalid uuid", r"invalid enum",
        r"field required", r"is a required", r"must not be (?:null|blank|empty)",
    ],
    "parsing": [
        r"missing request body", r"malformed json", r"cannot deserialize",
        r"unexpected field", r"unsupported media type", r"invalid json",
        r"json parse error", r"could not be parsed",
    ],
    "auth": [
        r"missing api key", r"missing authorization", r"invalid jwt",
        r"token expired", r"unauthoriz", r"access denied", r"invalid token",
        r"invalid credentials", r"authentication required",
    ],
    "business_logic": [
        r"user not found", r"resource not found", r"tenant not found",
        r"account not found", r"already exists", r"\bconflict\b",
        r"\bduplicate\b",
    ],
    "framework": [
        # Spring Boot's default JSON error shape / Whitelabel HTML page.
        r"whitelabel error page", r"org\.springframework",
        # ASP.NET
        r"server error in '/' application", r"microsoft\.aspnetcore",
        r"system\.web\.httpexception",
        # Laravel
        r"illuminate\\", r"laravel\\framework",
        # Django
        r"django\.(?:core|urls)\.exceptions", r"disallowedhost",
        r"page not found.*django",
        # FastAPI / pydantic
        r'"detail":\s*"', r"pydantic\.error",
        # Express / Node
        r"cannot (?:get|post|put|delete) /", r"\bexpress\b.*error",
    ],
}
SIGNAL_PATTERNS: dict[str, list[re.Pattern]] = {
    cat: [re.compile(p, re.IGNORECASE) for p in pats]
    for cat, pats in _RAW_PATTERNS.items()
}

# Status codes that would be unambiguous in isolation — a real body or
# redirect came back. Still capped at LIKELY, not auto-CONFIRMED, unless
# baseline proves it: an unmeasured host (no ``raw/baseline/`` for this run)
# can be a blanket 200 SPA fallback or a catch-all redirect just as easily as
# a real page, and status alone can't tell the two apart. See
# :func:`classify`'s "exists" branch for the measured false-positive this
# guards against.
_DEFINITE_EXISTS_STATUS = frozenset({200, 201, 202, 204, 206, 301, 302, 303, 307, 308})

# The genuinely ambiguous statuses from the spec's "HTTP behavior" bullet.
# Strong: the server had to resolve routing (and often parse the request)
# before it could reject on method/media-type/semantics grounds — 401/403
# join this set too, since both require the route to exist and be recognised
# as auth-gated. Weak: on their own these are ambiguous either way (429 =
# rate-limited, could hit ANY path including nonexistent ones; 500 could be a
# crash in front-end middleware that never reached routing) — they nudge a
# verdict, never confirm alone.
_STRONG_STATUS = frozenset({401, 403, 405, 406, 415, 422})
_WEAK_STATUS = frozenset({429, 500})

_STRONG_CATEGORIES = frozenset(
    {"validation", "parsing", "auth", "business_logic", "framework"})


@dataclass(frozen=True)
class Existence:
    """Result of :func:`classify` — a verdict plus the evidence behind it."""

    verdict: str
    signals: dict[str, list[str]] = field(default_factory=dict)
    status_signal: str = ""     # "" | "strong" | "weak"
    baseline_is_noise: bool | None = None

    @property
    def reasons(self) -> list[str]:
        """Human-readable evidence lines, most-specific first."""
        out = [f"{cat}: {phrase}" for cat, phrases in self.signals.items()
               for phrase in phrases]
        if self.status_signal == "exists":
            out.append("status is a real response/redirect (2xx/3xx)")
        elif self.status_signal == "strong":
            out.append("status implies routed request (401/403/405/406/415/422)")
        elif self.status_signal == "weak":
            out.append("status is ambiguous alone (429/500)")
        if self.baseline_is_noise is True:
            out.append("identical shape to this host's not-found baseline")
        elif self.baseline_is_noise is False:
            out.append("differs from this host's not-found baseline")
        return out


def match_signals(snippet: str) -> dict[str, list[str]]:
    """Body-preview phrase matches, grouped by category. ``{}`` for an empty
    or signal-free snippet — most previews are, and that's fine, it just
    means this hit's verdict rests on baseline/status instead."""
    text = (snippet or "").strip()
    if not text:
        return {}
    out: dict[str, list[str]] = {}
    for cat, patterns in SIGNAL_PATTERNS.items():
        hits = [p.pattern for p in patterns if p.search(text)]
        if hits:
            out[cat] = hits
    return out


def classify(
    status: int,
    snippet: str = "",
    *,
    baseline_is_noise: bool | None = None,
) -> Existence:
    """Classify one fuzzed hit. Pure, no I/O — callers own baseline lookup
    and body-preview fetch, both already computed elsewhere in the pipeline.

    ``baseline_is_noise``:
      * ``True``  — this hit's response is identical in shape to what the
        host returns for a path guaranteed not to exist (``Baseline.is_noise``).
      * ``False`` — the host has a consistent not-found shape and this hit
        does NOT match it. This is the ONLY case that lets a bare 2xx/3xx
        reach CONFIRMED — see the "exists" branch below.
      * ``None``  — no usable baseline for this host (unmeasured, or the
        host's not-found answer wasn't consistent across probes). Treated
        the same as ``True`` for 2xx/3xx status (capped at LIKELY): absence
        of a baseline is not evidence the response is real.
    """
    signals = match_signals(snippet)
    n_strong = sum(1 for c in signals if c in _STRONG_CATEGORIES)

    status_signal = ""
    if status in _DEFINITE_EXISTS_STATUS:
        status_signal = "exists"
    elif status in _STRONG_STATUS:
        status_signal = "strong"
    elif status in _WEAK_STATUS:
        status_signal = "weak"

    # A real body/redirect (2xx/3xx) reaches CONFIRMED only when baseline
    # PROVES this shape differs from what a guaranteed-fake path on this
    # host also gets (``baseline_is_noise is False`` — actually measured,
    # not just absent). ``None`` (no baseline captured for this run) is NOT
    # enough on its own: measured on a real acronis.com run,
    # ``account.acronis.com`` 302-redirects every unmatched word to
    # ``/#/<word>&email=`` — a client-side-router catch-all that echoes the
    # request into the URL FRAGMENT, so ``behavior.redirect_shape`` (which
    # only reads ``.path``) can't distinguish it from a real redirect, and
    # with no baseline probe on that run every one of those fake words
    # would have been stamped CONFIRMED. Demoting status-only "exists" to
    # LIKELY whenever baseline is unmeasured closes that gap without
    # needing the echo pattern itself to be recognised.
    if status_signal == "exists":
        verdict = CONFIRMED if baseline_is_noise is False else LIKELY
    # Baseline says "this is exactly what nothing looks like" for every OTHER
    # status too — status alone is NOT enough to override that (status is
    # already part of what the baseline fingerprint matched on, so a
    # "strong" status here is not independent evidence). Only a BODY signal
    # — text the not-found baseline never said — is: a JSON business-logic
    # error can legitimately share the host's generic error SHAPE (same
    # status/content-type/size bucket) while saying something new, so it's
    # worth a second look rather than being silently collapsed.
    elif baseline_is_noise:
        verdict = LIKELY if signals else NOT_FOUND
    elif n_strong >= 2 or (n_strong >= 1 and status_signal == "strong"):
        verdict = CONFIRMED
    elif n_strong >= 1 or status_signal == "strong":
        verdict = LIKELY
    elif baseline_is_noise is False:
        # Differs from the host's not-found shape but no keyword/status
        # signal fired — some evidence, not enough to call it confirmed.
        verdict = LIKELY
    else:
        verdict = UNKNOWN

    return Existence(verdict=verdict, signals=signals,
                     status_signal=status_signal,
                     baseline_is_noise=baseline_is_noise)


def summary_counts(results: list[Existence]) -> dict[str, int]:
    """``{"confirmed": n, "likely": n, "unknown": n, "not_found": n}``, every
    key present even at zero so a report table never has to guess a
    missing key means zero versus "not computed"."""
    out = {CONFIRMED: 0, LIKELY: 0, UNKNOWN: 0, NOT_FOUND: 0}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    return out
