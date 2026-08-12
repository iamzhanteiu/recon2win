"""Source / sink / sanitizer taxonomies shared by all analyzers.

Kept in one place so the data-flow engine, the individual analyzers and
the knowledge base all agree on what counts as a source, a sink, or a
sanitizer. Matching is on the flattened dotted name produced by
``ast_engine.member_name`` / ``call_name``.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# SOURCES — attacker-influenceable inputs. name-substring match on the
# flattened member expression. kind drives candidate classification.
# --------------------------------------------------------------------------
# NOTE: only genuinely attacker-influenceable inputs belong here. The parts
# of `location` an attacker can drive via a crafted link (hash/search/href,
# and pathname weakly) are sources; `location.hostname/host/origin/protocol/
# port` are the victim's *current* site and are NOT attacker-controlled — a
# bare "location" catch-all here was the #1 false-positive source.
SOURCES: dict[str, str] = {
    "location.hash": "url",
    "location.search": "url",
    "location.href": "url",
    "location.pathname": "url",
    "document.URL": "url",
    "document.documentURI": "url",
    "document.baseURI": "url",
    "document.referrer": "url",
    "document.cookie": "storage",
    "window.name": "dom",
    "history.state": "dom",
    "localStorage.getItem": "storage",
    "sessionStorage.getItem": "storage",
    "URLSearchParams": "url",
}

# member suffixes on `location` that are explicitly NOT attacker-controlled,
# so a fuzzy match never promotes them to a source.
NON_SOURCE_LOCATION = (
    "location.hostname", "location.host", "location.origin",
    "location.protocol", "location.port", "location.ancestorOrigins",
)

# postMessage handler event data is a source, but detected structurally
# (event.data inside a message handler) — see postmessage analyzer.

# --------------------------------------------------------------------------
# SINKS — dangerous operations. Two flavours:
#   ASSIGN_SINKS: member targets of `x.y = value`
#   CALL_SINKS:   call callees `f(value)`  (arg index that is dangerous)
# --------------------------------------------------------------------------
ASSIGN_SINKS: dict[str, str] = {
    "innerHTML": "dom-xss",
    "outerHTML": "dom-xss",
    "src": "script-src",          # only interesting on script/iframe — refined later
    "href": "open-redirect",      # location.href = ... / a.href
    "location": "open-redirect",
    "location.href": "open-redirect",
    "location.hash": "dom-xss",
}

# call callee -> (sink_kind, dangerous_arg_indexes)
CALL_SINKS: dict[str, tuple[str, tuple[int, ...]]] = {
    "eval": ("code-injection", (0,)),
    "Function": ("code-injection", (0,)),
    "setTimeout": ("code-injection", (0,)),        # only when arg0 is a string
    "setInterval": ("code-injection", (0,)),
    "document.write": ("dom-xss", (0,)),
    "document.writeln": ("dom-xss", (0,)),
    "insertAdjacentHTML": ("dom-xss", (1,)),
    "el.insertAdjacentHTML": ("dom-xss", (1,)),
    "window.open": ("open-redirect", (0,)),
    "jQuery": ("dom-xss", (0,)),
    "$": ("dom-xss", (0,)),
    "$.html": ("dom-xss", (0,)),
    "html": ("dom-xss", (0,)),                      # jQuery .html(x)
    "append": ("dom-xss", (0,)),
    "after": ("dom-xss", (0,)),
    "before": ("dom-xss", (0,)),
    "$.globalEval": ("code-injection", (0,)),
}

# member-suffix sinks for assignments (matches the *last* segment too, so
# `el.innerHTML` and `foo.bar.innerHTML` both hit "innerHTML").
ASSIGN_SINK_SUFFIXES = {"innerHTML", "outerHTML"}

# --------------------------------------------------------------------------
# SANITIZERS — wrapping calls that change the taint verdict.
# --------------------------------------------------------------------------
KNOWN_SAFE = {
    "DOMPurify.sanitize", "dompurify.sanitize", "sanitizeHtml", "sanitize-html",
    "textContent", "encodeURIComponent", "encodeURI", "escape",
    "createTextNode", "sanitizeHTML", "purify.sanitize",
}
# weak / context-wrong sanitizers — present but insufficient for the sink
WEAK_SANITIZERS = {
    "encodeURIComponent",  # safe for URL param, useless for HTML sink
    "escape", "replace", "JSON.parse", "JSON.stringify",
    "decodeURIComponent", "parseInt", "Number", "String",
}

# --------------------------------------------------------------------------
# PROTOTYPE POLLUTION — merge-style sinks + pollution keys.
# --------------------------------------------------------------------------
MERGE_SINKS = {
    "merge", "mergeWith", "defaultsDeep", "_.merge", "lodash.merge",
    "$.extend", "jQuery.extend", "extend", "assign", "Object.assign",
    "deepMerge", "deepmerge", "setWith", "set", "_.set", "objectPath.set",
}
POLLUTION_KEYS = ("__proto__", "constructor", "prototype")

# --------------------------------------------------------------------------
# ENDPOINT / NETWORK sinks — where URLs get requested.
# --------------------------------------------------------------------------
NETWORK_CALLS = {
    "fetch": "GET", "axios": "GET", "axios.get": "GET", "axios.post": "POST",
    "axios.put": "PUT", "axios.delete": "DELETE", "axios.patch": "PATCH",
    "$.ajax": "GET", "$.get": "GET", "$.post": "POST", "$.getJSON": "GET",
    "jQuery.ajax": "GET", "XMLHttpRequest": "GET",
}
XHR_OPEN = {"open"}          # xhr.open(method, url)

# --------------------------------------------------------------------------
# INTERESTING ENDPOINT PATHS — bump priority when a resolved URL hits these.
# --------------------------------------------------------------------------
INTERESTING_PATH = re.compile(
    r"(?:/admin|/internal|/debug|/api/|/graphql|/v\d+/|/auth|/login|/logout|"
    r"/token|/oauth|/sso|/user|/account|/password|/reset|/upload|/file|"
    r"/config|/setting|/secret|/key|/private|/manage|/root|/su/|/impersonat)",
    re.I,
)

# --------------------------------------------------------------------------
# OBJECT IDENTIFIERS (BOLA/IDOR) + sensitive operations (BFLA).
# --------------------------------------------------------------------------
# A dynamic URL segment named like an object identifier — the classic BOLA
# lever: /users/{id}, /orders/{orderId}, /accounts/{uuid}.
OBJECT_ID_NAME = re.compile(
    r"(?:^|[._])(?:id|uid|uuid|guid|pk|key|"
    r"user(?:_?id)?|account(?:_?id)?|customer(?:_?id)?|order(?:_?id)?|"
    r"org(?:anization)?(?:_?id)?|team(?:_?id)?|group(?:_?id)?|project(?:_?id)?|"
    r"doc(?:ument)?(?:_?id)?|file(?:_?id)?|invoice(?:_?id)?|payment(?:_?id)?|"
    r"tenant(?:_?id)?|member(?:_?id)?|record(?:_?id)?|entity(?:_?id)?|slug)$",
    re.I)
# a resolved path segment that is (or looks like) an id value: /123, /{uuid}
OBJECT_ID_SEGMENT = re.compile(
    r"/(?:\d{1,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|\{[^}]*(?:id|uid|uuid|key|pk|slug|user|account|order|org)[^}]*\})",
    re.I)
# path namespaces where a missing function-level check (BFLA) is high impact
SENSITIVE_PATH = re.compile(
    r"(?:/admin|/manage|/management|/internal|/superuser|/root|/su/|"
    r"/impersonat|/billing|/payment|/invoice|/refund|/payout|/security|"
    r"/permission|/role|/grant|/revoke|/delete|/disable|/enable|/approve|"
    r"/organization|/tenant|/settings?/|/config|/debug)",
    re.I)
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def object_ids_in(url_template: str, parameters: list[str]) -> list[str]:
    """Client-controlled object-identifier segments in a resolved URL.

    Both the dynamic ``{name}`` placeholders our resolver injects and literal
    id-looking path segments count — either is a BOLA lever worth verifying.
    """
    ids: list[str] = []
    # dynamic {placeholders} whose name reads like an id
    for seg in re.findall(r"\{([^}]+)\}", url_template):
        base = seg.rstrip("()").rsplit(".", 1)[-1]
        if OBJECT_ID_NAME.search(base) or base.lower() in ("id", "uid", "pk"):
            ids.append(seg)
    # literal id segments (/123, /uuid)
    for m in OBJECT_ID_SEGMENT.finditer(url_template):
        ids.append(m.group(0).lstrip("/"))
    # query params named like ids
    for p in parameters:
        if OBJECT_ID_NAME.search(p):
            ids.append(p)
    # dedupe, keep order
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


# --------------------------------------------------------------------------
# CLIENT-SIDE AUTHZ signals.
# --------------------------------------------------------------------------
AUTHZ_IDENTS = re.compile(
    r"\b(isAdmin|isOwner|isSuperuser|canEdit|canDelete|canView|canManage|"
    r"hasRole|hasPermission|hasAccess|isAuthorized|isAuthenticated|"
    r"roles?|permissions?|privileges?|featureFlags?|isEnabled|isPremium|"
    r"isStaff|accessLevel|userRole)\b",
    re.I,
)

# --------------------------------------------------------------------------
# SECRETS — high-signal literal patterns (complements recon2win jsluice).
# --------------------------------------------------------------------------
# Each entry: (kind, regex, secret_class). secret_class drives §12:
#   credential   — high-confidence live secret (AWS/GitHub/Stripe live/priv key)
#   token        — a bearer/JWT/session token (sensitive but may be short-lived)
#   config       — sensitive config (firebase url) — context matters
#   public-id    — a PUBLISHABLE identifier (OAuth client_id, Stripe pk_,
#                  recaptcha site key). NOT a secret — suppressed to info (§12).
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "credential"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "token"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "credential"),
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "credential"),
    ("github_fine_pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{60,}\b"), "credential"),
    ("stripe_live", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "credential"),
    ("stripe_test_secret", re.compile(r"\bsk_test_[0-9A-Za-z]{24,}\b"), "credential"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "credential"),
    ("aws_secret_assign", re.compile(
        r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"), "credential"),
    ("client_secret_assign", re.compile(
        r"(?i)client[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]"), "credential"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "token"),
    ("firebase_url", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "config"),
    # public identifiers — NOT secrets (§12: avoid reporting public client IDs)
    ("oauth_client_id", re.compile(r"\b\d{9,}-[0-9a-z]{20,}\.apps\.googleusercontent\.com\b"), "public-id"),
    ("stripe_publishable", re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b"), "public-id"),
    ("recaptcha_site_key", re.compile(r"\b6L[0-9A-Za-z_-]{38}\b"), "public-id"),
    ("generic_secret_assign", re.compile(
        r"(?i)(?:api[_-]?key|secret|passwd|password|token|auth[_-]?token|"
        r"access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]"), "token"),
]


def match_source(name: str) -> str | None:
    """Return source kind if *name* is (or contains) a known source."""
    if any(ns in name for ns in NON_SOURCE_LOCATION):
        return None
    if name in SOURCES:
        return SOURCES[name]
    for src, kind in SOURCES.items():
        if src in name:
            return kind
    return None


def match_assign_sink(name: str) -> str | None:
    if name in ASSIGN_SINKS:
        return ASSIGN_SINKS[name]
    last = name.rsplit(".", 1)[-1]
    if last in ASSIGN_SINK_SUFFIXES:
        return "dom-xss"
    if last in ("href", "src", "action"):
        return "open-redirect" if last in ("href", "action") else "script-src"
    return None


def match_call_sink(name: str) -> tuple[str, tuple[int, ...]] | None:
    if name in CALL_SINKS:
        return CALL_SINKS[name]
    last = name.rsplit(".", 1)[-1]
    if last in ("insertAdjacentHTML",):
        return ("dom-xss", (1,))
    if last in ("html", "append", "after", "before", "write", "writeln"):
        return CALL_SINKS.get(last, ("dom-xss", (0,)))
    return None
