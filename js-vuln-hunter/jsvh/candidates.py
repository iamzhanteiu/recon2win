"""Candidate engine + ranking.

Turns analyzer records into ranked, verifiable Candidates. The guiding
rule is §19 (HIGH SIGNAL / LOW NOISE): a candidate is emitted only when
there is *meaningful evidence*, and confidence honestly reflects how much
of the chain we could prove statically. Nothing here is a confirmed bug —
every candidate carries ``verification_status`` and needs a plan (§14).
"""

from __future__ import annotations

from .analyzers import auth as A_auth
from .analyzers import dataflow as A_flow
from .analyzers import endpoints as A_ep
from .analyzers import jwt_oauth as A_jwt
from .analyzers import postmessage as A_pm
from .analyzers import prototype_pollution as A_proto
from .analyzers import secrets as A_secrets
from .analyzers import sourcemap as A_smap
from .analyzers import websocket as A_ws
from .analyzers import patterns as P
from . import ast_engine as A
from . import exploitability as EXPLOIT
from .models import Candidate, DataFlow, JSAsset


# ---- priority + base confidence per candidate type -----------------------
# (priority follows mission §18)
_TYPE_META = {
    "DOM-XSS": ("P1", "high"),
    "CODE-INJECTION": ("P1", "critical"),
    "PROTOTYPE-POLLUTION": ("P1", "high"),
    "POSTMESSAGE-XSS": ("P1", "high"),
    "SECRET-EXPOSURE": ("P1", "high"),
    "CLIENT-SIDE-AUTHZ": ("P1", "medium"),
    "BOLA": ("P1", "high"),
    "BFLA": ("P1", "high"),
    "OAUTH-REDIRECT": ("P1", "high"),
    "OPEN-REDIRECT": ("P2", "medium"),
    "SENSITIVE-API": ("P2", "medium"),
    "WEBSOCKET": ("P2", "low"),
    "POSTMESSAGE-WILDCARD": ("P2", "low"),
    "JWT-TRUST": ("P2", "medium"),
    "TOKEN-STORAGE": ("P2", "low"),
    "SOURCE-MAP-EXPOSURE": ("P2", "low"),
}


# Direct HTML-write / eval sinks are unambiguous; jQuery collection methods
# (`.append/.after/.before/.html`) are a weaker, noisier signal (often library
# internals inside a bundle) — tier confidence accordingly.
_STRONG_SINKS = {"innerHTML", "outerHTML", "write", "writeln", "eval",
                 "Function", "insertAdjacentHTML"}
_WEAK_SINKS = {"append", "after", "before", "html", "appendChild", "prepend"}


def _flow_confidence(f: DataFlow) -> float:
    c = 0.35
    if f.attacker_controlled == "yes":
        c += 0.35
    elif f.attacker_controlled == "unknown":
        c += 0.05
    if f.sanitization == "none":
        c += 0.2
    elif f.sanitization == "weak":
        c += 0.12
    elif f.sanitization == "known-safe":
        c -= 0.25
    sink_base = (f.sink or "").rsplit(".", 1)[-1].rstrip("()")
    if sink_base in _WEAK_SINKS:
        c -= 0.2
    elif sink_base in _STRONG_SINKS:
        c += 0.05
    return max(0.05, min(0.98, c))


def _flow_type(f: DataFlow) -> str:
    return {
        "dom-xss": "DOM-XSS",
        "code-injection": "CODE-INJECTION",
        "open-redirect": "OPEN-REDIRECT",
        "script-src": "DOM-XSS",
        "proto": "PROTOTYPE-POLLUTION",
    }.get(f.sink_kind, "DOM-XSS")


def from_asset(asset: JSAsset, pm: A.ParsedModule,
               flows: list[DataFlow], data: bytes | None = None
               ) -> tuple[list[Candidate], dict]:
    """Generate candidates for one asset. Returns (candidates, analyzer_dump)."""
    cands: list[Candidate] = []
    n = 0

    def _mk(ctype, title, **kw) -> Candidate:
        nonlocal n
        n += 1
        pri, sev = _TYPE_META.get(ctype, ("P3", "info"))
        return Candidate(
            id=f"{asset.asset_id}-c{n:03d}", type=ctype, priority=pri,
            severity=kw.pop("severity", sev), confidence=kw.pop("confidence", 0.5),
            asset_id=asset.asset_id, url=asset.url, title=title, **kw)

    # --- data-flow candidates (DOM XSS / code-injection / open redirect) ---
    for f in flows:
        # known-safe sanitized flows are the *correct* defensive pattern
        # (e.g. DOMPurify.sanitize(x) -> innerHTML). Suppress as noise —
        # revisit manually only if the sanitizer version is suspect.
        if f.sanitization == "known-safe":
            continue
        # unresolved-provenance flows only matter if the sink is severe
        if f.attacker_controlled == "unknown" and f.sink_kind not in ("code-injection", "dom-xss"):
            continue
        ctype = _flow_type(f)
        conf = _flow_confidence(f)
        if conf < 0.4:
            continue
        cands.append(_mk(
            ctype, f"{f.source} → {f.sink}",
            confidence=round(conf, 2), source=f.source, sink=f.sink,
            attacker_controlled=f.attacker_controlled, sanitization=f.sanitization,
            evidence=f.evidence, location=f.sink_location, flow_id=f.flow_id))

    # --- prototype pollution ---
    for pf in A_proto.analyze(pm):
        conf = 0.75 if pf.attacker_controlled == "yes" else (
            0.6 if pf.kind == "merge-sink" else 0.5)
        cands.append(_mk(
            "PROTOTYPE-POLLUTION", f"prototype pollution via {pf.sink}",
            confidence=conf, sink=pf.sink, attacker_controlled=pf.attacker_controlled,
            evidence=pf.evidence, location=pf.location))

    # --- postMessage ---
    for m in A_pm.analyze(pm):
        # strict origin === check → the correct defensive pattern; suppress as
        # noise (§8). weak (indexOf/startsWith/includes) or none → candidate.
        if m.role == "receiver" and m.handler_uses_data and m.origin_check != "strict":
            weak = m.origin_check == "weak"
            base = 0.85 if m.reaches_sink else 0.6
            conf = base - (0.15 if weak else 0.0)  # weak-but-present is lower signal
            label = ("message handler with WEAK origin validation "
                     "(substring/regex — bypassable)" if weak
                     else "message handler without origin check")
            cands.append(_mk(
                "POSTMESSAGE-XSS",
                label + (f" reaching {m.reaches_sink}" if m.reaches_sink else ""),
                confidence=round(conf, 2), source="event.data",
                sink=m.reaches_sink or "handler",
                attacker_controlled="yes",
                sanitization="weak" if weak else "none",
                evidence=m.evidence, location=m.location))
        elif m.role == "sender" and m.wildcard_origin:
            cands.append(_mk(
                "POSTMESSAGE-WILDCARD", "postMessage to wildcard origin ('*')",
                confidence=0.5, sink="postMessage",
                evidence=m.evidence, location=m.location))

    # --- client-side authorization ---
    for af in A_auth.analyze(pm):
        cands.append(_mk(
            "CLIENT-SIDE-AUTHZ",
            f"client-side authz check: {af.identifier}",
            confidence=0.6 if af.guards_endpoint else 0.45,
            endpoint=af.guards_endpoint, evidence=af.evidence, location=af.location))

    # --- API endpoints: sensitive-API + BOLA (object id) + BFLA (function) ---
    endpoints = A_ep.analyze(asset.asset_id, pm)
    authz_idents = [af.identifier for af in A_auth.analyze(pm)]
    client_authz_present = bool(authz_idents)
    for ep in endpoints:
        # BOLA: a client-controlled object id in the path/params. Higher
        # confidence when a client-side authz gate is the only visible control.
        if ep.object_ids:
            conf = 0.55 + (0.1 if client_authz_present else 0.0) + (0.05 if ep.sensitive_op else 0.0)
            cands.append(_mk(
                "BOLA", f"{ep.method or 'GET'} {ep.url_template} (object id: {', '.join(ep.object_ids[:2])})",
                confidence=round(min(conf, 0.8), 2), method=ep.method or "GET",
                sink=ep.method or "GET", object_id=", ".join(ep.object_ids),
                endpoint=ep.url_template, attacker_controlled="yes",
                evidence=f"{ep.method} {ep.url_template}", location=ep.location))
        # BFLA: a mutating/privileged function on a sensitive namespace.
        elif ep.sensitive_op and ep.interesting and (ep.method in P.MUTATING_METHODS
                                                     or P.SENSITIVE_PATH.search(ep.url_template)):
            cands.append(_mk(
                "BFLA", f"{ep.method or 'GET'} {ep.url_template} (privileged function)",
                confidence=0.5 + (0.1 if client_authz_present else 0.0),
                method=ep.method or "GET", sink=ep.method or "GET",
                endpoint=ep.url_template, evidence=f"{ep.method} {ep.url_template}",
                location=ep.location))
        elif ep.interesting:
            cands.append(_mk(
                "SENSITIVE-API", f"{ep.method or 'GET'} {ep.url_template}",
                confidence=0.5 if ep.dynamic else 0.6,
                method=ep.method or "GET", sink=ep.method or "GET",
                endpoint=ep.url_template, evidence=f"{ep.method} {ep.url_template}",
                location=ep.location))

    # --- secrets (classified §12) ---
    for s in A_secrets.analyze(pm):
        # public identifiers (OAuth client_id, Stripe pk_, recaptcha) are NOT
        # secrets — surface only as low info, never P1.
        if s.secret_class == "public-id":
            cands.append(_mk(
                "SECRET-EXPOSURE", f"[public-id] {s.kind}: {s.match}",
                severity="info", confidence=s.confidence,
                evidence=f"{s.kind} {s.match} (publishable identifier, not a secret)",
                location=s.location, notes=["public/publishable identifier — not a secret (§12)"]))
            continue
        sev = "high" if (s.secret_class == "credential") else (
            "medium" if s.confidence >= 0.75 else "low")
        cands.append(_mk(
            "SECRET-EXPOSURE", f"[{s.secret_class}] {s.kind}: {s.match}",
            severity=sev, confidence=s.confidence,
            evidence=f"{s.kind} {s.match} (class={s.secret_class})", location=s.location))

    # --- JWT / OAuth / OIDC (§11) ---
    for tf in A_jwt.analyze(pm):
        if tf.kind == "token-storage":
            cands.append(_mk("TOKEN-STORAGE", tf.detail, confidence=0.5,
                             evidence=tf.evidence, location=tf.location))
        elif tf.kind == "jwt-claim-trust":
            cands.append(_mk("JWT-TRUST", tf.detail, confidence=0.55,
                             evidence=tf.evidence, location=tf.location))
        elif tf.kind == "oauth-redirect":
            cands.append(_mk("OAUTH-REDIRECT", tf.detail,
                             confidence=0.6 if tf.attacker_controlled == "yes" else 0.45,
                             attacker_controlled=tf.attacker_controlled,
                             evidence=tf.evidence, location=tf.location))
        elif tf.kind == "oauth-state":
            cands.append(_mk("OAUTH-REDIRECT", tf.detail, severity="medium",
                             confidence=0.4, evidence=tf.evidence, location=tf.location))
        # 'jwt-decode' (no claim authz) is informational — not emitted as a candidate

    # --- source-map exposure (§13) ---
    if data is not None:
        for sm in A_smap.analyze(data):
            interesting = sm.inline and (sm.has_sources_content or sm.interesting_sources)
            note = (f"internal sources: {', '.join(sm.interesting_sources[:5])}"
                    if sm.interesting_sources else "")
            cands.append(_mk(
                "SOURCE-MAP-EXPOSURE",
                f"{sm.kind}: {sm.map_ref}",
                severity="medium" if interesting else "low",
                confidence=0.6 if interesting else 0.35,
                evidence=sm.evidence, notes=[note] if note else []))

    # --- websocket ---
    for w in A_ws.analyze(pm):
        cands.append(_mk(
            "WEBSOCKET", f"WebSocket {w.url}",
            confidence=0.4, endpoint=w.url, evidence=w.evidence, location=w.location))

    # Third-party library internals are not the target app's bug (§18: P3).
    # Demote everything from a vendor/CDN asset so it never crowds the P1/P2
    # shortlist, but keep it (a genuinely vulnerable outdated lib is still
    # worth a low-priority look).
    if asset.third_party:
        for c in cands:
            c.priority = "P3"
            c.severity = "info" if c.severity in ("high", "critical") else c.severity
            c.confidence = min(c.confidence, 0.35)
            c.notes.append("third-party library asset — demoted (§18)")

    # attach structured exploitability + reason-refined priority (§15)
    for c in cands:
        EXPLOIT.refine(c)

    dump = {
        "flows": [f.to_dict() for f in flows],
        "endpoints": [e.to_dict() for e in endpoints],
    }
    return cands, dump


# ---- ranking -------------------------------------------------------------
_PRIORITY_WEIGHT = {"P1": 1000, "P2": 400, "P3": 100}
_SEVERITY_WEIGHT = {"critical": 500, "high": 350, "medium": 180, "low": 80, "info": 20}


def rank(cands: list[Candidate], per_asset_cap: int = 6) -> list[Candidate]:
    for c in cands:
        score = _PRIORITY_WEIGHT.get(c.priority, 100)
        score += _SEVERITY_WEIGHT.get(c.severity, 20)
        score += c.confidence * 400
        if c.attacker_controlled == "yes":
            score += 200
        if c.sanitization == "none":
            score += 80
        c.rank_score = round(score, 1)
        c.verification_status = "NEW"

    # HIGH SIGNAL (§19): collapse duplicates and cap the long tail a single
    # noisy bundle can produce. Dedup key ignores location so 40 identical
    # `location.href → setTimeout` hits in one minified file become one.
    deduped: dict[tuple, Candidate] = {}
    for c in cands:
        key = (c.asset_id, c.type, c.source, c.sink, c.endpoint)
        if key not in deduped:
            deduped[key] = c
        else:
            deduped[key].notes.append(f"+1 duplicate at {c.location}")
    unique = sorted(deduped.values(), key=lambda x: x.rank_score, reverse=True)

    # cap per asset so one file cannot flood the shortlist
    kept: list[Candidate] = []
    seen_per_asset: dict[str, int] = {}
    for c in unique:
        n = seen_per_asset.get(c.asset_id, 0)
        if n >= per_asset_cap:
            continue
        seen_per_asset[c.asset_id] = n + 1
        kept.append(c)
    return kept
