"""Attack-chain correlation engine (mission §14).

Candidates are not analysed in isolation. Real bug-bounty impact usually
comes from *correlating* several weaker observations into one high-value
hypothesis:

    source map + hidden admin API + client-side role check + object id
        → potential BOLA/BFLA

    postMessage (weak/no origin) + privileged API/sink
        → potential cross-origin privilege abuse

    token exposure/storage + sensitive API + weak authz
        → potential account compromise

    prototype pollution + attacker source + security-sensitive sink
        → high-value prototype-pollution candidate

This module takes the full ranked candidate list (plus the endpoint
inventory) for a target and emits ``AttackChain`` records. Chains are
correlated per host (same origin ⇒ same trust surface); a chain's
confidence is a conservative function of its members, and it links back to
the candidate ids so the verifier can pivot.
"""

from __future__ import annotations

from collections import defaultdict

from .models import AttackChain, Candidate


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


def _p(priority: str, conf: float) -> str:
    if priority == "P1" or conf >= 0.8:
        return "P1"
    if conf >= 0.55:
        return "P2"
    return "P3"


def correlate(candidates: list[Candidate]) -> list[AttackChain]:
    """Build attack chains from a ranked candidate list."""
    chains: list[AttackChain] = []
    n = 0

    # index candidates by host (same-origin trust surface)
    by_host: dict[str, list[Candidate]] = defaultdict(list)
    for c in candidates:
        if c.priority == "P3":
            continue  # demoted/library noise doesn't seed chains
        by_host[_host_of(c.url)].append(c)

    def new_chain(name, impact, conf, members, rels, rationale, verify) -> None:
        nonlocal n
        n += 1
        cid = f"CHAIN-{n:03d}"
        ch = AttackChain(
            chain_id=cid, name=name, impact=impact,
            confidence=round(conf, 2), priority=_p("", conf),
            observations=[m.id for m in members],
            relationships=rels, rationale=rationale, verification=verify)
        for m in members:
            m.chain_ids.append(cid)
        chains.append(ch)

    for host, cs in by_host.items():
        by_type: dict[str, list[Candidate]] = defaultdict(list)
        for c in cs:
            by_type[c.type].append(c)

        # 1. BOLA/BFLA authorization chain: object-id/privileged endpoint +
        #    client-side authz gate (+ source-map that exposed the API).
        authz = by_type.get("CLIENT-SIDE-AUTHZ", [])
        bola = by_type.get("BOLA", []) + by_type.get("BFLA", [])
        smap = by_type.get("SOURCE-MAP-EXPOSURE", [])
        if bola and authz:
            top_bola = max(bola, key=lambda x: x.confidence)
            members = [top_bola, authz[0]] + (smap[:1])
            conf = min(0.9, 0.5 + 0.15 * len(bola) / max(1, len(bola)) +
                       0.2 + (0.1 if smap else 0.0))
            new_chain(
                name=f"Broken object/function authorization on {host}",
                impact="potential BOLA/BFLA (cross-user or privilege escalation)",
                conf=conf, members=members,
                rels=[f"{top_bola.id} exposes a client-controlled object id",
                      f"{authz[0].id} shows authz is decided client-side",
                      *([f"{smap[0].id} leaks the API's original source"] if smap else [])],
                rationale=("A privileged/object-scoped API is reachable with a "
                           "client-controlled identifier while the only visible "
                           "authorization is a JS gate — the classic BOLA/BFLA shape."),
                verify=["Replay the endpoint as a low-priv / other user, tampering the object id.",
                        "Confirm the server does not re-check object/function authorization.",
                        "If the JS gate is the sole control, escalate to a real finding."])

        # 2. Cross-origin privilege abuse: weak/no-origin postMessage that
        #    reaches a sink, on a host that also exposes a sensitive/BOLA API.
        pm = by_type.get("POSTMESSAGE-XSS", [])
        sensitive = by_type.get("SENSITIVE-API", []) + bola
        if pm:
            top_pm = max(pm, key=lambda x: x.confidence)
            members = [top_pm] + (sensitive[:1])
            conf = min(0.88, top_pm.confidence + (0.1 if sensitive else 0.0))
            new_chain(
                name=f"Cross-origin message → privileged action on {host}",
                impact="potential cross-origin privilege abuse / DOM XSS",
                conf=conf, members=members,
                rels=[f"{top_pm.id} accepts cross-origin messages without strict origin check",
                      *([f"{sensitive[0].id} is a sensitive action reachable in the same origin"]
                        if sensitive else [])],
                rationale=("An attacker page can post a message the handler trusts; "
                           "if it drives a sink or a privileged request, impact is "
                           "cross-origin."),
                verify=["Host an attacker page that frames/opens the target and posts a crafted message.",
                        "Confirm the payload reaches the sink / triggers the action.",
                        "Document required user interaction."])

        # 3. Account compromise: token exposure/storage + sensitive API.
        tokens = (by_type.get("TOKEN-STORAGE", []) + by_type.get("JWT-TRUST", []) +
                  [c for c in by_type.get("SECRET-EXPOSURE", []) if c.severity in ("high", "medium")])
        if tokens and (by_type.get("SENSITIVE-API") or bola):
            api = (by_type.get("SENSITIVE-API", []) + bola)[0]
            members = [tokens[0], api]
            conf = min(0.85, 0.45 + 0.2 * min(2, len(tokens)) + 0.1)
            new_chain(
                name=f"Token exposure + sensitive API on {host}",
                impact="potential account compromise",
                conf=conf, members=members,
                rels=[f"{tokens[0].id} exposes/stores a token insecurely",
                      f"{api.id} is a sensitive API the token could reach"],
                rationale=("A token readable from the client (storage/leak/claim "
                           "trust) combined with a sensitive API is an account-"
                           "takeover primitive if authorization is weak."),
                verify=["Extract the token at runtime; confirm it is live and scoped.",
                        "Call the sensitive API with it; test for over-broad access.",
                        "Do not exceed a benign read while proving validity."])

        # 4. High-value prototype pollution: reachable (attacker-controlled)
        #    pollution + an XSS/code sink on the same host (gadget target).
        proto = [c for c in by_type.get("PROTOTYPE-POLLUTION", []) if c.attacker_controlled == "yes"]
        sinks = by_type.get("DOM-XSS", []) + by_type.get("CODE-INJECTION", [])
        if proto:
            members = [proto[0]] + (sinks[:1])
            conf = min(0.85, proto[0].confidence + (0.1 if sinks else 0.0))
            new_chain(
                name=f"Reachable prototype pollution on {host}",
                impact="high-value prototype-pollution candidate (gadget → XSS/authz)",
                conf=conf, members=members,
                rels=[f"{proto[0].id} lets attacker JSON reach a deep-merge sink",
                      *([f"{sinks[0].id} is a sink a pollution gadget could reach"]
                        if sinks else [])],
                rationale=("Attacker-controlled data reaches a recursive merge; if a "
                           "gadget property is read by app/library code, it can "
                           "escalate to XSS or an authorization bypass."),
                verify=["Send ?__proto__[x]=1 style input into the merge source; confirm ({}).x.",
                        "Identify a gadget the app reads; chain to a concrete impact."])

    chains.sort(key=lambda ch: ch.confidence, reverse=True)
    return chains
