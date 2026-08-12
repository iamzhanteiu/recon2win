"""Verification-plan generator.

Mission §14: static analysis produces *candidates*, never confirmed bugs.
Every high-value candidate gets a concrete, type-specific plan describing
exactly how a human turns it into a confirmed finding — the request to
send, the payload to try, and what a positive result looks like.
"""

from __future__ import annotations

from .models import Candidate


_PLANS = {
    "DOM-XSS": [
        "1. Open the asset URL in a browser with devtools open.",
        "2. Locate the sink `{sink}` (source map / pretty-print if minified).",
        "3. Drive the source `{source}` with a probe, e.g. append "
        "`#<img src=x onerror=alert(document.domain)>` to the URL (hash) or "
        "the matching query param.",
        "4. Confirm the payload reaches `{sink}` unescaped and executes.",
        "5. If a sanitizer is present ({sanitization}), test known bypasses for "
        "that specific sanitizer before discarding.",
        "6. Capture: request URL, rendered DOM, alert screenshot.",
    ],
    "CODE-INJECTION": [
        "1. Identify what feeds `{sink}` ({source}).",
        "2. Craft input that breaks out into executable context "
        "(e.g. `');alert(document.domain)//`).",
        "3. Confirm execution (alert / DNS callback).",
        "4. Capture request + execution evidence.",
    ],
    "PROTOTYPE-POLLUTION": [
        "1. Find the input feeding `{sink}` (URL param / JSON body / query string).",
        "2. Send `?__proto__[jsvhTest]=polluted` (and `constructor[prototype][jsvhTest]`).",
        "3. In devtools console check `({}).jsvhTest === 'polluted'`.",
        "4. If polluted, find a gadget (a property the app reads) to escalate "
        "to XSS / auth bypass; document the gadget.",
    ],
    "POSTMESSAGE-XSS": [
        "1. Host an attacker page that `window.open`s / iframes the target.",
        "2. `postMessage` a payload matching the handler's expected shape.",
        "3. Since origin is not validated, confirm the payload reaches "
        "`{sink}` and executes.",
        "4. Capture the attacker page + result.",
    ],
    "CLIENT-SIDE-AUTHZ": [
        "1. Note this is a CLIENT-side check on `{title}` — NOT yet a vuln.",
        "2. Identify the endpoint it guards: {endpoint}",
        "3. As a low-privilege (or unauthenticated) user, replay that request "
        "directly (curl/Burp), bypassing the JS gate.",
        "4. If the server returns privileged data / performs the action, it is "
        "a real authorization bypass. If it returns 401/403, the gate is "
        "cosmetic only — mark FALSE_POSITIVE.",
    ],
    "SENSITIVE-API": [
        "1. Resolve the full URL for `{endpoint}` (fill dynamic segments).",
        "2. Probe with correct method `{sink}`; test authn/authz "
        "(no token, other user's token, IDOR on ids).",
        "3. Check for verbose errors, debug data, missing access control.",
    ],
    "BOLA": [
        "1. Authenticate as user A; capture the `{sink}` request to `{endpoint}`.",
        "2. Note the client-controlled object id(s): {object_id}.",
        "3. Replay swapping the id for user B's object (and unauth), keeping A's session.",
        "4. If B's data is returned / mutated, it is a BOLA/IDOR. If 401/403, "
        "the object authz is enforced server-side — mark FALSE_POSITIVE.",
        "5. Capture both requests + responses.",
    ],
    "BFLA": [
        "1. As a NORMAL (non-admin) user, replay the `{sink}` call to `{endpoint}`.",
        "2. This is a privileged/mutating function — confirm the server checks "
        "function-level authorization, not just the client.",
        "3. If it executes for a normal user, it is a BFLA / privilege escalation.",
    ],
    "OAUTH-REDIRECT": [
        "1. Map the OAuth/OIDC flow (authorize URL, redirect_uri, response_type).",
        "2. Test redirect_uri tampering (open-redirect / token exfiltration) and "
        "state/nonce presence + validation (CSRF).",
        "3. For implicit/token flows, confirm whether PKCE is used.",
        "4. Do not steal a real user's token — prove the flaw with your own account.",
    ],
    "JWT-TRUST": [
        "1. Locate where the client decodes the JWT and reads the claim(s) noted.",
        "2. Confirm whether an authorization/UI decision is made from those claims.",
        "3. Tamper the (client-held) token's claims and see if privileged UI/paths unlock.",
        "4. The real bug is only confirmed if the SERVER also trusts the tampered "
        "claim — replay a guarded request with the tampered token.",
    ],
    "TOKEN-STORAGE": [
        "1. Confirm the token is written to localStorage/sessionStorage (not httpOnly cookie).",
        "2. Show it is readable via `localStorage` in the console (any XSS reads it).",
        "3. Impact is conditional on an XSS/injection in the origin — pair with a "
        "DOM-XSS candidate if one exists.",
    ],
    "SOURCE-MAP-EXPOSURE": [
        "1. Fetch the map (`.map` next to the bundle, or decode the inline data: map).",
        "2. Extract original sources: internal endpoints, comments, debug funcs, config.",
        "3. Feed newly-revealed endpoints/logic back into analysis; prioritise any "
        "secrets or security logic disclosed.",
    ],
    "OPEN-REDIRECT": [
        "1. Drive `{source}` into `{sink}` with `//evil.example`, "
        "`https://evil.example`, and `/\\evil.example`.",
        "2. Confirm the browser navigates off-origin.",
    ],
    "SECRET-EXPOSURE": [
        "1. Recover the full secret from the JS (this report redacts it).",
        "2. Validate it is live and scoped to something sensitive "
        "(call the API it authenticates).",
        "3. Do NOT use it beyond a benign read to prove validity; document scope.",
    ],
    "WEBSOCKET": [
        "1. Connect to `{endpoint}` and observe the message protocol.",
        "2. Test whether authz is enforced per-message or only at connect.",
        "3. Try privileged commands as a low-priv user.",
    ],
    "POSTMESSAGE-WILDCARD": [
        "1. Confirm sensitive data is posted to `*`.",
        "2. Register a listener from a foreign origin and capture the data.",
    ],
}

_GENERIC = [
    "1. Reproduce the code path in a browser / proxy.",
    "2. Drive the source with a probe payload.",
    "3. Confirm impact and capture request/response evidence.",
]


def plan_for(c: Candidate) -> str:
    steps = _PLANS.get(c.type, _GENERIC)
    ctx = {
        "{sink}": c.sink or "the sink",
        "{source}": c.source or "the source",
        "{sanitization}": c.sanitization,
        "{endpoint}": c.endpoint or "(unresolved — resolve from the JS)",
        "{object_id}": c.object_id or "(the client-controlled id)",
        "{title}": c.title,
    }

    # Explicit replacement, NOT str.format: both the templates (e.g. the JS
    # snippet `({}).jsvhTest`) and the data-derived values (URL templates like
    # `{baseURL}/api/...`) legitimately contain braces that str.format would
    # misread as fields.
    def fill(s: str) -> str:
        for k, v in ctx.items():
            s = s.replace(k, str(v))
        return s

    body = "\n".join(fill(s) for s in steps)

    ex = c.exploitability
    exploit_md = ""
    if ex:
        missing = "\n".join(f"  - {m}" for m in ex.missing_evidence) or "  - (none noted)"
        exploit_md = (
            f"\n## Exploitability (§15)\n"
            f"- **Who controls the input:** {ex.who_controls}\n"
            f"- **Auth required:** {ex.auth_required}   "
            f"**User interaction:** {ex.user_interaction}\n"
            f"- **Security boundary:** {ex.boundary}\n"
            f"- **Cross-origin:** {ex.cross_origin}   "
            f"**Reachability:** {ex.reachability}\n"
            f"- **Exploitability / Impact:** {ex.exploitability} / {ex.impact}\n"
            f"- **Why interesting:** {ex.why_interesting}\n"
            f"- **Why not obviously a false positive:** {ex.why_not_fp}\n"
            f"- **Missing evidence:**\n{missing}\n"
        )

    chains_md = (f"\n## Attack chains\nPart of: {', '.join(c.chain_ids)}\n"
                 if c.chain_ids else "")

    return (
        f"# Verification plan — {c.id}\n\n"
        f"- **Type:** {c.type}  ({c.priority} / {c.severity})\n"
        f"- **Asset:** {c.url}\n"
        f"- **Confidence (static):** {c.confidence:.0%}\n"
        f"- **Source → Sink:** {c.source} → {c.sink}\n"
        f"- **Attacker-controlled:** {c.attacker_controlled}   "
        f"**Sanitization:** {c.sanitization}\n"
        f"- **Evidence:** `{c.evidence}`\n"
        f"- **Location:** {c.location}\n"
        f"{exploit_md}{chains_md}\n"
        f"## Steps\n{body}\n\n"
        f"## Verdict\n- [ ] VERIFIED   - [ ] FALSE_POSITIVE\n"
    )
