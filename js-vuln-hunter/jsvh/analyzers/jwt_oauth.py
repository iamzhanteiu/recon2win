"""JWT / OAuth / OIDC and token-handling analysis (mission §11).

We do NOT flag ordinary JWT decoding as a vulnerability. We surface three
verifiable concerns:

  1. **Token storage** — access/refresh/id tokens written to localStorage/
     sessionStorage (readable by any XSS in the origin), vs. httpOnly cookies.
  2. **Client-side trust of token claims** — the app decodes a JWT and reads
     claims like ``role``/``isAdmin``/``scope`` to make an authorization
     decision *in the browser* (server enforcement unverified).
  3. **OAuth/OIDC redirect handling** — ``redirect_uri`` built from a client
     value, or a flow missing ``state`` / (where relevant) PKCE.

All are candidates with verification plans, never confirmations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import ast_engine as A

# token-ish names, storage sinks, decode calls, claim reads
_TOKEN_NAME = ("accesstoken", "access_token", "refreshtoken", "refresh_token",
               "idtoken", "id_token", "jwt", "bearer", "authtoken", "auth_token",
               "sessiontoken", "apitoken", "credential")
_STORAGE_SET = ("localStorage.setItem", "sessionStorage.setItem")
_JWT_DECODE = ("jwt_decode", "jwtDecode", "jwt.decode", "decodeJwt",
               "parseJwt", "decodeToken")
_CLAIM_AUTHZ = ("role", "roles", "isadmin", "is_admin", "scope", "scopes",
                "permission", "permissions", "admin", "superuser", "priv")
_OAUTH_PARAM = ("redirect_uri", "redirecturi", "response_type", "client_id",
                "client_secret", "code_challenge", "code_verifier", "state",
                "nonce", "grant_type", "id_token", "access_token")


@dataclass
class TokenFinding:
    kind: str                 # token-storage | jwt-claim-trust | oauth-redirect | oauth-state
    detail: str
    location: dict | None
    evidence: str
    attacker_controlled: str = "unknown"


def _low(s: str | None) -> str:
    return (s or "").lower()


def _string_or_name(node: Any) -> str:
    v = A.string_value(node)
    if v is not None:
        return v
    return A.member_name(node)


def analyze(pm: A.ParsedModule) -> list[TokenFinding]:
    if not pm.ok:
        return []
    out: list[TokenFinding] = []
    seen: set[tuple] = set()

    def add(kind, detail, node, evidence, attacker="unknown"):
        loc = A.loc_of(node)
        key = (kind, detail, (loc or {}).get("line"))
        if key in seen:
            return
        seen.add(key)
        out.append(TokenFinding(kind=kind, detail=detail, location=loc,
                                evidence=evidence, attacker_controlled=attacker))

    for node in A.walk(pm.ast):
        t = getattr(node, "type", None)
        if t != "CallExpression":
            continue
        name = A.call_name(node) or ""
        base = name.rsplit(".", 1)[-1]
        args = list(getattr(node, "arguments", []) or [])

        # 1. token storage: localStorage.setItem('access_token', tok)
        if name in _STORAGE_SET or base == "setItem":
            key_arg = _low(A.string_value(args[0])) if args else ""
            val_name = _low(A.member_name(args[1])) if len(args) > 1 else ""
            if any(tn in key_arg for tn in _TOKEN_NAME) or any(tn in val_name for tn in _TOKEN_NAME):
                store = name.split(".")[0] if "." in name else "webStorage"
                add("token-storage",
                    f"token written to {store} (key='{A.string_value(args[0]) if args else '?'}')",
                    node, f"{name}(...)")

        # 2. client-side JWT claim trust: role = decodeJwt(...).role used in authz
        if name in _JWT_DECODE or base in {d.rsplit('.', 1)[-1] for d in _JWT_DECODE}:
            # look at how the decoded value is used in the enclosing statement:
            # is a claim read that smells like authorization?
            claims = _claims_read_near(node)
            if claims:
                add("jwt-claim-trust",
                    f"client reads JWT claim(s) {sorted(claims)} after {base}(...)",
                    node, f"{base}(...) → {sorted(claims)}")
            else:
                add("jwt-decode", f"client-side {base}() (informational)", node, f"{base}(...)")

        # 3. OAuth redirect / param handling
        low_name = _low(name)
        if base in ("assign", "replace") and "location" in low_name or base == "open":
            # navigation whose target mentions oauth params + a client value
            joined = " ".join(_string_or_name(a) for a in args).lower()
            if ("redirect_uri" in joined or "response_type" in joined or
                    ("oauth" in joined and "{" in joined)):
                attacker = "yes" if "{" in joined and "redirect_uri" in joined else "unknown"
                add("oauth-redirect",
                    "OAuth navigation with a client-built redirect/params", node,
                    joined[:100], attacker)

    # 4. OAuth param inventory over string literals (state/PKCE presence check)
    oauth_ctx = _oauth_context(pm)
    if oauth_ctx["is_oauth"]:
        missing = []
        if not oauth_ctx["has_state"]:
            missing.append("state (CSRF protection)")
        if oauth_ctx["response_type_token"] and not oauth_ctx["has_pkce"]:
            missing.append("PKCE (implicit/token flow)")
        if missing:
            out.append(TokenFinding(
                kind="oauth-state",
                detail="OAuth flow appears to omit: " + ", ".join(missing),
                location=None,
                evidence="oauth params seen: " + ", ".join(sorted(oauth_ctx["params"])),
            ))
    return out


def _claims_read_near(decode_node: Any) -> set[str]:
    """After a jwt decode, is an authorization-relevant claim read?

    Cheap heuristic: scan sibling member accesses in the same statement chain
    for ``.role`` / ``.isAdmin`` / ``.scope`` style reads. Runs on the whole
    module (decodes are rare) but only keeps authz-flavoured claim names.
    """
    found: set[str] = set()
    # walk the parent expression is hard without parent links; instead scan
    # the whole tree for MemberExpression whose property is a claim name — a
    # decode being present at all is the gate that makes this meaningful.
    for n in A.walk(decode_node):
        if getattr(n, "type", None) == "MemberExpression":
            prop = A.member_name(n).rsplit(".", 1)[-1].lower()
            if prop in _CLAIM_AUTHZ:
                found.add(prop)
    return found


def _oauth_context(pm: A.ParsedModule) -> dict:
    params: set[str] = set()
    for node in A.walk(pm.ast):
        if getattr(node, "type", None) == "Literal" and isinstance(getattr(node, "value", None), str):
            v = node.value.lower()
            for p in _OAUTH_PARAM:
                if p in v:
                    params.add(p)
    is_oauth = bool(params & {"redirect_uri", "response_type", "client_id",
                              "code_challenge", "grant_type"})
    return {
        "is_oauth": is_oauth,
        "params": params,
        "has_state": "state" in params or "nonce" in params,
        "has_pkce": "code_challenge" in params or "code_verifier" in params,
        "response_type_token": "access_token" in params or "id_token" in params,
    }
