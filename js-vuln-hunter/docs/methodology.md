# Methodology

The workspace encodes one rule above all others (mission §14):

```
Static Analysis → Candidate → Verification → Confirmed Vulnerability
```

Never `Static Analysis → Confirmed Vulnerability`.

## The funnel

```
recon2win JS assets
   → inventory (what JS exists, HTTP-verified)
   → AST feature extraction (sources, sinks, calls, endpoints, literals)
   → data-flow correlation (which source reaches which sink, sanitized how)
   → candidates (only where evidence is meaningful)
   → ranking (P1 first, confidence-weighted)
   → verification plans (exact steps to confirm each)
   → manual verification (you send the request / build the PoC)
   → finding + report
```

## Prioritization (mission §18)

- **P1** — authorization bypass, sensitive API exposure, DOM XSS with a
  clear attacker-controlled source, prototype pollution with a reachable
  source, token/credential exposure, privileged postMessage.
- **P2** — interesting API endpoints, WebSocket authz, open redirects,
  sensitive source maps, client-side security-boundary weaknesses.
- **P3** — informational endpoints, fingerprints, low-confidence secrets,
  generic library findings.

## High-signal rule (§19)

Do not produce thousands of regex matches. Emit a ranked shortlist of
candidates with real evidence. The tool optimizes for **HIGH SIGNAL / LOW
NOISE / FAST VERIFICATION / REAL IMPACT**.

## Client-side authorization — special handling

A client-side `isAdmin` / `role` / `permission` check is **never**
auto-classified as privilege escalation. It is a *candidate* whose entire
value is telling apart two cases only a request can distinguish:

1. the gate is cosmetic and the server re-enforces it → **FALSE_POSITIVE**;
2. the gate is the only control and the API answers a low-priv replay →
   **real authorization bypass**.

The generated plan replays the guarded endpoint directly (bypassing JS).

## Verification is where value is created

Each P1/P2 candidate gets `candidates/new/<target>/<id>.md` — a concrete,
type-specific plan (payload to try, request to send, positive-result
criteria). Move the file through `candidates/{investigating,verification,
verified,false-positive}/` as you work it. Only after `VERIFIED` do you
write a `findings/FINDING-XXX/` from the finding template.
