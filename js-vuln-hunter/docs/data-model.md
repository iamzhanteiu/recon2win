# Data Model

All internal objects are dataclasses in `jsvh/models.py`; JSON Schemas in
`schemas/` are the authority on shape. Every object has `to_dict()` so the
`output/` artifacts stay stable and diff-friendly.

## JSAsset (`schemas/asset.json`, `schemas/javascript.json`)

One row per distinct JS URL recon2win knows about. Split into recon
metadata (mirrors upstream) and analysis metadata (owned here).

| field | owner | meaning |
|---|---|---|
| `asset_id` | jsvh | `js_000123`, stable per target (canonical-URL sort order) |
| `target`,`host`,`url` | recon2win | identity |
| `source` | jsvh | `recon2win` / `recon2win-raw` |
| `provenance` | recon2win | tools that saw the URL (`all_urls.jsonl`) |
| `status_code`,`content_type`,`content_length` | recon2win | httpx/jsluice fetch detail |
| `sha256`,`size`,`local_path` | jsvh | acquired body |
| `framework`,`bundler`,`source_map`,`minified` | jsvh | fingerprint |
| `analysis_status` | jsvh | pending→acquired→analyzed / regex_scan / parse_error / error |

## Endpoint (`schemas/endpoint.json`)

An API call resolved out of JS — including dynamically-constructed URLs
rebuilt from concatenation/templates.

`{endpoint_id, asset_id, method, url_template, kind(rest|graphql|websocket),
dynamic, parameters[], auth_hint, interesting, object_ids[], sensitive_op,
location}`

`url_template` keeps dynamic pieces as `{name}` placeholders, e.g.
`{baseURL}/api/admin/users/{userId}`. `object_ids` are the client-controlled
identifier segments (the BOLA lever); `sensitive_op` marks a mutating verb or
a privileged/sensitive path (the BFLA lever).

## DataFlow (`schemas/dataflow.json`)

The core record: `SOURCE → transforms → sanitization → SINK`.

`{flow_id, asset_id, source, source_kind, sink, sink_kind, transforms[],
attacker_controlled(yes|no|unknown), sanitization(none|weak|known-safe|unknown),
source_location, sink_location, evidence}`

## Candidate (`schemas/candidate.json`)

`{id, type, priority(P1|P2|P3), severity, confidence(0..1), asset_id, url,
title, source, sink, attacker_controlled, sanitization, evidence, location,
flow_id, endpoint, method, object_id, verification_status, rank_score,
exploitability{…}, chain_ids[], notes[]}`

Candidate types: `DOM-XSS`, `CODE-INJECTION`, `PROTOTYPE-POLLUTION`,
`POSTMESSAGE-XSS`, `POSTMESSAGE-WILDCARD`, `OPEN-REDIRECT`, `SENSITIVE-API`,
`CLIENT-SIDE-AUTHZ`, `BOLA`, `BFLA`, `SECRET-EXPOSURE`, `JWT-TRUST`,
`TOKEN-STORAGE`, `OAUTH-REDIRECT`, `SOURCE-MAP-EXPOSURE`, `WEBSOCKET`.

Lifecycle: `NEW → TRIAGED → INVESTIGATING → VERIFICATION_REQUIRED →
VERIFIED` or `FALSE_POSITIVE`. Mirrored by the `candidates/<state>/` dirs.

## Exploitability (`schemas/candidate.json` → `exploitability`)

Structured reasoning attached to every candidate (§15):
`{who_controls, auth_required, boundary, impact, exploitability(low|medium|
high), user_interaction, cross_origin, reachability, why_interesting,
why_not_fp, missing_evidence[]}`. This is what refines the candidate's
priority — reasoned risk, not raw pattern class.

## AttackChain (`schemas/attack_chain.json`)

Correlated observations forming one high-value hypothesis (§14):
`{chain_id, name, impact, confidence(0..1), priority, observations[](candidate
ids), relationships[], rationale, verification[]}`. Written to
`attack_chains.json`; candidates back-reference their chains via `chain_ids`.

## Confidence semantics

Confidence is the **static** confidence that the source→sink chain is real
and exploitable — never a claim of confirmation. It rises with proven
attacker-control and absent/weak sanitization, and falls when a known-safe
sanitizer is present or the flow was only inferred by regex. Verification
(a real request/PoC) is what turns a candidate into a finding.
