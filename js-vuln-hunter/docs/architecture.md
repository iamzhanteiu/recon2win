# Architecture

This workspace is the **JavaScript vulnerability analysis layer** on top of
recon2win. recon2win discovers the attack surface; this workspace turns the
JavaScript in that surface into ranked, verifiable vulnerability candidates.
It performs **no reconnaissance**.

```
                    recon2win
                        │  reconnaissance data (outputs/<domain>/)
                        ▼
        ┌───────────────────────────────────┐
        │  JS Vulnerability Research Workspace │
        └───────────────────────────────────┘
                        │
   ingest ─▶ acquire ─▶ fingerprint ─▶ AST parse
                        │
        ┌───────────────┼─────────────────────────────┐
        ▼               ▼                              ▼
   sources/sinks    endpoints                    postMessage / proto-
        │           auth / secrets               pollution / websocket
        ▼               │                              │
   data-flow ──────────┴──────────────────────────────┘
        ▼
   candidate engine ─▶ exploitability ─▶ ranking ─▶ attack-chain
        ▼                                              correlation
   verification plans ─▶ verification queue ─▶ findings
```

## Pipeline stages (`jsvh/pipeline.py`)

| Stage | Module | Responsibility |
|---|---|---|
| Ingest | `ingest/loader,validator,adapter,normalizer` | read recon2win, validate contract, normalize to `JSAsset`, dedupe |
| Acquire | `acquire.py` | reuse recon2win's cached JS bodies; `--net` for the uncached tail |
| Fingerprint | `fingerprint.py` | framework / bundler / source-map / minified |
| Parse | `ast_engine.py` | esprima AST; regex fallback for oversized/minified |
| Analyze | `analyzers/*` | source, sink, data-flow, endpoints (+object-id/BFLA), secrets (classified), postMessage (origin strength), prototype-pollution, auth, websocket, jwt_oauth, sourcemap |
| Candidates | `candidates.py` | evidence → `Candidate`s (incl. BOLA/BFLA/JWT/OAuth/source-map) |
| Exploitability | `exploitability.py` | structured who-controls/boundary/impact + reasoned priority (§15) |
| Rank + correlate | `candidates.rank`, `chains.py` | dedup/cap ranking, then attack-chain correlation (§14) |
| Verify | `verification.py` | per-type verification plan + exploitability/chain sections (§14) |
| Report | `report.py` | JSON artifacts + Top-Candidates + Verification Queue (§17) |

## Design decisions

- **AST-first, regex-fallback.** esprima (pure-Python) parses real
  compiled/bundled JS. Raw TS/JSX and files above `max_parse_bytes` fall
  back to a bounded regex scan so no asset is dropped, but at explicitly
  lower confidence — ranking prefers proven AST flows.
- **Scope-aware intra-file taint.** The data-flow engine propagates taint
  across local assignments to a fixpoint within one file, keyed by **lexical
  scope** (`(scope_id, name)`) so a variable tainted in one function is
  visible only in that function and its descendants — never a sibling. This
  was added after verification of a real candidate exposed a false positive:
  minified code reuses one-letter/`options` names across unrelated functions,
  and name-only taint had leaked `location.search` from a query-param helper
  into an unrelated widget's `innerHTML`. Inter-procedural / cross-file flow
  is still left to manual verification — the tool optimizes for honest
  recall, not false precision.
- **Reasoned priority, not pattern class (§15).** `exploitability.py` derives,
  per candidate, who controls the input, which security boundary is crossed,
  impact, user interaction, cross-origin, reachability, and what evidence is
  still missing — then *refines* priority from that reasoning. An unresolved-
  provenance `innerHTML` is a P2 lead, not a P1 claim; a proven attacker→sink
  flow with no sanitizer is P1.
- **Correlation over isolation (§14).** `chains.py` groups ranked candidates
  per host (same-origin trust surface) and correlates them into attack chains
  (BOLA/BFLA authorization, cross-origin message → privileged action, token
  exposure + sensitive API, reachable prototype pollution). Chains, not lone
  patterns, top the verification queue.
- **Everything is a candidate.** Static analysis never emits a "confirmed"
  bug. Every candidate carries a `verification_status` and a plan (§14).
- **Zero recon duplication.** No subfinder/httpx/nuclei/crawl here. Missing
  upstream data is reported, never regenerated (§2/§17).
- **High signal.** Known-safe sanitized flows are suppressed; confidence
  reflects how much of the source→sink chain was proven statically (§19).

## What the workspace owns vs. what recon2win owns

| recon2win (recon metadata) | this workspace (analysis metadata) |
|---|---|
| domains, subdomains, hosts, URLs | asset sha256/size, framework/bundler |
| HTTP status/content-type/tech | source→sink data-flows |
| discovered JS URLs + bodies | endpoint resolution, taint, candidates |
| jsluice secrets/endpoints/params | candidate ranking + verification plans |
