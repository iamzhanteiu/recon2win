# js-vuln-hunter

A production-quality workspace for **JavaScript vulnerability research**,
built as the analysis layer **on top of [recon2win](../README.md)**.

> recon2win is the upstream reconnaissance engine. This workspace does
> **not** duplicate any reconnaissance (no subdomain/DNS/port/crawl/httpx/
> nuclei). It consumes recon2win's `outputs/<domain>/` datasets and turns
> the discovered JavaScript into ranked, verifiable vulnerability
> candidates.

```
recon2win  ──recon data──▶  js-vuln-hunter
                                │
   ingest ▸ acquire ▸ fingerprint ▸ AST ▸ analyzers ▸ data-flow
                                │
                 candidates ▸ ranking ▸ verification plans ▸ findings
```

## Why it exists

recon2win already finds *where* the JavaScript is (and even mines endpoints/
secrets with jsluice). What it does not do is reason about **JS
vulnerabilities**: which `location.hash` reaches which `innerHTML`, through
what sanitizer; which merge is reachable by attacker JSON; which
`postMessage` handler skips origin validation; which client-side `isAdmin`
gate is the only control. That reasoning is this workspace.

## Install

```bash
cd js-vuln-hunter
python3 -m pip install -r requirements.txt   # esprima (pure-Python JS parser)
```

Uses the sibling recon2win `../outputs/` by default; override with
`--outputs`.

## Quick start

```bash
# 1. check the recon2win input contract for a target
python3 jsvh.py validate omnicell.com

# 2. build the JS inventory only (no analysis)
python3 jsvh.py ingest omnicell.com

# 3. full pipeline → ranked candidates + verification plans + artifacts
python3 jsvh.py run omnicell.com

# 4. re-print the top candidates from the last run
python3 jsvh.py top omnicell.com

# 5. print the verification plan for one candidate
python3 jsvh.py plan omnicell.com js_000123-c001
```

By default `run` reuses the JS bodies recon2win already downloaded
(`raw/jsluice/*.js`) — zero duplication, exact analysed bytes. Add `--net`
to also fetch the discovered-but-uncached long tail (often WAF-blocked).

### Useful flags

| Flag | Effect |
|---|---|
| `--outputs PATH` | recon2win `outputs/` dir (default `../outputs`) |
| `--project NAME` | recon2win `-p` project grouping |
| `--net` | network-fetch JS not cached by recon2win |
| `--no-acquire` | analyze already-acquired JS only |
| `--max-assets N` | cap assets analysed (fast smoke runs) |
| `--max-parse N` | AST-parse byte cap (default 150000; larger → regex fallback) |

## Outputs

Per target, under `output/<target>/`:

| File | Contents |
|---|---|
| `javascript_inventory.json` | every JS asset + recon/analysis metadata |
| `endpoint_inventory.json` | endpoints resolved from JS (incl. dynamic) |
| `dataflow.json` | source→sink data-flow records |
| `vulnerability_candidates.json` | ranked candidates |
| `source_sink_map.json` | source-kind × sink-kind rollup |
| `attack_surface.json` | per-host asset/framework/candidate rollup |
| `attack_chains.json` | correlated candidates → attack chains (§14) |
| `TOP_CANDIDATES.txt` | the high-signal shortlist (mission §19) |
| `VERIFICATION_QUEUE.txt` | prioritized "what to test first" queue (§17) |
| `validation.md` | recon2win input-contract report |

Each candidate carries a structured **exploitability** block (§15) — who
controls the input, which security boundary is crossed, impact, why it's
interesting, why it's not obviously a false positive, and what evidence is
still missing.

Verification plans for P1/P2 candidates land in
`candidates/new/<target>/<id>.md`. Move them through
`candidates/{investigating,verification,verified,false-positive}/` as you
work them; write `findings/FINDING-XXX/` only after `VERIFIED`.

## What it detects

DOM XSS (taint-tracked source→sink + sanitizer classification), code
injection (`eval`/`Function`/string-timer), prototype pollution (reachable
deep-merge, with class-extension false positives suppressed), postMessage
(origin-validation strength: none/weak/strict + wildcard sender),
client-side authorization gates, **BOLA/IDOR** (client-controlled object id)
and **BFLA** (privileged function) candidates, sensitive/dynamic API
endpoints, open redirects, **JWT/OAuth/OIDC** (insecure token storage,
client-side claim trust, OAuth redirect / missing state/PKCE), **classified
secrets** (credential/token/config vs. publishable public-id), **source-map
exposure**, and WebSocket usage. Candidates are correlated into **attack
chains** and each ships a structured **exploitability** assessment and a
verification plan. See `knowledge/` and `docs/vulnerability-engine-audit.md`.

## Layout

```
js-vuln-hunter/
├── jsvh.py                CLI entry
├── jsvh/                  package
│   ├── ingest/            recon2win loader/validator/adapter/normalizer
│   ├── analyzers/         source/sink/dataflow/endpoints/…/patterns
│   ├── ast_engine.py      esprima AST + walker + helpers
│   ├── acquire.py         reuse recon2win bodies (+ optional net)
│   ├── fingerprint.py     framework/bundler/source-map
│   ├── candidates.py      candidate engine + ranking
│   ├── exploitability.py  structured exploitability + priority (§15)
│   ├── chains.py          attack-chain correlation (§14)
│   ├── verification.py    per-type verification plans
│   ├── report.py          artifacts + top-candidates + verification queue
│   └── pipeline.py        orchestration
├── docs/                  architecture, recon2win-integration, data-model, methodology
├── knowledge/             per-class research notes
├── schemas/               JSON Schemas for every artifact
├── candidates/            lifecycle dirs (new→verified/false-positive)
├── findings/              verified findings (FINDING-XXX)
├── targets/<t>/raw/       acquired JS bodies
└── output/<t>/            generated artifacts
```

## Known limitations

Honest accounting — these shape how to read the output:

- **Bundled libraries.** Third-party files served from a known CDN/lib name
  are demoted to P3. But a library (jQuery, etc.) **bundled inside an app
  webpack chunk** (`dist/9755.js`) cannot be told apart from app code
  cheaply, so its internal `location.hash → $(...).append` patterns still
  appear as candidates. Treat DOM-XSS in a large minified chunk as "confirm
  it's reachable from *your* code path" before trusting it.
- **esprima is ES2017-era.** The pure-Python parser (v4.0.1) predates
  optional chaining / nullish coalescing / BigInt, so modern un-transpiled
  bundles fail to parse and fall back to the (lower-confidence) regex scan.
  `assets_parse_failed` in the run meta tells you how often.
- **Intra-file, scope-aware taint.** Data-flow is tracked within one file to
  a fixpoint, keyed by lexical scope so minified name reuse across functions
  can't manufacture cross-function flows. Cross-file and inter-procedural
  flow is left to manual verification. `attacker_controlled` is `yes` only
  when the source→sink chain shares a scope chain; otherwise it is honestly
  `unknown` (a lead to check, not a claim).
- **Speed vs. depth.** Files above `--max-parse` (150KB default) use the
  regex scan, not AST — raise it for depth at the cost of runtime.
- **Static, not dynamic.** Every output is a *candidate*. Confidence is
  static confidence, never confirmation. Verify before reporting.

## Next improvements

- Sub-file library-boundary detection (strip vendored code from bundles).
- A newer parser (tree-sitter / a Node-based acorn sidecar) to raise the
  AST hit-rate on modern syntax.
- Source-map-aware analysis: map minified sinks back to original source.
- Cross-file taint via a lightweight module graph.
- Consume recon2win `all_urls.jsonl` provenance to weight ranking by source
  quality; correlate resolved endpoints against recon2win's live URL set.

## Golden rule

```
Static Analysis → Candidate → Verification → Confirmed Vulnerability
```

Never `Static Analysis → Confirmed Vulnerability`. Every candidate ships
with a verification plan; nothing is a finding until a request/PoC proves
it. See `docs/methodology.md`.
