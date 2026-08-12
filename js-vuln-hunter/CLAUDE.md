# CLAUDE.md — js-vuln-hunter operating rules

This workspace is the **JavaScript vulnerability analysis layer on top of
recon2win**. It is NOT a second reconnaissance platform.

## Hard rules

1. **Never run reconnaissance here.** No subfinder/amass/httpx/nuclei/
   katana/gau/waymore/dirsearch/ffuf. Domains, subdomains, URLs, alive
   hosts, HTTP metadata, JS URLs, tech fingerprints, crawl/historical URLs
   are all **owned by recon2win** and consumed as-is.
2. **When given a recon2win dataset, do NOT ask to re-run recon.** Instead:
   inspect recon2win output → load JS assets → build inventory → analyze JS
   → generate candidates → rank → generate verification plans → help verify
   the highest-value candidates.
3. **Missing upstream data is reported, never regenerated.** Say exactly:
   `Missing upstream data: <exact data>`. Do not silently substitute
   another recon pipeline.
4. **Static analysis produces candidates, not confirmed bugs.** Every
   high-value candidate needs a verification plan. `Static Analysis →
   Candidate → Verification → Confirmed Vulnerability`.
5. **Client-side authz is a candidate, never auto-classified as privilege
   escalation.** Generate a verification plan (replay the guarded endpoint).
6. **High signal, low noise.** No thousand-line regex dumps. Emit ranked
   candidates with real evidence and honest confidence.

## Where recon2win data lives

`../outputs/<domain>/` (or `../outputs/<project>/<domain>/`). The detected
input contract is in `docs/recon2win-integration.md`. The only module that
knows recon2win's on-disk layout is `jsvh/ingest/loader.py`.

## Workflow when asked to hunt on a target

```
python3 jsvh.py validate <target>     # confirm the input contract
python3 jsvh.py run <target>          # inventory → candidates → plans
python3 jsvh.py top <target>          # the shortlist to work
python3 jsvh.py plan <target> <id>    # per-candidate verification plan
```

Then help the user verify the top candidates by hand (build the request,
craft the payload, judge the result), and only after a candidate is
VERIFIED, draft `findings/FINDING-XXX/finding.md`.

## Priority (§18)

P1: authz bypass, sensitive API exposure, DOM XSS w/ clear source,
prototype pollution w/ reachable source, token/credential exposure,
privileged postMessage. P2: interesting endpoints, WebSocket authz, open
redirect, source-map exposure. P3: informational / low-confidence.

## Language

Respond in **Vietnamese** by default (inherited from the parent recon2win
project); keep code, payloads, HTTP, CVE/vuln names, paths in English.

## Docs to keep in sync

`README.md`, `docs/architecture.md`, `docs/recon2win-integration.md`,
`docs/data-model.md`, `docs/methodology.md`. Update them when the code or
the recon2win contract changes; verify claims against the source before
writing them.
