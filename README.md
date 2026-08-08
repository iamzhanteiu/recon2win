# recon-agent

Automated recon framework that follows a strict 9-stage workflow
(0 → 9) modelled on the `recon.html` diagram.

## Workflow

```
0. Validate domain & create output/<domain>/ folder
1. Subdomain collection  (subfinder, amass, chaos)   → processed/hosts/subdomains.txt
2. DNS resolution        (dnsx)                      → processed/hosts/resolved.txt + resolved_detail.json
3. HTTP alive check      (httpx)                     → processed/hosts/alive.txt + alive_detail.{json,csv}
   + optional screenshots (httpx -screenshot, off by default: httpx.screenshot.enabled) → processed/hosts/screenshots_index.json
4. PARALLEL — dirsearch/ffuf are fuzz_depth-aware: each selected host is
   tiered deep/standard/light (hostname score + httpx -td tech signal) and
   "deep" hosts get an extra merged wordlist + their own time-slice
   ├─ 4.1  katana + urlfinder + gau collection       → raw/{katana,urlfinder,gau}_urls.txt
   ├─ 4.2  dirsearch (SecLists wordlists +/or sensitive ext) → processed/sources/dirsearch_urls.txt
   ├─ 4.3  ffuf (-ac/-ach + recursive dirs, per host) → processed/sources/ffuf_urls.txt
   └─ 4.4  waymore (archived URLs + JS)              → processed/sources/waymore_urls.txt
5. Merge                                                    → processed/corpus/all_urls.txt
   + processed/corpus/js_urls.txt, processed/corpus/dynamic_urls.txt
   + mine new in-scope subdomains from URLs → processed/hosts/url_derived_subdomains.txt
6. PARALLEL
   ├─ 6.1  httpx on all_urls.txt                    → processed/hosts/alive_urls.txt
   ├─ 6.2  xnLinkFinder on js_urls.txt (regex)      → processed/js/xnlinkfinder_{endpoints,urls}.txt
   ├─ 6.3  jsluice on js_urls.txt (AST)             → processed/js/jsluice_{endpoints,urls}.txt
   │                                                   + findings/jsluice_secrets.json
   └─ 6.4  api-docs probe + OSINT                   → processed/sources/apidocs_{urls,params}.txt
           (wildcard-dedup + tech-aware paths; follows swagger-ui/redoc     + findings/api_docs.json
            UIs to the real spec; extracts query+path+body params)
       re-merge xnlinkfinder + jsluice + apidocs output back into all_urls.txt
   ├─ 6.post fuzz_recurse — fuzz UNDER discovered dirs (/api/FUZZ, /admin/…)
   │        (on by default: fuzz_recurse.enabled)     → processed/sources/fuzz_recurse_urls.txt
   │                                                     re-merged into all_urls.txt
   ├─ 6.5  GraphQL introspection probe (on by default) → findings/graphql_schema.json
   ├─ 6.6  CORS misconfiguration probe (on by default) → findings/cors.json
   ├─ 6.6.2 server/microservice misconfig probe — "deep"-tier hosts only
   │        (on by default: misconfig_probe.enabled)  → processed/sources/misconfig_urls.txt
   │                                                     + findings/misconfig_probe.json
   ├─ 6.7  cloud storage bucket enumeration (opt-in: buckets.enabled) → findings/buckets.json
   └─ 6.8  .git exposure source dump (opt-in: gitdump.enabled) → findings/git_dump.json
7. Arjun on dynamic_urls.txt                        → processed/targets/parameterized_urls.txt
   + seed already-param URLs (arjun-independent) + jsluice params
8. Nuclei default scan (alive hosts) — the last scan → findings/default/nuclei.{txt,json}
9. Final Telegram summary  (HTML report path included)
10. Generate final report  → report/final_report.{html,md} + summary.json + priority_targets.txt + delta.md
```

## Quick start

```bash
cd recon-agent
pip install -r requirements.txt
# reproducible install (exact versions verified together) instead:
#   pip install -r requirements-lock.txt

# 0. (one-time) bootstrap the environment — verify tools, clone SecLists
python3 bootstrap.py --all -y

# 1. dry-run to preview the workflow without touching anything
python3 main.py -d example.com --config config.yml --dry-run

# 2. run for real
python3 main.py -d example.com --config config.yml
```

`main.py`/`bootstrap.py` stay repo-root scripts run from the repo root (both
resolve `config.yml`/`wordlists/` relative to the current directory — this
is unchanged). `modules/` is additionally an installable package
(`pip install .`, extras: `.[web]`, `.[xlsx]`, `.[all]`) for tooling that
wants to import it as a library or audit its dependency tree; see
`pyproject.toml` and `docs/architecture/decisions.md`.

### Troubleshooting common startup failures

| Symptom (from `stages.json`) | Root cause | Fix |
|---|---|---|
| `dirsearch` → `failed (count=0, <1s)` with `ModuleNotFoundError: No module named 'pkg_resources'` | dirsearch imports `pkg_resources`, which Python 3.12+ dropped from the stdlib **and** setuptools 81+ dropped from its bundle | Same venv: `pip install -r requirements.txt` (pins `setuptools>=68,<81`). **pipx install** (dirsearch in its own venv): `pipx inject dirsearch "setuptools<81" --force` |
| `arjun` → `failed (count=0, 3600s)` with `timeout after 3600s` | Stage budget exceeded because too many dynamic URLs were fed to arjun | Lower `arjun.max_urls` in `config.yml` (default 200) or raise `arjun.timeout` |
| `arjun` → `AttributeError: 'dict' object has no attribute 'status_code'` in `logs/arjun.log` | Upstream bug in arjun ≤2.2.7: it prints `request.status_code` on a dict the moment a target answers 400/413/418/429/503, killing the whole invocation | Fixed automatically — the stage patches the installed `arjun/__main__.py` before running (`arjun.patch_upstream: true`, backup kept as `__main__.py.recon2win.bak`). If site-packages is read-only, `extra.upstream_patch` in `stages.json` says `failed: …`; install arjun with `pip install --user` or fix it by hand |
| `arjun` → hours spent on a handful of URLs (`Processing chunks: n/103` crawling) | `arjun.stable: true` — `--stable` sleeps a random 3–9s before **every** request (~660s per URL) and overrides `rate_limit` | Leave `arjun.stable: false` (the default); only turn it on when arjun reports the target is rate-limiting, and drop `max_urls` to ~20 when you do |
| `xnlinkfinder` → `failed (count=0, 1200s)` | xnLinkFinder hangs on a single slow JS URL | Lower `xnlinkfinder.timeout` *or* pre-filter `js_urls.txt` |

### `bootstrap.py` — environment bootstrap

`bootstrap.py` is a self-contained script that:

1. **Verifies** every external tool (subfinder, amass, chaos, dnsx, httpx,
   katana, urlfinder, dirsearch, ffuf, waymore, xnLinkFinder, arjun, nuclei) and
   prints their versions.
2. **Optionally installs** missing tools via the platform's package manager
   (`brew` on macOS, `apt` on Linux, `go install` for Go tools, `pip3` for
   Python tools).
3. **Clones SecLists** into `./wordlists/SecLists/` (i.e. inside the
   repo, next to `bootstrap.py`) so every path the framework expects is
   present out of the box. Override with `--wordlists-dir PATH`.
4. **Verifies** the expected wordlists are present.
5. Creates `outputs/`.
6. Prints a structured summary.

By default the script is **read-only** (verify only). Use `--install`
and/or `--wordlists` to actually do something.

```bash
python3 bootstrap.py                       # verify only, no installs
python3 bootstrap.py --wordlists           # clone SecLists
python3 bootstrap.py --install             # install missing tools
python3 bootstrap.py --all -y              # install + download, no prompts
python3 bootstrap.py --wordlists-dir PATH  # custom clone target
python3 bootstrap.py --no-color            # disable ANSI colors
```

### CLI flags

| Flag                   | Effect                                                    |
|------------------------|-----------------------------------------------------------|
| `-d DOMAIN`            | Target domain (required)                                  |
| `-p, --project NAME`   | Optional grouping: `outputs/<project>/<domain>/` instead of the flat `outputs/<domain>/`. Independent of `--h1-program`. Omit to keep the flat layout. |
| `--config PATH`        | YAML config (default: `config.yml`)                       |
| `--resume`             | Skip stages whose expected outputs already exist          |
| `--dry-run`            | Print the plan and exit — never invokes external tools    |
| `--skip-nuclei`        | Skip the nuclei default scan                              |
| `--skip-dirsearch`     | Skip the dirsearch sensitive-extension scan               |
| `--skip-ffuf`          | Skip the ffuf recursive fuzzing stage                     |
| `--skip-fuzz-recurse`  | Skip fuzzing under discovered directories (post-merge stage) |
| `--skip-waymore`       | Skip the waymore archived-URL collection                  |
| `--skip-arjun`         | Skip the arjun parameter discovery                        |
| `--skip-apidocs`       | Skip the API-docs probe + external OSINT stage             |
| `--skip-misconfig-probe` | Skip the deep-tier server/microservice misconfig probe   |
| `--skip-xnlinkfinder`  | Skip the xnLinkFinder JS scan                             |
| `--skip-jsluice`       | Skip the jsluice AST JS analysis (endpoints + secrets)    |
| `--xlsx-report`        | Also generate `report/final_report.xlsx` (detailed, cross-referenced Excel workbook — needs `openpyxl`) |
| `--color`              | Force ANSI colors even when stdout is not a TTY (CI, tmux capture) |
| `--no-color`           | Disable ANSI colors (overrides `$FORCE_COLOR`)            |

### Terminal output

Every recon stage gets a distinct color so the output is scannable
at a glance, especially when parallel stages interleave (stage 4 runs
5 stages concurrently, stage 6 runs 2):

| Stage                | Color          |
|----------------------|----------------|
| `subdomain`          | bright cyan    |
| `dnsx`               | blue           |
| `httpx_alive`        | bright blue    |
| `content_discovery`  | bright magenta |
| `dirsearch`          | bright yellow  |
| `ffuf`               | orange         |
| `waymore`            | yellow         |
| `url_merge`          | white          |
| `httpx_urls`         | cyan           |
| `xnlinkfinder`       | bright green   |
| `arjun`              | green          |
| `nuclei_default`     | bright red     |
| `report`             | bright white   |

Status glyphs:

* `✓ success` (green)
* `✗ failed`  (red)
* `⊘ skipped` (yellow)

Color is auto-detected: enabled when `sys.stdout.isatty()`, disabled
otherwise. Override with `--color` / `--no-color`, or set the env vars
`$FORCE_COLOR` (always on) / `$NO_COLOR` (always off, per
[no-color.org](https://no-color.org)). When colors are off the icons
become ASCII (`[OK] [FAIL] [SKIP]`) and the unicode bars become `-`,
so log files stay grep-friendly:

```
$ python3 main.py -d example.com 2>&1 | tee /tmp/scan.log   # colors on terminal, plain in log
$ FORCE_COLOR=1 python3 main.py -d example.com             # force colors (CI logs)
$ NO_COLOR=1    python3 main.py -d example.com             # force plain text
```

## Project structure

```
recon-agent/
├── main.py                # CLI entry point & orchestrator
├── bootstrap.py           # One-shot environment bootstrap (tools + wordlists)
├── config.yml             # Default configuration
├── requirements.txt
├── README.md
├── modules/
│   ├── runner.py          # Centralized subprocess runner (logs every cmd)
│   ├── utils.py           # Domain validation, IO helpers, result factory
│   ├── subdomain.py       # Stage 1
│   ├── puredns.py         # Stage 1 post — validate/filter subdomains
│   ├── dnsx.py            # Stage 2
│   ├── httpx.py           # Stages 3 & 6.1
│   ├── content_discovery.py  # Stage 4.1
│   ├── dirsearch.py       # Stage 4.2
│   ├── ffuf.py            # Stage 4.3 (-ac/-ach + recursive dirs)
│   ├── fuzz_recurse.py    # Stage 6.post — fuzz UNDER discovered directories
│   ├── fuzz_targets.py    # Chọn host fuzz (dedup response + rank + cap)
│   ├── waymore.py         # Stage 4.4
│   ├── url_merge.py       # Stage 5 (+ 6.post re-merge)
│   ├── xnlinkfinder.py    # Stage 6.2 (regex JS link extraction)
│   ├── jsluice.py         # Stage 6.3 (AST JS endpoints + secrets)
│   ├── arjun.py           # Stage 7
│   ├── nuclei.py          # Stages 4.4 & 8
│   ├── report.py          # Final HTML/MD/JSON report builder
│   ├── hackerone.py       # HackerOne scope integration (--h1-*)
│   ├── telegram.py        # Notifications
│   ├── progress.py        # Progress bar (sequential + parallel phases)
│   ├── console.py         # Terminal formatting (colors, status icons)
│   └── sensitive_ext.py   # Shared extension lists
├── tests/                 # Pytest unit tests (see `pytest tests/`)
├── web/                   # Optional Flask UI (live xterm.js terminal)
└── outputs/               # Created per-run (see below)
```

## Output directory layout (v2)

For every scan the framework creates `outputs/<domain>/` with this
layout — ``raw/`` is grouped per stage and ``findings/`` per kind so
you can `ls raw/<stage>/` to see everything one tool produced, instead
of grepping through a flat 50-file dir.

**Optional project grouping.** Pass `-p/--project NAME` and the same
layout nests one level deeper: `outputs/<project>/<domain>/`. The two
shapes coexist — existing scans keep working at their flat
`outputs/<domain>/` path (`modules/dashboard.py` shows them as
"ungrouped"); grouping is opt-in per invocation, not a forced migration.
`--project` is independent of `--h1-program` — it's a free-form label
(client, campaign, engagement, …), not tied to a HackerOne program.
`outputs/dashboard.html` groups/filters by project when set.

```
outputs/[<project>/]<domain>/
├── raw/                                # tool outputs grouped per stage
│   ├── subdomain/                      # subfinder.txt, amass.txt, chaos.txt
│   ├── puredns/                        # resolvers.txt (validation resolver list)
│   ├── content_discovery/              # katana_urls.txt, urlfinder_urls.txt, gau_urls.txt
│   ├── dirsearch/                      # merged_wordlists.txt, merged_wordlists_deep.txt, targets.txt, deep/, standard/
│   ├── ffuf/                           # <host>.json, ffuf_raw.txt, merged_wordlists.txt, merged_wordlists_deep.txt
│   ├── waymore/                        # waymore_raw.txt
│   ├── jsluice/                        # NNNN.js (fetched JS, one per URL)
│   ├── misconfig_probe/                # candidates.txt, probe.jsonl (deep-tier hosts only)
│   └── arjun/                          # input_subset.txt
├── processed/                          # cleaned + merged, grouped by lifecycle
│   ├── sources/                        # per-tool output, pre-merge — scratch
│   │   ├── crawler_urls.txt, dirsearch_urls.txt
│   │   ├── ffuf_urls.txt, waymore_urls.txt
│   │   ├── apidocs_urls.txt, apidocs_params.txt
│   │   └── misconfig_urls.txt
│   ├── corpus/                         # merged + classified — the pipeline's spine
│   │   ├── all_urls.txt
│   │   ├── all_urls.jsonl              # same list + which tool(s) produced each URL
│   │   └── js_urls.txt, dynamic_urls.txt
│   ├── hosts/                          # subdomain → DNS → liveness inventory
│   │   ├── subdomains.txt, url_derived_subdomains.txt
│   │   ├── resolved.txt, resolved_detail.json
│   │   ├── alive.txt, alive_detail.json, alive_table.txt
│   │   └── alive_urls.txt, alive_urls_detail.json, alive_urls_table.txt
│   ├── js/                             # everything mined out of JavaScript
│   │   ├── jsluice_endpoints.txt, jsluice_urls.txt, jsluice_params.json
│   │   ├── jsluice_alive*.{txt,json}, jsluice_js_*.{txt,json}
│   │   └── xnlinkfinder_endpoints.txt, xnlinkfinder_urls.txt
│   └── targets/                        # ★ the hand-testing shortlist — open first
│       └── parameterized_urls.txt, arjun_params.txt, forms.json
├── findings/                           # nuclei + jsluice secrets
│   ├── default/                        # nuclei.json, nuclei.txt (alive hosts)
│   ├── jsluice_secrets.json            # secrets found in JS (kind/severity/url)
│   └── misconfig_probe.json            # server/microservice misconfig hits (deep-tier hosts)
├── logs/
│   ├── commands.log                    # cumulative command history (UTC ts + argv)
│   ├── <stage>.log                     # per-stage stdout/stderr (sub-stages merged)
│   └── stages.json                     # per-stage structured result
└── report/
    ├── final_report.html
    ├── final_report.md
    ├── final_report.xlsx              # optional — see "Final report" below
    ├── priority_targets.txt           # ranked "test these first" URLs
    ├── delta.md                       # what changed since the previous scan
    └── summary.json
```

(`outputs/<domain>/.scan_state.json` holds the previous run's snapshot for
the delta — a hidden state file, not a per-run artifact.)

**`processed/` grouping (v3).** It used to be one flat folder of ~25 files
that mixed per-tool scratch, the merged corpus, and the two or three files
a human actually opens — opening it told you nothing about which was which.
`modules/layout.py` is now the single source of truth for where each
artefact lives; nothing else should join a `processed/` path by hand:

```python
from modules import layout
layout.path(output_dir, "all_urls.txt")   # → processed/corpus/all_urls.txt
```

`layout.path()` resolves for both reading and writing, and falls back to
the pre-v3 flat location when a file already exists there — so `--resume`
over an older output tree keeps reading and rewriting it in place. Only
artefacts with no legacy counterpart are created in the new folders.

**Behavioural screening (v3).** Content discovery is a comparison, and the
pipeline never established what it was comparing against. Two new pieces fix
that, both built on `modules/behavior.py`:

* **`modules/baseline.py`** probes every host with a few paths that cannot
  exist, *before* fuzzing. If all the answers are identical **and** that
  answer is already in the tool's match list (`ffuf.match_status` /
  `dirsearch.include_status`), the host cannot tell real paths from fake ones
  and is skipped. The same measurement replaces the old dedup key — grouping
  used to compare **home pages**, but what decides whether two hosts are the
  same app is how they answer a path that isn't there.
* **`behavior.screen`** runs after each tool and drops hit clusters that are
  one response wearing many paths, keyed on status + content-type family +
  redirect destination + words/lines.

Byte length is deliberately *not* the key. ffuf's own `-ac` was enabled on the
discover.com run and could not fire, because the Akamai block page echoes the
requested path: 4,082 hits on one host showed **50 distinct lengths** while
`words` was 13 for every one of them. `parse_report` had been discarding
`words`/`lines` entirely.

Measured over that run's raw output:

| stage | hits before | after | dropped |
|---|---|---|---|
| ffuf | 44,442 | 128 | 99.7% |
| dirsearch | 13,895 | 155 | 98.9% |

A cluster must be both large (`min_cluster`) and dominant for its host
(`min_share`) to be dropped, so a repeated error template on an otherwise
varied host survives; and a host is only marked `blanket` when *nothing*
survived, so `app.discover.com` — 84 of 89 hits one redirect-to-apex cluster,
5 of them real — keeps its 5.

**`processed/MANIFEST.json` (v3).** A 0-line file has two opposite meanings
that look identical on disk — "we looked and the target has none of this"
(a result) and "we never looked" (no data) — and reporting the second as
the first is how a broken run turns into a clean bill of health. The
manifest records, per artefact, which one it is:

| state | means |
|---|---|
| `ok` | has data |
| `ran_empty` | stage ran, found nothing — **this IS a result** |
| `blocked` | stage ran but the target refused it (401/403) — **not** a result |
| `truncated` | stage hit its time budget — partial or no data, **not** a result |
| `skipped` | stage never ran (flag, missing binary, dry-run) |
| `failed` | stage failed |
| `absent` | never written |

Written at end of run by `audit.build_manifest()`, which attributes each
file to a stage from that stage's own declared `outputs` — so a new
artefact is covered without editing a table. `INDEX.md`'s ⚪ section reads
it back, and the run log prints a warning when any artefact is empty for a
no-data reason. Stages signal a refused probe with `extra["blocked"]`
rather than leaving it to be sniffed out of error text.

**URL provenance (v3).** `corpus/all_urls.jsonl` carries
`{"url": …, "sources": [tool, …]}` for every line of `all_urls.txt`. The
merge used to flatten sources of wildly different quality into an anonymous
list: on a real `discover.com` run, jsluice-mined URLs came back 23.6% HTTP
200 while ffuf's 44,431 hits were a near-pure wildcard-403 artefact — and
after the merge nothing downstream could tell them apart, so
`arjun.max_urls=200` drew its whole sample from the noise. Capped consumers
now sort by source before they cut (`url_merge.rank_urls_by_source`), and
`url_merge`'s stage result reports the corpus mix, so one source at ~80% of
the total is visible in the run log instead of hidden inside it.

**Log consolidation:** every tool's stdout/stderr is captured into
`stages.json` (structured). If a stage needs its own per-call log file
(e.g. for post-mortem analysis), `runner.run()` accepts a `log_name=`
parameter that groups sub-stage outputs (e.g. all three subdomain
tools land in `logs/subdomain.log` with section headers).

**Files removed in v2** (the data is in the canonical file already):

| Removed | Why |
|---|---|
| `processed/all_urls_raw.txt` | Just the pre-dedup input; can re-derive from the three source files |
| `processed/js_urls_from_crawler.txt` | Just a subset of `js_urls.txt` |
| `processed/alive_detail.csv` | JSON is canonical; CSV was a convenience export |
| `logs/<stage>.stdout` / `.stderr` | One `<stage>.log` per stage (sub-stages merged) |

## Required vs optional stages

**Required:** `subdomain`, `dnsx`, `httpx_alive`, `url_merge`.
**Optional** (skipped with a clear warning when the binary is missing):
`dirsearch`, `ffuf`, `waymore`, `nuclei`, `arjun`, `xnLinkFinder`.

## Output schema (per stage)

```json
{
  "stage": "dnsx",
  "status": "success|failed|skipped",
  "input": "/path/to/input",
  "outputs": ["/path/to/output1", "/path/to/output2"],
  "count": 1234,
  "error": null
}
```

## Telegram

Fill in `bot_token` and `chat_id` in `config.yml` and set `enabled: true`.

Three notification modes, all controllable via flags:

| Flag | Default | What it does |
|---|---|---|
| `notify_high_critical` | `true` | Immediate alert for each High/Critical nuclei finding (with template + target URL) |
| `notify_summary` | `true` | Milestone summary at stage-6 and at the end of the run (includes final HTML path) |
| `per_phase` | `false` | One message per stage with count + output paths (~13 messages per scan — turn on for a live progress feed) |

Per-stage messages look like:

```
✅ subdomain — 343 result(s)
  • processed/hosts/subdomains.txt
  • raw/subdomain/subfinder.txt
  • raw/subdomain/amass.txt
  • raw/subdomain/chaos.txt
```

## Final report

After the workflow completes, the framework writes three artefacts to
`outputs/<domain>/report/` — plus a fourth, optional one:

| File | Purpose |
|------|---------|
| `final_report.html` | Self-contained HTML with CSS, clickable links to every output, severity-grouped findings, KPI cards, searchable/filterable tables, collapsible sections. Open it in any browser. |
| `final_report.md`   | Flat Markdown mirror for quick terminal review. |
| `summary.json`      | The same structured data the report renders, as JSON (for downstream tooling). |
| `final_report.xlsx` | **Opt-in** — `--xlsx-report` or `report.xlsx: true` in `config.yml`. A 17-sheet Excel workbook built from the same data as the HTML report: Nuclei, High-Value Targets, JS Secrets, Params, Forms, API Docs, Misconfig, GraphQL, CORS, Buckets, Git Dump, Subdomains & DNS, **Endpoint Existence** (Confirmed/Likely/Unknown/Not Found verdict per ffuf/dirsearch hit — see section 7 of the report for what drives it), Files — all cross-linked to and from a central **URL Surface** hub sheet (every URL seen anywhere in the run, one row each), plus a table-of-contents sheet. Every one of those 13 detail sheets also carries a blank **Tag** column (dropdown: Reviewed / False Positive / Reported / Duplicate / Ignore / Need Retest) for manual triage while reviewing in Excel — the tool never fills it in. Needs `openpyxl` (`pip install openpyxl`); if it isn't installed the run still completes and just skips this one file with a console warning. |

The report has 16 sections. Endpoint extraction (JavaScript Analysis) and
Nuclei Findings sit right after the KPIs (sections 3–4) — they are the two
things a reader wants first, not buried after DNS/content-discovery
bookkeeping — everything else keeps its original relative order:

1. Executive Summary — target / timing / mode / config
2. Recon Coverage Summary — KPI cards + clickable source counts
3. JavaScript Analysis (Endpoint Extraction) — JS file count, **both** JS
   tools side by side (xnLinkFinder = regex, jsluice = AST), plus jsluice's
   param table (`url / method / queryParams / bodyParams`) and interesting
   API paths
   3.1 JavaScript Secrets — API keys/tokens jsluice extracted from JS, grouped by severity
   3.2 HTTP Method Check — endpoints re-probed with the HTTP verb jsluice
   found in the JS source (not a blind GET), flagging routes a GET-only
   probe would read as dead
4. Nuclei Findings — **grouped by severity**, with template / name / URL / matcher / evidence
   4.1 GraphQL Introspection — endpoints where a single POST returned a live
   schema (query/mutation/subscription fields + type names), not just "a
   /graphql URL exists"
   4.2 CORS Misconfiguration — hosts that reflect an arbitrary `Origin` back
   in `Access-Control-Allow-Origin`, flagged critical when
   `Access-Control-Allow-Credentials: true` is also sent
   4.3 Cloud Storage Buckets — confirmed public/private S3 & GCS buckets
   (extracted references always checked; domain-permutation guessing is
   opt-in via `buckets.enabled`), plus any Azure Blob account references seen
   4.4 Git Exposure Dump — actual source files reconstructed from a
   confirmed `.git/HEAD` exposure via `.git/index` + loose objects
   (opt-in via `gitdump.enabled`; best-effort — objects packed by `git gc`
   are skipped, not fabricated)
5. Asset Inventory — search/filterable table of every alive host
6. DNS Inventory — search/filterable table of resolved subdomains
7. Content Discovery — katana / urlfinder / dirsearch / ffuf / waymore summary,
   plus a link to `responses/index.md` (body previews for ffuf/dirsearch hits).
   Two independent fuzzing diagnostics, easy to conflate but computed at
   different times:
     * **Host fuzzing coverage** — a PRE-fuzz number: how many alive hosts got
       deduped/WAF-skipped/blanket-skipped (via a baseline probe,
       `modules/fuzz_targets.py` + `modules/baseline.py`) before the wordlist
       ever ran, and how many were capped by `max_hosts`.
     * **Behavioural hit screening** — a POST-fuzz number: of the hits the
       wordlist actually produced, how many were fingerprinted (status +
       content-type + redirect target + words/lines, `modules/behavior.py`)
       as one response shape repeated across many paths and dropped, plus
       which hosts triggered it (`blanket_hosts`). This is what tells you a
       `400`/`403`/any status was a real per-path signal and not a
       WAF/catch-all answering everything the same way.
   * **Endpoint existence** (`modules/existence.py`) — a THIRD, per-hit
     verdict: **Confirmed Exists** / **Likely Exists** / **Unknown** /
     **Not Found**, computed from response *behaviour* instead of trusting
     status code alone. Combines three signals, all already on disk from
     earlier in the same run (no extra requests): (1) does this hit's
     response shape match what `modules/baseline.py` measured as THIS
     host's answer for a path guaranteed not to exist; (2) does the body
     preview (`responses/preview.json`) contain a validation/parsing/auth/
     business-logic/framework-specific error phrase (`Missing required
     parameter`, `Invalid JWT`, `User not found`, a Spring/Django/Laravel
     error shape, …) — a `404 {"error":"user not found"}` means routing
     AND business logic both ran, very different from a blank webserver
     404 page; (3) does the status itself structurally imply a routed
     request (`401/403/405/406/415/422`). The report table lists every
     Confirmed/Likely hit with its matched evidence; Not Found entries are
     counted but not listed (they're noise, already explained by matching
     the baseline).
8. Parameter Discovery — Arjun + jsluice params + the first 100 lines of
   `parameterized_urls.txt` embedded inline (the hand-testing shortlist)
   8.1 Forms & Input Surface — every `<form>` the crawler saw, **ranked by
   testing value**: uploads first, then POST bodies, then forms carrying
   auth/identity fields
   8.2 API Documentation — parsed OpenAPI/Swagger specs (paths / auth
   schemes / document URL), docs UIs, and external Postman/GitHub hits
9. High-Value Targets — auto-detected admin / login / API / env / git / backups /
   directory listings (detected from the response title/body — `Index of /…` —
   not the URL text, so an autoindexed `/uploads/` is caught too)
10. Errors / Skipped / Missing Tools — clickable link to `commands.log`
11. Manual Testing Recommendations — prioritized list
12. Appendix — tool versions, config snapshot, all file links

### Form ranking

`processed/targets/forms.json` routinely holds 100+ forms and most are search boxes
and newsletter signups, so section 8.1 sorts them by `report.form_score()`:
multipart uploads (+100) → POST (+50) → number of *real* inputs (capped at
+8) → fields whose names look like identity/auth (+8 each, capped).

Framework plumbing is explicitly excluded from the input count:
`__VIEWSTATE`, `__EVENTTARGET` and the rest of the ASP.NET postback set are
on every page of that stack and are never the target. Without that
exclusion a postback stub outranks a login form purely on field count —
measured at 84 vs 74 on a real `acronis.com` run. CSRF tokens
(`_token`, `csrfmiddlewaretoken`, …) are treated as neutral-positive: their
presence means the form really changes state, but the token field itself is
never the bug.

Every referenced file is a **clickable relative link** (e.g.
`../raw/subfinder.txt`) so the report works from disk (`file://`) or when
copied elsewhere. Missing files are displayed as “Not generated” instead
of crashing.

## Dirsearch wordlists (SecLists)

The dirsearch stage now accepts one or more wordlist paths via
`dirsearch.wordlists` in `config.yml`. Each path can be either:

* a single `.txt` file, or
* a directory (recursively expanded to every `*.txt` inside, sorted).

`~` is expanded. Non-existent paths are skipped with a warning so a
missing SecLists checkout does not break the stage.

Default paths in `config.yml` (relative to the repo root, which is the
directory you run `python3 main.py` from):

```yaml
dirsearch:
  wordlists:
    - wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt
    - wordlists/SecLists/Discovery/Web-Content/uri-from-top-55-most-popular-apps.txt
    - wordlists/SecLists/Discovery/Web-Content/Service-Specific
  combine: false   # set true to also fuzz each word with each extension (noisy)
  extensions: []   # explicit list — empty = use curated sensitive-ext set
```

### Installing SecLists

`python3 bootstrap.py --wordlists` clones SecLists into
`./wordlists/SecLists/` (i.e. inside the repo) so the default paths
above resolve out of the box. The `wordlists/` folder is git-ignored —
it's a build artifact, not source.

Manual clone (if you skipped `bootstrap.py`):

```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git wordlists/SecLists
```

To use a different location, pass `--wordlists-dir PATH` to `bootstrap.py`
and edit the paths in `config.yml` to match.

The `Service-Specific` directory contains ~50 small wordlists
(`apache.txt`, `nginx.txt`, `spring-boot.txt`, `swagger.txt`, etc.) and is
expanded into ~50 individual `-w` arguments to dirsearch.

### Mode precedence

* If `wordlists` is non-empty → **wordlist mode**. The framework
  resolves the configured paths to a flat list of `.txt` files, then
  **merges them into a single deduped file** before invoking dirsearch
  (see *Wordlist merging* below). Extensions are appended via `-e` only
  when `combine: true`.
* Else if `extensions` is non-empty → **extension mode** (legacy).
* Else → curated `SENSITIVE_EXT` fallback.

### Wordlist merging

**dirsearch only accepts a single `-w` flag** — passing multiple `-w`
flags is silently dropped on most versions (only the first is honoured)
and triggers an argparse error on others. To keep `config.yml`'s
multi-entry `wordlists:` list ergonomic, the framework resolves the
list to a flat set of `.txt` files (recursing into directories) and
then **merges them into one deduped file** at:

```
outputs/<domain>/raw/merged_wordlists/all.txt
```

The merge:

* Skips `#`-comments and blank lines (matches `read_lines()` semantics).
* Dedupes case-sensitively — the first occurrence wins (preserves
  ordering from the first wordlist that contributed the entry).
* Silently skips missing files (the warning is already emitted by
  `_resolve_wordlists`).
* Records `files`, `lines_in`, `lines_out`, and `path` in the stage
  result's `extra.merge` dict for visibility in the report.

If you want to run dirsearch *sequentially* per wordlist instead,
either repeat the stage with different configs (using `--resume`) or
set `combine: true` to fuzz each word against every extension.

## ffuf — auto-calibration + recursive fuzzing (stage 4.3)

`ffuf` runs **in parallel with dirsearch**, not instead of it: the two
disagree often enough that the union is worth the wall clock. What ffuf
adds is auto-calibration and real recursion.

```yaml
ffuf:
  enabled: true
  threads: 40                 # -t, per ffuf process
  timeout: 1800               # per-host wall clock
  max_hosts: 50               # cap targets taken from alive.txt (0 = no cap)
  concurrency: 3              # ffuf processes running at once
  autocalibration: true            # -ac
  autocalibration_per_host: true   # -ach
  autocalibration_strategy: ""     # -acs ("basic" | "advanced")
  recursion: true                  # -recursion
  recursion_depth: 2               # -recursion-depth
  recursion_strategy: ""           # -recursion-strategy ("default" | "greedy")
  follow_redirects: false          # -r  (see the warning below)
  rate: 0                          # -rate, req/s (0 = unlimited)
  match_status: [200, 204, 301, 302, 307, 400, 401, 403, 405, 500]   # -mc
  filter_status: [404, 429]                                     # -fc
  wordlists: [...]                 # same rules as dirsearch.wordlists
  extensions: []                   # -e, ".php,.bak"
```

**`-ac` / `-ach` — auto-calibration.** Before fuzzing, ffuf requests a
batch of random paths and derives filters from what comes back. A host
that answers `200` + identical body to everything (SPA fallback,
soft-404, WAF landing page) yields 0 hits instead of your entire
wordlist. `-ach` recomputes that calibration per host; it implies `-ac`
inside ffuf, and the stage emits both so the argv in `commands.log`
says what it does.

**`-recursion` — recursive directories.** Every matched directory is
queued and fuzzed again, up to `recursion_depth` levels.

> ⚠️ ffuf spots a directory via the **redirect** a matched response
> points at, so `follow_redirects: true` (`-r`) breaks recursion — the
> redirect gets consumed before ffuf can read it. Keep it `false` while
> recursion is on, and keep `301`/`302` in `match_status`, or nothing
> is ever queued for the next level.

**Fan-out.** ffuf takes one URL per process (`-u <base>/FUZZ`), not a
host list, so the stage walks `alive.txt` itself: the first `max_hosts`
targets, `concurrency` processes at a time, `timeout` seconds each. One
host timing out costs you that host's results, not the stage. Each
target gets its own `raw/ffuf/<host>.json`; the hits are merged into
`processed/sources/ffuf_urls.txt` and flow into `all_urls.txt` from there.

Turn it off with `--skip-ffuf` for one run, or `enabled: false` for good.

## Tối ưu fuzzing — không bắn trùng, không ăn ban

Hai stage fuzzing (dirsearch 4.2 + ffuf 4.3) dùng chung
`modules/fuzz_targets.py` để chọn host, và được phân vai để không đào
trùng nhau.

### 1. Gom host trả về cùng một response

Wildcard DNS là chuyện thường: `*.example.com` trỏ về một load balancer,
httpx báo 200 cho cả 200 host, và nếu cứ thế fuzz thì wordlist bị bắn lại
200 lần vào **cùng một ứng dụng**.

`alive_detail.json` của httpx đã có sẵn thứ cần để phát hiện —
`status_code` / `title` / `webserver` / `words` / `lines`. Host nào cùng
vân tay đó thì gom một nhóm, chỉ fuzz một đại diện:

```
200 alive -199 trùng response → 1 target
```

Cố tình **không** dùng `content_length` làm khoá: chỉ cần một nonce CSRF
hay timestamp trong HTML là byte count lệch, gom nhóm chính xác sẽ hỏng.
`words`/`lines` chịu được nhiễu đó. Host thiếu dữ liệu để tính vân tay
được coi là **duy nhất** — thà fuzz thừa còn hơn bỏ sót một app thật.

Đại diện của nhóm chọn theo `score_subdomain`, nên `admin.example.com`
thắng `cdn-assets-3.example.com` khi cả hai phục vụ cùng nội dung.

### 2. Dedup TRƯỚC, cap SAU

Thứ tự này quan trọng. Có 60 bản sao + 3 app thật, `max_hosts: 5`:

| Thứ tự | Kết quả |
|---|---|
| Cap trước | 5 slot bị bản sao chiếm sạch, **3 app thật biến mất** |
| Dedup trước (đang dùng) | 1 đại diện + 3 app thật = 4 target |

### 3. Phân vai dirsearch / ffuf

Trước đây cả hai cùng chạy `raft-small-directories` **và** cùng bật
recursion — mọi thư mục tìm được bị quét lại hai lần bởi hai tool.

| Stage | Vai trò | Wordlist | Recursion |
|---|---|---|---|
| dirsearch 4.2 | file + extension nhạy cảm | `quickhits.txt`, `raft-small-files.txt` | **tắt** |
| ffuf 4.3 | directory | `common.txt` (nhỏ) | **bật**, depth 2 |

Wordlist của ffuf phải nhỏ vì recursion nhân nó lên: mỗi directory match
được sẽ chạy lại toàn bộ wordlist ở tầng sau. `common.txt` (~4.6k) chịu
được phép nhân đó; `raft-small-directories` (~20k) thì không.

`Service-Specific/` (~50 file) đã bỏ khỏi dirsearch — nạp wordlist Spring
cho host PHP là request phí. Xem phần tech-aware bên dưới.

### 4. Rate limit

`ffuf.rate` mặc định `30` (× `concurrency: 3` = ~90 req/s tổng), không còn
`0`. Rate không giới hạn là cách nhanh nhất để ăn ban rồi phải chạy lại từ
đầu — và nhiều chương trình bug bounty ghi rõ trần req/s trong policy.
Chỉnh theo policy của target.

### 5. `-fr` cho API soft-404

`ffuf.filter_regex` (`-fr`) lọc theo **nội dung** body thay vì kích thước.
Cần cho target trả JSON kiểu `{"error":"not found","path":"/<đã-thử>"}`:
body echo lại path nên độ dài đổi mỗi request, `-ac` (lọc theo size) bó
tay — thậm chí chính chuỗi thăm dò của calibration bị báo thành hit. Đặt
`filter_regex: '"error"'` là sạch.

### 6. Extension vs tên file — hai kênh khác nhau

`modules/sensitive_ext.py` tách làm hai danh sách vì chúng đi theo hai
đường hoàn toàn khác:

| | Ví dụ | Đi qua | Sinh ra |
|---|---|---|---|
| `SENSITIVE_EXT` | `.bak` `.sql` `.tar.gz` | `-e` | `admin.bak` |
| `SENSITIVE_FILES` | `.env` `.git/config` `docker-compose.yml` | wordlist (`-w`) | `/.env` |

Trước đây cả hai nằm chung một list rồi đổ hết vào `-e`, nên dirsearch đi
thử `admin..env` và `admin.docker-compose.yml` — còn `/.env`, `/.git/config`,
`/.DS_Store` thì **không bao giờ được chạm tới**. Chế độ extension-fallback
(chạy khi chưa cấu hình wordlist) vì thế không thể tìm ra bất kỳ dotfile
nào, đúng nhóm file giá trị nhất khi đi săn.

Giờ fallback dùng cả hai kênh cùng lúc: `-w raw/dirsearch/sensitive_files.txt`
cộng `-e <extension thật>`.

### 7. Ngân sách thời gian

Hai stage có hai kiểu timeout khác nhau vì cách chạy khác nhau:

```yaml
ffuf:
  timeout: 1800          # MỖI HOST
  budget_seconds: 3600   # trần cho CẢ stage
dirsearch:
  timeout_per_host: 300  # ngân sách mỗi host
  timeout: 3600          # trần cho cả stage
```

**ffuf** chạy một process mỗi host. Không có trần tổng thì worst case là
`max_hosts / concurrency × timeout` = 50/3 × 1800 = **8.5 giờ**, trong khi
3 stage còn lại của phase 4 đã xong từ lâu. Hết `budget_seconds` thì không
khởi động target mới nữa; target đang chạy được để chạy nốt, và chúng
không bị tính là thất bại.

**dirsearch** quét các host trong `-l` tuần tự trong một process, nên một
con số cố định là ngân sách chia đều: 3600s cho 50 host = 72s/host, gần
như chắc chắn bị cắt giữa chừng. Giờ tính theo số target thật (sau dedup)
rồi mới chặn trần — và in cảnh báo kèm số giây thực tế mỗi host khi trần
bị chạm.

### 8. Rate limit đối xứng

`dirsearch.max_rate` (mặc định 30) đối xứng với `ffuf.rate`. Trước đây chỉ
ffuf bị ghì còn dirsearch 30 thread bắn tự do vào cùng target — ghì một
nửa thì vẫn ăn ban. Cờ `--max-rate` / `--delay` đã xác minh trên dirsearch
0.4.3.

### 9. Dedup cho các stage khác

| Stage | Mặc định | Vì sao |
|---|---|---|
| dirsearch, ffuf | **bật** | bỏ bản sao chỉ mất thời gian |
| content_discovery (katana) | **bật** | crawl bản sao cũng lãng phí y hệt |
| nuclei_default | **tắt** | đánh đổi coverage — xem dưới |

Với nuclei, dedup là đánh đổi coverage chứ không đơn thuần là tiết kiệm:
hai host cùng trang chủ vẫn có thể khác nhau ở tầng sâu hơn, và bỏ sót một
finding thật đắt hơn nhiều so với vài phút quét thừa. Bật bằng
`nuclei.default.dedup_targets: true` khi bạn biết chắc mình đang nhìn
wildcard.

### Tech-aware wordlist

`alive_detail.json` có field `tech` từ httpx (`["Cloudflare"]`, `PHP`,
`Spring`…) — `modules/fuzz_depth.py` đã dùng tín hiệu này để phát hiện
tech VÀ fuzz đúng theo tech xác định được, thay vì nạp cả
`Service-Specific/` (~50 file) cho mọi host:

1. **Detect** — mỗi host tier "deep" được khớp `tech`/`webserver`/`title`
   với một tập keyword (`jenkins`, `gitlab`, `grafana`, `prometheus`,
   `kubernetes`, `docker`, `elastic`/`kibana`, `confluence`, `consul`,
   `tomcat`, `spring`, `wordpress`, …) — cùng tín hiệu đã dùng để xếp tier.
2. **Fuzz theo tech xác định** — với MỖI keyword khớp có wordlist SecLists
   riêng (`TECH_WORDLIST_MAP`), file đó được merge thêm vào wordlist của
   dirsearch/ffuf **chỉ cho run có host đó** — không có host nào chạy
   Jenkins thì không file Jenkins nào được nạp.

Cấu hình ở `fuzz_depth.tech_aware_wordlists` (mặc định `true`; đặt `false`
để chỉ dùng `deep_wordlists` tĩnh). Không phải keyword nào cũng có wordlist
riêng — chỉ map khi SecLists có file nhỏ, đặc dành riêng cho đúng tech đó
(map bừa sang list to là quay lại đúng vấn đề đã bỏ `Service-Specific/`).
Host demote khỏi tier "deep" (vượt `deep_max_hosts`) không còn được tính,
nên không kéo theo wordlist tốn kém cho một host sắp không được fuzz sâu.

### Nguồn tech thứ 2: CONFIRMED, không phải đoán

httpx `-td` (Wappalyzer rút gọn) chỉ bắt tech lộ rõ qua header/meta-tag —
nhiều host chạy Jenkins/Spring/GitLab... vẫn "im lặng" với httpx nếu
banner bị ẩn/đổi. `misconfig_probe` (chạy sau dirsearch/ffuf trong cùng
lần scan) đã TỰ XÁC NHẬN tech bằng cách đọc nội dung response thật — một
hit `/actuator/env` trả đúng `propertySources` chắc chắn là Spring Boot,
đáng tin hơn nhiều so với đoán qua title.

Kết quả xác nhận này được lưu vào `processed/tech_confirmed.json`
(`{host: [tech_key, ...]}`, tích luỹ qua nhiều lần scan — không bị ghi đè
mỗi run như `alive_detail.json`) và tự động merge vào tín hiệu tier/tech ở
trên — `modules/fuzz_depth.py::load_confirmed_tech` /
`merge_confirmed_tech`.

**Thứ tự chạy trong MỘT lần scan**: dirsearch/ffuf (stage 4) chạy TRƯỚC
misconfig_probe (stage 6+), nên `tech_confirmed.json` của chính lần scan
này chưa tồn tại lúc dirsearch/ffuf tier — không có vòng lặp ngược trong
cùng một run. Giá trị thật nằm ở **lần scan SAU của cùng target**
(`outputs/<domain>/` giữ nguyên giữa các lần chạy, đúng mô hình
scandiff/dashboard đã có sẵn): tech xác nhận ở lần trước làm tier +
tech-aware wordlist ở lần sau chính xác hơn — không cần đợi httpx đoán
đúng, không cần chạy lại misconfig_probe để "làm nóng" tín hiệu.

### API-aware wordlist (fuzz_depth)

`common.txt`/`raft` gần như không chứa endpoint API, nên fuzz một host REST
bằng chúng gần như không ra gì. `modules/fuzz_depth.py` nhận diện **host API**
qua 3 tín hiệu — tên host (`api.`/`rest.`/`graphql.`), tech framework API từ
httpx `-td`, hoặc tech `"api"` do `apidocs` XÁC NHẬN ở lần scan trước
(`tech_confirmed.json`) — rồi xếp host đó vào tier "deep" và cấp thêm wordlist
route API nhỏ (`api/api-endpoints.txt`, `common-api-endpoints-mazen160.txt`,
`graphql.txt`). Tắt bằng `fuzz_depth.api_aware_wordlists: false`.

### Extension-aware `-e` (fuzz_depth)

Corpus chưa tồn tại lúc stage 4, nhưng tech httpx `-td` thì có. Host tier
"deep" được cấp extension đúng theo stack thật (PHP→`.php`, ASP.NET→`.aspx`,
Java→`.jsp`…, khớp theo word-boundary nên `java` không dính `javascript`)
thay vì đoán `.php` cho mọi host. Chỉ áp cho host deep khớp tech. Tắt bằng
`fuzz_depth.tech_aware_extensions: false`.

## Fuzz theo directory đã phát hiện (fuzz_recurse — stage 6.post)

dirsearch/ffuf ở stage 4 chỉ fuzz từ **gốc** mỗi host; `-recursion` của ffuf
chỉ đi theo redirect nó tự tìm. Directory do katana/gau/waymore/jsluice/
dirsearch phát hiện (`/api/`, `/admin/`, `/internal/`…) **không bao giờ được
dùng làm gốc fuzz** — một wordlist đáng ra tìm ra `/api/v2/keys` không có cơ
hội, vì `/api/` được biết SAU khi fuzz gốc đã xong.

`modules/fuzz_recurse.py` đóng vòng lặp đó. Chạy **sau merge** (khi
`all_urls.txt` đã đủ), nó:

1. rút directory prefix của mọi URL trong corpus, theo host, tới `max_depth`
   segment;
2. gom host wildcard về 1 đại diện (dùng lại `fuzz_targets.select_targets`);
3. xếp directory theo độ đáng ngờ (`/api/`, `/admin/` > `/static/`; bỏ hẳn
   cây asset tĩnh), cap, rồi fuzz `<host><dir>FUZZ` bằng wordlist nhỏ +
   auto-calibration — **dùng lại** command builder / parser / behavior screen
   của ffuf, không viết lại phần xử lý hit.

Hit ghi ra `processed/sources/fuzz_recurse_urls.txt` và merge ngược
`all_urls.txt`. Cap nhiều tầng (`max_dirs_per_host`, `max_total_dirs`,
`max_hosts`, `budget_seconds`). Tắt bằng `--skip-fuzz-recurse` hoặc
`fuzz_recurse.enabled: false`.

## Scan delta — "what changed since last time"

Recon is run against the same target again and again; 95% of each run is
identical to the last. After the report, the framework diffs the current
run against the previous one and writes:

```
outputs/<domain>/report/delta.md
```

It lists **new nuclei findings** (first — highest signal), **new
subdomains**, **new alive hosts**, and **new URLs** (capped at 100).
A one-line summary is echoed to the console:

```
delta since last scan: +2 findings, +5 subdomains, +1 alive, +38 urls
```

State is kept in `outputs/<domain>/.scan_state.json` (a snapshot of the
key result sets) and persists across runs — the first scan just
establishes the baseline. Pair this with a scheduled/cron run and you get
a change feed for the target: only the new attack surface, not the whole
haystack every time.

## Priority targets — "test these first"

A full scan emits thousands of URLs and, on noisy targets, hundreds of
`info`-level nuclei hits — the one High finding drowns in the flood
(a real run returned **585 findings, 533 of them `info`**). After the
report, the framework distils everything into a single ranked file:

```
outputs/<domain>/report/priority_targets.txt
```

Each URL accumulates a score + reasons from every source it appears in:

| Signal | Weight |
|---|---|
| nuclei finding | by severity — critical 1000 / high 800 / medium 400 / low 120 / info 15 |
| jsluice secret | severity score + 100 |
| parameterized URL (arjun + jsluice) | 300 (injection surface) |
| dirsearch hit | 220 (exists + passed status filter) |
| ffuf hit | 220 (exists + survived auto-calibration) |
| high-value path (`.env` `.git` `.sql` `actuator` `graphql` `admin` `/api/` …) | 120–350 |

The top 10 are also echoed to the console at the end of the run. On the
`vulnweb.com` test scan the real finding floated straight to the top:

```
[ 1520]  http://rest.vulnweb.com/db.sql  — nuclei high: WordPress Database
                                            Backup File - Exposure; sql dump
[  270]  http://rest.vulnweb.com  — nuclei info: WAF Detection; …
```

## JavaScript analysis — xnLinkFinder (regex) + jsluice (AST)

Stage 6 runs **two** JS analysers in parallel; they complement each other:

| Tool | Technique | Strengths |
|------|-----------|-----------|
| xnLinkFinder (6.2) | regex over JS text | broad, fast, catches loose string patterns |
| **jsluice (6.3)** | **tree-sitter AST** | resolves dynamically-built URLs (`BASE + "/api/" + id`, template literals), extracts **secrets** with context, reports method + query/body params |

**Why AST matters:** regex can't follow how a URL is *assembled* in code. On a
real target with 135 JS files, xnLinkFinder returned **0** endpoints while
jsluice recovered **21** real routes (e.g. `/docs/src/routes/users.php`).

**Flow.** jsluice does not fetch JS itself, so the framework:

1. Downloads every URL in `js_urls.txt` → `raw/jsluice/NNNN.js`
   (concurrent, size-capped at 5 MB, dependency-free).
2. Runs `jsluice urls <files…>` and `jsluice secrets <files…>`.
3. Resolves relative URLs against each file's *original* URL and
   scope-filters to the target domain (drops CDN/tracker noise).
4. Writes `processed/js/jsluice_{urls,endpoints}.txt` +
   `processed/js/jsluice_params.json` + `findings/jsluice_secrets.json`.
5. Endpoints/URLs are merged back into `all_urls.txt` (→ httpx);
   parameterised ones flow on to arjun. Secrets fire a Telegram alert.
6. **Param intel → shortlist:** right after arjun (stage 8),
   `jsluice_params.json` (`{url, method, queryParams, bodyParams}`) is
   turned into fuzzable URLs (`base?p1=&p2=`) and merged into
   `parameterized_urls.txt`. This surfaces the **POST/JSON body params
   arjun never sees** (arjun is GET-only + capped) — and still works when
   arjun is skipped, since jsluice params alone can populate the shortlist.

```yaml
jsluice:
  enabled: true
  mode: [urls, secrets]   # drop either to run only one analysis
  fetch_timeout: 10       # per-file download timeout (s)
  max_js: 500             # cap JS files fetched+parsed (0 = no cap)
  timeout: 1200           # overall stage budget
```

Skip it entirely with `--skip-jsluice`. If the `jsluice` binary is missing
the stage is skipped with a warning (optional stage), like the other JS tools.

## Nuclei — one pass, last in the pipeline + fresh templates

Nuclei runs exactly once, as the final stage before the report:

| Pass | Input | Templates | Findings dir |
|---|---|---|---|
| default | alive hosts (`alive.txt`) | full set | `findings/default/` |

It deliberately runs **on its own** rather than beside content discovery, so
it never shares its rate budget with the four crawlers — on a target that
already answers 403 from the edge, opening connections slowly matters more
than raw throughput.

> **Known trade-off:** nuclei only sees the root hosts. Endpoints that
> katana / dirsearch / jsluice / waymore discover are *not* scanned; they
> land in `processed/hosts/alive_urls.txt` and `processed/targets/parameterized_urls.txt`
> for hand-testing, and feed `report/priority_targets.txt`. Two earlier
> passes (`endpoints` on discovered URLs, `dynamic` with `-dast` on
> parameterised URLs) were removed on 2026-07-28.

Before the pass, `nuclei -update-templates` refreshes the template store
once per run (stale templates miss recent CVEs — the biggest silent quality
drain on a scanner). It's a fast no-op when already current; disable with
`nuclei.update_templates: false` (air-gapped hosts / pinned versions).

## `parameterized_urls.txt` — the hand-testing shortlist

Stage 8 builds `processed/targets/parameterized_urls.txt`: every endpoint the run
found that takes a parameter. Nothing scans it automatically — it is the
list you open in Burp/curl, and it feeds `report/priority_targets.txt`.

It is the **union** of three sources, so an endpoint lands in it if *any*
of them has a param for it:

```
parameterized_urls.txt = {URLs that already carry ?a=1 in the crawl output}
                       ∪ {params arjun discovered on param-less endpoints}
                       ∪ {params jsluice extracted from JS (incl. POST/JSON body)}
```

The first set is seeded **independently of arjun** (from `dynamic_urls.txt`).
This matters: arjun is capped (`max_urls`) and optional (`--skip-arjun`), so
without the seed, obvious injection targets like `/list?id=1` would be missing
whenever arjun is skipped, capped, or fails — even though they were sitting in
the crawl results. On the `vulnweb.com` test target this is the difference
between a shortlist of **0** URLs and **752**.

## API documentation discovery (stage 6.4)

An OpenAPI/Swagger document is the highest-signal artefact in web recon: it
hands over every route, parameter and auth scheme the developers wrote
down. One `/v3/api-docs` hit beats a day of directory brute-forcing.

Two independent sources, both fail-soft:

**1. Active probe.** A curated list of well-known spec paths (`/openapi.json`,
`/v3/api-docs`, `/swagger-ui.html`, `/graphql`, `/wp-json`, `/actuator`,
`/.well-known/openid-configuration`, …) against every alive host, via httpx
with `-irr` so the body comes back. `401/403` is kept as a match: a
`/v3/api-docs` behind auth still proves the spec exists.

**Wildcard-dedup + tech-aware paths.** The probe reuses
`fuzz_targets.select_targets` so a wildcard target's 200 identical hosts
collapse to one representative *before* the path list is multiplied out —
the same waste the fuzzers already avoid (`apidocs.dedup_targets`). Freed of
that cost, each real host also gets the extra paths its tech implies
(Spring→`/actuator`,`/v3/api-docs`; DRF→`/api/schema/`; …), driven by httpx
`-td` + tech confirmed on a prior scan (`apidocs.tech_aware_paths`).

**A 200 is not a spec.** Plenty of SPA hosts answer 200-with-index.html on
*every* path, so a status-code check alone would report a swagger doc on
every host in the run. Nothing counts unless the body parses as OpenAPI,
Swagger or AsyncAPI — see `apidocs.parse_spec()`, which requires both the
version key and the structural object (`paths`/`channels`).

**A docs UI is not a dead end (spec chase).** When the probe finds a
swagger-ui / redoc / scalar shell but no spec at a guessed path, it follows
the pointer the UI hands the browser — `/v3/api-docs/swagger-config`,
`/swagger-resources`, or a `url:`/`spec-url=` inside the HTML — and fetches
the real document in a second/third probe round (`apidocs.spec_chase`). This
is the single biggest recall win in the stage; specs found this way are
tagged `source: ui-chase` in `findings/api_docs.json` and the report.

Parsed specs become absolute URLs merged into `all_urls.txt` (→ httpx →
nuclei), and their **declared parameters — query, path-template AND
body/`requestBody` (with local `$ref` resolved)** — go straight to
`parameterized_urls.txt`. Body params are exactly the POST/PUT surface a
GET-only crawler never sees. Path templates keep their `{id}` placeholders:
substituting a guessed value would fabricate a URL nobody observed. Server
URL variables (`https://{env}.x.com`) are filled from their declared default.

A host that yields any spec/UI/discovery hit is recorded as an **API host**
in `tech_confirmed.json`, so the NEXT scan's fuzzing hands it the API
wordlist (see *API-aware wordlist* above) — apidocs runs after fuzzing this
run, so the benefit lands next time, same model as `misconfig_probe`.

**2. External OSINT.** Public Postman workspaces, plus GitHub code search
when `apidocs.github_token` is set (GitHub rejects anonymous code search).

Postman results are filtered on **word boundaries against the domain's
distinctive tokens**, not substrings, and restricted to workspaces and
collections. Measured against live data on 2026-07-28: searching
`discover.com` with substring matching returned 25 results — "Bloomreach -
Discovery Workspace", "Ticketmaster Discovery API", "discover posts" — none
of them the target, because `discover` is a substring of `Discovery`. Word
boundaries cut that to 4, all genuinely naming "Discover". Score is not
usable as a filter on its own: "Postman Public Workspace" scored 252 for
that query, above where a real hit for a small org would land.

**SwaggerHub is deliberately absent.** Its public `/specs?query=` endpoint
does filter (totalCount changes) but returns results in *alphabetical*
order, not by relevance — a `stripe` query yields 4,457 results whose first
page contains nothing named Stripe, and `sort=BEST_MATCH` behaves the same.
There is no way to triage that, so including it would only generate noise.

```yaml
apidocs:
  enabled: true
  probe: true
  max_hosts: 300          # hosts × ~60 paths = requests; cap it
  match_codes: "200,401,403"
  extra_paths: []         # target-specific paths, must start with "/"
  osint: true
  postman: true
  github_token: "${GITHUB_TOKEN}"   # empty → GitHub search skipped
```

## Adaptive fuzz depth + microservice misconfig probe (`fuzz_depth`, stage 6.6.2)

`fuzz_targets` already decides **which** alive hosts get fuzzed at all
(wildcard dedup, WAF/blanket-deny skip, `score_subdomain`-ranked cap). Until
this stage, every host that survived that filter got the exact same
wordlist and the exact same depth — a host named `jenkins-ci.example.com`
got no more attention than `cdn-assets-3.example.com`.

`modules/fuzz_depth.py` adds a second layer: it tiers each already-selected
host into `deep` / `standard` / `light` using two signals:

1. **`score_subdomain(host)`** — the existing hostname scorer (apex, high-value
   prefixes like `api`/`admin`, known bug-bounty tech substrings). A score at
   or above `fuzz_depth.deep_score_threshold` (default 1000) → `deep`; at or
   below `fuzz_depth.light_score_threshold` (default -500, i.e. it matched
   the noise list) → `light`.
2. **httpx `-td` tech-detection** — `alive_detail.json`'s `tech`/`webserver`/
   `title` fields, matched against a curated list of interesting stacks
   (Spring, Jenkins, GitLab, Kubernetes, Grafana, Prometheus, Elasticsearch,
   WordPress, phpMyAdmin, Jira, Confluence, Consul, Nexus, …). **Any match
   wins outright, regardless of hostname score** — this is what catches a
   generically-named host that happens to run Jenkins, which the hostname
   string alone would never reveal. Measured live on a real `discover.com`
   run: `dbblog.discover.com` (a name that scores nothing on its own) was
   correctly flagged `deep` because httpx's tech fingerprint found
   WordPress + MySQL + PHP running on it.

`light` never means "skip" — a host that classifies there still gets fuzzed
at the normal depth; it just doesn't receive the expensive extras. A host
can only be dropped entirely by `fuzz_targets`, never by this stage.

**What "deep" actually buys a host:**

- `dirsearch`/`ffuf` merge `fuzz_depth.deep_wordlists` on top of the stage's
  normal wordlist for that host only (`raw/dirsearch/merged_wordlists_deep.txt`).
  dirsearch additionally runs the deep-tier hosts as their **own group** with
  a dedicated slice of the stage's timeout (`fuzz_depth.deep_time_share`,
  default 0.35) — so one slow deep-tier host can't starve the standard
  group's budget, and vice versa. `deep_max_hosts` (default 15) caps how
  many hosts qualify for this heavier treatment; anything past the cap is
  demoted to `standard`, never dropped.
- `misconfig_probe` (below) runs **only** against the `deep` set.

```yaml
fuzz_depth:
  enabled: true
  deep_max_hosts: 15
  deep_score_threshold: 1000
  light_score_threshold: -500
  deep_wordlists: []      # extra files merged ONLY for deep-tier hosts
  deep_time_share: 0.35   # % of dirsearch's stage timeout reserved for "deep"
```

### `misconfig_probe` — sensitive service sub-endpoints, deep-tier only

`apidocs.py` already probes every alive host for OpenAPI/Swagger plus a
handful of discovery documents (bare `/actuator`, `/wp-json`,
`/.well-known/*`). `misconfig_probe` goes further — the **sensitive**
sub-endpoints of specific services (Spring actuator `/env`/`/heapdump`,
Jenkins `/script` console, GitLab `/api/v4/version`, Kubernetes
`/api/v1/namespaces`, Docker registry `/v2/_catalog`, phpMyAdmin/Adminer,
Prometheus, Elasticsearch, Consul, Nexus, …) — but only against the `deep`
tier, since this is a narrower, more expensive probe than apidocs' broad
sweep.

Same precision discipline as `apidocs.parse_spec`: **a 200 is not proof.**
Confirmed live against `gitlab.com` — its own frontend answers 200 with its
normal app shell for any unrecognised path (`/pma/` included), which would
misreport as phpMyAdmin under a status-only check. Every path family has a
dedicated content validator (e.g. actuator/env requires a `propertySources`
key, GitLab version requires both `version` and `revision` keys, Kubernetes'
own 403 `Status` body on `/api/v1/namespaces` still counts because it proves
the apiserver is reachable). Paths with no strong validator available
(Consul, Nexus ping) are accepted on status alone but tagged
`confidence: "low"` so they can never outrank a validated hit in the report
or `priority_targets.txt`.

```yaml
misconfig_probe:
  enabled: true
  threads: 20
  http_timeout: 10
  timeout: 900
  match_codes: "200,401,403"
```

## Arjun tunables (input capping)

`arjun` is a parameter fuzzer — given an unbounded list of dynamic URLs
it will happily spend hours fuzzing every one. On targets with
aggressive crawlers + waymore, `dynamic_urls.txt` can easily grow past
5k URLs, which causes the stage to time out at the configured
`arjun.timeout` (default 3600s).

The framework mitigates this by:

1. Ranking dynamic URLs by high-value hints
   (`/api/`, `/login`, `/admin`, `/graphql`, `id=`, `q=`, …)
2. Demoting archive noise (`web.archive.org`, `webcache.googleusercontent`)
3. Keeping only the top `arjun.max_urls` (default 200)

The original URL count and the scanned count are both recorded in
`outputs/<domain>/logs/stages.json` under the `arjun` stage's `extra`
field so you can see how many were dropped.

```yaml
arjun:
  max_urls: 200          # cap input; ranking preserves the interesting ones
  request_timeout: 10    # arjun -T; lower = hung URLs die faster
  timeout: 3600          # overall stage budget
```

## Tests

```bash
cd recon-agent
python3 -m pytest tests/ -v
```

The tests cover the pure helpers in `modules/url_merge.py` and
`modules/dirsearch.py`, plus a resume-mode behaviour test that uses
`tmp_path` fixtures to assert stage-skip logic.

## Web UI (optional)

`web/app.py` is a tiny Flask server that lets you run recon2win from
a browser with a live terminal view (xterm.js + Server-Sent Events),
and browse existing scan results without touching the filesystem.

```bash
pip install flask                 # optional — CLI works without it
python3 web/app.py                # http://127.0.0.1:5000
python3 web/app.py --host 0.0.0.0 --port 8080
```

**Run a scan** (`/`) — form + live terminal:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Single-page UI (form + xterm.js terminal) |
| `/api/run` | POST | Start a scan, returns `scan_id` |
| `/api/stream/<scan_id>` | GET | SSE stream of stdout |
| `/api/status/<scan_id>` | GET | JSON snapshot |
| `/api/scans` | GET | List known scan_ids |

**Browse results** (`/results`) — read-only, over whatever is already in
`output_root` (`outputs/` by default; `-p/--project`-grouped targets show
up grouped, ungrouped targets show up ungrouped, exactly like
`outputs/dashboard.html`):

| Route | Purpose |
|---|---|
| `/results` | Target list, grouped by project |
| `/results/<domain>` or `/results/<project>/<domain>` | Target overview — KPIs, stage health, links |
| `.../hosts`, `.../urls` | Paginated, filterable (`q=`, `status=`) tables — reads `alive_table.txt` / `alive_urls_table.txt` directly, no database |
| `.../findings` | Paginated, filterable (`q=`, `severity=`) nuclei findings |
| `.../report/<filename>` | Serves `report/final_report.html` / `asm_report.html` / etc. directly |

No index/database yet — each request reads and filters the relevant file
from disk. Fine for one local user; `docs/architecture/decisions.md`
records when to revisit that (a SQLite index per target, already designed
in `docs/ui-design.md`, is the documented next step if this ever needs to
serve more than one person at once or the biggest targets make per-request
scans noticeably slow).

No auth, no persistence — single-process dev server only. For
real-world usage run behind a reverse proxy (nginx + auth_basic) or a
tunnel that handles auth (e.g. Cloudflare Tunnel), or use a production
WSGI server (`gunicorn web.app:app`).

## Required external tools

| Tool         | Stage(s)    | Install                                           |
|--------------|-------------|---------------------------------------------------|
| subfinder    | 1           | `brew install subfinder` / `go install ...subfinder` |
| amass        | 1           | `brew install amass`                              |
| chaos        | 1           | `go install -v github.com/projectdiscovery/chaos/...` |
| dnsx         | 2           | `brew install dnsx` / `go install ...dnsx`        |
| httpx        | 3, 6.1      | `brew install httpx` / `go install ...httpx`      |
| katana       | 4.1         | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| urlfinder    | 4.1         | `pip install urlfinder` (Python)                  |
| gau          | 4.1         | `go install github.com/lc/gau/v2/cmd/gau@latest`  |
| dirsearch    | 4.2         | `pip install dirsearch` (Python)                  |
| ffuf         | 4.3         | `brew install ffuf` / `go install github.com/ffuf/ffuf/v2@latest` |
| waymore      | 4.4         | `pip install waymore` (Python)                    |
| xnLinkFinder | 6.2         | `go install -v github.com/xnl-h4ck3r/xnLinkFinder@latest` |
| jsluice      | 6.3         | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| arjun        | 7           | `pip install arjun` (Python)                      |
| nuclei       | 4.5, 8      | `brew install nuclei` / `go install ...nuclei`     |

## Notes

* All raw outputs (`raw/<stage>/*.txt`) are never deleted.
* Every external command is logged to `outputs/<domain>/logs/commands.log`.
* Each stage's stdout/stderr is persisted to a single
  `outputs/<domain>/logs/<stage>.log` (sub-stages merged with section
  headers) for post-mortem analysis.
* This tool is for **authorized recon only** — do not use it against systems
  you do not own or have explicit permission to test.
# recon2win
