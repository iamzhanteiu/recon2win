# recon-agent

Automated recon framework that follows a strict 9-stage workflow
(0 → 9) modelled on the `recon.html` diagram.

## Workflow

```
0. Validate domain & create output/<domain>/ folder
1. Subdomain collection  (subfinder, amass, chaos)   → processed/subdomains.txt
2. DNS resolution        (dnsx)                      → processed/resolved.txt + resolved_detail.json
3. HTTP alive check      (httpx)                     → processed/alive.txt + alive_detail.{json,csv}
4. PARALLEL
   ├─ 4.1  katana + urlfinder crawling              → raw/katana_urls.txt + raw/urlfinder_urls.txt
   ├─ 4.2  dirsearch (SecLists wordlists +/or sensitive ext) → processed/dirsearch_urls.txt
   ├─ 4.3  waymore (archived URLs + JS)              → processed/waymore_urls.txt
   └─ 4.4  nuclei default scan                      → findings/default/nuclei.{txt,json}
5. Merge                                                    → processed/all_urls.txt
   + processed/js_urls.txt, processed/dynamic_urls.txt
6. PARALLEL
   ├─ 6.1  httpx on all_urls.txt                    → processed/alive_urls.txt
   ├─ 6.2  xnLinkFinder on js_urls.txt (regex)      → processed/xnlinkfinder_{endpoints,urls}.txt
   └─ 6.3  jsluice on js_urls.txt (AST)             → processed/jsluice_{endpoints,urls}.txt
                                                       + findings/jsluice_secrets.json
       re-merge xnlinkfinder + jsluice output back into all_urls.txt
7. Arjun on dynamic_urls.txt                        → processed/parameterized_urls.txt
   + seed already-param URLs (arjun-independent) + jsluice params
8. Nuclei endpoints scan (discovered alive URLs)    → findings/endpoints/nuclei.{txt,json}
9. Nuclei dynamic scan                              → findings/dynamic/nuclei.{txt,json}
10. Final Telegram summary  (HTML report path included)
11. Generate final report   → report/final_report.{html,md} + summary.json + priority_targets.txt + delta.md
```

## Quick start

```bash
cd recon-agent
pip install -r requirements.txt

# 0. (one-time) bootstrap the environment — verify tools, clone SecLists
python3 setup.py --all -y

# 1. dry-run to preview the workflow without touching anything
python3 main.py -d example.com --config config.yml --dry-run

# 2. run for real
python3 main.py -d example.com --config config.yml
```

### Troubleshooting common startup failures

| Symptom (from `stages.json`) | Root cause | Fix |
|---|---|---|
| `dirsearch` → `failed (count=0, <1s)` with `ModuleNotFoundError: No module named 'pkg_resources'` | dirsearch imports `pkg_resources`, which Python 3.12+ dropped from the stdlib **and** setuptools 81+ dropped from its bundle | Same venv: `pip install -r requirements.txt` (pins `setuptools>=68,<81`). **pipx install** (dirsearch in its own venv): `pipx inject dirsearch "setuptools<81" --force` |
| `arjun` → `failed (count=0, 3600s)` with `timeout after 3600s` | Stage budget exceeded because too many dynamic URLs were fed to arjun | Lower `arjun.max_urls` in `config.yml` (default 200) or raise `arjun.timeout` |
| `xnlinkfinder` → `failed (count=0, 1200s)` | xnLinkFinder hangs on a single slow JS URL | Lower `xnlinkfinder.timeout` *or* pre-filter `js_urls.txt` |
| `nuclei_dynamic` → `skipped (input file empty or missing)` | Cascade from `arjun` failing | Fix arjun (above) and the cascade clears |

### `setup.py` — environment bootstrap

`setup.py` is a self-contained script that:

1. **Verifies** every external tool (subfinder, amass, chaos, dnsx, httpx,
   katana, urlfinder, dirsearch, waymore, xnLinkFinder, arjun, nuclei) and
   prints their versions.
2. **Optionally installs** missing tools via the platform's package manager
   (`brew` on macOS, `apt` on Linux, `go install` for Go tools, `pip3` for
   Python tools).
3. **Clones SecLists** into `./wordlists/SecLists/` (i.e. inside the
   repo, next to `setup.py`) so every path the framework expects is
   present out of the box. Override with `--wordlists-dir PATH`.
4. **Verifies** the expected wordlists are present.
5. Creates `outputs/`.
6. Prints a structured summary.

By default the script is **read-only** (verify only). Use `--install`
and/or `--wordlists` to actually do something.

```bash
python3 setup.py                       # verify only, no installs
python3 setup.py --wordlists           # clone SecLists
python3 setup.py --install             # install missing tools
python3 setup.py --all -y              # install + download, no prompts
python3 setup.py --wordlists-dir PATH  # custom clone target
python3 setup.py --no-color            # disable ANSI colors
```

### CLI flags

| Flag                   | Effect                                                    |
|------------------------|-----------------------------------------------------------|
| `-d DOMAIN`            | Target domain (required)                                  |
| `--config PATH`        | YAML config (default: `config.yml`)                       |
| `--resume`             | Skip stages whose expected outputs already exist          |
| `--dry-run`            | Print the plan and exit — never invokes external tools    |
| `--skip-nuclei`        | Skip both nuclei default and nuclei dynamic scans         |
| `--skip-dirsearch`     | Skip the dirsearch sensitive-extension scan               |
| `--skip-waymore`       | Skip the waymore archived-URL collection                  |
| `--skip-arjun`         | Skip the arjun parameter discovery                        |
| `--skip-xnlinkfinder`  | Skip the xnLinkFinder JS scan                             |
| `--skip-jsluice`       | Skip the jsluice AST JS analysis (endpoints + secrets)    |
| `--color`              | Force ANSI colors even when stdout is not a TTY (CI, tmux capture) |
| `--no-color`           | Disable ANSI colors (overrides `$FORCE_COLOR`)            |

### Terminal output

Every recon stage gets a distinct color so the output is scannable
at a glance, especially when parallel stages interleave (stage 4 runs
4 stages concurrently, stage 6 runs 2):

| Stage                | Color          |
|----------------------|----------------|
| `subdomain`          | bright cyan    |
| `dnsx`               | blue           |
| `httpx_alive`        | bright blue    |
| `content_discovery`  | bright magenta |
| `dirsearch`          | bright yellow  |
| `waymore`            | yellow         |
| `nuclei_default`     | bright red     |
| `url_merge`          | white          |
| `httpx_urls`         | cyan           |
| `xnlinkfinder`       | bright green   |
| `arjun`              | green          |
| `nuclei_dynamic`     | red            |
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
├── setup.py               # One-shot environment bootstrap (tools + wordlists)
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
│   ├── waymore.py         # Stage 4.3
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

```
outputs/<domain>/
├── raw/                                # tool outputs grouped per stage
│   ├── subdomain/                      # subfinder.txt, amass.txt, chaos.txt
│   ├── puredns/                        # resolvers.txt (validation resolver list)
│   ├── content_discovery/              # katana_urls.txt, urlfinder_urls.txt
│   ├── dirsearch/                      # merged_wordlists.txt
│   ├── waymore/                        # waymore_raw.txt
│   ├── jsluice/                        # NNNN.js (fetched JS, one per URL)
│   └── arjun/                          # input_subset.txt
├── processed/                          # cleaned + merged (flat, single source of truth)
│   ├── subdomains.txt
│   ├── resolved.txt, resolved_detail.json
│   ├── alive.txt, alive_detail.json
│   ├── crawler_urls.txt, js_urls.txt
│   ├── dirsearch_urls.txt, waymore_urls.txt
│   ├── all_urls.txt, dynamic_urls.txt
│   ├── xnlinkfinder_endpoints.txt, xnlinkfinder_urls.txt
│   ├── jsluice_endpoints.txt, jsluice_urls.txt, jsluice_params.json
│   ├── alive_urls.txt, alive_urls_detail.json
│   └── arjun_params.txt, parameterized_urls.txt
├── findings/                           # nuclei + jsluice secrets
│   ├── default/                        # nuclei.json, nuclei.txt (root hosts)
│   ├── endpoints/                      # nuclei.json, nuclei.txt (discovered URLs)
│   ├── dynamic/                        # nuclei.json, nuclei.txt (param URLs)
│   └── jsluice_secrets.json            # secrets found in JS (kind/severity/url)
├── logs/
│   ├── commands.log                    # cumulative command history (UTC ts + argv)
│   ├── <stage>.log                     # per-stage stdout/stderr (sub-stages merged)
│   └── stages.json                     # per-stage structured result
└── report/
    ├── final_report.html
    ├── final_report.md
    ├── priority_targets.txt           # ranked "test these first" URLs
    ├── delta.md                       # what changed since the previous scan
    └── summary.json
```

(`outputs/<domain>/.scan_state.json` holds the previous run's snapshot for
the delta — a hidden state file, not a per-run artifact.)

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
`dirsearch`, `waymore`, `nuclei`, `arjun`, `xnLinkFinder`.

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
  • processed/subdomains.txt
  • raw/subdomain/subfinder.txt
  • raw/subdomain/amass.txt
  • raw/subdomain/chaos.txt
```

## Final report

After the workflow completes, the framework writes three artefacts to
`outputs/<domain>/report/`:

| File | Purpose |
|------|---------|
| `final_report.html` | Self-contained HTML with CSS, clickable links to every output, severity-grouped findings, KPI cards, searchable/filterable tables, collapsible sections. Open it in any browser. |
| `final_report.md`   | Flat Markdown mirror for quick terminal review. |
| `summary.json`      | The same structured data the report renders, as JSON (for downstream tooling). |

The report has 12 sections:

1. Executive Summary — target / timing / mode / config
2. Recon Coverage Summary — KPI cards + clickable source counts
3. Asset Inventory — search/filterable table of every alive host
4. DNS Inventory — search/filterable table of resolved subdomains
5. Content Discovery — katana / urlfinder / dirsearch / waymore summary
6. JavaScript Analysis — JS file count, xnLinkFinder endpoints, interesting API paths
   6.1 JavaScript Secrets — API keys/tokens jsluice extracted from JS, grouped by severity
7. Parameter Discovery — Arjun + parameterized URLs
8. Nuclei Findings — **grouped by severity**, with template / name / URL / matcher / evidence
9. High-Value Targets — auto-detected admin / login / API / env / git / backups
10. Errors / Skipped / Missing Tools — clickable link to `commands.log`
11. Manual Testing Recommendations — prioritized list
12. Appendix — tool versions, config snapshot, all file links

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

`python3 setup.py --wordlists` clones SecLists into
`./wordlists/SecLists/` (i.e. inside the repo) so the default paths
above resolve out of the box. The `wordlists/` folder is git-ignored —
it's a build artifact, not source.

Manual clone (if you skipped `setup.py`):

```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git wordlists/SecLists
```

To use a different location, pass `--wordlists-dir PATH` to `setup.py`
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
4. Writes `processed/jsluice_{urls,endpoints}.txt` +
   `processed/jsluice_params.json` + `findings/jsluice_secrets.json`.
5. Endpoints/URLs are merged back into `all_urls.txt` (→ httpx → nuclei);
   parameterised ones flow on to arjun. Secrets fire a Telegram alert.
6. **Param intel → nuclei_dynamic:** between arjun (7) and nuclei_dynamic
   (8), `jsluice_params.json` (`{url, method, queryParams, bodyParams}`) is
   turned into fuzzable URLs (`base?p1=&p2=`) and merged into
   `parameterized_urls.txt`. This gives nuclei the **POST/JSON body params
   arjun never sees** (arjun is GET-only + capped) — and still works when
   arjun is skipped, since jsluice params alone can drive the dynamic scan.

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

## What nuclei_dynamic actually scans

`nuclei_dynamic` (stage 8) fuzzes injection templates (sqli/xss/lfi/ssrf/…)
against `parameterized_urls.txt`. That file is the **union** of three sources,
so an endpoint reaches the dynamic scan if *any* of them has a param for it:

```
parameterized_urls.txt = {URLs that already carry ?a=1 in the crawl output}
                       ∪ {params arjun discovered on param-less endpoints}
                       ∪ {params jsluice extracted from JS (incl. POST/JSON body)}
```

The first set is seeded **independently of arjun** (from `dynamic_urls.txt`).
This matters: arjun is capped (`max_urls`) and optional (`--skip-arjun`), so
without the seed, obvious injection targets like `/list?id=1` would be dropped
from the dynamic scan whenever arjun is skipped, capped, or fails — even though
they were sitting in the crawl results. On the `vulnweb.com` test target this
is the difference between nuclei_dynamic scanning **0** URLs and **752**.

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
a browser with a live terminal view (xterm.js + Server-Sent Events).

```bash
pip install flask                 # optional — CLI works without it
python3 web/app.py                # http://127.0.0.1:5000
python3 web/app.py --host 0.0.0.0 --port 8080
```

Endpoints:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Single-page UI (form + xterm.js terminal) |
| `/api/run` | POST | Start a scan, returns `scan_id` |
| `/api/stream/<scan_id>` | GET | SSE stream of stdout |
| `/api/status/<scan_id>` | GET | JSON snapshot |
| `/api/scans` | GET | List known scan_ids |

No auth, no persistence — single-process dev server only. For
real-world usage run behind a reverse proxy (nginx + auth_basic) or
use a production WSGI server (`gunicorn web.app:app`).

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
| dirsearch    | 4.2         | `pip install dirsearch` (Python)                  |
| waymore      | 4.3         | `pip install waymore` (Python)                    |
| xnLinkFinder | 6.2         | `go install -v github.com/xnl-h4ck3r/xnLinkFinder@latest` |
| jsluice      | 6.3         | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| arjun        | 7           | `pip install arjun` (Python)                      |
| nuclei       | 4.4, 8      | `brew install nuclei` / `go install ...nuclei`     |

## Notes

* All raw outputs (`raw/<stage>/*.txt`) are never deleted.
* Every external command is logged to `outputs/<domain>/logs/commands.log`.
* Each stage's stdout/stderr is persisted to a single
  `outputs/<domain>/logs/<stage>.log` (sub-stages merged with section
  headers) for post-mortem analysis.
* This tool is for **authorized recon only** — do not use it against systems
  you do not own or have explicit permission to test.
# recon2win
