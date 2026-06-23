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
   └─ 4.4  nuclei default scan                      → findings/nuclei_default.{txt,json}
5. Merge                                                    → processed/all_urls.txt
   + processed/js_urls.txt, processed/dynamic_urls.txt
6. PARALLEL
   ├─ 6.1  httpx on all_urls.txt                    → processed/alive_urls.txt
   └─ 6.2  xnLinkFinder on js_urls.txt              → processed/xnlinkfinder_{endpoints,urls}.txt
       re-merge xnlinkfinder output back into all_urls.txt
7. Arjun on dynamic_urls.txt                        → processed/parameterized_urls.txt
8. Nuclei dynamic scan                              → findings/nuclei_dynamic.{txt,json}
9. Final Telegram summary  (HTML report path included)
10. Generate final report   → report/final_report.{html,md} + summary.json
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
│   ├── dnsx.py            # Stage 2
│   ├── httpx.py           # Stages 3 & 6.1
│   ├── content_discovery.py  # Stage 4.1
│   ├── dirsearch.py       # Stage 4.2
│   ├── waymore.py         # Stage 4.3
│   ├── url_merge.py       # Stage 5 (+ 6.post re-merge)
│   ├── xnlinkfinder.py    # Stage 6.2
│   ├── arjun.py           # Stage 7
│   ├── nuclei.py          # Stages 4.4 & 8
│   ├── telegram.py        # Notifications
│   └── sensitive_ext.py   # Shared extension lists
├── tests/                 # Pytest unit tests
│   ├── test_url_dedup.py
│   ├── test_js_extraction.py
│   ├── test_dynamic_url.py
│   ├── test_dirsearch_normalize.py
│   ├── test_dirsearch_wordlists.py
│   ├── test_telegram_notify.py
│   ├── test_setup.py
│   └── test_resume.py
└── outputs/               # Created per-run
```

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
- High/Critical nuclei findings fire an **immediate** alert.
- Per-stage summaries fire when `nuclei_default`, `nuclei_dynamic`, and
  `content_discovery` finish with results (count > 0).
- Stage-6 and final summaries are sent at the end of the run.
- The **final** Telegram message includes the path to `final_report.html`.

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

* If `wordlists` is non-empty → **wordlist mode** (one `-w` per file).
  Extensions are appended only when `combine: true`.
* Else if `extensions` is non-empty → **extension mode** (legacy).
* Else → curated `SENSITIVE_EXT` fallback.

## Tests

```bash
cd recon-agent
python3 -m pytest tests/ -v
```

The tests cover the pure helpers in `modules/url_merge.py` and
`modules/dirsearch.py`, plus a resume-mode behaviour test that uses
`tmp_path` fixtures to assert stage-skip logic.

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
| arjun        | 7           | `pip install arjun` (Python)                      |
| nuclei       | 4.4, 8      | `brew install nuclei` / `go install ...nuclei`     |

## Notes

* All raw outputs (`raw/*.txt`) are never deleted.
* Every external command is logged to `outputs/<domain>/logs/commands.log`.
* Stdout / stderr are persisted to `outputs/<domain>/logs/<stage>.stdout` /
  `.stderr` for post-mortem analysis.
* This tool is for **authorized recon only** — do not use it against systems
  you do not own or have explicit permission to test.
# recon2win
