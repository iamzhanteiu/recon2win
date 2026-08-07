# recon2win Console — Web Management UI Design Spec

Design spec for a dark-first, analyst-grade web console over the existing recon2win
engine. **No backend redesign, no scanner changes.** This document describes the
management/visualisation layer only.

Audience: whoever implements the frontend, plus whoever builds the thin read API it
needs.

---

## 0. Data reality map (read this first)

The design below is written against **fields that actually exist on disk today**.
Every module is tagged so nobody builds a screen with no data behind it.

Legend: ✅ backed by real data · ⚠️ partial / derivable · ❌ no producer yet

| UI module | Status | Source of truth |
|---|---|---|
| Targets | ✅ | `outputs/<domain>/` directory per target |
| Projects | ❌ | no concept — needs UI-side grouping (see §0.2) |
| Subdomains | ✅ | `processed/subdomains.txt`, `.scan_state.json` |
| DNS Records | ✅ | `processed/resolved_detail.json` — `subdomain, ip, aaaa, cname, asn, resolver` |
| Hosts | ✅ | `processed/alive_detail.json` — `url, host, host_ip, port, scheme, status_code, content_length, content_type, webserver, tech[], cdn_name, cdn_type, time, a[], path, knowledgebase.PageType/pHash` |
| URLs | ✅ | `processed/all_urls.txt`, `alive_urls.txt`, `dynamic_urls.txt`, `parameterized_urls.txt`; aggregate in `summary.json.url_surface` (`total, by_status, by_type, apis, auth_gated`) |
| JavaScript Files | ✅ | `processed/js_urls.txt` |
| API Endpoints | ✅ | `processed/jsluice_endpoints.txt`, `jsluice_urls.txt`, `xnlinkfinder_endpoints.txt`, `summary.json.interesting_api_paths`, apidocs module |
| Misconfig Hits | ✅ | `findings/misconfig_probe.json` — `service, confidence, status, url` (actuator/Jenkins/GitLab/k8s/phpMyAdmin, deep-tier hosts only — see `fuzz_depth` module) |
| Parameters | ✅ | `processed/jsluice_params.json` (`url, method, queryParams[], bodyParams[]`), `arjun_params.txt` |
| Technologies | ✅ | derived — `alive_detail.json[].tech[]` + `webserver` |
| Secrets | ✅ | `findings/jsluice_secrets.json` — `kind, severity, url, data{}, context` |
| Nuclei Results | ✅ | `findings/{default,endpoints,dynamic}/nuclei.json` — full nuclei JSON incl. `template-id, info.severity, info.name, matched-at, template-url` |
| Interesting Assets | ✅ | `summary.json.high_value_targets` (`url, categories[]`), `report/priority_targets.txt` |
| Scan Jobs / History | ✅ | `logs/stages.json` — `stage, status, input, outputs[], count, error, extra.elapsed_seconds` |
| Logs | ✅ | `logs/<stage>.log`, `logs/commands.log` |
| Diff / Changes | ✅ | `report/delta.md`, `stages.json` → `scan_diff` entry |
| Reports | ✅ | `report/final_report.{html,md}`, `summary.json`, `graph.mmd` |
| Attack Surface Graph | ⚠️ | `report/graph.mmd` exists (static Mermaid); interactive graph needs an edge-list endpoint derived from existing joins |
| HTTP Responses | ⚠️ | only `responses/preview.json` + `index.md` on some targets — no full response bodies |
| Open Ports | ⚠️ | httpx probes 80/443 only — `port` field exists but no port-scan stage (no naabu) |
| Certificates / TLS | ❌ | no tlsx / cert collection stage |
| Screenshots | ❌ | no screenshot stage (note: `knowledgebase.pHash` implies httpx screenshot mode is one flag away) |
| Findings triage state | ❌ | nuclei output is stateless — no open/verified/ignored/reported/FP |
| Tags | ❌ | no tag store |
| Scheduler | ❌ | no scheduler (cron-only today) |
| Notifications | ⚠️ | `modules/telegram.py` sends out; no inbox/feed model |
| Settings | ⚠️ | `config.yml` exists and is surfaced in `summary.json.config_text` |

### 0.1 The two things the UI genuinely needs added

Not backend redesign — additive, and unavoidable:

**A. A read API.** Today there is no way to query data over HTTP. The UI needs a
paginated, filterable read layer over `outputs/`. Recommended shape:

```
GET /api/v1/targets
GET /api/v1/targets/{domain}/summary          → summary.json passthrough
GET /api/v1/targets/{domain}/hosts            ?q=&status=&tech=&cdn=&sort=&page=&limit=
GET /api/v1/targets/{domain}/hosts/{host}     → joined host detail bundle
GET /api/v1/targets/{domain}/dns
GET /api/v1/targets/{domain}/urls             ?status=&type=&has_params=&q=
GET /api/v1/targets/{domain}/js
GET /api/v1/targets/{domain}/endpoints
GET /api/v1/targets/{domain}/findings         ?severity=&source=&state=&q=
GET /api/v1/targets/{domain}/stages           → logs/stages.json
GET /api/v1/targets/{domain}/logs/{stage}     ?tail=&follow=1 (SSE)
GET /api/v1/targets/{domain}/graph            ?depth=&root=
GET /api/v1/search                            ?q=  (cross-target)
```

Two hard constraints from the data: `all_urls.txt` hit **469,143 rows** on
guildwars2.com and `katana_urls.txt` is **63 MB**. Line-oriented text files cannot
be paged, sorted or filtered at that size on every request. Build a **SQLite index
per target** (`outputs/<domain>/index.db`), rebuilt at end of run from the same
files, and serve all list endpoints from it. Everything else stays as-is.

**B. A small mutable state store** for things the engine deliberately does not own:
projects, tags, finding triage state + notes + assignee, saved filters, schedules,
notification read-state. One SQLite file at `outputs/_console.db`. This is UI state,
not recon state — keeping it out of `outputs/<domain>/` means a target directory
stays disposable and re-scannable.

### 0.2 Project model

Today: `outputs/<domain>` is simultaneously the project, the target and the scope.
The UI introduces a grouping layer without touching disk layout:

```
Project  (console.db)  — e.g. "Acronis VDP", "HackerOne — Q3"
  └── Target  (= outputs/<domain>/, the real unit of scanning)
        └── Scan Run  (= one main.py execution, keyed by logs/stages.json + summary.meta)
              └── Assets (subdomains → hosts → urls → js → endpoints → findings)
```

A target may belong to exactly one project (keeps breadcrumbs unambiguous).
Projects are cheap: create, rename, colour, archive.

---

## 1. Information architecture

```
recon2win Console
│
├── GLOBAL SCOPE  (all projects — the "fleet" view)
│   ├── Dashboard                 fleet health, risk-ranked targets, global deltas
│   ├── Asset Inventory ★         cross-project asset search — THE primary screen
│   ├── Findings                  cross-project triage queue
│   ├── Scan Jobs                 running / queued / done / failed
│   ├── Scheduler                 recurring scans
│   ├── Notifications             event feed
│   └── Settings                  config, tools, integrations, API keys
│
├── PROJECT SCOPE  (scoped by project switcher in top bar)
│   ├── Project Dashboard         widgets: alive hosts, new assets, criticals, tech mix
│   ├── Targets                   domains in this project
│   ├── Attack Surface ★          interactive graph
│   ├── Reports                   generated reports + exports
│   └── History                   run-over-run diff timeline
│
└── TARGET SCOPE  (scoped by target)
    ├── Overview                  target summary + stage health
    ├── Assets
    │   ├── Subdomains
    │   ├── Hosts          → Host Detail (14 tabs)
    │   ├── URLs
    │   ├── API Endpoints
    │   ├── JavaScript Files
    │   ├── Parameters
    │   ├── Technologies
    │   ├── DNS Records
    │   ├── Certificates      (dark until tlsx stage exists)
    │   ├── Open Ports        (dark until port-scan stage exists)
    │   ├── HTTP Responses
    │   └── Screenshots       (dark until screenshot stage exists)
    ├── Findings
    │   ├── Nuclei Results
    │   ├── Secrets
    │   └── Interesting Assets
    ├── Scan History          runs, stages, logs, artifacts
    └── Report                embedded final_report.html + downloads
```

★ = the two screens that carry the product.

**Scope is a first-class URL concept**, not a hidden dropdown:

```
/                                       fleet dashboard
/inventory?scope=all                    global asset inventory
/p/acronis-vdp                          project dashboard
/p/acronis-vdp/graph                    attack surface
/t/acronis.com                          target overview
/t/acronis.com/hosts                    host table
/t/acronis.com/hosts/www.acronis.com    host detail
/t/acronis.com/findings?severity=high
/t/acronis.com/runs/2026-07-25T14:38
```

Every filter state is URL-encoded. An analyst can paste a link into Slack and the
recipient lands on the exact same filtered view. Non-negotiable for a SOC tool.

---

## 2. Sidebar hierarchy

Two-rail sidebar. Rail 1 is constant (scope + global nav), rail 2 is contextual
(current scope's sections). Collapses to icons at `<1280px`, drawer at `<768px`.

```
┌────┬──────────────────────┐
│ ▣  │  ACRONIS VDP      ▾  │  ← project switcher (⌘P)
│    │                      │
│ ⌂  │  ── GLOBAL ─────────  │
│ ▤  │   ⌂  Dashboard        │
│ ⚑  │   ▤  Asset Inventory  │  ⌘⇧A
│ ⏱  │   ⚑  Findings     12▲ │  badge = unresolved critical+high
│ ⚙  │   ⏱  Scan Jobs     2● │  badge = running
│    │   ⌾  Scheduler        │
│    │   ⌁  Notifications  5 │
│    │                       │
│    │  ── PROJECT ────────  │
│    │   ◈  Overview         │
│    │   ⊞  Targets       4  │
│    │   ⧉  Attack Surface   │
│    │   ⎘  Reports          │
│    │   ⟲  History          │
│    │                       │
│    │  ── TARGET ─────────  │
│    │   acronis.com      ▾  │  ← target switcher (⌘T)
│    │   ◉  Overview         │
│    │   ▼ Assets            │
│    │     Subdomains    574 │
│    │     Hosts         574 │
│    │     URLs        18.7k │
│    │     API Endpoints 316 │
│    │     JavaScript    421 │
│    │     Parameters    1.2k│
│    │     Technologies   88 │
│    │     DNS Records  1689 │
│    │     Certificates    — │  dimmed, tooltip "no TLS stage"
│    │     Open Ports      — │  dimmed
│    │     Responses       2 │
│    │     Screenshots     — │  dimmed
│    │   ▼ Findings          │
│    │     Nuclei          3 │
│    │     Secrets        47 │
│    │     Interesting   112 │
│    │   ⏱  Scan History  9  │
│    │   ⎘  Report           │
│ ⌄  │                       │
│ ▢  │  nhantieu        ⚙    │
└────┴──────────────────────┘
```

Rules:
- **Counts live in the nav.** An analyst decides where to go based on volume. A nav
  item with no number is a nav item you have to click to evaluate — that's a wasted
  click, 200× a day.
- **Dimmed ≠ hidden.** Certificates/Ports/Screenshots stay visible and dimmed with a
  tooltip explaining which stage would populate them. Hiding them makes the product
  look incomplete; dimming makes it look *honest and extensible*.
- Section headers are sticky. The target sub-tree scrolls independently.
- `[` toggles rail 2. `⌘B` toggles the whole sidebar for max-density work.

---

## 3. Navigation flow

**Primary loop (the 8-hour-a-day path):**

```
Dashboard ──► "3 new criticals on acronis.com"
    │
    ▼
Findings (filtered severity:critical, state:open)
    │  click row → split-pane detail opens on the right, table stays
    ▼
Finding detail ──► "matched-at: https://cloud.acronis.com/api/v1/…"
    │  pivot ⤳
    ▼
Host Detail: cloud.acronis.com
    │  tabs: Overview / Headers / Tech / JS / Endpoints / Findings / Timeline
    ▼
JS tab → app.7f3c.js → 12 extracted endpoints → 2 secrets
    │  select 2 rows → Bulk → "Tag: needs-manual" + "Rescan with nuclei"
    ▼
back to Findings queue (browser back restores exact filter + scroll + selection)
```

**Three entry paths, all one keystroke:**

1. `⌘K` command palette — "go to acronis.com", "run scan", "filter status:403"
2. `/` global search — searches assets across every project, results grouped by type
3. Sidebar — for browsing rather than seeking

**Pivot is universal.** Any host/URL/domain rendered anywhere in the app is a
right-clickable pivot source:

```
right-click on  api.acronis.com
┌──────────────────────────────┐
│ Open host detail        ↵    │
│ Open in Attack Surface  G    │
│ ─────────────────────────    │
│ Filter inventory by this     │
│ Show findings (3)            │
│ Show JS files (12)           │
│ Show DNS records             │
│ ─────────────────────────    │
│ Copy host           ⌘C       │
│ Copy as curl                 │
│ Open in browser         ⇧↵   │
│ ─────────────────────────    │
│ Tag…                    T    │
│ Rescan host…                 │
└──────────────────────────────┘
```

**Back always restores state.** Table scroll offset, selection, filter chips, split
pane width, active tab. Stored per history entry.

---

## 4. Universal contracts

Defined once here; every page below inherits and only states its *deltas*. This is
also the component contract — one `<DataTable>` implementation, 25 usages.

### 4.1 Data table contract

Every table in the product supports, without exception:

| Capability | Behaviour |
|---|---|
| Pagination | Cursor-based. Footer: `1–100 of 18,722`. Page size 50/100/250/500. Virtualised rows above 250. |
| Sorting | Click header; ⇧-click adds secondary sort. Sort state in URL. Server-side. |
| Column visibility | `⌘⇧C` opens column manager: reorder (drag), toggle, pin left/right, reset. Persisted per table per user. |
| Saved filters | Name + save current filter set. Shared across team. Pinned ones become toolbar chips. `console.db`. |
| Tag filtering | `tag:prod`, `tag:!ignored` in query bar; tag chips in the filter rail. |
| Quick search | Debounced 200ms, searches the table's primary text column. `⌘F` focuses. |
| Export CSV | Exports **current filter**, not current page. Streamed. Column set = visible columns. |
| Export JSON | Same, full field set (not just visible), NDJSON option for big sets. |
| Bulk tagging | Select → `T` → tag picker with typeahead + create-new. |
| Bulk delete | Select → `⌫` → confirm modal naming the count. Soft-delete (`hidden` flag), restorable from Trash. Never deletes engine output. |
| Bulk rescan | Select → `R` → stage picker (nuclei / httpx / jsluice / full) → queues a job, toast links to Scan Jobs. |
| Row selection | Click checkbox, ⇧-click range, `⌘A` select-all-matching-filter (not just page). Sticky selection bar. |
| Density | Compact / Comfortable toggle. **Compact is default** — 28px rows, 40 rows visible at 1080p. |
| Copy | `⌘C` copies selected rows as TSV; `⌘⇧C` as JSON. |

**Selection bar** (appears docked at table bottom when ≥1 row selected):

```
┌────────────────────────────────────────────────────────────────────┐
│ ✓ 47 selected  (of 18,722 matching)   [Select all matching]        │
│                                                                     │
│  🏷 Tag   ⟳ Rescan   ⚑ Create finding   ⤓ Export   ⊘ Ignore   🗑    │
└────────────────────────────────────────────────────────────────────┘
```

### 4.2 Query bar (advanced filtering)

One text input, Kibana/GitHub-style, above every table. Structured but forgiving.

```
┌──────────────────────────────────────────────────────────────────────┐
│ 🔍  status:200 AND tech:nginx AND NOT cdn:cloudflare AND new:7d      │
└──────────────────────────────────────────────────────────────────────┘
     ↑ typeahead suggests fields, then values from the actual index
```

Grammar: `field:value`, `field:>value`, `field:a,b` (OR), `AND`/`OR`/`NOT`,
`"quoted phrase"`, `/regex/`, bare words = full-text. Fields come from the data map
in §0 — `status`, `tech`, `webserver`, `cdn`, `ip`, `asn`, `port`, `ctype`, `title`,
`len`, `severity`, `source`, `state`, `tag`, `new`, `changed`.

Below the input: filter results as removable chips, so a complex query is still
readable and partially undoable:

```
 [status:200 ×] [tech:nginx ×] [not cdn:cloudflare ×] [new:7d ×]   Clear all
 ⌕ 1,643 of 18,722                              💾 Save filter  ⤓ Export
```

Why one bar and not 12 dropdowns: dropdowns don't compose, can't express `NOT`, and
can't be pasted into a ticket. Power users type. The filter rail (§4.3) exists for
the discovery case.

### 4.3 Filter rail

Collapsible left rail inside the content area (`\` toggles). Faceted counts drawn
from the actual index — every facet shows how many rows it would yield, so an
analyst never clicks into an empty result.

```
┌────────────────────┐
│ FILTERS      Clear │
│                    │
│ ▼ Status           │
│  ☑ 200      1,643  │
│  ☐ 301     12,246  │
│  ☐ 403      4,128  │
│  ☐ 401          7  │
│  ☐ 5xx          5  │
│                    │
│ ▼ Technology       │
│  🔍 filter…        │
│  ☐ nginx      312  │
│  ☐ IIS         88  │
│  ☐ React       41  │
│  … show all (88)   │
│                    │
│ ▼ CDN              │
│  ☐ cloudflare 201  │
│  ☐ aws        150  │
│  ☐ none        88  │
│                    │
│ ▼ Content type     │
│ ▼ ASN              │
│ ▼ Port             │
│ ▼ Tags             │
│ ▼ First seen       │
│  ○ 24h ○ 7d ○ 30d  │
└────────────────────┘
```

Rail selections and query-bar text are the same state — clicking a facet writes a
chip into the bar, and vice versa.

### 4.4 State screens

Not afterthoughts. These are what analysts see most on a fresh target.

**Loading** — skeleton rows matching final row height (no layout shift), header and
toolbar render immediately and are interactive. Above 400ms show an inline
progress bar in the toolbar, never a blocking spinner. Never a full-page overlay.

**Empty (no data yet)** — explain *why* and offer the action that fixes it:

```
        ▤
   No hosts yet

   acronis.com hasn't completed an httpx stage.
   Subdomains: 574 · Resolved: 0

   [ Run DNS + probe stage ]   [ View scan history ]
```

**Empty (filtered to nothing)** — different copy, different action:

```
   No hosts match this filter

   status:200 AND tech:jboss
   The `tech:jboss` clause excludes all 1,643 rows.

   [ Remove tech:jboss ]   [ Clear all filters ]
```

**Error** — state what failed, at which layer, and what is still usable:

```
   ⚠ Couldn't load hosts

   GET /api/v1/targets/acronis.com/hosts → 500
   index.db missing or corrupt (run finished 2026-07-25, index built?)

   [ Retry ]  [ Rebuild index ]  [ Copy error ]  [ View raw alive_detail.json ]
```

**Stale/degraded** — a first-class state this domain needs. If the run had failed
stages, a persistent amber banner sits above the table:

```
 ⚠ Partial data — 2 of 14 stages failed in the last run (dirsearch, waymore).
   URL counts are undercounted.        [ View stages ]   [ Dismiss for this run ]
```

**Dark module** (certificates/ports/screenshots):

```
        ⚿
   Certificates not collected

   No TLS collection stage is configured for this target.
   Adding a `tlsx` stage to config.yml would populate this view.

   [ Docs: enabling TLS collection ]
```

---

## 5. Page-by-page

### 5.1 Fleet Dashboard `/`

**Purpose** — answer "where do I spend the next hour" in under five seconds, across
every project. This is the login screen; it must be scannable, not explorable.
(`modules/dashboard.py` already computes exactly this risk model — health,
risk score, staleness, delta — so this widget set is directly backed.)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ Fleet Dashboard                          Last 7 days ▾    ⟳ 2m ago    ⤓  ⚙  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ ┌──────────┐┌──────────┐┌──────────┐┌──────────┐┌──────────┐┌──────────┐    │
│ │ TARGETS  ││ ALIVE    ││ CRITICAL ││ NEW 7D   ││ SECRETS  ││ RUNS     │    │
│ │    4     ││  1,247   ││    3     ││   +182   ││    47    ││  2 ●     │    │
│ │  +1 ▲    ││  +94 ▲   ││  +3 ▲    ││          ││  +12 ▲   ││ running  │    │
│ │ ▁▂▃▅▆▇   ││ ▁▂▄▅▆▇   ││ ▁▁▁▁▂▃   ││ ▂▃▁▅▂▇   ││ ▁▁▂▂▃▃   ││          │    │
│ └──────────┘└──────────┘└──────────┘└──────────┘└──────────┘└──────────┘    │
│                                                                              │
│ ┌─────────────────────────────────────────┐┌───────────────────────────────┐ │
│ │ TARGETS BY RISK                         ││ CRITICAL & HIGH FINDINGS      │ │
│ │                                         ││                               │ │
│ │ ● acronis.com      ████████████ 340  ⚠ ││ ⬤ CRIT  Salesforce community  │ │
│ │   574 hosts · 3 crit · 2 stages failed  ││    misconfig                  │ │
│ │                                         ││    cloud.acronis.com     2h   │ │
│ │ ● discover.com     ███████ 180          ││                               │ │
│ │   412 hosts · 0 crit · healthy          ││ ⬤ HIGH  Exposed .git/config   │ │
│ │                                         ││    dev.discover.com      6h   │ │
│ │ ● guildwars2.com   ██ 40         STALE  ││                               │ │
│ │   194 hosts · 0 crit · 6d ago           ││ ⬤ HIGH  GCP key in JS bundle  │ │
│ │                                         ││    www.acronis.com       1d   │ │
│ │ ○ example.com      ▏ 0          NO RUN  ││                               │ │
│ │                                         ││        [ View all findings ]  │ │
│ └─────────────────────────────────────────┘└───────────────────────────────┘ │
│                                                                              │
│ ┌──────────────────────────┐┌──────────────────────────┐┌──────────────────┐ │
│ │ ASSET GROWTH             ││ TECHNOLOGY DISTRIBUTION  ││ RECENT SCANS     │ │
│ │  2.0k ┤            ╭──   ││ nginx      ████████ 312  ││ ● acronis   45%  │ │
│ │  1.5k ┤       ╭────╯     ││ IIS        ███ 88        ││   nuclei…  ▓▓▓░░ │ │
│ │  1.0k ┤   ╭───╯          ││ Cloudflare ██▌ 71        ││                  │ │
│ │  0.5k ┤╭──╯              ││ React      ██ 41         ││ ✓ discover  6h   │ │
│ │     0 ┼┴───┴───┴───┴──   ││ Apache     █▌ 33         ││   14/14 · 2h11m  │ │
│ │       Jun  Jul  Aug      ││ Express    █ 22          ││                  │ │
│ │  ─ hosts  ─ urls  ─ js   ││   [ view all 88 ]        ││ ✗ guildwars 6d   │ │
│ └──────────────────────────┘└──────────────────────────┘│   ffuf failed    │ │
│                                                          └──────────────────┘ │
│ ┌─────────────────────────────────────────────────────────────────────────┐  │
│ │ RECENT CHANGES                                    from report/delta.md   │  │
│ │ + 94 new subdomains      acronis.com        2026-07-25 14:38    [diff]  │  │
│ │ + 3 new alive hosts      discover.com       2026-07-25 09:12    [diff]  │  │
│ │ ~ 12 hosts changed status (200→403)  acronis.com                [diff]  │  │
│ │ − 6 subdomains disappeared           guildwars2.com             [diff]  │  │
│ └─────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

- **Layout** 12-col grid, widgets drag-reorderable, layout saved per user.
- **Toolbar** time range, refresh (auto 60s, pausable), export dashboard PNG/JSON.
- **Actions** every widget row is a pivot; every number is a link into a pre-filtered table.
- **Empty** first run → single centred "Add your first target" card with domain input.
- **Loading** each widget loads independently with its own skeleton; a slow widget never blocks the page.
- **Error** per-widget error card with retry — one dead widget doesn't kill the dashboard.
- **Bulk** n/a (dashboard is read-only).

**Project Dashboard** (`/p/{project}`) is the same layout scoped to one project,
with the required widget set: Alive Hosts, New Assets, Critical Findings, Technology
Distribution, Recent Scans, Asset Growth, Top Findings, Recent Changes — plus a
target grid replacing "targets by risk".

---

### 5.2 Asset Inventory `/inventory` ★ THE SCREEN

**Purpose** — one searchable surface over every asset in every project. An analyst
should be able to go from "I heard about a new nginx CVE" to "here are my 312
affected hosts, tagged and queued for rescan" in under 30 seconds without leaving
this page.

This is the screen the product is judged on. Everything else is supporting cast.

**Layout** — three panes, all resizable, split state persisted:

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ ▣ ACRONIS VDP ▾   🔍 status:200 AND tech:nginx AND new:7d              ⌘K   ⌁5   ◉ nhan  │
├──────────────┬────────────────────────────────────────────────────┬───────────────────────┤
│ FILTERS      │ ASSET INVENTORY                                    │ cloud.acronis.com  ✕ │
│        Clear │ ⌕ 312 of 18,722   💾 Saved ▾  ⊞ Cols  ⤓ Export     │ ───────────────────── │
│              │ [status:200 ×][tech:nginx ×][new:7d ×]             │  ┌─────────────────┐  │
│ SCOPE        │                                                    │  │                 │  │
│ ● All (4)    │ ┌──┬─────────────────────┬────┬─────┬──────┬────┐ │  │   screenshot    │  │
│ ○ acronis    │ │☐ │ HOST                │STAT│ TECH│  IP  │NEW │ │  │   unavailable   │  │
│ ○ discover   │ ├──┼─────────────────────┼────┼─────┼──────┼────┤ │  │                 │  │
│ ○ guildwars2 │ │☑ │● cloud.acronis.com  │200 │ngin…│185.…│ 2d │ │  └─────────────────┘  │
│              │ │  │  Acronis Cyber Cloud│    │ +4  │      │ ⬤3 │ │                       │
│ ▼ STATUS     │ ├──┼─────────────────────┼────┼─────┼──────┼────┤ │  cloud.acronis.com    │
│ ☑ 200  1,643 │ │☑ │● api.acronis.com    │200 │ngin…│185.…│ 2d │ │  200 · nginx · AWS    │
│ ☐ 301 12,246 │ │  │  {"version":"4.2"}  │    │ +2  │      │    │ │  185.174.140.101      │
│ ☐ 403  4,128 │ ├──┼─────────────────────┼────┼─────┼──────┼────┤ │  ───────────────────  │
│ ☐ 401      7 │ │☐ │● dev.acronis.com    │403 │ngin…│52.5.…│ 5d │ │  ⚑ FINDINGS       3   │
│ ☐ 5xx      5 │ │  │  403 Forbidden      │    │     │      │ 🏷 │ │  ⬤ CRIT Salesforce…  │
│              │ ├──┼─────────────────────┼────┼─────┼──────┼────┤ │  ⬤ MED  Missing CSP  │
│ ▼ TECH    🔍 │ │☐ │○ old.acronis.com    │ —  │ —   │  —   │30d │ │  ⬤ LOW  Version disc │
│ ☑ nginx  312 │ │  │  dead since 07-20   │    │     │      │    │ │  ───────────────────  │
│ ☐ IIS     88 │ └──┴─────────────────────┴────┴─────┴──────┴────┘ │  ⚙ TECHNOLOGIES   5   │
│ ☐ React   41 │                                                    │  nginx 1.18 · React   │
│ … all (88)   │ ┌────────────────────────────────────────────────┐│  HSTS · GA · jQuery    │
│              │ │ ✓ 2 selected (of 312)  [Select all 312]        ││  ───────────────────  │
│ ▼ CDN        │ │ 🏷 Tag  ⟳ Rescan  ⚑ Finding  ⤓ Export  🗑      ││  ⎔ JS FILES      12   │
│ ☐ aws    150 │ └────────────────────────────────────────────────┘│  app.7f3c.js   240KB  │
│ ☐ cloudfl 201│                                                    │  vendor.a91.js 1.2MB  │
│              │  1–100 of 312        ‹ 1 2 3 4 ›      100/page ▾  │  ───────────────────  │
│ ▼ TAGS       │                                                    │  ⇥ ENDPOINTS     47   │
│ ▼ FIRST SEEN │                                                    │  /api/v1/users        │
│ ○24h ●7d ○30d│                                                    │  /api/v1/tenants      │
│              │                                                    │  ───────────────────  │
│              │                                                    │  [ Open full detail ↵]│
└──────────────┴────────────────────────────────────────────────────┴───────────────────────┘
```

**Why this layout wins:**

- **Preview pane, not navigation.** Clicking a row fills the right pane; the table
  keeps its scroll and selection. An analyst triages 40 hosts without a single page
  load. `j`/`k` moves the row cursor and live-updates the preview — this is the
  Gmail/Superhuman pattern and it is worth ~10× on throughput.
- **Two-line rows.** Line 1 = identity + facts, line 2 = title/snippet/reason. Dense
  without being unreadable. Toggle to one-line for maximum density.
- **Facet counts before you click.** No dead-end filters.
- **The screenshot slot exists even though screenshots don't.** It renders a labelled
  placeholder. When the stage lands, the UI needs zero changes.

**Toolbar** — saved filters dropdown, column manager, export (CSV/JSON/NDJSON/target
list for piping into other tools), density toggle, refresh.

**Search** — the §4.2 query bar. Additionally supports pasted lists: dropping 400
hostnames into the bar auto-converts to `host:in(...)` — analysts constantly arrive
with a list from elsewhere.

**Statistics strip** (optional, `S` toggles) — a thin row of sparkline chips above
the table showing the current result set broken down by status / tech / age, so the
filter's *shape* is visible, not just its count.

**Actions** — per row: open detail, open in browser, copy as curl, pivot to graph,
tag, rescan, create finding. Bulk: all of §4.1.

**Empty** — "No assets in this project yet" + add-target CTA. Filtered-empty variant
per §4.4.

**Loading** — skeleton rows; facet counts load separately and shimmer until ready
(they're the expensive query).

**Error** — table-level error card; filter rail stays interactive so the analyst can
back out of a query that killed the request.

**Keyboard**

| Key | Action |
|---|---|
| `j` / `k` | next / prev row (live preview) |
| `x` | toggle selection |
| `⇧j/k` | extend selection |
| `↵` | open full detail |
| `⇧↵` | open host in new browser tab |
| `o` | open preview pane |
| `esc` | close preview / clear selection |
| `/` | focus query bar |
| `f` | focus filter rail |
| `t` | tag selected |
| `r` | rescan selected |
| `e` | export |
| `\` | toggle filter rail |
| `]` | toggle preview pane |
| `g` then `i/f/h/d` | go to inventory / findings / hosts / dashboard |
| `?` | shortcut cheatsheet |

---

### 5.3 Host Detail `/t/{domain}/hosts/{host}`

**Purpose** — everything known about one host, without leaving the page. Tabbed
because 14 sections stacked vertically is a scroll graveyard.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ‹ Hosts   cloud.acronis.com                        ⟳ Rescan  🏷 Tag  ⤓  ⋯      │
│ ● 200 OK · https · :443 · nginx · AWS CDN · 185.174.140.101 · 136ms             │
│ 🏷 prod  🏷 needs-manual                            first seen 2026-06-12 · 2d  │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Overview │Headers│Response│Tech│TLS│Certs│DNS│Ports│JS│Endpoints│Shots│Δ│Find│⏱ │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│ ┌───────────────────────────┐ ┌───────────────────────────────────────────────┐ │
│ │  screenshot placeholder   │ │ SUMMARY                                       │ │
│ │  (no screenshot stage)    │ │ Status        200 OK                          │ │
│ │                           │ │ Title         Acronis Cyber Cloud             │ │
│ │                           │ │ Server        nginx                           │ │
│ │                           │ │ Content-Type  text/html                       │ │
│ │                           │ │ Length        41,238 bytes                    │ │
│ │                           │ │ Response      136.87 ms                       │ │
│ └───────────────────────────┘ │ CDN           aws (cloud)                     │ │
│                               │ Page type     error  (httpx knowledgebase)    │ │
│ ┌───────────────────────────┐ │ Resolvers     8.8.4.4:53                      │ │
│ │ RISK                      │ └───────────────────────────────────────────────┘ │
│ │   ⬤⬤⬤⬤○  HIGH  score 78  │                                                   │
│ │  3 findings · 2 secrets   │ ┌───────────────────────────────────────────────┐ │
│ │  1 critical               │ │ ADDRESSES                                     │ │
│ └───────────────────────────┘ │ A     185.174.140.101, .103, .104, .106 (+3)  │ │
│                               │ AAAA  —                                       │ │
│ ┌───────────────────────────┐ │ CNAME abgw-phx1-arp1.acronis.com              │ │
│ │ QUICK STATS               │ │ ASN   —                                       │ │
│ │ JS files          12      │ └───────────────────────────────────────────────┘ │
│ │ Endpoints         47      │                                                   │
│ │ Parameters        23      │ ┌───────────────────────────────────────────────┐ │
│ │ URLs             318      │ │ RECENT ACTIVITY                               │ │
│ │ Findings           3      │ │ 2d   status 301 → 200                         │ │
│ │ Secrets            2      │ │ 2d   +4 technologies detected                 │ │
│ └───────────────────────────┘ │ 6d   first seen                               │ │
│                               └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

Tab contents:

| Tab | Content | Source |
|---|---|---|
| **Overview** | above | `alive_detail.json` + joins |
| **Headers** | response header table, security-header scorecard (HSTS/CSP/XFO/CORS graded), copy-all | ⚠ needs header capture — httpx `-irh` |
| **Response** | body viewer, syntax-highlighted, pretty/raw toggle, search-in-body, size guard >2MB | ⚠ `responses/preview.json` only |
| **Technologies** | chip grid grouped by category, version, confidence, "N other hosts run this" pivot | `tech[]`, `webserver` |
| **TLS** | protocol, cipher, ALPN, chain summary | ❌ dark |
| **Certificates** | subject, SAN list (pivot-able — SANs are a great subdomain source), issuer, validity gauge, fingerprint | ❌ dark |
| **DNS** | A/AAAA/CNAME/NS/MX/TXT records, resolver, ASN | `resolved_detail.json` |
| **Open Ports** | port grid + service + banner | ❌ dark (httpx 80/443 only) |
| **JavaScript** | JS file table: URL, size, hash, endpoints found, secrets found; inline source viewer with secret positions highlighted | `js_urls.txt`, jsluice |
| **Endpoints** | extracted endpoints, method, source JS file, params, "probe now" per row | `jsluice_endpoints.txt`, `jsluice_params.json` |
| **Screenshots** | current + historical thumbnails, diff slider | ❌ dark |
| **Historical Changes** | field-level diff timeline across runs (status, tech, title, IP, content-length) | `delta.md`, `scan_diff` |
| **Findings** | scoped findings table, full triage inline | nuclei + secrets |
| **Timeline** | unified chronological event stream — discovery, probes, status flips, findings, scans, tags, notes | derived |

**Actions** — rescan (stage picker), tag, add note, create finding, export bundle
(JSON of every tab), open in browser, copy as curl, mark out-of-scope.
**Empty/dark tabs** — per §4.4, never a blank pane.
**Loading** — header bar and tab strip render instantly from list-view data already
in cache; tab bodies lazy-load on first open and stay cached.

---

### 5.4 Attack Surface `/p/{project}/graph`

**Purpose** — see structure and reach, not rows. Answers "what hangs off this
subdomain", "which JS file feeds the most endpoints", "what's the blast radius of
this host". Replaces the static `report/graph.mmd` with something explorable.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│ ATTACK SURFACE — Acronis VDP     Layout: Force ▾  Depth: 4 ▾  ⛶  ⤓ PNG/SVG/JSON │
├───────────────────────────────────┬──────────────────────────────────────────────┤
│ LAYERS              │             │  NODE DETAIL                              ✕  │
│ ☑ Project     1     │             │  ──────────────────────────────────────────  │
│ ☑ Target      4     │      ◆ acronis.com                                         │
│ ☑ Subdomain 574     │       ╱  │  ╲   │  ⎔  app.7f3c.js                          │
│ ☑ Host      574     │      ╱   │   ╲  │  JavaScript bundle · 240 KB              │
│ ☑ JS        421     │     ●    ●    ● │  https://cloud.acronis.com/dist/…        │
│ ☑ Endpoint  316     │   www  cloud  api                                          │
│ ☑ Finding    50     │     │    │╲   │ │  ┌────────────────────────────────────┐  │
│                     │     │    │ ╲  │ │  │ CONNECTIONS                        │  │
│ COLOR BY            │     │    ⎔  ⎔ │ │  │ ← 1 host    cloud.acronis.com      │  │
│ ○ Type              │     │   app vendor │ → 12 endpoints                     │  │
│ ● Severity          │     │    │╲   │ │  │ → 2 findings   ⬤ LOW gcpKey ×2     │  │
│ ○ Status code       │     │    │ ╲  │ │  └────────────────────────────────────┘  │
│ ○ Technology        │     │    ⇥  ⇥ │ │                                          │
│ ○ Age               │     │  /api  /adm                                          │
│                     │     │    │    │ │  ┌────────────────────────────────────┐  │
│ FILTER              │     │    ⚑    │ │  │ ENDPOINTS (12)                     │  │
│ 🔍 severity:critical│     │  CRIT   │ │  │ /api/v1/users            GET       │  │
│                     │             │  │ /api/v1/tenants          GET       │  │
│ ☑ Hide isolated     │   ● alive  ○ dead    │ /api/v1/admin/config     POST  ⚑   │  │
│ ☑ Cluster by ASN    │   ⚑ finding          │ … 9 more                          │  │
│ □ Show dead nodes   │                      └────────────────────────────────────┘  │
│                     │  ⊕ ⊖ ⌂  1,946 nodes / 3,102 edges                            │
│ ── MINIMAP ──       │                       │ [Open host detail]  [Filter inventory]│
│ ┌───────────┐       │                       │ [Expand neighbours] [Pin node]        │
│ │  ░▒▓█▒░   │       │                       │                                       │
│ └───────────┘       │                       │                                       │
└─────────────────────┴───────────────────────┴───────────────────────────────────────┘
```

**Node types & shapes** — Project ◆ / Target ◆ / Subdomain ● / Host ● / JS ⎔ /
Endpoint ⇥ / Finding ⚑. Size ∝ degree. Colour by the selected dimension.

**Interaction**
- Click node → detail panel (does not navigate away)
- Double-click → expand its neighbours (progressive disclosure)
- `⌘`-click → multi-select → bulk actions on the selection
- Drag → reposition + pin; pinned layout persists per project
- Scroll → zoom to cursor; box-select with drag on empty canvas
- Hover → highlight the full path root→node, dim everything else

**Layouts** — Force-directed (default, organic), Hierarchical (strict
Project→Target→Subdomain→Host→JS→Endpoint→Finding tiers, best for the required
relationship model), Radial (one target at centre), Cluster (grouped by ASN/CDN/tech).

**Performance** — this is the real constraint. 574 hosts is fine; 18k URLs is not.
Rules: never render URL nodes by default (they're a count badge on the host node);
cap at 2,000 visible nodes; above that, auto-collapse to aggregate nodes ("+418
hosts") that expand on click. Canvas/WebGL rendering, not SVG.

**Empty** — "Graph needs at least one completed run." **Loading** — progressive:
render tiers as they stream, don't wait for the full edge list. **Error** — fall
back to offering the static `graph.mmd` download.

---

### 5.5 Findings `/findings` · `/t/{domain}/findings`

**Purpose** — a triage queue with real workflow state. Today nuclei output is
stateless: every run re-reports the same finding and there's no way to say "seen it,
it's a false positive". This screen adds the state layer (in `console.db`, keyed by
a stable finding fingerprint: `template-id + matched-at + host`).

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│ FINDINGS                                        ⌕ 50   💾 Saved ▾  ⊞ Cols  ⤓  ⟳      │
│ 🔍 severity:critical,high AND state:open                                              │
├─────────────┬─────────────────────────────────────────────┬───────────────────────────┤
│ STATE       │ ┌─┬────┬──────────────────────┬──────┬─────┐│ Salesforce Community      │
│ ●Open   34  │ │☐│SEV │ FINDING              │ HOST │AGE  ││ Misconfiguration       ✕  │
│ ○Verified 8 │ ├─┼────┼──────────────────────┼──────┼─────┤│ ───────────────────────── │
│ ○Ignored  5 │ │☑│⬤CR │Salesforce community  │cloud…│ 2h  ││ ⬤ CRITICAL   CVSS 9.1    │
│ ○Reported 2 │ │ │    │misconfig             │      │     ││ Risk score 94             │
│ ○False P  1 │ │ │    │nuclei · default      │      │ ⚑   ││ ───────────────────────── │
│             │ ├─┼────┼──────────────────────┼──────┼─────┤│ STATE                     │
│ SEVERITY    │ │☐│⬤HI │Exposed .git/config   │dev.d…│ 6h  ││ [Open ▾] [Assign ▾] [⚑]  │
│ ⬤ Critical 3│ │ │    │nuclei · endpoints    │      │     ││  Open · unassigned        │
│ ⬤ High    12│ ├─┼────┼──────────────────────┼──────┼─────┤│ ───────────────────────── │
│ ⬤ Medium  18│ │☐│⬤HI │GCP API key in bundle │www.a…│ 1d  ││ MATCHED AT                │
│ ⬤ Low     15│ │ │    │jsluice · gcpKey      │      │     ││ https://cloud.acronis.com │
│ ⬤ Info     2│ ├─┼────┼──────────────────────┼──────┼─────┤│ /services/data/v52.0/…    │
│             │ │☐│⬤ME │Missing CSP header    │api.a…│ 1d  ││  [open] [curl] [host ↗]   │
│ SOURCE      │ │ │    │nuclei · default      │      │     ││ ───────────────────────── │
│ ☐ nuclei 41 │ └─┴────┴──────────────────────┴──────┴─────┘│ TEMPLATE                  │
│ ☐ jsluice 7 │                                             │ salesforce-community-     │
│ ☐ manual  2 │ ┌───────────────────────────────────────────┐│ misconfig                │
│             │ │ ✓ 1 selected  🏷 ⚑ State ▾ 👤 Assign ▾ ⤓ ││ misconfiguration/http     │
│ TEMPLATE 🔍 │ └───────────────────────────────────────────┘│  [view on cloud.pd.io ↗]  │
│ ASSIGNEE    │                                             │ ───────────────────────── │
│ TAGS        │  1–50 of 50                    50/page ▾    │ EVIDENCE                  │
│ FIRST SEEN  │                                             │ ┌───────────────────────┐ │
│             │                                             │ │ GET /services/data/…  │ │
│             │                                             │ │ HTTP/1.1 200 OK       │ │
│             │                                             │ │ {"records":[{"Id":…   │ │
│             │                                             │ └───────────────────────┘ │
│             │                                             │ ───────────────────────── │
│             │                                             │ NOTES (2)          + Add  │
│             │                                             │ nhan · 1h                 │
│             │                                             │ "Confirmed manually,      │
│             │                                             │  guest user can read       │
│             │                                             │  Contact object."          │
│             │                                             │ ───────────────────────── │
│             │                                             │ TIMELINE                  │
│             │                                             │ 2h  detected (run #9)     │
│             │                                             │ 1h  note added            │
│             │                                             │ ───────────────────────── │
│             │                                             │ [Report ▸] [Ignore] [FP]  │
└─────────────┴─────────────────────────────────────────────┴───────────────────────────┘
```

**Workflow states** — `Open → Verified → Reported`, with `Ignored` and
`False Positive` as terminal branches. Transitions are one keystroke (`v`, `i`, `f`,
`r`) and always require a reason note for `Ignored`/`False Positive` (so the next
analyst knows why, and so suppression is auditable).

**Suppression is the killer feature.** Marking a finding False Positive stores its
fingerprint; subsequent runs auto-suppress the match and it never re-enters the
queue. Without this, a recurring nuclei scan produces the same 50 rows forever and
the queue becomes noise. Suppressed matches remain visible under `state:false_positive`.

**Risk score** — composite: severity weight × exposure (is host internet-facing,
auth-gated?) × asset criticality (tags) × age. `modules/dashboard.py` already has a
`_RISK_WEIGHTS` model — reuse those weights so the UI and the CLI agree.
CVSS is a manual field (nuclei templates rarely carry one); shown only when set.

**Bulk** — set state, assign, tag, export, create report bundle. Bulk state change
on 40 rows is the single most-used action in a triage session; it must be one
keystroke after selection.

**Empty** — "No open findings. 🎉 Last scan 2h ago, 14/14 stages clean." with a link
to all findings including closed ones. Crucially *not* a bare empty table — zero
findings is meaningful information and should read as a positive result plus its
provenance (analysts need to distinguish "clean" from "scan didn't run").

**Sub-views** — *Nuclei Results* (same table, `source:nuclei`, extra template
columns), *Secrets* (`source:jsluice`, columns: kind, redacted value with reveal-on-
click + copy, JS file, occurrences across hosts), *Interesting Assets*
(`high_value_targets` — URL, matched categories, why-it-matched explanation, promote
to finding).

---

### 5.6 Scan Jobs & History

**Scan Jobs** `/jobs` — live operational view. Auto-refresh via SSE (the existing
`/api/stream/<scan_id>` pattern already proves this works).

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│ SCAN JOBS                        ● 2 running · 1 queued · 47 done · 3 failed  ⟳   │
│ [ Running ] [ Queued ] [ Completed ] [ Failed ] [ All ]        + New Scan          │
├───────────────────────────────────────────────────────────────────────────────────┤
│ ● RUNNING                                                                         │
│ ┌───────────────────────────────────────────────────────────────────────────────┐ │
│ │ acronis.com · full scan          started 14:38 · elapsed 1h 12m · ETA ~48m     │ │
│ │ ████████████████████████░░░░░░░░░░░░░░░░░  9/14 stages · 62%                   │ │
│ │                                                                                │ │
│ │ ✓ subdomain  30.6s  574   ✓ dnsx     0.4s  1689   ✓ httpx    4m12s  574        │ │
│ │ ✓ crawl      22m    18.7k ✓ jsluice  3m01s 421    ✓ apidocs  1m    16          │ │
│ │ ⏵ nuclei_default  ▓▓▓▓▓▓░░░░ 61%  1,204/1,980 hosts · 3 findings · 18m        │ │
│ │ ○ nuclei_endpoints  ○ dirsearch  ○ ffuf  ○ report  ○ diff                      │ │
│ │                                                                                │ │
│ │ [ ▮ Pause ]  [ ✕ Cancel ]  [ ⌗ Live logs ]  [ ⤓ Artifacts ]                    │ │
│ └───────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                   │
│ ⧗ QUEUED                                                                          │
│ │ discover.com · nuclei only · queued 14:51 · position 1    [↑] [✕]              │
│                                                                                   │
│ ✓ COMPLETED / ✗ FAILED                                                            │
│ ┌────┬──────────────┬──────────┬────────┬────────┬─────────┬──────────┬────────┐ │
│ │    │ TARGET       │ MODE     │ START  │ DURA   │ STAGES  │ FINDINGS │        │ │
│ ├────┼──────────────┼──────────┼────────┼────────┼─────────┼──────────┼────────┤ │
│ │ ✗  │ guildwars2   │ full     │ 6d ago │ 6h10m  │ 12/14 ⚠ │ 0        │ [logs] │ │
│ │ ✓  │ discover.com │ full     │ 6h ago │ 2h11m  │ 14/14   │ 12       │ [logs] │ │
│ │ ✓  │ acronis.com  │ nuclei   │ 1d ago │ 18m    │ 3/3     │ 3        │ [logs] │ │
│ └────┴──────────────┴──────────┴────────┴────────┴─────────┴──────────┴────────┘ │
└───────────────────────────────────────────────────────────────────────────────────┘
```

Backed by `logs/stages.json` — every field shown (`stage`, `status`, `count`,
`error`, `extra.elapsed_seconds`) exists today. Only queue/pause/cancel need a job
runner.

**Job Detail** — split view: stage list left, live log tail right (xterm-style,
follow-tail toggle, search, level filter, download). Artifacts tab lists
`stage.outputs[]` with size and a preview/download per file. Failed stages show
`error` inline with a "retry this stage only" button — `main.py` already supports
resume, so this is a UI affordance over existing capability.

**History** `/p/{project}/history` — run-over-run change timeline, from
`report/delta.md` + `scan_diff`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ HISTORY — acronis.com          Compare: [run #9 ▾] ⇄ [run #8 ▾]   ⤓ diff    │
├─────────────────────────────────────────────────────────────────────────────┤
│  ●─── run #9   2026-07-25 14:38   2h11m   14/14 ✓                           │
│  │    +94 subdomains  +12 hosts  +3 findings  ~12 status changes            │
│  │    ┌──────────────────────────────────────────────────────────────────┐  │
│  │    │ + cloud-eu.acronis.com          new · 200 · nginx        [pivot] │  │
│  │    │ + dev-api.acronis.com           new · 403                [pivot] │  │
│  │    │ ~ old.acronis.com               200 → 410                [pivot] │  │
│  │    │ − legacy.acronis.com            gone (was 200)           [pivot] │  │
│  │    │   … 115 more changes                            [ view all diff ]│  │
│  │    └──────────────────────────────────────────────────────────────────┘  │
│  │                                                                          │
│  ●─── run #8   2026-07-18 09:02   1h58m   13/14 ⚠  (ffuf failed)            │
│  │    +6 subdomains  +2 hosts  0 findings                                   │
│  ●─── run #7   2026-07-11 09:02   2h04m   14/14 ✓                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

Change types are colour-coded and filterable: `+ added`, `− removed`, `~ modified`.
Every change row pivots to the asset. Two-run comparison picker for arbitrary diffs.

---

### 5.7 Remaining pages (deltas from the universal contract)

Each inherits §4.1–4.4 in full. Only what's specific is listed.

**Projects** `/projects` — card grid (not a table): name, colour, target count, host
count, open criticals, last scan, risk sparkline. Actions: create, rename, archive,
move targets between projects. Empty: single create-project CTA.

**Targets** `/p/{project}/targets` — table: domain, project, hosts, urls, findings by
severity chips, last run, health badge (`healthy` / `degraded` / `no_report` /
`stale` — these four states come straight from `modules/dashboard.py`), risk score,
next scheduled run. Row actions: scan now, edit scope, view report, archive. Bulk:
scan selected, tag, move to project.

**Subdomains** — table: subdomain, resolved?, IP(s), CNAME, alive?, status, source
tool (subfinder/amass/chaos — `raw/subdomain/*.txt` tells us which), first seen.
Facets: resolved, alive, source, wildcard-suspected. Bulk: probe, tag, mark
out-of-scope. Value-add column: **source count** — a subdomain found by 3 tools is
more trustworthy than one found by permutation alone.

**URLs** — the biggest table (469k rows on one target). Columns: URL (truncated
middle, full on hover), status, content-type, length, params count, source
(crawler/waymore/jsluice/ffuf/dirsearch), host. Facets from
`summary.json.url_surface.by_status` / `by_type` — already precomputed, so facets
are instant. Extra filters: `has_params`, `is_api`, `auth_gated`, extension.
**Must be virtualised and server-paged**; never load more than one page.

**API Endpoints** — endpoint path, method, source JS file, params (query/body from
`jsluice_params.json`), probed status, host. Grouping toggle: flat list vs. tree by
path segment (`/api/v1/users`, `/api/v1/tenants` collapse under `/api/v1`) — the
tree view is how you spot an undocumented API surface in seconds. Actions: probe
now, send to fuzzer, create finding.

**JavaScript Files** — URL, size, host, endpoints extracted, secrets found, hash,
first seen, changed? Row expands to inline source viewer with extracted endpoints
and secret positions highlighted in the gutter. Sort by "secrets found" desc by
default — that's why you're on this page. Diff view when a file's hash changes
between runs (JS diffs are where new endpoints appear).

**Technologies** — two views: (a) aggregate table — technology, version, host count,
% of surface, first seen, findings-on-hosts-running-it; (b) matrix heatmap
host × tech. Clicking a tech filters inventory to `tech:X`. This is the "new CVE
dropped" page: search the tech, get the affected hosts, bulk-tag, bulk-rescan.

**DNS Records** — subdomain, type, value, TTL, resolver, ASN. From
`resolved_detail.json` (1,689 rows on acronis.com). Facets by record type, resolver,
ASN. Highlight dangling CNAMEs (CNAME present, no resolution) — takeover candidates,
and this is derivable from data already on disk.

**Certificates** ❌ dark — spec'd for when a TLS stage exists: subject, issuer, SANs
(each SAN pivot-able and diffable against known subdomains — free asset discovery),
valid from/to with an expiry gauge, key algorithm, fingerprint, hosts sharing this cert.

**Open Ports** ❌ dark — host × port matrix, service, banner, first seen.

**HTTP Responses** — request/response pairs, header table, body viewer with
syntax highlighting and search, security-header scorecard. Currently only
`responses/preview.json`; page degrades to "preview only" mode with a banner.

**Screenshots** ❌ dark — masonry grid, hover to zoom, click for lightbox with
metadata sidebar and prev/next. Filter by status/tech/tag. Selection → bulk tag.
Diff mode: side-by-side or slider between two runs — visual diff is the fastest way
to spot a changed login page across 500 hosts.

**Scheduler** ❌ needs a scheduler — list of schedules: target, cadence (cron or
preset), stages, next run, last run + result, enabled toggle. Create modal with a
human-readable cron preview ("every Monday at 02:00 UTC — next: Mon 4 Aug 02:00").
Calendar view showing scan load per day, so an analyst doesn't stack six 6-hour
scans on the same night.

**Reports** — generated report list: target, type, date, size, format. Preview pane
embeds the existing `report/final_report.html` in a sandboxed iframe (it's already a
complete standalone report — reuse it, don't rebuild it). Actions: download
HTML/MD/JSON, regenerate, share link. Report builder: pick target + run + sections +
severity threshold + branding.

**Notifications** — event feed grouped by day: new critical finding, scan completed,
scan failed, new asset spike, schedule missed. Read/unread, filter by type/project,
mark all read. Settings sub-tab configures channels — `modules/telegram.py` already
exists as a sink, so the UI configures rules ("notify on critical+high only") and
shows delivery status.

**Settings** — tabbed: **Profile** (theme, density, default landing page, timezone),
**Projects & Targets** (scope rules, out-of-scope patterns), **Scanning** (edit
`config.yml` in a schema-aware YAML editor with validation + diff-before-save —
`summary.json.config_text` proves config is already serialised per run),
**Tools** (installed tool versions + health from `summary.json.tool_versions` and
`missing_tools`, backed by `modules/doctor.py` — show a red row per missing tool with
the install command), **Integrations** (Telegram, HackerOne — `modules/hackerone.py`
exists — webhooks), **API keys**, **Notifications**, **Data** (retention, index
rebuild, export all, storage usage per target).

---

## 6. Component hierarchy

```
<App>
├── <CommandPalette/>            ⌘K — global, portal-rendered
├── <ShortcutProvider/>          scoped keymaps, ? cheatsheet
├── <ToastRegion/>               job started, export ready, bulk applied (with Undo)
├── <ContextMenuProvider/>       right-click pivots
│
├── <AppShell>
│   ├── <IconRail/>              scope icons, collapse toggle
│   ├── <NavSidebar>
│   │   ├── <ScopeSwitcher/>     project ⌘P / target ⌘T
│   │   ├── <NavSection/>        global | project | target
│   │   ├── <NavItem count badge dimmed?/>
│   │   └── <UserMenu/>
│   ├── <TopBar>
│   │   ├── <Breadcrumbs/>       project › target › section › asset
│   │   ├── <GlobalSearch/>      /
│   │   └── <JobIndicator/>  <NotificationBell/>  <ThemeToggle/>
│   └── <PageOutlet/>
│
├── <PageLayout variant="table|dashboard|detail|graph">
│   ├── <PageHeader>  <Title/> <StatStrip/> <PageActions/>
│   ├── <SplitPane resizable persistKey>
│   │   ├── <FilterRail>  <FacetGroup> <FacetItem count/>
│   │   ├── <MainPane>
│   │   │   ├── <QueryBar>  <TokenInput/> <FilterChips/> <SavedFilters/>
│   │   │   ├── <TableToolbar>  <ColumnManager/> <ExportMenu/> <DensityToggle/>
│   │   │   ├── <DataTable virtualised>
│   │   │   │   ├── <TableHeader sortable resizable pinnable/>
│   │   │   │   ├── <TableRow>  <SelectCell/> <Cell*/> <RowActions/>
│   │   │   │   ├── <SkeletonRows/> <EmptyState/> <ErrorState/>
│   │   │   │   └── <Pagination/>
│   │   │   └── <SelectionBar>  <BulkAction*/>
│   │   └── <PreviewPane>  <EntityPreview/> <PreviewActions/>
│   └── <DetailDrawer/>
│
├── Domain components
│   ├── <SeverityBadge/> <StatusCodePill/> <TechChip/> <TagChip editable/>
│   ├── <HostSummaryCard/> <FindingCard/> <ScreenshotThumb fallback/>
│   ├── <StageProgress/> <LogViewer follow search/> <ArtifactList/>
│   ├── <DiffViewer mode="unified|split"/> <TimelineFeed/>
│   ├── <GraphCanvas/>  <GraphControls/> <GraphLegend/> <NodeDetailPanel/>
│   └── <ConfigEditor schema validate diff/>
│
└── Widgets (dashboard)
    ├── <StatTile value delta sparkline/>
    ├── <RiskList/> <FindingFeed/> <TechDistribution/>
    ├── <GrowthChart/> <RecentScans/> <ChangeFeed/>
    └── <WidgetFrame loading error dragHandle/>
```

Design-system discipline: **one** `<DataTable>`, **one** `<QueryBar>`, **one**
`<SplitPane>`. Twenty-five pages, three primitives. If a page needs a bespoke table,
that's a bug in the primitive, not a licence to fork it.

---

## 7. UX rationale

**Why split-view everywhere.** Triage is a scan-then-inspect loop. Full-page
navigation destroys the scan context and costs two page loads per item. With a
preview pane, 40 items get triaged in one context. This single decision is worth
more than every other UX choice here combined.

**Why compact density is the default.** At 1080p, compact 28px rows show ~40 rows vs
~22 comfortable. For someone reading tables 8 hours a day, that's ~45% fewer scroll
actions. Comfortable stays available for demos and for pointing at a screen with
someone else.

**Why the query bar beats filter dropdowns.** Dropdowns can't express `NOT`, can't
compose, can't be pasted into a ticket, and can't be saved as text. Text queries are
shareable, diffable, scriptable. The filter rail exists for the discovery case —
when you don't yet know what values exist. Both write to the same state.

**Why counts are in the navigation.** Every unlabelled nav item is a click you make
to learn a number. Put the number in the nav and the analyst routes correctly the
first time, every time.

**Why facet counts are pre-computed.** A filter that leads to zero results is a
wasted interaction. `summary.json.url_surface.by_status` already ships these counts —
use them.

**Why "0 findings" is designed carefully.** In recon, zero findings has two very
different meanings: "clean target" and "the scan silently broke". `stages.json`
distinguishes them. The UI must too — a green empty state when 14/14 stages passed,
an amber warning when 12/14 did. This repo already learned this lesson (there's a
whole `recon-health` skill about it); the UI should encode it rather than re-teach it.

**Why stale data is a visual state.** Recon data decays. A host that was 200 six days
ago may be gone. Every view carries run provenance ("last run 6d ago") and dims or
flags data past a staleness threshold. `modules/dashboard.py` already uses 30 days;
the UI should surface the same threshold rather than inventing another.

**Why suppression is mandatory.** Without false-positive persistence, a recurring
scan yields an identical queue every run, and analysts stop reading it. Suppression
is what makes scheduled scanning viable rather than noise-generating.

**Why keyboard-first.** The target user lives in a terminal. Mouse-only workflows
feel slow and foreign. Every frequent action has a single-key binding; the command
palette covers the long tail so nothing needs memorising.

**Why URLs encode all state.** Analysts work in teams and paste links. A filter you
can't link to is a filter you have to describe in prose.

**Cognitive load budget.** Max 7 primary nav items per scope group. Max 8 default
table columns (the rest opt-in). Max 6 dashboard widgets above the fold. One accent
colour, so "highlighted" always means one thing. Severity colours are reserved
exclusively for severity — never decorative.

---

## 8. Recommended frontend stack

| Layer | Choice | Why |
|---|---|---|
| Framework | **React 18 + TypeScript** | ecosystem for the hard parts (virtualised tables, graph canvas); types matter when modelling 20 entities |
| Build | **Vite** | fast HMR; static build drops straight into Flask's `static/` |
| Routing | **TanStack Router** | typed routes + typed search params — the URL-as-state requirement becomes compile-time safe |
| Server state | **TanStack Query** | caching, background refetch, infinite queries, optimistic bulk mutations |
| Client state | **Zustand** | small: selection, pane sizes, column prefs |
| Tables | **TanStack Table + TanStack Virtual** | headless; 469k-row virtualisation is the whole ballgame |
| Styling | **Tailwind + CSS variables** | tokens as variables → theming without a runtime |
| Components | **shadcn/ui (Radix)** | accessible primitives you own the source of; no vendor lock |
| Charts | **visx** or **Recharts** | sparklines, growth, distribution |
| Graph | **Sigma.js (WebGL)** + graphology | handles thousands of nodes; Cytoscape.js if hierarchical layouts matter more than raw scale |
| Code/log viewer | **CodeMirror 6** | JS source, YAML config editing, log tailing |
| Diff | **diff-match-patch** + custom renderer | JS file and config diffs |
| Terminal | **xterm.js** | already in use in `web/static/app.js` — keep it for live logs |
| Realtime | **SSE** | already proven by `/api/stream/<scan_id>`; simpler than WebSockets, one-way is all that's needed |
| Icons | **Lucide** | consistent 24px grid, tree-shakeable, ~1400 icons |
| Keyboard | **tinykeys** + custom scope stack | context-aware bindings |
| Palette | **cmdk** | the ⌘K primitive |
| Tests | **Vitest + Testing Library + Playwright** | matches the repo's existing pytest discipline |

**Serving** — build to static assets served by the existing Flask app under `/app`,
API under `/api/v1`. No separate node runtime in production; one process, same as
today. Dev uses Vite proxy.

**Non-negotiable perf budgets** — first contentful paint <1s on localhost; table
interaction <16ms/frame at 100k rows (virtualisation, never full-set render); route
transition <100ms with cached data; graph interaction 60fps to 2k nodes.

---

## 9. Colour palette

Dark-first. Values are OKLCH-derived hex, tuned for long sessions: low-chroma
neutrals so severity colours stay the only thing that pops. Continues the existing
`web/static/style.css` accent (`#00d4ff`) rather than introducing a new brand colour.

### Dark (default)

```
SURFACES
--bg-base        #0a0a0c   page background (near-black, not pure — reduces halation)
--bg-surface     #111114   cards, sidebar
--bg-elevated    #17171b   modals, popovers, preview pane
--bg-inset       #08080a   code blocks, log viewer, table zebra
--bg-hover       #1c1c21   row hover
--bg-active      #232329   row selected
--border         #26262c   default border
--border-strong  #35353d   emphasised divider, focus outline base

TEXT
--fg-primary     #e8e8ec   body text
--fg-secondary   #9a9aa4   labels, metadata
--fg-muted       #6b6b75   placeholder, disabled, timestamps
--fg-inverse     #0a0a0c   text on accent fills

ACCENT (single, reserved for interactive/selected)
--accent         #00d4ff   primary action, active nav, focus ring, links
--accent-hover   #33ddff
--accent-muted   #00d4ff1a  10% — selected row wash, chip background
--accent-fg      #0a0a0c   text on accent

SEVERITY (reserved — never decorative)
--sev-critical   #ff3b5c   ⬤ crit
--sev-high       #ff7a2f   ⬤ high
--sev-medium     #ffb800   ⬤ med
--sev-low        #4ec9f5   ⬤ low
--sev-info       #8b8b96   ⬤ info

STATUS / SEMANTIC
--ok             #3ecf8e   2xx, success, healthy, alive
--warn           #ffb800   3xx, degraded, stale, partial data
--danger         #ff3b5c   5xx, failed, destructive action
--auth           #a78bfa   401/403 — distinct from 4xx because auth-gated is
                            an opportunity, not an error, in recon
--neutral        #6b6b75   dead host, no data, dark module
--new            #00d4ff   newly discovered asset marker
--running        #00d4ff   in-progress (animated pulse)

DATA VIZ (categorical — for tech distribution, sources, etc.)
--viz-1 #00d4ff  --viz-2 #a78bfa  --viz-3 #3ecf8e  --viz-4 #ffb800
--viz-5 #ff7a2f  --viz-6 #f472b6  --viz-7 #38bdf8  --viz-8 #94a3b8
```

### Light

Same token names, remapped. Not an inversion — light needs more contrast on borders
and less saturation on severity to avoid vibrating.

```
--bg-base #fafafa  --bg-surface #ffffff  --bg-elevated #ffffff
--bg-inset #f4f4f6 --bg-hover #f4f4f6    --bg-active #e8f7fc
--border  #e2e2e8  --border-strong #c8c8d0
--fg-primary #18181b --fg-secondary #52525b --fg-muted #8b8b96
--accent #0090b8  (darkened for AA on white)
--sev-critical #d61f3d --sev-high #d45f10 --sev-medium #b07d00
--sev-low #0284c7      --sev-info #71717a
--ok #16915e --warn #b07d00 --danger #d61f3d --auth #7c5cd6
```

**Accessibility** — body text ≥7:1 on base (AAA), secondary ≥4.5:1, all severity
colours ≥4.5:1 against their surface. Severity is **never** encoded by colour alone:
always paired with a filled dot glyph and a text label, because a meaningful share of
security analysts are red-green colourblind and this palette's critical/high sit in
exactly that range.

**Status code colour rule** — `2xx` ok · `3xx` warn · `401/403` auth (purple) ·
other `4xx` muted · `5xx` danger. Splitting auth-gated out of generic 4xx is a
recon-specific decision: a 403 is interesting, a 404 is not.

---

## 10. Icons (Lucide names)

```
NAVIGATION            ENTITIES                  ACTIONS
Dashboard   layout-dashboard   Project  folder-tree      Search       search
Inventory   database           Target   crosshair        Filter       sliders-horizontal
Findings    shield-alert       Subdomain git-branch      Export       download
Scan jobs   activity           Host     server           Rescan       refresh-cw
Scheduler   calendar-clock     URL      link             Tag          tag
Notifs      bell               JS file  file-code        Delete       trash-2
Settings    settings           Endpoint arrow-right-left Assign       user-plus
Attack surf network            Param    variable         Note         message-square
Reports     file-text          Tech     layers           Columns      columns-3
History     history            DNS      globe            Save filter  bookmark
                               Cert     shield-check     Pin          pin
STATUS                         Port     ethernet-port    Expand       maximize-2
Alive       circle (filled)    Response file-json        Copy         copy
Dead        circle (outline)   Screenshot image          Open ext     external-link
Running     loader (spin)      Secret   key              Command      command
Success     check-circle-2     Finding  flag             More         more-horizontal
Failed      x-circle           Log      scroll-text      Pivot        git-fork
Warning     alert-triangle     Artifact package
Stale       clock-alert        Note     sticky-note
Queued      clock
```

Rules: 16px in tables and nav, 20px in toolbars, 24px in empty states. Stroke 1.5px
(2px reads heavy at 16px on dark). Icons never appear alone in primary nav when the
sidebar is expanded — always icon + label. Severity uses filled dots (`●`), not
icons, so the colour reads at a glance in a dense table.

---

## 11. Design principles

1. **Density is a feature.** This is a tool for professionals, not a marketing site.
   Whitespace that costs a row of data is whitespace that costs an analyst a scroll.
2. **Never navigate when you can preview.** Full page loads break flow. Split panes,
   drawers, and expanding rows preserve context.
3. **Every number is a link.** If the UI shows "574 hosts", clicking it lands on
   those 574 hosts, filtered. No dead-end statistics.
4. **State lives in the URL.** If you can see it, you can link to it.
5. **Show provenance.** Every datum carries when it was collected and by which stage.
   Recon data decays; undated data is untrustworthy data.
6. **Distinguish "clean" from "broken".** Zero results must always say which one it
   is. This is the single most important correctness property in a recon UI.
7. **Colour carries exactly one meaning.** Severity colours are reserved for severity.
   One accent means "interactive/selected". Nothing decorative.
8. **The keyboard is the primary input device.** Mouse is the fallback.
9. **Degrade honestly.** Missing data shows as a labelled empty state explaining which
   stage would fill it — never a fake chart, never a hidden section, never a zero
   pretending to be a measurement.
10. **Bulk is a first-class verb.** Anything doable to one asset is doable to 500.
11. **Nothing destructive without a named count.** "Delete 1,247 assets?" not
    "Delete selected?". Soft-delete with undo where possible; never touch engine output.
12. **The engine is the source of truth.** The UI stores triage state, tags and
    projects — never recon results. A target directory must remain disposable.

---

## 12. Future extensibility

**Near term (unblocks whole modules with small backend additions)**
- Screenshot stage (httpx `-screenshot`, or gowitness) → lights up Screenshots, the
  inventory thumbnails, and visual diff. Highest UI value per unit of backend work.
- TLS stage (tlsx) → Certificates tab + SAN-based asset discovery.
- Header capture (httpx `-irh`) → Headers tab + security-header scorecard.
- Port scan (naabu) → Open Ports.
- Per-target SQLite index → makes every large table actually usable.

**Medium term**
- Multi-user: roles (admin / analyst / viewer), audit log, per-project permissions.
- Collaboration: @mentions in notes, assignment queues, shared saved filters.
- Bug bounty integrations: submit-to-HackerOne from a finding (`modules/hackerone.py`
  is already there), scope sync so out-of-scope assets auto-tag.
- Custom dashboards: user-composed widget layouts, saved and shared.
- Webhook/API-out so other tools can subscribe to "new critical finding".

**Long term**
- Plugin architecture: third-party stages register their own asset type, table
  columns, detail tab and icon via a manifest. The `<DataTable>` contract in §4.1 is
  what makes this possible — a plugin declares columns and filters, gets the full
  table feature set free.
- Diff-driven monitoring mode: continuous scanning where the UI shows only deltas.
- Correlation engine: "this JS file appears on 12 hosts across 3 targets" —
  cross-project asset fingerprinting.
- Query language export: turn a saved filter into a CLI invocation, closing the loop
  back to the terminal where this project started.

**Extensibility rules for whoever builds this**
- New asset type = new row in the §0 data map + a table config + a detail tab. No new
  primitives.
- New severity source = register with the finding fingerprint scheme; triage state,
  suppression and bulk actions come free.
- Never fork `<DataTable>`. If it can't do something, extend the contract in §4.1 so
  all 25 tables gain it at once.
```
