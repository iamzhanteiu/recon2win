# Configuration

Configuration is code-level (`jsvh/config.py::Config`) plus CLI flags; there
is no separate config file to maintain. Defaults are chosen so a bare
`python3 jsvh.py run <target>` does the right thing against the sibling
recon2win `../outputs/`.

## Config fields (`jsvh/config.py`)

| Field | Default | Meaning |
|---|---|---|
| `target` | — | recon2win target domain, e.g. `omnicell.com` |
| `outputs_dir` | `../outputs` | recon2win `outputs/` directory |
| `project` | `None` | recon2win `-p` project grouping |
| `acquire` | `True` | run the acquisition step |
| `net` | `False` | allow network fetch for JS not cached by recon2win |
| `max_bytes` | `6_000_000` | per-file download cap |
| `timeout` | `20` | per-request network timeout (s) |
| `workers` | `12` | acquisition thread pool size |
| `max_assets` | `0` | cap assets analysed (0 = all) |
| `max_parse_bytes` | `150_000` | AST-parse cap; larger files use the regex fallback |
| `progress_every` | `100` | heartbeat interval during analysis |

## CLI flag → field map

```
--outputs      → outputs_dir
--project      → project
--net          → net
--no-acquire   → acquire=False
--max-assets   → max_assets
--max-parse    → max_parse_bytes
--workers      → workers
```

## Tuning notes

- **Speed vs. depth.** `max_parse_bytes` is the main lever. Pure-Python
  esprima costs ~20s on a 500KB minified bundle; the default 150KB keeps a
  full target to a couple of minutes and routes big vendored bundles to the
  bounded regex scan. Raise `--max-parse` (and expect longer runs) when you
  want AST depth on large files.
- **WAF reality.** Leave `--net` off for the first pass — recon2win's cached
  bodies are already the exact analysed bytes, and production WAFs 403 an
  unbranded client anyway. Turn `--net` on only to reach JS recon2win
  discovered but never fetched.
- **Directory ownership.** Everything this workspace writes stays under
  `targets/` and `output/`; it never writes into recon2win's `../outputs/`.
