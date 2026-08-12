# Module map — `modules/`

Trách nhiệm từng file, xác minh từ docstring + `from . import ...` thật của
mỗi module (không suy đoán). Nhóm theo vai trò trong pipeline (xem
`overview.md § 3` cho thứ tự thực thi).

## Nền tảng (không phụ thuộc stage nào khác)

| Module | Trách nhiệm |
|---|---|
| `layout.py` | SSOT: `processed/<file>` thuộc nhóm nào (`sources/corpus/hosts/js/targets`), fallback layout phẳng cũ cho `--resume` |
| `runner.py` | Điểm gọi subprocess duy nhất — log lệnh, timeout, capture stdout/stderr |
| `utils.py` | `validate_domain`, `validate_project` (grouping tuỳ chọn), `make_result` (contract chuẩn), IO helpers (`read_lines`/`write_lines`/`write_json`/`write_jsonl`/`read_jsonl`), `create_output_structure(domain, root, project=None)` — `outputs/[<project>/]<domain>/` |
| `console.py` | Màu terminal, icon trạng thái, tự phát hiện TTY/`NO_COLOR`/`FORCE_COLOR` |
| `progress.py` | Progress bar (`rich`), fallback no-op khi không phải TTY |
| `sensitive_ext.py` | 3 danh sách dùng chung: `SENSITIVE_EXT` (đuôi file), `SENSITIVE_FILES` (tên file nhạy cảm), `STATIC_EXT` |

## Chọn & phân loại target fuzz

| Module | Trách nhiệm | Phụ thuộc |
|---|---|---|
| `baseline.py` | Đo response của path chắc chắn không tồn tại trên mỗi host, TRƯỚC khi fuzz | `layout` |
| `behavior.py` | Gom hit theo hình dạng response (status+content-type+redirect+words/lines), bỏ cụm lớn-áp-đảo | — |
| `existence.py` | Confirmed/Likely/Unknown/Not-Found cho một hit, từ baseline + body pattern + status | — |
| `fuzz_targets.py` | Dedup host cùng response (wildcard DNS), cap theo `score_subdomain`, dùng chung cho dirsearch+ffuf | `baseline`, `layout` |
| `fuzz_depth.py` | Tier deep/standard/light + chọn wordlist/extension theo tech (httpx `-td` + `tech_confirmed.json`); nhận diện host API → cấp wordlist route API (B3) + extension theo stack (B2) | — |
| `fuzz_recurse.py` | Stage 6.post — fuzz UNDER directory đã phát hiện trong corpus (`/api/FUZZ`…), tái dùng `ffuf._build_cmd`/`parse_report`/`behavior.screen` | `behavior`, `ffuf`, `fuzz_depth`, `fuzz_targets`, `layout`, `dirsearch._resolve_wordlists` |

## Stage 1–3: subdomain → DNS → alive

| Module | Trách nhiệm |
|---|---|
| `subdomain.py` | subfinder + amass + chaos, merge + dedupe |
| `puredns.py` | Validate qua public resolver (trickest list) — bỏ host không resolve + wildcard |
| `dnsx.py` | Resolve JSON, cap `max_resolved` (có retry mở rộng nếu 0 alive host ở stage 3) |
| `httpx.py` | Alive-check (stage 3) + URL-check (stage 6.1) + `capture_screenshots` (opt-in) |

## Stage 4: content discovery / fuzzing (song song)

| Module | Trách nhiệm | Phụ thuộc mới (behavior/fuzz_depth) |
|---|---|---|
| `content_discovery.py` | katana (+ `-fx` form extraction) + urlfinder + gau | `fuzz_targets`, `layout` |
| `dirsearch.py` | Fuzz file/extension nhạy cảm, chunk theo host, ngân sách suy từ khối lượng request thật | `behavior`, `fuzz_depth`, `fuzz_targets`, `layout` |
| `ffuf.py` | Fuzz directory + recursion, auto-calibration (`-ac`/`-ach`) | `behavior`, `fuzz_depth`, `fuzz_targets`, `layout` |
| `waymore.py` | URL đã archive (Wayback/CommonCrawl/...) + JS |

## Stage 5: merge

| Module | Trách nhiệm |
|---|---|
| `url_merge.py` | Merge + classify → `all_urls.txt`/`js_urls.txt`/`dynamic_urls.txt`; `rank_urls_by_source` + `all_urls.jsonl` (provenance từng URL); scope filter; param-template collapse |
| `responses.py` | Body preview (httpx `-bp`) cho hit ffuf/dirsearch → `responses/index.md` |

## Stage 6: JS analysis + probe (song song + post)

| Module | Trách nhiệm |
|---|---|
| `xnlinkfinder.py` | Regex JS link extraction |
| `jsluice.py` | AST (tree-sitter) endpoint + secret extraction, theo chuỗi JS đệ quy |
| `jsluice_verify.py` | Probe URL jsluice mới mine (`verify`) + probe đúng HTTP verb JS dùng (`verify_methods`) |
| `apidocs.py` | Probe OpenAPI/Swagger/AsyncAPI + OSINT (Postman/GitHub); wildcard-dedup + tech-aware paths (`fuzz_targets`/`fuzz_depth`); chain swagger-ui/redoc→spec thật; trích query+path+body param; đánh dấu host `"api"` vào `tech_confirmed.json`. `build_candidates()` cũng được `misconfig_probe.py` tái dùng |
| `graphql_probe.py` | Xác nhận GraphQL introspection bằng 1 POST, không chỉ nêu `/graphql` tồn tại |
| `cors_probe.py` | Xác nhận CORS misconfig (Origin phản chiếu + `Allow-Credentials`) |
| `misconfig_probe.py` | Sub-path nhạy cảm theo service cụ thể (actuator/Jenkins/GitLab/k8s/phpMyAdmin...), chỉ tier "deep" | `fuzz_depth`, `layout`, `apidocs.build_candidates`, `fuzz_targets._host_of` |
| `buckets.py` | Enum bucket S3/GCS (extracted + opt-in domain-permutation guessing) |
| `gitdump.py` | Dựng lại source từ `.git` exposure đã xác nhận |

## Stage 7: parameter discovery

| Module | Trách nhiệm |
|---|---|
| `arjun.py` | Param discovery trên `dynamic_urls.txt`, chunk theo URL, tự vá 2 crash upstream của arjun ≤2.2.7 |

## Stage 8–10: scan + report + post-scan intelligence

| Module | Trách nhiệm | Phụ thuộc |
|---|---|---|
| `nuclei.py` | Scan cuối cùng, batch + autotune batch_size theo corpus thật đo bằng `nuclei -tl` | — |
| `report.py` | `final_report.{html,md,json}` — existence verdict, high-value target, coverage/screening section | `baseline`, `behavior`, `existence`, `layout`, `xlsx_report` |
| `xlsx_report.py` | `final_report.xlsx` (17 sheet), render lại đúng dict `report.py` đã build, không đọc lại đĩa | — |
| `priority.py` | `priority_targets.txt` — gộp mọi tín hiệu thành 1 danh sách xếp hạng, loại URL blanket/noise | `asm_report`, `baseline`, `layout` |
| `scandiff.py` | `delta.md` — so với `.scan_state.json` của lần chạy trước | `layout` |
| `graphgen.py` | `graph.mmd` — provenance graph (Mermaid) với số liệu thật mỗi node | `layout` |
| `audit.py` | `MANIFEST.json` (per-artefact state) + `INDEX.md` (bản đồ review) | `layout` |
| `asm_report.py` | `asm_report.html` — chấm điểm tin cậy run, danh sách test tay ưu tiên | `layout` |
| `dashboard.py` | `outputs/dashboard.html` — tổng quan mọi target, đọc lại `logs/stages.json`. `discover_targets()` nhận diện 2 tầng: `outputs/<domain>/` (ungrouped, `project: None`) VÀ `outputs/<project>/<domain>/` (`_is_target_dir()` phân biệt qua skeleton `raw/logs/report/processed`) | `report` (`classify_stages`, `load_json_safe`, `missing_tools_from_skips`, `rel_link`) |

## Web UI (`web/`, tuỳ chọn)

| File | Trách nhiệm | Phụ thuộc |
|---|---|---|
| `web/app.py` | Flask — chạy scan qua subprocess (`/`, `/api/*`) + browse kết quả (`/results/*`) | `modules.webdata` |
| `modules/webdata.py` | Đọc `alive_table.txt`/`alive_urls_table.txt`/`nuclei.json` cho `/results/*` + duyệt cây file recon (`list_files`/`resolve_file`/`read_text_preview`, traversal-safe) cho `/results/<t>/files` | `dashboard`, `layout` |

## Tích hợp phụ

| Module | Trách nhiệm |
|---|---|
| `hackerone.py` | Pull program/scope từ HackerOne Hacker API |
| `telegram.py` | Thông báo outbound, fail-soft khi thiếu token |
| `doctor.py` | Preflight — tool/API key/wordlist nào sẵn sàng, trước khi scan |

## Quan hệ đáng chú ý (thứ tự phụ thuộc thật, không phải thứ tự file)

```
layout.py  ←── gần như mọi module khác (đường dẫn processed/)
baseline.py, behavior.py  ←── fuzz_targets.py ←── dirsearch.py, ffuf.py
fuzz_depth.py  ←── dirsearch.py, ffuf.py, misconfig_probe.py, apidocs.py, fuzz_recurse.py
ffuf.py        ←── fuzz_recurse.py (tái dùng _build_cmd/parse_report)
existence.py, baseline.py, behavior.py, xlsx_report.py  ←── report.py ←── dashboard.py
asm_report.py, baseline.py  ←── priority.py
apidocs.py (build_candidates), fuzz_targets.py (_host_of)  ←── misconfig_probe.py
```

`audit.py::build_manifest()` không hardcode danh sách artefact — nó đọc
`res["outputs"]` mà chính stage tự khai, nên một stage mới không cần sửa
`audit.py` để được MANIFEST theo dõi.
