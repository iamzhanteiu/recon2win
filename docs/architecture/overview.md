# Kiến trúc tổng thể

> Xác minh từ `main.py`, `modules/*.py`, `config.yml` tại thời điểm viết. Khi
> pipeline đổi, cập nhật file này cùng lúc (yêu cầu của `CLAUDE.md`).

## 1. Nguyên lý thiết kế

Bốn nguyên lý xuyên suốt toàn bộ codebase, không phải mô tả sau khi đã viết
code mà là thứ có thể quan sát trực tiếp trong cách `main.py`/`modules/*`
được viết:

* **Config-first.** Gần như không có magic number trong code — mọi rate,
  timeout, ngưỡng, wordlist đều là key trong `config.yml`, kèm comment giải
  thích số đo thật đứng sau con số đó (xem `decisions.md`).
* **Fail-soft.** Stage tuỳ chọn thiếu binary → skip kèm cảnh báo, không crash
  cả run. `modules/runner.py` bọc mọi subprocess; lỗi một tool không lan sang
  tool khác.
* **Resumable + giới hạn thiệt hại.** `--resume` bỏ qua stage đã có output;
  các stage tốn thời gian nhất (`dirsearch`, `arjun`, `nuclei_default`) chia
  theo chunk/batch để một timeout chỉ mất đúng phần đang chạy, không mất cả
  stage.
* **Tự kiểm chứng (self-auditing).** Đây là phần khác biệt nhất so với một
  wrapper gọi tool thông thường: `modules/audit.py` (MANIFEST — phân biệt
  "0 dòng vì sạch" với "0 dòng vì chưa từng chạy"), `modules/asm_report.py`
  (chấm điểm tin cậy của cả run), `modules/baseline.py` +
  `modules/behavior.py` + `modules/existence.py` (không tin status code/độ
  dài byte một mình) đều tồn tại để trả lời "kết quả này có tin được không"
  trước khi trả lời "target có lỗ hổng gì".

## 2. Orchestration

`main.py::main()` là điểm vào duy nhất. Luồng:

```
parse CLI args
  → load config.yml (+ config.local.yml overlay, ${ENV_VAR} interpolation)
  → --doctor? → modules.doctor.run() rồi thoát
  → preflight ngắn (cảnh báo tool thiếu, không chặn)
  → HackerOne flow tuỳ chọn (--h1-list / --h1-program) → chọn domain
  → validate_domain() → create_output_structure()
  → --dry-run? → in kế hoạch rồi thoát (không gọi tool ngoài nào)
  → chạy pipeline (xem § 3)
  → ghi logs/stages.json, in đường dẫn report
```

Mọi stage được gọi qua `main.py::_run_stage(name, fn, *args, **kwargs)` — một
wrapper thống nhất: in header màu, đo thời gian, bắt exception thành kết quả
`failed` thay vì crash tiến trình, in đường dẫn output tương đối, gửi
Telegram theo stage nếu bật, và echo lệnh đã lên kế hoạch khi `--dry-run`.

**Contract giữa các stage.** Mọi stage function theo đúng chữ ký:

```python
def stage_fn(input_path, output_dir, cfg, *, resume=False, dry_run=False, skip=False) -> dict
```

trả về qua `modules.utils.make_result(stage, status, ...)` — dict có
`stage/status/input/outputs/count/error/extra`. `_run_stage` dựa hoàn toàn
vào hình dạng dict này để render/notify, nên đây là API nội bộ thật sự của
hệ thống dù không có type ràng buộc (xem `decisions.md` § nợ kỹ thuật).

## 3. Pipeline — thứ tự thực thi thật trong `main.py`

Đánh số theo comment trong code (`prog.start_phase(..., num=N)`), không phải
theo thứ tự file:

| # | Stage | Song song với | Bắt buộc? |
|---|---|---|---|
| 1 | `subdomain` (subfinder+amass+chaos) → `puredns` validate | — | có |
| 2 | `dnsx` resolve | — | có |
| 3 | `httpx_alive` (+ retry 2-pass nếu 0 alive host) | — | có |
| 3.post | `httpx_screenshot` (opt-in) | — | không |
| 4 | `content_discovery` (katana+urlfinder), `dirsearch`, `ffuf`, `waymore` | 4 stage chạy `ThreadPoolExecutor` | tuỳ chọn từng cái |
| 5 | `url_merge` → `all_urls.txt`/`js_urls.txt`/`dynamic_urls.txt` | — | có |
| 5.post | `responses` (body preview cho hit ffuf/dirsearch) | — | không |
| 6 | `httpx_urls`, `xnlinkfinder`, `jsluice`, `apidocs` | 4 stage song song | tuỳ chọn từng cái |
| 6.post | merge URL từ xnlinkfinder/jsluice/apidocs ngược vào `all_urls.txt` | — | — |
| 6.post.a2/a3 | `jsluice_verify` (probe URL jsluice mới mine) / `jsluice_method_check` (probe đúng verb JS dùng) | — | — |
| 6.post.b | mine subdomain mới từ URL đã thu thập | — | — |
| 6.post.c–f | `graphql_probe`, `cors_probe`, `misconfig_probe` (chỉ tier "deep"), `buckets` (opt-in), `gitdump` (opt-in) | — | không |
| 7 | `arjun` trên `dynamic_urls.txt` | — | không (nhưng có 2 nguồn seed độc lập, xem dưới) |
| 7.post | enrich `parameterized_urls.txt`: jsluice params + seed đã-có-param + apidocs spec params | — | — |
| 8 | `nuclei_default` — scan cuối cùng, full rate budget | — | không |
| 9 | `summary` (tổng hợp số liệu, không gọi tool ngoài) | — | — |
| 10 | `report` (HTML/MD/JSON/XLSX) | — | — |
| 10.post | `priority` (priority_targets.txt), `scandiff` (delta.md), `graphgen` (graph.mmd), `audit` (MANIFEST.json + INDEX.md), `asm_report` (asm_report.html) | — | — |
| 10.post.e | `dashboard` (outputs/dashboard.html, đọc mọi `outputs/<target>/logs/stages.json`) | chạy sau khi stages.json của run này đã ghi | — |

`parameterized_urls.txt` cố tình có **3 nguồn độc lập** (URL đã có `?a=1`
sẵn trong crawl, param arjun tìm ra, param jsluice trích từ JS) — nếu chỉ
dựa vào arjun, `--skip-arjun` hoặc arjun bị cap/lỗi sẽ làm rỗng cả shortlist
hand-testing dù dữ liệu đã có sẵn trong run.

## 4. Data flow trên đĩa — `outputs/<domain>/`

```
raw/<stage>/            # output thô của từng tool, không sửa, không xoá
processed/
  sources/                # output đã parse của từng tool, TRƯỚC merge — scratch
  corpus/                  # all_urls.txt + all_urls.jsonl (provenance) + js_urls.txt + dynamic_urls.txt
  hosts/                     # subdomains → resolved → alive (3 tầng inventory)
  js/                          # mọi thứ đào từ JavaScript (jsluice + xnlinkfinder)
  targets/                       # parameterized_urls.txt, forms.json — shortlist tay-test
  MANIFEST.json                    # per-artefact: ok / ran_empty / blocked / truncated / skipped / failed / absent
findings/                # nuclei + jsluice secrets + misconfig_probe + graphql + cors + buckets + git_dump
logs/                    # commands.log (mọi lệnh đã chạy) + <stage>.log + stages.json (kết quả có cấu trúc)
report/                  # final_report.{html,md,json,xlsx} + priority_targets.txt + delta.md + graph.mmd
```

`modules/layout.py` là nguồn sự thật duy nhất cho việc `processed/<file>` nằm
ở nhóm nào — không module nào khác được tự nối path. `layout.path()` có
fallback về layout phẳng cũ (pre-v3) khi `--resume` chạy trên output tree cũ,
nên nâng cấp layout không phá `--resume`.

**Vì sao MANIFEST.json tồn tại:** một file 0 dòng có hai nghĩa đối lập nhìn
giống hệt nhau trên đĩa — "đã quét, target sạch" (kết quả thật) và "chưa
từng quét" (không phải kết quả). `modules/audit.py::build_manifest()` gán
mỗi artefact một trạng thái trong 7 trạng thái (`ok/ran_empty/blocked/
truncated/skipped/failed/absent`), suy ra từ chính `extra["blocked"]`/
`extra["timed_out"]` mà từng stage tự khai — không đoán qua text lỗi.

## 5. Các lớp xuyên suốt (cross-cutting)

| Lớp | Module | Vai trò |
|---|---|---|
| Subprocess | `runner.py` | Điểm gọi duy nhất cho tool ngoài — log lệnh, bắt timeout, capture stdout/stderr |
| Run log | `runlog.py` | `logs/run.log` — bản ghi leveled (`stdlib logging`), ghi ngay theo thời gian thực, song song với terminal (không in ra console) |
| Đường dẫn | `layout.py` | SSOT cho vị trí artefact trong `processed/` |
| Kết quả stage | `utils.py::make_result` | Hình dạng dict chuẩn cho mọi stage |
| Chọn target fuzz | `fuzz_targets.py` | Dedup host cùng response (wildcard DNS), cap theo `score_subdomain` |
| Độ sâu fuzz | `fuzz_depth.py` | Tier deep/standard/light + wordlist theo tech xác định |
| Đường nền so sánh | `baseline.py` | Response của path chắc chắn không tồn tại, đo TRƯỚC khi fuzz |
| Phân loại hit | `behavior.py` | Gom hit theo hình dạng response (status+content-type+redirect+words/lines), không theo byte length |
| Route thật hay noise | `existence.py` | Confirmed/Likely/Unknown/Not-Found — tổng hợp baseline + body pattern + status |
| Provenance URL | `url_merge.py` (`rank_urls_by_source`) | Mỗi URL trong corpus biết nó đến từ tool nào, chất lượng nguồn khác nhau tới ~24x |
| Tính đúng đắn output | `audit.py` | MANIFEST.json + INDEX.md |
| Ưu tiên | `priority.py` | Gộp mọi tín hiệu (nuclei/secret/param/hit) thành 1 danh sách xếp hạng |
| Tin cậy cả run | `asm_report.py` | Chấm điểm run dựa trên stage nào cụt/blocked/truncated |
| So sánh lịch sử | `scandiff.py` | Delta so với `.scan_state.json` của lần chạy trước |
| Tổng quan nhiều target | `dashboard.py` | Đọc `logs/stages.json` của mọi `outputs/<target>/` |

## 6. Cấu hình

`config.yml` (mặc định, tracked) + `config.local.yml` (git-ignored, deep-merge
đè lên, chứa secret) → `${ENV_VAR}` / `${ENV_VAR:-default}` được resolve sau
khi merge (`main.py::_resolve_env_vars`). Không có schema validation — một
key gõ sai tên bị `_deep_merge` nuốt im lặng (xem `decisions.md` § nợ kỹ
thuật).

## 7. Giao diện phụ

* **HackerOne** (`modules/hackerone.py`) — `--h1-list`/`--h1-program` lấy
  scope trực tiếp từ API thay vì copy-paste tay.
* **Telegram** (`modules/telegram.py`) — 3 chế độ thông báo (`notify_high_
  critical`, `notify_summary`, `per_phase`), fail-soft (không có token thì
  không gửi, không lỗi).
* **Web UI** (`web/app.py`) — Flask dev server tuỳ chọn, 2 phần:
  1. **Run** (`/`) — chạy `main.py` qua subprocess + xterm.js qua SSE.
  2. **Browse results** (`/results/*`, `modules/webdata.py`) — đọc trực
     tiếp `alive_table.txt`/`alive_urls_table.txt`/`nuclei.json` qua
     `layout.path()`, phân trang/lọc bằng Python, KHÔNG có index/database
     riêng (chấp nhận đánh đổi này cho 1 người dùng cục bộ — xem
     `decisions.md`). Tái dùng `dashboard.discover_targets()`/
     `dashboard.load_target()` cho danh sách target theo project.
  Không auth (dựa vào tunnel/reverse-proxy đứng trước, vd Cloudflare
  Tunnel), không persistence ngoài file trên đĩa. `ui-design.md` là spec
  đầy đủ hơn nhiều (SQLite index, triage state, multi-user) — `/results/*`
  hiện tại là một lát cắt tối thiểu của spec đó, không phải toàn bộ.

## 8. Testing & CI

`tests/conftest.py` stub `baseline.measure` mặc định cho mọi test (không test
nào chạm mạng trừ khi gắn `@pytest.mark.baseline`). `.github/workflows/
tests.yml`: `ruff check .` + `pytest tests/ -q` trên Python 3.11/3.12/3.13.
