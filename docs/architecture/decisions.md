# Design decisions & nợ kỹ thuật

Rút từ comment trong `config.yml`/`README.md` (đã có sẵn, thường kèm số đo
thật) — gom lại một chỗ thay vì để rải rác. Ngày tháng giữ nguyên theo nguồn
gốc khi có; nhiều quyết định không ghi ngày cụ thể.

## Quyết định thiết kế

### Screening theo hành vi response, không theo status/byte-length

**Vấn đề:** ffuf `-ac` lọc theo độ dài byte; trang chặn của Akamai echo lại
path được yêu cầu nên độ dài đổi mỗi request — `-ac` không thể lọc được.

**Đo được (run discover.com, 2026-07-28):** 4.082 hit của `mapi.discover.com`
có 50 giá trị length khác nhau nhưng `words` = 13 cho toàn bộ.

**Quyết định:** `modules/behavior.py` gom hit theo status + content-type +
redirect target + words/lines (không dùng content-length làm khoá). Kết quả
đo trên cùng run: ffuf 44.442→128 hit (-99,7%), dirsearch 13.895→155 (-98,9%).

### URL provenance — biết mỗi URL đến từ tool nào

**Vấn đề:** merge cũ làm phẳng nguồn có chất lượng rất khác nhau thành một
danh sách vô danh.

**Đo được:** trên discover.com, URL do jsluice mine trả 200 ở tỷ lệ 23,6%
trong khi 44.431 hit của ffuf gần như thuần wildcard-403 — sau merge không
ai phân biệt được, khiến `arjun.max_urls=200` rút mẫu toàn từ phần nhiễu.

**Quyết định:** `modules/url_merge.py::rank_urls_by_source()` sắp theo nguồn
trước khi cắt cap; `processed/corpus/all_urls.jsonl` ghi `{url, sources[]}`
cho từng dòng.

### MANIFEST.json — phân biệt "sạch" với "chưa từng quét"

**Vấn đề:** file 0 dòng có hai nghĩa đối lập giống hệt nhau trên đĩa. Ví dụ
thật: `apidocs_urls.txt`/`apidocs_params.txt` 0 byte trên một run — stage
chạy bình thường nhưng mọi probe đều bị 401/403 (bị chặn, không phải "target
không có API doc"); trước đây thông tin này chỉ nằm trong
`findings/api_docs.json`.

**Quyết định:** `modules/audit.py::build_manifest()` — 7 trạng thái
(`ok/ran_empty/blocked/truncated/skipped/failed/absent`), suy từ
`extra["blocked"]`/`extra["timed_out"]` mà stage tự khai, không đoán qua
text lỗi.

### Phân vai dirsearch (file, không recursion) vs ffuf (directory, có recursion)

**Vấn đề:** trước đây cả hai cùng chạy `raft-small-directories` + cùng bật
recursion → mọi thư mục tìm được bị quét lại hai lần bởi hai tool khác nhau.

**Quyết định:** dirsearch = file + extension nhạy cảm, `recursive: false`;
ffuf = directory, `recursion: true` depth 2. Wordlist ffuf phải nhỏ vì
recursion nhân nó lên theo số thư mục tìm được.

### Ngân sách dirsearch suy từ khối lượng request, không phải hằng số mỗi host

**Sự cố (acronis.com, 2026-07-25):** giả định cũ "`timeout_per_host × số
host` không bao giờ bị cắt giữa chừng" sai — run vẫn chết đúng ở mốc cũ vì
khối lượng thật là 50 target × 13.799 từ ở `max_rate=30` = 22.998s trong khi
trần chỉ 6000s (thiếu ~4×).

**Quyết định:** `modules/dirsearch.py::_plan_budget` tính
`wanted = target × từ ÷ max_rate × 1,3`, và **chunk theo host** (không phải
theo thời gian) — dirsearch quét tuần tự trong 1 process nên bị kill giữa
chừng bỏ sót toàn bộ host chưa tới lượt (đo được: chỉ 3/50 target có kết
quả trên acronis.com trước khi chunk hoá).

### Rate limit đối xứng + không bao giờ để `rate: 0`

**Quyết định:** `ffuf.rate` mặc định 30 (không phải 0 — unlimited là cách
nhanh nhất bị ban rồi phải chạy lại từ đầu), `dirsearch.max_rate` đối xứng
(mặc định 200, không còn 30 — 30 req/s không đủ cho khối lượng request thật
đo được, xem mục trên).

### `arjun.stable` không phải "cẩn thận hơn"

**Sự cố (acronis.com, 2026-07-25):** `--stable` chèn delay ngẫu nhiên 3-9s
TRƯỚC MỖI request, nuốt luôn ý nghĩa của `rate_limit` — đo được ~660s/URL,
budget 3600s chỉ đủ ~5 URL trong khi `max_urls=200`.

**Quyết định:** mặc định `stable: false`; chỉ bật khi target báo rate-limit
rõ ràng, và hạ `max_urls` xuống ~20 khi bật.

### Tự vá 2 crash upstream của arjun (≤2.2.7)

Hai `AttributeError` khác nhau (dict/str không có `.status_code`) giết cả
tiến trình arjun khi target trả 400/413/418/429/503/lỗi mạng.
`arjun.patch_upstream: true` vá `__main__.py` trước khi chạy (giữ `.bak`,
idempotent); `chunk_size: 25` giới hạn thiệt hại khi patch không áp được
(site-packages read-only).

### nuclei batch + autotune, chỉ tự thu nhỏ

**Vấn đề:** `-json-export` chỉ ghi lúc process exit — một run timeout ở
timeout tổng thì KHÔNG ghi gì cả ("salvaged 0 partial findings").

**Quyết định:** chia URL thành batch, mỗi batch ghi xong trước khi batch sau
chạy; `batch_autotune` đo corpus thật bằng `nuclei -tl` rồi so với công thức
ngân sách, **chỉ thu nhỏ `batch_size`, không tự phóng to** (batch nhỏ hơn tối
ưu chỉ tốn thêm vài lần load template; batch to hơn mất cả đuôi danh sách
template cho MỌI URL trong batch — đắt hơn nhiều).

### nuclei chạy một mình, cuối pipeline

Loại bỏ 2 pass cũ (`endpoints`, `dynamic` với `-dast`) ngày 2026-07-28 — chỉ
còn `nuclei_default` trên `alive.txt`, chạy sau cùng để không chia sẻ rate
budget với 4 tool discovery đang chạy song song ở stage 4.

### Tech-aware wordlist + xác nhận tech tích luỹ qua nhiều lần scan

`fuzz_depth.py` phát hiện tech qua httpx `-td` (có thể "im lặng" nếu banner
bị ẩn) VÀ qua `misconfig_probe` đọc nội dung response thật (đáng tin hơn
đoán qua title). Kết quả xác nhận ghi vào `processed/tech_confirmed.json`,
**không bị ghi đè mỗi run** — giá trị thật nằm ở lần scan SAU của cùng
target, không phải trong cùng một run (misconfig_probe chạy sau dirsearch/
ffuf nên không có vòng lặp ngược trong 1 lần).

### Postman OSINT — word-boundary + giới hạn độ dài tên

**Vấn đề:** substring match trên `discover.com` trả 25 kết quả (không cái
nào là target — `discover` là substring của `Discovery`). Word-boundary cắt
còn 4 nhưng vẫn lọt qua clickbait dài (`dialogue.co` → tên 106 ký tự không
liên quan chỉ vì chứa từ "dialogue").

**Quyết định:** word-boundary match + `_MAX_NAME_LEN = 80` (tên workspace/
collection thật dài nhất quan sát được là 38 ký tự).

### SwaggerHub bị loại có chủ đích

`/specs?query=` filter đúng nhưng sort theo alphabet, không theo relevance —
`sort=BEST_MATCH` hành xử giống hệt. Không có cách triage → chỉ sinh nhiễu,
nên không tích hợp.

### JSON compact cho file `*_detail.json`

`write_json(..., compact=True)` bỏ `indent=2` cho các file lớn không ai đọc
bằng mắt. Đo trên discover.com: 5 file detail 49,8MB → 37,4MB (**-25%**),
riêng `alive_urls_detail.json` (57k record) 47,3→35,5MB.

### Form ranking loại trừ trường ASP.NET postback

`__VIEWSTATE`/`__EVENTTARGET`... có mặt trên MỌI trang của stack ASP.NET —
không loại trừ thì một postback stub thắng một form login thật chỉ vì đếm
field (đo trên acronis.com: 84 vs 74).

### Đổi tên `setup.py` → `bootstrap.py`

**Vấn đề:** thêm `[project]` + `[build-system]` vào `pyproject.toml` để đóng
gói `modules/` làm package cài được — nhưng `setup.py` ở repo root vốn là
script bootstrap môi trường (verify/install tool, clone SecLists), không
phải packaging script. setuptools' PEP 517 backend (`setuptools.build_meta`)
luôn tự gọi `setup.py` như subprocess (`egg_info`/`dist_info`) bất cứ khi
nào file đó tồn tại ở repo root, bất kể `pyproject.toml` đã khai `[project]`
đầy đủ hay chưa.

**Đo được (trước khi đổi tên):**

```
$ pip install --no-build-isolation --dry-run .
setup: error: unrecognized arguments: dist_info --output-dir ... --keep-egg-info
error: metadata-generation-failed
```

`pip install .` fail cứng — không phải giả định, là hành vi thật.

**Quyết định:** đổi tên `setup.py` → `bootstrap.py` (giữ nguyên toàn bộ
hành vi/CLI, chỉ đổi tên file + `argparse(prog=...)` + docstring). Xác nhận
lại sau khi đổi: `pip install --no-build-isolation --dry-run .` chạy sạch,
`python3 -m build --wheel` ra đúng `modules/*.py`, không lẫn `outputs/`/
`wordlists/`/`tests/`. `README.md`, `config.yml`, `setup_kali.sh`,
`docs/index.md`, `tests/test_bootstrap.py` (đổi tên từ `test_setup.py`) đã
cập nhật theo. Không rename bừa các file khác có tên tương tự — đây là
trường hợp thật sự cần thiết vì xung đột trực tiếp với goal đóng gói.

### Lock dependency — `requirements-lock.txt`

**Quyết định:** không chuyển sang `pip-tools`/`uv`/`poetry` (thêm tool mới
vào quy trình vốn chỉ cần `pip install -r requirements.txt`). Thay vào đó
`requirements-lock.txt` ghi tay phiên bản chính xác đã verify cùng nhau
(`pyyaml`/`requests`/`setuptools`/`rich` + extras `flask`/`openpyxl` VÀ cây
transitive của chúng) — cố tình KHÔNG gồm các tool recon cài qua pip
(`arjun`/`waymore`/`xnLinkFinder`...), vì đó là CLI ngoài, không phải thư
viện `recon2win` import. `requirements.txt` (range mở) vẫn là nguồn tài liệu
"những gì được biết là chạy được"; lock file là đường tái lập chính xác.

### Typed stage-result contract — additive, không sửa từng module

**Quyết định:** thêm `StageResult` (`TypedDict`) + `StageStatus`
(`Literal["success","failed","skipped"]` — grep xác nhận đây là 3 giá trị
DUY NHẤT từng được truyền cho `make_result()` trong toàn bộ `modules/*.py`)
vào `modules/utils.py`, annotate `make_result() -> StageResult`. `TypedDict`
không ràng buộc gì lúc runtime (`type(make_result(...))` vẫn là `dict`
thường) — mọi module gọi/đọc dict kết quả tiếp tục hoạt động y hệt, không
cần sửa. Chỉ 50+ stage function trong `modules/*` GIỜ có type checker hiểu
đúng hình dạng, không cần sửa từng file.

Kiểm bằng `mypy modules/utils.py` (cài tạm để verify, không thêm vào
dependency — dự án chưa áp dụng mypy toàn repo) phát hiện luôn 1 lỗi type
thật trong chính `make_result()`: biến `output_list` được gán lại theo 2
nhánh `if/else` không cùng type suy luận (`outputs or []` ở nhánh gán đầu
tiên làm mypy suy ra `list[Path|str]`, trong khi cả 2 nhánh sau đó đều thực
sự trả `list[str]`) — đã sửa bằng cách bỏ dòng gán trung gian, gán thẳng
`List[str]` ở cả 2 nhánh. Hành vi runtime không đổi (verify bằng pytest đầy
đủ).

### Structured logging (`logs/run.log`) — song song với console, không thay thế

**Vấn đề:** `_run_stage` in narrative ra terminal, nhưng gần như không gì
sống sót trên đĩa theo thời gian thực — `logs/stages.json` chỉ ghi MỘT LẦN ở
cuối run. Một run bị giết giữa chừng (mất SSH, OOM lúc nuclei chạy lâu,
VPS reboot) không để lại dấu vết nào về việc gì đã xảy ra trước đó, ngoài
output thô per-stage.

**Quyết định:** `modules/runlog.py` — `stdlib logging`, ghi `logs/run.log`
(leveled, UTC, flush ngay mỗi dòng). Cố tình KHÔNG gắn console/stream
handler — `console.py`/`print()` đã sở hữu terminal, gắn thêm handler ở đây
sẽ in trùng hoặc đụng màu/format. `main.py::_run_stage` log start (DEBUG) +
kết quả (INFO khi success/skipped, WARNING khi failed) — cùng thông tin đã
in ra console, chỉ khác là bền trên đĩa. `--dry-run` cố tình không gọi
`runlog.setup()` — giữ đúng cam kết "không đụng gì" đã có từ trước.

Bẫy phát hiện khi viết test: `logging.getLogger("recon2win")` là singleton
toàn tiến trình pytest — một test gọi `main._run_stage` trực tiếp (bỏ qua
`main()`, nơi DUY NHẤT gọi `runlog.setup()` thật) sẽ kế thừa file handler
còn sót từ test TRƯỚC ĐÓ, ghi nhầm vào `tmp_path` đã bị pytest dọn. Fix:
`tests/conftest.py::_isolated_runlog` (autouse) đóng + gỡ mọi handler sau
mỗi test — cùng tinh thần với `_no_baseline_probe` đã có sẵn trong file đó.

### Project grouping (`outputs/<project>/<domain>/`) — opt-in, không migrate data cũ

**Yêu cầu:** gom nhiều target vào một "project" khi scan.

**Quyết định layout:** lồng thư mục thật (`outputs/<project>/<domain>/`),
không phải chỉ gắn nhãn logic — chọn vì `dashboard.html`/report tự nhiên
nhóm theo cấu trúc đĩa, không cần một tầng ánh xạ riêng.

**Quyết định migrate:** 12 target thật đang có tại `outputs/<domain>/` (phẳng)
GIỮ NGUYÊN, không di chuyển. `layout.py` đã có tiền lệ y hệt cho việc này
(fallback v2→v3 của `processed/`), nên áp dụng lại: một target không nằm
trong project nào là hợp lệ, gọi là "ungrouped" (`project: None`), không
phải lỗi hay trạng thái tạm.

**Vì sao không cần sửa `layout.py`/`apidocs.py`/`jsluice.py`/
`xnlinkfinder.py`/`responses.py`:** tất cả những chỗ đó dùng
`output_dir.name` để suy ra domain — mà domain LUÔN LÀ thư mục lá
(leaf), bất kể phía trên nó lồng thêm bao nhiêu tầng project. Thêm một
tầng cha không đổi `output_dir.name`. Đây là lý do toàn bộ thay đổi chỉ
gói gọn trong 3 file: `utils.py` (tạo path + `validate_project`), `main.py`
(CLI flag `-p/--project`), `dashboard.py` (nhận diện 2 tầng khi liệt kê
target — `_is_target_dir()` kiểm tra có skeleton `raw/logs/report/processed`
hay không để phân biệt "đây là 1 target" với "đây là 1 project chứa
target bên trong").

**Quyết định khái niệm:** project độc lập với `--h1-program` (không tự
động suy ra project từ HackerOne program) — theo yêu cầu, vì project ở đây
là nhãn tự do (khách hàng/chiến dịch), không nhất thiết trùng 1-1 với một
chương trình H1.

**Phạm vi đã làm**: CLI (`-p/--project`) + layout + dashboard (cột Project,
gom nhóm). CHƯA làm: web UI (`web/app.py`), REST API, gán project cho 12
target cũ (còn "ungrouped" tới khi tự tay làm hoặc yêu cầu công cụ hỗ trợ).

## Nợ kỹ thuật đã biết (chưa xử lý, ghi lại để không phải phát hiện lại)

| Nợ | Mô tả | Mức ảnh hưởng |
|---|---|---|
| Không có schema validation cho `config.yml` | Gõ sai tên key bị `main.py::_deep_merge` nuốt im lặng — không có cảnh báo | Trung bình — dễ cấu hình sai mà không biết |
| ~~Contract giữa stage chỉ là dict quy ước~~ | Một phần đã xử lý — `StageResult`/`StageStatus` (`modules/utils.py`) cho type checker, xem mục "Typed stage-result contract" ở trên. CHƯA làm: chưa có mypy/pyright trong CI để việc gõ sai thật sự bị chặn, `main.py` chưa annotate `results: list[StageResult]` | Giảm — còn thiếu bước enforce trong CI |
| `main.py` là orchestrator đơn khối | Thêm 1 stage cần sửa ~5 chỗ (import, `ThreadPoolExecutor` wiring, `_STAGE_NOUN`, dry-run plan text, CLI flag) | Trung bình — tăng chi phí mở rộng pipeline |
| Output qua `print()`, không dùng `logging` | Không có level, không log ra ngoài tiến trình — phù hợp chạy tương tác, yếu cho chạy nền/lịch định kỳ | Thấp cho hiện tại, tăng dần theo quy mô vận hành |
| Không có khái niệm workspace ngoài `outputs/<domain>/` | Không có scope/notes/knowledge base theo từng target — chỉ có scan artefact | Cao nếu muốn mở rộng thành "workspace nghiên cứu bảo mật" lâu dài |
| ~~Chưa lock dependency~~ | Đã xử lý — `requirements-lock.txt` + `pyproject.toml [project]` (xem mục "Lock dependency" ở trên) | Đã xử lý |
| Web UI không auth, in-memory | Tự nhận trong docstring là chỉ dùng dev/demo | Thấp — miễn không dùng làm workflow thật |
| Lịch sử git từng đi sau code trên đĩa | Tính đến trước phiên dọn dẹp gần nhất, nhiều module nền tảng (`layout.py`, `baseline.py`, `behavior.py`, `existence.py`, `asm_report.py`, `dashboard.py`, 5 probe mới, `xlsx_report.py`) chưa từng được commit dù đã chạy trên production | Đã xử lý — xem lịch sử `git log` từ commit `docs: them CLAUDE.md...` trở đi |
