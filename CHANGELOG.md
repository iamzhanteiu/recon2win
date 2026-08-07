# Changelog

Định dạng theo [Keep a Changelog](https://keepachangelog.com/), version theo
[SemVer](https://semver.org/). Lịch sử chi tiết từng commit xem `git log` —
file này tóm tắt ở mức tính năng, không lặp lại từng commit.

Repo chưa gắn version cho tới bản này (`pyproject.toml [project].version`);
lịch sử trước đó (108 commit, 2026-06-23 → 2026-08-07) được gộp vào `[0.1.0]`
làm điểm mốc đầu tiên.

## [Unreleased]

### Added

* **Structured logging** — `modules/runlog.py` ghi `logs/run.log` (leveled,
  UTC, `stdlib logging`), song song với terminal, không thay thế. Config
  mới: `logging.enabled` / `logging.level` trong `config.yml`.
* **Typed stage-result contract** — `StageResult`/`StageStatus` (`TypedDict`)
  trong `modules/utils.py`, additive (không đổi runtime, không sửa từng
  module gọi `make_result()`).
* `CHANGELOG.md` (file này).

## [0.1.0] - 2026-08-07

Điểm mốc version đầu tiên. Framework đã hoạt động đầy đủ pipeline 9+ giai
đoạn từ trước, bản này chính thức hoá packaging + đưa lịch sử git khớp với
code trên đĩa (xem `docs/architecture/decisions.md` cho quyết định chi tiết).

### Added

* **Pipeline lõi**: subdomain (subfinder+amass+chaos) → puredns validate →
  dnsx → httpx alive → content discovery (katana/urlfinder/dirsearch/ffuf/
  waymore, song song) → merge → JS analysis (xnLinkFinder + jsluice AST) +
  probe (apidocs/graphql/cors/misconfig/buckets/gitdump) → arjun → nuclei →
  report.
* **Screening theo hành vi response** (`modules/baseline.py`,
  `modules/behavior.py`, `modules/existence.py`) — đo response của path
  không tồn tại trước khi fuzz, gom hit theo status+content-type+redirect+
  words/lines thay vì status/byte-length đơn lẻ; verdict Confirmed/Likely/
  Unknown/Not-Found cho mỗi hit.
* **Fuzz theo độ sâu + tech** (`modules/fuzz_depth.py`) — tier deep/standard/
  light, wordlist chọn theo tech xác định (httpx `-td` + `misconfig_probe`
  xác nhận, tích luỹ qua nhiều lần scan).
* **Layout v3** (`modules/layout.py`) — `processed/` nhóm theo lifecycle
  (`sources/corpus/hosts/js/targets`), SSOT cho mọi đường dẫn artefact.
* **MANIFEST.json** (`modules/audit.py`) — phân biệt "0 dòng vì sạch" với
  "0 dòng vì chưa từng quét" (`ok/ran_empty/blocked/truncated/skipped/
  failed/absent`).
* **URL provenance** (`modules/url_merge.py`) — `all_urls.jsonl` ghi mỗi URL
  đến từ tool nào, xếp hạng theo chất lượng nguồn trước khi cắt cap.
* **5 probe xác nhận mới**: `graphql_probe`, `cors_probe`, `misconfig_probe`
  (deep-tier), `buckets` (opt-in), `gitdump` (opt-in) — xác nhận finding
  bằng 1 request thật thay vì chỉ nêu URL tồn tại.
* **Screenshot host** (`modules/httpx.py::capture_screenshots`, opt-in).
* **Post-scan intelligence**: `modules/priority.py` (priority_targets.txt),
  `modules/scandiff.py` (delta.md), `modules/graphgen.py` (graph.mmd),
  `modules/asm_report.py` (asm_report.html — chấm điểm tin cậy run),
  `modules/dashboard.py` (dashboard.html — tổng quan mọi target).
* **Report**: `modules/xlsx_report.py` (workbook 17 sheet, opt-in
  `--xlsx-report`).
* **Tích hợp**: HackerOne (`modules/hackerone.py`), Telegram
  (`modules/telegram.py`), Web UI tuỳ chọn (`web/app.py`).
* **Claude Code skills**: `recon-surface`, `recon-health`, `bug-hunter`
  (`.claude/skills/`).
* **Đóng gói**: `pyproject.toml [project]` (package `modules/`, extras
  `web`/`xlsx`/`all`), `requirements-lock.txt`.
* **Docs**: `docs/index.md`, `docs/architecture/{overview,modules,
  decisions}.md`, `CLAUDE.md`.

### Changed

* `setup.py` → `bootstrap.py` — tránh xung đột tên với PEP 517 build
  (`pip install .` fail cứng khi trùng tên; xem `docs/architecture/
  decisions.md`). Hành vi/CLI không đổi.
* `nuclei`: chỉ còn 1 pass (`nuclei_default`, alive hosts) chạy cuối pipeline,
  bỏ 2 pass cũ (`endpoints`/`dynamic`) để không chia rate budget với 4 tool
  discovery song song ở stage 4.
* `dirsearch`/`ffuf`: ngân sách suy từ khối lượng request thật
  (`target × từ ÷ rate`) thay vì hằng số mỗi host; `dirsearch` chunk theo
  host để một timeout không xoá sạch kết quả các host chưa tới lượt.

### Fixed

* 2 crash upstream của `arjun` ≤2.2.7 (`AttributeError` khi target trả
  400/413/418/429/503 hoặc lỗi mạng) — tự vá trước khi chạy.
* `setuptools>=81` xoá `pkg_resources` khỏi bundle → `dirsearch` crash ngay
  khi chạy — pin `<81`.
