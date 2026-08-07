# recon2win — Project Index

Điểm vào để định hướng toàn bộ repo. Mọi thông tin dưới đây được xác minh từ
mã nguồn tại thời điểm viết (không suy đoán) — nếu lệch với code, code là
nguồn sự thật, sửa tài liệu này theo code.

## Đọc gì trước

| Muốn biết | Đọc |
|---|---|
| Cách chạy, CLI flags, output layout, cách đọc report | [`README.md`](../README.md) |
| Kiến trúc tổng thể, pipeline, data flow | [`architecture/overview.md`](architecture/overview.md) |
| Vai trò + quan hệ giữa các module trong `modules/` | [`architecture/modules.md`](architecture/modules.md) |
| Vì sao một tham số/ngưỡng có giá trị như hiện tại (design decisions, technical debt) | [`architecture/decisions.md`](architecture/decisions.md) |
| Spec thiết kế báo cáo ASM (mô hình dữ liệu từ output thật) | [`report-design.md`](report-design.md) |
| Spec thiết kế web console (read API, state store) | [`ui-design.md`](ui-design.md) |
| Quy ước duy trì tài liệu + ngôn ngữ trả lời | [`../CLAUDE.md`](../CLAUDE.md) |
| Cách Claude Code nên review output/finding của một run | [`../.claude/skills/`](../.claude/skills/) — `recon-surface`, `bug-hunter`, `recon-health` |

## Repo này là gì

`recon2win` là một framework tự động hoá recon (bug bounty / ASM / red team
recon), điều phối bởi `main.py` qua một pipeline nhiều giai đoạn (subdomain →
DNS → HTTP alive → content discovery/fuzzing → merge → JS analysis + probe →
param discovery → nuclei → report). Chi tiết đầy đủ: `architecture/overview.md`.

## Cấu trúc thư mục (mức 1)

```
recon2win/
├── main.py              # CLI + orchestrator — điểm vào duy nhất để chạy scan
├── setup.py              # Bootstrap môi trường (tool + wordlist)
├── config.yml             # Cấu hình mặc định (nguồn sự thật cho mọi tham số runtime)
├── config.local.yml       # (git-ignored) override bí mật — Telegram token, HackerOne token
├── modules/                # Logic nghiệp vụ — mỗi file một stage hoặc một mối quan tâm xuyên suốt
├── tests/                   # pytest — xem architecture/modules.md để map test ↔ module
├── web/                       # Flask dev UI tuỳ chọn (không auth, không phải production)
├── docs/                        # Bạn đang ở đây
├── .claude/skills/                # Skill cho Claude Code review output/finding
├── wordlists/SecLists/              # (git-ignored, do setup.py --wordlists tải về)
└── outputs/<domain>/                  # Artefact mỗi lần scan — xem README § Output directory layout
```

## Entry point / API quan trọng

* **CLI**: `python3 main.py -d <domain> [--config config.yml] [--resume] [--dry-run] [--doctor] ...`
  — danh sách đầy đủ cờ trong `README.md § CLI flags`.
* **Module contract**: mọi stage function theo chữ ký
  `fn(input_path, output_dir, cfg, *, resume=False, dry_run=False, skip=False) -> dict`,
  trả về qua `modules.utils.make_result()` — xem `architecture/modules.md § Contract giữa các stage`.
* **Đường dẫn artefact**: không tự nối `output_dir / "processed" / "..."` — luôn qua
  `modules.layout.path(output_dir, name)` / `modules.layout.ensure_tree(output_dir)`.
* **Web UI** (tuỳ chọn): `python3 web/app.py` → `POST /api/run`, `GET /api/stream/<scan_id>` — xem
  `README.md § Web UI`.

## Trạng thái tài liệu

Repo đã có lịch sử phát triển (`git log`) đi sau code trên đĩa một khoảng —
tính đến lần cập nhật tài liệu này, lịch sử đã được đồng bộ lại (xem commit
`docs:`/`feat(layout)`/... gần nhất). `docs/architecture/` mới được tạo lần
đầu ở đây; trước đó kiến trúc chỉ tồn tại rải rác trong docstring của từng
module và comment trong `config.yml`.
