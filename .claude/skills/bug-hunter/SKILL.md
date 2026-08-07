---
name: bug-hunter
description: Xác minh và chấm severity thật cho finding của một run recon2win trong outputs/<domain>/ — biến nuclei findings + priority_targets.txt thành bug report có thể nộp. Dùng khi được hỏi "bug này có thật không", "finding này nghiêm trọng cỡ nào", "phân tích kết quả recon như security analyst", "target này có gì nộp bug bounty được", "confirm lỗ hổng", "soạn báo cáo/PoC". KHÔNG dùng để audit độ tin cậy của run (xem recon-health) hay để liệt kê ứng viên thô chưa xác minh (xem recon-surface).
---

# Xác minh bug thật (recon2win)

Mục tiêu: từ finding thô (`findings/*/nuclei.json`) + ứng viên đã xếp hạng
(`report/priority_targets.txt`) rút ra **danh sách bug đã xác minh**, mỗi cái
kèm severity có lý do (không copy tag nuclei), bằng chứng tái hiện được, và
khung report gần dạng nộp H1. Đây là bước SAU `recon-surface`, không phải làm
lại nó.

## Ranh giới với 2 skill khác — đọc trước khi bắt đầu

- **`recon-health`** trả lời "run này đáng tin không". Skill này giả định câu
  đó đã được trả lời "có". Nếu chưa audit, chạy `recon-health` trước — một
  finding severity cao từ một stage bị cắt cụt vẫn có thể đúng, nhưng "0
  finding" từ stage đó thì vô nghĩa, không phải "sạch".
- **`recon-surface`** trả lời "chỗ nào đáng soi tay mà scanner bỏ sót" — đầu ra
  là ứng viên **chưa xác minh**. Skill này lấy đầu ra đó (và đầu ra nuclei) làm
  input, rồi xác minh/chấm điểm/viết report. Đừng liệt kê lại ứng viên thô ở
  đây — nếu chưa verify được, nó thuộc nhóm NEEDS-DIGGING (xem cuối), không
  phải CONFIRMED.

## Phase 1 — gộp tín hiệu bằng script, đừng đọc raw nuclei.json

`findings/*/nuclei.json` mang theo `request`/`response`/`curl-command` đầy đủ
cho từng finding — đo thật trên `outputs/dialogue.co`: file thô **173.658
byte** cho 24 finding. Đọc thẳng để có bức tranh tổng quan là phí; script gộp
xuống còn severity/name/host/matched-at/tags:

```bash
python3 .claude/skills/bug-hunter/collect.py outputs/<domain>
```

Script cũng gộp sẵn `report/priority_targets.txt` (top 30), `findings/
jsluice_secrets.json` (nếu không rỗng), và các form POST trong `forms.json`
(lọc method) — một lệnh là đủ input để bắt đầu triage, không cần tự mở từng
file. Chỉ quay lại đọc field `curl-command`/`request`/`response` trong
`nuclei.json` gốc (bằng `jq`) cho **đúng finding đang verify** ở Phase 2.

## Phase 2 — xác minh, đừng tin severity/matcher-status cũ

**Nuclei finding**: mỗi finding tự chứa `curl-command` sẵn header/cookie cần
thiết — chạy thẳng nó, không tự bịa lại request:

```bash
jq -r '.findings[] | select(.["template-id"]=="librechat-config-exposure") | .["curl-command"]' \
  outputs/<domain>/findings/default/nuclei.json
```

So kết quả với `matcher-status` gốc trong JSON. Hai khả năng cần phân biệt:
- Vẫn tái hiện được → giữ trong CONFIRMED, đi tiếp Phase 3.
- Không còn tái hiện (đã patch / đổi hạ tầng) → hạ xuống "không còn hiệu lực",
  không giữ nguyên severity gốc dù nuclei từng báo `high`/`critical`.

**Ứng viên từ `priority_targets.txt`**: verify bằng `curl -sk` như
`recon-surface` Phase 6, và áp dụng đúng bộ lọc WAF/blanket-deny đã viết ở
`recon-surface` Phase 3 (401 ≠ 403; probe path không tồn tại để phân biệt CDN
trả lời thay origin) — không viết lại quy tắc đó ở đây, chỉ áp dụng.

## Phase 3 — chấm severity theo impact thật, không copy tag nuclei

Severity trong template nuclei là mặc định của tác giả template, không phải
đánh giá impact trên target cụ thể. Ví dụ thật từ `outputs/dialogue.co`:

- `librechat-config-exposure` bị gắn **low** trên `librechat.dialogue.co/api/
  config` và `librechat-phi.dialogue.co/api/config` — nhưng cùng run có
  `CVE-2025-8848` (**medium**, HTML injection qua header `Accept-Language`)
  trên chính 2 host đó. Config exposure một mình là low; nhưng nếu response
  của nó lộ ra thứ dùng được để tăng impact của CVE cạnh nó (endpoint nội
  bộ, version, feature flag) thì phải nâng lên khi viết report, không giữ
  `low` máy móc.
- Các finding `info` như `CORS Misconfiguration` lặp lại trên gần chục host
  đều đến từ cùng 1 template — hỏi tiếp: origin nào được reflect? có
  `Access-Control-Allow-Credentials: true` không? Không có 2 câu đó thì CORS
  info đúng nghĩa là info, đừng thổi phồng.

Trục đánh giá bắt buộc trước khi chốt severity: có cần auth không / loại dữ
liệu lộ ra (PII, secret, nội bộ) / read hay write / blast radius (1 host lẻ
hay hạ tầng dùng chung nhiều host, như 2 host LibreChat ở trên).

## Phase 4 — tìm cơ hội chain, đừng báo cáo rời rạc

Nhìn `priority_targets.txt` theo domain/luồng, không theo từng dòng độc lập.
Ví dụ thật, cùng domain `dialogue.co`:

```
[  710]  .../content-tools-menu/api/v1/content/validate-hubspot-user?redirect_url=  — open-redirect candidate
[  680]  .../help.dialogue.co/auth/v3/signin?return_to=...  — auth
[  680]  .../help.dialogue.co/auth/v3/signin?return_to=...  — auth
```

Một `redirect_url`/`open-redirect candidate` đứng cạnh nhiều URL đăng nhập
dùng `return_to=` là dấu hiệu đáng kiểm chéo: hai tham số đó có đi qua cùng
một hàm validate không? Open-redirect nằm trong luồng auth (redirect sau
login) có giá trị cao hơn hẳn open-redirect độc lập, vì có thể ghép thành
account-takeover-adjacent (đánh cắp token qua redirect). Báo cáo phải nêu
rõ đây là **giả thuyết cần verify tay** cho tới khi test được, không tự nâng
severity chỉ vì nhìn giống chain.

## Phase 5 — kỷ luật false positive (tái dùng, không viết lại)

- Secret trong JS: áp dụng nguyên văn quy tắc ở `recon-surface` Phase 5 (GCP
  browser key public là bình thường trừ khi không giới hạn referrer; key lặp
  trên nhiều host là asset dùng chung, không phải rò rỉ riêng).
- WAF/CDN trả lời thay origin: áp dụng `recon-surface` Phase 3 +
  `modules/baseline.py`/`behavior.py` (fingerprint theo shape response, không
  theo status/length đơn lẻ).
- Riêng phần mới ở đây: finding nuclei từng severity cao nhưng Phase 2 xác
  nhận không còn tái hiện được → ghi rõ "đã kiểm tra lại ngày <hôm nay>,
  không còn khai thác được", đừng để nó lẫn vào CONFIRMED chỉ vì nuclei từng
  gắn cờ.

## Kết quả trả về

Hai nhóm, không trộn lẫn:

**CONFIRMED** (đã tái hiện được, tối đa ~10-15 mục, ưu tiên impact thật chứ
không phải số lượng) — mỗi mục gồm:

1. Title
2. Asset / URL bị ảnh hưởng
3. Severity + 1 dòng lý do (theo trục Phase 3, không copy tag nuclei)
4. Steps to reproduce — lệnh `curl` chạy được ngay (lấy từ `curl-command` gốc
   hoặc lệnh đã verify ở Phase 2)
5. Impact — hậu quả cụ thể trên target này, không phải mô tả chung của CVE
6. Remediation gợi ý

Định dạng đủ gần khung Summary/Steps/Impact để copy sang khi nộp qua
`modules/hackerone.py` (nếu domain có chương trình H1 tương ứng).

**NEEDS-DIGGING** (có tín hiệu, chưa verify được — target đổi hành vi, cần
thao tác tay ngoài `curl`, hoặc cần điều kiện auth không có sẵn): liệt kê
ngắn gọn kèm lý do chưa xác minh được, để không mất dấu nhưng cũng không lẫn
vào danh sách đã confirm.
