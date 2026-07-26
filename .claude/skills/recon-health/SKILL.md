---
name: recon-health
description: Audit sức khoẻ và độ tin cậy của một run recon2win trong outputs/<domain>/ — trả lời "kết quả này có đáng tin không", đặc biệt khi run báo 0 finding. Dùng khi được hỏi "run này có ổn không", "sao không có finding nào", "quét xong chưa", "stage nào hỏng", "coverage bao nhiêu", hoặc trước khi kết luận bất cứ điều gì từ output của một lần quét.
---

# Audit sức khoẻ run (recon2win)

Skill này trả lời **đúng một câu hỏi**: *kết quả của run này có đáng tin không?*

Đặc biệt là câu "0 finding". Nó có hai nghĩa hoàn toàn trái ngược —
**"đã quét, sạch"** và **"chưa từng quét"** — mà nhìn output thì giống hệt
nhau. Phân biệt được hai cái đó là toàn bộ giá trị ở đây.

## Vì sao không đọc thẳng stages.json

**`status` của stage nói dối.** Trong data thật:

```
dirsearch          status: success   error: "timeout after 4484s — salvaged 318 partial"
nuclei_endpoints   status: success   error: "8/8 batches ... continued past timed-out"
```

Cả hai đều `success`. Một run báo "26/26 success" vẫn có thể đã bỏ qua 88%
bề mặt mà không dòng nào nói ra. Thông tin thật nằm ở `error` và
`extra.timed_out` / `extra.deadline_hit`, không ở `status`.

`stages.json` cũng nặng ~60 KB. **Đừng `Read` nó.** Chạy script:

```bash
python3 .claude/skills/recon-health/audit.py outputs/<domain>
```

Ra ~1,6 KB (~0,5k token) đã gộp sẵn 5 mục: stage thất bại, stage cụt-nhưng-
báo-success, ngân sách vô lý, sổ cái coverage, thời gian đi đâu.

## Đọc kết quả: 4 archetype lỗi, cả 4 đều gặp thật

**1. Cụt nhưng báo success** — nguy hiểm nhất, vì không ai đọc `error`.
`nuclei_endpoints` của acronis: `success`, chạy 3,95h, trả về 2 finding, và
mọi batch đều timeout. Con số "2" trông như kết luận; thật ra là mảnh vụn.

**2. Ngân sách hỏng** — thông báo timeout không khớp thời gian chạy thật.
`arjun` báo `timeout after 1s` nhưng `elapsed_seconds: 3601`. Số "1s" là lỗi
tính ngân sách, không phải timeout thật. Gặp cái này thì **đừng tin cả stage**,
kể cả phần nó báo thành công — và đó là bug cần sửa trong code, không phải
tinh chỉnh config.

**3. Coverage bị cắt âm thầm** — stage chạy trọn vẹn, nhưng chỉ trên một lát
mỏng của input. `arjun` acronis: **200/23.661 URL = 0,8%**. Không có dòng nào
gọi đó là lỗi, vì nó không phải lỗi — nó là cap trong config. Nhưng nó khiến
"arjun không tìm thấy param nào" thành vô nghĩa.

**ĐỌC PHẦN TRĂM COVERAGE CHO ĐÚNG.** Con số thô không phải thước đo; cái đáng
đọc là **thành phần** của phần bị cắt, in ngay bên cạnh:

- **có dấu `!`** (`capped!`, `unrun!`) — cắt vì hết ngân sách. Đây mới là bề
  mặt **chưa từng được nhìn**.
- **không có `!`** (`deduped`, `per_host_capped`, `dropped_no_param`,
  `waf_skipped`) — bỏ bản sao hoặc bỏ thứ chắc chắn vô ích. **Không mất gì.**

Ví dụ hai dòng cùng "thấp" nhưng trái ngược nhau:

```
dirsearch         43/157   27.4%  -114 deduped                    <- 114 host wildcard trung nhau, khong mat gi
arjun            200/6329   3.2%  -6129 capped!                   <- 6129 URL that su chua quet
nuclei_endpoints 482/5487   8.8%  -4945 per_host_capped waf:2     <- bo ban sao cua 1 trang WAF, tot hon 2000/5487
```

Dòng thứ ba là bản sửa `max_per_host`: danh sách nhỏ hơn 4 lần nhưng số URL
trả 200 tăng từ 13 lên 177. Chấm theo phần trăm thô thì tưởng là bước lùi.

**4. Thời gian không đổi ra kết quả** — `nuclei_default` acronis đốt 3,98h cho
4 finding; `nuclei_endpoints` 3,95h cho 2. Không tự nó là lỗi, nhưng là chỗ
đáng hỏi tiếp: tag set sai? target chặn hết ở edge? (xem skill
`recon-surface` phase 3).

Đối chiếu: `guildwars2.com` có 7/24 stage hỏng, cả 3 scan nuclei timeout ở
7200s với **0 finding cứu được**. Run đó không phải "target sạch" — nó là
**không có dữ liệu**. Đừng bao giờ báo cáo con số 0 từ một run như vậy.

## Đối chiếu chéo: stage khai gì vs đĩa có gì

Stage báo success nhưng artifact rỗng là dấu hiệu hỏng thầm lặng:

```bash
python3 -c "
import json,os
d=json.load(open('outputs/<domain>/logs/stages.json'))
for s in (d if isinstance(d,list) else d.get('stages',d)):
    for o in s.get('outputs') or []:
        if os.path.exists(o) and os.path.getsize(o)==0:
            print('RONG:', s['stage'], o)
"
```

Riêng nuclei, cờ `complete` mới là thứ `--resume` tin — file có dữ liệu vẫn
có thể là scan cụt:

```bash
for k in default endpoints dynamic; do
  f=outputs/<domain>/findings/$k/nuclei.json
  [ -f "$f" ] && python3 -c "
import json;d=json.load(open('$f'))
print('$k', 'complete=', d.get('complete'), 'findings=', len(d.get('findings',[])))"
done
```

`complete=False` ⇒ `--resume` sẽ quét lại stage đó, và con số finding hiện tại
là **sàn**, không phải kết quả.

## Truy ngược coverage về config

Mỗi dòng coverage thấp đều có một khoá config đứng sau. Tra để biết nên nới
hay đó là cắt cố ý:

| stage | nguồn cắt | khoá trong `config.yml` |
|---|---|---|
| `nuclei_endpoints` | `url_filter` | `nuclei.endpoints.max_urls`, `max_per_host`, `waf_host_max` |
| `nuclei_dynamic` | `param_filter` | `nuclei.dynamic.max_urls` |
| `dirsearch` / `ffuf` / `content_discovery` | `selection` | `*.max_hosts`, `dedup_targets` |
| `arjun` | `input_urls`→`scanned_urls` | `arjun.max_urls` |
| mọi nuclei | `batches` | `batch_size`, `batch_timeout`, `timeout` |

**Cắt cố ý không phải lỗi** — cap tồn tại vì ngân sách có hạn. Lỗi là *không
biết mình đã cắt gì*. Nhiệm vụ của báo cáo là nói ra ranh giới đó.

## Kết quả trả về

1. **Một dòng kết luận trước tiên**: tin được / một phần / vô nghĩa.
2. **Stage nào hỏng và hỏng kiểu gì** — theo 4 archetype trên, kèm số đo.
3. **Ranh giới đã kiểm vs chưa kiểm** — nói thẳng dạng "đã quét 2.000/18.722
   URL phát hiện được (10,7%); 0 finding chỉ áp dụng cho phần 10,7% đó".
4. **Việc cần làm tiếp**, tách rõ hai loại:
   - *bug cần sửa code* (ngân sách vô lý, timeout không khớp)
   - *đánh đổi cần quyết định* (nới cap thì tốn thêm bao nhiêu giờ)

Nếu có stage thất bại hoặc ngân sách hỏng, **nói rõ là không thể kết luận gì
về bảo mật của target từ run này**. Báo cáo "không tìm thấy lỗ hổng" dựa trên
một run hỏng còn tệ hơn không báo cáo gì.
