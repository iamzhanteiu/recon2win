---
name: recon-surface
description: Review bề mặt tấn công của một run recon2win trong outputs/<domain>/ — chỉ ra chỗ đáng soi tay mà scanner không bắt được. Dùng khi được hỏi "review output recon", "run này có gì đáng xem", "bề mặt tấn công của <domain>", "còn gì scanner bỏ sót", hoặc khi cần triage processed/ + findings/jsluice_secrets.json sau một lần quét.
---

# Review bề mặt tấn công (recon2win)

Mục tiêu: từ `outputs/<domain>/` rút ra **danh sách ngắn chỗ đáng soi tay**, kèm
bằng chứng và lệnh verify. KHÔNG phải liệt kê lại những gì nuclei đã quét —
mà tìm đúng phần scanner mù: API trả JSON, ranh giới xác thực, form ghi dữ
liệu, tham số lạ, secret trong JS.

## Quy tắc cứng: gộp bằng shell TRƯỚC, chỉ nạp phần đã distill

Đây là ràng buộc về chi phí, không phải lời khuyên phong cách. Đo thật trên
`outputs/acronis.com`:

| cách làm | dung lượng | ~token |
|---|---|---|
| đọc raw các file bề mặt | 2,31 MB | **~661k** |
| aggregate bằng shell rồi mới đọc | 8,5 KB | **~2,4k** |

Chênh ~275 lần, và bản raw vượt quá context window.

**KHÔNG BAO GIỜ** `Read`/`cat` nguyên các file này — chúng lên tới hàng MB:
`processed/alive_urls_table.txt`, `processed/alive_urls.txt`,
`processed/all_urls.txt`, `processed/crawler_urls.txt`,
`processed/waymore_urls.txt`, `processed/alive_urls_detail.json`,
`logs/*.log`.

Luôn đi qua `awk`/`sort`/`uniq`/`jq` và chỉ để kết quả đã gộp vào context.
File nhỏ (`findings/jsluice_secrets.json`, `processed/jsluice_params.json`,
`report/priority_targets.txt`) thì đọc thẳng được — kiểm bằng `stat -c%s`
trước, ngưỡng an toàn ~50 KB.

Định dạng `alive_urls_table.txt`: `ST  LENGTH  CONTENT-TYPE  URL`
→ `$1`=status, `$2`=length, `$3`=content-type, `$4`=url, có dòng header.

## Phase 0 — cổng tin cậy (bắt buộc, làm trước)

Một run cụt cho ra bề mặt cụt, và nó trông y hệt bề mặt sạch. Kiểm trước khi
kết luận bất cứ điều gì về coverage:

```bash
python3 -c "
import json; d=json.load(open('outputs/<domain>/logs/stages.json'))
st=d if isinstance(d,list) else d.get('stages',d)
for s in st:
    e=s.get('extra') or {}
    flag=[k for k in ('timed_out','deadline_hit') if e.get(k)]
    if flag or s.get('status')!='success':
        print(s.get('stage'), s.get('status'), flag, str(s.get('error'))[:120])
"
```

Có stage nào cụt thì **nói rõ trong báo cáo** là bề mặt bị thiếu ở đâu, đừng
im lặng. Đặc biệt: `httpx_urls` cụt ⇒ `alive_urls.txt` thiếu ⇒ mọi phase dưới
đều thiếu theo.

## Phase 1 — hình dạng bề mặt

```bash
cd outputs/<domain>
awk 'NR>1 {print $1, $3}' processed/alive_urls_table.txt | sort | uniq -c | sort -rn | head -20
```

Đọc phân bố này để biết cái gì là nhiễu nền. Ví dụ acronis.com: 12.246× 301 và
4.128× 403 là nền, 1.643× 200 mới là bề mặt thật.

## Phase 2 — nội dung không phải HTML (chỗ scanner yếu nhất)

```bash
awk 'NR>1 && $1==200 && $3 ~ /json|octet|plain|xml|csv/ {print}' processed/alive_urls_table.txt | head -40
awk 'NR>1 && $1==200 {print $2}' processed/alive_urls_table.txt | sort -n | uniq -c | sort -rn | tail -15
```

`application/json` trả 200 mà không cần auth là ứng viên hàng đầu (IDOR, rò
dữ liệu, endpoint nội bộ). Dòng thứ hai tìm **size lạ** — 200 có
content-length nằm ngoài các cụm phổ biến thường là trang thật giữa một biển
soft-404 cùng kích thước.

## Phase 3 — ranh giới xác thực (đọc kỹ, dễ sai)

```bash
awk 'NR>1 && ($1==401 || $1==403 || $1>=500) {print}' processed/alive_urls_table.txt | head -40
```

**401 và 403 KHÔNG cùng giá trị:**

- `401` = app trả lời "cần xác thực" → endpoint có thật, đáng soi.
- `403` **hàng loạt trên cùng một host** = nhiều khả năng CDN/WAF trả lời thay,
  request chưa từng tới origin. Vô giá trị.

Phân biệt bằng cách hỏi path không tồn tại — nếu nó cũng 403 thì là edge:

```bash
curl -sk -o /dev/null -w "%{http_code}\n" "https://<host>/zzz-khong-ton-tai-9931"
```

Đã gặp thật: `apps.discover.com` trả trang Akamai `errors.edgesuite.net` cho
mọi path. Lưu ý body các trang đó **không giống nhau từng byte** (Akamai echo
lại URL + reference nonce) nên dedup theo hash body không bắt được — phải nhìn
phân bố status. Danh sách host bị vậy có sẵn trong kết quả stage:

```bash
python3 -c "
import json; d=json.load(open('outputs/<domain>/logs/stages.json'))
st=d if isinstance(d,list) else d.get('stages',d)
for s in st:
    w=((s.get('extra') or {}).get('url_filter') or {}).get('waf_hosts')
    if w: print(s['stage'], '→ waf_hosts:', w)
"
```

## Phase 4 — tham số và form (ứng viên injection)

Gộp URL có tham số theo **tên tham số**, bỏ giá trị — `?id=1` và `?id=2` là
cùng một chỗ để test:

```bash
awk -F'?' 'NF>1 {split($2,a,"&"); s=""; for(i in a){split(a[i],b,"="); s=s b[1] ","} print $1" ["s"]"}' \
  processed/parameterized_urls.txt | sort -u | head -40
```

Form ghi dữ liệu (POST) đáng giá hơn GET nhiều — CSRF, mass assignment, auth
bypass:

```bash
jq -r '.forms[] | select(.method|ascii_upcase=="POST")
       | "\(.method) \(.action)  [\(.parameters|join(","))]"' processed/forms.json | sort -u | head -30
```

Tham số jsluice moi từ JS thường là tham số **không xuất hiện trong crawl** —
tức là đường đi ẩn:

```bash
jq -r '.[] | select(((.queryParams-["/"])|length)>0 or ((.bodyParams-["/"])|length)>0)
       | "\(.url)  q=\((.queryParams-["/"])|join(","))  b=\((.bodyParams-["/"])|join(","))"' \
  processed/jsluice_params.json | head -30
```

`- ["/"]` là bắt buộc: jsluice trả `queryParams: ["/"]` cho mọi route template
kiểu `/careers/job/:id?/` — đó là nhiễu parse, không phải tham số. Trên
acronis.com nó chiếm 278/302 mục; lọc xong còn 24 mục thật.

## Phase 5 — secret trong JS (triage, đừng báo cáo thô)

File nhỏ, đọc thẳng được:

```bash
jq -r '.findings[] | "\(.severity)\t\(.kind)\t\(.url)"' findings/jsluice_secrets.json | sort | uniq -c | sort -rn
```

**Phần lớn hit ở đây là false positive** và báo cáo thô sẽ mất uy tín:

- `gcpKey` dạng `AIzaSy…` trong JS client hầu như luôn là **key trình duyệt
  cố ý public** (Firebase/Maps). Nó chỉ thành finding khi **không bị giới hạn**
  referrer/API. Phải kiểm giới hạn, không phải kiểm sự tồn tại.
- Key lặp lại y hệt trên nhiều host thường là asset dùng chung của một bundle,
  không phải rò rỉ riêng của host nào.

Chỉ nâng lên báo cáo khi có **credential phía server** (khoá private, token
IAM, connection string DB) hoặc chứng minh được key không bị giới hạn.

## Phase 6 — kết quả trả về

`report/priority_targets.txt` đã xếp hạng sẵn theo heuristic — đọc để đối chiếu
(`stat -c%s` trước; thường ~20 KB), nhưng đừng chép lại. Giá trị của skill này
là những gì heuristic bỏ sót.

Trả về **danh sách xếp hạng, mỗi mục gồm**:

1. URL / endpoint cụ thể
2. Vì sao đáng soi — bằng chứng từ data, không phải phỏng đoán
3. Lệnh verify chạy được ngay (`curl -sk …`)
4. Điều gì sẽ chứng minh hoặc bác bỏ nó

Giới hạn ~15 mục. Danh sách 60 mục không ai soi hết, và độ dài không phải là
thước đo chất lượng ở đây.

Kèm một dòng cuối nói rõ **phần nào của bề mặt chưa được nhìn** (từ Phase 0, và
từ các cap `max_urls`/`max_per_host` trong `config.yml`) — người đọc cần biết
ranh giới giữa "đã kiểm, sạch" và "chưa kiểm".
