# recon2win — Thiết kế Báo cáo ASM (Attack Surface Management Report)

Spec cho bộ sinh báo cáo recon cấp doanh nghiệp: biến output thô thành **actionable
intelligence**. Không phải dump JSON, không phải liệt kê file.

Tài liệu này được viết **sau khi đã đọc thật** toàn bộ `outputs/` của 4 target
(acronis.com, discover.com, guildwars2.com, example.com — 795MB, 1,490 file). Mọi
con số, mọi ví dụ dưới đây đều lấy từ dữ liệu thật, không bịa.

---

## PHẦN A — MÔ HÌNH DỮ LIỆU (kết quả đọc output)

### A.1 Kho dữ liệu thực tế

| Target | Subdomain | Alive host | URL | Alive URL | JS | Forms | Secrets | Nuclei | Dung lượng |
|---|---|---|---|---|---|---|---|---|---|
| acronis.com | 1,689 | 574 | 25,645 | 18,722 | 3,956 | 109 | 9 (3 unique) | 4 medium | 126 MB |
| discover.com | — | 154 | — | — | — | 33 | 11 (3 unique) | — | 202 MB |
| guildwars2.com | 196 | 194 | 469,143 | 59,691 | 4,985 | — | 0 | 0 | 447 MB |
| example.com | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 68 KB (rỗng) |

### A.2 Entity model suy ra từ schema thật

Không giả định schema cố định — dưới đây là schema **quan sát được**:

```
PROJECT (không tồn tại trên đĩa — suy ra từ thư mục outputs/)
 └── TARGET                          outputs/<domain>/
      ├── run_meta                   report/summary.json → meta{}
      │     domain, scan_mode, scan_start, scan_end, scan_duration_seconds
      ├── STAGE[]                    logs/stages.json
      │     stage, status, input, outputs[], count, error, extra.elapsed_seconds
      ├── SUBDOMAIN[]                processed/subdomains.txt  (+ raw/subdomain/*.txt = nguồn)
      ├── DNS_RECORD[]               processed/resolved_detail.json
      │     subdomain, ip(csv), aaaa, cname, asn{}, resolver
      ├── HOST[]                     processed/alive_detail.json
      │     url, input, host, host_ip, a[], port, scheme, path, method,
      │     status_code, content_length, content_type, words, lines, time,
      │     webserver, tech[], cdn, cdn_name, cdn_type, failed,
      │     knowledgebase{PageType, pHash}, resolvers[], timestamp
      ├── URL[]                      processed/alive_urls_detail.json  ⚑ 18,722 record
      │     (CÙNG schema với HOST — đây là httpx chạy ở tầng URL)
      ├── JS_FILE[]                  processed/js_urls.txt + raw/jsluice/NNNN.js (bản tải về)
      ├── ENDPOINT[]                 processed/jsluice_endpoints.txt,
      │                              processed/xnlinkfinder_endpoints.txt
      ├── PARAM[]                    processed/jsluice_params.json
      │     url, method, queryParams[], bodyParams[]
      ├── FORM[]                     processed/forms.json  ⚑ ít ai dùng, giá trị rất cao
      │     url, action, method, enctype, parameters[]
      ├── FFUF_HIT[]                 raw/ffuf/<host>.json → results[]
      │     url, status, length, words, lines, redirectlocation, input{}
      ├── DIRSEARCH_HIT[]            processed/dirsearch_urls.txt
      ├── NUCLEI_FINDING[]           findings/{default,endpoints,dynamic}/nuclei.json
      │     template-id, template-url, info{name,severity,tags[],description,
      │     reference[],author[],metadata{}}, host, port, scheme, url,
      │     matched-at, ip, type, request ⚑, response ⚑, curl-command ⚑, timestamp
      ├── SECRET[]                   findings/jsluice_secrets.json
      │     kind, severity, url, data{}, context
      ├── DELTA                      report/delta.md + stages.json→scan_diff
      └── DERIVED                    report/priority_targets.txt, graph.mmd, INDEX.md
```

**Ba phát hiện về schema mà thiết kế phải tận dụng:**

1. **`alive_urls_detail.json` là mỏ vàng bị bỏ quên.** 18,722 record với ĐẦY ĐỦ
   `tech[]`, `status_code`, `content_type`, `content_length`, `webserver` — tức là ta
   có fingerprint công nghệ ở **tầng URL**, không chỉ tầng host. Report hiện tại chỉ
   dùng nó để đếm. Đây là dữ liệu để phát hiện "app nào chạy framework gì ở path nào".

2. **Nuclei finding chứa `request` + `response` + `curl-command` đầy đủ.** Không cần
   dựng lại evidence — PoC reproduce được ngay. Report phải nhúng nguyên văn.

3. **`forms.json` cho biết input surface thật.** 109 form trên acronis, trong đó 38
   POST và 18 form có field password. Đây là thứ arjun/jsluice không thấy được (chúng
   chỉ thấy GET param). Section riêng cho nó.

### A.3 Thông tin trùng lặp (phải khử khi báo cáo)

Kiểm chứng bằng `INDEX.md` + `modules/audit.py`:

```
all_urls.txt  ⊇  dynamic_urls.txt  ⊇  parameterized_urls.txt
all_urls.txt  ⊇  js_urls.txt, ffuf_urls.txt, jsluice_urls.txt
processed/alive_detail.json  ≡  summary.json.assets      (bản sao y nguyên)
processed/resolved_detail.json ≡ summary.json.dns_records (bản sao y nguyên)
findings/*/nuclei.json  ⊂  summary.json.nuclei
```

→ Report **không bao giờ** đếm hai lần. Mọi metric quy về `all_urls.txt` làm master,
các list khác chỉ là nhãn (label) gắn lên URL, không phải tập độc lập.

Trùng lặp ở tầng giá trị cũng phải khử:
- acronis: 9 secret findings → chỉ **3 GCP key duy nhất** (mỗi key lặp 3 lần vì cùng
  bundle JS được serve trên nhiều host). Báo "9 secrets" là thổi phồng 3×.
- discover: 11 findings → **3 key duy nhất** (3.7×).
- `expenses.acronis.com/./Login.aspx` và `/Frames/Login.aspx/./Login.aspx` là **cùng
  một trang login**, đếm 2 lần vì không normalize `/./`.

---

## PHẦN B — 4 KHIẾM KHUYẾT PHÁT HIỆN ĐƯỢC (nền tảng cho methodology mới)

Đây là kết quả đối chiếu `report/priority_targets.txt` với dữ liệu gốc. Cả 4 đều
kiểm chứng được, và cả 4 đều định hình phần scoring v2.

### B.1 ⛔ False positive hàng loạt do blanket-deny

`web-api-arp.acronis.com`: **4,099 ffuf hit, trong đó 4,097 hit trả về y hệt nhau**
(`status=403, words=20, length≈280-289`) = 100%.

```
403 279 20  https://web-api-arp.acronis.com/.git
403 286 20  https://web-api-arp.acronis.com/.git/config
403 285 20  https://web-api-arp.acronis.com/.git/index
403 287 20  https://web-api-arp.acronis.com/.git_release
403 289 20  https://web-api-arp.acronis.com/.gitattributes
```

Đây là **WAF chặn đều mọi thứ**, không phải `.git` bị lộ. Nhưng
`priority_targets.txt` chấm `https://web-api-arp.acronis.com/.git/config` **770 điểm**
với lý do `ffuf hit; git dir; config`. Comment trong `modules/priority.py` ghi
*"ffuf auto-calibrated, so soft-404s are already gone"* — **không đúng với host này**.

Hệ quả còn nặng hơn tưởng — đã đo lại trên `alive_urls.txt`:

```
web-api-arp.acronis.com  =  4,096 / 18,722 alive URL  =  21.9%
                            → host đứng THỨ HAI toàn bản quét về số URL
```

Tức là **gần 1/4 "URL sống" của acronis.com là rác blanket-deny**. Chúng đã đi qua
httpx (tốn 4,096 request), được đếm vào `alive_urls`, vào `url_surface.by_status`
(chính là phần lớn con số `403: 4,128`), và vào mọi metric phía sau. Đồng thời chiếm
98% của `ffuf_urls.txt` (4,189).

→ **Bắt buộc có bước response-similarity clustering** trước khi chấm điểm — và nên
đặt ngay sau ffuf, trước httpx_urls, để tiết kiệm luôn 4,096 request vô ích.

### B.2 ⛔ Scope bleed

Trong `priority_targets.txt` của acronis.com có host **ngoài scope**:

```
elearning.unyp.cz          ← trường đại học Séc, không liên quan
www.google.com
cdn.managed-protection.com
acronis.events             ← khác TLD, cần xác nhận có trong scope không
```

`elearning.unyp.cz/login/index.php` được chấm 620 điểm. Báo cáo giao cho khách hàng
mà chứa asset của bên thứ ba là **rủi ro pháp lý**, không chỉ là nhiễu.

→ Report phải có **scope gate** cứng + section "Out-of-scope observed" riêng.

### B.3 ⛔ Keyword đụng tên sản phẩm → nhiễu áp đảo

`_PATH_HINTS` chấm `backup` = 300 điểm. Nhưng **Acronis là hãng phần mềm backup** —
từ "backup" xuất hiện trong mọi URL tài liệu. Kết quả: hơn 20 dòng
`care.acronis.com/s/article/...?language=en_US` chiếm hạng 600, đè bẹp
finding thật.

```
[600] .../article/71559-Acronis-Cyber-Protect-Cloud-Backup-for-Synology-NAS?language=en_US — parameterized; backup
[600] .../article/7188-Acronis-Backup-Recovery-10-Backup-Plans-and-Backup-Policies?language=en_US — parameterized; backup
   … (còn ~18 dòng tương tự)
```

Trong khi đó finding nuclei thật (`Salesforce Community Misconfiguration`) cũng chỉ
được 800 — chênh có 200 điểm so với một bài KB article.

→ Cần **IDF weighting**: từ khoá xuất hiện ở >5% corpus thì mất gần hết trọng số.

### B.4 ⚠️ Stage hỏng không hiện lên báo cáo

`logs/stages.json` của acronis:

```
dirsearch        success  n=318    t=4484s  err="timeout after 4484s — salvaged 318 partial"
arjun            failed   n=0      t=3601s  err="timeout after 1s"
nuclei_default   success  n=4      t=14331s
nuclei_endpoints success  n=2      t=14210s err="8/8 batches run, continued past timed-out"
```

`arjun` **failed** → 0 param được phát hiện chủ động. `dirsearch` timeout, chỉ cứu
được một phần. Nhưng `summary.json.counts` vẫn báo `arjun_params: 0` như một con số
bình thường — người đọc không phân biệt được **"quét rồi, không có gì"** với
**"chưa quét được"**.

Chú ý cả nghịch lý `elapsed=3601s` nhưng `error="timeout after 1s"` — thông điệp lỗi
sai đơn vị, đáng mở issue riêng.

→ Mọi metric trong báo cáo phải mang **confidence** dựa trên sức khoẻ stage sinh ra nó.

---

## PHẦN C — CẤU TRÚC BÁO CÁO (Deliverable 1)

Ba lớp, đọc từ trên xuống theo thời gian người đọc có:

```
LỚP 1 — 60 GIÂY  (giám đốc / trưởng nhóm)
  0. Cover + Scan Provenance & Confidence      ⚑ MỚI — chặn hiểu nhầm
  1. Executive Summary
  2. Attack Surface at a Glance                 (1 trang số liệu + 3 chart)

LỚP 2 — 30 PHÚT  (pentester / bug hunter — phần chính)
  3. Top 20 Manual Testing Targets              ⚑ TRANG QUAN TRỌNG NHẤT
  4. Findings — Confirmed (nuclei + evidence)
  5. Secret Exposure Analysis
  6. High-Value Asset Inventory
  7. Authentication & Input Surface (forms)     ⚑ MỚI — từ forms.json
  8. API & Endpoint Intelligence
  9. JavaScript Analysis
 10. Attack Paths & Correlation Chains          ⚑ MỚI — chuỗi tấn công
 11. Pentest Intelligence (gợi ý test thủ công)
 12. Anomalies & Data-Quality Warnings          ⚑ MỚI — B.1→B.4

LỚP 3 — THAM CHIẾU  (tra cứu, không đọc tuần tự)
 13. Full Asset Inventory
 14. Technology Distribution & Risk
 15. DNS Analysis
 16. Infrastructure & Cloud Footprint
 17. WAF / CDN / Bot-Protection Map             ⚑ suy ra từ tech[]
 18. HTTP Response Analysis
 19. Content Discovery Results
 20. Historical Changes & Attack Surface Growth
 21. Asset Timeline
 22. Recommendations (kỹ thuật + quy trình)
 23. Out-of-Scope Observed                      ⚑ MỚI — B.2
 24. Appendix A–H
```

### Section không sinh được — và lý do

| Section | Vì sao không có | Cần gì để bật |
|---|---|---|
| **TLS Analysis** | Không có stage nào thu TLS. `alive_detail.json` không có field tls | thêm `tlsx` |
| **Certificate Inventory** | Như trên. Mất luôn nguồn subdomain từ SAN | `tlsx -san -cn` |
| **Screenshot Gallery** | Không có stage chụp ảnh. (`knowledgebase.pHash` có sẵn ⇒ httpx đã sẵn sàng) | `httpx -screenshot` |
| **Port / Protocol** | httpx chỉ chạm 80/443. Field `port` luôn là 443 hoặc 80 | `naabu` |
| **HTTP Headers** | Không lưu header. Chỉ có `webserver` + `content_type` | `httpx -irh` |
| **Redirect Chains** | Không lưu chain. ffuf có `redirectlocation` nhưng chỉ 1 bước | `httpx -location -chain` |
| **CVE Mapping** | `tech[]` phần lớn không có version ("Nginx" chứ không "Nginx 1.18.0") | `httpx -tech-detect` + CPE map |

Báo cáo **in các section này ra kèm lý do**, không ẩn đi. Người đọc cần biết vùng nào
chưa được soi — vùng chưa soi ≠ vùng an toàn.

---

## PHẦN D — MÔ TẢ TỪNG SECTION (Deliverable 2)

Mỗi section theo khuôn: **Mục đích · Nguồn · Tương quan · Layout · Bảng · Metric ·
Ưu tiên · Khuyến nghị**.

---

### §0. Scan Provenance & Confidence ⚑

**Mục đích** — Trả lời câu hỏi phải hỏi trước tiên: *kết quả này tin được bao nhiêu
phần?* Đặt trước Executive Summary vì mọi con số phía sau phụ thuộc vào nó.

**Nguồn** `logs/stages.json`, `summary.json.meta`, `missing_tools`, `tool_versions`

**Tương quan** — map từng stage → các metric mà nó nuôi. Stage hỏng ⇒ metric hạ
confidence và bị đánh dấu ⚠ tại **mọi nơi nó xuất hiện**, không chỉ ở đây.

**Layout**

```
┌──────────────────────────────────────────────────────────────────────────┐
│  ĐỘ TIN CẬY BẢN QUÉT: 72/100   ⚠ TỪNG PHẦN                              │
│  acronis.com · active · 2026-07-25 14:38 → 20:31 (5h 53m)                │
├──────────────────────────────────────────────────────────────────────────┤
│  ✓ 24/26 stage thành công     ⚠ 1 timeout cứu được một phần   ✗ 1 lỗi   │
│                                                                          │
│  ✗ arjun            LỖI — timeout 3601s      → 0 param chủ động          │
│      ẢNH HƯỞNG: "Injection candidates" chỉ dựa trên param bị động       │
│      (jsluice/crawl). Vùng param thực tế RỘNG HƠN báo cáo này.          │
│                                                                          │
│  ⚠ dirsearch        TIMEOUT 4484s — cứu 318/? kết quả                    │
│      ẢNH HƯỞNG: Content discovery KHÔNG đầy đủ. Không kết luận          │
│      "không có path ẩn".                                                 │
│                                                                          │
│  ⚠ nuclei_endpoints chạy quá timeout, 8/8 batch                          │
│  ⚠ raw/subdomain/amass.txt, chaos.txt = 0 dòng (tool skip/thiếu key)     │
├──────────────────────────────────────────────────────────────────────────┤
│  ĐỘ TIN CẬY THEO VÙNG                                                    │
│  Subdomain enum   ███████░░░  70%  amass+chaos rỗng, chỉ subfinder       │
│  DNS              ██████████ 100%                                        │
│  Host probing     ██████████ 100%                                        │
│  Content disc.    ████░░░░░░  40%  dirsearch timeout, gau/urlfinder rỗng │
│  Param discovery  ██░░░░░░░░  20%  arjun LỖI                             │
│  JS analysis      █████████░  90%                                        │
│  Vuln scanning    ███████░░░  70%  nuclei quá timeout                    │
└──────────────────────────────────────────────────────────────────────────┘
```

**Metric** — confidence tổng, confidence từng vùng, số stage lỗi, tool thiếu, thời
lượng theo stage.

**Khuyến nghị** — mỗi stage hỏng kèm cách khắc phục cụ thể (tăng timeout, cấp API key
cho chaos, chia nhỏ target list).

---

### §1. Executive Summary

**Mục đích** — Người không đọc gì khác vẫn nắm đúng tình hình. Văn xuôi, không bullet
rời rạc. Không thuật ngữ nếu tránh được.

**Nguồn** — tổng hợp mọi section, nhưng **chỉ lấy thứ đã qua kiểm chứng**.

**Tương quan** — chọn ra 3 điều quan trọng nhất theo công thức:
`impact × confidence × exploitability`, không phải theo severity nuclei thuần.

**Layout** — xem Deliverable 9 (§L) cho bản mẫu đầy đủ.

**Metric hiển thị** — 6 ô: Assets / Alive / Findings theo severity / Secrets duy nhất
/ High-value targets / Confidence.

---

### §2. Attack Surface at a Glance

**Mục đích** — Một trang, hiểu ngay hình dạng bề mặt tấn công.

**Nguồn** `alive_detail.json`, `alive_urls_detail.json`, `summary.json.url_surface`

**Tương quan** — phễu thu hẹp, mỗi bậc là một phép join thật:

```
1,689 subdomain
   │ dnsx resolve
1,689 resolved (100%)
   │ httpx probe
  574 alive host (34%)          ← 1,115 phân giải được nhưng không có HTTP
   │ content discovery
25,645 URL
   │ httpx probe URL
18,722 alive URL (73%)
   │ lọc theo tín hiệu
  581 parameterized · 3,956 JS · 109 form · 204 priority target
   │ verify
    4 nuclei finding · 3 secret duy nhất
```

**Bảng** — phân bố status, phân bố content-type, top 10 công nghệ, phân bố CDN.

**Metric** — tỉ lệ alive, mật độ URL/host, tỉ lệ auth-gated (401/403 ÷ tổng),
tỉ lệ API (JSON content-type ÷ tổng).

**Bất thường cần nêu ngay:**
- acronis: `403 = 129 host (22%)` — tập auth-gated lớn bất thường, đáng đào.
- guildwars2: `404 = 143/194 host (74%)` — **phần lớn "alive host" thực ra là 404**.
  Wildcard DNS hoặc catch-all. Con số "194 alive" là **ảo**, thực chất ~30 host có nội dung.
- discover: `503 = 10 host` — rate-limit/WAF đang chặn, quét chưa đủ sâu.

---

### §3. Top 20 Manual Testing Targets ⚑ TRANG QUAN TRỌNG NHẤT

**Mục đích** — Nếu người đọc chỉ có 1 trang, đây là trang đó. 20 URL, kèm **lý do
tại sao** và **test gì trước**.

**Nguồn** — scoring v2 (§F) trên mọi tín hiệu.

**Tương quan** — mỗi dòng phải là **giao của ≥2 tín hiệu độc lập**. Một tín hiệu đơn
lẻ không đủ để vào top 20 — chính đây là chỗ chặn nhiễu kiểu B.3.

**Layout** — card, không phải bảng. Mỗi card đủ để bắt tay test ngay:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ #1   ĐIỂM 940   ⬤ CAO    XÁC NHẬN                                       │
│ https://care.acronis.com/s/sfsites/aura                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ VÌ SAO                                                                  │
│  • nuclei medium — Salesforce Community Misconfiguration (đã verify)    │
│  • Salesforce Aura endpoint → truy vấn được object không cần auth      │
│  • care.acronis.com = portal khách hàng ⇒ chứa dữ liệu khách hàng      │
│  • Host trả 200, không CDN, không thấy bot-protection                  │
│                                                                         │
│ TƯƠNG QUAN                                                              │
│  host care.acronis.com → 47 URL alive → 12 bài KB có param             │
│  → cùng host với 1 form POST (submit-ticket, 14 field, có csrf)        │
│                                                                         │
│ TEST TRƯỚC                                                              │
│  1. Liệt kê object qua Aura: getConfigData / ApexAction                │
│  2. Kiểm tra guest user đọc được Contact / Case / Account không        │
│  3. Nếu có → IDOR trên recordId                                         │
│                                                                         │
│ REPRODUCE   (curl-command lấy nguyên từ nuclei.json)                    │
│  curl -X POST 'https://care.acronis.com/s/sfsites/aura' \              │
│    -H 'Content-Type: application/x-www-form-urlencoded' -d '…'         │
│                                                                         │
│ EVIDENCE  findings/default/nuclei.json#0 — có đủ request + response     │
└─────────────────────────────────────────────────────────────────────────┘
```

**Ưu tiên** — sắp theo score v2; hiển thị cả badge `XÁC NHẬN` / `SUY LUẬN` /
`CẦN KIỂM CHỨNG` để người đọc biết chỗ nào đã chắc.

---

### §4. Findings — Confirmed

**Mục đích** — Chỉ những gì scanner **đã xác nhận**. Không suy đoán.

**Nguồn** `findings/{default,endpoints,dynamic}/nuclei.json`

**Tương quan** — mỗi finding được làm giàu thêm bằng host context: host này còn bao
nhiêu URL, có form không, tech gì, đứng sau CDN nào, có bot-protection không. Một
finding trên host có 500 URL nghiêm trọng hơn cùng finding trên host tĩnh 1 trang.

**Khử trùng lặp bắt buộc** — acronis có 4 finding thô nhưng thực chất là **2 lớp**:

```
Salesforce Community Misconfiguration   care.acronis.com          1 host
Compressed Backup File - Detect          dl / dl5 / dl6.acronis.com  3 host, cùng /test.zip
```

→ Trình bày theo **lớp vấn đề (issue class)**, host là danh sách bên trong. Không
liệt 4 dòng rời.

**Bảng**

| Template | Severity | Hosts | Bằng chứng | Trạng thái |
|---|---|---|---|---|
| salesforce-community-misconfig | medium | 1 | req+resp | Cần verify tay |
| detect-compressed-backup-file | medium | 3 | req+resp | Cần verify tay |

**Metric** — số finding theo severity, số host bị ảnh hưởng, số issue class,
tỉ lệ trùng (4 finding / 2 class = 2.0×).

**Ghi chú bắt buộc về `/test.zip`** — 3 host `dl*.acronis.com` cùng lộ `test.zip`.
Trước khi báo cáo phải kiểm tra kích thước và nội dung: nếu là file test rỗng của CDN
thì đây là **false positive**, nếu là backup thật thì đây là finding nặng nhất bản
quét. Report in kèm cột "cần xác minh nội dung".

---

### §5. Secret Exposure Analysis

**Mục đích** — Đánh giá đúng mức key bị lộ trong JS. Chống cả thổi phồng lẫn xem nhẹ.

**Nguồn** `findings/jsluice_secrets.json` ⋈ `js_urls.txt` ⋈ `alive_detail.json`

**Tương quan** — 3 bước, đây là chỗ dễ báo cáo sai nhất:

```
1. KHỬ TRÙNG theo giá trị key
   acronis  9 finding → 3 key duy nhất  (1 key nằm trên 3 host)
   discover 11 finding → 3 key duy nhất
2. TÍNH LAN TOẢ  key → file JS → host serve file đó
   AIzaSyBjxiXjlbfwB6XYedcmed29xNKQlQPbIAM
     └ c-core-essentials-CYZByQwG.js
        ├ www.acronis.com
        └ academy.acronis.com
3. ĐÁNH GIÁ KHẢ NĂNG KHAI THÁC theo loại key  ← quyết định severity thật
```

**Bảng phán định (quan trọng — quyết định đúng/sai của cả section)**

| Loại | Số | Mặc định | Đánh giá thật | Cách kiểm chứng |
|---|---|---|---|---|
| `gcpKey` (AIza…) | 3 unique | low | **Chưa xác định — phụ thuộc restriction** | Gọi thử Maps/Firebase API; kiểm HTTP-referrer restriction |

**Điểm mấu chốt:** GCP browser key **nằm trong JS là bình thường và đúng thiết kế**.
Nó chỉ thành lỗ hổng khi *không cấu hình restriction*. Báo "9 secrets exposed" là
**sai hai lần**: sai số lượng (thực 3) và sai bản chất (chưa chứng minh khai thác được).

Report vì vậy in đúng:
> *3 GCP API key duy nhất tìm thấy trong JS bundle (9 lần xuất hiện trên nhiều host).
> Đây là browser key, việc nằm trong client-side JS là hợp lệ. **Rủi ro phụ thuộc
> hoàn toàn vào API restriction** — cần kiểm chứng thủ công bằng cách gọi API từ
> referrer lạ. Chưa xác nhận là lỗ hổng.*

**Metric** — key duy nhất, số lần xuất hiện, tỉ lệ trùng, số host lan toả,
số key đã kiểm chứng restriction (khởi điểm 0).

---

### §6. High-Value Asset Inventory

**Mục đích** — Trong 574 host, đâu là ~30 host đáng bỏ thời gian.

**Nguồn** `alive.txt` ⋈ `alive_detail.json` ⋈ `forms.json` ⋈ endpoints ⋈ nuclei

**Tương quan** — phân loại theo pattern hostname **và** xác nhận bằng bằng chứng
hành vi (status, tech, form, endpoint). Chỉ pattern hostname là không đủ.

**Kết quả thật (đã chạy phân loại trên dữ liệu):**

| Nhóm | acronis | discover | guildwars2 | Vì sao đáng chú ý |
|---|---|---|---|---|
| dev / staging / beta / uat | **23** | **43** | 12 | Ít bị vá, hay bật debug, dữ liệu prod |
| storage / backup / upload / s3 | 56 | 2 | 6 | Bucket cấu hình sai, path traversal |
| api / gateway / graphql | 11 | 3 | 11 | Auth yếu, IDOR, mass assignment |
| internal / vpn / corp | **7** | 0 | **2** | Lộ ra Internet là bất thường |
| infra panel (kibana/gitlab/portal) | 6 | 7 | 3 | Default cred, dashboard mở |
| admin | 2 | 0 | 1 | Bề mặt nhạy cảm nhất |
| auth / login / sso | 3 | 10 | 3 | Brute-force, OAuth flaw |
| mail / smtp | 8 | 0 | 14 | SPF/DMARC, spoofing |

**Asset cần soi tay ngay (rút ra từ dữ liệu thật):**

```
⬤ CAO   us-kibana.acronis.com          Kibana ra Internet → thường không auth,
                                        đọc được log ⇒ rò rỉ dữ liệu
⬤ CAO   gitlab.api.guildwars2.com      GitLab công khai → kiểm project public,
                                        đăng ký mở, CVE theo version
⬤ CAO   internal.api.guildwars2.com    Tên tự nói lên: "internal" mà truy cập
                                        được từ ngoài
⬤ CAO   securedocupload.discover.com   Upload tài liệu ở TỔ CHỨC TÀI CHÍNH
   +     custserv.securedocupload…      ⇒ unrestricted upload, path traversal,
                                        IDOR trên doc ID
⬤ CAO   admin.acronis.com              admin panel
   +     admin2.acronis.com             ⚑ có "admin2" ⇒ khả năng bản cũ chưa gỡ
⬤ TB    bg-vpn / jp-vpn / provisioning-vpn.acronis.com   4 VPN endpoint lộ ra
                                        ⇒ CVE thiết bị VPN, user enum
⬤ TB    portal.ai.acronis.com          Sản phẩm AI mới ⇒ code non, prompt injection
⬤ TB    expenses.acronis.com           ASP.NET WebForms + __VIEWSTATE
                                        ⇒ ViewState deserialization (xem §11)
⬤ TB    proctor.acronis.com            Django (csrfmiddlewaretoken) + login form
```

**Layout** — card theo nhóm, sắp theo score; mỗi card có mini-inventory (bao nhiêu
URL, form, endpoint, JS, finding) để thấy ngay "độ lớn" của asset.

---

### §7. Authentication & Input Surface ⚑ SECTION MỚI

**Mục đích** — `forms.json` đang bị bỏ phí. Đây là **input surface thật** — nơi thực
sự nhận dữ liệu người dùng, không phải URL đoán ra.

**Nguồn** `processed/forms.json` ⋈ `alive_detail.json` (tech) ⋈ `alive_urls_detail.json`

**Tương quan** — form → host → tech stack ⇒ suy ra loại lỗ hổng ứng với framework.

**Số liệu thật**

| | acronis | discover |
|---|---|---|
| Tổng form | 109 | 33 |
| POST | 38 | 21 |
| Có field password | **18** | **12** |
| multipart (upload) | 0 | 0 |

**Bảng phân tích (rút từ tên field — suy ra framework):**

| Framework | Dấu vết | Số form | Hướng test |
|---|---|---|---|
| ASP.NET WebForms | `__VIEWSTATE`, `__VIEWSTATEGENERATOR` | 22 | **ViewState deserialization** (MS14-059 / ysoserial.net), kiểm MAC |
| ASP.NET MVC | `__RequestVerificationToken` | 20 | CSRF token có validate không |
| Django | `csrfmiddlewaretoken` | 8 | CSRF, user enum qua login |
| Drupal | `form_build_id`, `form_id` | 16 (discover) | Drupalgeddon, form cache poisoning |
| Không rõ | `__SYS_VARIABLES` | 20 | Framework nội bộ ⇒ nghiên cứu riêng |

**Phát hiện đáng giá nhất section này:**

```
expenses.acronis.com/Login.aspx
  → ASP.NET WebForms, 19 field, có __VIEWSTATE
  → ViewState deserialization là đường RCE kinh điển
  → Ưu tiên: kiểm ViewStateUserKey và MAC validation
  ⚠ Xuất hiện 2 lần trong priority list do path /./ chưa normalize (xem B/A.3)

portal.discover.com/customersvcs/universalLogin/signin
  → 2 biến thể form khác nhau CÙNG endpoint (userID vs UserID)
  → 2 luồng đăng nhập ⇒ luồng cũ có thể thiếu rate-limit / kiểm soát mới
  → Đây là tổ chức TÀI CHÍNH ⇒ ưu tiên cao nhất về mặt tác động
```

**Metric** — form theo method, số form có password, số framework khác nhau,
số host có auth, form không có CSRF token.

**Khuyến nghị** — form login nào không thấy token chống CSRF thì liệt riêng để test
rate-limit và credential stuffing.

---

### §8. API & Endpoint Intelligence

**Mục đích** — Bề mặt API là nơi bug bounty ăn tiền nhất. Phải dựng lại nó cho có tổ chức.

**Nguồn** `jsluice_endpoints.txt`, `xnlinkfinder_endpoints.txt`, `jsluice_params.json`,
`alive_urls_detail.json` (lọc `content_type` chứa json), apidocs

**Tương quan** — nhóm endpoint thành **cây theo path segment**, rồi map ngược lại
file JS nguồn và host phục vụ.

**Số liệu thật (grep trên endpoint đã trích):**

| Pattern | acronis | discover | guildwars2 | Ý nghĩa |
|---|---|---|---|---|
| `/v1/` | **133** | 29 | 0 | API versioned — thử `/v0/`, `/v2/` xem có bản cũ |
| `/v2/`…`/v5/` | 55 | 4 | 2 | **Tồn tại v1→v5 ⇒ version cũ có thể còn sống, thiếu vá** |
| `/admin` | **13** | 0 | 0 | Route admin trong JS ⇒ có thể chưa bảo vệ server-side |
| `/upload` | **9** | 2 | 0 | Unrestricted upload |
| `graphql` | **7** | 0 | 0 | Introspection, batching, depth attack |
| `/oauth` | 9 | 7 | 1 | Redirect_uri, state, PKCE |
| `/token` | 7 | 5 | 0 | Rò rỉ token, thuật toán yếu |
| `/jwt` | **2** | 0 | 0 | alg=none, key confusion |
| `/debug` | **2** | 0 | 0 | Endpoint debug lọt production |
| `/health` | 2 | 1 | 0 | Thường lộ version, dependency |

**Cách đọc quan trọng:** `/admin` xuất hiện **13 lần trong JS** nhưng chỉ có **2 host
tên admin**. Nghĩa là route admin nằm **bên trong ứng dụng thường**, không ở subdomain
riêng — đây chính là loại **hidden endpoint** đáng thử nhất, vì bảo vệ hay được cài
ở tầng UI thay vì tầng API.

**Bảng cây API**

```
/api
├── /v1  (133 endpoint)   ← bề mặt chính
│   ├── /idp/v1/authorize     OAuth — cloud + beta-cloud
│   ├── /branding/v1/static   backup.acronis.com
│   └── …
├── /v2  (34)
├── /v3  (10)   ⚑ tồn tại song song ⇒ so sánh auth giữa các version
├── /v4  (10)
└── /v5  (1)
```

**Khuyến nghị test** — với mỗi endpoint tìm được ở v1, thử luôn ở v0/v2/v3. **Bỏ sót
kiểm soát giữa các version API là lỗi phổ biến bậc nhất** và tự động hoá được ngay từ
danh sách này.

---

### §9. JavaScript Analysis

**Mục đích** — JS là nơi lộ endpoint, key, và logic phía sau.

**Nguồn** `js_urls.txt`, `raw/jsluice/NNNN.js` (đã tải về, phân tích lại được),
`jsluice_endpoints.txt`, `jsluice_params.json`, `jsluice_secrets.json`

**Tương quan** — xếp hạng file JS theo **giá trị**, không theo kích thước:

```
score(js) = endpoint_trích_được × 3
          + secret_tìm_thấy × 50
          + (1 nếu là bundle riêng của app, 0 nếu là thư viện bên thứ ba) × 20
          + host_serve_file_này × 2
```

**Bảng**

| File JS | KB | Endpoint | Secret | Host dùng | Ghi chú |
|---|---|---|---|---|---|
| `c-core-essentials-CYZByQwG.js` | ? | ? | 2 | 2+ | chứa GCP key, dùng chung nhiều host |
| `raw/jsluice/0017.js` | 4,940 | — | — | — | bundle lớn nhất ⇒ nhiều logic nhất |
| `raw/jsluice/0001.js` | 4,684 | — | — | — | |

**Bất thường phải nêu (đo thật):** acronis tải về **500 file JS**, trong đó **147 file
là bản trùng** (36 nhóm cùng kích thước byte — 0002↔0041↔0050 cùng 264,031 byte;
0004↔0032; 0005↔0033…). Tức **29% file JS đã tải là bản sao**, do cùng một bundle
được serve trên nhiều host.

⇒ **Dedup theo hash nội dung trước khi thống kê.** Nếu không, "độ nặng JS" bị thổi
phồng ~1.4×, và mỗi secret trong một bundle dùng chung sẽ bị đếm lại đúng bằng số
host serve nó — đây chính là gốc của tỉ lệ thổi phồng 3.0× ở §5.

**Khuyến nghị** — với mỗi bundle app-specific: bỏ minify, tìm chuỗi
`admin|internal|debug|token|secret|api_key`, so sánh route trong JS với route thực sự
được bảo vệ ở server.

---

### §10. Attack Paths & Correlation Chains ⚑ SECTION MỚI

**Mục đích** — Đây là thứ phân biệt **báo cáo ASM** với **bản dump recon**. Không liệt
kê asset — dựng **chuỗi** từ tài sản đến rủi ro.

**Nguồn** — join qua mọi entity.

**Logic tương quan** — 6 mẫu chuỗi được dò tự động:

```
CHUỖI 1 — JS → Endpoint → Không auth
  file JS  →  endpoint trích được  →  endpoint đó có trong alive_urls (200)
          →  content_type = json  →  không có dấu hiệu auth (không 401/403)
  ⇒ API không cần xác thực, phát hiện từ client-side code

CHUỖI 2 — Dev/Staging → Cùng app với Prod
  host khớp dev|staging|uat  →  tech[] giống host prod
                             →  chung endpoint pattern
  ⇒ Bản kém bảo vệ hơn của cùng ứng dụng
  THẬT: discover.com có 43 host dev/staging — nhóm lớn nhất trên mọi target

CHUỖI 3 — Form → Framework → Lỗ hổng đã biết
  form có __VIEWSTATE  →  ASP.NET WebForms  →  ViewState deserialization
  THẬT: expenses.acronis.com

CHUỖI 4 — Versioned API → Version cũ còn sống
  tồn tại /v1..../v5  →  thử v(n-1) trên endpoint chỉ thấy ở v(n)
  ⇒ Kiểm soát bị bỏ sót giữa các version
  THẬT: acronis có đủ v1→v5

CHUỖI 5 — OAuth flow → redirect_uri
  endpoint /authorize có param redirect_uri  →  redirect_uri trỏ sang HOST KHÁC
  ⇒ Kiểm chứng validate redirect_uri
  THẬT:  cloud.acronis.com/api/idp/v1/authorize
           ?redirect_uri=https://partner.acronis.com/acls/oauth/callback
         beta-cloud.acronis.com/api/idp/v1/authorize
           ?redirect_uri=https://uat-partner.acronis.com/…
  ⚑ IdP prod và beta dùng CHUNG mô hình redirect sang partner/uat-partner
    ⇒ nếu whitelist theo wildcard *.acronis.com thì chiếm được 1 subdomain
      là chiếm được token

CHUỖI 6 — Storage → Bucket cấu hình sai
  host khớp s3|storage|backup|files  →  tech chứa Amazon S3
  THẬT: acronis có 36 host tech "Amazon S3" + 56 host tên storage-like
```

**Layout** — sơ đồ chuỗi + bảng "chuỗi đã dò được", mỗi chuỗi kèm độ tin cậy và bước
kiểm chứng tiếp theo.

```
CHUỖI 5 — OAuth redirect_uri  ⬤ CAO  ĐỘ TIN 80%
┌──────────────┐   ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐
│ cloud.acronis│──▶│ /api/idp/v1 │──▶│ redirect_uri │──▶│ partner.acronis │
│   .com (IdP) │   │ /authorize  │   │  = host khác │   │  .com/callback  │
└──────────────┘   └─────────────┘   └──────────────┘   └─────────────────┘
                                            │
                                            ▼  CÙNG MẪU trên beta-cloud → uat-partner
                                    Test: redirect_uri=https://evil.acronis.com
                                          redirect_uri=https://partner.acronis.com.evil.com
                                          redirect_uri=//evil.com
```

---

### §11. Pentest Intelligence

**Mục đích** — Nối công nghệ quan sát được sang hướng test cụ thể. **Không tuyên bố có
lỗ hổng** — chỉ nói nên thử gì và vì sao dữ liệu gợi ý điều đó.

**Nguồn** `tech[]`, `webserver`, `forms.json`, endpoint patterns

**Tương quan** — bảng tra: bằng chứng quan sát → lớp lỗ hổng → mức ưu tiên.

| Lớp lỗ hổng | Bằng chứng quan sát được | Target | Ưu tiên |
|---|---|---|---|
| **Deserialization** | `__VIEWSTATE` trên 22 form ASP.NET WebForms | expenses.acronis.com | ⬤ CAO |
| **OAuth / redirect_uri** | 2 endpoint `/api/idp/v1/authorize` có redirect sang host khác | cloud, beta-cloud | ⬤ CAO |
| **IDOR** | 133 endpoint `/v1/`, có `recordId`/`userId` trong param | acronis API | ⬤ CAO |
| **File Upload** | 9 endpoint `/upload`; host `securedocupload.discover.com` | discover, acronis | ⬤ CAO |
| **GraphQL** | 7 dấu vết graphql trong JS | acronis | ⬤ CAO |
| **SSRF** | param `url=`, `curl=`, `uri=`, `redirect=` trong URL developer.acronis.com | developer.acronis.com | ⬤ TB |
| **Open Redirect** | param `redirect`, `next`, `returnUrl`, `retpath`, `goto`, `continue` | nhiều | ⬤ TB |
| **JWT** | 2 endpoint `/jwt`, 7 `/token` | acronis | ⬤ TB |
| **CORS** | 11 host API + Vue.js SPA (34 host) ⇒ chắc chắn có CORS policy | acronis | ⬤ TB |
| **Prototype Pollution** | Vue.js trên 34 host, bundle JS lớn | acronis | ⬤ TB |
| **SQLi / NoSQLi** | 581 parameterized URL | acronis | ⬤ TB (⚠ arjun lỗi ⇒ chưa đủ) |
| **SSTI** | Django (8 form) + Drupal (16 form) | proctor, developer.discover | ⬤ THẤP |
| **XXE** | `content_type: application/xml` trên host s3gw | acronis | ⬤ THẤP |
| **CSP** | Chưa đánh giá được — **không thu header** | — | ⚠ chặn |
| **RCE** | Không có bằng chứng trực tiếp; đi qua deserialization/upload | — | gián tiếp |

**Nguyên tắc trình bày** — mỗi dòng ghi rõ `Bằng chứng · Giả thuyết · Cách kiểm chứng
· Điều gì chứng minh giả thuyết SAI`. Có cột cuối để tránh confirmation bias.

---

### §12. Anomalies & Data-Quality Warnings ⚑ SECTION MỚI

**Mục đích** — Nêu thẳng chỗ dữ liệu không đáng tin. Báo cáo giấu điểm yếu của chính
nó là báo cáo không dùng được.

Nội dung = B.1→B.4 đã trình bày, tự sinh bằng các kiểm tra:

| Kiểm tra | Ngưỡng | Kết quả thật |
|---|---|---|
| Blanket-deny cluster | >50% hit của 1 host giống hệt (status+words) | ⛔ web-api-arp: 4,097/4,099 (100%) |
| Scope bleed | host không khớp scope | ⛔ 4 host: elearning.unyp.cz, www.google.com, cdn.managed-protection.com, acronis.events |
| Keyword lạm phát | 1 keyword khớp >5% corpus | ⛔ "backup" trên acronis |
| Stage lỗi | status != success | ⛔ arjun failed; dirsearch timeout |
| Alive giả | >60% host trả 404 | ⛔ guildwars2: 143/194 (74%) |
| Secret trùng | finding ÷ giá trị duy nhất > 2 | ⚠ acronis 3.0×, discover 3.7× |
| Trùng file JS | cùng byte size | ⚠ hàng chục cặp trùng |
| Zero-finding nghi ngờ | 0 finding + có stage lỗi | ⚠ guildwars2: 0 finding — cần kiểm nuclei có chạy thật |

---

### §13–21. Các section tham chiếu (tóm tắt)

| § | Section | Nguồn | Điểm nhấn |
|---|---|---|---|
| 13 | Full Asset Inventory | `alive_detail.json` | Bảng đầy đủ, sort được, kèm cột "vì sao đáng chú ý" |
| 14 | Technology Distribution & Risk | `tech[]` + `webserver` | ⚠ Đa số không có version ⇒ **không map CVE được**. Nêu rõ giới hạn |
| 15 | DNS Analysis | `resolved_detail.json` | Dangling CNAME (có CNAME, không resolve) = ứng viên subdomain takeover. **1,689 record acronis chưa ai soi** |
| 16 | Infrastructure & Cloud | `a[]`, `asn`, `cdn_*`, tech AWS/GCP | Gom IP theo dải; IP dùng chung ⇒ virtual host |
| 17 | WAF / CDN / Bot Protection | `tech[]` | **Suy ra được**: acronis 33 host Cloudflare Bot Mgmt, discover 55 host Akamai Bot Mgr ⇒ vùng cần bypass để test |
| 18 | HTTP Response Analysis | `alive_urls_detail.json` | 18,722 record: phân bố status/type/length; nhóm theo `content_length` giống nhau ⇒ trang template |
| 19 | Content Discovery | ffuf/dirsearch | **Bắt buộc lọc blanket-deny trước** (B.1) |
| 20 | Historical Changes | `delta.md`, `scan_diff` | Cả 3 target đang là baseline ⇒ ghi "chưa có so sánh", không để trống |
| 21 | Asset Timeline | `timestamp` các entity | Timeline hợp nhất theo thời gian |

---

## PHẦN E — LOGIC TƯƠNG QUAN (Deliverable 3)

### E.1 Khoá join thật (đã kiểm chứng)

```
subdomains.txt[line]        ⋈ resolved_detail.json[subdomain]      khoá: hostname
resolved_detail[subdomain]  ⋈ alive_detail[input]                  khoá: hostname
alive_detail[host]          ⋈ alive_urls_detail[host]              khoá: hostname
alive_urls_detail[url]      ⋈ all_urls.txt[line]                   khoá: URL chuẩn hoá
js_urls.txt[line]           ⋈ jsluice_secrets[url]                 khoá: URL JS
jsluice_endpoints[line]     ⋈ alive_urls_detail[path]              khoá: path (join mờ)
forms.json[url]             ⋈ alive_detail[url]                    khoá: URL gốc
nuclei[host]                ⋈ alive_detail[host]                   khoá: hostname
nuclei[matched-at]          ⋈ all_urls.txt                         khoá: URL
raw/ffuf/<host>.json        ⋈ alive_detail[host]                   khoá: TÊN FILE = hostname
```

### E.2 Chuẩn hoá URL bắt buộc trước mọi join

Rút ra từ lỗi thật gặp phải:

```python
def canon(u):
    u = u.strip()
    u = re.sub(r'/\./', '/', u)         # /./Login.aspx  → /Login.aspx   (lỗi B/A.3)
    u = re.sub(r'/{2,}', '/', u.replace('://','\x00')).replace('\x00','://')
    u = u.rstrip('/') if u.count('/') > 2 else u
    u = drop_default_port(u)            # :443 với https, :80 với http
    u = sort_query_params(u)            # ?b=1&a=2 → ?a=2&b=1
    u = lower(scheme_and_host(u))       # path giữ nguyên hoa/thường
    return u
```

Không có bước này thì mọi thống kê đều đếm dư.

### E.3 Thứ tự dựng model (pipeline 6 bước)

```
1. NẠP      đọc mọi file, ép về entity chuẩn
2. CHUẨN HOÁ canon URL, lower hostname, tách IP csv thành list
3. LỌC SCOPE loại host ngoài scope → chuyển sang §23 (không xoá)
4. KHỬ NHIỄU response-similarity clustering  → hạ cấp blanket-deny
            hash JS                          → gộp bundle trùng
            giá trị secret                   → gộp key trùng
5. JOIN     dựng đồ thị theo E.1
6. LÀM GIÀU chấm điểm, phân loại, dò chuỗi tấn công
```

**Bước 3 và 4 phải đứng TRƯỚC bước 6.** Pipeline hiện tại chấm điểm trên dữ liệu
chưa lọc — đó là gốc của cả B.1, B.2 và B.3.

---

## PHẦN F — PHƯƠNG PHÁP XẾP HẠNG RỦI RO (Deliverable 4)

### F.1 Vì sao công thức hiện tại chưa đủ

`modules/priority.py` cộng điểm tuyến tính: `score = Σ(tín hiệu)`. Ba hệ quả quan sát
được:

1. Nhiều tín hiệu yếu cộng lại vượt một tín hiệu mạnh (KB article 600 vs nuclei 800 —
   chỉ cách 200).
2. Không có khái niệm độ tin cậy → false positive (B.1) vẫn được 770.
3. Từ khoá cố định không thích ứng theo target (B.3).

### F.2 Công thức đề xuất — nhân thay vì cộng

```
RISK = BASE  ×  CONFIDENCE  ×  EXPOSURE  ×  CONTEXT  ×  NOVELTY

BASE — điểm tín hiệu mạnh nhất, KHÔNG cộng dồn
   nuclei critical         1000        secret có thể khai thác     700
   nuclei high              800        form login/upload           450
   nuclei medium            400        endpoint API versioned      300
   nuclei low               120        URL có param                200
   nuclei info               15        hit content-discovery       150
   (tín hiệu thứ 2 trở đi chỉ cộng thêm 15% giá trị của nó — chống lạm phát B.3)

CONFIDENCE — 0.1 … 1.0   ⚑ nhân tố mới, sửa B.1
   1.00  nuclei có matcher + response
   0.90  form trích từ HTML thật
   0.70  endpoint từ JS, đã probe sống
   0.40  endpoint từ JS, chưa probe
   0.10  hit nằm trong blanket-deny cluster   ← .git/config tụt 770 → 77

EXPOSURE — mức phơi bày thật
   ×1.3  status 200, không CDN, không bot-protection
   ×1.0  status 200 sau CDN
   ×0.8  401/403 (có auth — vẫn đáng test nhưng khó hơn)
   ×0.3  404/5xx
   ×0.5  đứng sau bot-protection (Cloudflare/Akamai Bot Mgmt)

CONTEXT — giá trị nghiệp vụ của host
   ×1.5  internal / admin / vpn
   ×1.4  dev / staging / uat
   ×1.3  api / gateway / auth
   ×1.2  storage / upload / backup
   ×1.0  mặc định
   ×0.5  docs / blog / kb / marketing        ← dập B.3 tận gốc
   ×0.0  ngoài scope                          ← dập B.2 tận gốc

NOVELTY — thưởng cái mới
   ×1.3  mới xuất hiện lần quét này
   ×1.0  đã tồn tại
   ×0.7  đã đánh dấu triaged/false-positive
```

### F.3 Trọng số keyword tự thích ứng (sửa B.3)

Thay hằng số bằng IDF tính trên chính corpus của target:

```
weight(kw) = base_weight(kw) × log(N / df(kw))   , chặn dưới ở 0.1×

acronis, kw="backup":  df = 1,305/25,645 = 5.1% corpus   (đo thật)
    → log(1/0.051) = 2.98  so với keyword hiếm log(1/0.001) = 6.91
    → trọng số còn 43%  ⇒ 300 điểm tụt còn ~130
```

Riêng "backup" vẫn còn 130 điểm — chưa đủ dập hết. Vì vậy IDF phải **đi kèm** hệ số
CONTEXT ×0.5 cho host tài liệu/KB: `care.acronis.com/s/article/…` nhận cả hai mức
giảm, tổng còn ~50 điểm. Một mình IDF không giải quyết được B.3.

Từ khoá trùng tên thương hiệu tự động mất giá trị, không cần cấu hình tay từng target.

### F.4 Kết quả mô phỏng trên dữ liệu thật

| URL | Điểm hiện tại | Điểm v2 | Vì sao đổi |
|---|---|---|---|
| `care.acronis.com/s/sfsites/aura` | 800 | **940** | nuclei verify × context (portal KH) |
| `securedocupload.discover.com` | không có trong list | **780** | upload × tổ chức tài chính |
| `expenses.acronis.com/Login.aspx` | 620 | **660** | form 19 field × ViewState |
| `us-kibana.acronis.com` | không có trong list | **650** | infra panel × internal context |
| `web-api-arp.acronis.com/.git/config` | 770 | **77** | ⛔ confidence 0.1 (blanket-deny) |
| `care.acronis.com/s/article/…?language=en_US` | 600 | **~50** | context docs ×0.5, IDF backup ×0.24 |
| `elearning.unyp.cz/login/index.php` | 620 | **0** | ⛔ ngoài scope |

Bốn khiếm khuyết ở Phần B được xử lý bằng đúng bốn nhân tố trong công thức.

---

## PHẦN G — XẾP HẠNG ASSET (Deliverable 5)

Khác với xếp hạng URL: xếp hạng **host** để biết đào host nào.

```
ASSET_SCORE = (
      50 × log₂(1 + số_url_alive)          quy mô ứng dụng
   +  80 × log₂(1 + số_endpoint_api)       độ giàu API
   +  40 × log₂(1 + số_file_js)            độ phức tạp client
   + 120 × số_form_có_password             bề mặt auth
   + 200 × số_finding_đã_verify            rủi ro đã biết
   + 150 × số_secret_duy_nhất              rò rỉ
) × CONTEXT_MULTIPLIER × EXPOSURE_MULTIPLIER
```

**Vì sao dùng log** — số liệu đo thật của acronis chứng minh điều này rất rõ:

```
www.acronis.com          12,446 URL alive (66% toàn bộ)  ·  1,279 JS
web-api-arp.acronis.com   4,096 URL  ⛔ blanket-deny, rác hoàn toàn
developer.acronis.com       673 URL
care.acronis.com            340 URL  ·  45 JS  ·  1 nuclei finding đã verify
us-kibana.acronis.com         2 URL  ·   0 JS  ·  Kibana ra Internet
expenses.acronis.com          6 URL  ·   2 JS  ·  2 form ViewState
```

Chấm tuyến tính theo số URL thì `www.acronis.com` (site marketing) đứng đầu tuyệt
đối, còn `us-kibana` với **2 URL** không bao giờ lọt vào tầm mắt — dù đó là Kibana
phơi ra Internet. Log-scale + CONTEXT multiplier đảo ngược đúng thứ tự này.

Đồng thời `web-api-arp` — host **hạng 2 về số URL** — phải bị loại thẳng bằng
confidence 0.1, nếu không nó chiếm chỗ trong mọi bảng xếp hạng.

**Bảng đầu ra** (số trong ngoặc = đo thật; ô `?` = chưa đo cho target đó)

| # | Host | Score | URL | JS | Form | Find | Ctx | Vì sao |
|---|---|---|---|---|---|---|---|---|
| 1 | care.acronis.com | 1,240 | 340 | 45 | 1 | 1 | portal KH | nuclei verify + form + dữ liệu khách hàng |
| 2 | securedocupload.discover.com | 890 | ? | ? | ? | 0 | upload | upload tài liệu + tổ chức tài chính |
| 3 | us-kibana.acronis.com | 650 | 2 | 0 | 0 | 0 | infra | Kibana ra Internet — nhỏ nhưng nhạy nhất |
| 4 | expenses.acronis.com | 640 | 6 | 2 | 2 | 0 | internal | WebForms + `__VIEWSTATE` |
| 5 | developer.acronis.com | 580 | 673 | ? | 0 | 0 | api/docs | param SSRF-like (`url=`,`curl=`,`uri=`) |
| — | www.acronis.com | 310 | 12,446 | 1,279 | ? | 0 | marketing ×0.5 | to nhất nhưng giá trị thấp nhất |
| ⛔ | web-api-arp.acronis.com | 41 | 4,096 | 0 | 0 | 0 | conf ×0.1 | blanket-deny — loại |

---

## PHẦN H — TRỰC QUAN HOÁ (Deliverable 6)

Chỉ những chart **trả lời một câu hỏi**. Không chart trang trí.

| # | Chart | Kiểu | Trả lời câu hỏi gì | Nguồn |
|---|---|---|---|---|
| 1 | **Phễu bề mặt tấn công** | Funnel | Từ 1,689 sub còn lại bao nhiêu đáng test? | counts |
| 2 | **Ma trận Rủi ro × Phơi bày** | Scatter | Asset nào vừa nhạy vừa hở? (góc trên-phải = ưu tiên) | asset score |
| 3 | **Phân bố status** | Bar ngang | Bao nhiêu % auth-gated? bao nhiêu 404 rác? | status_code |
| 4 | **Treemap công nghệ** | Treemap | Tech nào phủ rộng nhất ⇒ 1 CVE ảnh hưởng bao nhiêu? | tech[] |
| 5 | **Đồ thị chuỗi tấn công** | Sankey/DAG | Đường đi từ JS → endpoint → finding | correlation |
| 6 | **Cụm phản hồi** | Scatter len×words | Lộ blanket-deny ngay bằng mắt (B.1) | ffuf results |
| 7 | **Heatmap độ tin cậy stage** | Heatmap | Vùng nào của bản quét đáng tin? | stages.json |
| 8 | **Tăng trưởng bề mặt** | Line | Bề mặt phình theo thời gian? | delta history |
| 9 | **Cây API theo version** | Sunburst | v1..v5 phân bố thế nào? | endpoints |
| 10 | **Nhóm host theo context** | Stacked bar | dev/staging chiếm bao nhiêu? | classification |

**Chart #6 quan trọng nhất về mặt chất lượng dữ liệu** — vẽ mỗi ffuf hit theo
(content_length, words), blanket-deny hiện thành **một chấm đặc duy nhất** với 4,097
điểm chồng lên nhau. Nhìn phát biết ngay.

**Chart #2 quan trọng nhất về mặt tác nghiệp** — trục X = độ phơi bày, trục Y = giá
trị nghiệp vụ, kích thước chấm = số finding. Góc trên-phải là danh sách việc cần làm.

---

## PHẦN I — BẢNG ĐỀ XUẤT (Deliverable 7)

| Bảng | Cột | Sort mặc định | Ghi chú |
|---|---|---|---|
| Top Manual Targets | rank, score, url, signals, confidence, test-first | score ↓ | Card, không phải bảng |
| Findings by Class | template, sev, hosts, evidence, verified?, action | sev ↓ | Gom theo class, không theo host |
| High-Value Assets | host, score, ctx, urls, apis, forms, findings, why | score ↓ | |
| Auth Surface | url, method, framework, fields, has-csrf, has-pwd, test | framework | Từ forms.json |
| API Inventory | path, version, method, source-js, probed?, status, params | path (cây) | Nhóm theo prefix |
| Secret Exposure | key(che), kind, unique, occurrences, js, hosts, verified? | occurrences ↓ | Che giữa giá trị |
| Tech Distribution | tech, hosts, %, version?, cve-mappable?, risk | hosts ↓ | Cột cve-mappable phần lớn = "không" |
| DNS Anomalies | subdomain, type, value, dangling?, takeover-candidate? | dangling ↓ | |
| Stage Health | stage, status, count, duration, error, affects | status | |
| Data Quality | check, threshold, result, severity, impact | severity ↓ | |
| Out-of-Scope | host, seen-in, times, action | times ↓ | |
| Blanket-Deny | host, hits, dominant-response, %, verdict | % ↓ | |

**Quy tắc chung cho mọi bảng:** cột cuối luôn là **hành động** hoặc **vì sao quan
trọng**. Bảng chỉ có dữ kiện mà không có "so what" là bảng chưa xong.

---

## PHẦN J — METRIC (Deliverable 8)

### Metric bề mặt
```
Tỉ lệ alive            = alive_host / subdomain          acronis 34%  gw2 99%*
Mật độ URL             = alive_url / alive_host          acronis 33   gw2 308
Tỉ lệ auth-gated       = (401+403) / alive_host          acronis 23%  disc 32%
Tỉ lệ API              = url json / alive_url            acronis 0.09%
Độ nặng JS             = js_file / alive_host            acronis 6.9
Mật độ form            = form / alive_host               acronis 0.19
Tỉ lệ dev/staging      = host dev|stag|uat / alive_host  disc 28% ⚠ cao
Tỉ lệ 404              = host 404 / alive_host           gw2 74% ⛔
```
*\*gw2 99% alive nhưng 74% trả 404 ⇒ **tỉ lệ alive vô nghĩa nếu không kèm tỉ lệ 404**.
Luôn báo cặp đôi.*

### Metric rủi ro
```
Mật độ finding      = finding / alive_host        acronis 0.007
Số issue class      = template-id duy nhất        acronis 2 (từ 4 finding)
Secret duy nhất     = giá trị key distinct        acronis 3 (từ 9)
Tỉ lệ thổi phồng    = finding / duy nhất          acronis 3.0×  disc 3.7×
Điểm rủi ro         = Σ RISK top 20
```

### Metric chất lượng ⚑
```
Confidence bản quét = Σ(stage ok × trọng số) / Σ trọng số      acronis 72%
Tỉ lệ FP ước tính   = hit blanket-deny / tổng hit ffuf         acronis 98% ⛔
Rò rỉ scope         = host ngoài scope / host trong report     acronis 4
Phủ stage           = stage success / tổng stage               acronis 24/26
```

### Metric tăng trưởng
```
Asset mới / tuần · Tốc độ tăng bề mặt · Tuổi trung bình asset
Thời gian tồn tại của finding (mở → đóng)
```
Cả 3 target hiện là baseline ⇒ báo cáo ghi *"cần ≥2 lần quét"*, không để ô trống.

---

## PHẦN K — MẪU EXECUTIVE SUMMARY (Deliverable 9)

Bản sinh tự động từ dữ liệu thật của acronis.com:

```markdown
# Executive Summary — acronis.com
Quét: 2026-07-25 14:38 → 20:31 (5h 53m) · chế độ active · độ tin cậy 72/100 ⚠

## Tình hình

Bản quét lập bản đồ 1,689 subdomain, trong đó 574 có dịch vụ web sống, phơi
bày 18,722 URL truy cập được. Bề mặt tấn công lớn và phân mảnh: 23 host
dev/staging/beta, 56 host lưu trữ/backup, 7 host mang tên VPN hoặc internal,
và 2 admin panel — trong đó có "admin2" gợi ý một phiên bản cũ chưa được gỡ.

Scanner tự động xác nhận **2 lớp vấn đề trên 4 host**, cả hai mức medium.
Không có finding critical hoặc high. Con số này cần đọc kèm cảnh báo bên dưới:
hai giai đoạn quét đã hỏng, nên đây **chưa phải bức tranh đầy đủ**.

## Ba điều cần làm trước

1. **Salesforce Community trên care.acronis.com bị cấu hình sai** (medium, đã
   xác nhận). Portal khách hàng dùng Salesforce Aura cho phép người dùng ẩn
   danh truy vấn object. Cần kiểm ngay xem Contact, Case và Account có đọc
   được không — nếu có, đây là rò rỉ dữ liệu khách hàng, không còn là medium.

2. **Bốn endpoint VPN và một Kibana đang mở ra Internet.** bg-vpn, bg-vpn-qa,
   jp-vpn, provisioning-vpn và us-kibana.acronis.com. Kibana thường được triển
   khai không xác thực; nếu đúng vậy, log nội bộ đang công khai. Đây là rủi ro
   hạ tầng, không phải lỗi ứng dụng, và khắc phục nhanh hơn nhiều so với sửa code.

3. **Luồng OAuth của IdP chấp nhận redirect sang subdomain khác.** Cả
   cloud.acronis.com và beta-cloud.acronis.com đều chuyển hướng sang
   partner/uat-partner sau xác thực. Nếu whitelist dùng wildcard *.acronis.com,
   chiếm được **một** subdomain bất kỳ trong 574 host là chiếm được token
   người dùng. Cần rà lại danh sách redirect_uri.

## Cảnh báo về độ tin cậy

Hai giai đoạn quét không hoàn tất: **arjun lỗi hoàn toàn** (không phát hiện
tham số chủ động) và **dirsearch timeout** sau 75 phút, chỉ cứu được một phần.
Ngoài ra 98% kết quả ffuf đến từ một host trả 403 cho mọi đường dẫn — đã lọc,
nhưng nghĩa là content discovery trên host đó **chưa thu được gì**.

Nói ngắn gọn: **những gì báo cáo nêu ra đều đã kiểm chứng; nhưng bề mặt thật
rộng hơn những gì đo được.** Không nên đọc "4 finding" thành "hệ thống sạch".

## Việc tiếp theo
- Ngay: xác minh 3 mục trên bằng tay (ước tính 4–6 giờ)
- Tuần này: quét lại với arjun được sửa và dirsearch tăng timeout
- Định kỳ: đặt lịch quét hằng tuần để theo dõi 23 host dev/staging
```

**Nguyên tắc viết:** văn xuôi; nêu con số kèm ý nghĩa; nói rõ chỗ chưa biết; kết bằng
việc cần làm có ước lượng thời gian. Không dùng từ "critical" khi dữ liệu không có
finding critical.

---

## PHẦN L — PHỤ LỤC (Deliverable 10)

| Phụ lục | Nội dung | Định dạng | Vì sao tách riêng |
|---|---|---|---|
| **A. Full Subdomain List** | 1,689 dòng kèm resolve/alive/nguồn tool | CSV | Quá dài cho thân báo cáo |
| **B. Full Host Inventory** | 574 host, mọi field từ `alive_detail.json` | CSV | Tra cứu |
| **C. Complete URL Inventory** | 18,722 URL alive kèm status/type/len | CSV.gz | Rất lớn |
| **D. API Endpoint Catalogue** | Mọi endpoint trích được kèm JS nguồn | JSON | Nạp vào Burp/ffuf |
| **E. Form & Parameter Catalogue** | 109 form + param, kèm framework | JSON | Đầu vào cho fuzzing |
| **F. Nuclei Raw Evidence** | Finding đầy đủ + request/response/curl | JSON | Bằng chứng reproduce |
| **G. Stage Execution Log** | `stages.json` diễn giải + thời lượng | Bảng | Kiểm toán bản quét |
| **H. Methodology & Limitations** | Công cụ, version, config, vùng chưa quét | Văn bản | **Bắt buộc cho báo cáo doanh nghiệp** |
| **I. Out-of-Scope Observed** | 4 host ngoài scope + nơi xuất hiện | Bảng | Minh bạch pháp lý |
| **J. Data Quality Checks** | 8 kiểm tra + kết quả + tác động | Bảng | Cho phép người đọc tự đánh giá |

**Phụ lục H là bắt buộc.** Báo cáo doanh nghiệp phải nói rõ **không quét gì**: không
TLS, không port scan (chỉ 80/443), không header, không screenshot, không map CVE
(thiếu version). Thiếu phần này, người đọc mặc định "không báo cáo = an toàn" — hiểu
sai nguy hiểm nhất trong bảo mật.

---

## PHẦN M — LỘ TRÌNH TRIỂN KHAI

| Ưu tiên | Việc | Vì sao | Công |
|---|---|---|---|
| **P0** | Response-similarity clustering (B.1) | 98% ffuf output đang là rác | Thấp |
| **P0** | Scope gate cứng (B.2) | Rủi ro pháp lý | Rất thấp |
| **P0** | Chuẩn hoá URL `canon()` (A.3) | Mọi metric đang đếm dư | Rất thấp |
| **P0** | Khử trùng secret theo giá trị | Đang thổi phồng 3–3.7× | Rất thấp |
| **P1** | Điểm nhân + confidence (F.2) | Sửa gốc xếp hạng | Trung bình |
| **P1** | IDF keyword (F.3) | Dập nhiễu thương hiệu | Thấp |
| **P1** | §0 Provenance & Confidence | Chống hiểu nhầm "0 finding = sạch" | Thấp |
| **P1** | §7 Auth Surface từ forms.json | Dữ liệu đã có, chưa ai dùng | Thấp |
| **P2** | §10 Attack Path chains | Điểm khác biệt của báo cáo ASM | Cao |
| **P2** | §12 Anomalies tự động | 8 kiểm tra ở Phần J | Trung bình |
| **P3** | Bật tlsx / naabu / screenshot / header | Mở khoá 6 section đang trống | Trung bình |

**Bốn việc P0 đều dưới một ngày công và cùng nhau loại bỏ phần lớn nhiễu hiện tại.**
Làm P0 trước khi đụng tới bất kỳ section mới nào — thêm section lên dữ liệu bẩn chỉ
làm báo cáo dài hơn chứ không đúng hơn.
