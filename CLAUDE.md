## Yêu cầu duy trì tài liệu dự án

Trong quá trình phân tích hoặc phát triển, mỗi khi hiểu thêm một phần quan trọng của codebase, hãy **cập nhật tài liệu của dự án** thay vì chỉ ghi nhớ trong phiên làm việc.

### Nhiệm vụ

* Xây dựng và duy trì **README.md** phản ánh chính xác trạng thái hiện tại của dự án.
* Xây dựng **Project Index** (ví dụ: `docs/index.md`) để mô tả cấu trúc tổng thể của repository.
* Cập nhật các tài liệu liên quan khi có thay đổi về kiến trúc hoặc luồng xử lý.
* Chỉ ghi nhận những thông tin đã được **xác minh từ mã nguồn**, không suy đoán hoặc tự thêm giả định.

### Luôn cập nhật các nội dung sau

* Kiến trúc tổng thể của hệ thống (Architecture)
* Vai trò và trách nhiệm của từng module (Responsibilities)
* Quan hệ giữa các module (Module Relationships)
* Các API, interface hoặc entry point quan trọng
* Các giả định và cơ chế bảo mật (Security Assumptions)
* Luồng nghiệp vụ (Business Logic)
* Quy ước phát triển, coding conventions và design patterns
* Pipeline xử lý dữ liệu và luồng thực thi của hệ thống
* Các quyết định thiết kế (Design Decisions) và Technical Debt nếu có

### Nguyên tắc

* Không phân tích lại những phần đã được xác minh trước đó.
* Ưu tiên cập nhật tài liệu hiện có thay vì tạo tài liệu trùng lặp.
* Khi phát hiện thông tin mới hoặc thay đổi trong codebase, hãy đồng bộ ngay vào README, Project Index và các tài liệu liên quan.
* Luôn sử dụng tài liệu đã được cập nhật làm nguồn tham chiếu chính trong các phiên làm việc tiếp theo, thay vì phân tích lại từ đầu.
* Nếu phát hiện tài liệu không còn khớp với mã nguồn hiện tại, hãy cập nhật tài liệu để phản ánh đúng implementation.

## Language Preference

### Default Language
- Always respond in **Vietnamese** unless the user explicitly requests another language.
- Keep technical terms, vulnerability names, CVE identifiers, HTTP headers, API endpoints, code, commands, and file paths in their original English form when appropriate.
- Explanations, reasoning, recommendations, and documentation should be written naturally in Vietnamese.
- If the user writes in English or explicitly asks for an English response, reply in English for that conversation.
- Do not translate source code, terminal commands, URLs, payloads, or log output.
