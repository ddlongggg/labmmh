# Báo cáo Phân tích An toàn Bảo mật (Security Engineering Discussion)
**Lab 4 — Hashing, PKI, and Practical Attacks**

---

## 1. Phân tích Cấu trúc Hàm băm (Hash Functions Analysis)

### a. Merkle–Damgård vs Sponge Construction
- **Merkle–Damgård (MD):** Là cấu trúc nền tảng của MD5, SHA-1 và SHA-2. Nó hoạt động bằng cách chia thông điệp thành các khối có kích thước cố định (ví dụ 512 bit), đệm (padding) khối cuối cùng và đưa từng khối qua một hàm nén (compression function) một chiều cùng với trạng thái (state) của khối trước đó. Mặc dù dễ cài đặt, MD dễ bị tấn công mở rộng chiều dài (Length Extension Attack).
- **Sponge Construction:** Là cấu trúc lõi của SHA-3 (Keccak). Nó duy trì một trạng thái nội bộ lớn (ví dụ 1600 bit) chia làm hai phần: `Rate` (phần tương tác với dữ liệu) và `Capacity` (phần bí mật, quyết định độ an toàn). Dữ liệu được "hấp thụ" (Absorb) vào `Rate` qua phép XOR và hoán vị, sau đó "vắt" (Squeeze) ra độ dài tuỳ ý. Cấu trúc này miễn nhiễm hoàn toàn với Length Extension Attack.

### b. Collision Resistance vs Preimage Resistance
- **Preimage Resistance (Chống nghịch đảo - One-way):** Cho một mã băm $H(x) = y$, cực kỳ khó để tìm lại được thông điệp gốc $x$ từ $y$.
- **Collision Resistance (Chống đụng độ):** Cực kỳ khó để tìm ra hai thông điệp *bất kỳ* $x_1 \neq x_2$ sao cho chúng có cùng một mã băm $H(x_1) = H(x_2)$. 
*Lưu ý:* MD5 và SHA-1 đã bị phá vỡ hoàn toàn khả năng chống đụng độ (Collision), nhưng hiện tại vẫn còn giữ được mức độ chống nghịch đảo (Preimage). Tuy nhiên, mất tính chống đụng độ là đủ để loại bỏ chúng khỏi các tiêu chuẩn mã hoá.

### c. Tại sao SHA-3 khác biệt cấu trúc so với SHA-2?
Năm 2006, khi SHA-1 bắt đầu bộc lộ điểm yếu, NIST lo ngại SHA-2 (cùng họ Merkle-Damgård) cũng có thể chịu chung số phận. Do đó, cuộc thi tuyển chọn SHA-3 yêu cầu các ứng viên phải có một mô hình toán học hoàn toàn khác biệt để làm phương án dự phòng. Keccak (Sponge) đã chiến thắng vì cấu trúc hấp thụ/vắt độc đáo, tính toán linh hoạt trên phần cứng và hoàn toàn miễn nhiễm với các điểm yếu của họ MD.

### d. Ứng dụng của XOF (Extendable-Output Functions)
XOF như SHAKE128/SHAKE256 cho phép đầu ra có chiều dài bất kỳ, không bị giới hạn cố định như SHA-256 (luôn ra 256 bit).
- **Domain Separation (Phân tách miền):** SHAKE có thể dùng để sinh ra các khoá phụ độc lập từ một master key bằng cách thêm prefix, giúp một khoá không bị tái sử dụng ở các ngữ cảnh khác nhau.
- **Key Derivation & Stream Ciphers:** XOF có thể đóng vai trò như hàm KDF hoặc băm vô tận để làm keystream giả ngẫu nhiên mã hoá dữ liệu.

---

## 2. Hạ tầng Khoá công khai (PKI) & Chứng thư số (X.509)

### a. Cấu trúc X.509: TBS (To-Be-Signed) vs Signature
Một chứng thư số X.509 gồm 3 phần chính: 
1. **TBSCertificate (To-Be-Signed):** Chứa thông tin thực sự (Subject, Issuer, Public Key, Validity, v.v.).
2. **SignatureAlgorithm:** Thuật toán dùng để ký (VD: sha256WithRSAEncryption).
3. **SignatureValue:** Giá trị băm của vùng TBS, sau đó được mã hoá bằng Private Key của Tổ chức phát hành (CA).
Khi Client kiểm tra, họ tự băm vùng TBS và so sánh với việc giải mã SignatureValue bằng Public Key của CA.

### b. Chuỗi uỷ thác (Chain of Trust)
Trình duyệt không tự nhiên tin tưởng website của chúng ta. Sự tin tưởng được bắc cầu: 
- Trình duyệt cài sẵn Root CA (như GlobalSign, DigiCert) ngay trong hệ điều hành.
- Root CA ký chứng nhận cho Intermediate CA (CA trung gian).
- Intermediate CA ký chứng nhận (End-Entity Certificate) cho website (như `example.com`).
Đây gọi là chuỗi uỷ thác, đứt gãy ở bất kỳ khâu nào (chữ ký sai, hết hạn) sẽ dẫn đến lỗi SSL/TLS.

### c. Tại sao SHA-1 và MD5 bị cấm ngặt? & Tấn công Chosen-Prefix
Bởi vì chúng dễ bị tấn công đụng độ. Hacker có thể tạo ra hai giấy chứng nhận khác nhau hoàn toàn về nội dung (một cái vô hại, một cái giả mạo tên miền ngân hàng) nhưng lại có chung *một* mã băm MD5. Khi CA ký lên mã băm đó, chữ ký hợp lệ cho cả hai giấy chứng nhận! Đây là thảm hoạ **Chosen-Prefix Collision**, từng được mã độc Flame sử dụng để giả mạo bản cập nhật Windows. Các chuẩn CA/B (CA/Browser Forum) hiện nay yêu cầu băm tối thiểu bằng SHA-256.

### d. Certificate Transparency (CT) & CA/B Requirements
Dù CA dùng mã hoá an toàn, họ vẫn có thể bị hack hoặc ký nhầm. CT là một cuốn sổ cái (Public Ledger) chống thay đổi (Append-only log). CA/B quy định: Mọi giấy chứng nhận cấp ra bắt buộc phải được đẩy lên hệ thống CT Log để toàn thế giới giám sát. Nếu có giấy phép giả mạo được ký chui, chủ sở hữu tên miền sẽ phát hiện ngay lập tức.

---

## 3. Lỗ hổng MAC và Length-Extension Attack

### a. Tại sao Merkle–Damgård cho phép Length Extension?
Cấu trúc MD cập nhật trạng thái băm (state) liên tục và nối tiếp. Khi bạn có được mã băm của $H(K || M)$, mã băm đó thực chất chính là *state nội bộ* cuối cùng của hàm băm. Hacker chỉ cần lấy state đó, coi nó như điểm khởi đầu, và tiếp tục băm thêm dữ liệu mới $M'$ tạo ra $H(K || M || padding || M')$ mà không hề cần biết khoá bí mật $K$.

### b. Tại sao HMAC và Prefix-free ngăn chặn được?
- **Prefix-free:** Nếu thông điệp luôn được mã hoá độ dài ngay từ đầu, hoặc không có tiền tố nào giống nhau, hacker không thể nối dài thêm vì hàm băm sẽ sai cấu trúc độ dài.
- **HMAC ($H(K_1 \oplus opad || H(K_2 \oplus ipad || M))$):** HMAC băm hai lần với hai lớp khoá (Inner pad và Outer pad). Việc băm lớp Outer bọc lấy kết quả lớp Inner khiến hacker không thể lấy được state nội bộ của thông điệp ban đầu để nối đuôi. Chặn đứng hoàn toàn Length Extension.

---

## 4. Đánh giá Hiệu năng Hashing (Performance Evaluation)

Dựa trên kết quả đo đạc từ mã nguồn C++ (Task 5):
- **Stream I/O vs Memory-Mapped I/O:** 
  - **Stream I/O:** Đọc file qua luồng (Buffer 4KB-8KB) tiêu tốn nhiều chu kỳ CPU cho việc gọi Syscall (Context Switch) liên tục vào OS. 
  - **Memory-Mapped (MMap):** Nạp thẳng file vào không gian bộ nhớ ảo. Bỏ qua overhead của Syscall nên tốc độ băng thông (Throughput MB/s) trên file lớn (100MB) cao hơn rõ rệt. Tuy nhiên, nó có thể gây tốn chi phí page-fault ban đầu.
- **SHA-2 vs SHA-3 (Keccak) Performance:** 
  - **SHA-256:** Có Throughput cực kỳ ấn tượng nhờ kiến trúc tập lệnh vi xử lý hiện đại được tối ưu tốt.
  - **SHA-512:** Chạy vô cùng nhanh trên nền tảng 64-bit do dùng thanh ghi 64-bit (xử lý dữ liệu gấp đôi mỗi block so với SHA-256 trong khi số vòng lặp ít hơn tương đối - 80 vòng so với 64 vòng).
  - **SHA-3:** Phức tạp hơn về mặt toán học (duy trì trạng thái 1600-bit khổng lồ), nên tốc độ xử lý trên phần mềm thuần tuý thường chậm hơn đáng kể so với SHA-256. Mặc dù an toàn hơn, nhưng chi phí CPU cao khiến SHA-3 thường phù hợp hơn với gia tốc phần cứng chuyên dụng.
