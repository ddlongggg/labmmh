# Báo cáo Phân tích An toàn Bảo mật (Security Engineering Discussion)
**Lab 2 — AES-128 Implementation (CTR Mode, FIPS-197 Compliant)**

---

## 1. Phân tích Rủi ro của Thuật toán AES Cốt lõi (AES Core Risks)

### a. Rò rỉ qua thời gian từ S-box dạng Bảng (Timing leakage & Cache-based attacks)
Trong mã nguồn `AESCore.cpp`, S-box được triển khai dưới dạng một mảng tĩnh (Table-based S-box): `static const uint8_t sbox[256] = {...}`. Việc lấy giá trị S-box (vd: `sbox[state[r][c]]`) yêu cầu CPU phải truy xuất vào bộ nhớ (Memory Access). 
Mặc dù cách làm này tối ưu về mặt hiệu năng so với việc tính toán đa thức Galois liên tục (Computed S-box), nó lại mở ra một lỗ hổng rất lớn gọi là **Cache-based Side-Channel Attacks** (Tấn công kênh kề qua Cache).
Thời gian để CPU đọc một giá trị từ Cache L1/L2 sẽ nhanh hơn rất nhiều so với việc phải truy xuất từ RAM chính. Kẻ tấn công có thể liên tục đẩy rác vào cache, ép CPU phải tải lại bảng S-box từ RAM, sau đó đo lường vi sai thời gian phản hồi (Timing Leakage). Vì vị trí truy xuất phụ thuộc trực tiếp vào bit của khoá (Key) hoà trộn với Plaintext, kẻ tấn công hoàn toàn có thể khôi phục từng bit của khoá gốc thông qua phương pháp đo lường thống kê.

### b. Tầm quan trọng của Constant-time Coding (Lập trình không phụ thuộc thời gian)
Trong bảo mật ứng dụng mã hóa, **Constant-time coding** là quy tắc cốt lõi. Bất kỳ một thuật toán mã hóa nào mà thời gian thực thi (hoặc các nhánh lệnh IF/ELSE) bị phụ thuộc vào dữ liệu bí mật (Key hoặc Plaintext) đều là một lỗ hổng nghiêm trọng.
Để viết AES an toàn tuyệt đối trước Side-Channel, chúng ta không được phép dùng các mảng tra cứu (lookup tables) có chỉ số (index) phụ thuộc vào thông tin bí mật. Giải pháp thay thế là **Computed S-box** (Dùng toán học bitwise tuần tự, còn gọi là Bit-sliced AES) hoặc sử dụng các tập lệnh phần cứng đặc dụng.

---

## 2. Rủi ro của Chế độ CTR (CTR Mode Risks)

### a. Tại sao lặp Nonce (IV Reuse) là thảm họa (Keystream reuse attack)
Chế độ CTR hoạt động bằng cách mã hóa giá trị `Counter Block` (bao gồm Nonce/IV + Counter) để tạo ra một chuỗi keystream giả ngẫu nhiên, sau đó đem XOR trực tiếp chuỗi này với Plaintext để sinh ra Ciphertext:
`C_i = P_i ⊕ S_i` (với $S_i$ là keystream).

Nếu vô tình sử dụng lại **CÙNG MỘT IV (Nonce) cho CÙNG MỘT KEY** trên hai thông điệp khác nhau ($P_A$ và $P_B$), chuỗi keystream sinh ra sẽ giống hệt nhau:
- $C_A = P_A ⊕ S$
- $C_B = P_B ⊕ S$

Lúc này, hacker chặn được $C_A$ và $C_B$ chỉ việc XOR chúng lại với nhau (đây gọi là lỗ hổng **Two-time pad vulnerability**):
`C_A ⊕ C_B = (P_A ⊕ S) ⊕ (P_B ⊕ S) = P_A ⊕ P_B`
Keystream bị triệt tiêu hoàn toàn. Hacker chỉ cần đoán hoặc phân tích ngôn ngữ tự nhiên của một phía là có thể dịch ngược 100% nội dung của CẢ HAI đoạn văn bản gốc mà không cần phải giải mã ra Key của chúng ta.

### b. Tại sao CTR KHÔNG đảm bảo tính xác thực (Authenticity)?
Chế độ CTR là một dạng **Stream Cipher**, nó hoạt động bằng cách XOR keystream vào từng bit Plaintext riêng lẻ một cách tuần tự. Nó **chỉ cung cấp tính bảo mật (Confidentiality)** để che giấu nội dung, nhưng nó hoàn toàn mù trước việc nội dung bị chỉnh sửa trên đường truyền (Tampering).
Nếu Hacker biết vị trí của từ "BUY" trong file văn bản được mã hoá, hacker có thể dễ dàng đảo ngược vài bit nhắm mục tiêu (bit-flipping attack) để ép phía nhận giải mã ra chữ "SELL" mà không làm hỏng toàn bộ cấu trúc file. (Bạn có thể xem minh hoạ kịch bản này ở script `run_negative_tests.ps1`).

### c. Sự cần thiết của MAC (Message Authentication Code) và thuật ngữ AEAD
Bởi vì lỗ hổng trên, CTR không bao giờ được phép sử dụng độc lập. Để bảo vệ dữ liệu khỏi việc bị chỉnh sửa trái phép, CTR bắt buộc phải đi kèm với một chữ ký xác thực khối (ví dụ như HMAC hoặc GMAC). Hệ thống sẽ sinh chữ ký từ Ciphertext, người nhận sẽ kiểm tra chữ ký (Tag) trước khi tiến hành giải mã. Nếu chữ ký không khớp, file sẽ bị ném bỏ ngay lập tức.
Cấu trúc kết hợp MÃ HOÁ (Encryption) + XÁC THỰC (Authentication) này được gọi chung là **AEAD** (Authenticated Encryption with Associated Data). Một trong những AEAD nổi tiếng nhất phát triển từ CTR là **AES-GCM**.

---

## 3. Vai trò của Tăng tốc Phần cứng (Hardware Acceleration)

### a. Sự ra đời của tập lệnh AES-NI
Để giải quyết tất cả các yếu điểm của AES thuần mềm (Software Implementation) bao gồm cả Hiệu năng chậm chạp và Lỗ hổng Side-Channel, các nhà sản xuất vi xử lý (Intel, AMD, ARM) đã nhúng sẵn thuật toán AES vào cấu trúc bán dẫn dưới dạng các tập lệnh mở rộng (AES-NI - AES New Instructions). 
Thay vì dùng mảng bộ nhớ (Table-based) và code C++ vòng lặp tốn kém, lập trình viên có thể đẩy thẳng khối dữ liệu vào phần cứng CPU. CPU sẽ xử lý một vòng AES chỉ trong 1-2 chu kỳ xung nhịp (clock cycles) thông qua mạch logic điện tử chuyên biệt.

### b. Đánh đổi giữa Hiệu năng và Bảo mật (Performance vs Security trade-offs)
- **Tốc độ (Throughput):** AES-NI có thể đạt tốc độ mã hoá hàng Gigabytes/giây, nhanh hơn hàng chục lần so với mã nguồn C++ thuần do không tốn chi phí rẽ nhánh, đọc ghi bộ nhớ. (Bạn có thể chạy thử OpenSSL so với aestool trong script test).
- **Bảo mật:** Quan trọng hơn cả tốc độ, do AES-NI chạy trên hệ thống mạch tổ hợp thuần luồng, không hề truy cập cache L1/L2 và có thời gian thực thi hằng số (**Constant-time execution**), nó **tự động vá mọi lỗ hổng Timing Attack và Cache-based Attack** được đề cập ở Phần 1.

Đây là lý do vì sao trong thực tế sản xuất, không một kĩ sư nào dùng bản AES tự code bằng C++ để phục vụ người dùng cuối mà luôn phải gọi thư viện hạ tầng (OpenSSL, Crypto++) để thư viện đó trực tiếp gọi hàm tăng tốc độ phần cứng AES-NI của thiết bị tương ứng.

---

## 4. Chế độ Mã hóa Ổ đĩa (AES-XTS)

### a. Cơ chế hoạt động (Two-key construction & Tweak multiplication)
AES-XTS (XEX-based tweaked-codebook mode with ciphertext stealing) là tiêu chuẩn vàng hiện nay cho việc mã hóa ổ đĩa toàn phần (Full Disk Encryption) như BitLocker (Windows), FileVault (macOS) và LUKS (Linux). 

Chế độ này giải quyết được vấn đề "thao túng vị trí" (copy-paste blocks) trên ổ đĩa bằng cách áp dụng một tham số **Tweak** (được khởi tạo từ địa chỉ Sector/LBA của ổ đĩa). 
- XTS sử dụng 2 khóa (Two-key construction): `Key1` dùng để mã hóa khối dữ liệu (Core block encryption), và `Key2` dùng để mã hóa Tweak khởi tạo ban đầu.
- **Tweak multiplication**: Với mỗi block tiếp theo trong cùng một Sector ổ đĩa, Tweak không đứng yên mà được nhân với đa thức $\alpha$ (alpha) trong trường hữu hạn Galois $GF(2^{128})$. Kết quả của phép nhân sẽ thay đổi toàn bộ bit của block trước khi được đưa vào bộ mã hóa AES (pre-XOR) và sau khi đi ra (post-XOR). 

### b. Disk Encryption Use Case (Ứng dụng thực tế)
- Nhờ Tweak thay đổi liên tục trên từng Sector và từng Block, **cùng một nội dung (Plaintext) nằm ở hai vị trí khác nhau trên ổ cứng sẽ tạo ra hai Ciphertext hoàn toàn khác nhau**. Điều này chặn đứng các cuộc tấn công Watermarking.
- Vì XTS mã hóa song song từng Block 16-byte một cách độc lập (chỉ phụ thuộc vào Tweak), tốc độ truy xuất ngẫu nhiên (Random Read/Write IOPS) của ổ đĩa không hề bị suy giảm - điều mà CBC hay CTR không làm được tốt bằng.
