# DNSenum Output Format

## Tổng quan

DNSenum có thể output theo nhiều format khác nhau tùy thuộc vào version và options được sử dụng. Tool hiện tại đã được thiết kế để xử lý các format phổ biến.

## Các Format Output Phổ Biến

### Format 1: DNS Zone Format (Standard)
```
dnsenum version 1.2.6
Starting enumeration of example.com
dnsenum: example.com
example.com.                    3600    IN    A        93.184.216.34
www.example.com.                3600    IN    A        93.184.216.34
mail.example.com.               3600    IN    A        93.184.216.34
subdomain.example.com.          3600    IN    A        192.0.2.1
```

**Đặc điểm:**
- Mỗi dòng chứa subdomain, TTL, record type, và IP
- Subdomain có thể kết thúc bằng dấu chấm (.)
- Format: `subdomain.domain.com.    TTL    IN    TYPE    IP`

### Format 2: Bracket Format
```
[+] Found: www.example.com (A: 93.184.216.34)
[+] Found: mail.example.com (A: 93.184.216.34)
[+] Found: subdomain.example.com (A: 192.0.2.1)
```

**Đặc điểm:**
- Có prefix `[+] Found:` hoặc `[INFO]`
- Subdomain trong ngoặc đơn hoặc sau dấu `:`
- Format: `[PREFIX] subdomain.domain.com (TYPE: IP)`

### Format 3: Simple List Format
```
www.example.com
mail.example.com
subdomain.example.com
test.example.com
```

**Đặc điểm:**
- Mỗi dòng chỉ chứa subdomain
- Không có thông tin bổ sung
- Format đơn giản nhất

### Format 4: Info Format
```
dnsenum v1.2.6
Target: example.com
[INFO] Starting DNS enumeration...
[INFO] Found: www.example.com -> 93.184.216.34
[INFO] Found: mail.example.com -> 93.184.216.34
[INFO] Enumeration complete.
```

**Đặc điểm:**
- Có log messages với `[INFO]`
- Subdomain sau `Found:` và trước `->`
- Format: `[INFO] Found: subdomain.domain.com -> IP`

### Format 5: Zone File Format
```
;; DNS Enumeration Results for example.com
www.example.com.                3600    IN    A        93.184.216.34
mail.example.com.               3600    IN    A        93.184.216.34
```

**Đặc điểm:**
- Có comment lines bắt đầu bằng `;;`
- Format giống Format 1 nhưng có comments

## Cách Tool Xử Lý

Tool `dnsenum.py` hiện tại xử lý output bằng cách:

1. **Đọc raw output** từ dnsenum command
2. **Parse từng dòng** và tách thành các parts
3. **Tìm subdomain** bằng cách:
   - Tìm các phần chứa target domain
   - Validate format (phải có ít nhất 2 dấu chấm)
   - Loại bỏ các ký tự đặc biệt (., [], (), {}, ", ')
   - Chỉ lấy subdomain (không lấy root domain)

4. **Lưu vào file** `dnsenum_<domain>.txt` với format:
   ```
   subdomain1.example.com
   subdomain2.example.com
   subdomain3.example.com
   ```

## Test Results

Test script đã được tạo tại `test_dnsenum_output.py` để kiểm tra parsing logic.

**Kết quả:** Tool có thể parse thành công tất cả 5 format trên và extract subdomains chính xác.

## Output File Format

File output cuối cùng (`dnsenum_<domain>.txt`) có format đơn giản:
- Mỗi dòng một subdomain
- Sorted alphabetically
- Lowercase
- Không có trailing dots
- Không có comments hoặc metadata

**Ví dụ:**
```
ftp.example.com
mail.example.com
subdomain.example.com
test.example.com
www.example.com
```

## Lưu ý

- Tool tự động bỏ qua:
  - Comment lines (bắt đầu bằng `#` hoặc `;`)
  - Empty lines
  - Root domain (chỉ lấy subdomains)
  - Invalid formats

- Tool sẽ extract subdomain từ bất kỳ vị trí nào trong dòng nếu nó chứa target domain và có format hợp lệ.

