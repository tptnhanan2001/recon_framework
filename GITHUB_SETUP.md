# Hướng dẫn Push lên GitHub

## Bước 1: Cấu hình Git (chỉ cần làm 1 lần)

```bash
# Cấu hình tên và email của bạn
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Hoặc chỉ cho repo này (không dùng --global)
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

## Bước 2: Tạo commit đầu tiên

```bash
cd /home/nhantieu/recontool
git commit -m "Initial commit: Recon Tool - Automated Reconnaissance Tool"
```

## Bước 3: Tạo repository trên GitHub

1. Đăng nhập vào GitHub: https://github.com
2. Click nút **"+"** ở góc trên bên phải → **"New repository"**
3. Đặt tên repository (ví dụ: `recontool`)
4. **KHÔNG** tích vào "Initialize with README" (vì bạn đã có code rồi)
5. Click **"Create repository"**

## Bước 4: Kết nối và push lên GitHub

Sau khi tạo repository, GitHub sẽ hiển thị các lệnh. Chạy các lệnh sau:

```bash
# Thêm remote (thay YOUR_USERNAME và REPO_NAME bằng thông tin của bạn)
git remote add origin https://github.com/YOUR_USERNAME/REPO_NAME.git

# Hoặc nếu dùng SSH:
# git remote add origin git@github.com:YOUR_USERNAME/REPO_NAME.git

# Đổi tên branch từ master sang main (nếu muốn)
git branch -M main

# Push code lên GitHub
git push -u origin main
# Hoặc nếu vẫn dùng master:
# git push -u origin master
```

## Bước 5: Xác thực (nếu cần)

- Nếu dùng HTTPS: GitHub sẽ yêu cầu nhập username và password (hoặc Personal Access Token)
- Nếu dùng SSH: Đảm bảo SSH key đã được thêm vào GitHub

## Lệnh nhanh (tất cả trong một)

```bash
# 1. Cấu hình git (thay thông tin của bạn)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# 2. Commit
git commit -m "Initial commit: Recon Tool - Automated Reconnaissance Tool"

# 3. Thêm remote (thay YOUR_USERNAME/REPO_NAME)
git remote add origin https://github.com/YOUR_USERNAME/REPO_NAME.git

# 4. Đổi tên branch sang main
git branch -M main

# 5. Push
git push -u origin main
```

## Lưu ý

- File `.gitignore` đã được tạo để loại bỏ các file không cần thiết (logs, output, cache, etc.)
- Các thư mục `recon_*`, `recon_output/`, `uploads/` sẽ không được commit
- File `auth.log`, `.auth_session.json` cũng sẽ bị bỏ qua

## Cập nhật code sau này

```bash
git add .
git commit -m "Mô tả thay đổi"
git push
```

