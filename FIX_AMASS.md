# Fix Amass Permission Issues

## 🔴 Vấn đề

1. **Permission denied khi đọc config file:**
   ```
   Failed to load the configuration file: open amass/config.ini: permission denied
   ```

2. **Permission denied khi chạy với sudo:**
   ```
   cannot create user data directory: /root/snap/amass/887: Permission denied
   ```

## ✅ Giải pháp

### Cách 1: Fix ownership của config file (Recommended)

```bash
# Fix ownership
sudo chown $USER:$USER ~/amass/config.ini
sudo chmod 644 ~/amass/config.ini

# Chạy amass không cần sudo
amass enum -config ~/amass/config.ini -d example.com
```

### Cách 2: Copy config vào thư mục user

```bash
# Tạo thư mục config cho user
mkdir -p ~/.config/amass

# Copy config file
sudo cp ~/amass/config.ini ~/.config/amass/config.ini
sudo chown $USER:$USER ~/.config/amass/config.ini

# Chạy amass với config mới
amass enum -config ~/.config/amass/config.ini -d example.com
```

### Cách 3: Dùng đường dẫn tuyệt đối

```bash
# Chạy với đường dẫn đầy đủ
amass enum -config /home/nhantieu/amass/config.ini -d example.com
```

### Cách 4: Fix snap directory (nếu vẫn cần sudo)

```bash
# Tạo và fix quyền snap directory
sudo mkdir -p /root/snap/amass/887
sudo chmod 755 /root/snap/amass/887

# Hoặc dùng user's snap directory
mkdir -p ~/snap/amass/887
# Copy config nếu cần
```

## 🚀 Quick Fix Script

Chạy script tự động:

```bash
chmod +x fix_amass_permissions.sh
./fix_amass_permissions.sh
```

Script sẽ:
- Fix ownership của `~/amass/config.ini`
- Fix quyền snap directory nếu cần
- Hướng dẫn chạy amass đúng cách

## 📝 Lưu ý

1. **Không chạy amass với sudo** - Snap packages không nên chạy với sudo
2. **Dùng đường dẫn đầy đủ** - `~/amass/config.ini` hoặc `/home/nhantieu/amass/config.ini`
3. **Kiểm tra quyền file** - `ls -la ~/amass/config.ini` phải show `nhantieu nhantieu`

## ✅ Test

Sau khi fix, test lại:

```bash
# Test đọc config
amass enum -config ~/amass/config.ini -d example.com -list

# Hoặc test với domain thật
amass enum -config ~/amass/config.ini -d example.com
```

## 🔍 Troubleshooting

### Vẫn bị permission denied

```bash
# Kiểm tra ownership
ls -la ~/amass/config.ini

# Fix lại nếu cần
sudo chown -R $USER:$USER ~/amass/
```

### Snap directory issues

```bash
# Kiểm tra snap directory
ls -la ~/snap/amass/ 2>/dev/null || echo "No user snap directory"

# Tạo nếu cần
mkdir -p ~/snap/amass
```

