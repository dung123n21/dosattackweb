
# DOS Attack Web (Demo)

Repo này cung cấp hướng dẫn cách build và chạy một chương trình kiểm thử tải (load testing) trên môi trường Linux.
**Chỉ dùng cho mục đích kiểm thử server hợp pháp – tuyệt đối không sử dụng vào các mục đích trái pháp luật.**

---
## discord
**https://discord.gg/WGBUtqvM**
---

## 1. Clone repository

```bash
git clone https://github.com/dung123n21/dosattackweb.git
cd dosattackweb
```

---

## 2. Cài đặt các gói cần thiết

```bash
sudo apt update && sudo apt install -y   build-essential   gcc   g++   make   libssl-dev   libnghttp2-dev   pkg-config   libpthread-stubs0-dev   wget   curl
```

---

## 3. Build chương trình

```bash
gcc hello.c -o attack   -I/usr/include/nghttp2   -L/usr/lib/x86_64-linux-gnu   -lnghttp2 -lssl -lcrypto -lpthread   -Wno-format-truncation
```

---

## 4. Chạy chương trình

```bash
./attack [url]
```

### Ví dụ

```bash
./attack https://example.com
```

---

## 5. Lưu ý quan trọng

- Chỉ chạy trên server thuộc quyền sở hữu của bạn.
- Dùng trong môi trường thử nghiệm riêng như VPS hoặc mạng nội bộ.
- Việc sử dụng công cụ này trên server không được phép có thể vi phạm pháp luật.
