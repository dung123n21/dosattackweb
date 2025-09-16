# DOS Attack Web (Demo)

Repo này cung cấp hướng dẫn cách build và chạy một chương trình kiểm thử tải (load testing) trên môi trường Linux.  
**Chỉ dùng cho mục đích kiểm thử server hợp pháp** – tuyệt đối không sử dụng vào các mục đích trái pháp luật.

---

## 1. Clone repository

```bash
git clone https://github.com/dung123n21/dosattackweb.git
cd dosattackweb

---

###2. Cài đặt các gói cần thiết

sudo apt update && sudo apt install -y \
  build-essential \
  gcc \
  g++ \
  make \
  libssl-dev \
  libnghttp2-dev \
  pkg-config \
  libpthread-stubs0-dev \
  wget \
  curl

---

##3. Build

gcc hello.c -o attack \
  -I/usr/include/nghttp2 \
  -L/usr/lib/x86_64-linux-gnu \
  -lnghttp2 -lssl -lcrypto -lpthread \
  -Wno-format-truncation

---

##4. Run

./attack [url]

---

## ví dụ

./attack https://example.com
