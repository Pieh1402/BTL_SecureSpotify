# SecureSpotify

SecureSpotify là một ứng dụng web cho phép người dùng upload, mã hóa, lưu trữ và tải về các file (âm thanh, tài liệu, hình ảnh, video...) một cách an toàn, sử dụng các kỹ thuật mật mã hiện đại như RSA, AES-GCM, xác thực chữ ký số và kiểm tra toàn vẹn dữ liệu. Ứng dụng mô phỏng quy trình truyền file bảo mật qua socket, phù hợp cho mục đích học tập và trình diễn các chủ đề về bảo mật thông tin.

## Tính năng chính

- **Upload file an toàn:**  
  File được mã hóa bằng AES-GCM, khóa phiên được trao đổi qua RSA, có kiểm tra toàn vẹn và xác thực chữ ký số.
- **Tải file tự động:**  
  Tự động giải mã file khi tải về, kiểm tra toàn vẹn và xác thực tính đúng đắn của dữ liệu.
- **Quản lý khóa và gói tin:**  
  Lưu trữ thông tin khóa phiên, metadata, và gói tin socket để dễ dàng kiểm tra, trình diễn.
- **Mô phỏng tấn công sửa đổi:**  
  Hỗ trợ tùy chọn giả lập việc sửa đổi dữ liệu để kiểm tra khả năng phát hiện tấn công.
- **Giao diện web đơn giản, dễ sử dụng:**  
  Sử dụng Flask, HTML, CSS, JS.

## Cấu trúc thư mục

```
SecureSpotify/
│
├── app.py                # Flask app chính, định nghĩa các route và logic upload/download
├── crypto_service.py     # Xử lý mã hóa, giải mã, tạo khóa, ký số, kiểm tra toàn vẹn
├── socket_service.py     # Mô phỏng giao tiếp socket, handshake, upload file qua socket
├── main.py               # Khởi động ứng dụng (nếu cần)
│
├── static/               # Thư mục chứa file tĩnh (CSS, JS)
├── templates/            # Thư mục chứa template HTML
│
└── uploads/              # Thư mục lưu file upload, file mã hóa, file giải mã, metadata, keys, packets
    ├── keys/             # Lưu file chứa session key cho từng file
    ├── packets/          # Lưu thông tin gói tin socket (dạng JSON)
    └── ...               # Các file upload, file info, file giải mã
```

## Hướng dẫn cài đặt & chạy

### 1. Cài đặt môi trường

- Yêu cầu Python 3.7+
- Cài đặt các thư viện cần thiết:
  
```bash
pip install flask pycryptodome
```

### 2. Chạy ứng dụng

```bash
cd SecureSpotify
python app.py
```

- Ứng dụng sẽ chạy ở địa chỉ: http://192.168.0.109:4000/

### 3. Sử dụng

- Truy cập `/` để vào trang chủ.
- Chọn **Upload** để tải file lên (các định dạng hỗ trợ: mp3, wav, flac, txt, pdf, doc, docx, jpg, png, mp4, avi).
- Sau khi upload thành công, bạn sẽ nhận được `file_id` và `session_key` để tải file về.
- Truy cập **Download** để xem danh sách file và tải về (giải mã tự động).
- Truy cập **/keys** để xem danh sách các khóa phiên đã lưu.
- Truy cập **/packets** để xem thông tin các gói tin socket đã upload.

## Công nghệ sử dụng

- **Flask**: Web framework cho Python.
- **PyCryptodome**: Thư viện mã hóa (AES, RSA, SHA-512).
- **HTML/CSS/JS**: Giao diện người dùng.

## Ghi chú bảo mật

- Ứng dụng này phục vụ mục đích học tập, trình diễn các kỹ thuật bảo mật, không khuyến nghị sử dụng cho môi trường sản xuất thực tế.
- Khóa RSA, session key, metadata, signature... đều được lưu dưới dạng file để tiện kiểm tra, minh họa.

## Đóng góp

Mọi đóng góp, ý kiến hoặc báo lỗi xin gửi về nhóm phát triển hoặc tạo issue trên repository. 
