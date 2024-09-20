# Web Vulnerability Scanner

## Giới thiệu
Web Vulnerability Scanner là một công cụ giúp phát hiện các lỗ hổng bảo mật phổ biến trên các trang web. Công cụ này hỗ trợ kiểm tra nhiều loại lỗ hổng, bao gồm XSS, SQL Injection, CORS, và kiểm tra cấu hình SSL/TLS.

## Tính năng
- **Quét XSS**: Phát hiện lỗ hổng Cross-Site Scripting.
- **Quét SQL Injection**: Kiểm tra khả năng bị tấn công SQL Injection.
- **Kiểm tra SSL/TLS**: Đảm bảo rằng trang web sử dụng HTTPS và kiểm tra chứng chỉ SSL.
- **Kiểm tra tiêu đề bảo mật**: Phát hiện các tiêu đề bảo mật thiếu sót.
- **Quét CORS**: Kiểm tra cấu hình CORS và phát hiện lỗ hổng.
- **Tích hợp Shodan API**: Tìm kiếm thông tin về máy chủ mục tiêu từ Shodan.
- **Hỗ trợ session cookie**: Quét các trang yêu cầu đăng nhập với session cookie.

## Cài đặt

### Yêu cầu
- Python 3.x
- Các thư viện cần thiết sẽ được cài đặt thông qua `install.py`.

## Sử dụng

### Clone/Run
Sau khi cài đặt, bạn có thể chạy chương trình bằng lệnh:

```bash
git clone https://github.com/dhungx/W scanweb
cd scanweb
python install.py
```
Run
```
python awvs.py
```

### Thông tin đầu vào
Khi chạy chương trình, bạn sẽ được yêu cầu nhập các thông tin sau:
1. **URL mục tiêu**: Địa chỉ trang web cần quét.
2. **Proxy (tùy chọn)**: Nếu bạn cần sử dụng proxy, hãy nhập địa chỉ proxy.
3. **Session cookie (tùy chọn)**: Nhập cookie phiên nếu cần quét trang yêu cầu đăng nhập.
4. **Shodan API key (tùy chọn)**: Nhập khóa API Shodan để tích hợp tìm kiếm thông tin.

### Định dạng báo cáo
Kết quả quét sẽ được lưu dưới dạng:
- **Text**
- **JSON**
- **HTML**

## Liên hệ
Nếu bạn có câu hỏi hoặc đề xuất, vui lòng liên hệ với chúng tôi qua email hoặc tạo issue trên GitHub.

## Giấy phép
Dự án này được cấp phép theo [Giấy phép MIT](LICENSE).