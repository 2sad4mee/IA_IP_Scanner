# 🛡️ IA IP Scanner (Information Assurance Edition v2.0)

Công cụ quét mạng nội bộ (LAN), kiểm toán cổng dịch vụ (Port Auditing) và quản trị hệ thống từ xa dành cho Windows, được phát triển bằng Python với giao diện Dark Mode hiện đại.

## ✨ Tính năng nổi bật
- **Quét mạng đa luồng tốc độ cao:** Hỗ trợ dải IP (`192.168.1.1-254`), CIDR (`192.168.1.0/24`) và danh sách IP tùy chỉnh.
- **TCP Ping Fallback:** Phát hiện cả những thiết bị bật tường lửa chặn gói tin ICMP Echo (Ping).
- **Nhận diện Hệ điều hành & Thiết bị:** Dự đoán OS qua giá trị `TTL`, phân giải Hostname qua DNS & NetBIOS (`nbtstat`), tra cứu hãng sản xuất qua địa chỉ MAC (OUI Vendor).
- **Kiểm toán Cổng & Thư mục chia sẻ:** Quét song song các cổng dịch vụ phổ biến (`HTTP`, `HTTPS`, `FTP`, `SSH`, `SMB`, `RDP`), hỗ trợ **Custom Ports** và tự động liệt kê các thư mục chia sẻ SMB (`net view`).
- **Tác vụ Quản trị nhanh:** Mở trực tiếp Web, Explorer Share (`\\IP\Share`), Remote Desktop (`mstsc`), SSH, Wake-on-LAN (Magic Packet) và Remote Shutdown.
- **Xuất Báo cáo An toàn thông tin:** Hỗ trợ xuất ra định dạng **HTML (Dark Theme)**, **CSV** và **XML**.

## 🚀 Cách cài đặt & Sử dụng

### 1. Chạy trực tiếp từ mã nguồn
Yêu cầu máy đã cài đặt **Python 3.8+**:
```bash
git clone [https://github.com/](https://github.com/)2sad4mee/IA-IP-Scanner.git
cd IA-IP-Scanner
