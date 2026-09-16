# Dịch vụ FTP, SFTP, SMTP, POP3 và IMAP: nguyên lý hoạt động, cài đặt, quản trị, nguy cơ bị tấn công, kỹ thuật phát hiện sớm và biện pháp phòng ngừa

## Lời mở đầu

Tài liệu này là sản phẩm nghiên cứu của đồ án Hệ điều hành Windows–Linux, tập trung vào năm dịch vụ mạng kinh điển mà mọi quản trị viên hệ thống Unix-like đều phải gặp: **FTP** và **SFTP** cho truyền tệp, **SMTP**, **POP3** và **IMAP** cho hệ thống thư điện tử. Đối tượng hướng tới là sinh viên công nghệ thông tin và người quản trị hệ thống muốn hiểu *bản chất* giao thức — kiến trúc kênh, phiên lệnh, bắt tay TLS — thay vì chỉ copy-paste cấu hình; bởi phần lớn sự cố bảo mật thực tế bắt nguồn từ cấu hình sai (misconfiguration) mà người vận hành không đủ nền tảng để nhận ra.

Phạm vi tài liệu trải suốt vòng đời khai thác một dịch vụ: từ nền tảng mạng (TCP/UDP, port, mô hình client–server, Active/Passive), nguyên lý hoạt động từng giao thức, cài đặt và quản trị trên Ubuntu Server (vsftpd, OpenSSH, Postfix, Dovecot), công cụ phía client và giám sát (FileZilla, Thunderbird, Wireshark, UFW, Fail2ban, nhật ký hệ thống), đến phân tích nguy cơ tấn công, kỹ thuật phát hiện sớm qua log/metric, biện pháp phòng ngừa và gia cố, thiết kế phòng lab cùng ba kịch bản demo, và cuối cùng là chuẩn bị báo cáo. Hệ thống phụ lục A–F hỗ trợ lộ trình học theo thứ tự, kế hoạch 7 ngày, thuật ngữ, câu tự kiểm tra và danh mục tài liệu chuẩn (RFC, tài liệu Ubuntu).

**Cam kết đạo đức và an toàn:** mọi kỹ thuật tấn công trong tài liệu chỉ được mô tả ở mức nguyên lý và dấu hiệu nhận biết, phục vụ mục đích giáo dục. Toàn bộ thao tác thực hành **chỉ được phép diễn ra trong phòng lab mạng riêng do nhóm tự dựng** (mạng host-only/NAT giữa các máy ảo thuộc quyền kiểm soát của nhóm). **Không** quét cổng, dò mật khẩu, giả mạo thư, chặn phiên (MITM) hay thực hiện bất kỳ hành vi nào tương tự trên hệ thống công cộng, máy chủ của bên thứ ba hoặc mạng không thuộc sở hữu của bạn — những hành vi đó vi phạm pháp luật an ninh mạng và quy chế của mọi tổ chức.

## Hướng dẫn đọc

- **Chương 1 — Kiến thức mạng nền tảng:** nên đọc trước nếu bạn chưa vững về TCP/UDP, cổng dịch vụ, mô hình client–server, DNS/MX, NAT và tường lửa — nền móng để hiểu mọi chương sau.
- **Chương 2a — Nguyên lý FTP/FTPS/SFTP:** kiến trúc hai kênh của FTP, Active vs Passive, khác biệt bản chất giữa FTPS và SFTP, phiên giao dịch mẫu và cách quan sát trong lab.
- **Chương 2b — Nguyên lý email (SMTP/POP3/IMAP):** đường đi của một bức thư từ MUA đến mailbox người nhận, các lệnh SMTP/POP3/IMAP, hàng đợi mail, relay và xác thực SASL.
- **Chương 3a — Phần mềm phía server:** vai trò, file cấu hình, log và các tham số bảo mật quan trọng của vsftpd, OpenSSH, Postfix, Dovecot (kiến thức "đọc trước", không phải cấu hình hoàn chỉnh).
- **Chương 3b — Client và công cụ giám sát:** FileZilla, Thunderbird, Wireshark, UFW, Fail2ban và hệ thống nhật ký — bộ đồ nghề quản trị hằng ngày.
- **Chương 4a — Nguy cơ nhóm xác thực & FTP:** brute-force, PASS_THE_HASH/credential stuffing, FTP anonymous, directory traversal, SSH sai cấu hình — theo khung Nguyên nhân → Điều kiện → Dấu hiệu log → Ảnh hưởng → Phòng ngừa.
- **Chương 4b — Nguy cơ nhóm email & TLS:** open relay, email spoofing, lạm dụng hàng đợi, flooding, TLS cấu hình sai/yếu, phần mềm EOL — cùng khung phân tích với log mẫu Postfix/Dovecot.
- **Chương 5 — Phát hiện sớm qua log và metric:** biến dấu vết trong log thành cảnh báo có ngưỡng: đếm fail theo IP, velocity anomaly, baseline, queue depth, phát hiện thay đổi file hệ thống.
- **Chương 6 — Phòng ngừa và gia cố:** tắt dịch vụ thừa, bắt buộc TLS/SFTP, key-based SSH, jail Fail2ban, SPF/DKIM/DMARC, chiến lược update và hardening theo nguyên lý tối thiểu hoá.
- **Chương 7 — Thiết kế phòng lab & ba kịch bản demo:** mạng host-only cô lập, CA tự ký, và ba demo trọn vẹn (FTP plaintext vs SFTP, brute-force có kiểm soát, open relay rồi khắc phục) kèm chuẩn bị – thực hiện – bằng chứng – kiểm thử lại.
- **Chương 8 — Chuẩn bị báo cáo:** bố cáo bố cục báo cáo học thuật, bảng tổng hợp, quy ước đặt tên/che thông tin khi chụp ảnh chứng minh, checklist tiêu chí demo thành công.
- **Phụ lục A/B/F:** lộ trình học theo thứ tự, kế hoạch 7 ngày, phân biệt nội dung bắt buộc vs nâng cao.
- **Phụ lục C/D/E:** bảng thuật ngữ, 20 câu tự kiểm tra kèm đáp án, danh mục RFC và tài liệu chính thức.

## Mục lục

1. [Kiến thức mạng nền tảng cần biết](#1-kiến-thức-mạng-nền-tảng-cần-biết)
2. [Nguyên lý hoạt động: FTP, FTPS và SFTP](#2a-nguyên-lý-hoạt-động-ftp-ftps-và-sftp)
3. [Nguyên lý hoạt động: SMTP, POP3, IMAP và luồng email](#2b-nguyên-lý-hoạt-động-smtp-pop3-imap-và-luồng-email)
4. [Phần mềm triển khai trên Ubuntu Server: vsftpd, OpenSSH, Postfix, Dovecot](#3a-phần-mềm-triển-khai-trên-ubuntu-server-vsftpd-openssh-postfix-dovecot)
5. [Công cụ phía client và giám sát: FileZilla, Thunderbird, Wireshark, UFW, Fail2ban, nhật ký hệ thống](#3b-công-cụ-phía-client-và-giám-sát-filezilla-thunderbird-wireshark-ufw-fail2ban-nhật-ký-hệ-thống)
6. [Nguy cơ và lỗ hổng: nhóm xác thực, FTP và quyền file](#4a-nguy-cơ-và-lỗ-hổng-nhóm-xác-thực-ftp-và-quyền-file)
7. [Nguy cơ và lỗ hổng: nhóm email, TLS và vòng đời phần mềm](#4b-nguy-cơ-và-lỗ-hổng-nhóm-email-tls-và-vòng-đời-phần-mềm)
8. [Kỹ thuật phát hiện sớm qua log và metric](#5-kỹ-thuật-phát-hiện-sớm-qua-log-và-metric)
9. [Biện pháp phòng ngừa và gia cố](#6-biện-pháp-phòng-ngừa-và-gia-cố)
10. [Thiết kế phòng lab an toàn và ba kịch bản demo](#7-thiết-kế-phòng-lab-an-toàn-và-ba-kịch-bản-demo)
11. [Chuẩn bị báo cáo và tiêu chí đánh giá](#8-chuẩn-bị-báo-cáo-và-tiêu-chí-đánh-giá)
12. [Phụ lục A/B/F: Checklist học theo thứ tự, kế hoạch 7 ngày, phân biệt bắt buộc vs nâng cao](#phụ-lục-abf-checklist-học-theo-thứ-tự-kế-hoạch-7-ngày-phân-biệt-bắt-buộc-vs-nâng-cao)
13. [Phụ lục C/D/E: Thuật ngữ, 20 câu tự kiểm tra, danh mục tài liệu chính thức](#phụ-lục-cde-thuật-ngữ-20-câu-tự-kiểm-tra-danh-mục-tài-liệu-chính-thức)

## Ghi chú phiên bản

- Phiên bản tài liệu: **1.0** — tổng hợp từ các chương thành phần (sec-01 đến sec-10), tháng **8/2026**.
- Bối cảnh hệ thống tham chiếu: Ubuntu Server (LTS 26.04), vsftpd, OpenSSH, Postfix, Dovecot, UFW, Fail2ban; các RFC được dẫn đầy đủ ở Phụ lục E.
- Bản chỉnh sửa từng chương vẫn được giữ riêng trong thư mục `sections/` để tiện cập nhật; tài liệu này là bản ghép liền mạch để đọc và nộp.
