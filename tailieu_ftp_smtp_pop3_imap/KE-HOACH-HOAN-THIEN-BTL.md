# Kế hoạch hoàn thiện bài tập lớn

## Dịch vụ FTP, SFTP, SMTP, POP3, IMAP

> Tài liệu này là checklist triển khai bài tập lớn: cần tìm hiểu gì, dựng lab ra sao, demo attack/defense thế nào, thu thập bằng chứng gì và trích dẫn nguồn nào. Các bài kiểm thử chỉ được thực hiện trên máy ảo/mạng lab do nhóm sở hữu.

## 1. Mục tiêu và sản phẩm cần nộp

### Mục tiêu kiến thức

- Giải thích được mục đích, mô hình client-server, phiên làm việc và cổng mặc định của FTP, SFTP, SMTP, POP3, IMAP.
- Phân biệt rõ **FTP**, **FTPS** và **SFTP**; không gọi SFTP là FTP có SSL.
- Mô tả được đường đi của email: mail client -> SMTP submission -> MTA -> mailbox -> POP3/IMAP client.
- Chỉ ra rủi ro do truyền rõ, xác thực yếu, quyền sai, relay sai, thiếu TLS và phần mềm chưa cập nhật.
- Chứng minh được một rủi ro bằng capture/log trong lab, sau đó bật biện pháp phòng thủ và kiểm thử lại.
- Xây dựng được cách phát hiện sớm dựa trên log, metric, baseline và cảnh báo.

### Sản phẩm nên chuẩn bị

- Báo cáo Markdown/Word/PDF theo bố cục ở mục 7.
- Bộ cấu hình lab đã làm sạch thông tin nhạy cảm.
- Ba kịch bản demo chính và các mini-test cho đủ năm dịch vụ.
- Ảnh chụp màn hình, file capture `.pcapng`, log trước/sau và transcript kết quả.
- Sơ đồ mạng, bảng phân công thành viên, danh mục nguồn tham khảo.
- Video dự phòng hoặc ảnh dự phòng nếu demo trực tiếp gặp lỗi.

Tài liệu chi tiết đã có trong thư mục này:

- `Tai-lieu-nghien-cuu-FTP-SMTP-POP3-IMAP.md`: bản nghiên cứu ghép đầy đủ.
- `sections/sec-02a-nguyen-ly-ftp-sftp.md`: nguyên lý FTP/FTPS/SFTP.
- `sections/sec-02b-nguyen-ly-email.md`: SMTP/POP3/IMAP và luồng thư.
- `sections/sec-04a-nguy-co-xac-thuc-ftp.md`: nguy cơ xác thực, FTP và quyền file.
- `sections/sec-04b-nguy-co-email-tls.md`: nguy cơ email, TLS và relay.
- `sections/sec-05-phat-hien-som.md`: log, metric và cảnh báo.
- `sections/sec-06-phong-ngua-gia-co.md`: hardening.
- `sections/sec-07-phong-lab.md`: topology và kịch bản lab chi tiết.
- `sections/sec-08-chuan-bi-bao-cao.md`: bố cục báo cáo và checklist ảnh.
- `sections/sec-10-phu-luc-C-D-E.md`: thuật ngữ, câu hỏi ôn tập và danh mục nguồn.

## 2. Phạm vi phải nghiên cứu

### 2.1. Bảng tổng quan bắt buộc

| Dịch vụ | Chức năng | Cổng rõ thường gặp | Cổng bảo vệ | Điểm cần giải thích |
|---|---|---:|---:|---|
| FTP | Truyền tệp | TCP 21; data thường 20 hoặc passive range | FTPS TCP 21/990 hoặc thay bằng SFTP TCP 22 | Hai kênh control/data, active/passive, plaintext, anonymous |
| SFTP | Truyền tệp trên SSH | TCP 22 | Đã mã hóa trong SSH | Không phải FTP + SSL; key authentication; phân quyền/chroot |
| SMTP | Gửi/chuyển tiếp thư | TCP 25 | Submission 587/465 | MTA/MUA/MSA, relay, `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA` |
| POP3 | Tải thư về client | TCP 110 | POP3S TCP 995 | Mailbox thường tải về; trạng thái xác thực và xóa thư |
| IMAP | Đọc/đồng bộ mailbox trên server | TCP 143 | IMAPS TCP 993 | Folder/flag/search, nhiều thiết bị, xác thực và TLS |

### 2.2. Nội dung lý thuyết cần có trong báo cáo

- TCP/IP, socket, port, DNS/MX, firewall và mô hình client-server.
- FTP control channel/data channel; active và passive mode.
- FTPS explicit `AUTH TLS` và implicit TLS; vì sao passive port range ảnh hưởng firewall.
- SFTP là subsystem của SSH; SSH transport, host key, user authentication và file permission.
- SMTP server-server và client-server; cổng 25 khác submission 587/465.
- POP3 và IMAP khác nhau về vị trí mailbox, đồng bộ, folder và cách dùng nhiều thiết bị.
- TLS, certificate, CA, hostname/SAN, STARTTLS và implicit TLS.
- SASL/AUTH; tuyệt đối phân biệt Base64 với mã hóa.
- SPF, DKIM, DMARC ở mức khái niệm và giới hạn của từng cơ chế.

## 3. Ma trận attack/defense/detection

| Dịch vụ | Kịch bản tấn công mô phỏng trong lab | Dấu hiệu phát hiện sớm | Phòng ngừa cần demo |
|---|---|---|---|
| FTP | Bắt phiên FTP rõ để thấy `USER/PASS`; anonymous access hoặc upload sai quyền; đăng nhập sai nhiều lần có kiểm soát | Wireshark thấy lệnh rõ; log vsftpd tăng `FAIL LOGIN`; upload ngoài thư mục cho phép | Tắt anonymous; ưu tiên SFTP/FTPS; bắt buộc TLS nếu phải dùng FTP; chroot; permission tối thiểu; fail2ban; giới hạn passive ports |
| SFTP | Thử đăng nhập sai có giới hạn để kiểm tra log SSH; kiểm tra user có thể đi ra ngoài thư mục được cấp hay không | `/var/log/auth.log` hoặc journal có `Failed password`; kết nối bất thường; file permission thay đổi | SSH key; tắt `PermitRootLogin`; cân nhắc tắt password login sau khi kiểm tra key; `AllowUsers`; chroot/subsystem; fail2ban; cập nhật OpenSSH |
| SMTP | Kiểm tra open relay bằng recipient thuộc domain lab giả lập; kiểm tra server từ chối relay sau hardening; không gửi ra Internet | Queue tăng; `Relay access denied`; nhiều `AUTH failed`; số lượng thư gửi tăng bất thường; log Postfix | `reject_unauth_destination`; tách 25 và 587; 587/465 bắt buộc TLS + AUTH; giới hạn rate/queue; SPF/DKIM/DMARC; không expose relay không cần thiết |
| POP3 | Quan sát banner và kiểm tra xác thực rõ trong lab; thử login sai có giới hạn | Wireshark thấy POP3 command nếu dùng 110; Dovecot log `Auth failed`; nhiều phiên từ một IP | Tắt POP3 nếu không cần; nếu cần dùng 995/TLS; `ssl = required`; mật khẩu mạnh; rate limit/fail2ban; giám sát login và mailbox |
| IMAP | Kiểm tra login rõ trên 143 trong lab; thử xác thực sai có giới hạn; truy cập mailbox bằng user không đúng quyền | Wireshark thấy IMAP command nếu không TLS; Dovecot `Disconnected (auth failed)`; login từ IP lạ | Ưu tiên 993/implicit TLS; bắt buộc TLS; tắt plaintext auth ngoài TLS; giới hạn mailbox/quyền; fail2ban; giám sát session |

Không cần biến mỗi dòng thành một công cụ tấn công riêng. Có thể dùng ba demo chính ở mục 5 và dùng banner, log, Wireshark, client hợp lệ để chứng minh các dịch vụ còn lại.

## 4. Thiết kế lab an toàn

### 4.1. Topology đề xuất

```text
                 Mạng Host-only/Internal: 192.168.100.0/24

       attacker/client                         server-file
       192.168.100.20                         192.168.100.10
       Wireshark, client                       FTP/FTPS, SSH/SFTP
              |                                      |
              +------------------+-------------------+
                                 |
                            server-mail
                            192.168.100.11
                            Postfix + Dovecot
```

Có thể gộp `server-file` và `server-mail` vào một VM nếu máy yếu, nhưng phải ghi rõ trong báo cáo. Dùng snapshot trước mỗi demo.

### 4.2. Quy tắc an toàn bắt buộc

- Chỉ dùng Host-only/Internal Network; không bridge vào mạng trường hoặc mạng gia đình.
- Chỉ dùng tài khoản, mật khẩu và file giả lập; không dùng credential thật.
- Không quét, brute-force, sniff, relay hay gửi thư tới hệ thống bên ngoài lab.
- Kiểm tra firewall trước khi chạy; khi kiểm thử relay chỉ dùng domain `.invalid`, `.example` hoặc domain nội bộ không route ra Internet.
- Không cấu hình open relay trên máy có đường ra Internet.
- Sau mỗi demo phải khôi phục cấu hình an toàn, unban IP test và chụp trạng thái sau hardening.
- Không đưa private key, `/etc/shadow`, IP công cộng, hostname máy thật hoặc mật khẩu thật vào ảnh/báo cáo.

### 4.3. Cấu hình và công cụ

| Nhóm | Gợi ý |
|---|---|
| Server file | Ubuntu Server, OpenSSH/SFTP, vsftpd hoặc một FTPS server |
| Server mail | Postfix + Dovecot IMAP/POP3 |
| Client | FileZilla hoặc `sftp`, Thunderbird, `openssl s_client` |
| Quan sát | Wireshark, `ss`, `tcpdump`, `journalctl`, `grep`, `postqueue` |
| Phòng thủ | UFW/nftables, Fail2ban, TLS certificate/CA lab |
| Ghi nhận | draw.io/diagrams.net, ảnh terminal, `.pcapng`, bảng kết quả |

## 5. Ba kịch bản demo chính

### Demo A - FTP plaintext và SFTP/FTPS đối chứng

**Mục tiêu:** chứng minh dữ liệu/credential của FTP không mã hóa và cho thấy cùng nhiệm vụ khi dùng SFTP hoặc FTPS được bảo vệ.

**Chuẩn bị:**

- Tạo một user FTP chỉ dành cho lab và một file test không nhạy cảm.
- Chạy Wireshark trên interface mạng lab, filter theo host/port của server.
- Cấu hình FTP tối thiểu trong thời gian ngắn; chụp cấu hình trước khi sửa.

**Thực hiện và bằng chứng:**

1. Client đăng nhập FTP và tải file.
2. Dùng `Follow TCP Stream` để chỉ ra lệnh `USER`, `PASS` và dữ liệu rõ.
3. Chuyển sang SFTP hoặc FTPS, thực hiện cùng thao tác.
4. Chụp capture đối chứng: không còn credential rõ; với SFTP thấy SSH/TLS thay vì lệnh FTP.
5. Bật hardening: tắt FTP rõ, bật SFTP hoặc bắt buộc FTPS, chroot và permission tối thiểu.
6. Kiểm thử lại bằng client hợp lệ và ghi rõ hạn chế: mã hóa không thay thế cho kiểm soát quyền.

**Kết luận phải trả lời:** tại sao FTP cần hai kênh, tại sao SFTP chỉ cần SSH port 22, FTPS khác SFTP ở đâu và vì sao firewall passive range dễ cấu hình sai.

### Demo B - Xác thực yếu, log và phản ứng tự động

**Mục tiêu:** tạo một số lần xác thực sai có giới hạn trên dịch vụ do nhóm dựng, quan sát log, kích hoạt Fail2ban/rate limit và xác nhận kết nối bị chặn.

**Phạm vi:** thực hiện lần lượt trên SSH/SFTP, FTP, POP3 hoặc IMAP; không cần chạy đồng thời trên mọi dịch vụ.

**Thực hiện:**

1. Ghi baseline: `ss -tlnp`, thời gian, IP client, user test và trạng thái Fail2ban.
2. Tạo số lần đăng nhập sai nhỏ, cố định và có ghi lại; không dùng wordlist lớn.
3. Theo dõi `auth.log`, journal, vsftpd log hoặc Dovecot log.
4. Dùng `fail2ban-regex` hoặc cơ chế tương đương để xác nhận rule khớp đúng log.
5. Kiểm tra trạng thái jail và chứng minh IP lab bị chặn ở firewall/netfilter.
6. Thử lại bằng client để chứng minh phản ứng có hiệu lực.
7. Unban IP test, khôi phục cấu hình và xác nhận user hợp lệ vẫn đăng nhập được.

**Bằng chứng:** log trước/sau, số lần fail, trạng thái jail, rule firewall, kết quả login hợp lệ sau khi unban.

**Giới hạn cần nêu:** Fail2ban không giải quyết được botnet phân tán, credential đã bị đánh cắp hoặc lỗi logic ứng dụng; cần kết hợp TLS, key, MFA nếu có, rate limit, mật khẩu mạnh và giám sát tập trung.

### Demo C - SMTP open relay và khắc phục

**Mục tiêu:** chứng minh cấu hình relay sai có thể cho phép server chuyển tiếp thư không được phép, sau đó đóng relay nhưng vẫn cho user hợp lệ gửi thư qua submission.

**Chuẩn bị:**

- Postfix chỉ hoạt động trong mạng lab.
- Mail domain dùng tên thử nghiệm như `lab.example` hoặc `lab.invalid`.
- Dovecot cung cấp mailbox nội bộ để đọc thư.
- Không dùng recipient Internet thật.

**Thực hiện:**

1. Ghi cấu hình Postfix trước khi hardening.
2. Từ client lab kiểm tra một phiên relay tới recipient ngoài domain lab giả lập; chỉ ghi nhận mã phản hồi và log, không phát tán thư.
3. Bật `reject_unauth_destination`, giới hạn `mynetworks`, tách cổng 25 với submission.
4. Cấu hình 587/465 yêu cầu TLS và AUTH.
5. Lặp lại test không xác thực: phải bị từ chối, ví dụ `Relay access denied`.
6. Gửi một thư nội bộ bằng user hợp lệ qua submission và đọc bằng IMAPS/POP3S.
7. Đối chiếu queue/log trước và sau; chụp cấu hình thay đổi.

**Kết luận phải trả lời:** vì sao port 25 không nên là cổng gửi thư tự do của user, `mynetworks` nguy hiểm nếu mở quá rộng, và vì sao đóng relay không có nghĩa là chặn người dùng hợp lệ.

## 6. Mini-test để bao phủ đủ năm dịch vụ

| Mini-test | Trước phòng thủ | Sau phòng thủ | Bằng chứng |
|---|---|---|---|
| FTP | Login/capture thấy lệnh rõ hoặc anonymous sai quyền | FTP rõ bị tắt; SFTP/FTPS hoạt động; anonymous bị từ chối | Wireshark, client, vsftpd log |
| SFTP | SSH password login và quyền user còn rộng | Key login; root/password policy được gia cố; user chỉ thấy vùng được cấp | `sshd_config`, `auth.log`, `sftp` session |
| SMTP | Relay test bị chấp nhận hoặc cấu hình không phân biệt 25/587 | Relay không xác thực bị từ chối; submission có TLS/AUTH vẫn gửi nội bộ | SMTP transcript, Postfix log, queue |
| POP3 | Cổng 110 cho phép phiên rõ hoặc auth không bắt TLS | Tắt 110 hoặc bắt buộc 995/TLS | `openssl s_client`, Dovecot log, client |
| IMAP | Cổng 143 cho phép auth rõ | Dùng 993/TLS, plaintext auth ngoài TLS bị từ chối | `openssl s_client`, Thunderbird, Dovecot log |

Mỗi mini-test chỉ cần trả lời bốn câu: **lỗ hổng/cấu hình yếu là gì, quan sát bằng gì, phòng thủ thay đổi gì, kiểm thử sau thay đổi ra sao**.

## 7. Kế hoạch viết báo cáo

### Chương 1 - Mở đầu

- Lý do chọn đề tài.
- Mục tiêu, phạm vi và giới hạn.
- Cam kết chỉ thực hành trong lab cô lập.

### Chương 2 - Cơ sở lý thuyết

- TCP/IP, socket, port, DNS/MX, TLS.
- Nguyên lý FTP/FTPS/SFTP.
- Nguyên lý SMTP/POP3/IMAP.
- Bảng so sánh rõ/bảo vệ và cổng mặc định.

### Chương 3 - Mô hình triển khai

- Sơ đồ topology và bảng IP.
- Phần mềm, phiên bản và vai trò từng máy.
- Firewall, user, certificate và log location.

### Chương 4 - Nguy cơ bị tấn công

- Sniffing/plaintext.
- Brute-force, password spraying và credential stuffing ở mức khái niệm.
- Anonymous FTP, quyền file và chroot sai.
- SSH/SFTP cấu hình yếu.
- Open relay, abuse hàng đợi và credential SMTP.
- POP3/IMAP plaintext, chiếm quyền mailbox.
- TLS downgrade, certificate hết hạn/sai hostname.
- Lỗ hổng do phần mềm EOL hoặc cập nhật chậm.

### Chương 5 - Demo và bằng chứng

Với mỗi demo, dùng cùng mẫu:

1. Mục tiêu.
2. Điều kiện ban đầu.
3. Các bước thực hiện an toàn.
4. Kết quả trước phòng thủ.
5. Biện pháp phòng ngừa.
6. Kết quả sau phòng thủ.
7. Log/ảnh/capture chứng minh.
8. Hạn chế và tình huống có thể vẫn bị bypass.

### Chương 6 - Phát hiện sớm

- Log nào cần theo dõi cho từng service.
- Baseline bình thường: số login, số session, queue depth, lưu lượng, lỗi TLS.
- Ngưỡng cảnh báo: nhiều fail từ một IP, nhiều IP cùng thử một user, queue tăng nhanh, relay denied tăng, certificate sắp hết hạn.
- Cách xác nhận cảnh báo không phải false positive.
- Hướng mở rộng: SIEM/Wazuh/Grafana/Loki nếu có thời gian.

### Chương 7 - Phòng ngừa và hardening

- Tắt dịch vụ/cổng không cần.
- TLS bắt buộc; certificate có SAN đúng hostname.
- SFTP/key authentication; least privilege/chroot.
- Tắt anonymous và hạn chế quyền ghi.
- Submission có AUTH; chặn open relay.
- Mật khẩu mạnh, rate limit, Fail2ban và cập nhật.
- Backup cấu hình, log rotation, quy trình ứng phó sự cố.

### Chương 8 - Kết luận

- Tóm tắt kết quả trước/sau.
- Biện pháp hiệu quả nhất và giới hạn.
- Công việc mở rộng: MFA, quản lý secret, SIEM, certificate automation, SPF/DKIM/DMARC thật trên domain được cấp quyền.

## 8. Checklist tiến độ thực hiện

### Giai đoạn 1 - Nghiên cứu

- [ ] Đọc bảng giao thức/cổng và viết lại bằng lời của nhóm.
- [ ] Đọc RFC cốt lõi ở mục 9.
- [ ] Đọc tài liệu chính thức của OpenSSH, Postfix, Dovecot, vsftpd.
- [ ] Hoàn thiện sơ đồ luồng FTP/SFTP và luồng email.
- [ ] Chốt ba kịch bản demo, tiêu chí thành công và bằng chứng cần chụp.

### Giai đoạn 2 - Dựng lab

- [ ] Tạo VM/snapshot và mạng Host-only/Internal.
- [ ] Đặt hostname/IP cố định trong dải lab.
- [ ] Cài dịch vụ và kiểm tra `ss -tlnp`.
- [ ] Tạo user/file test; không dùng dữ liệu thật.
- [ ] Cấu hình firewall chỉ cho phép IP lab.
- [ ] Kiểm tra log từng dịch vụ.

### Giai đoạn 3 - Demo trạng thái yếu có kiểm soát

- [ ] Demo FTP plaintext/capture.
- [ ] Demo SFTP hoặc FTPS đối chứng.
- [ ] Tạo login failure nhỏ trên SSH/FTP/POP3/IMAP.
- [ ] Demo relay test chỉ trong domain lab.
- [ ] Lưu capture/log/config trước hardening.

### Giai đoạn 4 - Hardening và kiểm tra lại

- [ ] Tắt anonymous, FTP rõ và plaintext auth không cần thiết.
- [ ] Bật TLS/key authentication/chroot/least privilege.
- [ ] Đóng open relay; bật submission có AUTH.
- [ ] Cấu hình Fail2ban/rate limit và kiểm tra regex.
- [ ] Kiểm tra queue, log, firewall và certificate.
- [ ] Lưu capture/log/config sau hardening.

### Giai đoạn 5 - Hoàn thiện báo cáo

- [ ] Mọi ảnh có caption: ảnh chứng minh điều gì, trước hay sau.
- [ ] Mọi kết luận quan trọng có nguồn.
- [ ] Không còn password thật/private key/IP công cộng trong file nộp.
- [ ] Kiểm tra link nguồn và ngày truy cập.
- [ ] Thành viên nào cũng giải thích được phần mình.
- [ ] Tập demo trong thời lượng thầy yêu cầu và chuẩn bị phương án dự phòng.

## 9. Nguồn nên đọc và trích dẫn

### 9.1. Chuẩn RFC/IETF

- [RFC 959 - File Transfer Protocol](https://www.rfc-editor.org/rfc/rfc959): FTP, control/data channel, lệnh cơ bản.
- [RFC 4217 - Securing FTP with TLS](https://www.rfc-editor.org/rfc/rfc4217): FTPS và `AUTH TLS`.
- [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251), [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252), [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253), [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254): kiến trúc, xác thực, transport và connection của SSH.
- [RFC 5321 - Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321): SMTP, mã phản hồi và relay.
- [RFC 6409 - Message Submission](https://www.rfc-editor.org/rfc/rfc6409): mô hình MSA/cổng 587.
- [RFC 3207 - SMTP STARTTLS](https://www.rfc-editor.org/rfc/rfc3207) và [RFC 4954 - SMTP AUTH](https://www.rfc-editor.org/rfc/rfc4954): TLS và xác thực SMTP.
- [RFC 1939 - POP3](https://www.rfc-editor.org/rfc/rfc1939): trạng thái và mô hình POP3.
- [RFC 9051 - IMAP4rev2](https://www.rfc-editor.org/rfc/rfc9051): IMAP hiện hành.
- [RFC 8314 - Cleartext Considered Obsolete](https://www.rfc-editor.org/rfc/rfc8314): khuyến nghị TLS cho submission, POP3 và IMAP.
- [RFC 8446 - TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446): TLS 1.3.
- [RFC 7208 - SPF](https://www.rfc-editor.org/rfc/rfc7208), [RFC 6376 - DKIM](https://www.rfc-editor.org/rfc/rfc6376), [RFC 7489 - DMARC](https://www.rfc-editor.org/rfc/rfc7489): xác thực domain email.
- [IANA Service Name and Port Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml): đối chiếu cổng chính thức.

Lưu ý khi viết về SFTP: SFTP chạy trên SSH và không phải FTP + TLS; giao thức SFTP phổ biến trong OpenSSH dựa trên các draft `secsh-filexfer`, không có một RFC Internet Standard duy nhất tương đương RFC 959.

### 9.2. Tài liệu triển khai chính thức

- [Ubuntu Server documentation](https://documentation.ubuntu.com/server/): OpenSSH, UFW, service management và bảo mật hệ thống.
- [OpenSSH manual](https://www.openssh.com/manual.html): `sshd_config`, key authentication, SFTP subsystem.
- [Postfix Basic Configuration](https://www.postfix.org/BASIC_CONFIGURATION_README.html): `myhostname`, `mydestination`, relay và cấu hình cơ bản.
- [Postfix TLS README](https://www.postfix.org/TLS_README.html): TLS certificate, client/server TLS.
- [Postfix Standard Configuration](https://www.postfix.org/STANDARD_CONFIGURATION_README.html): cấu hình MTA và relay restrictions.
- [Dovecot documentation](https://doc.dovecot.org/): IMAP/POP3, authentication, TLS, mailbox và LMTP.
- [Ubuntu vsftpd man page](https://manpages.ubuntu.com/manpages/noble/en/man5/vsftpd.conf.5.html): tham số `vsftpd.conf`.
- [Wireshark documentation](https://www.wireshark.org/docs/): capture, display filter, Follow TCP Stream.
- [Fail2ban project](https://github.com/fail2ban/fail2ban): jail, filter và action ban.

### 9.3. Khung an toàn và phát hiện

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): phát hiện, xử lý và phục hồi sự cố.
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final): least privilege, audit log và bảo mật truyền tải.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): xác thực, chống brute-force và enumeration.
- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/).
- [MITRE ATT&CK T1040 - Network Sniffing](https://attack.mitre.org/techniques/T1040/).
- [MITRE ATT&CK T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/).
- [MITRE ATT&CK T1071.002 - File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002/).
- [MITRE ATT&CK T1071.003 - Mail Protocols](https://attack.mitre.org/techniques/T1071/003/).

Khi nộp báo cáo, ghi ngày truy cập nguồn. Nếu phiên bản Ubuntu/phần mềm thay đổi, ưu tiên tài liệu đúng phiên bản lab đang dùng và không chép nguyên cấu hình từ bản khác.

## 10. Tiêu chí tự chấm trước khi nộp

- [ ] Báo cáo giải thích được **nguyên lý**, không chỉ liệt kê lệnh cài đặt.
- [ ] Có đủ cả FTP, SFTP, SMTP, POP3 và IMAP; không bỏ qua POP3/IMAP vì chỉ demo SMTP.
- [ ] Có ít nhất một bằng chứng attack và một bằng chứng defense cho từng dịch vụ.
- [ ] Có so sánh trước/sau hardening.
- [ ] Có log/capture/ảnh giúp người đọc tự kiểm tra kết luận.
- [ ] Có phần giới hạn: lab cô lập, công cụ phòng thủ không phải viên đạn bạc.
- [ ] Không dùng mục tiêu ngoài quyền kiểm soát, không gửi spam, không lộ dữ liệu thật.
- [ ] Mọi nguồn quan trọng trỏ tới RFC hoặc tài liệu chính thức.
- [ ] Các thành viên có thể trả lời: FTP khác SFTP thế nào, 25 khác 587 thế nào, POP3 khác IMAP thế nào, vì sao STARTTLS không tự động đồng nghĩa an toàn nếu cấu hình/client sai.

## 11. Phân công gợi ý cho nhóm

| Vai trò | Việc chính | Đầu ra |
|---|---|---|
| Thành viên 1 | FTP/FTPS/SFTP và capture | Chương lý thuyết file, Demo A, ảnh Wireshark |
| Thành viên 2 | SMTP/Postfix/relay/TLS | Chương email gửi, Demo C, transcript Postfix |
| Thành viên 3 | POP3/IMAP/Dovecot/client | Chương email nhận, mini-test 110/995/143/993 |
| Thành viên 4 | Log, Fail2ban, firewall, báo cáo | Demo B, bảng phát hiện, checklist bằng chứng |

Mỗi thành viên phải review chéo ít nhất một phần của người khác để tránh tình trạng chỉ một người hiểu toàn bộ lab.

