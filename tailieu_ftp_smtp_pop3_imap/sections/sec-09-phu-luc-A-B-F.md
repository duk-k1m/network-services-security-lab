## Phụ lục A/B/F: Checklist học theo thứ tự, kế hoạch 7 ngày, phân biệt bắt buộc vs nâng cao

Phụ lục này dành cho người mới bắt đầu đồ án: nó trả lời ba câu hỏi "học gì trước – học gì sau" (Phụ lục A), "trong 7 ngày thì làm gì mỗi ngày" (Phụ lục B), và "cái nào phải xong để đạt điểm sàn, cái nào là điểm cộng" (Phụ lục F). Toàn bộ thực hành chỉ diễn ra trong **lab mạng riêng do nhóm tự dựng** (mạng host-only giữa các máy ảo), không đụng tới bất kỳ hệ thống công cộng nào.

> Ghi chú phiên bản: tính đến tháng 8/2026, bản Ubuntu Server LTS mới nhất là **26.04 LTS "Resolute Raccoon"** (phát hành 23/4/2026, bản vá điểm 26.04.1 ra ngày 27/8/2026). Bản **24.04 LTS "Noble Numbat"** vẫn được hỗ trợ song song. Lab trong đồ án chạy tốt trên cả hai; nếu nhóm bạn đã dựng máy ảo từ 24.04 thì không cần nâng cấp gấp.

---

### Phụ lục A — Checklist kiến thức cần học theo thứ tự

Các mục được sắp xếp theo **quan hệ phụ thuộc (dependency)**: bạn không thể hiểu FTP passive mode nếu chưa hiểu TCP có hai kênh, không hiểu SFTP nếu chưa hiểu SSH, không đọc được log Fail2ban nếu chưa biết dịch vụ ghi log ở đâu. Mỗi mục có một câu hỏi tự kiểm tra — nguyên tắc: **nếu trả lời được câu hỏi đó mà không cần mở tài liệu thì coi như đạt**, tick vào ô `[x]`.

#### A1. Nền tảng mạng (network cơ bản)

- [ ] Mô hình OSI / TCP-IP theo lớp (layer), vai trò của IP và MAC.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Khi tester `ping` tới máy server trong mạng host-only, gói tin đi qua những lớp nào và thiết bị nào quyết định đường đi?"
- [ ] Khái niệm cổng (port), dải well-known ports 0–1023, vì sao dịch vụ dưới 1024 cần quyền root để bind.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Vì sao vsftpd phải chạy với quyền root (hoặc dùng cơ chế trao quyền) để nghe cổng 21?"
- [ ] DNS: bản ghi A (tên → IP), MX (máy nhận mail của domain), TXT (nơi SPF/DKIM/DMARC sống).
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "SPF và DKIM được công bố qua loại bản ghi DNS nào? Vì sao mail server cần đúng tên hostname (FQDN)?"
- [ ] Mạng riêng / NAT; mạng host-only trong VirtualBox (dải ví dụ `192.168.56.0/24`).
  - *Kiểmtra hiểu bài bằng cách:* tự trả lời — "Vì sao lab của mình không dùng IP công khai thật, và 'open relay' trong lab có gây hại cho ai không?"

#### A2. TCP và socket

- [ ] Bắt tay ba bước (three-way handshake: SYN → SYN-ACK → ACK) và ý nghĩa trạng thái kết nối.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Vẽ 3 bước bắt tay khi kết nối tới cổng 25; gói nào do client gửi trước?"
- [ ] Mô hình socket listen/accept/connect trên server/client.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Lệnh `ss -tlnp` cho thấy cột nào của handshake?"
- [ ] Hai kênh của FTP: điều khiển (control) và dữ liệu (data); active vs passive mode.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Ở chế độ PASV, ai là bên chủ động mở kết nối data, và server báo cổng bằng lệnh nào?"

#### A3. Ý niệm TLS và SSH (TLS/SSH concepts)

- [ ] Mã đối xứng (symmetric) vs bất đối xứng (asymmetric), hash, chữ ký số.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Vì sao TLS dùng cả hai loại mã hoá thay vì chỉ một?"
- [ ] Chứng thư số X.509, Certificate Authority (CA), chuỗi tin cậy (chain of trust).
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Client 'tin' certificate của server mail trong lab dựa vào điều gì khi ta phát hành internal CA?"
- [ ] STARTTLS (nâng cấp kết nối plaintext đang mở) vs implicit TLS (mã hoá ngay từ đầu, cổng riêng).
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Khác biệt giữa cổng 587 (submission/STARTTLS) và 465 (implicit TLS) là gì?"
- [ ] SSH: cặp khoá public/private, `~/.ssh/authorized_keys`, kênh điều khiển duy nhất.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Vì sao nói 'SFTP không phải là FTP có TLS'? Chúng khác nhau ở tầng nào?"

#### A4. Giao thức theo từng cặp

Cặp file: **FTP → FTPS → SFTP**

- [ ] FTP thuần (RFC 959): lệnh `USER/PASS/RETR/STOR/LIST`, cổng 21/20, chế độ anonymous.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Mở một phiên FTP bắt được bằng Wireshark, đăng nhập nằm ở gói nào và ở dạng gì (mã hoá hay plaintext)?"
- [ ] FTPS (RFC 4217 — explicit AUTH TLS; implicit 990): vẫn giữ mô hình 2 kênh.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Vì sao FTPS cần cấu dải passive port trong firewall, còn SFTP thì không?"
- [ ] SFTP (file transfer chạy trong SSH, cổng 22; giao thức định nghĩa qua tài liệu IETF `draft-ietf-secsh-filexfer` chưa thành RFC chuẩn hoá — xem openssh.com).
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Kẻ tấn công đã có credential SSH thì SFTP còn bảo vệ được gì nữa?"
- [ ] SSH (mã hoá toàn bộ; RFC cho TLS là 8446 để đối chiếu khái niệm handshake).

Cặp mail: **SMTP → POP3 → IMAP**

- [ ] SMTP (RFC 5321): `EHLO / MAIL FROM / RCPT TO / DATA`, cổng 25/587/465, mở rộng ESMTP AUTH (RFC 4954) và STARTTLS (RFC 3207).
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Quyết định 'relay' xảy ra ở lệnh nào? Dấu hiệu nào trong log mail cho thấy một relay bị từ chối?"
- [ ] POP3 (RFC 1939): cổng 110/995, mô hình tải về và (thường) xoá.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Vì sao kiểm tra mail bằng POP3 trên hai thiết bị gây mất/mail trùng?"
- [ ] IMAP (IMAP4rev2 là RFC 9051; bản rev1 cũ RFC 3501): cổng 143/993, mailbox nằm lại server, đồng bộ folder.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "IMAP khác POP3 ở chỗ dữ liệu nằm đâu, và điều đó ảnh hưởng gì tới dung lượng server và giá trị của log?"

#### A5. Công cụ trên Ubuntu

- [ ] `apt update/upgrade`, `systemctl status|restart`, `journalctl -u <dichvu>`.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Sau khi sửa vsftpd.conf, hai lệnh bắt buộc phải chạy là gì?"
- [ ] `ss -tlnp` (xem cổng đang nghe + process), `tcpdump` (bắt gói trên server), `openssl s_client -starttls smtp`.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Làm sao chứng minh service nào đang giữ cổng 993?"
- [ ] nano/vi chỉnh config; `adduser`, `usermod`; quyền file (`chown`, `chmod`).

#### A6. Log

- [ ] Vị trí log trên Ubuntu: `/var/log/auth.log` (SSH, PAM, vsftpd nếu log vào syslog), `/var/log/mail.log` (Postfix, Dovecot), `/var/log/fail2ban.log`; và `journalctl` khi rsyslog không ghi file.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Dòng log nào tương ứng 'một đăng nhập SSH thất bại' và dòng nào tương ứng 'Fail2ban đã ban IP'?"
- [ ] Đọc hiểu format timestamp + hostname trong log để lần vết (tracing) giữa các dịch vụ.

#### A7. Nguy cơ bị tấn công

- [ ] Sniffing credential plaintext (FTP/POP3/IMAP/SMTP-AUTH không TLS).
- [ ] Brute-force / password spraying đăng nhập SSH, FTP, mail.
- [ ] SMTP open-relay bị lợi dụng phát tán mail rác.
- [ ] FTP anonymous upload (ghi file tuỳ ý → webshell/backdoor lưu trữ).
- [ ] MITM trên kênh plaintext, downgrade khi ép tắt TLS.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Với mỗi nguy cơ trên, TLS *loại bỏ hoàn toàn* được cái nào và chỉ *giảm* được cái nào?"

#### A8. Biện pháp phòng thủ

- [ ] Bắt buộc TLS/SSH cho mọi kênh mang credential; tắt listener plaintext.
- [ ] Fail2ban (bantime/maxretry/findtime), UFW (chỉ mở cổng cần, nhớ dải passive FTP).
- [ ] Hardening cấu hình: `sshd_config`, `vsftpd.conf`, `main.cf` (`reject_unauth_destination`), Dovecot `disable_plaintext_auth = yes`.
- [ ] SPF/DKIM/DMARC ở mức khái niệm (RFC 7208 / 6376 / 7489).
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Nếu chỉ được làm đúng 3 việc cho máy chủ FTP, bạn chọn 3 việc nào và vì sao?"

#### A9. Lab (kịch bản A/B/C)

- [ ] Kịch bản A: FTP plaintext capture → so sánh với SFTP.
- [ ] Kịch bản B: brute force trong lab → Fail2ban ban/unban.
- [ ] Kịch bản C: open relay → phát hiện → sửa.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Mỗi kịch bản kết thúc bằng bằng chứng (evidence) nào: ảnh chụp màn hình hay file PCAP?"

#### A10. Viết báo cáo

- [ ] Cấu trúc: mô hình lab → cấu hình → tấn công mô phỏng → phát hiện → khắc phục → đánh giá.
  - *Kiểm tra hiểu bài bằng cách:* tự trả lời — "Người đọc báo cáo có tái dựng được lab của bạn chỉ từ các file cấu hình bạn đính kèm không?"

**Nguồn:**
- RFC 959: https://www.rfc-editor.org/info/rfc959 — RFC 5321 (SMTP): https://www.rfc-editor.org/info/rfc5321 — RFC 1939 (POP3): https://www.rfc-editor.org/info/rfc1939 — RFC 9051 (IMAP4rev2): https://www.rfc-editor.org/info/rfc9051 — RFC 4217 (FTPS): https://www.rfc-editor.org/info/rfc4217 — RFC 8446 (TLS 1.3): https://www.rfc-editor.org/info/rfc8446 — RFC 7208 (SPF): https://www.rfc-editor.org/info/rfc7208 — RFC 7489 (DMARC): https://www.rfc-editor.org/info/rfc7489
- OpenSSH: https://www.openssh.com/portable.html — Ubuntu Server docs: https://documentation.ubuntu.com/server/

---

### Phụ lục B — Kế hoạch 7 ngày

Bảng dưới quy hoạch 1 tuần (mỗi ngày ≈ 4–6 giờ). Cột cuối là **cảnh báo lỗi hay gặp** — đa số thời gian của người mới cháy ở đây chứ không phải ở lý thuyết.

| Ngày | Lý thuyết | Thực hành | Đầu ra / kiểm tra | Cảnh báo lỗi hay gặp |
|---|---|---|---|---|
| **1** | Ôn OSI/TCP, DNS, NAT; kiến trúc lab 3 máy: Ubuntu Server (dịch vụ), Ubuntu Desktop (quản trị + Wireshark), tester (Kali hoặc Ubuntu client) — tất cả trong **host-only network** VirtualBox | Cài 3 VM (Ubuntu Server 26.04 hoặc 24.04 LTS); cấu hình IP tĩnh qua **netplan** (`/etc/netplan/00-lab.yaml`, `sudo netplan apply`); mở SSH; `apt update` toàn bộ; tạo user lab | Sơ đồ topo + bảng IP; `ping` thông 3 chiều giữa các máy; ảnh chụp `ip a` | netplan sai indent (YAML kén tab/space) hoặc **quên `chmod 600` file netplan** → cảnh báo bảo mật; chọn sai adapter (NAT thay vì host-only) → các VM không thấy nhau; cloud-init ghi đè cấu hình mạng trên Ubuntu Server (disable cloud-init netplan nếu cấu hình tay) |
| **2** | FTP: RFC 959, hai kênh, active/passive, anonymous. vsftpd (`/etc/vsftpd.conf`) | `apt install vsftpd`; cấu hình `anonymous_enable=NO`, `local_enable=YES`, `write_enable=YES`; `chroot_local_user=YES` + `allow_writeable_chroot=YES`; tài khoản FTP test. **Làm trước kịch bản A phần 1**: dùng tester `ftp 192.168.56.x`, Desktop chạy Wireshark filter `ftp` bắt plaintext `USER`/`PASS` | PCAP + ảnh capture credential; cấu trúc báo cáo mục "FTP hoạt động" | **Quên cho phép dải passive ports trong UFW** (`pasv_min_port`/`pasv_max_port` trong vsftpd.conf rồi `ufw allow 30000:30099/tcp`) → lệnh `LIST` treo timeout trong khi `login` vẫn OK (đây là lỗi kinh điển nhất của lab FTP); sửa conf quên `systemctl restart vsftpd` |
| **3** | SSH/SFTP: khoá, `sshd_config`, chroot cho SFTP; so sánh mô hình 2 kênh (FTP/FTPS) vs 1 kênh (SFTP) | Tạo nhóm `sftpusers`; `Match Group sftpusers` với `ChrootDirectory /sftp/%u`, `ForceCommand internal-sftp`, `PasswordAuthentication no` (key-only cho nhóm này); scp/sftp client; **hoàn tất kịch bản A**: bắt lại bằng Wireshark thấy chỉ còn nhiễu mã hoá | Ảnh so sánh side-by-side FTP plaintext vs SFTP; bảng đối chiếu FTP/FTPS/SFTP nháp | **Chroot fail do owner/quyền**: `ChrootDirectory` phải **root-owned và không group/world-writable** (`chown root:root`), ngược lại sshd báo "bad owner or permissions" và drop kết nối; user SFTP đặt shell `/usr/sbin/nologin` nhưng vẫn cần thuộc `AllowGroups`; khoá sai `authorized_keys` quyền 600 |
| **4** | SMTP (RFC 5321) luồng receive/deliver; POP3 vs IMAP (mô hình mailbox); kiến trúc Postfix (master/subagent) + Dovecot (LDA + IMAP/POP3 provider) | `apt install postfix dovecot-imapd dovecot-pop3d`; `main.cf`: `myhostname`, `mydestination=$myhostname, localhost, mail.lab.local`, `inet_interfaces=all`, `smtpd_recipient_restrictions=permit_mynetworks,reject_unauth_destination`; Dovecot `mail_location=maildir:~/Maildir`, `disable_plaintext_auth=no` (tạm thời để test), `auth_mechanisms=plain login`; nối Postfix→Dovecot SASI qua `smtpd_sasl_type=dovecot`, `smtpd_sasl_path=private/auth`; Thunderbird cấu hình SMTP 25(587)+IMAP 143 trong lab; gửi/nhận nội bộ | Ảnh Thunderbird nhận được mail lab; 1 chu kỳ `mail.log` của một email đi + đến | **Dovecot không auth được Postfix**: socket `private/auth` không cùng vị trí `queue_directory` của Postfix hoặc **quyền socket sai** (nhóm `postfix` phải đọc được → `user = postfix` trong block `unix_listener` của dovecot `master.conf`); `mydestination` thiếu hostname → mail local bị trả về; `myhostname` không phải FQDN → Postfix warn + nhiều server ngoài từ chối (trong lab thì không, nhưng nhớ ghi vào báo cáo) |
| **5** | TLS: CA tự dựng, STARTTLS vs implicit; RFC 3207 (SMTP STARTTLS), RFC 2595 (IMAP); kiểm certificate bằng `openssl s_client` | Sinh internal CA + server cert (`openssl req -x509 ...`); Postfix: `smtpd_tls_cert_file/key`, `smtp_tls_security_level=may`; Dovecot: `ssl=required`, trỏ cert; bật `submission 587` trong `master.csv`→`master.cf` với `smtpd_tls_auth_only=yes`; Thunderbird xuất/nhập CA để tin cậy; **kịch bản C**: tình nguyên tắt `reject_unauth_destination` tạo open relay, chứng minh bằng `telnet/openssl s_client` gửi thư "mượn" server, **bật lại và chụp log `Relay access denied`** | PCAP có STARTTLS; ảnh log từ chối relay; ảnh Thunderbird hiển thị ổ khoá | **Postfix đọc không được private key**: file key root-only 600 trong khi postfix chạy user `postfix` → `chmod 640 + chgrp postfix` (hoặc `smtpd_tls_key_file` trỏ quyền đúng); CN/SAN không khớp `myhostname` → client cảnh báo; quên thêm CA lab vào kho tin cậy (trust store) của Thunderbird → bị từ chối kết nối TLS; test relay bằng script **phải chạy từ máy lab, không bao giờ nhắm server ngoài** |
| **6** | Log Syslog/mail log; cơ chế Fail2ban (failregex, jail, banaction); firewall stateful | Đọc `/var/log/mail.log`, `auth.log`, `vsftpd.log` (`xferlog_enable=YES`); cài fail2ban (`apt install fail2ban`, tạo `/etc/fail2ban/jail.local`: `bantime=600`, `findtime=300`, `maxretry=5`; bật jail `[sshd]`, `[postfix]`, thêm filter cho vsftpd); **kịch bản B**: từ tester cố tình gõ sai mật khẩu SSH vài lần → thấy `BAN` trong `fail2ban.log`, `fail2ban-client status sshd`, rồi `unban` thủ công; siết UFW: `ufw allow OpenSSH`, từng dịch vụ, nhớ dải passive FTP đã nói ở Ngày 2 | Ảnh IP bị ban + status jail; bảng cổng UFW cuối cùng khớp bảng cổng dịch vụ | **Quên `ufw allow OpenSSH` trước khi `ufw enable`** → tự khoá mình khỏi SSH (làm qua console VM); jail Fail2ban **regex không match format log thật** → `fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf` để debug; Ubuntu dùng journald: cần `backend = systemd` trong jail.local nếu không có rsyslog ghi file; ban luôn IP chính máy tester rồi không unban → tưởng Fail2ban hỏng |
| **7** | SPF/DKIM/DMARC ở mức khái niệm: ai kiểm tra gì, DNS TXT trông ra sao (`v=spf1 ip4:192.168.56.0/24 -all` mẫu trong lab); tổng kết mô hình phòng thủ nhiều lớp | Hoàn thành báo cáo: đủ ảnh chụp từng bước (evidence), file cấu hình trước/sau, PCAP; luyện phản biện chéo trong nhóm theo kịch bản "người hỏi đóng vai hội đồng" | Báo cáo nháp hoàn chỉnh + slide; checklist Phụ lục A tick đạt ≥ 90% | Ghi evidence thiếu timestamp/hostname; dán cấu hình còn lộ đường dẫn file key (che bớt khi nộp); chỉ trình bày "cách làm" mà quên "vì sao attack đó thành công/thất bại" — hội đồng hay hỏi đúng chỗ đó |

**Nguồn:**
- Ubuntu release notes (26.04 LTS): https://documentation.ubuntu.com/release-notes/26.04/ — Release cycle: https://ubuntu.com/about/release-cycle
- vsftpd README/man (gói `vsftpd`): https://manpages.ubuntu.com/manpages/noble/en/man5/vsftpd.conf.5.html — Hướng dẫn FTP của Red Hat (khái niệm tương thích Ubuntu): https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/monitoring_and_managing_system_files_and_the_file_system/setting-up-and-configuring-vsftpd
- Postfix: https://www.postfix.org/STANDARD_CONFIGURATION_README.html — Dovecot: https://doc.dovecot.org/configuration_manual/
- OpenSSH: https://www.openssh.com/manual.html — Fail2ban README: https://github.com/fail2ban/fail2ban — Wireshark: https://www.wireshark.org/docs/

---

### Phụ lục F — Phân biệt nội dung bắt buộc vs nâng cao

#### F1. Phần BẮT BUỘC (phải đủ trong báo cáo để đạt yêu cầu tối thiểu)

| # | Hạng mục | Bằng chứng tối thiểu phải nộp |
|---|---|---|
| 1 | Toàn bộ demo kịch bản A/B/C | PCAP/ảnh chụp từng bước + cấu hình trước/sau |
| 2 | So sánh FTP vs SFTP (và vị trí FTPS) | Bảng đối chiếu: cổng, số kênh, chỗ nào mã hoá, credential đi plaintext ở đâu |
| 3 | Open relay → phát hiện → fix | Log `Relay access denied` + diff `main.cf` |
| 4 | Plaintext capture trên FTP/POP3/IMAP | Ảnh Wireshark thấy `USER`/`PASS` (chỉ trong lab) |
| 5 | Fail2ban ban + unban | Ảnh `fail2ban.log` dòng BAN + `fail2ban-client status` |
| 6 | Bảng 5 giao thức (FTP, SFTP, SMTP, POP3, IMAP) | Cổng mặc định, RFC, plaintext/TLS, dùng để làm gì |
| 7 | SPF/DKIM/DMARC mức **khái niệm** | Sơ đồ "ai kiểm tra gì": receiver check SPF (RFC 7208), verify DKIM (RFC 6376), đối chiếu alignment theo DMARC (RFC 7489) — không cần triển khai thật |

#### F2. Phần NÂNG CAO (điểm cộng; chọn 2–3 mục làm cho sâu còn hơn làm 8 mục hời hợt)

- **TLS termination với internal CA + giải mã Wireshark bằng `SSLKEYLOGFILE`.** Đặt biến môi trường `SSLKEYLOGFILE` tới một file *trước khi* khởi động client (OpenSSL/browser sẽ ghi session key vào đó), rồi trỏ Wireshark *Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename*. Điểm mấu chốt cần giải thích trong báo cáo: cách này thu key **từ phía client**; dùng private key của server chỉ giải mã được khi cipher **không có forward secrecy** (RSA key exchange), còn TLS 1.3/ECDHE thì không. Kiểm chứng: filter `tls` và thấy "Decrypted".
- **DKIM key thật ký trên lab.** Triển khai OpenDKIM (hoặc tương tự) để Postfix ký thư nội bộ; dùng `dig TXT default._domainkey.mail.lab.local` xem public phần; kiểm chuỗi `d=`, `s=`, `b=` trong header thư đã ký.
- **MFA trên SSH.** Thêm lớp OTP qua PAM (ví dụ `libpam-google-authenticator` có trong repo Ubuntu) cho một tài khoản lab; trình bày `AuthenticationMethods publickey,keyboard-interactive`.
- **Audit script tự động hardening.** Script bash/python kiểm: cổng đang nghe (`ss -tlnp`), phiên SSH (`ss -tn state established '( sport = :22 )'`), cờ plaintext còn bật trong conf — xuất bảng đạt/không đạt. Đây là dạng "defensive tooling" nên khuyến khích nhưng không bắt buộc.
- **Giám sát bằng cron + alert script.** Job cron mỗi 5–10 phút grep log tìm mẫu `Failed password|BAN|relay=.*5\.7\.` rồi ghi file cảnh báo — trình bày ý tưởng "SIEM mini".
- **IPv6 trong lab.** Bật dải IPv6 host-only, chứng minh dịch vụ listen `::`, và kiểm UFW `ufw6 status` — pitfall hay gặp: chỉ mở cổng cho IPv4 nên client gọi IPv6 timeout.
- **LMTP + Maildir.** Thay vì Postfix tự deliver qua LDA, nối Dovecot LMTP (`smtpd` lmtp trong master.cf của dovecot, Postfix `mailbox_transport`/`lmtp_host`) — giải thích được lợi ích tách trách nhiệm MTA vs LDA.
- **Phân tích PCAP bằng tshark CLI.** Ví dụ mẫu (chỉ trên file PCAP của lab): `tshark -r capture.pcap -Y ftp -T fields -e ftp.command -e ftp.arg` — cho thấy cùng dữ liệu Wireshark hiển thị được nhưng script hoá được để làm báo cáo tự động.
- **ssh-audit.** Công cụ nguồn mở công khai **`jtesta/ssh-audit`** (PyPI/Snap, MIT license — *lưu ý: repo thuộc về Joseph Testa, không phải "jarun"*): quét banner và đề xuất thuật toán KEX/cipher/MAC của server SSH, cho điểm theo khuyến nghị. Chạy `ssh-audit 192.168.56.x` trên lab rồi so với cấu hình `sshd_config` nhóm đã harden.
- **Mô hình hoá ATT&CK mapping** cho từng nguy cơ (dùng trong mục "phát hiện sớm"). Các ID đã **kiểm chứng** trên attack.mitre.org tính đến 8/2026:

| Nguy cơ trong lab | Kỹ thuật MITRE ATT&CK | ID (đã verify) |
|---|---|---|
| Doạ đoán mật khẩu SSH/FTP/IMAP/SMTP | Brute Force (có sub-technique Password Spraying T1110.003) | [T1110](https://attack.mitre.org/techniques/T1110/) |
| Dùng tài khoản đánh cắp được từ sniffing / lạm dụng anonymous FTP | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Ngửi credential plaintext trên mạng lab | Network Sniffing | [T1040](https://attack.mitre.org/techniques/T1040/) |
| Truyền file/C2 qua FTP, SFTP | Application Layer Protocol: File Transfer Protocols | [T1071.002](https://attack.mitre.org/techniques/T1071/002/) |
| Spam/phishing/C2 mượn kênh mail | Application Layer Protocol: Mail Protocols (từ ATT&CK v12+ đổi tên từ "Email Protocols" thành **"Mail Protocols"**) | [T1071.003](https://attack.mitre.org/techniques/T1071/003/) |
| Ghi file trái phép lên FTP vùng anonymous-write, sửa dữ liệu trên server | Data Manipulation — **T1565**, **KHÔNG phải T1657** | [T1565](https://attack.mitre.org/techniques/T1565/) |

> ⚠️ **Đính chính quan trọng** (nhóm đừng lặp trong báo cáo): qua kiểm tra trang chính thức, **T1657 = Financial Theft** (thuộc tactic Impact, chỉ các hành vi chiếm tiền như BEC/ransom), còn **Data Manipulation là T1565** với sub-technique T1565.001 (Stored — ví dụ đúng là file trên FTP share), T1565.002 (Transmitted — ví dụ đúng là message bị sửa khi relay), T1565.003 (Runtime). Mapping của mình dùng **T1565**.

- **Lưu ý nguyên tắc:** mọi brute-force/open-relay test chỉ nhắm vào IP trong dải host-only của lab; tài liệu không nêu cú pháp của công cụ tấn công (hydra/medusa…) ngoài mức "chúng tồn tại và dùng trong lab được phê duyệt".

**Nguồn:**
- Wireshark TLS wiki (SSLKEYLOGFILE): https://wiki.wireshark.org/TLS — mitmproxy hướng dẫn master secrets: https://docs.mitmproxy.org/stable/howto/wireshark-tls/
- ssh-audit (jtesta): https://github.com/jtesta/ssh-audit — PyPI: https://pypi.org/project/ssh-audit/
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1078/ · https://attack.mitre.org/techniques/T1110/ · https://attack.mitre.org/techniques/T1040/ · https://attack.mitre.org/techniques/T1071/002/ · https://attack.mitre.org/techniques/T1071/003/ · https://attack.mitre.org/techniques/T1565/ · https://attack.mitre.org/techniques/T1657/
- RFC 7208 (SPF): https://www.rfc-editor.org/info/rfc7208 — RFC 7489 (DMARC): https://www.rfc-editor.org/info/rfc7489 — DKIM RFC 6376: https://www.rfc-editor.org/info/rfc6376 — OpenDKIM: https://www.opendkim.org/

---

*Hết Phụ lục A/B/F. Quay lại Chương chính để xem chi tiết kỹ thuật từng giao thức; mỗi mục ở Phụ lục A có liên kết ngầm tới đúng mục tương ứng của chương đó.*
