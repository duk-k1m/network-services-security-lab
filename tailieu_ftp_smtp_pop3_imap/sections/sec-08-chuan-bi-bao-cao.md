## 8. Chuẩn bị báo cáo và tiêu chí đánh giá

Chương này là phần "dàn dựng" của đồ án: sau khi đã nghiên cứu giao thức (chương 1–2), triển khai lab (chương 3) và phân tích tấn công/phòng thủ (chương 4–6), nhóm cần đóng gói toàn bộ thành một báo cáo học thuật mạch lạc, kèm bộ ảnh chứng minh (evidence) mà giám khảo có thể kiểm tra lại được. Phần dưới đây đề xuất bố cục báo cáo, các bảng tổng hợp then chốt nên đưa vào phụ lục chính, quy ước đặt tên và che thông tin nhạy cảm khi chụp ảnh, cuối cùng là checklist tiêu chí "demo thành công" cho từng kịch bản.

> **Nguyên tắc xuyên suốt:** mọi số liệu, ảnh chụp, dòng log trong báo cáo phải đến từ lab riêng của nhóm, với mật khẩu giả định và tên miền giả định (ví dụ `lab.example`, `example.invalid`). Không dùng hệ thống thật, không tấn công ra ngoài phạm vi lab, không phát tán thư thật.

### 8.1. Bố cục báo cáo đề xuất

Báo cáo đề xuất gồm **10–15 trang thân** (không tính phụ lục), theo trình tự sau. Cấu trúc này đi theo đúng logic "học → làm → chứng minh → đánh giá" mà hội đồng thường chờ đợi ở đồ án an toàn thông tin cấp đại học: người đọc phải thấy bạn hiểu bản chất giao thức trước, rồi mới thấy bạn làm chủ công cụ.

| Phần | Dung lượng | Nội dung chính |
|---|---|---|
| Trang bìa | 1 | Tên đồ án, lớp, mã nhóm NN, thành viên, GVHD, học kỳ |
| Abstract / Tóm tắt | 0,5 | 150–250 từ: tóm tắt vấn đề (dịch vụ FTP/mail dễ bị nghe lén & brute-force), phương pháp (lab + 3 kịch bản), kết quả chính, kết luận |
| Mục lục | 0,5 | Tự động sinh (LibreOffice/Word → References → Table of Contents) |
| 1. Giới thiệu | 1 | Động lực, mục tiêu, phạm vi; **nêu rõ giới hạn lab**: mạng ảo riêng (VirtualBox/VMware NAT + host-only), không kết nối internet công cộng, mọi attack chỉ nhắm vào máy trong lab của nhóm |
| 2. Kiến thức nền | 2–3 | Tóm tắt chương 1–2: mô hình client-server, bắt tay ba bước (three-way handshake), TCP ports, vòng đời SMTP transaction, mô hình mailbox của IMAP vs POP3, khác biệt SFTP (ứng dụng SSH) so với FTPS (FTP + TLS) |
| 3. Môi trường lab & triển khai | 2–3 | Sơ đồ tô-pô (2–3 VM Ubuntu Server: srv-ftp, srv-mail, máy attacker Kali/Ubuntu client); **bảng cấu hình chính — chỉ liệt kê tham số bảo mật**: `ssl_enable`, `anonymous_enable=NO`, `chroot_local_user=YES`, Postfix `smtpd_relay_restrictions`, Dovecot `ssl`, jail fail2ban, rule iptables/nftables. Không copy toàn file cấu hình vào thân báo cáo — để ở phụ lục |
| 4. Phân tích nguy cơ | 2 | Bảng nguy cơ → dấu hiệu → log → phòng ngừa (bản rút gọn của mục 8.3 bên dưới, đầy đủ 13 dòng) |
| 5. Thực nghiệm 3 kịch bản A/B/C | 3–4 | Mỗi kịch bản theo 5 bước: **mục tiêu → cách làm → kết quả → ảnh chứng minh → kết luận**. Đây là phần "ăn điểm" nhất — ảnh phải sắc nét, có khung đỏ đánh dấu dòng quan trọng |
| 6. Đánh giá & khuyến nghị | 1–1,5 | Những gì lab chứng minh được; **what-if nếu có thêm thời gian**: tự động hóa chứng thư bằng ACME/Let's Encrypt (hết hạn cert là lỗi kinh điển), gom log vào SIEM (Wazuh/Grafana+Loki) thay vì đọc tay, MFA cho SSH/webmail; thừa nhận hạn chế (lab nhỏ, chưa lượng traffic lớn, fail2ban không chống được distributed low-and-slow) |
| 7. Kết luận | 0,5 | Trả lời đúng mục tiêu đã nêu ở phần 1 |
| Phụ lục | không giới hạn | A: cấu hình đầy đủ; B: bảng log gốc (raw log trích đoạn); C: checklist demo của mục 8.6 |

Mẹo trình bày: thống nhất font (Times New Roman 13 hoặc 14 cho tiếng Việt có dấu hiển thị tốt), mã nguồn/log để trong khung `monospace`, mỗi ảnh có caption "Hình N: mô tả — chụp tại srv-ftp-NN, ngày ...".

Nguồn: kinh nghiệm trình bày báo cáo đồ án; tài liệu giao thức dẫn ở 8.2.

### 8.2. Bảng so sánh 5 giao thức (đưa vào chương 2 hoặc phụ lục)

Bảng này nên đặt ở đầu phần phân tích để giám khảo có "bản đồ" trước khi đi vào chi tiết. Đọc bảng cần nắm hai khái niệm: **mã hóa ở lớp nào** — SFTP mã hóa ngay từ gói đầu tiên vì nó là kênh con (channel) của SSH, còn FTP/SMTP/POP3/IMAP gốc đều khởi sinh (originate) từ plaintext rồi mới "nâng cấp" lên TLS qua lệnh STARTTLS/AUTH TLS (hoặc dùng biến thể cổng kín như FTPS/IMAPS/POP3S). Đó chính là gốc rễ của các tấn công downgrade/stripping ở chương 4.

| Giao thức | RFC/chuẩn | Mục đích | Cổng mặc định (明文 — plaintext) | Cổng an toàn | Có encryption mặc định? | Xác thực | Mô hình | Ghi chú |
|---|---|---|---|---|---|---|---|---|
| FTP | RFC 959 (1985) | Truyền file | 21 (điều khiển) + 20 (data ở active mode) | — (bản thân không có) | **Không** — USER/PASS đi rõ văn bản | username/password FTP thuần | Client–server, 2 kênh TCP tách biệt | Đã cũ; chuyển sang SFTP/FTPS. Lệnh PORT/EPRT tạo kênh data → nguy cơ FTP bounce |
| SFTP | Không phải RFC chuẩn hóa độc lập — đặc tả IETF draft `draft-ietf-secsh-filexfer` (SSH File Transfer Protocol), chạy trên SSH (RFC 4253) | Truyền file | — | 22 (chung cổng SSH) | **Có** — toàn bộ phiên nằm trong encrypted SSH transport | Key SSH / password qua kênh đã mã hóa | Client–server, 1 kênh TCP | Khác FTPS hoàn toàn; không có khái niệm active/passive data port → dễ firewall |
| SMTP | RFC 5321 (2008) | Gửi/mail transfer | 25 (MTA-to-MTA) | 587 submission + STARTTLS (RFC 3207, RFC 6409); 465 SMTPS | **Không** — mặc định明文, nâng cấp bằng `STARTTLS` | Có/không `AUTH` (SASL); MTA-to-MTA thường không auth | Store-and-forward, push | OPEN RELAY = cấu hình sai nghiêm trọng nhất |
| POP3 | RFC 1939 (1996) | Nhận mail (download-and-delete) | 110 | 995 (POP3S) | **Không** — `USER`/`PASS` rõ văn bản | USER/PASS hoặc APOP (yếu) | Client–server, kéo (pull) | STATELESS sau download; không phù hợp multi-device |
| IMAP | RFC 9051 — **IMAP4rev2 (2021)**, thay thế RFC 3501 (IMAP4rev1, 2003) | Nhận mail (server-side mailbox) | 143 | 993 (IMAPS) | **Không** mặc định, có `STARTTLS`; IMAP4rev2 coi TLS là bắt buộc cho triển khai mới | LOGIN/SASL; rev2 tích hợp sẵn SASL-IR, IDLE, MOVE | Client–server, đồng bộ mailbox 2 chiều | Phức tạp hơn POP3 → attack surface lớn hơn |

Ba điểm cần "đọc thấy" từ bảng:

1. **Cả 5 giao thức gốc đều được thiết kế trước khi TLS phổ biến** (RFC 951/959 là 1984–1985, RFC 821/SMTP 1982, POP3 từ 1988→1996). Vì vậy encryption là "dán thêm" (STARTTLS/AUTH TLS) chứ không phải mặc định — đây là lý do Wireshark vẫn bắt được mật khẩu FTP/POP3/IMAP/SMTP AUTH trong lab của ta.
2. **SFTP là kẻ duy nhất có encryption mặc định**, không phải vì thiết kế tốt hơn mà vì nó sinh sau (1997–2001, trong lòng SSH) và thừa kế encrypted transport.
3. Chuẩn hiện hành đã "dời" về phía encryption: TLS 1.3 là RFC 8446, **RFC 8996 (2021) chính thức deprecated TLS 1.0/1.1**; IETF cũng khuyến cáo "cleartext considered obsolete" cho mail (RFC 8314). Trong lab, nếu client của nhóm vẫn kết nối được bằng TLS 1.0 thì đó là bằng chứng server cần sửa.

Nguồn:
- https://www.rfc-editor.org/rfc/rfc959
- https://www.rfc-editor.org/rfc/rfc5321
- https://www.rfc-editor.org/rfc/rfc1939
- https://www.rfc-editor.org/rfc/rfc9051
- https://www.rfc-editor.org/rfc/rfc4253
- https://www.rfc-editor.org/rfc/rfc8446
- https://www.rfc-editor.org/rfc/rfc8996
- https://www.rfc-editor.org/rfc/rfc8314

### 8.3. Bảng ánh xạ Nguy cơ → Dấu hiệu → Log → Phòng ngừa

Đây là "xương sống" của chương 4 báo cáo, gộp từ chương 4 (nguy cơ), chương 5 (log & phát hiện sớm) và chương 6 (phòng ngừa) của đồ án. 13 dòng, mỗi dòng là một cặp attack–defense khép kín, đúng tinh thần "attacker chỉ cần 1 lỗi, defender phải vá hết". Khi đưa vào báo cáo chính, giữ nguyên thứ tự theo giao thức để người đọc khỏi nhảy cóc.

| # | Nguy cơ (risk) | Dấu hiệu (sign) quan sát được | Log (đường dẫn thật trong lab Ubuntu) | Phòng ngừa chính |
|---|---|---|---|---|
| 1 | Nghe lén mật khẩu FTP (plaintext sniffing) | Trong capture Wireshark xuất hiện dòng `USER labftp01` / `PASS passlab123` rõ văn bản | Không có trong log server (server không biết bị sniff) → phát hiện bằng capture phía mạng | Thay FTP bằng SFTP/FTPS; buộc `ssl_enable=YES`, `local_umask`, `ftp_ssl_enable`... với vsftpd: `ssl_enable=YES` + `allow_anon_ssl=NO` |
| 2 | Brute-force đăng nhập FTP | Chuỗi `FAIL LOGIN` lặp cùng IP, nhịp đều mỗi ~1s | `/var/log/auth.log` (PAM: `pam_unix(vsftpd:auth): authentication failure`) + `/var/log/vsftpd.log` nếu bật `xferlog_enable` | fail2ban jail `[vsftpd]`, `maxretry=5`, `bantime` tăng dần; password độ dài ≥12 |
| 3 | Anonymous FTP bị lợi dụng upload malware | Thư mục `incoming/` có file lạ; log `OK UPLOAD` từ user `ftp`/`anonymous` | `/var/log/vsftpd.log` (dòng `upload` khi `xferlog_std_format=NO`), `find /srv/ftp -newer ...` | `anonymous_enable=NO`; nếu bắt buộc: read-only, no-write, cách ly thư mục |
| 4 | FTP bounce / PORT độc hại (server connect trở lại host khác) | Log kết nối data tới IP/port bất thường, `connect_timeout` lặp | `/var/log/vsftpd.log`; `ss -tnp` thấy server initiate kết nối outbound port cao | `pasv_enable=YES` + `pasv_min_port`/`pasv_max_port` chặn ở firewall; vsftpd tự chặn PORT ngoài cùng IP |
| 5 | Brute-force SSH/SFTP | `/var/log/auth.log`: `Failed password for invalid user` dày đặc từ 1 IP | `/var/log/auth.log` (journald: `journalctl -u ssh`) | Jail `[sshd]` của fail2ban; khóa password auth: `PasswordAuthentication no`, chỉ dùng key |
| 6 | Open relay SMTP (spammer dùng server gửi ra ngoài) | Queue đầy mail tới domain lạ: `postqueue -p` / `mailq` nhiều dòng `*@*` ngoài lab | `/var/log/mail.log`: `status=sent` tới recipient ngoài, kèm IP client lạ | Postfix: `smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination` |
| 7 | Brute-force SMTP AUTH | `SASL LOGIN authentication failed` lặp | `/var/log/mail.log` (Postfix) + `/var/log/auth.log` (saslauthd) | Jail `[postfix-sasl]`, rate-limit submission, fail2ban |
| 8 | Giả mạo email (spoofing domain của lab) | Nhận thư có `From: admin@lab.example` trong khi lab không gửi | `/var/log/mail.log` dòng `header=Received` chuỗi đầu cuối; kiểm tra DNS SPF | SPF (RFC 7208) `-all`, DKIM (RFC 6376) ký bởi OpenDKIM, DMARC (RFC 7489) `p=quarantine`→`reject` |
| 9 | Nghe lén POP3/IMAP password | Capture thấy `USER`/`PASS` (POP3) hoặc `LOGIN "..." "..."` (IMAP)明文 | Server không log nội dung → chỉ phát hiện được khi phân tích mạng | Dovecot: `ssl = required`, tắt plaintext auth; dùng cổng 993/995 |
| 10 | Brute-force IMAP/POP3 | `Disconnected (Auth failed)` lặp cùng IP trong 1 phút | `/var/log/mail.log` (Dovecot: `auth: Info: ... Disconnected (Auth failed)`) | Jail `[dovecot]` của fail2ban; lockout theo user |
| 11 | Chứng thư hết hạn / self-signed bị bỏ qua (MITM) | Client Thunderbird báo `Your certificate is not secure` hoặc im lặng vì user bấm "Accept" | Nhật ký cert phía server không có; check `openssl s_client -connect ...:993` → `NotAfter` | Cert tự động qua ACME (certbot) — hết hạn là lỗi vận hành, không phải lỗi tấn công; pin cert |
| 12 | Lấn chiếm ngoài chroot của user FTP | User `labftpNN` đọc được `/etc/passwd` qua symlink hoặc upload vào web dir | `/var/log/vsftpd.log`; `find` trong home bất thường | `chroot_local_user=YES`, `secure_chroot_dir` của vsftpd; chmod 750, owner root cho thư mục gốc chroot |
| 13 | Quét cổng & enumeration (đ reconnaissance) | `ss -tlnp` cho thấy 21/110/143 vẫn mở dù đã "khai tử" service; log `connect timeout`/RST dồn dập | `/var/log/kern.log` nếu iptables `LOG`; `nmap` chủ động phía attacker phát hiện | Đóng cổng PLAINTEXT 21/110/143 bằng firewall: chỉ expose 22, 990, 993, 995, 587; ẩn banner |

Cách dùng bảng trong báo cáo: mỗi dòng nên được "neo" bằng ít nhất 1 ảnh chứng minh ở chương 5 (mục 8.4 liệt kê ảnh nào). Bảng này cũng là cơ sở cho kết luận phần 6: mọi nguy cơ đều có ít nhất một lớp phòng thủ "cấu hình đúng" — không nguy cơ nào cần công cụ thương mại.

Nguồn:
- https://www.rfc-editor.org/rfc/rfc7208 (SPF)
- https://www.rfc-editor.org/rfc/rfc6376 (DKIM)
- https://www.rfc-editor.org/rfc/rfc7489 (DMARC)
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/monitoring_and_managing_system_status_and_health/configuring-the-very-secure-ftp-daemon-vsftpd-for-file-transfers_monitoring-and-managing-system-status-and-health (vsftpd security options)
- https://www.postfix.org/STANDARD_CONFIGURATION_README.html
- https://doc.dovecot.org/configuration_manual/authentication/
- https://github.com/fail2ban/fail2ban (jail/filter mẫu trong `filter.d/`, `jail.d/`)
- https://documentation.ubuntu.com/server/how-to/security/ (Ubuntu Server docs: openssh, firewall)

### 8.4. Danh sách ảnh cần chụp (checklist khi demo)

Ảnh là bằng chứng. Một demo "chạy được" mà không có ảnh đúng chuẩn cũng mất điểm như demo lỗi. Khi kết thúc buổi demo, từng thành viên đối chiếu danh sách này — thiếu ảnh nào phải chụp bù ngay khi môi trường còn sống (đặc biệt các ảnh "trước khi" — vì sau khi bật phòng thủ thì không chụp lại được trạng thái yếu nữa). Quy ước đặt tên theo mục 8.5.

| # | Nội dung ảnh | Chụp trên | Chứng minh cho dòng bảng 8.3 |
|---|---|---|---|
| 1 | Sơ đồ tô-pô lab (vẽ draw.io, chụp màn hình) | — | Giới hạn phạm vi an toàn (mục 1 báo cáo) |
| 2 | `ss -tlnp` hiển thị toàn bộ listening ports | srv-ftp-NN, srv-mail-NN | Trạng thái cổng trước/sau hardening |
| 3 | Wireshark capture phiên FTP thấy `USER`/`PASS` rõ văn bản — **follow TCP stream**, khung đỏ 2 dòng đó, redact phần không liên quan | Máy attacker | Dòng 1, 9 |
| 4 | Wireshark capture cùng cảnh với SFTP: chỉ toàn entropy, KHÔNG có chuỗi `USER` | Máy attacker | Đối chứng: SFTP an toàn |
| 5 | `/var/log/auth.log` thời điểm TRƯỚC khi bật fail2ban: dày đặc `FAIL LOGIN` / `Failed password` | srv-ftp-NN / srv-mail-NN | Dòng 2, 5, 10 |
| 6 | `fail2ban-client status sshd` (và `vsftpd`) — thấy `Currently banned: N` | srv-mail-NN | Dòng 5: hệ thống phản ứng |
| 7 | `ipset list f2b-sshd` hoặc `iptables -L -n -v` thấy IP test nằm trong chain `FAIL2BAN-SSH` | srv-mail-NN | Bằng chứng "ban thật", không phải log suông |
| 8 | Terminal client bị timeout/không connect được sau khi ban (chứng minh bantime có hiệu lực) | Máy attacker | Kiểm thử end-to-end |
| 9 | Kết quả `swaks`/`nc` cho SMTP TRƯỚC hardening: `250 2.0.0 Ok: queued` khi relay ra ngoài | srv-mail-NN | Dòng 6 (open relay mở) |
| 10 | Cùng lệnh SAU hardening: `554 5.7.1 <user@example.org>: Relay access denied` | srv-mail-NN | Dòng 6 (đã đóng) — cặp ảnh 9/10 là "ảnh đinh" của kịch bản C |
| 11 | Hội thoại `EHLO` hiển thị `250-STARTTLS` trước/sau, hoặc Thunderbird dialog cấu hình IMAPS (cổng 993, `SSL/TLS`) | Máy client | Dòng 9, 11 |
| 12 | `postconf -n` / `postqueue -p` rỗng + `mail.log` cho thấy auth submission thành công (`status=sent` khi có SASL) | srv-mail-NN | Dòng 6, 7: relay đúng phải vẫn chạy |
| 13 | `diff -u vsftpd.conf.before vsftpd.conf.after` (hoặc highlight 4 dòng thay đổi) | srv-ftp-NN | Dòng 1, 3, 12: giá trị của hardening là cấu hình |
| 14 | Đầu ra `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` (fingerprint) — minh chứng không chụp private key | srv-*-NN | Tuân thủ mục 8.5 |
| 15 | `fail2ban-regex /var/log/auth.log filter` chạy khớp N dòng (tránh bantime "ảo" do regex sai) | srv-mail-NN | Độ tin cậy phát hiện sớm |

Yêu cầu kỹ thuật chung cho mọi ảnh: độ phân giải đủ đọc chữ (≥1280px ngang), font terminal to vừa phải, nền tối chữ sáng đồng nhất, và **duy nhất một thông điệp mỗi ảnh** — đánh mũi tên/ô đỏ vào đúng dòng cần xem, caption ghi rõ ảnh chứng minh điều gì.

Nguồn:
- https://www.wireshark.org/docs/ (Guide: Follow TCP Stream; filter `ftp`, `ssh`)
- https://github.com/jetmore/swaks (công cụ SMTP test — ảnh 9, 10, 12)
- https://www.thunderbird.net/ (client cho ảnh 11)

### 8.5. Quy ước đặt tên theo nhóm và che thông tin nhạy cảm

**Vì sao phải đặt tên theo mã nhóm (NN).** Khi nhiều lab của các nhóm cùng chạy trên một phòng máy / cùng dải VLAN, và khi ảnh của em nằm lẫn trong phụ lục của nhóm khác, giám khảo cần trả lời được trong 5 giây: "cái này là của ai, kịch bản nào, trước hay sau khi sửa?". Vì vậy thống nhất:

- **Hostname:** `srv-ftp-NN`, `srv-mail-NN`, `attacker-NN` (NN = mã nhóm 2 chữ số). Đặt trong `/etc/hostname` + `/etc/hosts` — và vì hostname xuất hiện trong SMTP banner/Helo, chỉ cần nhìn log là biết của nhóm nào.
- **User FTP:** `labftpNN` (không dùng tên chung `ftpuser` vì dễ trùng khi gom file).
- **Subject email test:** `[LAB-NN] demo relay test` — để khi lục `mail.log` hoặc queue, dòng của nhóm mình nổi lên ngay, và khi lỡ có thư "thoát" ra ngoài thì cũng nhận diện được nguồn gốc tức thì (dù theo nội quy, thư không được phép ra ngoài lab).
- **File ảnh bằng chứng:** `NN-<kịch bản>-<công cụ>-<nội dung>[-<thời điểm>].png`, ví dụ `01-A-wireshark-ftp-plaintext-before.png`, `01-C-postfix-relay-554-after.png`.
- **Tên mail domain lab:** `lab.example` hoặc `example.invalid` (`.invalid`, `.example`, `.test` là các TLD được RFC 6761/2606 dành riêng cho mục đích thử nghiệm — không bao giờ resolve ra hệ thống thật, nên dù có lỗi cấu hình cũng không gửi thư tới người dùng thật được).

**Che thông tin nhạy cảm trong ảnh (redaction).** Báo cáo và ảnh có thể được upload lên LMS — coi như đã "công bố". Do đó:

1. **Không dùng mật khẩu thật ở bất kỳ đâu**, kể cả trong lab. Toàn bộ demo dùng mật khẩu giả định công khai trong báo cáo: `passlab123`. Lý do kép: không lộ pass thật nếu ảnh bị phát tán; và giám khảo đọc được đúng pass để hiểu capture.
2. **Redact trước khi nộp** bằng Paint/GIMP: che IP công cộng (nếu VM có NAT/IP thật ngoài dải lab), hostname máy của trường, tên người dùng Windows trong đường dẫn `C:\Users\...`. Kỹ thuật: hình chữ nhật đặc (solid fill), KHÔNG dùng bút nhớ mờ/blur nhẹ — blur vẫn có thể recover được bằng công cụ.
3. **Private key: không bao giờ chụp**, kể cả đã "che một phần". Chỉ chụp fingerprint: `ssh-keygen -lf ~/.ssh/id_ed25519.pub` (fingerprint là dữ liệu công khai, an toàn). Tương tự, chỉ chụp `.pub`, không chụp file không đuôi.
4. **Không chụp `/etc/shadow` thật.** Nếu cần minh chứng hash, dùng hàng mẫu: `labftp01:$6$rounds=...$<hash-mẫu>:0:99999:7:::` tự sinh trên máy khác hoặc bịa giá trị hash.
5. **Mật khẩu mặc định phải đổi trước khi demo live** — một giám khảo có thể bấm "thử đăng nhập" ngay; nếu họ vào được bằng `admin/admin` thì mọi ảnh chứng minh đều vô giá trị.
6. Khi quay màn hình/ảnh, đóng mọi tab trình duyệt, messenger có chứa thông tin cá nhân; chụp ở độ phân giải vừa đủ, không "chụp luôn cả desktop 4K" rồi mới cắt — dễ sót vùng chưa redact.

Nguồn:
- https://www.rfc-editor.org/rfc/rfc6761 (Special-Use Domain Names: `.invalid`)
- https://www.rfc-editor.org/rfc/rfc2606 (Reserved Top-Level DNS Names: `.example`, `.test`)
- https://www.gimp.org/ (công cụ redact)

### 8.6. Tiêu chí đánh giá demo thành công (checklist từng kịch bản)

Mỗi kịch bản cần "đỗ" theo tiêu chí đo được (objective) — không chấp nhận "demo đại khái nó chạy". Khuyến nghị: tập dượt theo đúng checklist này, người này đóng vai giám khảo bấm từng dòng; kết quả tick được ghi chú vào cột bên cạnh khi nộp phụ lục.

**Kịch bản A — Sniffing plaintext (FTP/SFTP đối chứng):**
- [ ] Trên capture Wireshark của phiên FTP, chỉ ra ĐÚNG dòng `USER labftpNN` và `PASS ...` trong cửa sổ "Follow TCP Stream", không phải dòng lệnh khác.
- [ ] Nêu được vì sao dòng đó nằm ở kênh điều khiển (control connection, port 21) chứ không phải kênh data — và vì sao cả file truyền cũng thấy rõ nếu bắt đúng kênh data.
- [ ] Capture SFTP cùng bài toán: khẳng định "không có chuỗi `USER` nào" bằng cách dùng chính Filter của Wireshark (`user contains "USER"` trên cả packet), giải thích payload nằm trong SSH binary packet protocol đã mã hóa.
- [ ] Kết luận nêu được 1 limitation: capture được là vì lab đặt switch/mirror/NAT cùng máy — trên mạng thật khó hơn, nhưng phòng thủ vẫn là TLS, không phải "hy vọng không bị bắt gói".

**Kịch bản B — Brute-force + fail2ban (SSH/FTP):**
- [ ] Trong `auth.log` đếm đủ **N lần FAIL** đúng như số lần thử đã khai (ví dụ N=10), chỉ ra failregex khớp bằng lệnh `fail2ban-regex`.
- [ ] `fail2ban-client status <jail>` hiện `Currently banned: 1` đúng IP máy attacker (IP lab, đã redact trên ảnh nếu công bố).
- [ ] **Kiểm tra tầng nhân:** `ipset list f2b-<jail>` (hoặc `iptables -S`) cho thấy IP thực sự nằm trong set bị DROP — chứng minh ban có tác động ở kernel netfilter, không chỉ "ghi log".
- [ ] Test lại từ máy attacker: kết nối mới **timeout** (không phải connection refused — vì DROP không trả RST; đây là điểm dễ bị hỏi, cần giải thích được).
- [ ] **UNBAN trước khi kết thúc demo:** `fail2ban-client unban <IP>`, xác nhận `Currently banned: 0`, để không khóa chính mình khi hội đồng kiểm tra.
- [ ] Nói được 1 bypass còn tồn tại: distributed botnet với mỗi IP ≤ maxretry thì fail2ban không bắt được → lý do phải kết hợp rate-limit + strong password.

**Kịch bản C — Open relay → đóng relay + submission có auth:**
- [ ] Trước hardening: swaks tới cổng 25 từ attacker được trả **`250`** (queued) khi recipient KHÔNG thuộc `mydestination`/`mynetworks` — chỉ ra đúng dòng đó.
- [ ] Sau hardening (`reject_unauth_destination`): cùng lệnh trả **`554 5.7.1 Relay access denied`** — cặp trước/sau phải hiển thị cạnh nhau trong cùng 1 ảnh.
- [ ] Có auth: submission qua cổng 587 với `-au user -ap passlab123 -tls` được **`250`** và recipient trong lab nhận được — chứng minh "đóng relay nhưng không đóng mail hợp lệ".
- [ ] **Không spam ra ngoài được**: giải thích vì sao recipient `@gmail.com` bị 554, đồng thời nhắc lab không (và không được) gửi thư thật ra internet.
- [ ] Bonus (nếu chuẩn bị trước): gửi thư `From: admin@lab.example` từ attacker KHÔNG qua auth bị DKIM/DMARC kiểm — hoặc trình bày record SPF `v=spf1 -all` bằng `dig TXT`.

**Toàn bộ buổi demo (chung):**
- [ ] Giới thiệu phạm vi lab trong 30 giây đầu ("mọi attack nhắm vào VM của nhóm trong mạng ảo riêng").
- [ ] Thời lượng ≤ quy định (thường 15–20 phút): phân bổ 5 phút A, 6 phút B, 6 phút C, 3 phút Q&A nháp.
- [ ] Mọi ảnh trong 8.4 có file tương ứng theo đúng tên; sẵn sàng chiếu lại ảnh khi live có sự cố (kế hoạch B).
- [ ] Mỗi thành viên trả lời được 1 câu "vì sao" bất kỳ trong bảng 8.3 (chống tình trạng chỉ 1 người làm chính).

### 8.7. Ưu / nhược / kết luận từng giải pháp

Bảng 3 cột dưới đây chốt lại chương 6: giải pháp nào cũng có giá trị và cái giá của nó — đồ án chỉ thuyết phục khi nhóm dám nói "giải pháp X không phải viên đạn bạc". Giám khảo rất hay hỏi đúng phần "nhược".

| Giải pháp | Ưu điểm | Nhược điểm / giới hạn | Kết luận cho lab |
|---|---|---|---|
| **SFTP thay FTP** | Encryption mặc định toàn phiên + tính toàn vẹn; chỉ 1 cổng (22) dễ firewall; xác thực key chống phishing/brute password tốt | Không có semantic của FTP (không "resume qua lệnh REST chuẩn" — thuộc implementation); không thay thế được FTP trong workflow legacy đòi cổng 21 | **Khuyến nghị số 1** cho truyền file nội bộ; lab bắt buộc dùng nó |
| **FTPS (explicit AUTH TLS, RFC 4217)** | Giữ được client/tool cũ chỉ thêm TLS; `ftptls` vsftpd bật được sau 1 cert | Phức tạp vì vẫn mang 2 kênh + passive port range; phải mở range cổng trên firewall; dễ cấu hình sai `require_cert`; không phải lựa chọn IETF khuyến khích mới | Dùng khi buộc giữ FTP; còn lại chọn SFTP |
| **TLS 1.2/1.3 + cipher hiện đại (ECDHE-AES-GCM/CHACHA20)** | Forward secrecy; chống được sniffing + MITM thụ động; chuẩn hóa (RFC 8446) | Cert phải quản lý vòng đời (hết hạn = hỏng dịch vụ hoặc user quen bấm "Accept" → thành vô nghĩa); self-signed không tạo niềm tin | Bắt buộc cho mọi dịch vụ; **tự động hóa bằng ACME/certbot** nếu có thời gian (khuyến nghị 6.3) |
| **SPF + DKIM + DMARC** | Phòng spoofing ở tầng DNS — chuẩn duy nhất chống "giả email domain lab"; DMARC cho biết ai đang giả mạo (báo cáo) | SPF vỡ khi forward mail (giải bằng ARC/redirect); DKIM phải ký đúng selector; triển khai 3 tầng cần phối hợp, không "bật 1 nút"; chỉ bảo vệ domain, không chống phishing nội dung | Lab chỉ cần chứng minh `p=reject` + test trên chính `example.invalid` |
| **fail2ban** | Phát hiện sớm + phản ứng tự động, zero-config cho sshd/vsftpd/dovecot/postfix jail mẫu; chi phí = 0 | Chỉ phản ứng theo log → failregex sai là "bantime ảo"; chậm hơn attack nhanh; thua low-and-slow distributed; có thể ban nhầm (self-ban) → phải có `ignoreip` và quy trình unban | **Đủ cho lab qui mô nhỏ**; ngoài production cần tính đến blocklist/WAF/SIEM |
| **Firewall đóng cổng plaintext (21/25/110/143 → chỉ mở 22/990/587/993/995)** | Biện pháp rẻ nhất, "một phát ăn ngay" — attack surface giảm ngay cả khi service còn lỗi; dễ demo bằng `ss -tlnp` | Không mã hóa nội dung nếu service bên trong vẫn明文 ở NIC nội bộ; không chống được abuse qua chính cổng mở (authenticated spam) | Bắt buộc làm trước khi demo — "defense in depth" bắt đầu bằng việc tắt cái không cần |
| **chroot + tắt anonymous (vsftpd)** | Ngăn user FTP nhìn ra hệ thống tệp; chặn đường upload-malware công khai | vsftpd yêu cầu `allow_writeable_chroot` khi chroot writable → cần cấu hình đúng chuỗi tham số; user vẫn đọc/ghi được file trong jail của mình | Bật mặc định; chỉ cho write vào thư mục `incoming` có quyền owner riêng |
| **Queue/mail-log monitoring (postfix + dovecot logs về một chỗ)** | Phát hiện sớm abuse: `status=sent` lạ, backlog tăng, `Auth failed` dồn — dữ liệu có sẵn, không thêm phần mềm | Đọc log tay không scale; log rotate + timestamp format giữa Ubuntu versions dễ gây nhầm khi phân tích | Lab: kết hợp `journalctl -u postfix -f` + `grep`; khuyến nghị gom về Grafana/Loki/Wazuh nếu mở rộng |

Điểm tổng của bảng: không có giải pháp nào đứng một mình — "đóng cổng plaintext + TLS + auth mạnh + fail2ban + giám sát log" cộng lại mới thành phòng thủ; và mỗi ô "Nhược" chính là các câu what-if mà nhóm nên chủ động nêu ở phần Đánh giá thay vì đợi hội đồng hỏi.

Nguồn:
- https://www.rfc-editor.org/rfc/rfc4217
- https://certbot.eff.org/ (ACME)
- https://github.com/fail2ban/fail2ban/releases (1.1.1 — 2026-08-15; lưu ý `action.d/iptables.conf` được viết lại, ảnh hưởng jail custom)
- https://documentation.ubuntu.com/server/how-to/security/
- https://ubuntu.com/about/release-cycle (LTS hiện hành: 26.04 "Resolute Raccoon", 04/2026)

### 8.8. Checklist cuối trước khi nộp báo cáo

Rà 5 phút cuối — mỗi mục là một lỗi phổ biến từng gặp ở đồ án:

- [ ] Dòng đầu tiên mỗi chương đúng cấp heading quy ước; đánh số chương/mục nhất quán (8.1 → H3).
- [ ] Mọi bảng hiển thị không bị tràn lề khi in A4 (bảng 8.2/8.3 xoay ngang nếu cần).
- [ ] RFC dẫn trong 8.2 đúng số và đúng năm; không có "tin đồn công nghệ" không nguồn.
- [ ] 15/15 ảnh mục 8.4 có trong thư mục nộp, đúng tên quy ước 8.5, caption đủ nghĩa khi xem KHÔNG đọc ngữ cảnh.
- [ ] Đã redact xong: không còn IP công cộng, không còn tên user Windows, không private key, không `/etc/shadow` thật, không mật khẩu thật (chỉ `passlab123`).
- [ ] Kịch bản A/B/C mỗi cái có đủ 5 bước: mục tiêu → cách làm → kết quả → ảnh → kết luận.
- [ ] Phần "Giới hạn" nêu rõ: lab mạng riêng, chỉ tấn công máy của nhóm, không spam, không attack hệ thống công cộng — đây là tuyên bố tuân thủ đạo đức, phải có.
- [ ] Trang cuối: danh mục nguồn (gộp các URL mục 8.2–8.7), format thống nhất `[tác giả/nhà xuất bản, năm, URL]`, kiểm tra tất cả URL mở được.
- [ ] Đọc to 2 lần: câu nào đọc thấy "vừa hiểu vừa không hiểu" thì viết lại cho người mới bắt đầu — chuẩn viết của cả tài liệu này.
