## 4b. Nguy cơ và lỗ hổng: nhóm email, TLS và vòng đời phần mềm

Chương này tiếp quản chương 4a (nhóm FTP/SFTP) và đi qua nhóm dịch vụ còn lại của đồ án: **SMTP (Postfix), POP3/IMAP (Dovecot)**, cộng thêm hai mảng xuyên suốt mà mọi dịch vụ đều dính — **cấu hình TLS** và **vòng đời phần mềm** (update/EOL, cấu hình mặc định). Bảy nguy cơ dưới đây được trình bày theo đúng khung 5 mục của chương 4a: **Nguyên nhân → Điều kiện xảy ra → Dấu hiệu trong log → Ảnh hưởng → Phòng ngừa**, kèm dòng log mẫu của Postfix/Dovecot/vsftpd đúng định dạng syslog.

> **Phạm vi thử nghiệm:** mọi phép kiểm thử, đo tải, thử relay, quét cấu hình trong chương này chỉ thực hiện trên lab mạng riêng do nhóm sở hữu (các máy ảo nội bộ, không định tuyến ra Internet công cộng). Không dùng các trang "open relay test" công cộng, không gửi spam thật, không tấn công hệ thống của người khác. Tài liệu phục vụ mục đích giáo dục và phòng thủ.

Toàn cảnh chương:

| # | Nguy cơ | Dịch vụ liên quan | Bản chất một câu |
|---|---------|-------------------|------------------|
| 1 | SMTP open relay | Postfix | Server chuyển tiếp thư cho người lạ → thành máy phát spam |
| 2 | Spoofing / phishing / giả mạo tên miền | SMTP | Giao thức không bắt buộc kiểm tra địa chỉ `From:` |
| 3 | Mã độc trong upload/đính kèm | vsftpd + Postfix/Dovecot | Server trở thành ổ chứa và trạm trung chuyển malware |
| 4 | Lạm dụng SMTP AUTH | Postfix + Dovecot auth | Tài khoản bị đánh cắp → "relay hợp pháp" |
| 5 | DoS | SMTP/IMAP/POP3 | Làm kiệt tiến trình, hàng đợi hoặc đĩa |
| 6 | Lỗi cấu hình TLS | Mọi dịch vụ có STARTTLS/SSL | Mã hóa "cho có": cert self-signed, cipher yếu, bị strip |
| 7 | Phần mềm lỗi thời & cấu hình mặc định | vsftpd, OpenSSH, Postfix, Dovecot | CVE tích tụ + default vì compatibility, không vì security |

---

### 1. SMTP open relay — khi mail server của bạn phát thư hộ kẻ lạ

**Nguyên nhân.** *Open relay* là tình trạng máy chủ SMTP nhận thư từ người không thuộc hệ thống của mình và chuyển tiếp (relay) đi đến một tên miền thứ ba không thuộc hệ thống — tức trở thành "kẻ trung chuyển" cho kẻ tấn công. Ba nguồn gốc kinh điển của open relay, cả ba đều rất dễ gặp trong đồ án sinh viên:

- **Thói quen "mạng học thuật cũ".** Thời kỳ đầu của Internet (RFC 788 rồi RFC 821 — hai RFC SMTP sớm nhất), hầu hết mail server để mở relay vì (a) tài nguyên máy chủ còn hạn chế, khó bật xác thực, và (b) các trường đại học, viện nghiên cứu **cố ý** mở relay để giảng viên/gửi viên trong mạng học thuật gửi thư đi mọi nơi. Mô hình tin tưởng đó sụp đổ khi spam bùng nổ; SMTP hiện đại (RFC 5321, 2008) không còn hàm ý "ai cũng được relay".
- **`mynetworks` khai báo quá rộng.** Trong Postfix, tham số `mynetworks` (khai báo ở `/etc/postfix/main.cf`, xem tài liệu cấu hình cơ bản của Postfix) liệt kê những mạng được "tự động cho relay". Một dòng `mynetworks = 0.0.0.0/0` (đại loại "ai cũng là mạng nội bộ") biến server thành open relay hoàn toàn — đây là lỗi kinh điển khi migrate: copy `main.cf` máy cũ rồi nới `mynetworks` "cho đỡ lỗi relay denied" rồi quên siết lại.
- **Sửa cấu hình khi đang "chữa cháy" sau migrate.** Nhiều hướng dẫn trên mạng khuyên đặt `smtpd_recipient_restrictions = permit_mynetworks` mà thiếu điều kiện chặn cuối; hoặc tắt nhầm tính năng chặn. Lưu ý quan trọng đã được **kiểm chứng từ tài liệu chính thức của Postfix**: tham số `smtpd_relay_restrictions` có từ Postfix 2.10 (được đưa ra đúng như "lưới an toàn" chống open relay do chuỗi lọc spam trong `smtpd_recipient_restrictions`), và ở các bản Postfix hiện hành — mọi bản Ubuntu còn được hỗ trợ đều dùng nhánh 3.x — giá trị **mặc định an toàn** là
  `smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination`
  — tức mọi thư gửi đến địa chỉ không thuộc domain của ta, từ client chưa xác thực, sẽ bị từ chối/trì hoãn. (Ngoại lệ: khi nâng cấp từ cấu hình rất cũ, cơ chế `compatibility_level` có thể giữ hành vi default rỗng — vì vậy luôn kiểm tra bằng `postconf` thay vì tin vào trí nhớ.) Open relay thường **không** đến từ mặc định, mà đến từ việc người quản trị **ghi đè** mặc định đó bằng một chuỗi thiếu điều kiện chặn cuối.

**Điều kiện xảy ra.** Đủ ba yếu tố là có open relay: (1) server nghe cổng 25 ở interface tiếp xúc được từ ngoài; (2) chuỗi quan hệ `*_restrictions` cho phép RCPT (địa chỉ nhận) không thuộc `mydestination`/`virtual_mailbox_domains` mà không chặn; (3) không có `reject_unauth_destination`/`defer_unauth_destination` (hoặc tương đương) ở cuối chuỗi.

**Dấu hiệu trong log.** Open relay **để lại dấu vết rất đặc trưng** trong `/var/log/mail.log`. Khi kẻ lạ dùng server của bạn gửi thư cho hàng loạt địa chỉ xa, bạn sẽ thấy chuỗi ba loại dòng sau lặp lại với tần suất bất thường:

```log
# 1) Kết nối đến từ IP vô danh, tự khai helo giả, nhận nhiều RCPT "xa"
Aug 29 03:14:02 mail01 postfix/smtpd[28744]: connect from unknown[185.220.101.42]
Aug 29 03:14:05 mail01 postfix/smtpd[28744]: 5F3A2C19D4: client=unknown[185.220.101.42]

# 2) cleanup ghi nhận message-id, còn qmgr đưa VÀO HÀNG ĐỢI GỬI ĐI
#    (chứng tỏ thư đã ĐƯỢC ACCEPT, không bị reject)
Aug 29 03:14:05 mail01 postfix/cleanup[28750]: 5F3A2C19D4: message-id=<20260829031405.5F3A2C19D4@mail01.lab.local>
Aug 29 03:14:06 mail01 postfix/qmgr[1234]: 5F3A2C19D4: from=<promo@get-rich-quick.example>, size=4213, nrcpt=57 (queue active)
```

Ba tín hiệu để nhận diện: `from=<địa chỉ xa>`, `to=<nhiều địa chỉ xa>` — đặc biệt `nrcpt` (số người nhận trong một message) lớn bất thường (57 người nhận trong 1 message là chữ ký điển hình của spam list), và `client=unknown[IP]` (IP không phân giải được ngược, không TLS, không SASL) rồi hàng đợi `mailqueue` (`postqueue -p`) phình lên nhanh. Server cấu hình đúng **phải** log dòng reject thay vì chấp nhận:

```log
# Cấu hình ĐÚNG sẽ chặn và log thế này (Postfix ghi rõ "Relay access denied";
# với defer_unauth_destination mã là 454 4.7.1, với reject_unauth_destination là 554 5.7.1):
Aug 29 03:14:05 mail01 postfix/smtpd[28744]: NOQUEUE: reject: RCPT from unknown[185.220.101.42]:
  554 5.7.1 <victim@aol.example>: Relay access denied; from=<promo@get-rich-quick.example> to=<victim@aol.example> proto=ESMTP helo=<mail.get-rich-quick.example>
```

Gõ trong lab: `tail -f /var/log/mail.log | grep -E "Relay access denied|connect from"` để theo dõi realtime (chuỗi Postfix ghi là `Relay access denied`, không phải `relaydenied` — grep sai chuỗi sẽ trả 0 kết quả và tạo cảm giác yên tâm giả); `postqueue -p` để xem số lượng thư chờ gửi (chờ gửi nhiều tới domain lạ = nguy cơ).

**Ảnh hưởng.** Hậu quả của open relay không nằm trong LAN của bạn mà ở **danh sách chặn (DNSBL)**: chỉ sau vài phút, IP của bạn bị Spamhaus (SBL/XBL, gộp trong danh sách "Zen") và các blocklist khác ghi nhận; mọi thư **hợp lệ** của domain `lab.local`/domain trường gửi đi các nơi sẽ bị từ chối hoặc rơi vào spam. IP/domain "bị ô nhiễm" có khi mất nhiều tuần mới gỡ khỏi danh sách (yêu cầu xác minh cấu hình lại). Đây là lý do nhóm phải coi open relay là sự cố nghiêm trọng, không phải "lỗi nhỏ".

**Phòng ngừa.**
1. Kiểm tra chuỗi relay đang hoạt động thực tế: `postconf smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks` và đảm bảo còn hạn chế cuối chặn relay không xác thực.
2. Siết `mynetworks` đúng nghĩa: chỉ `127.0.0.0/8`, dải `10.x` nội bộ.
3. **Không** gửi thử relay qua website công cộng. Thay vào đó dùng chính server trong lab làm "máy khách": trên VM B (IP lạ, không nằm trong mynetworks), kết nối SMTP tới port 25 VM A rồi thử gửi tới một địa chỉ ngoài — server an toàn phải trả **`554 5.7.1 Relay access denied`** và log dòng NOQUEUE ở trên. (Về mặt tự động, có các thư viện/script kiểm tra relay — chỉ chạy giữa các máy của nhóm, không chạm hệ thống ngoài.)
4. Bật TLS opportunistically (`smtpd_tls_security_level = may`) và SASL cho submission (port 587) để relay "hợp pháp" qua xác thực, không qua IP nguồn.
5. Đưa giám sát `connect from unknown` + `nrcpt>` lớn vào cron alert; bật Fail2ban (mục 5) với filter `postfix-sasl`/`postfix-rbl` như lớp phòng thủ phụ.

**Nguồn:**
- Postfix — Configuration parameters (mặc định `smtpd_relay_restrictions`): https://www.postfix.org/postconf.5.html
- Postfix — SMTP relay and access control: https://www.postfix.org/SMTPD_ACCESS_README.html
- Postfix — SASL Howto: https://www.postfix.org/SASL_README.html
- RFC 5321 — Simple Mail Transfer Protocol: https://www.rfc-editor.org/info/rfc5321
- Spamhaus Blocklist: https://www.spamhaus.org/

---

### 2. Email spoofing, phishing và giả mạo tên miền

**Nguyên nhân.** Đây là điểm cần hiểu bản chất nhất chương: **SMTP (RFC 5321) không bắt buộc máy chủ kiểm tra tính xác thực của địa chỉ gửi.** Trong một phiên SMTP có tới *hai* "địa chỉ gửi":

```text
MAIL FROM:<envelope@sender.example>   ← envelope (SMTP command), dùng cho đường trả về
From: "Ngân hàng ACB" <cskh@acb-vip.example>   ← HEADER (RFC 5322), người dùng nhìn thấy
```

Hai cái này **hoàn toàn độc lập**: RFC cho phép MAIL FROM là bất kỳ chuỗi nào; header `From:` lại càng do người gửi tự viết, server không có nghĩa vụ xác minh. Do đó chỉ cần một server nhận thư bất kỳ (kể cả open relay như mục 1), kẻ tấn công ghi `From: Ngân hàng nọ <no-reply@nganhang.vn>` và mọi client mail hiển thị đúng như vậy. **Không có lỗ hổng phần mềm nào ở đây cả** — đó là thiết kế lịch sử của giao thức, và giải pháp (SPF/DKIM/DMARC — giải thích kỹ ở chương 6) là bổ sung ngữ nghĩa **bên trên** SMTP, không phải SMTP tự kiểm tra.

Ba biến thể người dùng hay mắc:
- **Display-name attack:** phần hiển thị `"Công ty ABC - Bộ phận IT"` gợi tin cậy, còn address thật là `abc-it-phishing@xyz.ru` — client thu gọn address, chỉ hiện display name.
- **Typosquatting domain:** đăng ký `g00gle-mail.com`, `trương-đại-học.edu.vn` (dấu tiếng Việt bị punycode hóa khó đọc)...
- **SMTP smuggling** (kỹ thuật nâng cao, có CVE thật): các biến thể xử lý dấu xuống dòng trong giao thức khiến server "nhìn thấy" một thư khác với thư server nhận kiểm tra DMARC. CVE xác minh được trong hệ sinh thái Exim: **CVE-2023-51766** — "SMTP smuggling", cho phép vượt DKIM để giả mạo người gửi, được vá ở Exim 4.97.1 (các sản phẩm khác cũng bị ảnh hưởng ở các mức khác nhau; bản vá của chúng được phát hành rộng rãi từ đầu 2024). Đừng nhầm với **CVE-2019-10149** — "The Return of the WIZard", một lỗi RCE Exim khác (xem mục 7).

**Điều kiện xảy ra.** (1) Server không áp dụng kiểm tra SPF/DKIM/DMARC ở chiều nhận **và** (2) người nhận không được cảnh báo. Server của nhóm nếu chỉ làm MTA chuyển tiếp thì không có lỗi nào — nhưng nếu nhóm dựng server nhận thư (MX cho domain nội bộ) thì thiếu kiểm tra xác thực phía nhận = tiếp tay phishing.

**Dấu hiệu trong log.** Spoofing **gần như vô hình trong log của server bạn**, trừ khi bạn là nạn nhân (thư bị bounce về `from=<địa chỉ bị giả mạo>` gây "backscatter"). Trong lab, cách duy nhất "nhìn thấy" nó là bật kiểm tra và đọc header:

```log
# Khi Postfix có policy server (postscreen/AMaVIS) hoặc header_checks, bạn có thể log:
Aug 29 09:02:11 mail01 postfix/smtpd[30102]: 9A21F0C4: client=dialer-42.isp.example[203.0.113.42]
# Và trong header Received của thư đến, so sánh MAIL FROM vs From — sẽ khác nhau.
```

Nghiên cứu header một thư mẫu bằng `less` / công cụ phân tích header trong lab: dòng nào đến từ máy chủ "không cùng nhà cung cấp với domain From:" là nghi ngờ.

**Ảnh hưởng.** Người dùng trong lab/trường bị dụ đăng nhập vào trang giả → mất credential (dẫn tới nguy cơ mục 4); tài khoản bị chiếm gửi phishing nội bộ rất khó bị chặn vì "đã được xác thực".

**Phòng ngừa.** Bật SPF/DKIM/DMARC trên domain của lab (chương 6 hướng dẫn cấu hình chi tiết); bật kiểm tra xác thực phía nhận bằng policy daemon; chặn backscatter bằng `smtpd_reject_unlisted_recipient = yes` (mặc định Postfix đã bật — để nguyên); và trên hết **đào tạo người dùng**: kiểm tra address thật (không chỉ tên hiển thị), không bấm link khi chưa xác minh qua kênh thứ hai.

**Nguồn:**
- RFC 5321 (SMTP envelope) và RFC 5322 (header `From:`): https://www.rfc-editor.org/rfc/rfc5321 / https://www.rfc-editor.org/rfc/rfc5322
- Postfix — SMTP smuggling advisory: https://www.postfix.org/smtp-smuggling.html
- NVD — CVE-2023-51766 (Exim SMTP smuggling): https://nvd.nist.gov/vuln/detail/CVE-2023-51766
- CERT/CC — VU#517845: authenticated SMTP users may spoof other identities (ambiguous "From" header): https://www.kb.cert.org/vuls/id/517845

---

### 3. Mã độc trong file upload và đính kèm

**Nguyên nhân.** Ba "cửa" đưa file độc vào hạ tầng lab và hợp nhất thành một chuỗi lây nhiễm: **anonymous upload của FTP** (vsftpd `anonymous_enable=YES` + `write_enable=YES` — chương 4a đã nói), **đính kèm email** (server nhận thư ai cũng gửi vào được), và **hành vi người dùng** mở `.exe`/`.scr`, `.docm`/`.xlsm` có macro. Bản chất: dịch vụ **không có nghĩa vụ** kiểm tra nội dung file — đó là tầng ứng dụng mà quản trị phải tự bổ sung thêm (antivirus daemon, content filter).

**Điều kiện xảy ra.** (1) Thư mục upload/anonymous có quyền ghi; (2) không có quét virus hoặc quét chỉ theo lịch (file đã nằm đó hàng giờ trước khi ai đó đọc `virus_scanner.log`); (3) người nhận bật macro Office; (4) thư mục upload nằm trên filesystem **cho phép thực thi** (đó là lý do mount option `noexec` — chương 4a — tồn tại).

**Dấu hiệu trong log.** vsftpd log upload với timestamp + user + kích thước (`/var/log/vsftpd.log`, định dạng "full time log"):

```log
Sat Aug 29 02:41:07 2026 [pid 22318] [ftp] UPLOAD: /incoming/invoice_final.exe  482304 bytes <- [185.220.101.42]
Sat Aug 29 02:41:09 2026 [pid 22318] [ftp] 1 files uploaded
```

Phía mail, thư có attachment nghi vấn thể hiện qua `postfix/cleanup` (kích thước lớn, message-id lạ) và log của content filter (nếu có amavisd/clamav):

```log
Aug 29 02:52:33 mail01 amavis[2311]: (2311-05) Passed CLEAN {RelayedInbound}, [203.0.113.42]:51772 [spam@x.example] -> <labmate@lab.local>, Queue-ID: 5F3A2C19D4, Message-ID: <20260829025201.9F1C@x.example>, Size: 482304, Elapsed time 1.2
Aug 29 02:52:33 mail01 clamd[2455]: /var/lib/amavis/tmp/amavis-20260829-0251/amavis@2311.12345: Eicar-Test-Signature FOUND   ← nếu bật scan
```

Trong lab, dùng chuỗi chuẩn **EICAR** (tệp test vô hại 68 ký tự) làm mẫu để kiểm pipeline quét có hoạt động hay không — đây là kỹ thuật kiểm tra phòng thủ được chấp nhận rộng rãi.

**Ảnh hưởng.** Server trở thành **ổ chứa** (cảnh sát/hệ thống ngoài phát hiện hosting malware trên IP của trường → bị blacklisted như mục 1); người cùng lab mở file từ shared FTP hoặc attachment → lây nội bộ; và khi đó máy của nạn nhân lại thành bàn đạp tấn công máy khác.

**Phòng ngừa.**
1. Tắt anonymous upload nếu không cần (`anonymous_enable=NO` hoặc `write_enable=NO`); nếu cần, mount `/srv/ftp` với `noexec` (kể cả `nosuid,nodev`) — file nằm đó không chạy được trực tiếp.
2. Quét virus bằng **ClamAV** (`clamav-daemon` + `amavisd-new` hoặc `clamsmtp`) — kèm **ghi chú chi phí thật**: ClamAV ăn CPU/RAM khi scan và **phải cập nhật signature hằng ngày** qua `freshclam` (cần cho phép truy cập `database.clamav.net` trong firewall của lab); quét sai cấu hình còn tệ hơn không quét (người dùng quen "đã scan = an toàn").
3. Policy định dạng: từ chối `*.exe, *.scr, *.vbs, *.docm` ở content filter phía nhận; với FTP, đặt `chown_uploads` về user không có shell và giới hạn dung lượng (`local_max_upload_rate`); yêu cầu người nhận kiểm tra bằng mắt tên kép (`invoice.pdf.exe`) — client nên bật hiển thị phần mở rộng.
4. Kiểm tra định kỳ `find /srv/ftp -perm -u+x` (file khả thi nằm trong vùng upload = bất thường).

**Nguồn:**
- vsftpd.conf manpage (Ubuntu): https://manpages.ubuntu.com/manpages/noble/man5/vsftpd.conf.5.html
- ClamAV (daemon + FreshClam signature updates): https://docs.clamav.net/
- EICAR test file (hiệp định kiểm thử AV chuẩn): https://www.eicar.org/download-anti-malware-testfile/

---

### 4. Lạm dụng SMTP AUTH — "relay hợp pháp" phát spam

**Nguyên nhân.** Mục 1–2 giả định kẻ tấn công **không** có gì trong tay. Nhưng nếu có credential hợp lệ — do phishing (mục 2), do mật khẩu yếu bị brute-force bằng các công cụ như hydra/medusa (tồn tại, chỉ dùng được trong lab được phê duyệt, không nêu cú pháp ở đây), do credential reuse từ vụ lộ dữ liệu khác — thì kẻ đó được Postfix/Dovecot đối xử như **người dùng thật**: `permit_sasl_authenticated` trong chuỗi relay **đành phải** cho qua, vì về mặt giao thức không có gì để từ chối. Đây là "lỗ hổng chính sách": xác thực chứng minh *đúng tài khoản*, không chứng minh *đúng ý định*.

**Điều kiện xảy ra.** Tài khoản mail có mật khẩu yếu / bị lộ + submission port 587 mở từ Internet + không giới hạn tốc độ theo user.

**Dấu hiệu trong log.** Sau xác thực thành công, Postfix ghi `client=` kèm thông tin SASL trong từng dòng cleanup/qmgr, cho phép truy vết theo `sasl_username`:

```log
Aug 29 10:05:12 mail01 postfix/submission/smtpd[31440]: 7E2B441C9A: client=victim-laptop.isp.example[203.0.113.7], sasl_method=PLAIN, sasl_username=sv_atp
Aug 29 10:05:13 mail01 postfix/qmgr[1234]: 7E2B441C9A: from=<sv_atp@lab.local>, size=3021, nrcpt=1 (queue active)
# Lặp lại hàng trăm lần/phút với CÙNG sasl_username nhưng recipient là domain lạ:
Aug 29 10:05:14 mail01 postfix/smtpd[31441]: 8A10F72D5B: client=... sasl_username=sv_atp
```

Cách phát hiện bằng mắt trong lab: `grep "sasl_username=sv_atp" /var/log/mail.log | grep "client=" | wc -l` so với baseline; hoặc đếm message/ngày theo username (`awk '{print $NF}' | sort | uniq -c`). Dovecot cũng log `imap-login`/`auth` với cùng username — đối chiếu thời điểm login bất thường (IP lạ, 3h sáng) với spike volume.

**Ảnh hưởng.** Spam đi từ domain "sạch", dễ vượt bộ lọc phía nhận hơn; cả domain bị vào Spamhaus (mục 1) dù cấu hình relay đúng; người dùng thật bị khóa do vượt quota.

**Phòng ngừa.**
1. **Giới hạn tốc độ** — Postfix có sẵn cơ chế qua daemon `anvil`: `smtpd_client_connection_rate_limit`, `smtpd_client_message_rate_limit`, `anvil_rate_time_unit` (mặc định 60s). Ví dụ cho submission: mỗi client/IP ≤ 30 message/phút.
2. **Cảnh báo volume theo tài khoản** (script cron đếm `sasl_username` theo giờ, alert khi > baseline × 3) — không tham số mặc định nào làm thay bạn việc này.
3. Chính sách mật khẩu + **MFA/app-password** cho webmail; nếu client buộc dùng SMTP plain-auth thì cấp app-password riêng dễ thu hồi.
4. Vô hiệu hóa ngay khi có nghi vấn: `postconf -e` không chặn theo-user — dùng `access(5)` map (`REJECT account suspended`) hoặc disable account phía backend auth (Dovecot dùng userdb `shadow`/SQL → đổi trạng thái user).
5. Fail2ban filter `postfix-sasl` chặn IP brute-force sau N lần auth fail (cấu hình ở `/etc/fail2ban/jail.local`).

**Nguồn:**
- Postfix — ANVIL (rate control): https://www.postfix.org/ANVIL_README.html và http://www.postfix.org/postconf.5.html#smtpd_client_message_rate_limit
- Postfix — access(5) map: https://www.postfix.org/access.5.html
- Fail2ban (filters postfix-sasl): https://github.com/fail2ban/fail2ban

---

### 5. Từ chối dịch vụ (DoS) — làm kiệt tiến trình, hàng đợi và đĩa

**Nguyên nhân / các biến thể.**
- **Flood kết nối:** kẻ tấn công mở hàng trăm kết nối tới port 25 rồi **giữ im lặng** (slowloris SMTP) hoặc đóng/mở liên tục; mỗi kết nối chiếm một process `smtpd` con do `master` sinh ra; chạm `default_process_limit` → server từ chối kết nối thật.
- **Làm đầy hàng đợi:** kết hợp open relay (mục 1) hoặc tài khoản bị chiếm (mục 4) — gửi khối lượng lớn thư tới các domain **không phân giải được MX** để thư kẹt trong queue chờ gửi lại (retry); `maximal_queue_lifetime` / `bounce_queue_lifetime` (mặc định Postfix giữ thư tới 5 ngày — `5d`) làm hàng đợi phình đến khi **đầy đĩa** — hết đĩa thì mọi dịch vụ khác trên máy (kể cả FTP/Dovecot maildir) sập theo.
- **Verb abuse:** khai thác lệnh `VRFY`/`EXPN` (lưu ý: compiled default của Postfix là `disable_vrfy_command = no` — phải chủ động bật `yes` và kiểm tra bằng `postconf disable_vrfy_command`, đừng mặc định nghĩ là đã tắt sẵn), hoặc abuse cổng 110/143 (POP3/IMAP) với login loop để đầy `dovecot` process slots (`default_process_limit`, `mail_max_userip_connections`).

**Điều kiện xảy ra.** Dịch vụ tiếp xúc Internet + không rate-limit + disk/queue không cảnh báo sớm.

**Dấu hiệu trong log.**
```log
# (a) Flood kết nối: smtpd báo chạm giới hạn process — dòng của postfix/master:
Aug 29 11:22:04 mail01 postfix/master[900]: warning: /usr/lib/postfix/sbin/smtpd: bad command startup -- throttling
# Khi kiệt file descriptor, các process Postfix báo nguyên văn "Too many open files"
# (điểm gọi cụ thể thay đổi tuỳ lúc, nhưng chuỗi này luôn xuất hiện — ví dụ:):
Aug 29 11:22:04 mail01 postfix/smtpd[31999]: fatal: cannot open queue file: Too many open files
# (b) Queue phình: thư bị defer vì MX đích chết — grep "status=deferred":
Aug 29 11:30:00 mail01 postfix/qmgr[1234]: D4117FE2C: from=<user@lab.local>, status=deferred (connect to mx.dead-domain.example[93.184.x.x]:25: Connection timed out)
# (c) Dovecot quá tải vì login loop (dòng thật, hay gặp khi flood POP3/IMAP):
Aug 29 11:31:10 mail01 dovecot: imap-login: Disconnected: Maximum number of connections from user+IP exceeded (mail_max_userip_connections=10): user=<>, method=PLAIN, rip=203.0.113.7
```
Giám sát trong lab: `mailq | tail -n1` (dòng cuối báo số kB / số message trong queue), `df -h /var/spool/postfix`, đếm `connect from` mỗi phút.

**Ảnh hưởng.** Mất dịch vụ theo nghĩa đen (không gửi/nhận được); đầy đĩa lan ra toàn hệ thống file; sửa sự cố tốn gấp nhiều lần phòng.

**Phòng ngừa.**
1. `smtpd_client_connection_rate_limit = 20` và `smtpd_client_connection_count_limit = 10` (anvil tính theo `anvil_rate_time_unit`); tương tự cho submission: đặt tên service riêng trong `master.cf` với `-o` overrides.
2. `disable_vrfy_command = yes` — compiled default của Postfix là **no**, nên dòng này phải chủ động thêm chứ không phải "mặc định đã bật"; `smtpd_helo_required = yes` (buộc handshake tử tế trước khi cho MAIL FROM).
3. Giới hạn vòng đời queue: `maximal_queue_lifetime = 1d`, `bounce_queue_lifetime = 1d` — thư kẹt chỉ tồn tại 24h thay vì 5 ngày (mặc định), giảm rõ rệt áp lực đĩa khi bị bơm thư.
4. Cảnh báo disk (`df` cron > 80%), alert số message trong queue vượt baseline.
5. Lớp network: UFW rate-limit cho port 25/587/143/993/995 (ví dụ `ufw limit proto tcp from any to any port 25` — theo manpage ufw, chặn IP khởi tạo **≥ 6 kết nối trong 30 giây**), Fail2ban tự động block IP sau N lỗi.

**Nguồn:**
- Postfix ANVIL README: https://www.postfix.org/ANVIL_README.html
- Postfix postconf — maximal_queue_lifetime: https://www.postfix.org/postconf.5.html#maximal_queue_lifetime
- Dovecot — Limits (process/connection limits) (giới hạn process/kết nối): https://doc.dovecot.org/latest/core/admin/limits.html
- ufw manpage (limit rule): https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html

---

### 6. Lỗi cấu hình TLS — mã hóa "cho có" còn tệ hơn không mã hóa

**Nguyên nhân.** Nhóm này đặc biệt vì **bản thân TLS không phải lỗ hổng — cách ta dùng nó mới là vấn đề**:

- **Cert self-signed + văn hóa "accept anyway".** Cert tự ký không có chuỗi tin cậy (CA) → trình mail báo lỗi to đùng → người dùng bấm "Proceed Anyway" cho nhanh. Hệ quả tâm lý: họ **quen** với cảnh báo, nên khi kẻ tấn công làm MitM thật (cert thật nhưng sai, hoặc cert self-signed khác), không ai nhận ra. Cert hết hạn còn tệ hơn: nhiều client bỏ hẳn phiên.
- **Thư viện/cipher lỗi thời.** Đã **kiểm chứng trong chuẩn**: SSLv3 bị **RFC 7568** (6/2015) deprecated sau tấn công **POODLE**; TLS 1.0/1.1 bị **RFC 8996** (3/2021) chính thức deprecated; RC4 bị **RFC 7465** (4/2015) nghiêm cấm trong TLS (tấn công bias RC4 keystream); cipher hạng xuất khẩu 40-bit và các suite "EXPORT" từng bị phá bởi tấn công Logjam-style. BEAST (CVE-2011-3389) đánh vào TLS 1.0 CBC — cùng họ lý do phải bỏ 1.0. Nếu server còn bật các giao thức này cho tương thích client cũ, mọi phiên "có ổ khóa" đó đều yếu.
- **Downgrade / STARTTLS stripping.** SMTP/POP3/IMAP dùng cơ chế **opportunistic STARTTLS** (RFC 3207): client kết nối plaintext, hỏi `EHLO`, thấy dòng `STARTTLS` mới nâng cấp. Nếu attacker ở giữa **lọc mất dòng `STARTTLS`** trong response (và response của server lại không được ký bởi một TLS binding — vì TLS chưa bật!), client "lặng lẽ" gửi tiếp plaintext, trong đó có **SASL PLAIN = mật khẩu dạng text**. Cơ chế chống: **Mandatory/Enforced TLS** (`smtpd_tls_security_level = encrypt` phía nhận nếu muốn; phía gửi `smtp_tls_security_level = mandatory` + DANE/checkname) và trên submission port **chỉ cho AUTH sau khi đã TLS** (`smtpd_tls_auth_only = yes`).
- **Không có tín hiệu trong log ứng dụng.** Đây là điểm phân biệt với các mục 1–5: cert sai, cipher yếu **không tự sinh log**. Phát hiện phải bằng **audit chủ động**: `openssl s_client -connect mail01.lab:25 -starttls smtp` (ràng buộc vào server của chính nhóm trong lab, hoàn toàn hợp lệ), hoặc script tự kiểm trong lab liệt kê protocol mà server chấp nhận.

**Điều kiện xảy ra.** Cert self-signed hết hạn; `ssl_protocols` chứa TLSv1; `smtpd_tls_auth_only` để `no`; port 993/995 cũ không cấu hình chain file đầy đủ.

**Dấu hiệu.** Trong Postfix log, phiên **không** TLS thể hiện ở `proto=` có mặt `STARTTLS` nhưng thiếu cờ an toàn — cách sạch nhất là cấu hình để log hiện tình trạng TLS: bật `smtpd_tls_loglevel = 1` sẽ thấy các dòng:

```log
Aug 29 12:02:41 mail01 postfix/smtpd[32210]: Anonymous TLS connection established from mail.isp.example[198.51.100.9]: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)   ← OK
# Kết nối KHÔNG TLS (bị strip hoặc client cũ) — không có dòng "TLS connection established" nào cho session này:
Aug 29 12:03:02 mail01 postfix/smtpd[32215]: 41B2C0F7: client=mail.isp.example[198.51.100.9]
# Dovecot: log login kèm hoặc không kèm trường "TLS":
Aug 29 12:10:00 mail01 dovecot: imap-login: Login: user=<sv_atp>, method=PLAIN, rip=10.0.2.15, TLS   ← có
Aug 29 12:10:05 mail01 dovecot: imap-login: Login: user=<sv_atp>, method=PLAIN, rip=203.0.113.7      ← KHÔNG có "TLS" = plaintext!
```

**Ảnh hưởng.** Nghe lén mật khẩu và nội dung thư (MitM), mất trust với các MTA ngoài yêu cầu enforced TLS (Google/Microsoft ngày càng siết), và quan trọng nhất với lab: người dùng **mất kỹ năng nhận diện** cert giả.

**Phòng ngừa.**
1. Dựng **internal CA trong lab** (openssl một lần, distribute CA cert cho các client lab) thay vì cert tự ký từng server; cấp cert server từ CA đó → người dùng **không có** lý do bấm accept.
2. Postfix: `smtpd_tls_security_level = may`, `smtpd_tls_auth_only = yes`, `smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1`; Dovecot: `ssl = required`, `ssl_min_protocol = TLSv1.2`.
3. Với phía gửi giữa server–server: cân nhắc `smtp_tls_security_level = dane` hoặc tối thiểu `verify/full` khi cả hai có cert hợp lệ.
4. Audit định kỳ bằng `openssl s_client` trong lab (chỉ với IP của lab!); đặt lịch nhắc đổi cert ít nhất 30 ngày trước khi hết hạn (hoặc cert nội bộ thời hạn ngắn + script gia hạn).
5. "HSTS-style": ở cổng submission (587) **từ chối AUTH khi chưa có TLS** — như trên, `smtpd_tls_auth_only` — để không tồn tại "chế độ plaintext tiện lợi".

**Nguồn:**
- RFC 8996 — Deprecating TLS 1.0/1.1: https://www.rfc-editor.org/info/rfc8996
- RFC 7568 — Deprecating SSLv3: https://www.rfc-editor.org/info/rfc7568
- RFC 7465 — Prohibiting RC4: https://www.rfc-editor.org/info/rfc7465
- RFC 3207 — STARTTLS in SMTP: https://www.rfc-editor.org/info/rfc3207
- Postfix TLS Readme: https://www.postfix.org/TLS_README.html
- Dovecot SSL configuration: https://doc.dovecot.org/latest/core/config/ssl.html

---

### 7. Phần mềm lỗi thời và cấu hình mặc định

**Nguyên nhân.** Hai thói quen "mặc nhiên an toàn" nhưng sai: **để phần mềm cũ chạy** và **tin cấu hình default**. Về phần mềm cũ: CVE **tích tụ** theo thời gian — một phiên bản Postfix/Dovecot/vsftpd/OpenSSH đứng yên một năm nghĩa là bỏ lỡ toàn bộ bản vá của năm đó. Ví dụ kinh điển đã kiểm chứng để minh họa cho rủi ro "phần mềm không vá": **vsftpd 2.3.4 (CVE-2011-2523, CVSS 10)** — bản phân phát bị cài backdoor mở shell cổng 6200 từ 30/6–3/7/2011; trở thành ví dụ dạy học nổi tiếng (Metasploitable 2) đúng vì nó cho thấy chỉ cần **một bản tải không rõ nguồn** là cả hệ thống mất tin cậy. Ở phía mail, họ Exim có hàng loạt CVE nghiêm trọng (2019: RCE CVE-2019-10149 "The Return of the WIZard" cùng CVE-2019-15846, CVE-2019-16928; 2024: CVE-2023-51766 SMTP smuggling) và OpenSSH/vsftpd/Dovecot/Postfix đều nhận các bản vá bảo mật phát hành liên tục qua kênh cập nhật của distro — điều này khẳng định: **delay-upgrade = tự tích nợ CVE**. Về vòng đời OS: một bản Ubuntu LTS có hỗ trợ chuẩn 5 năm; tính đến 8/2026 bản LTS hiện hành mới nhất là **Ubuntu 26.04 "Resolute Raccoon" (ra 23/4/2026)**, còn các bản như 20.04 (hỗ trợ chuẩn kết thúc 4/2025) nếu vẫn chạy mà không có Ubuntu Pro/ESM tức là **không còn bản vá an ninh** cho vsftpd/postfix/dovecot cài trên đó.

**Vì sao default không vì security.** Cấu hình mặc định được thiết kế cho **compatibility** (mọi client cũ kết nối được) và **zero-configuration install**: `anonymous_enable=YES` trong `/etc/vsftpd.conf` của vsftpd là ví dụ kinh điển — mặc định để AI cũng download được → mở luôn nguy cơ upload; Postfix may mắn hơn vì default `defer_unauth_destination` an toàn, nhưng đổi lại các bài hướng dẫn trên mạng "sửa giúp hết lỗi relay denied" lại là nguồn cấu hình sai lớn nhất (mục 1). Tóm lại: **default chỉ là điểm khởi đầu, không phải chính sách.**

**Dấu hiệu.** Không có log "bị lỗi thời" — phải tự kiểm:
```bash
apt list --upgradable | grep -E "postfix|dovecot|vsftpd|openssh"   # còn bao nhiêu bản vá chờ?
postfix check        # kiểm cấu hình self-diagnosis
dovecot -n           # in ra toàn bộ cấu hình đang hiệu lực — đọc lại để tìm default đáng ngờ
grep -E "ssl_protocols|ssl = " /etc/dovecot/conf.d/10-ssl.conf
```

**Ảnh hưởng.** RCE làm chủ server (vsftpd 2.3.4), vượt xác thực/giả mạo (SMTP smuggling), hoặc đơn giản là service hết được bảo mật bởi ai đó — vì OS không còn nhận patch.

**Phòng ngừa.**
1. **unattended-upgrades** cho `*-security` (có sẵn trong Ubuntu, bật qua `sudo apt install unattended-upgrades` + cấu hình `/etc/apt/apt.conf.d/50unattended-upgrades`): server lab không tự vá = chậm hơn khai thác ít nhất một chu kỳ.
2. Nâng lịch trình OS: kiểm tra EOL của bản đang chạy tại https://ubuntu.com/about/release-cycle và kế hoạch nâng lên bản LTS gần nhất (hiện là 26.04).
3. Review cấu hình định kỳ bằng **hardening checklist**: `postfix check`, `dovecot -n`, đọc `vsftpd.conf` so với mặc định — ghi diff mỗi lần đổi.
4. Tải phần mềm **từ repository chính thức của distro**, không từ file `.tar.gz` trôi nổi — chính CVE-2011-2523 là bài học về nguồn phát phần mềm.
5. Khi migrate (bối cảnh mở đầu mục 1): **không copy `main.cf` cũ nguyên si**; dựng `postconf -n` mới và thêm từng dòng có chủ đích.

**Nguồn:**
- NVD — CVE-2011-2523 (vsftpd 2.3.4): https://nvd.nist.gov/vuln/detail/CVE-2011-2523
- NVD — CVE-2019-10149 (Exim "The Return of the WIZard"; advisory gốc của Qualys): https://nvd.nist.gov/vuln/detail/CVE-2019-10149
- Ubuntu release cycle & EOL: https://ubuntu.com/about/release-cycle
- Ubuntu 26.04 LTS release notes: https://documentation.ubuntu.com/release-notes/26.04/
- unattended-upgrades package (Ubuntu): https://packages.ubuntu.com/noble/unattended-upgrades

---

### 4b.5. Tổng kết khung 5 mục (bảng tra nhanh)

| Nguy cơ | Dấu hiệu log đặc trưng nhất | Phòng ngừa chủ lực |
|---|---|---|
| Open relay | `Relay access denied` **xuất hiện**; `nrcpt` lớn + `from/`domain lạ | `smtpd_relay_restrictions` giữ nguyên chặn cuối, `mynetworks` hẹp |
| Spoofing/phishing | Gần như không log; chỉ thấy khi bật auth-check | SPF/DKIM/DMARC (ch.6) + đào tạo user |
| Mã độc | `vsftpd [pid] UPLOAD: *.exe`; clamav FOUND | `noexec`, tắt anon write, ClamAV + EICAR test |
| Lạm dụng AUTH | Spike `sasl_username=` cùng recipient xa | anvil rate limit + volume alert + MFA/app-password |
| DoS | `bad command startup -- throttling`; `status=deferred` hàng loạt | connection rate limit, queue lifetime 1d, `ufw limit`, fail2ban |
| TLS sai | Không có "TLS connection established" cho session; `Login:` thiếu `TLS` | Internal CA, `ssl = required`, `smtpd_tls_auth_only`, bỏ TLS<1.2 |
| Lỗi thời/default | `apt list --upgradable` còn tồn đọng; `dovecot -n` lộ default | unattended-upgrades, theo EOL (26.04 LTS từ 4/2026), review checklist |

Chương 5 tiếp theo sẽ chuyển sang phía **phát hiện sớm** (giám sát log chủ động, IDS, baseline) dựa chính xác trên các dấu hiệu log đã liệt kê ở đây.
