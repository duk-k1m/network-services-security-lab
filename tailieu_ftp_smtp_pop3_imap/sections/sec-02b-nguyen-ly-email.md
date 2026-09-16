## 2b. Nguyên lý hoạt động: SMTP, POP3, IMAP và luồng email

Chương này trình bày "bản chất" của ba giao thức email mà đồ án quản trị: **SMTP** (Simple Mail Transfer Protocol) dùng để **gửi và chuyển tiếp thư**, **POP3** (Post Office Protocol v3) và **IMAP** (Internet Message Access Protocol) dùng để **đọc/lấy thư**. Mỗi giao thức được phân tích theo ba tầng: cơ chế hoạt động → ví dụ phiên giao dịch thật → cách quan sát trong lab (dùng `telnet`/`nc`/`openssl s_client` trên mạng riêng do nhóm sở hữu). Toàn bộ kiểm thử chỉ thực hiện trong phạm vi lab nội bộ, không tấn công hệ thống công cộng.

### 2b.1 Kiến trúc tổng thể: ai nói chuyện với ai

Một email không đi "thẳng" từ máy người gửi sang máy người nhận như cuộc gọi điện thoại. Nó đi qua một dây chuyền các thành phần, mỗi thành phần nói một giao thức:

```
 [An]                                                     [Bình]
  │ Thunderbird (MUA)          Server lab mail.lab.local   │ Thunderbird (MUA = MRA client)
  │   │ gửi (submission)          ┌────────────────┐       │   │ đọc
  ▼   ▼                           │                │       ▼   ▼
 MUA ──► MSA ──► MTA ──► (internet/├─ port 25 ─►  MTA ─► MDA ─► mailbox ─◄ MRA ◄── MUA
             (587/465)  relay 25   │  (Postfix)   │  (Postfix/local│ (INBOX/    (Dovecot
                                   │              │   hoặc Dovecot)│  Maildir)  POP3/IMAP)
                                   └────────────────┘
```

- **MUA (Mail User Agent)**: ứng dụng phía người dùng — Thunderbird, Outlook. Người dùng *tưởng* là mình "gửi email trực tiếp cho Bình", thực chất chỉ đưa thư cho MSA của mình.
- **MSA (Mail Submission Agent)**: cổng tiếp nhận thư từ MUA, lắng nghe port **587/465**, **bắt buộc xác thực** (SMTP AUTH). Trong thực tế MSA và MTA thường chạy chung một tiến trình Postfix nhưng cấu hình listener riêng.
- **MTA (Mail Transfer Agent)**: "bưu cục trung chuyển" — Postfix, Exim, Sendmail. Nhận thư từ MSA hoặc từ MTA khác qua port **25**, tra DNS MX (Mail Exchanger) record để tìm MTA đích, chuyển tiếp (relay) hoặc bàn giao tại chỗ (delivery).
- **MDA (Mail Delivery Agent)**: lấy thư ra khỏi hàng đợi và ghi vào hộp thư của người nhận — `postfix/local`, Dovecot LDA, hoặc ghi trực tiếp dưới định dạng Maildir/Mbox.
- **Mailbox**: nơi lưu thư, thường là định dạng **Maildir** (một thư mục, mỗi thư một file) hoặc **mbox** (một file lớn) — Dovecot đọc trực tiếp các file này.
- **MRA (Mail Retrieval/Access Agent)**: phục vụ client đọc thư — Dovecot cung cấp POP3/IMAP.

**Điểm cốt lõi cần phân biệt**: *gửi* (submission + relay) luôn là SMTP; *nhận/đọc* (client lấy thư từ server của chính mình) là POP3 hoặc IMAP. Bình không bao giờ "nhận SMTP" trực tiếp từ An — trừ khi Bình tự vận hành MTA riêng và domain của Bình trỏ MX thẳng vào máy đó — mà đọc qua IMAP/POP3 từ mailbox của mình trên server.

**Quan sát trong lab**: trên Ubuntu Server 26.04 LTS (phát hành 4/2026, hỗ trợ đến 5/2031), bộ đôi phổ biến là `apt install postfix dovecot-imapd` — Postfix series 3.10 và Dovecot 2.4 trong repo `main` mặc định. Kiểm tra tiến trình nào giữ vai trò nào: `ss -tlnp | grep -E ':(25|143|465|587|993|995)[[:space:]]'`.

Nguồn:
- https://ubuntu.com/server/docs/how-to/mail-services/install-postfix/
- https://www.postfix.org/README.html
- https://doc.dovecot.org/

### 2b.2 SMTP: phiên lệnh, mã reply, relay và hàng đợi (RFC 5321)

SMTP (RFC 5321, kế thừa RFC 821) là giao thức **text-based, hướng kết nối, request-response**: server trả lời bằng mã 3 chữ số, client ra lệnh bằng dòng ASCII.

#### Phiên giao dịch mẫu đầy đủ (có chú thích)

Lab: `openssl s_client -connect mail.lab.local:587 -starttls smtp` để thấy cả phiên plaintext trước khi bật TLS.

```text
S: 220 mail.lab.local ESMTP Postfix (Ubuntu)   <- server chào, 2xx = sẵn sàng
C: EHLO laptop.an.lab                          <- EHLO (extended) thay cho HELO cũ; khai báo tên client
S: 250-mail.lab.local                          <- 250 = OK; gạch nối '-' nghĩa là còn dòng tiếp
S: 250-AUTH PLAIN LOGIN                        <- server liệt kê các extension nó hỗ trợ
S: 250-STARTTLS
S: 250 8BITMIME                                <- dòng cuối cùng dùng khoảng trắng '250 '
C: AUTH PLAIN AGFuAG1hdGtoYXVnaWEA           <- đăng nhập (xem 2b.4): base64 của \0an\0matkhaugia (RFC 4616)
S: 235 2.7.0 Authentication successful         <- 235 = xác thực thành công
C: MAIL FROM:<an@lab.local>                    <- envelope sender (dùng cho bounce/Return-Path); RFC 5321: MAIL FROM phải đi TRƯỚC RCPT TO
S: 250 2.1.0 Ok
C: RCPT TO:<binh@lab.local>                    <- envelope recipient; có thể lặp lại nhiều lần (một thư, nhiều người)
S: 250 2.1.5 Ok
C: DATA                                        <- báo "tôi sắp gửi nội dung"
S: 354 End data with <CR><LF>.<CR><LF>         <- 3xx = trung gian, chờ dữ liệu
C: Date: Sat, 29 Aug 2026 09:00:00 +0700       <- từ đây là nội dung message (RFC 5322 headers + body)
C: From: An <an@lab.local>                     <- header hiển thị, khác envelope ở trên!
C: Subject: Hop lab
C:
C: Xin chao Binh.
C: .                                           <- dòng chứa DẤU CHÂM đơn độc kết thúc DATA
S: 250 2.0.0 Ok: queued as 3A2B1C4D            <- "queued as" = đã vào mail queue, mã queue để tra mail.log
C: QUIT
S: 221 2.0.0 Bye
```

#### Bảng mã reply (RFC 5321 §4.2)

| Chữ số đầu | Ý nghĩa | Ví dụ thường gặp trong lab |
|---|---|---|
| 2xx | Hoàn thành (positive completion) | `250` Ok, `235` auth OK, `221` Bye |
| 3xx | Trung gian, chờ thêm (positive intermediate) | `354` gửi dữ liệu đi, `334` server chờ response của AUTH |
| 4xx | Thất bại **tạm thời** (transient) → MTA sẽ **thử lại** | `451` lỗi tạm thời, `452` hết chỗ |
| 5xx | Thất bại **vĩnh viễn** (permanent) → bounce thư về | `550` mailbox không tồn tại/relay denied, `554` giao dịch thất bại |

Mã 3 chữ số còn kèm **enhanced status code** dạng `X.Y.Z` (RFC 3463), ví dụ `5.7.1` nghĩa là "từ chối vì chính sách an toàn" — đọc mã này là cách nhanh nhất biết vì sao một thư bị chặn.

**252 vs 550 5.7.1/554 5.7.1 — hai thái độ với relay**: `252` nghĩa là "tôi không xác minh được hộp thư này nhưng tôi **nhận** thư và sẽ tự thử chuyển tiếp" (hay gặp với lệnh VRFY, hoặc một số MTA nhận thư cho domain lạ rồi mới phát hiện không chuyển được → bounce sau). Ngược lại, `550/554 5.7.1 Relay access denied` (thông điệp kinh điển của Postfix `554 5.7.1 <x@domain.net>: Relay access denied`) nghĩa là **từ chối ngay từ RCPT TO** vì bạn không có quyền dùng server làm relay. Kiểm thử trong lab: gửi `RCPT TO:<nguoi@yahoo.com>` tới Postfix cấu hình `mynetworks=127.0.0.0/8` khi chưa AUTH → nhận 554; chạy tiếp `AUTH` đúng rồi thử lại → 250. Đây chính là bằng chứng "open relay" hình thành như thế nào.

#### Relay, mail queue và cơ chế retry/backoff

- **Relaying** = hành động một MTA chuyển thư mà nó nhận **cho một domain khác** mà nó không phục vụ. MTA công cộng phải giới hạn relay (chỉ cho `mynetworks` nội bộ hoặc client đã AUTH), nếu không sẽ thành **open relay** — đích yêu thích của spammer.
- Sau `250 queued as`, thư nằm trong **mail queue** (`/var/spool/postfix/active`, `deferred`): Postfix chưa chắc kết nối được MTA đích ngay (bạn nhận offline, mạng gián đoạn).
- **Retry với exponential backoff**: MTA liên tục thử lại trong khoảng thời gian cấu hình (Postfix mặc định giữ thư deferred khoảng 5 ngày, `maximal_queue_lifetime`), mỗi lần thất bại kéo dài dần khoảng chờ. Thử quá hạn → trả bounce 5xx về envelope sender.
- **Quan sát trong lab**: `postqueue -p` (hoặc `mailq`) xem queue; `postcat -q 3A2B1C4D` mổ một bức thư trong queue (thấy cả envelope + header); tắt mạng MTA "đích" giả lập rồi gửi thư, xem `/var/log/mail.log` in dòng `status=deferred` rồi `status=sent` khi mạng hồi — hai trạng thái kinh điển của queue.

#### Envelope vs header From: — gốc rễ của phishing

SMTP chỉ vận chuyển theo **envelope** (phong bì): `MAIL FROM` = người gửi trả bounce (Return-Path), `RCPT TO` = người nhận mà MTA căn cứ để chuyển thư. Bên trong envelope là **message** theo RFC 5322, chứa các header như `From:`, `To:`, `Subject:` — những thứ này **chỉ để hiển thị** trong MUA, MTA trung gian không cần quan tâm tới tính đúng đắn của chúng.

Hệ quả: kẻ tấn công có thể đặt `MAIL FROM:<spam@example.com>` (thậm chí để trống `<>` như bounce) nhưng ghi header `From: nganhang@nganhang-that.example` — Bình đọc Thunderbird chỉ thấy header. Đó là bản chất spoofing trong phishing. Các cơ chế **SPF** (kiểm tra domain của *envelope* MAIL FROM có cho phép IP gửi này không — chính vì vậy SPF đọc `MAIL FROM`, không đọc header `From:`), DKIM (chữ ký số trên message) và DMARC ra đời để vá khoảng hở này; chúng sẽ được phân tích ở chương nguy cơ/phòng ngừa.

**Quan sát trong lab**: tự gửi một thư bằng `nc` tới MSA lab (AUTH bằng tài khoản lab của mình trước, rồi mới `MAIL FROM`), đặt `MAIL FROM:<a@lab.local>` nhưng header `From: <b@lab.local>` — Thunderbird của Bình hiển thị "b@lab.local", còn `mail.log` và `Return-Path` nói lên a@lab.local. Kiểm chứng bằng View source / Analyze message trong Thunderbird.

#### MIME: vì sao gửi được file đính kèm (RFC 2045)

SMTP cổ điển chỉ an toàn với ASCII 7-bit và dấu chấm đơn độc. MIME (Multipurpose Internet Mail Extensions, bộ RFC 2045–2049) mở rộng bằng cách thêm header: `MIME-Version: 1.0`, `Content-Type`, `Content-Transfer-Encoding`. Một thư có file đính kèm là `multipart/mixed`, mỗi phần một `Content-Type: application/pdf` với body mã hóa **base64** (tăng ~33% dung lượng). `Content-Disposition: attachment; filename="..."` quy định cách MUA hiển thị. Lưu ý MIME **không** mã hóa bảo mật — base64 chỉ là encoding, giải mã được ngay, không phải encryption; đây là lý do chương phòng ngừa phải bàn tới S/MIME hoặc PGP khi cần bảo mật nội dung.

Nguồn:
- https://www.rfc-editor.org/rfc/rfc5321.html (SMTP)
- https://www.rfc-editor.org/rfc/rfc5322.html (format message/header)
- https://www.rfc-editor.org/rfc/rfc2045.html (MIME)
- https://www.postfix.org/QSHAPE_README.html và https://www.postfix.org/postqueue.1.html (queue)
- https://datatracker.ietf.org/doc/html/rfc7208 (SPF — envelope sender)

### 2b.3 Ba cổng SMTP: 25, 587, 465 và bài toán TLS

| Cổng | Vai trò | Chuẩn | Yêu cầu |
|---|---|---|---|
| **25** | MTA → MTA (relay/mail exchange) | RFC 5321 | Không AUTH giữa server với server; TLS *opportunistic* |
| **587** | Submission: MUA → MSA của mình | RFC 6409 | **Bắt buộc SMTP AUTH**; STARTTLS theo best practice RFC 8314 |
| **465** | SMTPS/submissions: MUA → MSA, **implicit TLS** | RFC 8314 | TLS ngay từ byte đầu tiên |

- **Port 25** là đường trục giữa các MTA. Ở đây người ta dùng **opportunistic TLS** (extension `STARTTLS` cho SMTP được định nghĩa lần đầu ở RFC 2487, rồi được chuẩn hóa lại trong RFC 3207 — RFC 3207 thay thế RFC 2487): MTA gọi `STARTTLS`, nếu bạn nhận hỗ trợ thì bật mã hóa, **nếu không thì vẫn gửi plaintext** — vì thư phải tới nơi, không thể vì bạn nhận chưa có TLS mà bounce. Điểm yếu của opportunistic là bị downgrade/stripping nếu kẻ tấn công đứng giữa chặn được câu trả lời `250-STARTTLS`; các biện pháp buộc TLS giữa các MTA là **DANE** (RFC 6698, cập nhật bởi RFC 8680) và **MTA-STS** (RFC 8461).
- **Port 587** (RFC 6409 – Message Submission): ra đời để tách "khách gửi thư có tài khoản" khỏi "MTA lạ". Vì client đã AUTH, MSA biết chính xác danh tính → chặn được spam giả mạo nguồn, và có thể **buộc** TLS + AUTH (khác port 25 vốn không thể buộc AUTH giữa các MTA).
- **Port 465** — xác minh trạng thái chuẩn: đây là ví dụ "chuẩn thay đổi chiều ngược". 465 được một số vendor đăng ký cho "SMTPS" (SMTP-over-SSL, giống HTTPS) giữa thập niên 1990, sau đó bị IANA thu hồi và khai tử khi cộng đồng chuyển sang STARTTLS/587. **RFC 8314** ("Cleartext Considered Obsolete: Use of TLS for Email Submission and Access", Best Current Practice, 1/2018) **phục hồi 465 và khuyến nghị implicit TLS là phương án ưu tiên cho submission và truy cập mailbox**, vì STARTTLS opportunistic trên 587/143/110 vẫn cho phép attacker loại bỏ TLS (stripping), còn implicit TLS thì kết nối không tồn tại nếu TLS không thành lập. RFC 8314 cũng khuyên trong giai đoạn chuyển tiếp nên hỗ trợ **cả hai** (465 và 587) và dùng **TLS ≥ 1.2**, client không được fallback về plaintext khi kết nối TLS bị lỗi.
- **SMTPS vs STARTTLS** — bản chất khác nhau: *implicit TLS (SMTPS)* = handshake TLS trước khi bất cứ dòng SMTP nào chạy (connect vào là `openssl s_client` không cần `-starttls`); *STARTTLS (explicit, RFC 3207)* = bắt đầu plaintext, `EHLO` → `STARTTLS` → `220 Ready to start TLS` → TLS handshake → chạy `EHLO` lại (vì extension list có thể đổi, và lệnh AUTH **chỉ nên** xuất hiện sau TLS để tránh lộ credential). Trên Ubuntu, cấu hình `smtpd_tls_security_level` trong `/etc/postfix/main.cf` (các mức `none`/`may`/`encrypt`/`secure`/`dane`) chính là công tắc opportunistic vs mandatory — chương quản trị sẽ đi sâu.

**Quan sát trong lab**: so sánh ba kết nối tới cùng một Postfix: (1) `nc mail.lab.local 25` rồi `EHLO` — thấy `250-STARTTLS` trong danh sách extension (nếu chưa bật `smtpd_tls_security_level=encrypt`, server vẫn nhận thư plaintext trên 25); (2) `openssl s_client -connect mail.lab.local:465` — kết nối TLS ngay, chạy `EHLO` thấy server **không** báo `STARTTLS` vì toàn bộ phiên đã mã hóa; (3) `tcpdump -i any -A port 587` trong khi Thunderbird submission → chỉ thấy bất định sau điểm STARTTLS, phần trước đó đọc được `EHLO` plaintext.

Nguồn:
- https://www.rfc-editor.org/rfc/rfc8314.html
- https://datatracker.ietf.org/doc/html/rfc6409
- https://datatracker.ietf.org/doc/html/rfc2487 , https://datatracker.ietf.org/doc/html/rfc3207
- https://www.postfix.org/TLS_README.html

### 2b.4 SMTP AUTH (RFC 4954): PLAIN, LOGIN và CRAM-MD5

SMTP AUTH (extension `AUTH`, RFC 4954 thay RFC 2554) cho phép MSA chứng thực người gửi trước khi cho relay. Server công bố cơ chế qua `EHLO` (`250-AUTH PLAIN LOGIN CRAM-MD5`), client chọn một cơ chế. Handshake dạng base64 challenge-response: `C: AUTH PLAIN <b64>` hoặc `C: AUTH LOGIN` → `S: 334 <b64 prompt>` → `C: <b64>`.

| Cơ chế | Cách hoạt động | Không có TLS | Có TLS |
|---|---|---|---|
| **PLAIN** (RFC 4616) | base64 của `user\0password` — **mã hóa thuận nghịch**, ai bắt được gói là decode ra mật khẩu | **Lộ mật khẩu** (chỉ cần base64 -d) | An toàn — nhưng server nên chỉ quảng bá khi phiên đã TLS |
| **LOGIN** | tương tự PLAIN nhưng tách 2 bước base64 username / password — **không phải cơ chế chuẩn IETF**, tồn tại như legacy tương thích | **Lộ mật khẩu** (thậm chí lộ từng bước) | An toàn tương đương PLAIN |
| **CRAM-MD5** (RFC 2195) | server gửi challenge (nonce), client trả `HMAC-MD5(password, challenge)` — **không bao giờ gửi mật khẩu** | **Không lộ mật khẩu trực tiếp**, nhưng attacker bắt được challenge + response có thể chạy **offline dictionary attack** (thử từng mật khẩu trong wordlist tính lại HMAC) | An toàn về mặt đường truyền, nhưng bị coi là lỗi thời so với SCRAM/OAUTHBEARER; vẫn tốt hơn PLAIN không TLS |

Kết luận thực hành (và là điểm chốt cho phần phòng ngừa): **một khi có TLS đủ mạnh, PLAIN/LOGIN không còn lộ mật khẩu** vì toàn bộ nội dung phiên đã mã hóa — nên Postfix/Dovecot ngày nay cấu hình `smtpd_tls_auth_only = yes` và chỉ bật PLAIN sau STARTTLS. **Nguy hiểm thật sự là PLAIN/LOGIN trên kết nối plaintext** (port 25/587 không TLS): mật khẩu bay qua mạng dưới dạng base64 đọc được bằng `tcpdump`. CRAM-MD5 sinh ra để chịu được plaintext nhưng bị đánh bại ngoại tuyến khi mật khẩu yếu — không còn là lý do để chấp nhận AUTH không TLS.

Trong lab Postfix + Dovecot SASL (`/etc/postfix/main.cf`: `smtpd_sasl_type = dovecot`, `smtpd_sasl_path = private/auth`), kiểm chứng bằng: `openssl s_client -starttls smtp -connect mail.lab.local:587` rồi gõ tay `AUTH LOGIN` — với cùng lệnh đó nhưng qua `nc` plaintext trên cấu hình `smtpd_tls_auth_only=yes`, server từ chối `538 5.7.9 Error: SMTP server requires TLS`.

**Ghi chú đạo đức**: công cụ brute-force dịch vụ AUTH (hydra, medusa…) tồn tại và chỉ được phép thử nghiệm trên máy lab do nhóm sở hữu với mật khẩu giả lập; chương 5 (phát hiện sớm) trình bày cách *phát hiện* các chuỗi thử sai này qua log + fail2ban chứ không hướng dẫn tấn công hệ thống thật.

Nguồn:
- https://datatracker.ietf.org/doc/html/rfc4954
- https://www.rfc-editor.org/rfc/rfc4616.html , https://datatracker.ietf.org/doc/html/rfc2195
- https://www.postfix.org/SASL_README.html

### 2b.5 POP3: mô hình tải-và-xóa đơn giản (RFC 1939)

POP3 (RFC 1939, 1996) thiết kế cho kỷ nguyên dial-up: client **tải toàn bộ thư về local**, rồi mặc định xóa trên server (hoặc "leave on server" nếu cấu hình — nhưng về bản chất server chỉ còn là nơi trung chuyển). POP3 **stateless** giữa các phiên: sau khi download, MUA tự quản lý tất cả; server không biết bạn đã đọc thư nào, không có khái niệm folder.

Phiên mẫu (lab: `nc mail.lab.local 110`):

```text
S: +OK mail.lab.local POP3 Dovecot (Ubuntu) ready   <- POP3 trả lời '+OK' / '-ERR', chia 3 trạng thái:
C: USER binh                              <- AUTHORIZATION state
S: +OK
C: PASS matkhaugia                       <- mật khẩu plaintext nếu chưa STLS/TLS!
S: +OK Logged in.
C: STAT
S: +OK 3 1522                             <- 3 message, tổng 1522 octets
C: LIST
S: +OK 3 messages:
S: 1 450
S: 2 700
S: 3 372
S: .
C: RETR 2                                 <- tải nguyên văn message #2 (header + body)
S: +OK 700 octets
S: (nội dung thư...)
S: .
C: DELE 2                                 <- đánh dấu xóa (chỉ thực sự xóa khi QUIT)
S: +OK message 2 deleted
C: QUIT                                   <- TRANSACTION state chốt; xóa các thư đã DELE
S: +OK Dovecot POP3 mail.lab.local signing off.
```

Các lệnh cốt lõi: `USER/PASS` (hoặc `APOP`), `STAT`, `LIST`, `UIDL` (ID bất biến của mỗi thư — công cụ để client "leave-on-server" không tải trùng), `RETR`, `DELE`, `NOOP`, `QUIT`. Nhận xét quan trọng cho phần bảo mật: **POP3 chỉ làm việc với mailbox INBOX**, không tạo/nhánh folder, không đồng bộ flag đã đọc — mỗi thiết bị tải về là một bản sao độc lập, dẫn tới hệ quả so sánh ở 2b.7.

- **APOP** (RFC 1957): challenge `+OK <timestamp@host>`, client gửi `MD5(timestamp + mật_khẩu)` — không lộ mật khẩu trên đường truyền nhưng dựa trên MD5 đã suy yếu và **vẫn dính offline attack** giống CRAM-MD5 (attacker giữ challenge + response rồi thử wordlist ngoại tuyến); ngày nay coi là legacy, các triển khai hiện đại nên tắt.
- **STLS** (RFC 2595): phiên bản STARTTLS của POP3 — `C: STLS` → `+OK Begin TLS negotiation` → TLS handshake, sau đó chạy `CAPA` lại.
- **Cổng**: 110 (POP3 plaintext/STLS) và **995 (POP3S, implicit TLS)** — RFC 8314 khuyến nghị 995 cho client hiện đại.

**Quan sát trong lab**: `tcpdump -i any -A tcp port 110` khi Thunderbird dùng POP3 không TLS trên lab riêng: thấy nguyên `PASS <mật_khẩu-giả-lab>`. Bật cấu hình `ssl = required` trong Dovecot thì server chỉ nghe 995 (`openssl s_client -connect mail.lab.local:995`) và từ chối 110 (`-ERR POP3 server requires SSL connections`).

Nguồn:
- https://datatracker.ietf.org/doc/html/rfc1939 , https://datatracker.ietf.org/doc/html/rfc1957
- https://datatracker.ietf.org/doc/html/rfc2595
- https://doc.dovecot.org/

### 2b.6 IMAP: mailbox nằm trên server (RFC 3501 → RFC 9051)

**Xác minh trạng thái chuẩn (8/2026)**: RFC 3501 (IMAP4rev1, 2003) đã được **thay thế chính thức bởi RFC 9051 – IMAP4rev2 (2021)**; RFC 3501 hiện mang trạng thái *Obsolete*. Thực tế triển khai trên các server phổ biến (Dovecot, Gmail) vẫn nói chuyện tương thích ngược với cả hai. IMAP4rev2 về cơ bản là IMAP4rev1 **cộng thêm** các extension vốn rời rạc thành bắt buộc trong lõi: `SASL-IR`, `LOGO`, `ENABLE`, `IDLE`... — server hiện đại phải quảng bá `IMAP4rev2` qua capability.

IMAP đảo ngược triết lý POP3: **thư ở lại server**, client chỉ là "cửa sổ". Server **stateful** (phiên có chọn mailbox, giữ unseen counter), và hỗ trợ:

- **Folder/mailbox** (`INBOX`, `Gửi đi`, `Lưu trữ/2026/...`) — cấu trúc cây, đồng bộ mọi thiết bị.
- **Flag**: `\Seen` (đã đọc), `\Answered`, `\Flagged`, `\Deleted`, `\Draft` + keyword tùy biến — "đọc trên điện thoại thì laptop cũng hiện đã đọc".
- **Fetch một phần (partial fetch)**: chỉ lấy header `BODY[HEADER.FIELDS (SUBJECT)]`, lấy `BODYSTRUCTURE`, hoặc một đoạn body bằng `BODY[]<offset.octets>` — tiết kiệm băng thông, cho phép xem trước 20 ký tự mà không tải file 10MB.
- **UID vs sequence number**: mỗi message có UID bền vững trong mailbox; sequence number đổi khi message bị expunge — lý do nên thao tác bằng `UID FETCH/STORE`.
- **IDLE** (RFC 2177, nằm trong rev2): client giữ kết nối mở, server *push* thông báo `* N EXISTS` khi có thư mới — nền tảng của "push email" kiểu smartphone mà không cần polling.

Phiên mẫu (lab: `nc mail.lab.local 143`, hoặc `openssl s_client -connect mail.lab.local:993`):

```text
S: * OK [CAPABILITY IMAP4rev2 ... LOGINDISABLED]  <- chưa TLS thì LOGINDISABLED: không cho LOGIN plaintext
C: a STARTTLS
S: a OK [CAPABILITY IMAP4rev2 ... AUTH=PLAIN] Begin TLS negotiation now   <- từ đây phiên đã mã hóa
C: n LOGIN binh matkhau
S: n OK [CAPABILITY ...] Login completed
C: m SELECT INBOX
S: * 4 EXISTS                <- mailbox có 4 message
S: * 1 RECENT
S: * OK [UIDVALIDITY 17] [UIDNEXT 21]
S: m OK [READ-WRITE] SELECT completed
C: x FETCH 3 (BODY.PEEK[HEADER.FIELDS (SUBJECT)] FLAGS)   <- PEEK = xem header KHÔNG đánh dấu \Seen
S: * 3 FETCH (FLAGS (\Recent) BODY[HEADER.FIELDS (SUBJECT)] {20}
S: Subject: Hop lab
S: )
S: x OK FETCH completed
C: y SEARCH UNSEEN           <- tìm thư chưa đọc — server-side search
S: * SEARCH 2 3              <- response untagged '*' liệt kê sequence number
S: y OK SEARCH completed
C: z STORE 1 +FLAGS (\Seen)  <- đồng bộ trạng thái đã đọc cho mọi thiết bị
S: * 1 FETCH (FLAGS (\Seen)) <- server trả flag mới dạng untagged
S: z OK STORE completed
C: p LOGOUT                  <- (trước LOGOUT có thể dùng IDLE để chờ thư mới)
S: * BYE Dovecot...
S: p OK LOGOUT completed
```

- **STARTTLS**: RFC 2595 định nghĩa lệnh `STARTTLS` cho IMAP (và POP3); trên cổng 143, trước khi AUTH. Best practice RFC 8314 là dùng thẳng cổng **993 (IMAPS, implicit TLS)**.
- **SASL**: IMAP AUTH dùng bộ cơ chế SASL chung với SMTP — PLAIN, LOGIN, CRAM-MD5, và hiện đại hơn là **OAUTHBEARER** (Gmail/Microsoft yêu cầu) hay **EXTERNAL** (client certificate).

**Quan sát trong lab**: bật Thunderbird tài khoản IMAP lab, xóa một thư trên laptop → `ss -tlnp` + log Dovecot `/var/log/mail.log` (`imap-login: Login: user=<binh>, method=PLAIN, rip=...`) và trên điện thoại refresh → thấy `\Deleted` đã đồng bộ; so sánh với tài khoản POP3 cùng kịch bản → mỗi thiết bị giữ bản riêng, không đồng bộ.

Nguồn:
- https://www.rfc-editor.org/rfc/rfc9051.html (IMAP4rev2 — trạng thái hiện hành, obsoletes RFC 3501)
- https://www.rfc-editor.org/rfc/rfc3501.html (IMAP4rev1 — obsolete)
- https://datatracker.ietf.org/doc/html/rfc2595 , https://datatracker.ietf.org/doc/html/rfc2177
- https://doc.dovecot.org/latest/

### 2b.7 POP3 hay IMAP? — so sánh theo use case

| Tiêu chí | POP3 (110/995) | IMAP (143/993) |
|---|---|---|
| **Số thiết bị** | 1 thiết bị "chính" — vì tải về là mất bản server (mặc định) | **Nhiều thiết bị** (điện thoại + laptop + webmail) — server là nguồn sự thật |
| **Trạng thái đã đọc/flag** | Không đồng bộ; mỗi máy tự đánh dấu cục bộ | Đồng bộ `\Seen`, `\Answered`, `\Flagged` real-time |
| **Folder** | Chỉ INBOX | Cây mailbox đầy đủ, move/copy phía server |
| **Offline** | Tốt (đã tải hết về local) | Hạn chế — phải cache (Dovecot supports CONDSTORE/QRESYNC và client offline sync) |
| **Băng thông/lưu trữ client** | Tốn bandwidth lần đầu (tải full), nhẹ server | Partial fetch nhẹ client hơn nhưng tốn **dung lượng server** và I/O |
| **Dung lượng server** | Thấp (xóa sau download) | Cao — mailbox phình theo năm, cần quota, expunge, archival |
| **Rủi ro mất dữ liệu** | **Cao**: chết ổ SSD laptop = mất hết thư đã xóa server | Thấp: dữ liệu nằm trên server (nhưng thành single point of failure → cần backup) |
| **Khi nào POP3 hợp lý** | Thiết bị đơn lẻ, mailbox giới hạn dung lượng khắt khe, hoặc pipeline lấy-thư-tự-động (`getmail` về file) | Mặc định cho người dùng hiện đại đa thiết bị, và cho MDA-server chạy webmail |

Kết luận cho lab của đồ án: dùng **IMAP/993** cho người dùng, chỉ bật POP3 khi cố ý minh họa khác biệt (hoặc khi thiết bị nhúng chỉ nói được POP3).

Nguồn:
- https://doc.dovecot.org/latest/configuration/services/imap.html
- https://www.rfc-editor.org/rfc/rfc3501.html (IMAP4rev1 — phần mở đầu có so sánh trực tiếp IMAP vs POP4)

### 2b.8 Luồng email đầy đủ trong lab: An gửi Bình một bức thư đi qua lab như thế nào

Kịch bản: An dùng Thunderbird tại `laptop.an.lab`, Bình dùng Thunderbird tại `desktop.binh.lab`; cả hai thuộc miền `lab.local` phục vụ bởi một máy chủ Ubuntu 26.04 chạy Postfix (MSA+MTA+MDA) + Dovecot (MRA). Toàn bộ diễn ra trong mạng riêng của nhóm.

```
(1) An nhấn Send
    Thunderbird ── TLS (implicit, 465 | STARTTLS, 587) ──► Dovecot-SASL/Postfix MSA
    [MÃ HÓA] phiên: AUTH PLAIN (sau TLS) → MAIL FROM:<an@lab.local>
             → RCPT TO:<binh@lab.local> → DATA → "250 queued as A1B2C3"
    [PLAINTEXT nếu dùng 587/25 mà không bật TLS — lab cần chứng minh bằng tcpdump]

(2) Postfix MTA phân tích RCPT: domain 'lab.local' nằm trong mydestination
    → KHÔNG relay ra ngoài; thư chuyển từ queue 'incoming' vào 'active' để delivery

(3) bàn giao (delivery): Postfix chạy agent 'lmtp:unix:/private/dovecot-lmtp' (LMTP local)
    Dovecot LDA kiểm tra hộp thư tồn tại, quota, (tùy chọn) chạy sieve filter
    → ghi file vào /home/binh/Maildir/lab.local/binh/new/  (Maildir: 1 thư = 1 file)
    mail.log: "status=sent (dovecot)"

(4) Bình mở Thunderbird
    desktop.binh.lab ── TLS implicit cổng 993 (IMAPS) ──► Dovecot IMAP
    [MÃ HÓA] n LOGIN → m SELECT INBOX → x UID FETCH... → * 1 EXISTS (thư mới!)
    flag \Seen được ghi NGAY vào Dovecot index → mọi thiết bị khác của Bình cũng "đã đọc"

(5) Bounce đường vòng (nếu sai): RCPT gửi tới <khongtonTai@lab.local> trong bước (1)
    → "550 5.1.1 User unknown"; nếu chấp nhận rồi mới biết (queue) → MTA gửi
       message delivery status (DSN) về envelope MAIL FROM (Return-Path)
```

**Đâu là plaintext, đâu là TLS — bảng chốt**:

| Chặng | Cổng/phiên | Mặc định | Đúng chuẩn (RFC 8314) |
|---|---|---|---|
| (1) MUA→MSA submission | 587/465 | Bắt buộc AUTH; TLS phụ thuộc cấu hình server | **TLS toàn trình** (465 implicit hoặc 587 + STARTTLS bắt buộc, `smtpd_tls_auth_only=yes`) |
| (2)(3) nội bộ MTA→MDA→mailbox | unix socket/LMTP loopback | plaintext trong máy, không ra mạng | OK (không có đường truyền để tấn công; có thể thêm TLS cho lab nhiều máy) |
| (giữa hai MTA, nếu Bình ở domain khác) | 25 | Opportunistic TLS — **rơi về plaintext nếu bạn nhận không hỗ trợ hoặc bị strip** | DANE/MTA-STS buộc TLS |
| (4) MUA↔MRA | 143/993 (110/995) | 143/110 cho phép plaintext nếu không siết | **993/995 implicit TLS**; Dovecot `ssl=required`, `disable_plaintext_auth=yes` |

Hai hệ quả cần ghi nhớ cho các chương sau: (a) nội dung email được **mã hóa đường truyền** (TLS) nhưng **không mã hóa đầu-cuối** (E2EE) — người quản trị server và MTA transit đều *đọc được* Maildir; (b) thông tin định danh (envelope, AUTH identity) đi theo từng chặng khác nhau với header hiển thị — nên phishing và spoofing sống khỏe ở tầng "header không ai kiểm".

**Tổng kết quan sát trong lab** (không tấn công, chỉ phân tích giao thức trên mạng riêng): dùng Wireshark capture cổng 25/143/110 (profile `smtp`, `imap`, `pop`) để đọc từng dòng lệnh như các phiên mẫu trên (Statistics → Packet Sizes, và Follow → TCP Stream để dựng lại phiên) — đây là cách trực quan nhất để ghi nhớ state machine của từng giao thức; sau đó bật TLS và lặp lại để thấy payload trở thành opaque (chỉ còn thấy TLS record).

Nguồn:
- https://www.wireshark.org/docs/wsug_html/ (User's Guide; xem mục Follow TCP Stream và danh sách protocol dissector)
- https://www.postfix.org/LMTP_README.html
- https://doc.dovecot.org/latest/configuration/services/lmtp.html
- https://ubuntu.com/server/docs/how-to/mail-services/
