## Phụ lục C/D/E: Thuật ngữ, 20 câu tự kiểm tra, danh mục tài liệu chính thức

Phụ lục này tổng hợp (C) bảng thuật ngữ dùng xuyên suốt tài liệu, (D) 20 câu hỏi tự kiểm tra kèm đáp án ngắn để người học ôn lại sau mỗi chương, và (E) danh mục tài liệu chính thức (RFC, tài liệu Ubuntu, tài liệu dự án mã nguồn mở, sách/báo cáo chuẩn hóa) kèm trạng thái và ngày truy cập. Mọi khái niệm tấn công chỉ được mô tả ở mức **nguyên lý và phòng thủ**, phục vụ mục đích giáo dục trong lab mạng riêng do nhóm tự dựng.

---

### Phụ lục C — Thuật ngữ (Glossary)

Các thuật ngữ sắp xếp theo bảng chữ cái (không phân biệt hoa/thường), định nghĩa 1–2 dòng kèm thuật ngữ tiếng Anh. Những mục có dấu `→` là tham chiếu chéo trong bảng.

- **AAA** — Bộ ba *Authentication* (xác thực — đúng là ai), *Authorization* (phân quyền — được làm gì), *Accounting/Audit* (ghi nhận — log những gì đã diễn ra). Mọi dịch vụ trong đồ án (FTP, SSH, mail) đều phải đáp ứng cả ba trụ; thiếu log thì không điều tra được sự cố.
- **Active mode (chế độ chủ động FTP)** — Chế độ FTP mà **server chủ động kết nối ngược** từ port 20 về port tạm của client theo địa chỉ client khai trong lệnh `PORT`. Dễ vỡ khi client đứng sau NAT/firewall (xem → PASSIVE mode).
- **Anonymous FTP** — FTP cho đăng nhập bằng user `anonymous`, mật khẩu là chuỗi bất kỳ/thông báo email. Tiện để phân phối file công khai nhưng là bề mặt tấn công nếu cho ghi (upload) hoặc lộ dữ liệu nội bộ.
- **AUTH** — Lệnh mở rộng để bắt đầu phiên mã hóa/xác thực: `AUTH TLS` trong FTPS (RFC 2228/4217) nâng cấp kênh điều khiển lên TLS; `AUTH` trong SMTP (RFC 4954) chọn cơ chế SASL như `PLAIN`, `LOGIN`, `CRAM-MD5`.
- **Banner** — Chuỗi chào đầu phiên do server gửi (ví dụ Postfix: `220 mail.example.com ESMTP Postfix`). Banner dài/hở lộ tên và phiên bản phần mềm → thu hút quét tự động; nên rút gọn theo nguyên tắc tối thiểu.
- **Base64** — Cách mã hóa (encoding) nhị phân sang ký tự ASCII (RFC 4648), dùng trong `AUTH LOGIN` của SMTP hay một phần lệnh FTP. **Lưu ý bản chất:** base64 *không phải mã hóa bảo mật* — chỉ cần một lệnh giải mã là thấy lại mật khẩu rõ.
- **Brute force (tấn công vét cạn)** — Thử dò mật khẩu/key theo sinh tự động toàn bộ không gian từ điển hoặc tổ hợp. Với dịch vụ mail/FTP, dấu hiệu quan sát được trong lab: hàng trăm dòng `Auth failed`/`530 Login incorrect` liên tiếp từ một IP nguồn.
- **CA (Certificate Authority)** — Tổ chức cấp và ký **certificate** (→), tạo chuỗi tin cậy để client xác định danh tính server khi bắt tay TLS. Trong lab có thể dựng CA riêng (self-signed) và chỉ định client tin tưởng nó.
- **Certificate (X.509 →)** — File khai báo "công khóa này thuộc về tên miền/nhà cung cấp này", do CA ký. Postfix/Dovecot khai đường dẫn cert trong `main.cf` (`smtpd_tls_cert_file`) và `ssl_cert`.
- **chroot** — Cơ chế nhốt tiến trình vào một thư mục gốc giả, không nhìn thấy phần còn lại của hệ thống tệp. Trong vsftpd: `chroot_local_user=YES` giới hạn user FTP trong home của họ (xấu nếu user thoát được shell — xem → jail).
- **Cipher suite (bộ mã hóa)** — Tập hợp thuật toán TLS thỏa thuận lúc bắt tay: trao đổi khóa + mã đối xứng + hash. Ở TLS 1.3 các suite gọn và mạnh, ví dụ `TLS_AES_256_GCM_SHA384`; cần tắt suite cũ có RC4/3DES/NULL trong cấu hình Postfix/Dovecot/OpenSSH.
- **Client–server** — Mô hình giao tiếp: client gửi yêu cầu, server phục vụ nhiều client (FTP client ↔ vsftpd, MUA ↔ Dovecot). Mọi giao thức trong đồ án theo mô hình này.
- **Control channel (kênh điều khiển)** — Kênh lệnh của FTP, chạy trên TCP 21; dữ liệu thật đi qua **kênh dữ liệu** riêng (TCP 20 ở active mode hoặc port tạm ở passive) — đặc điểm "hai kênh" dễ gây lỗi firewall nhất của FTP.
- **Credential stuffing** — Dùng danh sách cặp email/mật khẩu lộ từ vụ rò rỉ này để thử đăng nhập hàng loạt trên dịch vụ khác (khác brute force: không dò mật khẩu, chỉ *nhồi* credential có sẵn). Phòng: bắt buộc mật khẩu mạnh + 2FA, bật Fail2ban với `maxretry` thấp.
- **DKIM (DomainKeys Identified Mail, RFC 6376)** — Server gửi **ký** email bằng → private key; domain công bố → public key trong DNS TXT (`selector._domainkey.example.com`). Server nhận kiểm chữ ký để chắc nội dung không bị sửa giữa đường.
- **DMARC (RFC 7489)** — Chính sách DNS TXT tại `_dmarc.example.com`: domain yêu cầu email phải vượt cả SPF lẫn DKIM (alignment) với mức `p=none/quarantine/reject`, kèm địa chỉ nhận báo cáo. DMARC "khóa" hai cơ chế trước thành vòng khép kín chống giả mạo domain.
- **DNS (Domain Name System)** — Dịch vụ phân giải tên → địa chỉ IP (và các bản ghi MX, TXT...). Toàn bộ SPF/DKIM/DMARC đều "sống" trên DNS; DNS dùng UDP 53 (và TCP khi dữ liệu lớn).
- **FTPS (FTP over TLS)** — FTP + TLS theo RFC 4217, có hai dạng: **explicit** (vẫn port 21, lên TLS bằng `AUTH TLS`) và **implicit** (port 990, TLS ngay từ đầu). Lưu ý: FTPS ≠ SFTP (→).
- **FTP (File Transfer Protocol, RFC 959)** — Giao thức chuyển file cổ điển, TCP 21 điều khiển + kênh dữ liệu riêng; nguyên bản truyền **rõ văn bản** kể cả `USER`/`PASS` — lý do chính phải thay bằng FTPS/SFTP.
- **Firewall** — Thiết bị/phần mềm lọc lưu lượng theo quy tắc. Trong lab Ubuntu dùng UFW/iptables ở phía host và security group ở router ảo.
- **FQDN (Fully Qualified Domain Name)** — Tên miền gồm cả máy và domain, ví dụ `mail.example.com.` — Postfix yêu cầu khai `myhostname` là FQDN đúng để phiên SMTP và cert khớp nhau.
- **Handshake (bắt tay)** — Chuỗi trao đổi thỏa thuận tham số trước khi truyền dữ liệu. Thường gặp nhất trong đồ án: **TLS handshake** (xác thực cert, trao đổi khóa, chốt cipher suite). Xem thêm → three-way handshake.
- **Hash (hàm băm)** — Hàm một chiều biến dữ liệu thành digest cố định (SHA-256...); dùng trong tính toàn vẹn DKIM, chứng thư số, và log. Hash ≠ mật mã đối xứng; không "giải" ngược được.
- **Hostname** — Tên máy trong mạng (lệnh `hostnamectl` trên Ubuntu). mail server nên đặt hostname trỏ đúng qua DNS ngược, vì nhiều MTA công cộng từ chối kết nối không khớp PTR.
- **IMAP (Internet Message Access Protocol, RFC 9051 IMAP4rev2)** — Giao thức đọc mail **hộp thư nằm trên server**: nhiều client cùng thấy một trạng thái, hỗ trợ folder/flag/search. Cổng 143 (rõ) và 993 (→ implicit TLS). Thay thế RFC 3501 (IMAP4rev1).
- **Implicit TLS** — Kết nối được mã hóa TLS ngay từ gói đầu tiên trên một cổng riêng (FTPS 990, SMTPS 465, POP3S 995, IMAPS 993). Đối trọng với **STARTTLS**: lên TLS giữa phiên. RFC 8314 khuyến nghị implicit TLS cho MSA.
- **Jail (Fail2ban)** — Đơn vị cấu hình ghép một **filter** (regex log) với một **action** (chặn IP): `[sshd]`, `[postfix]`, `[dovecot]`. Xem `fail2ban-client status postfix-sasl` để kiểm chứng trong lab.
- **journalctl** — Công cụ đọc log của systemd: `journalctl -u postfix -f`, `-u dovecot`, `-u ssh`, `-u fail2ban` — trên Ubuntu bản mới, log dịch vụ nằm trong journald (kèm syslog ở `/var/log/mail.log` qua rsyslog).
- **Least privilege (đặc quyền tối thiểu)** — Mỗi tiến trình/user chỉ giữ quyền tối thiểu cần: vsftpd chạy `ftp` không phải root, Dovecot có `dovenull`/`vmail`, Postfix phân tách tiến trình privilege separation, key SSH đặt 600. Là trục của mọi bài phòng thủ trong tài liệu.
- **LMTP (Local Mail Transfer Protocol, RFC 2033/6418)** — Biến thể SMTP cho **giao thư cục bộ**: Postfix (MTA) đẩy thư cho Dovecot lda qua LMTP (`/var/run/dovecot/lmtp` hoặc TCP 24), khác SMTP chỗ không retry toàn phần.
- **mail queue (hàng đợi thư)** — Nơi Postfix giữ thư chưa gửi được (`postqueue -p` để xem); đối tượng tấn công/lan truyền spam nếu máy thành open relay; quản trị hằng ngày bằng `postsuper`/`postqueue`.
- **MDA/LDA (Mail Delivery Agent / Local Delivery Agent)** — Khâu cuối giao thư vào mailbox người nhận; trong lab thường là `dovecot-lda` nhận LMTP, hoặc `procmail`. Trong Postfix là tiến trình `local`.
- **MSA (Mail Submission Agent)** — Dịch vụ nhận thư **từ client đã xác thực** ở cổng 587 (STARTTLS) hoặc 465 (implicit TLS) theo RFC 6409 — tách khỏi MTA công cộng (25) để kiểm soát được người gửi.
- **MTA (Mail Transfer Agent)** — Chương trình chuyển thư giữa các server: Postfix ở lab là một MTA. Nghe SMTP ở cổng 25, tra DNS MX để route.
- **MUA (Mail User Agent)** — Ứng dụng người dùng cuối đọc/gửi mail (Thunderbird, webmail). MUA nói chuyện với MSA để gửi và với IMAP/POP3 server để đọc.
- **NAT (Network Address Translation)** — Cơ chế nhiều host dùng chung một IP công cộng. Kẻ thù của **active mode FTP** (server không biết NAT dịch port nào) và của passive khi server sau NAT — phải cấu hình `pasv_address`/range port.
- **Open relay** — SMTP server cho **người lạ** nhờ chuyển thư đi nơi khác — "máy phát spam" cho kẻ tấn công và bị liệt blacklist. Test bằng chính `EHLO`/`MAIL FROM` trong lab: nhận thư gửi tới địa chỉ ngoài domain = relay hở.
- **PASSIVE mode (PASV)** — Chế độ FTP mà **client chủ động** kết nối tới port tạm server mở (server trả về trong đáp lệnh `PASV`). Thân thiện với NAT client nhưng đòi firewall server cho mở dải port tạm (`pasv_min_port`/`pasv_max_port`).
- **POP3 (Post Office Protocol v3, RFC 1939)** — Giao thức đọc mail "tải về máy, có thể xóa server". Đơn giản nhưng làm mail nằm phơi bày trên client; cổng 110 (rõ) và 995 (implicit TLS). Vẫn là Internet Standard (STD 53), được cập nhật bởi RFC 1957/2449/6186/8314.
- **Port forwarding** — Chuyển cổng này sang cổng khác/host khác (`ufw route ...`, `ssh -L`, virtual IP trong lab nhiều subnet); nhắc tới khi đi debug FTP qua NAT, không phải kỹ thuật tấn công.
- **Postfix** — MTA mã nguồn mở mặc định nhiều bản Ubuntu, kiến trúc nhiều tiến trình nhỏ thay cho sendmail cũ; cấu hình chính `/etc/postfix/main.cf`, `master.cf`. Bản đang duy trì: nhánh 3.10.x/3.11.x (8/2026).
- **Private key (khóa bí mật)** — Nửa cặp khóa bất đối xứng, **giữ kín** (key SSH của user, key ký DKIM, key TLS server); file quyền 600. Lộ private key = phải rotate và thu hồi cert.
- **Public key (khóa công khai)** — Nửa cặp khóa phân phối công khai (công bố DNS cho DKIM, gửi cho server khi đăng nhập SSH key, nằm trong certificate TLS).
- **RSA** — Thuật toán mã hóa/chữ ký **bất đối xứng** (→ private key/→ public key), hay gặp trong host key SSH và cert; kích thước khuyến nghị ≥ 2048 bit, ECDSA/Ed25519 gọn hơn.
- **SASL (Simple Authentication and Security Layer, RFC 4422)** — Khung xác thực "cắm" vào giao thức text-based: SMTP `AUTH` (RFC 4954), IMAP/POP3 `AUTHENTICATE`. Postfix/Dovecot dùng chung SASL qua `smtpd_sasl_type = dovecot`.
- **socket** — Điểm chốt giao tiếp TCP/UDP trong hệ điều hành (`/var/run/dovecot/lmtp` là UNIX socket); hiểu socket giúp đọc `ss -tlnp` khi kiểm tra dịch vụ nào đang thật sự mở cổng.
- **SFTP (SSH File Transfer Protocol)** — Chuyển file **chạy trên nền SSH** (cổng 22), không liên quan gì đến FTP — tên dễ nhầm với FTPS. Trong OpenSSH là subsystem `sftp-server` khai trong `sshd_config`; protocol do IETF từng soạn (bộ draft `draft-ietf-secsh-filexfer`, chưa từng thành RFC) và bản OpenSSH phổ biến nhất là version 3.
- **SMTP (Simple Mail Transfer Protocol, RFC 5321)** — Giao thức chuyển thư giữa server và từ MSA; chạy trên TCP 25 (công cộng), 587/465 (submission). Trả lời bằng mã số ba chữ số: 2xx thành công, 4xx tạm thời, 5xx vĩnh viễn (→ open relay: `554 5.7.1 Relay access denied`).
- **SMTPS** — Tên dân gian cho implicit TLS ở cổng 465; từng bị "gỡ đăng ký" một thời gian vì cho rằng thừa so với STARTTLS, nay được **phục hồi** như lựa chọn khuyến nghị cho MSA theo RFC 8314. Không nhầm với STARTTLS trên 587.
- **SPF (Sender Policy Framework, RFC 7208)** — Bản ghi TXT khai "những IP nào được phép gửi mail cho domain tôi"; server nhận so IP kết nối SMTP với danh sách này. Cập nhật RFC 4408 (cũ, đã Historic). SPF một mình chống được *giả envelope sender*, không chống giả tên hiển thị.
- **SSL (Secure Sockets Layer)** — Tiền thân của → TLS; SSL 2.0/3.0 đã bị khai tử (SSL 3.0 bị chính thức deprecated bởi RFC 7568) vì lỗi thiết kế (POODLE). Ngày nay nói "SSL" thường chỉ là cách gọi dân gian của TLS — không bật SSL trong cấu hình.
- **STARTTLS** — Lệnh nâng cấp kết nối *đang chạy rõ văn bản* lên TLS ngay trong cùng phiên (`220 ... STARTTLS` → handshake). Điểm yếu so với implicit: bị **downgrade stripping** nếu đối thủ chặn trước thông báo hỗ trợ; mitigations: `smtpd_tls_security_level = may/enforce` (Postfix), buộc `ssl = required` (Dovecot), MSA dùng implicit 465.
- **Stateful firewall** — Firewall theo dõi trạng thái kết nối: cho lại lưu lượng "đã từng được phép" mà không cần rule hai chiều (iptables `-m state --state ESTABLISHED,RELATED`). Là lý do active mode FTP qua firewall *có thể* hoạt động khi có module conntrack `nf_conntrack_ftp`.
- **Subnet** — Dải IP cùng mạng logic; lab nên tách subnet riêng (server/client) để mô phỏng NAT, firewall giữa hai vùng và quan sát rõ hướng kết nối bằng Wireshark.
- **Symmetric encryption (mã hóa đối xứng)** — Một khóa chung để mã/giải (AES-GCM...). Nhanh, dùng cho toàn bộ dữ liệu phiên TLS; bài toán "trao khóa thế nào" do phía bất đối xứng (RSA/ECDSA/DH) giải quyết trong handshake.
- **Syslog** — Chuẩn/niềm ghi log hệ thống; trên Ubuntu: rsyslog ghi `/var/mail.log` (facility `mail`, `auth`), hoặc đọc qua → journalctl. Log là "camera an ninh": không có log đủ tốt thì Fail2ban và điều tra sự cố đều vô nghĩa.
- **TCP (Transmission Control Protocol)** — Tầng vận chuyển hướng kết nối, đảm bảo thứ tự/độ tin cậy; mọi giao thức trong tài liệu chạy trên TCP. Server phải có: `ss -tlnp` liệt kê tiến trình đang listen.
- **Three-way handshake** — Ba bước mở TCP: `SYN` → `SYN-ACK` → `ACK`. Quan sát bằng Wireshark filter `tcp.flags.syn==1 && tcp.flags.ack==0`. Là nền để hiểu vì sao firewall DROP (không SYN-ACK) làm client timeout, còn REJECT trả RST ngay.
- **TLS (Transport Layer Security)** — Lớp mã hóa "đặt dưới" các giao thức ứng dụng: TLS 1.3 (RFC 8446) là bản hiện hành, 1.2 (RFC 5246) vẫn dùng phổ biến khi client chưa theo kịp. Cung cấp bí mật + toàn vẹn + xác thực server (tùy chọn cả client).
- **Tunnel (đường hầm)** — Đóng gói giao thức này trong giao thức khác: SSH tunnel (`ssh -L 1143:imap.internal:143`) để đọc IMAP mã hóa qua kênh SSH; hoặc VPN site-to-site giữa hai subnet lab.
- **UDP** — Tầng vận chuyển không kết nối; các dịch vụ FTP/SSH/mail trong tài liệu **không** dùng UDP, nhưng **DNS** (nền tảng SPF/DKIM/DMARC/MX) dùng UDP 53 → không chặn nhầm khi siết firewall.
- **UFW** — Frontend firewall đơn giản của Ubuntu: `ufw allow 993/tcp`, `ufw status numbered`. Kèm `fail2ban` để tự động chặn IP brute force vào các rule này.
- **Username enumeration (liệt kê tên đăng nhập)** — Để lộ "user này có tồn tại hay không" qua khác biệt phản hồi/định thời gian (SMTP `VRFY/EXPN` bật, POP3 `+OK/-ERR` khác nhau theo user, hay SSH trả `bad authentication` chỉ khi user có key). Đóng bằng cách trả lời đồng nhất, tắt VRFY/EXPN, vô hiệu timing side-channel qua rate limit.
- **X.509** — Cấu trúc chuẩn của certificate và CRL (RFC 5280): tên subject, SAN, thời hạn, chuỗi issuer. Cert TLS của Postfix/Dovecot/vsftpd là X.509; lệnh kiểm tra nhanh: `openssl s_client -connect host:993 -showcerts`.

*(Nguồn: định nghĩa đối chiếu RFC từng giao thức ở Phụ lục E.1, docs Ubuntu/Dovecot/Postfix/OpenSSH ở E.2–E.3; cập nhật 8/2026.)*

---

### Phụ lục D — 20 câu hỏi tự kiểm tra (kèm đáp án)

Cách dùng: trả lời nháp trước, đối chiếu đáp án một dòng, rồi đọc lại đúng mục được dẫn. Bố cục: 5 câu khái niệm nền, 8 câu giao thức, 4 câu nguy cơ, 3 câu phòng thủ.

#### D.1 — Khái niệm nền (5 câu)

1. **TLS giải quyết ba vấn đề gì mà truyền rõ văn bản không có?** — Bí mật (mã hóa), toàn vẹn (không sửa giữa đường), xác thực (đúng server qua cert). *(Xem mục TLS, certificate — Phụ lục C.)*
2. **Vì sao TLS dùng cả mã đối xứng lẫn bất đối xứng?** — Bất đối xứng để trao khóa/xác thực không cần gặp trước; đối xứng (AES) để mã dữ liệu lớn cho nhanh. *(Xem symmetric encryption, cipher suite.)*
3. **CA tồn tại để làm gì trong phiên TLS?** — Ký certificate để client kiểm chuỗi tin cậy và tin công khóa nhận được là của đúng domain, không phải kẻ trung gian. *(Xem CA, X.509.)*
4. **Cho hai ví dụ nguyên tắc least privilege áp lên máy chủ mail/FTP?** — vsftpd `chroot_local_user=YES`; Postfix privilege separation + user `vmail` không shell đăng nhập; key SSH `chmod 600`. *(Xem chroot, least privilege; chương Quản trị.)*
5. **Stateful firewall khác stateless ở đâu, ích lợi gì cho FTP active?** — Có/ không theo dõi trạng thái phiên; stateful + conntrack cho phép dữ liệu FTP "hồi đáp" vào port tạm mà không mở cả dải. *(Xem stateful firewall, three-way handshake.)*

#### D.2 — Giao thức, cổng, mô hình, lệnh (8 câu)

6. **FTP active mode: dữ liệu đi qua cổng nào và hướng kết nối ra sao?** — Server **từ port 20** chủ động kết nối tới port tạm client khai trong lệnh `PORT`. *(Xem active mode, control channel.)*
7. **SFTP chạy trên nền giao thức nào, cổng bao nhiêu?** — Nền **SSH, TCP 22**; không phải FTP và không dùng kênh điều khiển/kênh dữ liệu của FTP. *(Xem SFTP.)*
8. **Kể cổng phổ biến của SMTP công cộng, submission và đọc mail (POP3/IMAP) bản TLS.** — 25 (SMTP), 587 (MSA/STARTTLS), 465 (MSA implicit TLS), 995 (POP3S), 993 (IMAPS), 22 (SFTP). *(Xem bảng cổng ở chương Cài đặt.)*
9. **587 và 465 khác nhau bản chất ở đâu?** — 587: phiên rõ rồi `STARTTLS` nâng lên; 465: TLS ngay từ gói đầu (implicit); RFC 8314 khuyến nghị 465 để tránh downgrade. *(Xem STARTTLS, implicit TLS, MSA.)*
10. **Trong sơ đồ Postfix + Dovecot + Thunderbird, thành phần nào là MUA/MSA/MTA/MDA?** — Thunderbird = MUA (gửi qua MSA 587); Postfix = MSA (cổng submission) + MTA (cổng 25); Dovecot lda = MDA qua LMTP. *(Xem MUA, MSA, MTA, MDA, LMTP.)*
11. **`554 5.7.1 <user@khác-domain>: Relay access denied` trong log Postfix nghĩa là gì?** — Server **từ chối chuyển tiếp** thư tới đích không thuộc domain mình vì người gửi chưa xác thực — hành vi đúng của máy không phải open relay. *(Xem open relay, mail queue; mục D.3.)*
12. **Bản chất POP3 vs IMAP khiến người dùng multi-device chọn giao thức nào?** — POP3 tải về (và có thể xóa server) → mailbox phân mảnh mỗi thiết bị một góc; IMAP (rev2, RFC 9051) giữ mailbox trên server, đồng bộ flag/folder. *(Xem POP3, IMAP.)*
13. **Ở FTP, lệnh nào quyết định kênh dữ liệu và kênh điều khiển là gì?** — `PORT` (active) / `PASV` (passive) chọn hướng kênh dữ liệu; kênh điều khiển luôn là TCP 21 (hoặc 990 TLS cho implicit). *(Xem control channel, active mode, PASSIVE mode.)*

#### D.3 — Nguy cơ bị tấn công (4 câu)

14. **Vì sao FTP rõ văn bản nguy hiểm ngay cả khi không ai "tấn công" tích cực?** — `USER`/`PASS` chạy plaintext → bất kỳ ai cùng mạng segment capture được là có credential; kiểm chứng trong lab bằng Wireshark filter `ftp.request.command == "PASS"`. *(Xem FTP; chương Nguy cơ.)*
15. **Brute force và credential stuffing khác nhau thế nào về dữ liệu đầu vào?** — Brute force **dò** mật khẩu theo từ điển/tổ hợp; stuffing **nhồi** cặp user:pass có thật từng rò rỉ, không cần dò. *(Xem brute force, credential stuffing.)*
16. **Vì sao bật anonymous FTP thường bị đánh giá rủi ro cao?** — Ai cũng vào được ⇒ nếu có thư mục ghi được, server biến thành nơi chứa malware/phishing; nếu lộ thư mục hệ thống ⇒ thông tin cho kẻ tấn công dựng cuộc tấn công tiếp theo. *(Xem anonymous FTP.)*
17. **Open relay gây hại gì cho chính chủ máy ngoài chuyện "phát thư giùm"?** — Bị Blacklist (Spamhaus...), tống tiền/ spam flood làm sập mail, lộ IP nội bộ và dùng như bàn đạp phishing — hệ quả: thư hợp lệ của tổ chức bị từ chối theo. *(Xem open relay.)*

#### D.4 — Phát hiện sớm & phòng thủ (3 câu)

18. **Fail2ban jail hoạt động thế nào; ví dụ jail đúng cho lab mail?** — Đọc log → regex filter → khớp nhiều lần trong `findtime` thì action chặn IP. `[postfix-sasl]`/`[dovecot]` trỏ `/var/log/mail.log` (hoặc journal), `bantime` tăng dần. *(Xem jail (Fail2ban), syslog, banner; chương Phòng ngừa.)*
19. **Không chroot FTP user thì vi phạm điều gì, hậu quả ra sao nếu user đó thoát được?** — Vi phạm → least privilege; thoát lệnh shell (qua `SITE EXEC` nếu cấu hình sai) ⇒ user FTP đọc khắp filesystem với quyền process. Chroot + không cho write-into-root + `allow_writeable_chroot` đúng chỗ. *(Xem chroot, least privilege.)*
20. **SPF, DKIM, DMARC ghép lại tạo vòng khép kín chống giả mạo như thế nào?** — SPF: đúng *đường* gửi (IP được domain ủy quyền); DKIM: *nội dung* còn nguyên + đúng chủ key; DMARC: đối *chủ domain* hai kết quả trên, ra chính sách reject/quarantine + báo cáo — mỗi cái một mình đều để hở. *(Xem SPF, DKIM, DMARC.)*

*(Nguồn: toàn bộ đáp án bám các mục tương ứng ở Phụ lục C và chuẩn RFC tương ứng — xem E.1; cập nhật 8/2026.)*

---

### Phụ lục E — Danh mục tài liệu chính thức

Quy ước: mỗi mục ghi **URL chính thức + trạng thái + công dụng trong đồ án**. Ngày truy cập/cập nhật: **8/2026**. Trạng thái RFC lấy theo trang RFC Editor (rfc-editor.org) tại thời điểm truy cập.

#### E.1 — RFC (chuẩn hóa IETF)

| RFC | Tên gọi | Trạng thái (RFC Editor, 8/2026) | Dùng để |
|---|---|---|---|
| [RFC 959](https://www.rfc-editor.org/rfc/rfc959) | File Transfer Protocol | Internet Standard (STD 9) | Định nghĩa FTP, kênh điều khiển/dữ liệu, lệnh `PORT`/`PASV`/`RETR`/`STOR` |
| [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) | SMTP | Internet Standard (STD 10) | Mã hồi đáp SMTP (2xx/4xx/5xx), quy tắc relay, `EHLO` |
| [RFC 6409](https://www.rfc-editor.org/rfc/rfc6409) | Message Submission for Relay | Proposed Standard | Mô hình MSA, cổng 587, buộc xác thực trước khi chấp nhận thư client |
| [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314) | Cleartext Considered Obsolete | Proposed Standard | Khuyến nghị implicit TLS cho submission/POP3/IMAP; cơ sở chọn 465/993/995 |
| [RFC 1939](https://www.rfc-editor.org/rfc/rfc1939) | POP3 | Internet Standard (STD 53; được cập nhật bởi 1957, 2449, 6186, 8314) | Mô hình tải-xóa của POP3, trạng thái TRANSACTION/UPDATE |
| [RFC 9051](https://www.rfc-editor.org/rfc/rfc9051) | IMAP4rev2 | Proposed Standard (2021; thay thế RFC 3501 IMAP4rev1) | Bản chuẩn hiện hành của IMAP; yêu cầu bắt buộc AUTH/TLS hiện diện sẵn trong spec |
| [RFC 4217](https://www.rfc-editor.org/rfc/rfc4217) | Securing FTP with TLS (FTPS) | Historic | Explicit vs implicit FTPS, cổng 990, thứ tự `AUTH TLS` |
| [RFC 2228](https://www.rfc-editor.org/rfc/rfc2228) | FTP Security Extensions | Historic | Nguồn gốc lệnh `AUTH`/`PROT` trong FTPS |
| [RFC 2487](https://www.rfc-editor.org/rfc/rfc2487) | SMTP over TLS | Historic (được thay bởi RFC 3207) | Giai đoạn đầu chuẩn hóa STARTTLS-TLS |
| [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207) | SMTP Service Extension for Secure SMTP over TLS | Proposed Standard | Hành vi `STARTTLS` SMTP, giới hạn khi downgrade bị chặn |
| [RFC 4954](https://www.rfc-editor.org/rfc/rfc4954) | SMTP Service Extension for Authentication | Proposed Standard | `AUTH` SMTP, cơ chế SASL (PLAIN/LOGIN/CRAM-MD5) |
| [RFC 4422](https://www.rfc-editor.org/rfc/rfc4422) | SASL | Proposed Standard | Định nghĩa khung SASL mà SMTP/IMAP/POP3 dùng |
| [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) | SPF | Proposed Standard (cập nhật RFC 4408 — Historic) | Bản SPF hiện hành, quy tắc chấm điểm `pass/fail/softfail` |
| [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) | DKIM | Proposed Standard | Cấu trúc header `DKIM-Signature`, selector/key trong DNS |
| [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) | DMARC | Proposed Standard | Bản ghi `_dmarc`, alignment, cơ chế báo cáo |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3 | Proposed Standard | Cipher suite TLS 1.3, handshake rút gọn — chuẩn mã hóa tham chiếu |
| [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) | TLS 1.2 | Proposed Standard | Bối cảnh tương thích khi chưa bật TLS 1.3 |
| [RFC 7568](https://www.rfc-editor.org/rfc/rfc7568) | Deprecating SSL 3.0 | Historic | Cứu chứng "tắt SSL" trong mọi cấu hình |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | X.509 PKI Certificate and CRL Profile | Proposed Standard | Cấu trúc certificate TLS/DKIM dùng |
| [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251)/[4252](https://www.rfc-editor.org/rfc/rfc4252)/[4253](https://www.rfc-editor.org/rfc/rfc4253)/[4254](https://www.rfc-editor.org/rfc/rfc4254) | SSH Architecture / Authentication / Transport / Connection | Proposed Standard (4253 được cập nhật tiếp bởi RFC 6668, 8268, 8308, 8332, 8709, 8758, 9142 theo RFC Editor) | Nền của SFTP/SSH tunnel: kiến trúc, thuật toán transport, auth |
| — | SFTP (file transfer subsystem) | **Không có RFC chính thức** — bộ IETF draft `draft-ietf-secsh-filexfer-*` (dừng ở -13, chưa thành chuẩn); thực tế tuân theo bản OpenSSH protocol version 3 | Giải thích vì sao hai triển khai SFTP có thể lệch hành vi so nhau |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) + [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Keywords for Requirement Levels | BCP 14 | Đọc đúng MUST/SHOULD/MAY khi trích RFC |
| [RFC 6335](https://www.rfc-editor.org/rfc/rfc6335) | IANA Procedures — Service Name and Transport Protocol Port Number Registry | BCP 165 (cập nhật RFC 2780 và các RFC liên quan) | Cơ sở tra cổng chính thức: `https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml` |

#### E.2 — Tài liệu Ubuntu (documentation.ubuntu.com)

| Tài liệu | URL | Công dụng |
|---|---|---|
| Ubuntu Server documentation | https://documentation.ubuntu.com/server/ | Hướng dẫn cài/quản trị OpenSSH server, UFW, services; bản LTS hiện hành **26.04 LTS "Resolute Raccoon" (ra 23/04/2026)**, hỗ trợ tới 2031; 24.04 LTS "Noble Numbat" vẫn trong chu kỳ hỗ trợ |
| Release notes 26.04 | https://documentation.ubuntu.com/release-notes/26.04/ | Đối chiếu phiên bản gói (Postfix 3.10.x, OpenSSH, Dovecot 2.4.x đi kèm bản LTS mới) |
| Ubuntu Community UFW | https://help.ubuntu.com/community/UFW | Cú pháp `ufw allow`, status, log rule — dùng cho chương Phòng ngừa |
| Man pages chính thức (manpages.ubuntu.com) | https://manpages.ubuntu.com/ | Tra `journalctl(1)`, `ss(8)`, `ufw(8)` đúng theo bản distro |

#### E.3 — Tài liệu dự án mã nguồn mở

| Dự án | Tài liệu | URL | Công dụng / phiên bản tham chiếu |
|---|---|---|---|
| Postfix | BASIC_CONFIGURATION_README | https://www.postfix.org/BASIC_CONFIGURATION_README.html | `myhostname`, `mydestination`, `inet_interfaces`; Postfix 3.10.x/3.11.x đang duy trì (8/2026) |
| Postfix | TLS_README | https://www.postfix.org/TLS_README.html | `smtpd_tls_security_level`, cert/key, chuỗi mật mã |
| Postfix | Announcements | https://www.postfix.org/announcements.html | Theo dõi bản vá bảo mật |
| Dovecot | Docs chính (2.4) | https://doc.dovecot.org/ | `ssl = required`, LMTP, `auth_mechanisms`; **Dovecot 2.4.4 (05/2026)** — lưu ý cấu hình 2.4 **tương thích ngược với 2.3**, cần đọc hướng dẫn nâng cấp |
| Dovecot | Upgrade 2.3 → 2.4 | https://doc.dovecot.org/main/installation/upgrade/2.3-to-2.4.html | Bước bắt buộc khi lab nâng từ bản cũ |
| Dovecot | Wiki (2.3) | https://wiki.dovecot.org/ | Tài liệu lịch sử, mẫu cấu hình các mục con |
| OpenSSH | Man pages portable | https://www.openssh.com/manual.html | `sshd_config(5)`: `Subsystem sftp`, `PasswordAuthentication`, `PermitRootLogin` |
| OpenSSH (OpenBSD) | sshd_config(5) | https://man.openbsd.org/sshd_config.5 | Bản man chi tiết nhất của từng tham số |
| vsftpd | Red Hat Enterprise Linux — FTP Servers (System Administrators Guide) | https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-ftp_servers | Mẫu `vsftpd.conf`, `chroot_local_user`, `pasv_min/max_port`; vsftpd hiện hành 3.0.5 |
| Wireshark | Display Filter Reference + wiki | https://wiki.wireshark.org/DisplayFilters , https://www.wireshark.org/docs/ | Bộ lọc thực hành quan sát lab: `ftp`, `smtp`, `imap`, `pop`, `ssh`, `tls.handshake.type` |
| Fail2ban | GitHub + docs | https://github.com/fail2ban/fail2ban , https://fail2ban.readthedocs.io/ | Jail `[postfix]`/`[dovecot]`/`[sshd]`, filter regex, action ban; bản 1.1.x |

#### E.4 — Sách và tài liệu tổ chức khác

| Nguồn | URL | Công dụng |
|---|---|---|
| NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Guide | https://csrc.nist.gov/pubs/sp/800/61/r3/final | Khung phát hiện sớm/xử lý sự cố áp cho các chương Nguy cơ & Phòng ngừa (Rev. 3 thay Rev. 2, phát hành 2025) |
| NIST SP 800-53 Rev. 5 (AC/AU/SC) | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | Ánh xạ control: least privilege (AC-6), audit log (AU-*), transmission confidentiality (SC-8) |
| OWASP Authentication Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html | Khuyến nghị policy mật khẩu, chống brute force/enumeration cho mọi dịch vụ trong đồ án |
| NVD (National Vulnerability Database) | https://nvd.nist.gov/ | Tra CVE của từng phần mềm nếu cần dẫn chứng (không nêu CVE bừa — chỉ khi có số thật) |
| E. Nemeth et al., *UNIX and Linux System Administration Handbook* (5th ed., Addison-Wesley, 2017) | — | Chương mail/DNS — nền khái niệm MTA/MSA/MDA |
| J. Kurose, K. Ross, *Computer Networking: A Top-Down Approach* (8th ed., Pearson, 2021) | — | Nền TCP/UDP, application layer cho người mới |

*(Nguồn: toàn bộ URL đã đối chiếu RFC Editor / site chính thức tại ngày truy cập 8/2026; trạng thái RFC có thể thay đổi khi IETF công bố văn bản mới — kiểm tra lại trước khi trích dẫn trong bản in.)*
