## 6. Biện pháp phòng ngừa và gia cố

Chương này tổng hợp các biện pháp **phòng ngừa** (ngăn tấn công xảy ra) và **gia cố** (hardening — thu nhỏ bề mặt tấn công, giảm thiệt hại nếu bị xâm nhập) cho năm dịch vụ mà đồ án quản trị: FTP, SFTP, SMTP, POP3, IMAP. Mỗi biện pháp được trình bày theo cùng một khung: **nguyên lý → ưu điểm → nhược điểm/chi phí → khi nào nên dùng**, đặt trong bối cảnh cụ thể của lab Ubuntu Server mà nhóm vận hành (mạng riêng do nhóm sở hữu, máy chủ `mail.lab.local`, bản Ubuntu 26.04 LTS "Resolute Raccoon" phát hành 23/4/2026, hỗ trợ tiêu chuẩn đến tháng 4/2031).

Nguyên tắc xuyên suốt: không có biện pháp đơn lẻ nào là "viên đạn bạc". An toàn đến từ **phòng thủ nhiều lớp (defense in depth)** — mã hóa kênh truyền + xác thực mạnh + thu hẹp bề mặt tấn công + kiểm soát mạng + giám sát + vận hành kỷ luật. Một biện pháp bị bỏ sót (ví dụ bật TLS nhưng quên tắt cổng plaintext) sẽ mở toang cánh cửa mà các lớp khác vừa khép lại.

### 6.1 Thay FTP bằng SFTP hoặc FTPS

**Nguyên lý.** FTP thuần (RFC 959) truyền **mọi thứ bằng plaintext**: cả lệnh `USER`/`PASS` lẫn dữ liệu file. Bất kỳ ai chặn được gói tin (sniffing trên cùng mạng LAN, switch bị ARP-spoof) đều đọc được mật khẩu và nội dung. Hai giải pháp mã hóa:

- **FTPS (FTP over TLS)**, dạng *explicit* (dùng lệnh `AUTH TLS` nâng cấp kết nối trên cổng 21) được chuẩn hóa trong RFC 4217; dạng *implicit* (TLS ngay từ đầu phiên trên cổng 990) là tập quán di sản, **không** nằm trong RFC 4217 — nên ưu tiên explicit. Bản chất vẫn là giao thức FTP, chỉ bọc thêm lớp TLS.
- **SFTP (SSH File Transfer Protocol)**, chạy như một *subsystem* của SSH trên **cổng 22**, mã hóa toàn bộ điều khiển + dữ liệu trong đúng một kênh. Lưu ý SFTP **không** phải "FTP chạy trong SSH" — nó là giao thức hoàn toàn khác, chỉ trùng tên viết tắt gần giống.

**So sánh quyết định:**

| Tiêu chí | FTPS | SFTP |
|---|---|---|
| Bản chất | FTP + TLS (RFC 4217) | Giao thức riêng của SSH |
| Cổng firewall | 21 + **dải cổng data** (passive mode) → khó mở tường lửa | **1 cổng duy nhất 22** → firewall-friendly |
| Mã hóa credentials | Có | Có |
| Mã hóa dữ liệu | Có (sau khi `AUTH TLS`) | Có (từ đầu đến cuối) |
| Client/app cũ đã viết cho FTP | **Giữ nguyên**, chỉ bật thêm TLS | **Phải đổi** sang client SFTP (không tương thích FTP) |
| Chứng thực | Certificate TLS (cần CA/cert) | SSH key hoặc password |

**Ưu điểm.** Cả hai loại bỏ ngay rủi ro lớn nhất của FTP: rò mật khẩu và nội dung khi bị nghe lén. FTPS có lợi thế *tương thích ngược* — ứng dụng/thiết bị đã lập trình theo API FTP chỉ cần bật cờ "Require explicit FTP over TLS" mà không đổi mã. SFTP có lợi thế *vận hành*: chỉ một cổng 22, tích hợp sẵn quản lý key, không phải cấu hình dải cổng passive (vốn là cơn ác mộng với NAT/firewall của FTP/FTPS).

**Nhược điểm/chi phí.** FTP thuần đôi khi **vẫn bắt buộc** cho thiết bị cũ (máy in, máy quét, firmware camera đời cổ) chỉ nói được FTP. FTPS vẫn mang nhược điểm cổng data động của FTP → cấu hình firewall phức tạp. SFTP có **giao tiếp chi phí (handshake overhead)**: thiết lập phiên SSH nặng hơn một kết nối TCP thuần, và quan trọng hơn là **không phải FTP** — công cụ tự động hóa chỉ hiểu cú pháp FTP sẽ phải viết lại. Quản lý chứng chỉ TLS (FTPS) hoặc cặp key (SFTP) là chi phí vận hành phát sinh.

**Khi nào nên dùng.** Mặc định trong lab: **gỡ FTP plaintext, dùng SFTP** cho người dùng tương tác (một cổng, không phải mở dải passive, dùng luôn key SSH đã có). Chọn **FTPS** khi buộc phải giữ một ứng dụng/thiết bị cũ chỉ nói FTP nhưng đã hỗ trợ `AUTH TLS`. Chỉ duy trì FTP thuần khi có thiết bị không còn lựa chọn nào khác — và khi đó phải cô lập nó trong VLAN riêng, không dùng credentials tái sử dụng (xem 6.5, 6.8).

```text
# Trong lab: tắt hẳn FTP plaintext, chuyển người dùng sang SFTP (cổng 22)
sudo systemctl disable --now vsftpd        # gỡ dịch vụ FTP khỏi bề mặt tấn công
# Người dùng chỉ cần: sftp -i ~/.ssh/id_ed25519 user@mail.lab.local
```

Nguồn:
- RFC 959 (FTP): https://www.rfc-editor.org/info/rfc959
- RFC 4217 (FTPS explicit): https://www.rfc-editor.org/info/rfc4217
- OpenSSH (SFTP subsystem): https://www.openssh.com/

### 6.2 Bắt buộc TLS cho SMTP/POP3/IMAP

**Nguyên lý.** Mặc định SMTP/POP3/IMAP có thể chạy plaintext. Gia cố là **buộc mọi phiên có xác thực đều đi qua TLS**, dùng cơ chế STARTTLS (nâng cấp cổng đang mở) hoặc cổng TLS-riêng (implicit).

Cấu hình Postfix — đặt mức bảo mật TLS cho SMTP:

```ini
# /etc/postfix/main.cf
smtpd_tls_security_level = may       # cổng 25: opportunistic TLS (bật nếu peer hỗ trợ)
# Với cổng submission (587) khai báo trong master.cf:
#   smtpd_tls_security_level = encrypt   # BẮT BUỘC TLS — từ chối mọi kết nối không TLS
smtpd_tls_auth_only = yes            # chỉ cho AUTH sau khi đã bật TLS → mật khẩu không bao giờ plaintext
smtpd_tls_cert_file = /etc/ssl/certs/mail.lab.local.pem
smtpd_tls_key_file  = /etc/ssl/private/mail.lab.local.key
```

Hai giá trị quan trọng của `smtpd_tls_security_level` — lưu ý danh sách giá trị hợp lệ **chỉ gồm** `none`, `may`, `encrypt`: **`encrypt`** nghĩa là "chỉ nhận kết nối đã được TLS hóa" (dùng cho submission/MSA); `may` = opportunistic. **"mandatory" không phải một giá trị của tham số này** — "mandatory encryption" chỉ là cách tài liệu Postfix mô tả mức `encrypt`; ở Postfix rất cũ (≤ 2.2), ý "bắt buộc TLS" được đặt bằng tham số `smtpd_enforce_tls = yes` (nay đã deprecated, được thay bằng `smtpd_tls_security_level = encrypt`). Khuyến nghị hiện đại: đặt `encrypt` cho cổng mà người dùng cuối kết nối vào (587/465), và bật **DANE (TLSA)/MTA-STS** khi muốn cưỡng chế ở tầng DNS.

Cấu hình Dovecot — POP3/IMAP:

```ini
# /etc/dovecot/conf.d/10-auth.conf
disable_plaintext_auth = yes   # chặn AUTH khi kênh chưa phải TLS (mặc định đã là yes từ 2.3+)

# /etc/dovecot/conf.d/10-ssl.conf
ssl = required                 # mọi kết nối bắt buộc TLS
ssl_min_protocol = TLSv1.2     # tắt SSLv3/TLS1.0/1.1 (đã bị coi là không an toàn)
ssl_dh_params_file = /etc/dovecot/dh.pem
# Ưu tiên TLS 1.3 khi client hỗ trợ; chỉ cho bộ mã hiện đại (AEAD, forward secrecy)
# Cú pháp Dovecot: dấu "<" phía trước đường dẫn = đọc nội dung từ file
ssl_cert = </etc/ssl/certs/mail.lab.local.pem
ssl_key  = </etc/ssl/private/mail.lab.local.key
```

Thu hẹp bề mặt bằng cổng: **ngừng mở ra ngoài các cổng plaintext** 143 (IMAP) và 110 (POP3); chỉ giữ các cổng TLS 993 (IMAPS) và 995 (POP3S), cùng 587/465 cho SMTP. Trong `master.cf`/`inet.conf` hoặc bằng UFW (xem 6.8) để 143/110 chỉ binding loopback hoặc đóng hoàn toàn.

**Ưu điểm.** Chống nghe lén và **credential stealing**, chống **downgrade attack** và **MITM** trên LAN. `disable_plaintext_auth` đảm bảo mật khẩu không bao giờ đi trên mạng ở dạng đọc được. `ssl_min_protocol=TLSv1.2` loại các bộ mã đã vỡ (RC4, 3DES, SHA-1, CBC cũ).

**Nhược điểm/chi phí.** **Quản lý chứng chỉ**: cert hết hạn sẽ sập dịch vụ hoặc mở ra cảnh báo — cần theo dõi vòng đời và tự động gia hạn (Let's Encrypt dùng ACME; trong lab tự dựng CA riêng hoặc dùng cert tự ký và import vào client). **Client cũ hỏng**: thiết bị chỉ biết POP3/110 plaintext hoặc chỉ nói được TLS 1.0 sẽ không kết nối được sau khi siết — phải nâng cấp hoặc cách ly. Opportunistic TLS ở cổng 25 không chống được MITM chủ động (chỉ DANE/MTA-STS mới đảm bảo).

**Khi nào nên dùng.** Luôn luôn, cho mọi dịch vụ có xác thực. Đây là biện pháp nền tảng — nếu chỉ được chọn *một* việc để làm trước khi đưa lab vào "production giả lập", hãy chọn bật TLS và tắt cổng plaintext.

Nguồn:
- Postfix TLS README: https://www.postfix.org/TLS_README.html
- Dovecot SSL/TLS settings: https://doc.dovecot.org/
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/info/rfc8446
- Bộ mã và giao thức bị deprecated (TLS 1.0/1.1 — RFC 8996): https://www.rfc-editor.org/info/rfc8996

### 6.3 SSH key thay cho mật khẩu (SFTP/SSH)

**Nguyên lý.** Sinh một **cặp khóa (key pair)** gồm *private key* (giữ bí mật ở client) và *public key* (đặt trên server). Server xác minh client chứng minh được sở hữu private key tương ứng, không truyền mật khẩu nào qua mạng.

```bash
# Trên máy client (lab): tạo khóa ed25519 — ngắn, nhanh, an toàn
ssh-keygen -t ed25519 -C "an@lab" -f ~/.ssh/id_ed25519
# Đưa public key lên server, vào file authorized_keys của user
ssh-copy-id -i ~/.ssh/id_ed25519.pub an@mail.lab.local
```

Public key được ghi vào `~/.ssh/authorized_keys` trên server — mỗi dòng một key; chỉ key nằm ở đây mới được phép đăng nhập. Private key **không bao giờ** rời máy client.

**Passphrase và ssh-agent.** Private key thường được khóa bằng một **mật khẩu bảo vệ khóa (passphrase)**: nếu file key bị đánh cắp, kẻ tấn công vẫn phải bẻ passphrase. `ssh-agent` giữ key đã mở khóa trong bộ nhớ phiên làm việc, để người dùng nhập passphrase một lần thay vì mỗi lần kết nối.

**Vì sao chống brute-force.** Không thể đoán private key bằng dò vét cạn: key ed25519 nằm trong không gian khóa ~$2^{252}$, và ngay cả RSA-4096 cũng đòi hỏi cỡ $2^{143}$ phép tính ở bài toán phân tích số nguyên tốt nhất hiện nay (NFS) — vượt xa mọi cụm máy chủ có thật. Server có thể **tắt hẳn xác thực bằng mật khẩu**, khi đó Hydra/Medusa (công cụ dò mật khẩu — chỉ dùng trong lab được phê duyệt, không nêu cú pháp) không còn gì để dò. Đây là phòng vệ chủ động: loại bỏ chính phương thức tấn công.

```ini
# /etc/ssh/sshd_config — chỉ cho phép key, tắt password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
```

**Nhược điểm/chi phí.** **Quản lý vòng đời key**: thu hồi quyền khi người dùng rời đi đòi phải sửa `authorized_keys`; cần quy trình **key rotation**. **Key bị đánh cắp**: private key không đặt passphrase ≈ mật khẩu mạnh bị lộ — ai có file là đăng nhập được ngay; đó là lý do passphrase gần như bắt buộc. **Onboarding nặng hơn** với người không quen dòng lệnh; key bị hỏng/mất thì phải cấp lại.

**Khi nào nên dùng.** Mặc định cho mọi truy cập SSH/SFTP của quản trị viên và người dùng có thể dùng key. Giữ password (kèm fail2ban + MFA) chỉ cho các workflow tự động không hỗ trợ key hoặc thiết bị giới hạn.

Nguồn:
- OpenSSH sshd_config man page: https://man.openbsd.org/sshd_config.5
- Ubuntu Server — SSH: https://documentation.ubuntu.com/server/how-to/security/

### 6.4 Mật khẩu mạnh và xác thực đa yếu tố (MFA)

**Nguyên lý mật khẩu.** Sức chống brute-force của mật khẩu đo bằng **entropy (độ ngẫu nhiên)**, phụ thuộc **chiều dài** hơn là bộ ký tự. `Tr0ub4dour&3` (12 ký tự, độ phức tạp cao) thường **yếu hơn** `correct horse battery staple` (độ dài lớn, dễ nhớ) vì độ dài là số mũ của không gian khóa. Ba quy tắc: đủ dài (khuyến nghị ≥ 14–16 ký tự), **không tái sử dụng** giữa các dịch vụ (một datastore bị lộ → mọi nơi khác bị domino), và **không chứa thông tin cá nhân** dễ đoán. Trong Postfix/Dovecot dùng mật khẩu hệ thống, hãy đặt thuật toán băm mạnh (`doveadm pw -s BLAKE2b-512` hoặc `sha512-crypt`) thay vì băm yếu.

**Nguyên lý MFA.** "Multi-factor authentication" yêu cầu ≥ 2 trong 3 loại bằng chứng: *điều bạn biết* (mật khẩu), *điều bạn có* (điện thoại/token), *điều bạn là* (vân tay). Kẻ tấn công có mật khẩu vẫn chưa vào được nếu thiếu thiết bị.

**Thực tế MFA cho các dịch vụ này — trình bày trung thực.** Đây là điểm dễ bị "hứa hẹn quá đà" trong tài liệu, nên đồ án cần nói rõ:

- **SSH**: MFA **khả thi và phổ biến**. Cài module PAM (Google Authenticator OATH TOTP, hoặc FreeRADIUS) vào `/etc/pam.d/sshd`, đặt `ChallengeResponseAuthentication (KbdInteractiveAuthentication) yes`. **Nhược điểm**: bật 2FA trên SSH sẽ **phá vỡ workflow SFTP-only** — nhiều client SFTP/script tự động không xử lý được bước nhập OTP tương tác, khiến cron/rsync/SCP tự động hóa hỏng.
- **Dovecot (IMAP/POP3) và Postfix submission**: **MFA gốc rất hạn chế**. Dovecot **không có passdb MFA/OATH/WebAuthn xây sẵn** ở cả bản 2.3 lẫn Dovecot CE 2.4 (tính đến 8/2026 — đã đối chiếu docs chính thức: passdb chỉ có PAM, passwd-file, LDAP, SQL, dict, Lua, OAuth2, checkpassword...). Các cơ chế SASL PLAIN/LOGIN chỉ gửi **một** blob mật khẩu, nên muốn dùng OTP phải *nối password+OTP* hoặc đứng sau một OIDC IdP làm MFA rồi Dovecot xác thực token qua `oauth2` passdb (`oauthbearer`/`xoauth2`) — phức tạp và nhiều mail client không hỗ trợ. Nửa con đường thứ ba: đi qua **PAM passdb + `pam_google_authenticator`**, nhưng khi đó người dùng phải nhập chuỗi *mật khẩu + OTP* gộp chung trong một ô password duy nhất của client — đa số mail client không có bước hỏi OTP tương tác. **Không thể** đặt WebAuthn ngay trên kết nối IMAP/POP3.
- **FTP**: không có chỗ cho MFA trong giao thức plaintext; FTPS/SFTP cũng chỉ mạnh tới mức của SSH/TLS chứ không phải MFA nội tại.

**Kết luận cho lab này.** "Trong lab, **MFA chỉ khả thi một cách thực tế ở SSH**." Với FTP/IMAP/POP3, thay vì hứa hẹn MFA everywhere, hãy dựa vào **rate limit + fail2ban (6.8) + mật khẩu mạnh + bắt buộc TLS (6.2)**. Nếu buộc phải có lớp hai cho email, con đường đúng là OIDC + app password (mật khẩu riêng cho từng thiết bị), không phải OTP thô trên cổng IMAP.

**Khi nào nên dùng.** Bắt buộc mật khẩu mạnh cho mọi tài khoản còn dùng mật khẩu. Bật MFA trên SSH cho admin; cân nhắc app-password/OAuth2 cho email nếu chấp nhận độ phức tạp; **không cam kết** MFA cho các dịch vụ không hỗ trợ.

Nguồn:
- Dovecot Authentication (PAM, OAuth2, auth policy): https://doc.dovecot.org/main/core/config/auth/overview.html
- Dovecot OAuth2 passdb: https://doc.dovecot.org/main/core/config/auth/databases/oauth2.html
- NIST SP 800-63B (Digital Identity Guidelines — quy tắc mật khẩu): https://pages.nist.gov/800-63-3/sp800-63b.html

### 6.5 Tắt anonymous và các dịch vụ không cần dùng

**Nguyên lý — giảm bề mặt tấn công (attack surface reduction).** Mỗi cổng mở, mỗi tính năng "mặc định bật" là một điểm mà kẻ tấn công có thể thử. Nguyên tắc: **cái gì không dùng thì tắt/gỡ**. vsftpd **mặc định bật anonymous** (`anonymous_enable=YES`) — nếu quên tắt, ai cũng đọc (thậm chí ghi) vào `/var/ftp` mà không cần tài khoản.

```ini
# /etc/vsftpd.conf
anonymous_enable=NO        # BẮT BUỘC tắt — giá trị mặc định của vsftpd là YES!
local_enable=YES
write_enable=NO            # nếu không thật sự cần upload qua FTP
```

Audit định kỳ các socket đang lắng nghe:

```bash
ss -tlnp        # liệt kê TCP LISTEN + tiến trình sở hữu → phát hiện dịch vụ "lạ"
systemctl list-units --type=service --state=running
```

Mỗi lần audit: so sánh danh sách cổng đang mở với danh sách *dịch vụ chủ đích cung cấp*. Cổng thừa (ví dụ 3306 MySQL, 6379 Redis, 139/445 Samba) mà không có lý do kinh doanh → **gỡ gói** (`apt remove`) hoặc **dừng + disable** (`systemctl disable --now`).

**Ưu điểm.** Giảm trực tiếp số lỗ hổng có thể bị khai thác — dịch vụ đã gỡ thì không còn CVE nào áp dụng được nữa. Anonymous FTP là kênh kinh điển để host malware/phishing và để lộ dữ liệu; tắt nó loại bỏ rủi ro nghiêm trọng với chi phí bằng 0.

**Nhược điểm/chi phí.** Phải **biết rõ hệ thống chạy gì** — tắt nhầm dịch vụ đang có người dùng phụ thuộc sẽ gây cố ngừng (outage). Cần quy trình ghi nhận "dịch vụ nào được phép" trước khi audit.

**Khi nào nên dùng.** Ngay từ khi dựng lab và lặp lại mỗi lần review cấu hình. Đây là bước **rẻ nhất, hiệu quả cao nhất** trong toàn chương — nên làm đầu tiên.

Nguồn:
- vsftpd.conf(5) man page: https://linux.die.net/man/5/vsftpd.conf
- Red Hat — Securing network services: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/securing-network-services_securing-networks
- Ubuntu Server — quản lý dịch vụ: https://documentation.ubuntu.com/server/

### 6.6 Chroot cho FTP/SFTP và giới hạn thư mục

**Nguyên lý.** **Chroot** giới hạn tầm nhìn hệ thống file của người dùng trong một thư mục gốc giả — họ không "nhìn thấy" phần còn lại của đĩa. Có hai triển khai cần phân biệt:

**vsftpd (FTP/FTPS):**

```ini
chroot_local_user=YES         # nhốt mỗi user vào home của chính nó
allow_writeable_chroot=YES    # CẨN THẬN: cho phép thư mục chroot-root ghi được
                              # vsftpd mặc định TỪ CHỐI startup nếu chroot root writable
                              # → chỉ bật khi thật sự cần upload ngay ở gốc
```

Điều kiện của vsftpd: thư mục gốc chroot **không được writable** theo thiết kế bảo mật. Giải pháp đúng là **thư mục upload riêng**, không cho execute:

```text
/home/ftpuser/            (root:root, 755 — KHÔNG writable bởi user → vsftpd hài lòng)
/home/ftpuser/upload/     (ftpuser:ftpuser, 755 — user ghi được vào ĐÂY, không phải gốc)
```

**SFTP (OpenSSH):** dùng `ChrootDirectory` + `ForceCommand internal-sftp`:

```ini
# /etc/ssh/sshd_config
Match Group sftpusers
    ChrootDirectory /srv/sftp/%u   # BẮT BUỘC: sở hữu root:root, mode 755 (không group/other writable)
    ForceCommand internal-sftp     # chỉ cho chạy SFTP nội bộ, chặn shell/tunnel
    AllowTcpForwarding no
    X11Forwarding no
```

Ràng buộc then chốt (đã xác minh từ man page): *"all components of the pathname are root-owned directories which are not writable by group or others."* Nghĩa là mọi cấp trong `/srv/sftp/<user>` phải **root-sở hữu và không ghi được bởi group/other** (thường 755); nếu không sshd từ chối chroot → fallback sang shell đầy đủ, hở bảo mật. Người dùng upload vào một thư mục con *writable* bên trong, không phải chính thư mục chroot.

**Ưu điểm.** Cô lập người dùng: user A không đọc được file của user B, không chạm tới `/etc`, không lần ra binary hệ thống để khai thác. `ForceCommand internal-sftp` biến SFTP user thành "chỉ truyền file", không có shell.

**Nhược điểm/chi phí — và giới hạn quan trọng.** **Chroot không phải sandbox.** Nếu người dùng *vừa có shell* *vừa có quyền ghi* trong hệ thống file thực, vẫn tồn tại các kỹ thuật thoát chroot (đã biết trong giới bảo mật). Vì vậy mục tiêu của chroot là **hạn chế tai nạn và leo thang dễ dàng**, **không** phải "ngăn tuyệt đối một kẻ có shell đã chiếm quyền." Chính vì thế ta kết hợp: chroot **và** không cấp shell (`/usr/sbin/nologin`) **và** thư mục upload **không execute** (`mount -o noexec`).

**Khi nào nên dùng.** Luôn chroot người dùng SFTP/FTP không đáng tin. Với quản trị viên có key + đã kiểm soát, có thể không cần. Chroot là một *lớp*, không phải *hàng rào cuối*.

Nguồn:
- OpenSSH sshd_config (ChrootDirectory): https://man.openbsd.org/sshd_config.5
- vsftpd.conf(5): https://linux.die.net/man/5/vsftpd.conf

### 6.7 Đặc quyền tối thiểu (least privilege) cho file và dịch vụ

**Nguyên lý.** Mỗi tiến trình và mỗi file chỉ nên có **vừa đủ** quyền để hoàn thành nhiệm vụ, không hơn. Dịch vụ chạy bằng user đặc quyền (`root`) là thảm họa khi bị chiếm: kẻ tấn công có ngay root.

- **Dịch vụ chạy như user "gần như nobody"**: vsftpd, postfix, dovecot đều fork tiến trình worker dưới user không đặc quyền (`nobody`/`postfix`/`dovecot`), chỉ tiến trình master giữ quyền đọc key/cổng.
- **Quyền file nghiêm ngặt** cho key và passdb:

```text
600  /etc/ssh/ssh_host_ed25519_key       # private key: chỉ root đọc
600  /etc/postfix/sasl/passwd            # mật khẩu: không cho cả group đọc
600  /etc/ssl/private/mail.lab.local.key # key TLS riêng tư
400  /etc/dovecot/private/dovecot.pem    # passdb/cert tư
# KHÔNG BAO GIỜ world-writable; kiểm tra:
find /etc -xdev -perm -o+w -type f       # quét file world-writable đáng ngờ
```

- **umask** của service account đặt `077`/`027` để file tạo ra mặc định không lộ cho group/other.
- **Group theo vai trò**: tạo `sftpusers` (được chroot-only), `vftp` (user FTP ảo) thay vì cho mọi người vào nhóm có shell.

**Mandatory Access Control (MAC).** Linux DAC (quyền rwx cổ điển) có thể bị qua khi tiến trình chạy root. Lớp trên cùng là **AppArmor** (mặc định bật trên Ubuntu) hoặc **SELinux** (mặc định trên RHEL). **Đừng tưởng daemon nào cũng đã được confines**: kiểm chứng bằng `aa-status` / `aa-unconfined` và xem `/etc/apparmor.d/`. Trên Ubuntu server, bộ profile đi kèm gói `apparmor` gốc phủ nhiều binary phổ biến (công cụ container, trình duyệt desktop, một số daemon mạng) nhưng OpenSSH và vsftpd thường chạy **`unconfined`** theo mặc định — muốn có profile cho chúng phải tự tạo (`aa-genprof`, chế độ `complain` rồi `enforce`) hoặc lấy từ các bộ profile cộng đồng đóng gói qua `apparmor-profiles`. Bài học thực tế từ Debian/Ubuntu: các profile sshd mới được đưa vào từng gây hỏng dịch vụ (vd. Debian bug #1078441 — profile sshd chặn kết nối đến), nên mọi profile viết thêm đều phải kiểm chứng trong lab trước khi `enforce`. **Nhược điểm chung**: profile sai chặn tính năng hợp lệ → luôn đi đường `complain` → `enforce`.

**Ưu điểm.** Chặn **leo thang đặc quyền (privilege escalation)**: chiếm được worker không đặc quyền ≠ chiếm root. Quyền file 600 ngăn user thường đọc key TLS. MAC giới hạn blast radius.

**Nhược điểm/chi phí.** Cấu hình quyền quá chặt gây hỏng dịch vụ (không đọc được cert) → cần thử nghiệm. AppArmor/SELinux có đường học steep, dễ bị "tắt cho xong" — sai lầm phổ biến.

**Khi nào nên dùng.** Luôn. Đặt quyền file private key/passdb = 600 ngay lần đầu tạo chúng; bật AppArmor có sẵn của Ubuntu và chỉ chuyển sang SELinux khi có yêu cầu tương thích RHEL.

Nguồn:
- Red Hat — Managing confined services (SELinux FTP): https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/chap-managing_confined_services-file_transfer_protocol
- Ubuntu — AppArmor: https://documentation.ubuntu.com/server/how-to/security/apparmor.html

### 6.8 Kiểm soát mạng: UFW và fail2ban

**Nguyên lý — default deny.** Tường lửa cấu hình theo hướng **chặn tất cả, mở từng cổng theo nhu cầu** (allowlist), không phải "mở hết rồi chặn cái nguy hiểm".

```bash
sudo ufw default deny incoming     # mặc định CHẶN mọi kết nối vào
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   comment 'SSH/SFTP'
sudo ufw allow 993/tcp  comment 'IMAPS'
sudo ufw allow 995/tcp  comment 'POP3S'
sudo ufw allow 587/tcp  comment 'SMTP submission'
sudo ufw allow from 10.0.0.0/24 to any port 25 proto tcp  # whitelist IP quản trị/subnet lab
sudo ufw limit 22/tcp              # rate-limit SSH: chặn brute-force ngay ở tầng tường lửa
sudo ufw enable
```

Lưu ý: nếu mở cổng **25 ra toàn thế giới** thì ai cũng quét được — chỉ 25 cho MTA-to-MTA (xem 6.9); còn cổng quản trị (SSH) nên **whitelist theo IP/subnet lab**.

**Nguyên lý — fail2ban.** fail2ban đọc log, đếm failure theo IP nguồn, và **tự động chặn** IP vượt ngưỡng (qua iptables/nftables). Mỗi dịch vụ có một **jail**:

```ini
# /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 1h          # thời gian chặn gốc
findtime = 10m
maxretry = 5
bantime.increment = true    # bantime TĂNG DẦN cho IP tái phạm
bantime.factor    = 2
ignoreip = 127.0.0.1/8 10.0.0.0/24    # loại trừ loopback + subnet lab khỏi bị khóa

[sshd]
enabled = true
[vsftpd]
enabled = true
[postfix]
enabled = true
[dovecot]
enabled = true
```

Cần bật `backend = systemd` hoặc trỏ `logpath` đúng với log thật của Ubuntu (`/var/log/auth.log`, `/var/log/mail.log`), và **khởi động jail tương ứng có filter** trong `/etc/fail2ban/filter.d/`.

**Nguyên lý — rate limiting trong chính dịch vụ.** Ngoài tường lửa, mỗi daemon tự giới hạn để chống DoS và làm chậm brute-force:

| Dịch vụ | Tham số | Tác dụng |
|---|---|---|
| sshd | `MaxAuthTries 4` (mặc định 6) | chặn số lần thử mật khẩu mỗi kết nối |
| sshd | `MaxStartups 10:30:60` (mặc định 10:30:100) | giới hạn kết nối đồng thời chưa xác thực |
| Postfix | `smtpd_client_connection_rate_limit`, `smtpd_client_connection_count_limit` | giới hạn kết nối/giây và đồng thời/IP |
| Postfix | `anvil_status_update_time` | anvil là daemon đếm tỉ lệ kết nối/nhận thư |
| vsftpd | `max_clients`, `max_per_ip` | tổng client và client mỗi IP |
| vsftpd | `local_max_rate`, `idle_session_timeout` | giới hạn băng thông + timeout phiên rảnh |
| Dovecot | `login_trusted_networks` | phân biệt mạng tin cậy để áp rate limit |

**Ưu điểm.** Chặn quét cổng và brute-force trước khi chúng chạm vào xác thực; giảm tải CPU cho dịch vụ; giới hạn thiệt hại DoS. `bantime.increment` khiến kẻ tấn công tái phạm bị khóa ngày càng lâu.

**Nhược điểm/chi phí.** **Khóa nhầm (false positive)** — quên `ignoreip` subnet lab thì chính nhóm tự khóa mình khỏi SSH. fail2ban phụ thuộc định dạng log đúng; đổi version có thể hỏng filter. Whitelist tĩnh không giúp gì nếu IP admin thay đổi (DSL). Rate limit quá chặt gây khó cho người dùng bình thường phía sau NAT công cộng.

**Khi nào nên dùng.** Luôn bật `default deny incoming` + fail2ban trên mọi cổng SSH/mail. Trong lab nhớ `ignoreip` dải nội bộ và máy test để không tự khóa.

Nguồn:
- fail2ban README (jails, bantime.increment): https://github.com/fail2ban/fail2ban
- OpenSSH sshd_config (MaxAuthTries/MaxStartups): https://man.openbsd.org/sshd_config.5
- Postfix postconf(5): https://www.postfix.org/postconf.5.html
- vsftpd.conf(5): https://linux.die.net/man/5/vsftpd.conf

### 6.9 Không trở thành open relay (Postfix)

**Nguyên lý.** **Open relay** là MTA cho phép ai cũng gửi thư **đến tên miền khác** — biến server thành bàn phát spam, dẫn đến bị blackhole (Spamhaus) và reputations sập. Chốt chặn là `smtpd_relay_restrictions` quyết định *ai được relay tới đâu*:

```ini
# /etc/postfix/main.cf
mynetworks = 127.0.0.0/8 [::1]/128 10.0.0.0/24   # chỉ loopback + subnet lab (liệt kê tĩnh dạng CIDR, phân tách bằng khoảng trắng)
smtpd_relay_restrictions =
    permit_mynetworks,             # cho relay từ dải tin cậy
    permit_sasl_authenticated,     # cho relay sau khi người dùng xác thực (submission)
    reject_unauth_destination      # CHẶN mọi relay khác — dòng "chốt" chống open relay
```

Thứ tự quan trọng: `reject_unauth_destination` **phải có mặt**; nếu chỉ dựa vào `mynetworks = 0.0.0.0/0` (sai lầm kinh điển) thì ai cũng relay được.

**Tự kiểm thử trong lab** (mạng riêng do nhóm sở hữu — không dùng dịch vụ quét công cộng, không gửi spam). Từ máy client lab, dùng `telnet`/`nc` tới cổng 25 rồi thử relay tới một địa chỉ **bên ngoài không thuộc quyền sở hữu** và xác nhận server **từ chối**:

```text
mail> nc mail.lab.local 25
220 mail.lab.local ESMTP Postfix
EHLO tester.lab.local
250-mail.lab.local
RCPT TO:<someone@example.org>          <- thử relay ra ngoài, chưa auth
554 5.7.1 <someone@example.org>: Relay access denied   <- ĐÚNG: bị chặn
QUIT
```

Kết quả kỳ vọng: khi chưa `AUTH` và không từ `mynetworks`, mọi `RCPT TO:` đi tới miền khác bị **`554 Relay access denied`**. Nếu server trả `250 OK` ở bước này → **bạn đã mở relay** → sửa `smtpd_relay_restrictions`/`mynetworks` rồi reload (`postfix reload`) và test lại.

**Ưu điểm.** Giữ reputation IP/domain, tránh bị liệt blacklist, tránh bị lợi dụng phát tán spam (rủi ro pháp lý).

**Nhược điểm/chi phí.** Siết relay có thể chặn nhầm thiết bị (máy scan, máy in gửi mail thông báo) nằm ngoài `mynetworks` — giải pháp đúng là cho chúng xác thực qua submission, **không** phải nới `mynetworks`.

**Khi nào nên dùng.** Bắt buộc trước khi máy chủ từng được kết nối với mạng ngoài. Ngay cả lab "kín" cũng nên test vì sinh viên thường vô tình cấu hình `mynetworks = 0.0.0.0/0`.

Nguồn:
- Postfix — SMTP relay and access control (relaying restrictions): https://www.postfix.org/SMTPD_ACCESS_README.html
- Postfix postconf(5) — smtpd_relay_restrictions: https://www.postfix.org/postconf.5.html

### 6.10 SMTP AUTH và submission bắt buộc (cổng 587)

**Nguyên lý.** Tách hai vai trò trên hai cổng:

- **Cổng 25** dành cho **MTA-to-MTA** (thư đến từ các server khác). Không bắt buộc auth ở đây (server ngoài không có tài khoản của bạn).
- **Cổng 587 (submission)** dành cho **người dùng cuối** (MUA → MSA), **bắt buộc SMTP AUTH + TLS** (đặt `smtpd_tls_security_level=encrypt`, `smtpd_sasl_auth_enable=yes` trong `master.cf`).

```ini
# /etc/postfix/master.cf — entry submission
submission inet n - y - - smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
```

Sau khi xác thực, Postfix **gán thư vào đúng user** → phân quyền và giới hạn theo từng người (ai gửi bao nhiêu, gửi đi đâu), dễ revocation khi một tài khoản bị lộ.

**Ưu điểm.** Chống giả mạo người gửi trong nội bộ (phải login), cho phép **throttling/phân quyền theo user**, và cổng 587 cho client dễ phân biệt với 25. Kết hợp SASL qua Dovecot (`smtpd_sasl_type=dovecot`) dùng chung một nguồn credentials cho gửi và nhận.

**Nhược điểm/chi phí.** Bắt buộc client cấu hình đúng (server gửi khác server nhận, khác cổng, khác TLS) — người dùng mới hay sai. Cần **password/app-password** cho mỗi thiết bị. Nếu để mở 25 cho client và không bắt auth, vẫn lộ đường vòng.

**Khi nào nên dùng.** Luôn dùng 587 cho người dùng cuối; giữ 25 chỉ để nhận thư từ thế giới. Trong lab, cấu hình Thunderbird trỏ **outgoing = 587 + STARTTLS/TLS + username/password**.

Nguồn:
- Postfix submission/RELAY: https://www.postfix.org/postconf.5.html
- Dovecot SASL cho Postfix: https://doc.dovecot.org/

### 6.11 SPF, DKIM, DMARC (bộ ba xác thực email)

Ba cơ chế này **giải quyết ba vấn đề khác nhau và bổ trợ nhau**. Điểm mấu chốt dễ nhầm: chúng chống **giả mạo tên miền gửi**, không chống mọi hình thức lừa đảo.

**SPF — RFC 7208 (Sender Policy Framework).** Một DNS TXT record khai báo **những IP nào được phép gửi thư** cho tên miền. Server nhận **kiểm tra trên envelope MAIL FROM** (return-path / địa chỉ bounce), *không* phải header "From:" hiển thị.

```dns
lab.local.  IN  TXT  "v=spf1 ip4:10.0.0.10 -all"
# v=spf1: phiên bản; ip4:...: IP được phép; -all: mọi nguồn khác = hard fail
```

- **Giới hạn SPF**: không chống được việc giả **header "From:"** hiển thị (kẻ lừa đảo dùng SPF pass cho tên miền *khác* rồi đặt From: hiển thị thành miền bạn — "header spoofing"). **Forwarding làm hỏng SPF** (thư relay qua server bên thứ ba → IP không còn khớp → thường chỉ nên đặt `~all` = *soft fail* khi chưa kiểm soát được forwarder). Giới hạn **10 lần tra cứu DNS** mỗi record (RFC 7208 §4.6.4) — vượt quá trả `permerror`; các `include:` lồng nhau dễ chạm trần.

**DKIM — RFC 6376 (DomainKeys Identified Mail).** MTA **ký số** vào một tập header + body bằng private key; public key đặt trong DNS tại `<selector>._domainkey.<domain>`. Server nhận verify chữ ký → chứng minh (1) nội dung **không bị sửa** giữa đường, (2) thư được gửi bởi bên **sở hữu private key** của tên miền.

```dns
default._domainkey.lab.local.  IN  TXT
  "v=DKIM1; k=rsa; p=MIGfMA0GCSqG... (public key)"
```

- **Giới hạn DKIM**: chữ ký gắn vào một **selector** và **phải xoay vòng key** (rotation); khi đổi key phải cập nhật DNS. Forwarding sửa body (thêm footer) làm **mất hiệu lực chữ ký**. DKIM tự nó không nói *domain đó có đáng tin không* — chỉ nói đúng là do domain ký.

**DMARC — RFC 7489 (Domain-based Message Authentication, Reporting and Conformance).** Lưu ý cập nhật: tháng 5/2026, RFC 7489 đã được bộ ba **RFC 9989** (DMARC core), **RFC 9990** (aggregate reporting) và **RFC 9991** (failure reporting) thay thế — nội dung cốt lõi không đổi, chỉ tách tài liệu và sửa lỗi (errata); trong lab vẫn quen gọi "DMARC RFC 7489". Đặt ở `_dmarc.lab.local` TXT, khai **chính sách xử lý** khi SPF/DKIM fail và **yêu cầu alignment**:

```dns
_dmarc.lab.local.  IN  TXT
  "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc-reports@lab.local; pct=100; adkim=s; asf=s"
# p= : none → quarantine → reject (mức cưỡng chế tăng dần theo thời gian)
# rua: nhận báo cáo aggregate; ruf: báo cáo forensic
# adkim=s / asf=s : yêu cầu STRICT alignment cho DKIM/SPF
```

- **Alignment** là trái tim của DMARC: yêu cầu **header "From:" khớp miền** với miền đã vượt qua SPF *hoặc* DKIM (organizational domain). Nhờ đó nó vá đúng chỗ hổng "SPF/DKIM pass nhưng From: là miền giả" mà hai cơ chế trước bỏ lọt.
- **Reporting**: `rua` gửi báo cáo XML định kỳ (ai đang gửi dưới tên miền, tỉ lệ pass/fail) → cho phép chuyển từ `p=none` (chỉ quan sát) lên `p=reject` một cách an toàn.

**Bộ ba hỗ trợ nhau (đây là ý chính cần nhấn mạnh).**

| Cơ chế | Chống | Bằng chứng cung cấp |
|---|---|---|
| SPF | Giả mạo **envelope MAIL FROM** | "IP này được miền ủy quyền gửi" |
| DKIM | **Sửa nội dung** trên đường + **chứng minh quyền sở hữu** miền (proof-of-dominance) qua private key | "Thư do miền ký, không bị biến đổi" |
| DMARC | **Liên kết** SPF + DKIM với header From: (alignment), đặt **chính sách** và **báo cáo** | "Không đạt thì xử lý thế nào + cho ai biết" |

Không có DMARC, SPF/DKIM pass trên một miền *không liên quan* vẫn không bảo vệ được tên miền thương hiệu của bạn; DMARC chính là thứ "khâu" ba mảnh lại và cho bạn kênh giám sát.

**Giới hạn chung (nói thẳng).** Bộ ba **không** chống được phishing dùng **display name** ("Ngân Hàng ABC <attacker@xyz.com>"), **look-alike domain** (`lab-1ocal.local` thay `lab.local`), và **không thay thế sự cảnh giác của người dùng** — nó chỉ làm kẻ tấn công *khó giả mạo chính tên miền của bạn*, không chặn mọi email xấu.

**BIMI — nâng cao.** Brand Indicators for Message Identification cho phép hiển thị **logo thương hiệu** trong client của người nhận, nhưng chỉ khi DMARC đạt mức `p=quarantine`/`p=reject` (và thường cần **Verified Mark Certificate**). Trạng thái chuẩn cần nói chính xác: tính đến 8/2026, BIMI **vẫn là Internet-Draft** (`draft-brand-indicators-for-message-identification`, chưa phải RFC chuẩn hóa). *Lưu ý tránh nhầm*: số "RFC 9627" đôi khi bị gán sai cho BIMI — RFC 9627 thực chất là một tài liệu RTCP/AVT không liên quan; **không** dẫn RFC 9627 cho BIMI.

Nguồn:
- RFC 7208 (SPF): https://www.rfc-editor.org/info/rfc7208
- RFC 6376 (DKIM): https://www.rfc-editor.org/info/rfc6376
- RFC 7489 (DMARC — đã được thay thế từ 5/2026): https://www.rfc-editor.org/info/rfc7489
- RFC 9989 / 9990 / 9991 (DMARC bản thay thế, 2026): https://www.rfc-editor.org/info/rfc9989
- BIMI Internet-Draft (không phải RFC): https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/

### 6.12 Vận hành: cập nhật, backup, log và phản ứng sự cố

**Nguyên lý — vá lỗi tự động và kế hoạch EOL.** Lỗ hổng trong vsftpd/openssh/postfix/dovecot được công bố liên tục; máy không cập nhật = cửa mở. Bật `unattended-upgrades` cho security updates:

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
# /etc/apt/apt.conf.d/50unattended-upgrades: chỉ auto-upgrade từ origin "UbuntuESM"/security
```

Kèm **kế hoạch EOL**: Ubuntu 24.04 LTS và bản mới nhất 26.04 LTS (23/4/2026, hỗ trợ tiêu chuẩn đến ~4/2031). Lên lịch **nâng phiên bản LTS** trước khi bản đang chạy hết hạn, và đăng ký **ESM/Pro** cho các gói còn CVE sau 5 năm. Ghi rõ trong runbook: dịch vụ nào đang chạy trên bản sắp hết hạn.

**Nguyên lý — backup cấu hình.** Một kho **git nội bộ** chứa cấu hình đã **ẩn secret**:

```bash
sudo git init /etc/ops-config && cd /etc/ops-config
git add main.cf master.cf dovecot/ sshd_config fail2ban/ vsftpd.conf
echo "/etc/ssl/private" > .git/info/exclude   # KHÔNG commit private key / mật khẩu
git commit -m "baseline hardening"
```

Lưu ý **không bao giờ** commit private key, mật khẩu passdb, hay cert tư vào repo; chỉ lưu cấu hình. Kèm **offline copy** để chống ransomware mã hóa cả backup.

**Nguyên lý — log và retention.** Gia cố chỉ có nghĩa nếu phát hiện được vi phạm. Cấu hình **log rotation + retention** (rsyslog/`logrotate`, journald `SystemMaxUse=`), gom log về một máy log **tách rời** (để kẻ xâm nhập không xóa dấu vết trên chính máy bị hại). Các **từ khóa log thật** cần soi hằng tuần:

```text
/var/log/auth.log:  "Failed password for", "Invalid user", "authentication failure"
/var/log/mail.log:  "SASL LOGIN authentication failed", "Relay access denied", "Disconnected: Too many authentication failures"
fail2ban:           "Ban 203.0.113.9" / "Unban 203.0.113.9"   (TEST-NET, dải minh họa RFC 5737)
```

**Incident response plan 6 bước — chu trình vòng đời (lifecycle) kinh điển của NIST SP 800-61 (Rev. 3 ban hành 4/2025, thay Rev. 2 năm 2012; Rev. 3 ánh xạ theo CSF 2.0 và gộp thành 4 giai đoạn: Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity; 6 bước dưới đây là cách trải các giai đoạn đó ra cho dễ tick trong lab):**

1. **Chuẩn bị (Preparation):** đã có backup, log, tài liệu này, người phụ trách.
2. **Phát hiện & phân tích (Detection & Analysis):** thấy log bất thường/quy trình fail2ban khóa IP lạ, đánh giá mức độ.
3. **Cô lập (Containment):** cô lập — chặn IP bằng UFW, đổi credential nghi lộ, tạm dừng dịch vụ bị lợi dụng (không rút điện, giữ hiện trường).
4. **Diệt trừ (Eradication):** tìm và xóa root cause — patched package, gỡ backdoor/malware, siết lại cấu hình hở.
5. **Phục hồi (Recovery):** khôi phục dịch vụ từ bản sạch, theo dõi log sau khi mở lại.
6. **Bài học (Lessons Learned):** cập nhật tài liệu/checklist, điều chỉnh chính sách để không lặp lại.

**Hardening checklist trước khi chạy production.** In ra, tick từng mục:

- [ ] FTP plaintext đã tắt (6.1); chỉ còn SFTP/FTPS.
- [ ] TLS bắt buộc cho 587/465/993/995; đã **đóng 143/110** ra ngoài (6.2).
- [ ] Chứng chỉ TLS còn hạn + quy trình gia hạn (6.2).
- [ ] `PasswordAuthentication no` cho SSH; đăng nhập bằng key + passphrase (6.3).
- [ ] Mật khẩu hệ thống đủ entropy, không reuse; MFA ở SSH nếu dùng (6.4).
- [ ] `anonymous_enable=NO`; gỡ/dừng mọi dịch vụ không cần (6.5).
- [ ] SFTP user bị chroot (`ChrootDirectory` root:root 755 + `ForceCommand internal-sftp`); thư mục upload `noexec` (6.6).
- [ ] Private key/passdb = 600; không có file world-writable; AppArmor enforce (6.7).
- [ ] `ufw default deny incoming`; jail fail2ban bật cho sshd/vsftpd/postfix/dovecot; `ignoreip` lab (6.8).
- [ ] `smtpd_relay_restrictions` có `reject_unauth_destination`; **test relay nội bộ = 554** (6.9).
- [ ] Client dùng 587 + AUTH + TLS (6.10).
- [ ] SPF/DKIM/DMARC công bố; DMARC ít nhất `p=none` + `rua` trước khi lên `p=reject` (6.11).
- [ ] `unattended-upgrades` bật + kế hoạch EOL; backup config offline; log retention + central log; IR plan & người phụ trách đã ghi (6.12).

Nguồn:
- NIST SP 800-61 Rev. 3 (Incident Response Recommendations): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- Ubuntu — Automatic updates: https://documentation.ubuntu.com/server/how-to/software/process-updates.html
- Ubuntu release cycle (LTS/ESM): https://ubuntu.com/about/release-cycle
- Ubuntu Server docs (mail/ssh/security): https://documentation.ubuntu.com/server/

---

**Tóm lại chương 6.** Phòng ngừa hiệu quả cho bộ dịch vụ FTP/SFTP/SMTP/POP3/IMAP là một chuỗi hành động *có trật tự*: trước tiên **loại bỏ plaintext** (SFTP/FTPS + TLS bắt buộc), **thay mật khẩu bằng key và siết xác thực**, **thu nhỏ bề mặt tấn công** (tắt anonymous, chroot, least privilege, default-deny + fail2ban), **không để lộ dịch vụ** (không open relay, submission bắt buộc), **bảo vệ danh tính tên miền** (SPF/DKIM/DMARC), và cuối cùng **vận hành kỷ luật** (vá lỗi, backup, log, kế hoạch ứng phó sự cố). Biện pháp nào cũng có chi phí và giới hạn — hiểu *vì sao dễ bị bypass* (chroot không phải sandbox, SPF không chặn header From, MFA không khả thi trên IMAP) mới chọn đúng lớp phòng thủ phù hợp cho lab của đồ án.
