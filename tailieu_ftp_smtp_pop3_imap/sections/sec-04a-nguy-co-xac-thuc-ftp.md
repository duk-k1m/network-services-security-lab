## 4a. Nguy cơ và lỗ hổng: nhóm xác thực, FTP và quyền file

> **Phạm vi và mục đích sử dụng:** Chương này chỉ phân tích nguy cơ và biện pháp phòng thủ trong **môi trường lab mạng riêng do nhóm sở hữu** (các máy ảo Ubuntu, mạng ảo của hypervisor). Mọi kỹ thuật được mô tả nhằm mục đích giáo dục — hiểu để cấu hình đúng và để đọc log phát hiện sự cố — không phải hướng dẫn tấn công hệ thống thật. Công cụ tấn công (hydra, medusa, ettercap...) chỉ được nhắc ở mức "tồn tại và chỉ dùng trong lab được phê duyệt", không kèm cú pháp chi tiết.

Nhóm nguy cơ phủ định ở chương này xoay quanh ba nhóm vấn đề: (i) **bí mật xác thực bị lộ hoặc bị đoán** (nghe lén plaintext, brute-force, credential stuffing, mật khẩu yếu, tài khoản mặc định/anonymous), (ii) **cấu hình FTP sai** (anonymous, không chroot), và (iii) **quyền file/tài khoản hệ thống sai** (777, symlink, `authorized_keys`, cấu hình SSH/SFTP). Đây là lớp "lỗ hổng người dùng và cấu hình" — thống kê thường xuyên nhất trong các sự cố thực tế, và cũng là lớp dễ phòng ngừa nhất bằng cấu hình đúng ngay từ đầu.

Mỗi nguy cơ được trình bày theo đúng năm mục: **1) Nguyên nhân → 2) Điều kiện xảy ra → 3) Dấu hiệu trong log (kèm log mẫu) → 4) Mức độ ảnh hưởng (C/I/A) → 5) Cách phòng ngừa.**

---

### 4a.1. Nghe lén tài khoản/mật khẩu trên giao thức plaintext

#### (1) Nguyên nhân

Bản chất của vấn đề: FTP, POP3, IMAP và SMTP AUTH khi chạy **không có TLS** truyền toàn bộ phiên — bao gồm cả dòng `USER`/`PASS`, `LOGIN` — dưới dạng **văn bản thuần (cleartext)** trên kênh TCP. Kẻ tấn công chỉ cần "nhìn thấy" được gói tin là đọc được mật khẩu, không cần phá khóa nào cả.

- FTP (RFC 959, TCP port 21) được thiết kế năm 1985, khi giả định mạng nội bộ tin cậy lẫn nhau còn phổ biến; lệnh `PASS` gửi nguyên văn.
- POP3 (RFC 1939, port 110) dùng cặp lệnh `USER`/`PASS` nguyên văn.
- IMAP4 (RFC 9051 — phiên bản IMAP4rev2, thay thế RFC 3501; port 143) dùng lệnh `LOGIN user pass`.
- SMTP AUTH (mở rộng theo RFC 4954, thường ở port 587 submission hoặc 25): cơ chế `AUTH PLAIN` (RFC 4616) chỉ là chuỗi `authzid\0user\0password` (thường để trống `authzid`) rồi **base64**; `AUTH LOGIN` cũng vậy.

**Vì sao base64 không phải mã hóa (encryption):** base64 (RFC 4648) chỉ là phép **biến đổi ký tự (encoding)** để đóng gói byte vào kênh chỉ cho phép ASCII — nó là một hàm song ánh cố định, **không có khóa**, không che giấu thông tin. Ai cũng có thể giải mã bằng một phép tra bảng đảo ngược trong mili-giây. Vì vậy trong Wireshark, filter `ftp` hiển thị thẳng mật khẩu bên cạnh lệnh `USER`/`PASS`; còn với các chuỗi đã base64 hóa (SMTP `AUTH PLAIN`, IMAP `AUTHENTICATE`), chỉ cần một phép đảo bảng mã là mật khẩu hiện nguyên hình — "trông giống mật mã" nhưng không phải mật mã.

#### (2) Điều kiện xảy ra

Không phải ai cũng nghe lén được — kẻ tấn công **phải có vị trí trung gian (Man-in-the-Middle, MitM)** trên đường đi của gói tin. Trong LAN chuyển mạch hiện đại, switch chỉ gửi khung Ethernet đến đúng cổng của đích, nên muốn "nghe" người khác, attacker thường phải:

- **ARP spoofing** (lợi dụng giao thức ARP, RFC 826, không có cơ chế xác thực): gửi giả mạo nói "IP của gateway/trạm đích là địa chỉ MAC của tôi" để nhận lưu lượng của hai bên — công cụ loại này tồn tại và chỉ nên thử trong lab cô lập.
- Đặt cổng switch ở chế độ **port mirroring/SPAN** (cấu hình sai trên switch quản trị được), hoặc
- Chạy máy attacker trên **cùng hub / cùng mạng không dây / cùng đoạn ảo hóa** với nạn nhân.
- Nạn nhân dùng đúng các phiên bản plaintext: FTP port 21 không TLS, POP3 port 110, IMAP port 143 chưa STARTTLS, SMTP `AUTH PLAIN/LOGIN` không bọc TLS.

Ngược lại, nếu hai bên đã dùng TLS thật sự (FTPS, POP3S 995, IMAPS 993, submission 465/587-TLS), dữ liệu trên đường truyền được mã hóa — đó là lý do các tài liệu chuẩn hóa như RFC 8314 ("Cleartext Considered Obsolete") khuyến nghị bắt buộc TLS cho mọi giao thức email.

#### (3) Dấu hiệu trong log — điểm mấu chốt: LOG CỦA NẠN NHÂN KHÔNG CÓ GÌ CẢ

Đây là lý do **phát hiện sớm bằng log phía server là cực kỳ khó** với nguy cơ này:

- Máy chủ FTP/POP3/IMAP/SMTP **không thể phân biệt** một phiên đăng nhập thành công "bình thường" với một phiên mà mật khẩu bị kẻ trung gian đọc trộm — với nó đó chỉ là kết nối TCP hợp lệ và lệnh xác thực đúng. Trong `/var/log/vsftpd.log` hay `auth.log`, mọi thứ vẫn "xanh":

```
# Log "bình thường" của nạn nhân — KHÔNG có bất kỳ dấu hiệu bất thường nào:
Mon Aug 24 21:03:11 2026 [pid 22107] [kimdp] OK LOGIN: Client "10.0.2.15"
```

- Mật khẩu đã qua TLS thì server log cũng không chứa mật khẩu; mật khẩu plaintext thì log càng không "báo" rằng có người thứ ba đang nghe.
- **Dấu hiệu gián tiếp duy nhất** nằm ở phía **mạng**: bảng ARP của các máy thay đổi bất thường (IP của gateway trỏ tới một MAC lạ xuất hiện lặp lại), hoặc lưu lượng của một host bị định tuyến qua một máy không phải gateway. Đây là thứ phải giám sát bằng công cụ chống ARP spoofing (ví dụ `arpwatch`, động thái ARP bất thường trong log switch) — không phải bằng log dịch vụ.

Vì vậy với lớp tấn công "vị trí MitM", phòng ngừa hoàn toàn đi trước phát hiện: không thiết kế hệ thống dựa vào việc "phát hiện nghe lén", mà loại bỏ plaintext khỏi đường truyền.

#### (4) Mức độ ảnh hưởng

| Tiêu chí | Đánh giá | Lý do |
|---|---|---|
| Confidentiality (C) | **Cao** | Tài khoản + mật khẩu bị lộ trực tiếp; với POP3/IMAP lộ cả nội dung mail đang truyền. |
| Integrity (I) | Trung bình–Cao | Attacker dùng credential hợp lệ để đăng nhập rồi sửa/xóa/đổi mật khẩu — hệ thống coi đó là người dùng thật. |
| Availability (A) | Thấp | Hiếm khi gây gián đoạn dịch vụ ngay, trừ khi attacker phá dữ liệu sau khi đăng nhập. |

#### (5) Cách phòng ngừa

1. **Tắt hẳn giao thức plaintext, bật phiên bản mã hóa:** FTPS (TLS) hoặc tốt hơn là **SFTP/SCP** thay FTP port 21; POP3S 995 thay 110, IMAPS 993 thay 143, SMTP submission 587 **bắt buộc STARTTLS** (hoặc 465 implicit TLS).
   ```
   # vsftpd: ép phiên nào cũng phải TLS (tham số trong /etc/vsftpd.conf)
   ssl_enable=YES             # bật FTPS
   allow_anon_ssl=NO          # anonymous không được dùng SSL (chặn hẳn về sau)
   force_local_data_ssl=YES   # dữ liệu bắt buộc qua TLS
   force_local_logins_ssl=YES # đăng nhập bắt buộc qua TLS
   ```
   ```
   # Dovecot (10-ssl.conf + 10-auth.conf): từ chối login khi chưa có TLS
   ssl = required                      # không cho phép AUTH khi chưa bật TLS
   auth_verbose = yes                  # ghi chi tiết cơ chế xác thực vào log
   ```
2. Trong lab khi cần test FTP để hiểu giao thức, **chỉ dùng tài khoản "mồi"**, đặt ở VLAN/mạng ảo tách khỏi máy chủ dữ liệu; sau bài học thì chuyển sang SFTP.
3. Triển khai chứng chỉ TLS (kể cả self-signed trong lab) và cấu hình client từ chối kết nối không TLS.
4. Giám sát ARP/mạng bằng `arpwatch` hoặc tính năng Dynamic ARP Inspection trên switch quản trị được; theo dõi động thái kết nối bất thường giữa hai máy nội bộ không có lý do truyền file.

**Nguồn:**
- FTP — RFC 959: https://www.rfc-editor.org/rfc/rfc959
- POP3 — RFC 1939: https://www.rfc-editor.org/rfc/rfc1939
- IMAP4rev2 — RFC 9051: https://www.rfc-editor.org/rfc/rfc9051
- SMTP AUTH — RFC 4954; AUTH PLAIN — RFC 4616; Base64 — RFC 4648: https://www.rfc-editor.org/rfc/rfc4954, https://www.rfc-editor.org/rfc/rfc4616, https://www.rfc-editor.org/rfc/rfc4648
- Khuyến nghị bỏ cleartext (RFC 8314): https://www.rfc-editor.org/rfc/rfc8314
- Wireshark hiển thị phiên FTP plaintext: https://wiki.wireshark.org/FTP

---

### 4a.2. Brute-force dò mật khẩu và credential stuffing

#### (1) Nguyên nhân

Hai kiểu tấn công "đoán mật khẩu" khác nhau về bản chất:

- **Brute-force / password spraying:** một tài khoản × nhiều mật khẩu ứng viên (theo dictionary từ yếu tới mạnh) hoặc nhiều tài khoản × một mật khẩu phổ biến. attacker được tiếp cận trực tiếp cổng đăng nhập lặp vô hạn vì **giao thức không giới hạn số lần thử**.
- **Credential stuffing:** **dùng sẵn danh hiệu credential rò rỉ** (từ các vụ lộ dữ liệu ở dịch vụ khác, bán/truyền trên mạng) để thử nguyên cặp user:pass vào nhiều dịch vụ. Vì sao hiệu quả: **người dùng tái sử dụng mật khẩu (password reuse)** — xác suất một email đăng ký ở dịch vụ A cũng dùng đúng mật khẩu đó ở dịch vụ B là đáng kể. Credential stuffing **không "đoán" gì cả**, nên mỗi lần thử đều là mật khẩu "hợp lý" theo quan điểm con người.

Trong lab đồ án: các dịch vụ mail/FTP mở port 21/110/143/587 là bề mặt lý tưởng cho cả hai, đặc biệt vì nhiều cấu hình mặc định không giới hạn số lần thất bại.

#### (2) Điều kiện xảy ra

- Dịch vụ đăng nhập bằng mật khẩu, mở từ mạng (hoặc từ cả LAN trong lab) và **không có rate-limit/lockout có kiểm soát**.
- attacker có mạng lưới botnet/IP phân tán (thực tế) hoặc nhiều máy trong lab (mô phỏng).
- Với credential stuffing: tồn tại "combo list" từ các vụ lộ dữ liệu — người dùng reuse password.
- Mật khẩu nằm trong dictionary (làm brute-force nhanh ăn) — xem 4a.3.

**Dịch vụ nào dễ bị nhất?** Theo thứ tự: **SSH (2222/22) và IMAP/FTP plaintext login** — vì xác thực nhiều lần trên cùng một kết nối TCP (IMAP LOGIN gửi lại nhiều lần rất rẻ; brute-force FTP mỗi lần thử thường phải mở kết nối điều khiển mới, chậm hơn một chút nhưng vẫn dễ tự động hóa). POP3 tương tự FTP. SMTP AUTH (587) cũng bị nhắm vì attacker muốn chiếm hộp thư để gửi spam.

#### (3) Dấu hiệu trong log — so sánh mẫu log hai loại

**Brute-force** — signature: **cùng một IP, cùng một user (hoặc ít user), rất nhiều lần `Failed`, chuỗi mật khẩu khác nhau liên tiếp**, cường độ cao trong thời gian ngắn:

```
# /var/log/auth.log — brute-force SSH (nhiều mật khẩu khác nhau, cùng tài khoản)
Aug 24 22:01:03 lab-srv sshd[3011]: Failed password for invalid user oracle from 10.0.2.99 port 51122 ssh2
Aug 24 22:01:04 lab-srv sshd[3012]: Failed password for invalid user oracle from 10.0.2.99 port 51123 ssh2
Aug 24 22:01:05 lab-srv sshd[3013]: Failed password for kimdp from 10.0.2.99 port 51124 ssh2
...  (hàng trăm dòng liên tiếp trong vài phút, cùng IP nguồn)
```

```
# vsftpd (/var/log/vsftpd.log) — brute-force nhiều mật khẩu trên cùng tài khoản
Mon Aug 24 22:04:11 2026 [pid 22340] FAIL LOGIN: Client "10.0.2.99"
Mon Aug 24 22:04:12 2026 [pid 22341] FAIL LOGIN: Client "10.0.2.99"
Mon Aug 24 22:04:13 2026 [pid 22342] FAIL LOGIN: Client "10.0.2.99"
```

```
# Dovecot — auth failed (mẫu giống nhau cho POP3/IMAP)
Aug 24 22:05:02 lab-srv dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<admin>, method=PLAIN, rip=10.0.2.99, lip=10.0.2.5
```

**Credential stuffing** — signature: **rất NHIỀU TÀI KHẢN khác nhau, mỗi tài khoản chỉ 1–2 lần thử, mật khẩu "trông có vẻ hợp lệ"** (không phải `password123` mà là chuỗi đủ dài theo chính sách cũ), IP phân tán hoặc một vài proxy đánh chậm (low-and-slow) để lẫn vào nền. Tỷ lệ `Failed` : `Accepted` cân bằng hơn nhiều, và quan trọng là **có một vài `Accepted` thật** vì có user reuse mật khẩu:

```
# Dovecot — một IP, nhiều user khác nhau, mỗi user 1 lần (mẫu stuffing)
Aug 24 23:10:01 dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<lankt@lab.local>, rip=10.0.3.77
Aug 24 23:10:03 dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<hongnv@lab.local>, rip=10.0.3.77
Aug 24 23:10:05 dovecot: pop3-login: Login: user=<minhtq@lab.local>, method=PLAIN, rip=10.0.3.77   <-- 1 lần THÀNH CÔNG hiếm hoi giữa hàng loạt thất bại
```

Mẹo phân biệt trong lab: brute-force thì **group by user → count lớn**; stuffing thì **group by IP → count lớn nhưng distinct users ≈ count attempts**.

#### (4) Mức độ ảnh hưởng

| Tiêu chí | Đánh giá | Lý do |
|---|---|---|
| Confidentiality (C) | **Cao** | Đăng nhập thành công → đọc toàn bộ mail (POP3/IMAP) hoặc file (FTP). |
| Integrity (I) | Cao | Đổi mật khẩu, xóa mail, gửi mail giả danh, upload file độc hại. |
| Availability (A) | Trung bình | Chính các đợt dò lớn có thể làm nghẽn dịch vụ/auth backend; lockout sai còn tự gây DoS (xem mục 5). |

#### (5) Cách phòng ngừa

1. **Chọn rate-limit thay vì lockout "cứng" theo tài khoản.** Khóa tài khoản sau 5 lần sai là dao hai lưỡi: attacker chỉ cần biết tên đăng nhập là có thể **cố tình gõ sai để khóa tài khoản nạn nhân** — tấn công từ chối dịch vụ (DoS) nhắm vào người dùng hợp lệ. Chính sách hiện đại (NIST SP 800-63B về định danh số) khuyến nghị **giới hạn tốc độ theo địa chỉ IP nguồn + throttle lũy tiến** (chậm dần theo số lần sai), không khóa vĩnh viễn người dùng chỉ vì ai đó đoán sai.
2. **Dùng Fail2ban** (https://github.com/fail2ban/fail2ban): đọc log `vsftpd`, `dovecot`, `sshd`, `postfix` và áp `iptables/nftables BAN` theo cửa sổ thời gian — tức rate-limit ngay tầng mạng, mặc định có sẵn filter `sshd`, `vsftpd`, `dovecot`.
3. Bỏ mật khẩu nếu có thể: **khóa SSH bằng public key**, tắt `PasswordAuthentication`.
4. Bắt buộc mật khẩu mạnh + chặn reuse giữa các dịch vụ (xem 4a.3); khuyến nghị bật **xác thực hai lớp (2FA)** cho các tài khoản quản trị mail/SSH.
5. Với credential stuffing phòng gần như duy nhất bằng phía người dùng: **mật khẩu duy nhất cho mỗi dịch vụ** (dùng trình quản lý mật khẩu), và phía server: thông báo cho user khi đăng nhập từ thiết bị/IP mới.
6. Trong lab: mô phỏng bằng công cụ dò tồn tại (hydra, medusa...) **giữa hai máy lab tự sở hữu**, bật Fail2ban và so sánh log trước/sau khi bật để thấy hiệu quả của throttle.

**Nguồn:**
- NIST SP 800-63B (Digital Identity Guidelines — rate-limit, blocklist mật khẩu rò rỉ): https://pages.nist.gov/800-63-3/sp800-63b.html
- Fail2ban (bộ lọc sshd/vsftpd/dovecot/postfix): https://github.com/fail2ban/fail2ban
- Dovecot (log định dạng `imap-login: Disconnected (auth failed...`): https://doc.dovecot.org/
- Postfix SASL: https://www.postfix.org/SASL_README.html

---

### 4a.3. Mật khẩu yếu và tài khoản mặc định

#### (1) Nguyên nhân

**Mật khẩu yếu:** người dùng chọn mật khẩu theo pattern quen — tên + số, `123456`, `password`, `qwerty`, chuỗi dictionary — vì dễ nhớ và không bị chính sách chặn. Về mặt thông tin (entropy), mật khẩu dictionary có không gian tìm kiếm quá nhỏ so với tốc độ dò của công cụ hiện đại; nếu kết hợp với 4a.1/4a.2 thì gần như chắc chắn bị phá.

**Tài khoản mặc định:** các image đóng gói sẵn thường kèm cặp user:pass công khai. Phổ biến nhất trong thế giới ảo hóa/lab: `ubuntu:ubuntu` (user `ubuntu` sẵn có trong image cloud/VM — ảnh dựng lab thường giữ nguyên mật khẩu gốc, khác với cloud image chính thức buộc cấu hình qua cloud-init), `admin:admin`, `root:root`, `test:test`, và chính **`anonymous:ftp@`** của FTP (mô tả kỹ ở 4a.4). Người dùng cuối không đổi vì "nó chạy được rồi".

#### (2) Điều kiện xảy ra

- Máy dựng từ image/template VM hoặc từ cài đặt nhanh không đi qua bước đổi mật khẩu root/admin.
- PAM không cấu hình kiểm độ mạnh mật khẩu; `/etc/login.defs` để chính sách cũ; hệ thống không đổi mật khẩu lần đầu bắt buộc.
- Dịch vụ mở port ra LAN công cộng của lab mà vẫn giữ credential mặc định — attacker chỉ cần tra bảng "default credentials" của hãng.

Trong lab của đồ án, đây là nguy cơ **hay xảy ra nhất một cách vô tình**: sinh viên clone máy ảo và quên đổi mật khẩu `ubuntu`, hoặc tạo user `test` cho tiện rồi bỏ quên.

#### (3) Dấu hiệu trong log

- Bản thân "mật khẩu yếu" không có log riêng — nó lộ ra khi kết hợp với brute-force (4a.2): tài khoản bị `Failed` rất nhiều lần rồi một `Accepted` từ cùng IP.
- Tài khoản mặc định bị quét: các dòng login **thành công** với user `ubuntu`/`admin`/`ftp` từ IP lạ:
```
Aug 25 00:12:44 lab-srv sshd[3390]: Accepted password for ubuntu from 10.0.3.51 port 4021 ssh2   # user ảnh gốc, mật khẩu gốc
Mon Aug 25 00:15:02 2026 [pid 22551] [ftp] OK LOGIN: Client "10.0.3.51", anon password "hack@"     # đăng nhập anonymous bằng pass là email (chuẩn RFC 959 cho phép)
```
- Kiểm tra chủ động bằng audit (không phải log): so tài khoản đang tồn tại với danh sách mặc định của image, chạy `passwd -S <user>` (xem ngày đổi mật khẩu lần cuối).

#### (4) Mức độ ảnh hưởng

| Tiêu chí | Đánh giá | Lý do |
|---|---|---|
| Confidentiality (C) | **Cao** | Mật khẩu dictionary/ mặc định = cánh cửa mở sẵn đọc dữ liệu. |
| Integrity (I) | **Cao** | Nếu tài khoản mặc định là `ubuntu`/`admin` có quyền sudo → toàn quyền trên máy. |
| Availability (A) | Cao | Attacker đã có shell có thể xóa dữ liệu/mã hóa tống tiền. |

#### (5) Cách phòng ngừa

1. **Chính sách độ dài > chính sách "phức tạp":** mật khẩu dài (≥ 12–16 ký tự, hoặc passphrase nhiều từ) cho entropy cao hơn kiểu bắt buộc `@#$` xen kẽ. Đồng thời **chặn pattern/dictionary**:
   - Trên Ubuntu/RHEL/Fedora, kiểm tra độ mạnh mặc định do **`pam_pwquality`** đảm nhiệm (gói `libpam-pwquality`, dòng `password requisite pam_pwquality.so retry=3` trong `/etc/pam.d/common-password`); phần kiểm tra từ điển dựa trên dữ liệu **CrackLib** (https://github.com/cracklib/cracklib).
   - Rule đặt ở `/etc/security/pwquality.conf`: độ dài tối thiểu `minlen`, số lớp ký tự `dcredit`/`ucredit`/`lcredit`/`ncredit`, `dictcheck`, `maxsequence` (chuỗi tăng/giảm đều như `12345`), `maxrepeat` (ký tự lặp).
   - Cấu hình vòng đời trong `/etc/login.defs`: `PASS_MIN_LEN 8`, `PASS_MAX_DAYS 180`... (giá trị chỉ là ví dụ — chọn theo chính sách đồ án).
2. **Loại bỏ mật khẩu rò rỉ:** đối chiếu với các danh sách mật khẩu bị lộ công khai (NIST SP 800-63B yêu cầu kiểm tra "breached password list" khi đổi mật khẩu).
3. **Xóa/khóa mọi tài khoản mặc định sau khi dựng hệ thống:** `userdel` các user `test`, đặt lại mật khẩu `ubuntu` ngay lần đăng nhập đầu, khóa `root` đăng nhập trực tiếp qua mật khẩu.
4. Trong lab: thêm bước "đổi mật khẩu mặc định" vào quy trình dựng ảnh chuẩn (golden image), và kiểm tra bằng audit trước khi mở port.

**Nguồn:**
- cracklib: https://github.com/cracklib/cracklib
- NIST SP 800-63B (breached list, yêu cầu độ dài): https://pages.nist.gov/800-63-3/sp800-63b.html
- login.defs(5) — Ubuntu manpages: https://manpages.ubuntu.com/manpages/noble/man5/login.defs.5.html
- vsftpd — log mẫu anonymous login: https://www.ossec.net/docs/docs/log_samples/ftp/vsftpd.html

---

### 4a.4. FTP anonymous cấu hình sai

#### (1) Nguyên nhân

FTP có chế độ **anonymous** hợp lệ theo chuẩn: tài khoản `ftp`/`anonymous`, mật khẩu quy ước là địa chỉ email (RFC 959 không kiểm tra giá trị này). Mục đích lịch sử: phân phối file công khai mà không cần cấp tài khoản. Nguy cơ nằm ở **cấu hình**, không ở chuẩn: vsftpd mặc định `anonymous_enable=YES`; nếu quản trị viên thêm các bật quyền ghi mà không hiểu hệ quả thì server biến thành "ổ đĩa công cộng":

```
# /etc/vsftpd.conf — bộ ba cấu hình SAI (chỉ dùng để minh họa trong lab):
anonymous_enable=YES          # cho phép tài khoản ftp/anonymous đăng nhập
anon_world_readable_only=NO   # SAI: anon được tải XUỐNG mọi file, kể cả file chỉ chủ sở hữu đọc được
anon_upload_enable=YES        # SAI: ai cũng UPLOAD file lên server được
```

- `anon_world_readable_only=NO` bỏ lớp bảo vệ cuối cùng của phía đọc.
- `anon_upload_enable=YES` (thường đi kèm `anon_mkdir_write_enable=YES`, `write_enable=YES` và một thư mục `ftp` sở hữu, world-writable) cho phép phía ghi.

#### (2) Điều kiện xảy ra

- vsftpd cài theo mặc định (Ubuntu/Debian bật anonymous download sẵn) + quản trị viên "copy-paste" hướng dẫn kích hoạt upload công khai mà không đặt giới hạn.
- Thư mục con trong `ftp_root` (thường `/srv/ftp` hoặc `/home/ftp`) **world-writable** để anonymous ghi được.
- Server có IP truy cập được từ LAN trong lab (hoặc tệ hơn là từ Internet).

#### (3) Dấu hiệu trong log

vsftpd log rõ ràng từng phiên anonymous — cần phân biệt "download công khai theo thiết kế" với "upload bất thường":

```
# /var/log/vsftpd.log — dòng đăng nhập anonymous (log thật của vsftpd, dạng OK LOGIN + anon password):
Mon Aug 21 14:32:06 2006 [pid 20127] [ftp] OK LOGIN: Client "10.0.2.15", anon password "lala@"

# /var/log/vsftpd.log (log_ftp_protocol=YES) — các hành vi đáng báo động phía sau đăng nhập:
... [pid 20128] ftp [10.0.2.x]: "[STOR malware.zip] 0 12345678 bytes"     # AI ĐÓ vừa UPLOAD file lên — điều không nên xảy ra
... [pid 20129] ftp [10.0.2.x]: "[DELE secret.sql]"                        # anon xóa file (anon_other_write_enable=YES — rất tệ)
```
*(Các daemon FTP khác dùng câu chữ tương đương, ví dụ pure-ftpd ghi "Anonymous user 10.0.2.15 logged in"; các log kiểu wu-ftpd/proftpd có dạng "anonymously logged in"; về bản chất cùng một sự kiện.)*

Dấu hiệu định lượng trong lab: nhiều `[STOR ...]` từ client lạ, file lạ xuất hiện trong `ftp_root`, băng thông upload tăng bất thường.

#### (4) Mức độ ảnh hưởng

| Tiêu chí | Đánh giá | Lý do |
|---|---|---|
| Confidentiality (C) | **Cao** (khi tắt `anon_world_readable_only`) | Ai cũng tải được mọi file trong thư mục FTP — bao gồm file không định công bố. |
| Integrity (I) | **Cao** | Người lạ ghi file vào server: phát tán malware, nội dung vi phạm pháp luật **mang danh máy của trường/nhóm**; nếu `chroot` sai còn có thể ghi đè file hệ thống (liên kết 4a.5). |
| Availability (A) | Trung bình | Đĩa đầy vì đối tượng lạ upload hàng loạt → dịch vụ chết. |

**Hệ quả điển hình:** máy FTP cấu hình sai trở thành **file hosting miễn phí phát tán malware** — chủ sở hữu server bị nhà mạng/đại học gắn trách nhiệm và bị black-list IP, dữ liệu trong thư mục FTP (backup, dump DB) bị mất bí mật hoàn toàn.

#### (5) Cách phòng ngừa

1. Nếu lab/dịch vụ **không cần** phân phối file công khai: `anonymous_enable=NO` (khuyến nghị mặc định cho đồ án).
2. Nếu **có** nhu cầu phân phối công khai:
   ```
   anonymous_enable=YES
   anon_world_readable_only=YES   # GIỮ NGUYÊN mặc định: chỉ file world-readable được tải
   anon_upload_enable=NO          # KHÔNG bật upload cho anonymous
   anon_mkdir_write_enable=NO
   anon_other_write_enable=NO     # không cho xóa/ghi đè
   ```
   và trỏ `ftp_username` tới user riêng không có shell (`/usr/sbin/nologin`), thư mục FTP tách khỏi dữ liệu khác, disk quota riêng.
3. Giám sát và cảnh báo: regex đếm dòng `OK LOGIN ... anon password` + `[STOR` trong `vsftpd.log`; Fail2ban có sẵn filter `vsftpd` cho login thất bại.
4. cân nhắc thay anonymous FTP bằng **HTTP/HTTPS công khai** — cùng mục đích phân phối file mà không cần tài khoản vô danh và có thể đặt CDN/cache.

**Nguồn:**
- vsftpd.conf(5) (định nghĩa các tham số anonymous): https://manpages.debian.org/testing/vsftpd/vsftpd.conf.5.en.html và https://linux.die.net/man/5/vsftpd.conf
- Red Hat Deployment Guide — vsftpd server: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/s2-ftp-servers-vsftpd
- Mẫu log vsftpd/xferlog (OSSEC docs): https://www.ossec.net/docs/docs/log_samples/ftp/vsftpd.html

---

### 4a.5. Thoát khỏi thư mục được phép và sai phân quyền file

#### (1) Nguyên nhân

Hai họ lỗi "hàng rào thư mục":

**a) Không cách ly (thiếu chroot) hoặc cách ly sai.** vsftpd **mặc định không chroot** user vào home — với filesystem khả kiến toàn bộ, user đăng nhập hợp lệ có thể `cd /etc`, `cd ~khac` và thử đọc theo quyền Unix. Các hướng dẫn chroot thường gặp lỗi cấu hình:
- vsftpd từ bản **2.3.5** **từ chối** chạy phiên khi thư mục chroot-root **do chính user đó sở hữu hoặc global-writable**, và từ bản **3.0.3** có thêm "lối thoát" `allow_writeable_chroot=YES` — nhiều người "gỡ lỗi bằng cách" bật dòng này → đúng ra hàng rào vừa bị bỏ: attacker upload file mới/symlink vào chính "buồng giam" của mình.
- **Symlink ra ngoài:** nếu FTP (hoặc SFTP) cho phép tạo symlink `dự án -> /`, rồi `cd dự án`, thì về mặt kernel đường dẫn vẫn được giải tham chiếu tới `/` — chroot nếu đặt **sai chỗ** (chroot sau khi đã ở trong vùng ghi được của user) là vô nghĩa.
- Lệnh `CWD ../..` kiểu **directory traversal** chỉ thành công khi server tự ghép đường dẫn mà không chuẩn hóa (canonicalize) — các daemon trưởng thành chặn được, nhưng cấu hình alias/virtual user sai vẫn để lọt; với daemon tự viết hoặc script PHP/Python phục vụ file thì đây là bug kinh điển.

**b) Phân quyền file sai.** `chmod 777` "cho nó chạy", file cấu hình world-readable:
- `/etc/passwd` về thiết kế phải `644` — đọc được là bình thường (chỉ có hash đã chuyển sang `/etc/shadow`, phải `640`/`600` root:shadow). Nhưng trong lab hoặc cấu hình sai, **`/etc/shadow` bị readable bởi mọi người** hoặc **`~/.ssh/` `authorized_keys` `666`** thì cực nguy hiểm.
- File cấu hình dịch vụ (`/etc/vsftpd.conf`, `inc.php` chứa DB password...) `777`/`644` cho mọi user đọc → lộ credential nội bộ → leo thang từ một tài khoản FTP "vô hại".

#### (2) Điều kiện xảy ra

- vsftpd không đặt `chroot_local_user=YES`, hoặc đặt nhưng home **sở hữu bởi user đó** + `allow_writeable_chroot=YES`.
- Người dùng có thể tạo symlink (quyền `allow_writeable_chroot`, hoặc SFTP có shell) vào thư mục world-writable.
- File `~/.ssh` hoặc `authorized_keys` thuộc sở hữu của user khác / permission mở (`777`, `666`).
- File `/etc/shadow`, file cấu hình nhạy cảm bị đổi mode do thao tác `chmod` sai trong quá trình làm lab.

#### (3) Dấu hiệu trong log

```
# vsftpd log_ftp_protocol=YES — hành vi dò đường đi lên filesystem:
... [pid 24001] kimdp [10.0.2.20]: "[CWD ../..]" 1
... [pid 24001] kimdp [10.0.2.20]: "[CWD /]" 1        # nếu trả về 1 (OK) => chưa chroot thành công
... [pid 24001] kimdp [10.0.2.20]: "[RETR /etc/passwd]" 1   # đọc thử file hệ thống — 1 = thành công!
```
```
# auth.log — dấu hiệu "thành công" của leo thang qua authorized_keys:
Aug 25 02:44:19 lab-srv sshd[4102]: Accepted publickey for kimdp from 10.0.2.99 port 47810 ssh2: RSA SHA256:9x...   # key mà KIMDP không hề tạo
```
Dấu hiệu fs: `auditd` hoặc kiểm tra định kỳ `find / -perm -o+w -type f`, `stat /etc/shadow`, `stat -c '%U %a' ~user/.ssh/authorized_keys` so với chuẩn (chủ sở hữu=user, `700` thư mục, `600` file).

#### (4) Mức độ ảnh hưởng

| Tiêu chí | Đánh giá | Lý do |
|---|---|---|
| Confidentiality (C) | **Cao** | Đọc `/etc/passwd` (liệt kê user để tấn công 4a.2), file cấu hình, mail spool của người khác. |
| Integrity (I) | **Rất cao** | Ghi `authorized_keys` của user khác (xem liên kết 4a.6) hoặc `crontab` hệ thống → chiếm quyền truy cập dài hạn. |
| Availability (A) | Trung bình | Xóa/ghi đè file của dịch vụ. |

#### (5) Cách phòng ngừa

1. **chroot đúng chuẩn vsftpd:**
   ```
   chroot_local_user=YES       # mọi user local bị giam vào home
   # KHÔNG BAO GIỜ dùng: allow_writeable_chroot=YES khi home do chính user sở hữu
   ```
   Mô hình an toàn: `home` do **root sở hữu, mode 755** (không cho user ghi → vừa thỏa vsftpd vừa chặn symlink), bên trong có thư mục `upload/` do user sở hữu để nhận file.
2. **SFTP thì dùng `ChrootDirectory` của sshd** (xem 4a.6) — chuẩn hơn vì enforced ở tầng SSH.
3. **Nguyên tắc quyền tối thiểu (least privilege):** không `777` bao giờ; dùng nhóm + `750`; file cấu hình nhạy cảm `600` root:root hoặc root:group-dịch-vụ.
4. Audit tự động trong lab: cron hàng ngày chạy `find` các file world-writable + `logwatch`/so sánh checksum cấu hình; cân nhắc `auditd` watch `/etc/shadow`, `~/.ssh`.
5. Khi cần traversal test trong lab: **chỉ test trên chính máy mình sở hữu** để thấy log mẫu — đây là cách học "dấu hiệu" chứ không phải để tấn công.

**Nguồn:**
- vsftpd.conf(5) (mô tả `chroot_local_user`, `allow_writeable_chroot`): https://manpages.debian.org/testing/vsftpd/vsftpd.conf.5.en.html
- Red Hat Deployment Guide — vsftpd: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/s2-ftp-servers-vsftpd
- Linux File Permissions (Ubuntu Community Help): https://help.ubuntu.com/community/FilePermissions

---

### 4a.6. Lạm dụng tài khoản SFTP/SSH

#### (1) Nguyên nhân

SSH/SFTP được mã hóa nên miễn nhiễm 4a.1, nhưng **nó vẫn là cửa vào shell** nếu cấu hình rộng:

- sshd cho phép user có **shell tương tác** (`/bin/bash`) hoặc chỉ muốn "gửi file" nhưng mở cả kênh SFTP → cùng tài khoản đó có thể chạy lệnh, forward cổng.
- **`authorized_keys` bị ghi bởi người khác:** nếu `~/.ssh` hoặc `authorized_keys` permission sai (xem 4a.5) — ví dụ thư mục `777` hoặc sở hữu bởi user khác — thì (a) sshd **từ chối dùng key đó** (StrictModes, log báo `Authentication refused: bad ownership or modes`), nhưng quan trọng hơn (b): một attacker đã có quyền ghi vào đó **thêm public key của họ** → vào như chủ nhà, không cần mật khẩu.
- **Tunnel/port-forward đi ngang trong lab:** tài khoản SSH bị dùng làm "bàn đạp" — `ssh -L`/`-R`/`ProxyJump` mở đường tới các máy khác vốn không mở port ra ngoài; máy có SSH trở thành router cho attacker.
- **`PermitRootLogin yes` + xác thực mật khẩu:** cho phép brute-force thẳng vào tài khoản quyền lực nhất.

Ngoài ra lưu ý chuỗi cung ứng lịch sử: vsftpd 2.3.4 từng bị cài **backdoor** công khai (CVE-2011-2523) — bài học "dịch vụ FTP/SSH chạy trên host cũng là bề mặt tấn công".

#### (2) Điều kiện xảy ra

- `PasswordAuthentication yes` + `PermitRootLogin yes` (mặc định cũ) trong khi máy mở port 22.
- User được thêm vào sshd mà không kèm `Match` block giới hạn.
- Thư mục `~/.ssh` không thuộc quyền user hoặc permission >700/600.
- `AllowTcpForwarding`/`GatewayPorts` bật mặc định cho mọi user.
- Quản trị viên dùng SFTP với tư duy "an toàn hơn FTP nên không cần giới hạn gì thêm" — **SFTP an toàn trên đường truyền nhưng không an toàn về cách ly nếu phân quyền trong máy sai**: cùng một user SFTP có thể đọc thư mục của user khác nếu Unix permission cho phép.

#### (3) Dấu hiệu trong log

```
# /var/log/auth.log — ĐĂNG NHẬP ROOT BẰNG MẬT KHẨU từ LAN (đọc kỹ dòng này):
Aug 25 03:11:40 lab-srv sshd[4310]: Accepted password for root from 10.0.2.99 port 41220 ssh2
```
```
# Key bị người khác ghi thêm / quyền sai:
Aug 25 03:12:02 lab-srv sshd[4321]: Authentication refused: bad ownership or modes for directory /home/kimdp/.ssh
Aug 25 03:12:05 lab-srv sshd[4325]: Accepted publickey for kimdp from 10.0.2.99 port 41240 ssh2: ED25519 SHA256:Kz...   # fingerprint KHÔNG có trong danh sách quản lý
```
```
# Forwarding đi ngang (log -vv / UsePAM + systemd, hoặc nftables theo dõi kết nối tới máy thứ ba):
... sshd[4400]: pam_unix(sshd:session): session opened for user sftpuser ...
# và trong nft/conntrack: máy 10.0.2.5 (chỉ mở 22) BẤT NGỜ kết nối tới 10.0.2.6:3306 — chính là tunnel của sftpuser.
```
So sánh fingerprint key trong log với `ssh-keygen -lf authorized_keys` — mọi key lạ là dấu hiệu chiếm quyền.

#### (4) Mức độ ảnh hưởng

| Tiêu chí | Đánh giá | Lý do |
|---|---|---|
| Confidentiality (C) | **Rất cao** | Một tài khoản SSH = đọc toàn bộ filesystem theo quyền user; root = mọi thứ. |
| Integrity (I) | **Rất cao** | Chạy lệnh bất kỳ, cài persistence (key, cron, service). |
| Availability (A) | Cao | Tunnel giúp attacker lan tới các máy khác trong lab, đánh sập nhiều dịch vụ cùng lúc. |

#### (5) Cách phòng ngừa

1. **Nhật hóa cấu hình SSH cho SFTP-only** (áp dụng nguyên mẫu chuẩn của OpenSSH, các tham số đã có sẵn từ lâu — `ChrootDirectory`/`ForceCommand`/`internal-sftp` từ OpenSSH 4.9 (2008), `PermitTTY` từ 6.7 (2014), `DisableForwarding` từ 7.4):
   ```
   # /etc/ssh/sshd_config
   PermitRootLogin prohibit-password   # Ubuntu/Debian mặc định là giá trị này; tốt nhất là "no"
   PasswordAuthentication no           # chỉ khóa public key
   Subsystem sftp internal-sftp        # sftp chạy trong tiến trình sshd — không cần file trong chroot

   Match Group sftpusers               # nhóm chỉ gửi file, không shell
       ChrootDirectory %h              # giam vào home (home phải root:root, 755 — vsftpd/sshd đều kiểm tra)
       ForceCommand internal-sftp      # chặn scp/shell, chỉ còn SFTP
       PermitTTY no                    # không cấp terminal
       DisableForwarding yes           # chặn MỌI loại forward (X11, agent, TCP, unix socket)
   ```
   Lưu ý phiên bản: `DisableForwarding` dùng được trong `Match` từ OpenSSH **8.5**; và có lỗi **CVE-2025-32728** ở các bản trước 10.0 (đúng ra `DisableForwarding` không tắt hẳn X11/agent forwarding) — luôn cập nhật openssh-server.
2. **Quản lý vòng đời key:** mỗi user tự giữ private key; khi nghỉ/khóa tài khoản phải xóa public key khỏi `authorized_keys`; ghi `~/.ssh` (700) và `authorized_keys` (600) thuộc chính user; bật `StrictModes` (mặc định).
3. Chặn tunnel ở tầng mạng lab: **egress firewall** — máy FTP/SFTP chỉ được phép nhận kết nối, không được khởi tạo tới các phân đoạn khác; khi đó dù attacker có forward cũng không đi đâu được.
4. Theo dõi `auth.log` tập trung (rsyslog → máy log riêng) + Fail2ban filter `sshd`; so sánh định kỳ fingerprint key trong `authorized_keys` với kho quản lý.
5. Tài khoản dịch vụ (dùng để đẩy file vào server) phải là user riêng, không có shell (`/usr/sbin/nologin`), và **bắt buộc chroot**.

**Nguồn:**
- sshd_config(5) (man page chính thức): https://man7.org/linux/man-pages/man5/sshd_config.5.html và https://man.openbsd.org/sshd_config
- OpenSSH 4.9 release notes (ChrootDirectory/ForceCommand/internal-sftp): https://www.openssh.org/txt/release-4.9
- OpenSSH 6.7 release notes (PermitTTY): https://www.openssh.org/txt/release-6.7
- OpenSSH 7.4 release notes (DisableForwarding): https://www.openssh.org/txt/release-7.4
- OpenSSH Security + CVE-2025-32728: https://www.openssh.com/security.html , https://nvd.nist.gov/vuln/detail/CVE-2025-32728
- CVE-2011-2523 (backdoor vsftpd 2.3.4): https://nvd.nist.gov/vuln/detail/CVE-2011-2523
- Fail2ban: https://github.com/fail2ban/fail2ban

---

### 4a.7. Tổng hợp nhanh — bảng đối chiếu phòng ngừa

| # | Nguy cơ | Phát hiện sớm khả thi? | Biện pháp chủ lực |
|---|---|---|---|
| 4a.1 | Nghe lén plaintext | **Rất khó** (log nạn nhân không có gì) → phòng ngừa tuyệt đối | Bỏ plaintext: FTPS/SFTP, 993/995/465-587 TLS; giám sát ARP |
| 4a.2 | Brute-force / stuffing | Có (log `Failed`/`auth failed` + mẫu phân bố) | Rate-limit theo IP (Fail2ban), khóa bằng key, chặn reuse password |
| 4a.3 | Mật khẩu yếu / mặc định | Một phần (audit + login lạ) | cracklib/pwquality, đổi credential mặc định, NIST 800-63B |
| 4a.4 | FTP anonymous sai | Có (`OK LOGIN ... anon password`, `[STOR`) | `anonymous_enable=NO` hoặc giữ nguyên các giới hạn world-readable, không upload |
| 4a.5 | Thoát thư mục / 777 | Có (`CWD /`, `RETR /etc/passwd`, audit file) | chroot đúng ownership, quyền tối thiểu, auditd |
| 4a.6 | Lạm dụng SSH/SFTP | Có (`Accepted password for root`, key lạ) | ChrootDirectory + ForceCommand internal-sftp + PermitTTY no + DisableForwarding, egress firewall |

Toàn bộ nội dung chương này được đối chiếu trên các bản tài liệu mới nhất tại thời điểm viết (tháng 8/2026); môi trường tham chiếu là **Ubuntu 26.04 LTS "Resolute Raccoon"** (phát hành tháng 4/2026, bản hiện hành trong lab của nhóm) — các đường dẫn cấu hình (`/etc/vsftpd.conf`, `/etc/ssh/sshd_config`, `/etc/login.defs`) không đổi so với LTS cũ 24.04.

**Nguồn tổng:**
- Ubuntu release cycle / LTS hiện hành: https://ubuntu.com/about/release-cycle , https://documentation.ubuntu.com/release-notes/26.04/
