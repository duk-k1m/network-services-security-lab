## 7. Thiết kế phòng lab an toàn và ba kịch bản demo

Chương này phục vụ hai mục đích. Thứ nhất, thiết kế một phòng lab mạng nội bộ cô lập (isolated lab network) đủ thật để minh họa toàn bộ các nguy cơ đã phân tích ở chương 5–6, nhưng đủ kín để không gây hại cho bất kỳ hệ thống nào bên ngoài. Thứ hai, trình bày ba kịch bản demo mẫu — FTP plaintext so với SFTP, brute-force có kiểm soát được fail2ban phát hiện, và open relay SMTP rồi khắc phục — theo một khuôn khổ chung: mục tiêu, luồng hoạt động, chuẩn bị, các bước thực hiện, kết quả mong đợi, bằng chứng cần thu thập, log cần quan sát, biện pháp phòng thủ, cách kiểm thử lại sau phòng thủ, và rủi ro/an toàn riêng của từng kịch bản.

> **Nguyên tắc xuyên suốt:** mọi hành vi "tấn công" trong chương này chỉ nhắm vào các máy do nhóm tự dựng trong dải mạng lab, được giảng viên phê duyệt. Đây là tài liệu giáo dục và phòng thủ — không phải hướng dẫn tấn công hệ thống thật.

### 7.1 Thiết kế phòng lab an toàn

#### 7.1.1 Vì sao phải dùng mạng riêng ảo cô lập (Host-only / Internal network)

Ba lý do cốt lõi khiến lab bắt buộc chạy trên VirtualBox *Host-only Adapter* hoặc *Internal Network* (VMware: *VMnet host-only* / *LAN Segment*), tuyệt đối không dùng Bridged Adapter:

1. **Cô lập spam và thư thật.** Kịch bản C mô phỏng open relay (máy chủ chuyển tiếp thư cho bên thứ ba). Nếu lab bridged (cầu nối) ra Internet, một cú gửi nhầm có thể khiến IP của trường bị các danh sách chặn (Blocklist) như Spamhaus ghi nhận — hậu quả thật, sửa rất lâu.
2. **Tránh bị quét ngược.** Máy chạy dịch vụ FTP/SMTP "mở toang" đặt trên mạng thật sẽ bị bot Internet dò thấy trong vài phút; password weak sẽ bị đoán thật, và email notification từ dịch vụ sẽ lộ ra ngoài.
3. **Không làm thật.** Brute-force vào máy chủ của người khác là hành vi vi phạm pháp luật (tại Việt Nam: xâm nhập trái phép vào mạng máy tính, mạng viễn thông hoặc phương tiện điện tử của người khác là tội phạm theo Điều 289 Bộ luật Hình sự 2015; hành vi tấn công hoặc vô hiệu hóa trái phép các biện pháp bảo vệ an ninh mạng còn bị nghiêm cấm theo Điều 8 Luật An ninh mạng 2018). Trong lab cô lập, mục tiêu do nhóm sở hữu, hành vi chỉ mang tính giáo dục.

Mạng Host-only/Internal không cấp quyền ra Internet cho các VM; muốn cập nhật gói (apt) thì tạm bật thêm card NAT cho *máy server*, hoặc dùng cache/mirror cục bộ — làm xong tắt trước khi chạy kịch bản.

#### 7.1.2 Sơ đồ topology

```
                          ✗ Internet (các VM KHÔNG có đường ra)
 ═══════════════════════════════════════════════════════════════════════
        VirtualBox Host-only / Internal Network  (VMnet riêng)
        Dải tĩnh: 192.168.100.0/24 — không DHCP, tự cấu hình IP
 ┌────────────────────┐    ┌──────────────────────────┐    ┌────────────────────┐
 │ lab-attacker-XX    │    │ lab-mail-XX              │    │ lab-user-XX        │
 │ .100.20            │◄──►│ 192.168.100.10           │◄──►│ 192.168.100.30     │
 │ Kali Linux hoặc    │    │ Ubuntu Server 24.04 LTS  │    │ Ubuntu/Windows     │
 │ Ubuntu Desktop     │    │ vsftpd · sshd · postfix  │    │ Desktop            │
 │ • nmap (quét port  │    │ dovecot · ufw · fail2ban │    │ • FileZilla (FTP/  │
 │   lab nội bộ)      │    │ (CA nội bộ + cert TLS)   │    │   FTPS/SFTP)       │
 │ • Wireshark (bắt   │    │                          │    │ • Thunderbird      │
 │   gói tin)         │    │                          │    │   (IMAP/SMTP test) │
 │ • swaks · ftp ·    │    │                          │    │ • ssh/scp          │
 │   sshpass          │    │                          │    │                    │
 └────────────────────┘    └──────────────────────────┘    └────────────────────┘
        │                          │
        └──── mọi lưu lượng demo ──┘   Host (PC thật): chỉ chạy hypervisor,
              đi trong /24             KHÔNG tham gia tấn công
```

Ba máy, ba vai trò rõ ràng: **server dịch vụ** (nạn nhân/quan sát), **máy kiểm thử** (attacker có kiểm soát + công cụ phân tích), **máy người dùng** (client hợp lệ, dùng để chứng minh phòng thủ không phá hỏng người dùng thật). Tên máy theo quy ước `lab-<vai trò>-XX` với **XX = mã nhóm** (ví dụ nhóm 07 → `lab-mail-07`), tránh trùng tên giữa các nhóm và dễ truy vết snapshot.

#### 7.1.3 Bảng IP — hostname — dịch vụ — cổng mở dự kiến

| Machine | Hostname | IP tĩnh | Vai trò | Dịch vụ chính | Cổng mở dự kiến |
|---|---|---|---|---|---|
| Ubuntu Server 24.04 LTS | `lab-mail-XX` | 192.168.100.10 | Mail/FTP server | vsftpd, sshd (OpenSSH), Postfix, Dovecot, ufw, fail2ban | 21 (FTP), 22 (SSH/SFTP), 25 (SMTP), 110 (POP3, tắt nếu không dùng), 143 (IMAP, tắt nếu không dùng), 587 (submission), 993 (IMAPS), 995 (POP3S); 989/990 nếu bật FTPS implicit |
| Kali hoặc Ubuntu | `lab-attacker-XX` | 192.168.100.20 | Máy kiểm thử | nmap, Wireshark, swaks, ftp, ssh, sshpass | Không cần mở (client thuần) |
| Ubuntu/Windows | `lab-user-XX` | 192.168.100.30 | Người dùng cuối | FileZilla, Thunderbird, ssh/scp | Không cần mở |

Các cổng trên khớp đăng ký IANA/RFC: 20/21 là điều khiển/dữ liệu FTP (STD 9, RFC 959); 22 là SSH, trên đó SFTP chạy như một subsystem (SFTP **không** có RFC chuẩn hóa riêng — tính đến nay vẫn chỉ ở dạng các bản nháp IETF `draft-ietf-secsh-filexfer-*`, còn SSH thì dựa trên RFC 4253); 25 là SMTP (STD 10, RFC 5321); 587 là *message submission* theo RFC 6409; 465 là SMTPS implicit-TLS được chuẩn hóa lại trong RFC 8314; 21 (explicit, `AUTH TLS` — khuyến nghị chính thức) và cặp 989/990 (implicit — quy ước legacy do RFC 4217 coi là cần tránh) cho FTPS; 993/995 là IMAPS/POP3S.

#### 7.1.4 Quy tắc an toàn bắt buộc (áp dụng cho cả 3 kịch bản)

1. **Chỉ nhắm vào IP trong dải 192.168.100.0/24** của lab mình. Cấm port-scan hay thử credential ra bất kỳ IP nào khác, kể cả Google/YouTube — mọi scan Internet đều có thể để lại log ở phía bị scan.
2. **Không gửi thư ra Internet.** Trong lab, máy đích chỉ là `*.lab.local`/`*.edu.lab` hoặc các domain được dành riêng cho thử nghiệm (`.test` — reserved theo RFC 6761).
3. **Không dùng credential thật.** Mật khẩu demo dạng `Lab@...123` do nhóm tự đặt, không trùng mật khẩu cá nhân/dịch vụ nào.
4. **Chỉ tấn công máy do nhóm mình sở hữu và được giảng viên phê duyệt.** Trong lớp đông nhóm, kiểm tra kỹ bảng IP trước khi bấm Enter.
5. **Snapshot trước mỗi kịch bản** (VirtualBox → Machine → Take Snapshot): `before-A`, `before-B`, `before-C`. Làm hỏng cấu hình thì revert trong 30 giây, và báo cáo có mốc thời gian "trước/sau" rõ ràng.
6. **Thu bằng chứng có ghi nhật ký:** mỗi nhóm giữ một file `chong-nhat-ky.md` ghi lệnh đã chạy + thời gian, để khi log server xuất hiện "tấn công" thì biết ngay đó là bài của nhóm nào.

#### 7.1.5 Chuẩn bị chung

**a) Cài đặt (làm trên `lab-mail-XX`, 64-bit):**

```bash
sudo apt update
# Bộ dịch vụ của đồ án: FTP, SSH, SMTP, IMAP/POP3 + tường lửa + chống brute-force
sudo apt install -y vsftpd postfix dovecot-imapd dovecot-pop3d \
                    ufw fail2ban
# Postfix khi cài sẽ hỏi "General type of mail configuration" → chọn "Internet Site"
# System mail name: đặt lab.local (xem mục b)
```

**b) Domain giả trong lab.** Dùng `lab.local` hoặc `edu.lab`. Đây là các tên *không tồn tại trên DNS công khai*, nên kể cả khi có thư "rò" ra cũng không tới được ai thật. Tuyệt đối không dùng domain thật (khamfu.vn, gmail.com...) làm `mydestination` vì máy có thể thử chuyển thư thật. Lưu ý thêm: khi cần một địa chỉ "người nhận ngoài Internet" để test relay, dùng đuôi **`.test`** (ví dụ `external@nowhere.test`) — TLD này được IETF dành riêng cho thử nghiệm (RFC 6761), bảo đảm không bao giờ phân giải ra máy thật.

**c) CA nội bộ tự dựng (self-signed internal CA) cho FTPS/SMTPS/IMAPS.** Vì `lab.local` không có chứng chỉ (certificate) công khai hợp lệ (không thể xin Let's Encrypt), cả nhóm tự làm một CA riêng — đây cũng là bài học về mô hình Trust-on-first-use và vì sao client sẽ cảnh báo "untrusted certificate":

```bash
# 1) Tạo CA tự ký (self-signed) — chạy trên lab-mail, thư mục /etc/ssl/lab
sudo mkdir -p /etc/ssl/lab && cd /etc/ssl/lab
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
     -keyout lab-ca.key -out lab-ca.crt \
     -subj "/CN=Lab Internal CA $USER"        # CN = tên CA hiển thị khi import

# 2) Tạo khóa + CSR cho server, cấp cert có SAN (Subject Alternative Name)
sudo openssl req -newkey rsa:2048 -nodes \
     -keyout lab-mail.key -out lab-mail.csr -subj "/CN=lab-mail.lab.local"
printf "subjectAltName=DNS:lab-mail.lab.local,IP:192.168.100.10\n" > san.cnf
sudo openssl x509 -req -in lab-mail.csr -CA lab-ca.crt -CAkey lab-ca.key \
     -CAcreateserial -days 365 -extfile san.cnf -out lab-mail.crt
# → lab-mail.crt dùng cho vsftpd (FTPS), Postfix (TLS), Dovecot (IMAPS/POP3S)
```

Client (lab-user, lab-attacker) import `lab-ca.crt` vào kho tin cậy thì hết cảnh báo. Toàn bộ cert chỉ có giá trị trong lab.

**d) Tường lửa cơ bản trên lab-mail (ufw):**

```bash
sudo ufw default deny incoming
# Chỉ mở dịch vụ cần demo, và chỉ cho đúng dải lab (from 192.168.100.0/24)
sudo ufw allow in on <tên-interface-lab> to any port 22,25,587,993,995 proto tcp
sudo ufw allow in on <tên-interface-lab> to any port 21 proto tcp   # kịch bản A mới bật plain FTP
sudo ufw enable
# Xem interface: ip -br a  (trên VirtualBox Host-only thường là enp0s8/vboxnet0)
```

Nguồn: https://documentation.ubuntu.com ; https://manpages.ubuntu.com/manpages/jammy/man5/vsftpd.conf.5.html ; https://www.rfc-editor.org/rfc/rfc6761 (`.test`); https://www.rfc-editor.org/rfc/rfc959 (FTP); https://www.rfc-editor.org/rfc/rfc4217 (FTPS); https://datatracker.ietf.org/doc/html/rfc6409 (submission 587); https://www.openssl.org/docs/manstable/man1/openssl-req.html

### 7.2 Kịch bản A — FTP plaintext vs SFTP: "mạng nội bộ cũng không vô hình"

#### (1) Mục tiêu
Chứng minh bản chất: FTP (RFC 959) gửi **toàn bộ điều khiển lẫn dữ liệu dạng plaintext** — gồm cả `USER`/`PASS` — nên ai nghe được đường truyền (eavesdropping/sniffing) là đọc được mật khẩu và nội dung file; trong khi SFTP (subsystem của SSH, cổng 22) che giấu bằng cách mã hóa (encryption) toàn bộ, kẻ bắt gói chỉ thấy một khối nhị phân (binary blob) không phân giải được. Người học hiểu vì sao các tài liệu quản trị (và chương 5) khuyến nghị bỏ plain FTP.

#### (2) Sơ đồ luồng hoạt động

```
 Phase 1 — Plain FTP                          Phase 2 — SFTP
 lab-user-XX(.30)  ──TCP 21──►  lab-mail(.10)  lab-user-XX(.30) ──TCP 22──► lab-mail(.10)
 FileZilla: USER labftp          vsftpd         ssh -i id_ed25519:            sshd + sftp-
 FileZilla: PASS <mật khẩu>                     handshake→kdf→aes256-ctr       server subsystem
 FileZilla: RETR bai-thuc-hanh.txt             tất cả payload = ciphertext
        │                                            │
        ▼                                            ▼
 lab-attacker-XX(.20): Wireshark capture enp0s8 (.20): Wireshark capture enp0s8
 → filter "ftp" → THẤY rõ USER/PASS,   → filter "ssh" → chỉ thấy banner "SSH-2.0-..."
   nội dung file (follow stream)         còn lại không decode được (không có key nào
                                         để load vì SSH KHÔNG dùng keylog kiểu TLS)
```

#### (3) Điều kiện chuẩn bị
- `lab-mail-XX`: vsftpd chạy plain (xem bước 4a), user hệ thống `labftp` với mật khẩu demo `Labftp@123`, file mẫu `/home/labftp/bai-thuc-hanh.txt` chứa một dòng đánh dấu dễ nhận (ví dụ `BI-MAT-LAB-DEMO-9F3K`).
- `lab-user-XX`: FileZilla, `ssh`/`sftp` client; đã tạo cặp khóa `ssh-keygen -t ed25519` và copy pubkey vào `~labftp/.ssh/authorized_keys`.
- `lab-attacker-XX`: Wireshark chạy trên interface của dải lab. Lưu ý kiến trúc: mạng Host-only/Internal của VirtualBox hoạt động như một switch ảo — mỗi VM chỉ nhận broadcast/multicast và các gói unicast gửi tới **chính IP của nó**, nên Wireshark trên máy này mặc định KHÔNG thấy traffic giữa hai VM khác; VMware Workstation có thể bật *Promiscuous Mode: Allow All* trên adapter host-only/LAN Segment, còn VirtualBox không có cơ chế tương đương cho host-only. Đơn giản nhất và đáng tin nhất cho demo là **chạy Wireshark ngay trên máy tham gia phiên** (lab-user ở kịch bản này).

#### (4) Các bước thực hiện

**Phase 1 — plain FTP:**

```bash
# lab-mail-XX: /etc/vsftpd.conf — cấu hình plain tối thiểu cho DEMO (sẽ gỡ ở phase 2)
listen=YES
anonymous_enable=NO        # tắt FTP ẩn danh
local_enable=YES           # cho user hệ thống đăng nhập
write_enable=NO            # chỉ đọc — giảm rủi ro trong lab
xferlog_enable=YES         # bật log kết nối + transfer
vsftpd_log_file=/var/log/vsftpd.log
log_ftp_protocol=YES       # log MỌI lệnh FTP — bằng chứng đẹp cho báo cáo
syslog_enable=YES          # ghi thêm vào syslog (auth.log/mail.* tùy distro)
# systemctl restart vsftpd
```

- Mở Wireshark trên `lab-user-XX`, interface dải lab, filter `ftp || ftp-data`, bấm Start.
- FileZilla → New Site: Host `192.168.100.10`, Protocol **FTP - File Transfer Protocol**, Encryption: *Only use plain FTP (insecure)*, User `labftp`, Pass `Labftp@123` → Connect → kéo `bai-thuc-hanh.txt` về.

**Phase 2 — SFTP:** đổi FileZilla sang Protocol **SFTP - SSH File Transfer Protocol**, cổng 22, Logon Type *Key file* trỏ vào `id_ed25519` (không còn mật khẩu); hoặc trên terminal:

```bash
sftp -i ~/.ssh/id_ed25519 labftp@192.168.100.10
sftp> get bai-thuc-hanh.txt
```

Capture lại với filter `ssh` trong lúc transfer.

#### (5) Kết quả mong đợi
- Phase 1: trong Wireshark, các gói "FTP" hiện nguyên văn `USER labftp`, `PASS Labftp@123` ngay trên khung nhìn (dissector FTP của Wireshark giải mã toàn bộ kênh điều khiển, dòng PASS nằm ngay sau dòng USER — chỉ một cú click là đọc được); chọn packet `RETR` → *Follow → TCP Stream* thấy cả nội dung file, gồm chuỗi `BI-MAT-LAB-DEMO-9F3K`.
- Phase 2: chỉ đọc được đúng dòng banner `SSH-2.0-OpenSSH_...` (theo thiết kế SSH, version exchange diễn ra plaintext — RFC 4253); sau đó là ciphertext: không có `USER`, không `PASS`, không tên file, không nội dung.

#### (6) Bằng chứng cần thu thập
- 2 file `.pcapng` đặt tên `ftp-plain.pcapng`, `sftp-encrypted.pcapng` (File → Save).
- 3 ảnh chụp: (i) dòng `USER`/`PASS` trong detail pane Wireshark; (ii) *Follow TCP Stream* của lệnh RETR thấy nội dung file; (iii) cùng vị trí trong capture SFTP chỉ là bytes hex.
- Ảnh giao diện FileZilla thành công ở cả hai chế độ; excerpt `/var/log/vsftpd.log` (phase 1) và `/var/log/auth.log` dòng `Accepted publickey` (phase 2).

#### (7) Log cần quan sát

| Máy | Đường dẫn | Từ khóa grep |
|---|---|---|
| lab-mail | `/var/log/vsftpd.log` | `grep -E "OPEN|CLOSE|RETR|login" /var/log/vsftpd.log` — thấy toàn bộ phiên FTP do `log_ftp_protocol=YES` |
| lab-mail | `/var/log/auth.log` | `grep -E "sshd.*(Accepted|Failed)" /var/log/auth.log` — phiên SFTP xác thực bằng publickey |

#### (8) Biện pháp phòng thủ áp dụng
Tắt plain FTP, chỉ dùng SFTP (hoặc tối thiểu FTPS — mục mở rộng); bắt buộc SSH dùng khóa, đặt `PasswordAuthentication no` trong `/etc/ssh/sshd_config` (kèm `PermitRootLogin no`) rồi `systemctl restart ssh`; giữ `write_enable=NO` nếu user chỉ cần đọc.

#### (9) Kiểm thử lại sau phòng thủ
1. Tắt vsftpd (`systemctl disable --now vsftpd`) và gỡ rule `21` khỏi ufw. Chạy lại đúng thao tác FileZilla plain FTP từ lab-user → báo lỗi *Connection refused/timed out*; Wireshark không còn gói `ftp` nào.
2. Thử `sftp labftp@192.168.100.10` **nhập sai mật khẩu** (key không được cung cấp) → bị từ chối `Permission denied (publickey)` vì đã tắt PasswordAuthentication → chứng minh không còn kênh plaintext nào cho credential.
3. Mở lại capture khi transfer SFTP thành công → đối chiếu: vẫn chỉ là ciphertext → kết luận phòng thủ đúng.

#### Mở rộng (advanced): FTPS explicit + giải mã TLS bằng SSLKEYLOGFILE
Bật FTPS trên vsftpd:

```bash
ssl_enable=YES                       # bật TLS cho FTP
allow_anon_ssl=NO
require_ssl_reuse=NO                 # tránh lỗi "No session reuse" với một số client
rsa_cert_file=/etc/ssl/lab/lab-mail.crt
rsa_private_key_file=/etc/ssl/lab/lab-mail.key   # cert từ CA nội bộ (mục 7.1.5c)
# Client FileZilla chọn "Require explicit FTP over TLS" → AUTH TLS trên cổng 21
```

Khi đó capture `ftp` chỉ thấy phần điều khiển plaintext **trước** lệnh `AUTH TLS`, còn lại là TLS record. Để chứng minh "TLS giải mã được nếu giữ được key" (và vì sao phải khóa key như khóa nhà): với các client nền Mozilla/NSS (Firefox, **Thunderbird** — dùng cho IMAPS/SMTPS ở kịch bản khác), đặt biến môi trường `SSLKEYLOGFILE=/tmp/sslkey.log` rồi khởi động lại app, trỏ Wireshark vào *Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename* là xem lại toàn bộ traffic đã "mã hóa". FileZilla/GnuTLS không hỗ trợ keylog nên phần FTPS chỉ demo được ở mức "không đọc được mà không có key". Lưu ý kỹ thuật: phải capture từ trước ClientHello, không có session resumption, và kênh dữ liệu FTPS là TCP nối mới riêng (Decode As → TLS) — đây chính là các pitfall được cộng đồng Wireshark ghi nhận.

#### (10) Rủi ro và quy tắc an toàn riêng của kịch bản
- Mật khẩu `Labftp@123` chỉ tồn tại trong lab; **không** gõ mật khẩu này ở bất kỳ form/website nào sau bài demo để tránh thói quen reuse.
- File `.pcapng` chứa mật khẩu plaintext của lab — coi như vật liệu nhạy cảm, không upload công khai (GitHub công khai, nhóm chat lớp...) trước khi báo cáo xong.
- Chỉ sniff traffic dải lab; không bật promiscuous trên card kết nối Internet của máy thật.

Nguồn: https://www.rfc-editor.org/rfc/rfc959 ; https://www.rfc-editor.org/rfc/rfc4217 ; https://wiki.wireshark.org/TLS ; https://manpages.ubuntu.com/manpages/jammy/man5/vsftpd.conf.5.html ; https://www.openssh.com/manual.html

### 7.3 Kịch bản B — Brute-force có kiểm soát và phát hiện sớm bằng fail2ban

#### (1) Mục tiêu
Chứng minh chuỗi "nguy cơ → phát hiện sớm → phòng thủ" đã nêu ở chương 5–6: (a) tài khoản dùng mật khẩu yếu đăng nhập qua SSH/FTP/Dovecot **có thể bị đoán dần** bằng đúng kỹ thuật attacker dùng; (b) các lần thất bại lộ nguyên trong log; (c) fail2ban đọc log, đếm vi phạm trong cửa sổ thời gian (findtime) và **tự động chặn IP** (bantime) — biến tấn công "im lặng về mặt người quản trị" thành sự kiện được ngăn chặn và ghi nhận.

#### (2) Sơ đồ luồng hoạt động

```
 lab-attacker-XX(.20)                      lab-mail-XX(.10)
 for pass in <wordlist-demo>; do ─────────► sshd / vsftpd / dovecot
   sshpass -p $pass ssh demo@.10           ├─ sai → ghi "Failed password for invalid
   ftp -n .10  (USER/PASS sai)             │        user demo" → /var/log/auth.log
 done (≤20 lần)                            ├─ vsftpd → /var/log/vsftpd.log
                                           │
                          fail2ban (daemon) ── tail logpath ── regex match
                                           │   count ≥ maxretry trong findtime
                                           ▼
                                    banaction → iptables chain f2b-sshd
                                    DROP mọi gói từ 192.168.100.20
 Test lại: ssh từ .20 → "Connection timed out"  ← phòng thủ có hiệu lực
```

#### (3) Điều kiện chuẩn bị
- fail2ban bản Ubuntu (`apt install fail2ban`), chưa cấu hình gì thêm; `sshd`, `vsftpd`, `dovecot` đang chạy (kế thừa từ kịch bản A — nhớ revert snapshot `before-A` nếu muốn môi trường sạch, hoặc dùng luôn).
- User demo trên lab-mail: `sudo adduser demo` (mật khẩu `Demo@9999` — **cố tình yếu về độ phức tạp nhưng chỉ tồn tại trong lab**).
- Wordlist demo 10–20 dòng, chỉ gồm mật khẩu giả: `demo1`, `demo123`, `Demo@1`, `Demo@2`, ..., `Labftp@123`, `admin2024`... **Không tải wordlist thật (rockyou...) về lab.**
- Trên lab-mail mở sẵn: `tail -f /var/log/auth.log /var/log/vsftpd.log /var/log/mail.log`.

> **Về công cụ chuyên dụng:** trong thực tế attacker dùng các framework brute-force như **hydra**, medusa, ncck... Tài liệu này chỉ ghi nhận *sự tồn tại* của chúng (chạy được trong lab đã phê duyệt) và **không** đưa cú pháp, vì một vòng lặp shell 10–20 lần thử cho bài demo đúng mục tiêu học mà rủi ro kỷ luật/pháp lý thấp hơn nhiều so với chạy công cụ quét tự động.

#### (4) Các bước thực hiện

**Bước 1 — brute-force có kiểm soát (từ lab-attacker-XX):**

```bash
# SSH: 15 lần thử sai + 1 lần thử đúng để thấy sự khác biệt trong log
# -o ConnectTimeout=5: không treo nếu máy đích chậm; 'true': không mở shell phiên
for pass in demo1 demo123 'Demo@1' 'Demo@2' 'Demo@3' 'Demo@4' 'Demo@5' \
            'Labftp@123' admin2024 'passw0rd' 'demo!' '123456' 'qwerty' \
            'letmein' 'iloveyou'; do
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
      demo@192.168.100.10 true
  sleep 1     # mô phỏng nhịp gõ của người — 1 lần/giây
done
sshpass -p 'Demo@9999' ssh -o StrictHostKeyChecking=no demo@192.168.100.10 echo OK
# → dòng cuối đăng nhập ĐÚNG: nếu đây là attacker thật thì đã chiếm được tài khoản

# FTP: cùng tư tưởng, dùng ftp -n (-n: không auto-login) kết hợp -s
for pass in demo1 demo123 'Demo@1' 'Labftp@123' admin2024 'qwerty' '123456' \
            'demo!' 'test' 'demo2024'; do
  printf 'user demo %s\nquit\n' "$pass" | ftp -n 192.168.100.10 >/dev/null 2>&1
  sleep 1
done
# Dovecot (IMAP): swaks CHỈ nói SMTP/ESMTP/LMTP, không hỗ trợ IMAP — muốn lặp lại
# ý tưởng trên cổng 143/993 có thể dùng curl (thử LOGIN bằng đúng giao thức IMAP):
#   for pass in demo1 demo123 'Demo@1'; do
#     curl -s --url imap://192.168.100.10 --user "demo:$pass" >/dev/null 2>&1; sleep 1
#   done
# hoặc chỉ cần log dovecot do các lần Thunderbird nhập sai ở lab-user.
```

**Bước 2 — quan sát log realtime (trên lab-mail, ở terminal khác):** thấy dày đặc `Failed password for invalid user demo` (tùy biến `invalid` hay không — `demo` là user hợp lệ nên dòng log không có chữ `invalid`), và dòng cuối `Accepted password for demo`.

**Bước 3 — bật phòng thủ fail2ban (trên lab-mail):**

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local   # KHÔNG sửa jail.conf gốc
sudo nano /etc/fail2ban/jail.local
```

```ini
[DEFAULT]
bantime  = 600      # chặn 10 phút — chọn ngắn để còn demo bước retest trong buổi học
findtime = 300      # đếm vi phạm trong 5 phút
maxretry = 5        # 5 lần sai → ban (mặc định upstream của fail2ban cũng là 5)

[sshd]
enabled = true
# vsftpd & dovecot: jail có sẵn trong bản Ubuntu — bật khi nào có kịch bản
[vsftpd]
enabled  = true
port     = ftp
logpath  = /var/log/vsftpd.log   # nếu distro log qua syslog, đổi thành /var/log/auth.log
[dovecot]
enabled  = true
logpath  = /var/log/mail.log     # dovecot: "Disconnected (auth failed" ...

sudo systemctl restart fail2ban
fail2ban-client status            # xác nhận 3 jail đang chạy
```

Mẹo kiểm tra filter trước khi tin nó: `sudo fail2ban-regex /var/log/vsftpd.log /etc/fail2ban/filter.d/vsftpd.conf` — nếu match 0 thì jail không bao giờ ban (lỗi phổ biến nhất khi làm fail2ban).

#### (5) Kết quả mong đợi
- Sau ~6 phút (5 lần sai + findtime) fail2ban tự tạo chain `f2b-sshd` và chèn rule DROP nguồn `192.168.100.20`.
- Lần thử tiếp theo (kể cả **đúng mật khẩu**) từ máy attacker → `ssh: connect to host ... port 22: Connection timed out`.
- Người dùng hợp lệ `lab-user-XX` (.30) vẫn đăng nhập SSH **bình thường** — phòng thủ nhắm theo IP, không phá dịch vụ.

#### (6) Bằng chứng cần thu thập
- Ảnh excerpt `auth.log`/`vsftpd.log` có chuỗi `Failed` → `Ban` từ fail2ban.
- Output các lệnh: `sudo iptables -L -n -v | grep -A5 f2b-sshd` (rule DROP + bộ đếm packet), `sudo fail2ban-client status sshd` (hiện `Banned IP list: 192.168.100.20`), tương tự `sudo fail2ban-client status vsftpd` cho jail FTP, `sudo ipset list f2b-sshd` (bản dùng ipset action), và excerpt `/var/log/fail2ban.log` dòng `... NOTICE Ban 192.168.100.20`.
- Video/ảnh ssh timeout từ .20 **kèm** ảnh ssh thành công từ .30 (chứng minh tính chọn lọc).
- File pcap Wireshark trên .20 cho thấy SYN gửi đi nhưng không có SYN-ACK trả về (gói bị DROP im lặng — khác REJECT sẽ trả ICMP).

#### (7) Log cần quan sát

| Máy | Đường dẫn | Từ khóa grep |
|---|---|---|
| lab-mail | `/var/log/auth.log` | `grep -E "Failed password\|Accepted\|session opened" /var/log/auth.log` |
| lab-mail | `/var/log/vsftpd.log` | `grep -iE "FAILED\|login\|error" /var/log/vsftpd.log` (vsftpd qua PAM ghi cả vào auth.log: `authentication failure`) |
| lab-mail | `/var/log/mail.log` | `grep -E "dovecot:.*auth failed\|Disconnected" /var/log/mail.log` |
| lab-mail | `/var/log/fail2ban.log` | `grep -E "NOTICE Ban\|Restore Ban" /var/log/fail2ban.log` — "nhật ký phát hiện sớm" |

*(Trên Ubuntu 22.04/24.04 nếu dịch vụ log vào journald thay vì file, đặt `backend = systemd` **trong từng jail** — biến trong `[DEFAULT]` đôi khi không propagate — hoặc dùng `journalctl -u ssh -f` để theo dõi.)*

#### (8) Biện pháp phòng thủ áp dụng
fail2ban (phát hiện sớm + chặn tự động theo log); kết hợp các lớp phòng thủ gốc: **tắt mật khẩu đăng nhập SSH, chỉ dùng khóa** (kịch bản A), chính sách mật khẩu mạnh, khóa tài khoản sau n lần sai (pam_faillock/pam_tally2), và ufw giới hạn cổng. Nhấn mạnh trong báo cáo: fail2ban là lớp *giảm sát thương*, không phải bức tường tuyệt đối — attacker đổi IP (botnet), gửi chậm dưới ngưỡng `maxretry`, hoặc brute-force hàng loạt tài khoản mỗi tài khoản 1 lần ("low and slow") là vượt qua được kiểu đếm-ngưỡng này.

#### (9) Kiểm thử lại sau phòng thủ
1. Chạy lại y nguyên vòng lặp SSH → quá 5 lần sai từ .20 → các lần *sau đó* timeout hoàn toàn (kể cả đúng pass): `ssh: ... timed out`.
2. `sudo fail2ban-client status sshd` → .20 nằm trong danh sách ban; `sudo iptables -L -n -v` → chain `f2b-sshd` tăng packet counter đúng bằng số lần .20 bị chặn.
3. Gỡ ban demo: `sudo fail2ban-client set sshd unbanip 192.168.100.20` → ssh từ .20 lại kết nối được, xác nhận ban là nguyên nhân chứ không phải cấu hình sai.
4. Thử "né ngưỡng": 3 lần sai từ .20, chờ > `findtime` (6 phút), thử tiếp — không bị ban → chính bằng chứng cho đoạn "hạn chế của fail2ban" ở mục (8).

#### (10) Rủi ro và quy tắc an toàn riêng của kịch bản
- **Giới hạn 10–20 lần thử, sleep ≥ 1 s** giữa các lần: đủ tạo bằng chứng, không biến lab thành stress-test.
- Wordlist chỉ chứa mật khẩu giả do nhóm nghĩ ra trong buổi đó.
- Trước khi bật jail SSH, **giữ sẵn một terminal SSH đang mở từ máy host khác** hoặc cấu hình `ignoreip = 127.0.0.1/8 192.168.100.30` (loại trừ máy user thật và chính máy quản trị) — tránh cảnh fail2ban ban mất cả... nhóm mình.
- Snapshot `before-B` để revert nếu jail cấu hình sai làm nghẽn dịch vụ của cả lớp (dùng chung máy chủ yếu không xảy ra với host-only riêng từng nhóm, nhưng quy tắc vẫn giữ).

Nguồn: https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf ; https://github.com/fail2ban/fail2ban/wiki ; https://manpages.ubuntu.com/manpages/jammy/man5/vsftpd.conf.5.html ; https://www.openssh.com/manual.html (sshd_config)

### 7.4 Kịch bản C — Postfix open relay, phát hiện và khắc phục

#### (1) Mục tiêu
Hiểu bản chất **open relay**: máy chủ SMTP nhận thư *không thuộc miền của mình* từ người gửi *không được tin cậy* rồi chuyển tiếp đi tiếp (third-party relay) — ngày xưa là thiết kế cố hữu của Sendmail, ngày nay là **cấu hình sai**, và trở thành công cụ phát tán spam/thư mạo danh quy mô lớn. Người học tự tay: (a) tạo open relay do lỗi `mynetworks`; (b) chứng minh bằng swaks + queue Postfix; (c) khắc phục bằng `smtpd_relay_restrictions` + submission 587 có xác thực SASL qua Dovecot; (d) chứng minh bằng log trước/sau.

#### (2) Sơ đồ luồng hoạt động

```
 TRƯỚC SỬA (open relay — mynetworks=0.0.0.0/0):
 lab-attacker-XX(.20)                          lab-mail-XX(.10)              "Internet"
 swaks --to external@nowhere.test ──SMTP25──►  Postfix smtpd:
                                               permit_mynetworks (=.20 ✔) ──► 250 Ok: vào
                                               queue → defer (DNS .test không phân giải
                                               được — may mà lab không có đường ra!)

 SAU SỬA:
 .20 không auth ──SMTP25──► reject_unauth_destination → "554 5.7.1 Relay access denied"
                                     │ log: "disconnect ... after RCPT"  → fail2ban đọc
 .30 (Thunderbird) ──SMTPS 587──► permit_sasl_authenticated (Dovecot SASL) → 250 → giao
       thư nội bộ demo@lab.local vào mailbox Dovecot → đọc lại bằng IMAPS 993
```

#### (3) Điều kiện chuẩn bị
- Postfix đang chạy ở chế độ `Internet Site`, `mydestination = lab.local, localhost`, hostname `lab-mail-XX`.
- `swaks` trên máy tester (công cụ kiểm thử SMTP chuẩn, một file Perl duy nhất — "Swiss Army Knife for SMTP", có sẵn trong kho Kali: `apt install swaks`).
- Dovecot đã cài (đã có ở 7.1.5); user `demo` + user `mailtest` có mailbox thật (`mailtest` dùng cho auth submission).
- Snapshot `before-C`.

#### (4) Các bước thực hiện

**Bước 1 — cố ý cấu hình SAI (chỉ trong phòng lab, chỉ vài phút):**

```bash
sudo postconf -e 'mynetworks = 0.0.0.0/0'   # SAI NGHIÊM TRỌNG: "mọi IP đều là bạn"
sudo systemctl reload postfix
postconf mynetworks    # xác nhận đã áp dụng
```

**Bước 2 — chứng minh open relay (từ lab-attacker-XX):**

```bash
swaks --to external@nowhere.test \
      --from ai-dó@chu-gia-nao-do.test \
      --server 192.168.100.10:25
# Kết quả mong đợi trong transcript:
#   << 250 ... RCPT To:<external@nowhere.test>
# Nghĩa là: máy KHÔNG thuộc miền ta, người gửi KHÔNG auth, đích KHÔNG thuộc ta
# → server vẫn đồng ý chuyển tiếp = OPEN RELAY.
```

Kiểm điểm trên server (bằng chứng queue):

```bash
postqueue -p    # thấy hàng đợi: một thư "deferred" tới nowhere.test
                # (trong lab cô lập không phân giải/gửi được ra ngoài — nhưng về
                #  nguyên tắc, nếu server này ở Internet nó ĐÃ chuyển tiếp spam)
sudo postcat -q <queue-id> | head -40    # xem nguyên văn header/entry của thư demo
```

So sánh nhanh với công cụ kiểm tra relay chuẩn: các "open relay test" của MXToolbox/ABUSE.NET chính là tự động hóa đúng lệnh swaks trên (lab không truy cập được — chỉ nói để người học liên hệ thực tế).

**Bước 3 — khắc phục đúng chuẩn:**

```bash
# (a) Thu hẹp mạng tin cậy về loopback — client lab KHÔNG còn là "mynetworks"
sudo postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128'

# (b) Hàng rào relay tường minh, kết thúc bằng reject vĩnh viễn:
sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
# permit_mynetworks         : chỉ loopback
# permit_sasl_authenticated : ai đã auth (qua 587) thì được relay
# reject_unauth_destination : còn lại → "554 5.7.1 <x>: Relay access denied"
#   (lưu ý default Postfix dùng defer_unauth_destination = từ chối tạm 4xx;
#    bản chính thức trong postconf là như vậy — dùng reject để trả lời dứt khoát)

# (c) Mở submission 587 yêu cầu auth — theo RFC 6409 (MSA bắt buộc xác thực):
sudo nano /etc/postfix/master.cf    # bỏ dấu # ở block submission và thêm -o:
# submission inet n - y - - smtpd
#   -o syslog_name=postfix/submission
#   -o smtpd_tls_security_level=encrypt        # bắt buộc TLS trên 587 (RFC 8314)
#   -o smtpd_sasl_auth_enable=yes              # buộc AUTH
#   -o smtpd_relay_restrictions=permit_sasl_authenticated,reject  # không auth → từ chối
#   -o milter_macro_daemon_name=SERVERING

# (d) Nối SASL sang Dovecot (Dovecot vừa là auth server vừa quản lý mailbox):
sudo postconf -e 'smtpd_sasl_type = dovecot'
sudo postconf -e 'smtpd_sasl_path = private/auth'
sudo postconf -e 'smtpd_sasl_auth_enable = no'   # 25 KHÔNG cần auth; 587 override = yes
# /etc/dovecot/conf.d/10-master.conf — block auth cho Postfix:
#   unix_listener /var/spool/postfix/private/auth {
#     mode = 0660
#     user = postfix
#     group = postfix
#   }
# /etc/dovecot/conf.d/10-auth.conf: disable_plaintext_auth = no (chỉ vì lab demo
#   không có CA được máy khách tin; ngoài thật phải = yes + TLS)
sudo systemctl restart dovecot postfix
sudo systemctl reload postfix
```

Cấp cert TLS cho Postfix/Dovecot từ CA mục 7.1.5c (`smtpd_tls_cert_file`, `smtp_tls_cert_file`, `ssl_cert`/`ssl_key` của Dovecot) — ở bài demo có thể chấp nhận tự ký trên Thunderbird sau khi import CA.

**Bước 4 — kiểm chứng sau sửa:**

```bash
# 4a) Tester KHÔNG auth, port 25 → phải bị chặn:
swaks --to external@nowhere.test --server 192.168.100.10:25
#   mong đợi: << 554 5.7.1 <external@nowhere.test>: Relay access denied

# 4b) Tester CÓ auth qua 587, gửi cho người nhận NỘI BỘ trong lab (an toàn tuyệt đối):
swaks --to demo@lab.local --from mailtest@lab.local \
      --server 192.168.100.10:587 --tls \
      --auth-login --auth-user mailtest --auth-password '<mat-khau-demo>'
#   mong đợi: << 250 ... Queued mail for delivery  → rồi demo@lab.local đọc được qua IMAPS

# 4c) Lab-user thử Thunderbird (đổi SMTP server: 587 + STARTTLS/TLS + username/password)
#     → gửi được cho demo@lab.local → chứng minh phòng thủ không chặn người dùng hợp lệ.
```

#### (5) Kết quả mong đợi
Trước sửa: `RCPT TO: <external@nowhere.test>` trả `250` từ một máy không quen biết = bằng chứng open relay. Sau sửa: cùng lệnh trả `554 5.7.1`; thư chỉ vào queue khi và chỉ khi người gửi đã SASL-auth qua 587 có TLS. Bảng so sánh trước/sau chính là deliverable của kịch bản.

#### (6) Bằng chứng cần thu thập
- Transcript swaks 2 lần (250 vs 554) — copy nguyên khối có timestamp.
- `postqueue -p` trước sửa (thư deferred trong queue) và `postcat` entry demo.
- Ảnh: Thunderbird gửi qua 587 thành công + IMAPS đọc lại thư trong INBOX.
- `netstat -tlnp | grep -E ":25|:587"` (hoặc `ss -tlnp`) chụp hai trạng thái master.cf.

#### (7) Log cần quan sát

| Máy | Đường dẫn | Từ khóa grep |
|---|---|---|
| lab-mail | `/var/log/mail.log` | `grep -E "postfix/smtpd.*(Relay access denied\|after RCPT\|disconnect\|client=)" /var/log/mail.log` |
| lab-mail | `/var/log/mail.log` | `grep "postfix/cleanup" mail.log` — dòng `message-id=` mỗi lần nhận thư thành công |
| lab-mail | `/var/log/mail.log` | `grep -E "submission.*SASL.*(fail|denied)" /var/log/mail.log` — auth thất bại trên 587 |
| lab-mail | hàng đợi | `postqueue -p`; xóa demo: `postsuper -d ALL deferred` |

Log mẫu của một phiên bị chặn (đúng mẫu hay gặp trong mail.log):

```
postfix/smtpd[1234]: NOQUEUE: reject: RCPT from lab-attacker-xx[192.168.100.20]:
    554 5.7.1 <external@nowhere.test>: Relay access denied;
    from=<ai-do@chu-gia-nao-do.test> to=<external@nowhere.test> proto=ESMTP
postfix/smtpd[1234]: disconnect from lab-attacker-xx[192.168.100.20]
    ehlo=1 mail=1 rcpt=0/1 quit=1 commands=3/4
```

Có thể bật thêm jail `[postfix]` trong fail2ban (logpath `/var/log/mail.log`) để chặn brute-force SMTP AUTH — liên kết trực tiếp với kịch bản B.

#### (8) Biện pháp phòng thủ áp dụng
Nguyên tắc một hàng rào duy nhất cho relay: **`smtpd_relay_restrictions` luôn kết thúc bằng `reject_unauth_destination`** (hoặc `defer_unauth_destination`) và không đặt `mynetworks` rộng; tách vai: 25 chỉ nhận thư server-to-server cho miền mình, người dùng cuối phải vào 587/465 kèm **auth + TLS** (RFC 6409 + RFC 8314); dùng Dovecot SASL làm nguồn auth duy nhất một chỗ; và luôn nghĩ tới "phòng phát hiện": mail.log + fail2ban.

#### (9) Kiểm thử lại sau phòng thủ
1. Chạy lại nguyên văn lệnh swaks bước 2 → nhận `554 5.7.1` → không có thư nào mới vào queue (`postqueue -p` = "Mail queue is empty") → attacker/lab-user không auth **không còn làm được như trước**.
2. Quét bằng chính danh sách người nhận đa dạng: `--to user@gmail.com`, `--to root@mta.edu`... tất cả đều `554` (chỉ đích thuộc `mydestination`/`relaydomains` mới đi tiếp).
3. `swaks --auth` với **sai mật khẩu** → `535` + dòng `SASL: PLAIN auth failed` trong log → thử 6 lần sai từ .20 → jail `[postfix]`/`[dovecot]` ban IP (nối với B).
4. `sudo postconf -n | grep -E "mynetworks|smtpd_relay_restrictions"` đính kèm báo cáo như "cấu hình chuẩn cuối kỳ".

#### (10) Rủi ro và quy tắc an toàn riêng của kịch bản
- Trạng thái `mynetworks=0.0.0.0/0` chỉ tồn tại trong **vài phút**, trong host-only không có đường ra Internet, giữa snapshot trước/sau. Không bao giờ giữ cấu hình này khi bật card NAT.
- Người nhận "bên ngoài" bắt buộc dùng đuôi `.test` (RFC 6761) → kể cả lỡ còn relay sót, DNS không phân giải → không thư nào tới người thật; trước khi rời phòng lab luôn `postsuper -d ALL deferred`.
- Thư demo chứa nội dung giả; không dùng tài khoản/mailbox thật của cá nhân làm người nhận.
- Không gửi thư hàng loạt (dù nội bộ) để "test hiệu năng" — vượt quá nhu cầu bằng chứng, có thể làm nghẽn queue và gợi nhầm hành vi spam.

Nguồn: https://www.postfix.org/SMTPD_ACCESS_README.html ; https://www.postfix.org/postconf.5.html ; https://www.postfix.org/SASL_README.html ; https://datatracker.ietf.org/doc/html/rfc6409 ; https://www.rfc-editor.org/rfc/rfc5321 (STD 10) ; https://www.rfc-editor.org/rfc/rfc8314 (TLS considerations) ; https://www.jetmore.org/john/code/swaks/ ; https://www.kali.org/tools/swaks/ ; https://doc.dovecot.org/

### 7.5 Kết nối ba kịch bản thành một câu chuyện

Ba kịch bản ghép lại thành đúng mô hình của đồ án: **A** chỉ ra vì sao plaintext chết (mật khẩu và dữ liệu lộ trên wire) → dẫn tới phòng thủ bằng mã hóa (SSH/TLS); **B** chỉ ra rằng cả khi đã mã hóa, kênh vẫn bị "mò" (credential guessing) → cần *phát hiện sớm* từ log + phản ứng tự động (fail2ban); **C** chỉ ra dịch vụ mail nếu cấu hình sai thì trở thành kẻ tiếp tay phát tán thư rác → cần thiết kế phân vai (25 vs 587) + bắt buộc xác thực. Mỗi kịch bản đều có vòng "kiểm thử lại sau phòng thủ", biến báo cáo đồ án từ mô tả thành **chứng minh thực nghiệm**: trước/sau có pcap, log excerpt và ảnh chụp màn hình kèm snapshot nhất quán.
