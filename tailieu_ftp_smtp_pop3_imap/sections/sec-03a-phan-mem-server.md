## 3a. Phần mềm triển khai trên Ubuntu Server: vsftpd, OpenSSH, Postfix, Dovecot

Chương này KHÔNG trình bày cấu hình hoàn chỉnh (không có file "copy-paste là chạy"). Mục tiêu của nó là trang bị **kiến thức cần đọc trước**: mỗi phần mềm đóng vai trò gì trong hệ thống, file cấu hình nằm ở đâu, log ghi ra đâu, những tham số nào quan trọng và **ý nghĩa bảo mật của từng tham số**. Khi hiểu bản chất, bạn mới đọc hiểu được cấu hình mẫu và phát hiện được cấu hình sai (misconfiguration) — nguồn gốc của phần lớn sự cố bảo mật dịch vụ.

**Phiên bản tham chiếu (kiểm tra tháng 8/2026):** bản LTS hiện hành của Ubuntu Server là **26.04 LTS "Resolute Raccoon"** (phát hành 23/04/2026, hỗ trợ đến 2031); **24.04 LTS "Noble Numbat"** vẫn được hỗ trợ đầy đủ (đến 04/2029). Chương này lấy mốc **24.04 LTS trở lên**. Hai lưu ý lớn khi làm trên bản mới:

| Thành phần | Ubuntu 24.04 LTS | Ubuntu 26.04 LTS | Hệ quả |
|---|---|---|---|
| vsftpd | 3.0.5 | 3.0.5 | Như nhau (upstream gần như "đóng băng" từ 2021) |
| OpenSSH | 9.6p1 (Canonical chỉ backport vá, không bump bản) | phiên bản mới hơn cùng họ | Cú pháp `sshd_config` ổn định |
| Postfix | 3.8 | 3.10 | Cú pháp ổn định, tham số mới chủ yếu về TLS/DNSSEC |
| Dovecot | **2.3.x** | **2.4.x** | **Cấu hình 2.3 KHÔNG tương thích 2.4** — xem mục 3a.4 |

Toàn bộ lệnh kiểm thử dưới đây chỉ thực hành trên **lab mạng riêng do nhóm sở hữu**.

---

### 3a.1 vsftpd — Very Secure FTP Daemon

#### Vai trò và vị trí trong hệ thống

vsftpd là FTP server mặc định khi nhắc tới "FTP trên Linux" trong các giáo trình quản trị. Nó do Chris Evans viết năm 2000 với mục tiêu "very secure" (tách tiến trình, chạy với quyền thấp, có chroot), nay được Red Hat duy trì; mã nguồn public tại `github.com/richardcochran/vsftpd`, trang chủ `security.appspot.com/vsftpd.html`. Phiên bản upstream mới nhất là **3.0.5 (2021)** — một signal quan trọng: vsftpd được coi là "xong việc, ít thay đổi", không phải dự án chết yểu.

Điểm cần phân biệt ngay với các daemon khác: vsftpd **không phải** daemon "một listen + một fork" kiểu cũ. Trên Debian/Ubuntu nó chạy ở chế độ standalone — **tự chiếm cổng 21 và tự fork tiến trình con** cho mỗi kết nối, dưới systemd unit `vsftpd.service` (không chạy qua socket-activate). Chi tiết bản đóng gói Ubuntu noble: file `/etc/vsftpd.conf` gốc đặt `listen=NO, listen_ipv6=YES` — vsftpd lắng nghe qua socket IPv6 dual-stack (vẫn nhận cả kết nối IPv4); trên các bản chỉ có IPv4 hoặc muốn rõ ràng, quản trị viên bật `listen=YES`.

#### File cấu hình: một file duy nhất, KHÔNG có drop-in

- File chính: **`/etc/vsftpd.conf`** (quy ước Debian/Ubuntu; Red Hat lại dùng `/etc/vsftpd/vsftpd.conf` — đừng nhầm khi đọc tài liệu chéo distro).
- **Kiểm chứng yêu cầu "/etc/vsftpd.conf.d": không tồn tại.** vsftpd upstream **không hỗ trợ thư mục drop-in** và không có directive `include`. Cơ chế gần nhất là `user_config_dir=/etc/vsftpd/conf.d` — nhưng đây là **cấu hình per-user** (mỗi file tên theo username), có từ bản 2.1.x, không phải fragment cấu hình global. Muốn nhiều mảnh cấu hình, quản trị viên phải tự concatenation lúc deploy hoặc chạy nhiều instance.
- File danh sách user: directive `userlist_file` mặc định **`/etc/vsftpd.user_list`**; ngoài ra PAM thường chặn theo **`/etc/ftpusers`** (xem phần PAM).
- Reload: `systemctl reload vsftpd` (vsftpd nhận SIGHUP), hoặc `systemctl restart vsftpd`; trạng thái: `systemctl status vsftpd`.

#### Các tham số PHẢI hiểu (kèm ý nghĩa bảo mật)

Bảng dưới lấy **default upstream** làm mốc; Ubuntu đã vá/ghi đè nhiều giá trị trong `vsftpd.conf` đóng gói — luôn kiểm tra bằng `grep -v '^#' /etc/vsftpd.conf`.

| Tham số | Default upstream | Ý nghĩa & góc nhìn bảo mật |
|---|---|---|
| `anonymous_enable` | **YES (nguy hiểm!)** | Cho phép login không mật khẩu (user `anonymous`/`ftp`). FTP ẩn danh từng là chuẩn Internet nhưng nay là vector phát tán malware và rò rỉ dữ liệu. **Ubuntu chủ động đặt `anonymous_enable=NO` ngay trong file mặc định** (man page Debian/Ubuntu ghi "Default: NO" chính vì bản vá này). Khi audit một hệ thống FTP lạ: đây là dòng đầu tiên phải tìm. |
| `local_enable` | NO | Cho phép user hệ thống (khai báo trong `/etc/passwd`, xác thực qua PAM) đăng nhập FTP. **File `/etc/vsftpd.conf` đóng gói sẵn của Ubuntu đặt tường minh `local_enable=YES`** — vì không có dòng này thì mọi login non-anonymous (kể cả virtual user) đều vô hiệu. |
| `write_enable` | NO | Bật ghi (upload, DELE, RNFR, MKD). Bật `write_enable` đồng nghĩa mở khả năng đối phương **ghi file thực thi/web shell** vào vùng web nếu chroot không nghiêm ngặt — chỉ bật cho nhóm thực sự cần. |
| `local_umask` | 077 | Quyền file tạo bởi user local. umask 022 phổ biến trong hướng dẫn nhưng cho file world-readable; 077 là mặc định " paranoia an toàn" của vsftpd. Ảnh hưởng trực tiếp đến việc ai đọc được dữ liệu vừa upload. |
| `chroot_local_user` | NO | Nhốt user vào home directory. **Không có chroot, một tài khoản FTP là bàn đạp duyệt toàn bộ filesystem** và đọc mọi file mà quyền của tài khoản đó cho phép (kể cả file hệ thống world-readable). vsftpd còn mặc định từ chối nếu chroot không an toàn. |
| `allow_writeable_chroot` | (thêm từ 3.0.0) | vsftpd **cố tình báo lỗi "500 OOPS: vsftpd: refusing to run with writable root inside chroot()"** (ràng buộc được giới thiệu từ bản 2.3.5, 2011) khi thư mục chroot thuộc sở hữu của user và ghi được — vì kỹ thuật `bind mount`/escape khỏi writable chroot là có thật. Cần upload ngay tại root chroot thì đặt `allow_writeable_chroot=YES`, nhưng hiểu rằng bạn **đánh đổi một lớp phòng vệ**; giải pháp sạch hơn: chroot thuộc `root:root`, có thư mục con `upload/` cho user ghi. |
| `pasv_enable`, `pasv_min_port`, `pasv_max_port` | YES / 0 / 0 | FTP chủ động (active, PORT) vs bị động (passive, PASV). Passive: server báo một cổng dữ liệu ngẫu nhiên trong khoảng `pasv_min_port..pasv_max_port` (0 = bất kỳ, do kernel chọn). Với firewall/NAT: **chặn mọi thứ trừ 20-21 rồi mở đúng dải đã cấu hình**, ví dụ giới hạn 30000–30009 — biến "cổng dữ liệu không đoán được" thành dải hữu hạn có audit trail. |
| `ssl_enable`, `rsa_cert_file`, `rsa_private_key_file`, `allow_anon_ssl` | NO / (upstream: `/usr/share/ssl/certs/vsftpd.pem`; Ubuntu ghi đè thành snakeoil) / — | FTP gốc **gửi plaintext cả user lẫn password** (RFC 959 không có TLS; phần mở rộng bảo mật là RFC 2228, và FTPS/EXPlicit TLS chuẩn hoá ở RFC 4217). Bật `ssl_enable=YES` + cặp chứng chỉ để dùng FTPES trên cổng 21 (lệnh `AUTH TLS`); `force_local_data_ssl`/`force_local_logins_ssl` mới thực sự chặn version không mã hoá. `allow_anon_ssl` chỉ đáng quan tâm khi còn bật anonymous. Ubuntu default trỏ `rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem` (chứng chỉ tự ký của gói `ssl-certs`) — đủ mã hoá nhưng **không xác thực được danh tính** (client phải tự chấp nhận fingerprint). |
| `userlist_enable`, `userlist_deny`, `userlist_file` | NO / YES / `/etc/vsftpd.user_list` | Bộ lọc danh sách user. `userlist_deny=YES` = danh sách là **blacklist** (chặn những người có tên); `=NO` = biến nó thành **whitelist** — cách gọn nhất để chỉ 2–3 account được dùng FTP mà không đụng `/etc/passwd`. (Chú ý tên đúng của directive là `userlist_file`, không phải `user_list_file` — rất nhiều blog viết sai.) |
| `secure_chroot_dir` | upstream: `/usr/share/empty`; Ubuntu đặt tường minh `secure_chroot_dir=/var/run/vsftpd/empty` trong config đóng gói (unit có `ExecStartPre=mkdir -p` cho nó) | Trong model tách tiến trình của vsftpd, các tiến trình con **nhảy (chroot) vào một thư mục rỗng trước khi đổi quyền** thành user không có quyền gì; đây là "xưởng giam giữ tạm". Nếu trỏ sai (không tồn tại), service không khởi động được — và về nguyên lý, đừng bao giờ trỏ nó vào nơi có dữ liệu. |

Ví dụ một đoạn file cấu hình mẫu dạng "dòng nào ra dòng ấy" chỉ để học đọc:

```bash
anonymous_enable=NO          # tắt ẩn danh — Ubuntu mặc định đã NO, đừng bật lại
local_enable=YES             # cho user hệ thống đăng nhập
write_enable=YES             # cho phép upload
local_umask=022              # file upload ra 644 — cân nhắc 077
chroot_local_user=YES        # nhốt user vào home
allow_writeable_chroot=YES   # CHẤP NĂN: cho phép ghi trong chroot — xem bảng trên
pasv_enable=YES
pasv_min_port=30000          # mở firewall đúng dải này
pasv_max_port=30009
ssl_enable=YES               # bật FTPES
rsa_cert_file=/etc/ssl/certs/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.key
force_local_logins_ssl=YES   # bắt buộc cả lệnh USER/PASS đi qua TLS
userlist_enable=YES
userlist_deny=NO             # whitelist
userlist_file=/etc/vsftpd.ftpusers_allowed
```

#### PAM: cánh cửa xác thực thật sự

vsftpd **không tự quản lý mật khẩu**; nó đặt `pam_service_name=vsftpd` (mặc định) và giao việc xác thực cho PAM qua `/etc/pam.d/vsftpd`. Trên Ubuntu file này include cấu hình COMMON (`common-auth`, `common-account`) — nghĩa là:

- User nào login được Linux **mặc định login được FTP**, kể cả tài khoản dịch vụ — trừ khi bị chặn bởi `/etc/ftpusers` (PAM `pam_listfile.so sense=deny` thường được kích hoạt ở đây) hoặc bởi whitelist `user_list`.
- Vì vậy khi điều tra "vì sao tài khoản X vẫn vào được FTP" phải đọc **cả ba lớp**: `/etc/vsftpd.conf`, `/etc/pam.d/vsftpd`, `/etc/ftpusers` (và `/etc/shells` nếu bật `check_shell`).
- Mật khẩu trong PAM đến từ `/etc/shadow` (hash) — nhưng **đường truyền vẫn plaintext nếu chưa bật `ssl_enable`**, nên đổi mật khẩu mạnh không thay thế được TLS.

#### Log: hai chế độ, kiểm tra cái nào đang bật

- Default upstream của `xferlog_enable` là **NO**, nhưng file `/etc/vsftpd.conf` đóng gói của Ubuntu đặt tường minh `xferlog_enable=YES` (man page Ubuntu ghi "Default: NO (but the sample config file enables it)"). Khi bật và `xferlog_std_format=NO` như mặc định, vsftpd ghi log "kiểu vsftpd" vào **syslog** (facility `ftp`) → trên Ubuntu đọc qua `/var/log/syslog` hoặc `journalctl -u vsftpd`; nếu muốn vào file riêng thì đặt `xferlog_file=/var/log/vsftpd.log` (hoặc `vsftpd_log_file=` — directive riêng cho log kiểu vsftpd).
- `xferlog_std_format=YES` đổi sang format wu-ftpd `xferlog` cũ → `/var/log/xferlog` (mặc định của `xferlog_file` ở upstream; ít gặp).
- Log FTP chỉ có giá trị khi nó còn ghi được: giám sát dung lượng, và nhớ rằng log plaintext (login thành công/thất bại) là đầu vào vàng cho phân tích brute force ở chương phát hiện sớm.

```bash
systemctl status vsftpd          # đơn vị + log gần nhất
ss -tlnp | grep ':21\b'          # cổng điều khiển 21 có listen không
# Lưu ý: cổng PASV KHÔNG xuất hiện trong ss -tlnp — không có tiến trình nào "listen" sẵn
# cả dải; mỗi phiên dữ liệu chỉ tạm thời chiếm một cổng trong dải 30000-30009.
# Bắt được nó khi đang transfer: ss -tnp | grep -E ':3000[0-9]\b'
```

**Nguồn:** https://security.appspot.com/vsftpd.html — https://manpages.ubuntu.com/manpages/noble/man5/vsftpd.conf.5.html — https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/s2-ftp-servers-vsftpd (bảng tham số vsftpd chuẩn của Red Hat) — https://github.com/richardcochran/vsftpd — RFC 959, RFC 4217 (https://www.rfc-editor.org/rfc/rfc959, https://www.rfc-editor.org/rfc/rfc4217).

---

### 3a.2 OpenSSH Server: SFTP không phải một "dịch vụ cài riêng"

#### Vai trò: Subsystem của sshd

Điểm nhận thức đầu tiên: **không có gói `sftp-server` riêng để bật trên Ubuntu** — SFTP là một *subsystem* chạy bên trong phiên SSH đã xác thực, do `sshd` điều phối. Hệ quả: **Ubuntu Server có SSH bật sẵn thì mặc nhiên có SFTP**, không cần cài gì thêm (`openssh-server` gần như luôn có mặt sau install, nếu người cài đặt tick "Install OpenSSH server"). SSH đồng thời gánh cả remote shell — nghĩa là mọi hardening SSH (mục 2.4) tự động là hardening cho SFTP, và ngược lại cấu hình SSH cẩu thả mở cửa SFTP.

#### Cấu trúc file cấu hình và cơ chế Include

- File chính: **`/etc/ssh/sshd_config`** — dòng đầu file mặc định của Ubuntu: `Include /etc/ssh/sshd_config.d/*.conf`.
- Từ OpenSSH 7.3+, các fragment trong **`/etc/ssh/sshd_config.d/`** (xếp theo thứ tự bảng chữ cái, ưu tiên cao hơn định nghĩa sau) là cách Ubuntu quản trị: ví dụ `50-cloud-init.conf` đặt `PasswordAuthentication`. **Lưu ý có tính bẫy:** directive đầu tiên thắng (first-match) với nhiều tham số SSH — nếu `sshd_config` định nghĩa `PermitRootLogin` trước khi Include, fragment có thể bị "che". Audit nhanh cấu hình hiệu dụng: `sshd -T | grep -E 'permitrootlogin|passwordauthentication|subsystem'`.
- Reload an toàn: `systemctl reload ssh` (Ubuntu dùng tên unit **`ssh`**, không phải `sshd`; trên 24.04 có song song `ssh.socket` cho socket-activation nhưng service `ssh.service` vẫn là chuẩn để reload). Test cú pháp trước reload: `sshd -t`.

#### `Subsystem sftp internal-sftp` — tại sao không phải binary cũ?

Dòng khai báo trong `sshd_config`:

```bash
Subsystem sftp internal-sftp   # SFTP server chạy TRONG TIẾN TRÌNH sshd
# Subsystem sftp /usr/lib/openssh/sftp-server   # kiểu cũ: fork binary riêng
```

Lý do chọn `internal-sftp` khi muốn làm chroot:

1. binary `sftp-server` cũ phải được **copy vào trong từng jail chroot** (kèm thư viện) — dễ sai, khó vá;
2. `internal-sftp` **có sẵn trong tiến trình sshd đang giữ session**, nên `ChrootDirectory` hoạt động mà không cần filesystem tối giản nào.

#### `ChrootDirectory` và quy tắc sở hữu root:root — giải thích tận gốc

```bash
Match Group sftpusers
    ChrootDirectory /srv/sftp/%u   # jail theo user
    ForceCommand internal-sftp -u 0077  # chỉ SFTP, không cho shell, umask chặt
    PasswordAuthentication no      # group này chỉ key-based
```

Điều kiện bắt buộc (nếu vi phạm, sshd từ chối session kèm "bad ownership or modes"): **mọi thành phần của đường dẫn jail, từ `/` đến tận cùng, phải do `root` sở hữu và không được group/world-writable.** Lý do bảo mật rất cụ thể: nếu thư mục cha của jail do user viết được, attacker upload một `authorized_keys`/thư mục con **bên ngoài** jail rồi bind vào trong, hoặc thao túng symlink để phá vỡ jail — chroot chỉ là thay đổi root path, không phải sandbox kiểu container. Jail an toàn là `root` "xây tường", user chỉ được quyền ghi vào **một thư mục con được trỏ riêng** (thường mount loop hoặc đặt trong jail với quyền sở hữu khác).

#### Các tham số an toàn cốt lõi (đọc để audit)

| Tham số | Mặc định Ubuntu | Ý nghĩa bảo mật |
|---|---|---|
| `PermitRootLogin` | `prohibit-password` (mặc định upstream, Ubuntu không ghi đè trong `sshd_config`; cloud image còn khoá mật khẩu root ở `/etc/shadow`) | root chỉ vào được bằng key → chặn brute-force mật khẩu root; đặt `no` khi có tài khoản quản trị riêng. |
| `PasswordAuthentication` | `yes` | Bật mật khẩu = mở cửa cho dictionary attack qua cổng 22. Chuẩn hardening: chuyển `no`, buộc `PubkeyAuthentication yes`. |
| `PubkeyAuthentication` | `yes` | Xác thực khoá công khai — nếu tắt thì mọi nỗ lực hardening "tắt mật khẩu" phản tác dụng (không ai vào được). |
| `MaxAuthTries` | 6 | Số lần thử mỗi kết nối (tính theo connection, không phải theo phiên) — giảm tốc brute force; song hành với `LoginGraceTime`. |
| `Ciphers`, `MACs`, `KexAlgorithms` | chỉ thuật toán hiện đại | SSHv1 bị loại bỏ hoàn toàn; keyword `Protocol` thậm chí **đã bị xóa khỏi sshd_config từ OpenSSH 7.6** (ghi vào sẽ bị "Bad configuration option"). Với SFTP cùng kênh transport, thuật toán yếu sẽ làm cả kênh yếu. |

#### Log và giám sát

SSH ghi qua facility `auth`: `/var/log/auth.log` (rsyslog) hoặc `journalctl -u ssh -f`. Đây là nơi thấy: `Failed password for ... from <ip> port ... ssh2` (brute force), `Accepted publickey for ...` (thành công bằng key), và khi jail sai: `Starting session: subsystem 'sftp' for ...` hoặc `fatal: bad ownership or modes for chroot directory`. `ss -tlnp | grep :22` xác nhận sshd listen; trên môi trường dùng socket-activation, port 22 do `systemd` giữ (cột PID/user hiện `systemd`/`sshd`).

**Nguồn:** https://man.openbsd.org/sshd_config (portable man pages do OpenSSH project duy trì — https://www.openssh.com/portable.html) — https://documentation.ubuntu.com/release-notes/26.04/ — https://canonical.com/blog/canonical-releases-ubuntu-26-04-lts-resolute-raccoon.

---

### 3a.3 Postfix — Mail Transfer Agent (MTA)

#### Kiến trúc: `master.cf` là "bản đồ dịch vụ", `main.cf` là "luật chơi toàn cục"

Postfix tách hai loại cấu hình, và hiểu đúng chỗ nào đặt gì là nửa cuộc chiến:

- **`/etc/postfix/master.cf`** — định nghĩa **dịch vụ nào chạy, tiến trình nào phục vụ, mode gì**: mỗi dòng gồm service name (`smtp`, `submission`, `smtps`, `lmtp`, `pickup`...), type (inet/unix), process management, và daemon tương ứng (`smtpd` cho nhận mail, `qmgr`, `cleanup`, `smtp` client...). Muốn bật cổng 465/587, sửa `master.cf` — không phải `main.cf`.
- **`/etc/postfix/main.cf`** — **hàng trăm tham số toàn cục** (`postconf` đọc/ghi được; `postconf -n` in ra các giá trị hiệu dụng khác mặc định — công cụ audit số 1).
- Chạy dưới systemd: `systemctl status postfix`, đổi cấu hình xong `systemctl reload postfix`.

#### Nhóm tham số quyết định "tôi là ai, nhận mail cho domain nào, relay cho ai"

```bash
myhostname = mail.lab.internal      # FQDN chính mình (EHLO advertise tên này)
mydomain = lab.internal
mydestination = $myhostname, localhost.$mydomain, lab.internal
                                  # chỉ những domain liệt kê ở đây được coi là
                                  # mail "nội bộ" — deliver vào local mailbox;
                                  # domain khác → Postfix chỉ relay hoặc từ chối
inet_interfaces = all             # interface nào LẮNG NGHE 25; `loopback-only` nếu
                                  # chỉ máy này tự gửi (đóng vai satellite)
mynetworks = 127.0.0.0/8, ::1     # AI ĐƯỢC coi là "mạng tin cậy"
```

**Mổ xẻ `mynetworks` — nguồn gốc open relay.** `mynetworks` khai báo dải IP mà Postfix **mặc nhiên cho relay không cần xác thực**. Error kinh điển của quản trị mới: đặt

```bash
mynetworks = 0.0.0.0/0    # ← TUYỆT ĐỐI TRÁNH
```

`0.0.0.0/0` = "mọi IP trên Internet đều là người nhà" → kẻ tấn công dùng mail server của bạn gửi spam thiên hạ, bạn bị liệt vào **blocklist** (chẳng hạn Spamhaus), bị nhà mạng cô lập; server của bạn trở thành **open relay** — và các scanner (được các botnet vận hành) quét toàn Internet tìm loại này mỗi ngày. `mynetworks` đúng nghĩa là **dải quản trị**, thường chỉ loopback + subnet nội bộ; mọi thứ ngoài đó phải vượt qua lớp xác thực bên dưới.

#### Relay restrictions — "hàng rào" thật sự, đọc từ trái sang phải

```bash
smtpd_relay_restrictions = permit_mynetworks,
                           permit_sasl_authenticated,
                           reject_unauth_destination
```

Đây là **mặc định của Postfix 3.x trên Ubuntu** (các bản cũ dùng `smtpd_recipient_restrictions`, vẫn hiểu tương tự nhưng relay restrictions tách riêng từ 3.0): Postfix duyệt list theo thứ tự, gặp `permit` thì cho qua, gặp `reject` thì chặn; `reject_unauth_destination` là chốt chặn cuối — **không phải mạng tin cậy, không xác thực SMTP AUTH → không nhận chuyển tiếp**. Khi đọc mail server bị tố spam, hai việc đầu tiên: `postconf -n | grep -E 'mynetworks|relay_restrictions'` và thử chính `reject_unauth_destination` có nằm cuối list không (đứng trước `permit` vô tội vạ là hỏng).

#### TLS: biến SMTP plaintext thành có mã hoá

```bash
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem   # cert cho EHLO STARTTLS
smtpd_tls_key_file  = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level = may    # opportunistic; `encrypt` = bắt buộc TLS (RFC 8314
                                  # khuyến nghị TLS cho mọi kết nối mail client-facing)
```

Cùng cặp khoá, cấu hình cho **submission**: bật/hai service trong `master.cf` — `submission` (port **587**, RFC 6409 — cổng cho *client gửi mail*, luôn đòi AUTH + TLS) và `smtps` (port **465**, SMTP-over-TLS "implicit"; từng bị bỏ rơi nay được RFC 8314 công nhận lại). Trên `master.cf` mỗi service có thể override riêng, ví dụ `submission` gán `-o smtpd_tls_security_level=encrypt -o smtpd_sasl_auth_enable=yes`.

#### Delivery cục bộ và hàng đợi

- `mailbox_command` (mặc định để trống → Postfix tự deliver) có thể trỏ về **Dovecot LMTP/delivery** để thống nhất một "người giữ hòm thư" — xem 3a.5.
- `mailbox_size_limit` (default **51200000 byte ≈ 50MB** — kiểm chứng bằng `postconf -d | grep mailbox_size_limit`): chặn "mail bomb" làm đầy `/var/spool/mail` và filesystem. Khác với `message_size_limit` (chặn ngay ở bước RCPT, mặc định ~10MB), `mailbox_size_limit` chỉ phát hiện lúc **giao thư tại chỗ** — mail vượt ngưỡng bị local/LMTP từ chối và bounce chứ không reject từ xa.
- **Hàng đợi (queue):** mail chưa đi được nằm trong `/var/spool/postfix/{active,deferred,incoming}`. Công cụ quan sát: `postqueue -p` (liệt kê, xem status/bounce reason), `postqueue -f` (ép thử lại), `postsuper -d <queue_id>` (xoá mail kẹt), `postsuper -d ALL deferred` (dọn bão bounce — dùng thận trọng, trong lab).
- Mail người dùng cuối: `~/Maildir` hoặc `/var/spool/mail/<user>` (mbox) — cùng tệp mà Dovecot sẽ đọc.

#### Log

Toàn bộ hoạt động mail vào facility `mail`/`auth` → **`/var/log/mail.log`** (`tail -f mail.log` khi test là phản xạ bắt buộc), kèm syslog id (`syslog_name`). Mỗi bước SMTP hiện nguyên: `connect from ...`, `client-hello`, `to=<rcpt>, relay=..., delay=..., status=sent/deferred/bounced` — status line này là chuỗi "evidence" đẹp nhất để dạy về hành vi relay.

```bash
postconf -n                    # dump cấu hình hiệu dụng
ss -tlnp | grep -E ':(25|465|587)\b'   # Postfix listen cổng nào qua master.cf
systemctl status postfix && systemctl reload postfix
```

**Nguồn:** https://www.postfix.org/BASIC_CONFIGURATION_README.html — https://www.postfix.org/postconf.5.html (định nghĩa từng tham số, gồm `mynetworks`, `smtpd_relay_restrictions`) — https://www.postfix.org/SASL_README.html — RFC 5321 (SMTP), RFC 6409 (submission), RFC 8314 (TLS cho mail — https://www.rfc-editor.org/rfc/rfc8314).

---

### 3a.4 Dovecot — Mail Retrieval Agent (POP3/IMAP) và "ngân hàng mật khẩu" của cả hệ thống

#### Vai trò kép

Dovecot không chỉ là server **IMAP (143/993) và POP3 (110/995)** để user kéo mail về; nó còn là **auth server dùng chung**: Postfix "hỏi" Dovecot "đúng mật khẩu này không" qua SASL socket (mục 3a.5). Nói Dovecot là thành phần bảo mật *tập trung* nhất của stack mail là không ngoa.

**CẢNH BÁO phiên bản — phát hiện khi nghiên cứu cho chương này:** trên **Ubuntu 26.04 LTS, Dovecot được đóng gói ở dòng 2.4** (nguồn: Ubuntu Discourse warning + Launchpad changelog), và **file cấu hình 2.3 hoàn toàn không tương thích 2.4**: dòng đầu `dovecot.conf` phải là `dovecot_config_version`, các tên setting trong `conf.d/` đã đổi/di dời; service 2.4 sẽ **từ chối khởi động** nếu đọc cấu hình 2.3 cũ. Nội dung tiếp theo mô tả cấu trúc **2.3 (Ubuntu 24.04)** — khi làm trên 26.04, dùng `doveconf -n` để đối chiếu và xem hướng dẫn upgrade chính thức (link Nguồn bên dưới).

#### Cấu trúc đánh số: `/etc/dovecot/conf.d/`

Dovecot dùng `!include conf.d/*.conf`, đọc theo thứ tự tên file số — quy tắc "số to thắng số nhỏ". Các file quan trọng:

- **`10-auth.conf`** — xác thực. `disable_plaintext_auth = yes` (mặc định an toàn của Dovecot): **từ chối cơ chế LOGIN/PLAIN khi kênh chưa có TLS** → chặn password dạng rõ (plaintext) bay trên mạng; chỉ nới `= no` cho kết nối từ loopback. `auth_mechanisms = plain login` quyết định Postfix sẽ được phép "đại diện" xác thực bằng cơ chế nào (thêm `gssapi`/`scram-sha-256`... tuỳ môi trường).
- **`10-mail.conf`** — nơi hòm thư nằm: `mail_location = maildir:~/Maildir` (thư mục riêng, mỗi mail một file — an toàn khi đồng thời nhiều reader, và là kiểu Dovecot khuyến nghị) vs `mbox:~/mail:INBOX=/var/spool/mail/%u` (một file to, lock khi đọc — dễ deadlock, chậm với mailbox lớn; trên 2.4, `mail_location` bị **bỏ hẳn**, tách thành `mail_driver`/`mail_path`/`mail_inbox_path` và driver mbox bị đóng băng — không phát triển thêm). Cùng file này đặt `mail_privileged_group = mail` (quyền đọc `/var/spool/mail`).
- **`10-master.conf`** — khai báo port/process mỗi service (`service imap-login`, `service pop3-login`: `inet_listener imap { port = 143 }`, `inet_listener imaps { port = 993 }`...). **Đây cũng là nơi mở socket SASL cho Postfix** (`unix_listener /var/spool/postfix/private/auth { mode = 0660 user = postfix group = postfix }`) — đặt quyền đúng để process `postfix:smtpd` đọc được mà user thường không đọc/ghi được.
- **`10-ssl.conf`** — `ssl = required` (ép TLS cho mọi login), `ssl_cert`/`ssl_key`, `ssl_min_protocol = TLSv1.2`, danh sách `ssl_protocols`. POP3/IMAP mặc định plaintext → TLS qua STARTTLS cùng cổng (143/110) hoặc cổng TLS-khép kín riêng (993/995). Đây là tham số biến "rò mật khẩu khi user check mail ở quán cà phê" thành bất khả thi về mặt nghe lén.
- `auth-passwdfile.conf.ext`, `passdb`/`userdb`: nguồn mật khẩu — hệ thống (`passdb { driver = pam }`, mặc định trong gói distro) hoặc file riêng của Dovecot (`driver = passwd-file`, trỏ tới file dạng `user:{SHA512-CRYPT}hash`).

Khái niệm **namespace INBOX**: hòm thư "đến" chuẩn (`mail_location` + namespace default INBOX) — hiểu nó để biết vì sao Postfix LMTP ghi vào đâu thì Dovecot đọc từ đó.

**LMTP (Local Mail Delivery Agent):** thay vì Postfix tự ghi hòm thư, chuyển `mailbox_command`/`transport` sang Dovecot qua **`service lmtp`** (unix socket hoặc `inet_listener lmtp { port = 24 }` trong cùng `10-master.conf`). Lợi ích: một chỗ duy nhất quyết định quota, sieve filter, format maildir; Dovecot wiki/doc gọi đây là bài toán của stack tích hợp.

Chẩn đoán nhanh bằng công cụ của chính Dovecot:

```bash
doveconf -n          # dump cấu hình HIỆU DỤNG (sau khi merge conf.d) — dùng khi audit
doveadm auth test kim "matkhau"   # (trong lab) hỏi thẳng passdb: đúng/sai?
ss -tlnp | grep -E ':(110|143|993|995)\b'
systemctl reload dovecot     # sau khi sửa conf.d; systemctl restart khi đổi passdb
```

**Nguồn:** https://doc.dovecot.org/2.3/configuration_manual/ (bản archive không còn được maintain — Dovecot gắn cảnh báo rõ trên trang) — https://doc.dovecot.org/main/howto/sasl/postfix.html ("Postfix with Dovecot SASL", hướng dẫn tích hợp Postfix↔Dovecot) — https://doc.dovecot.org/main/installation/upgrade/2.3-to-2.4.html — https://discourse.ubuntu.com/t/warning-dovecot-2-4-incompatible-with-2-3-config-files/68786 — https://launchpad.net/ubuntu/+source/dovecot/+changelog — RFC 9051 (IMAP4rev2, thay 3501), RFC 1939 (POP3), RFC 2033 (LMTP) — https://www.rfc-editor.org/standards.

---

### 3a.5 Mối liên kết giữa bốn thành phần: ai giữ user, ai nói với ai

Đây là phần dễ bị bỏ qua nhưng trả lời câu hỏi "vì sao đổi mật khẩu chỗ nào đó mà ba dịch vụ cùng ảnh hưởng".

#### Sơ đồ luồng trên một máy Ubuntu Server

```
                    ┌──────────────────────── systemd ────────────────────────┐
Client FTPES ─:21──▶│ vsftpd ──(PAM: /etc/pam.d/vsftpd)──▶ /etc/shadow        │
Client SFTP  ─:22──▶│ sshd  ──(subsystem internal-sftp)──▶ /etc/shadow        │
Client SMTP ─:25/587▶ Postfix smtpd ──(SASL qua unix socket)──┐               │
                                                              ▼               │
                                                    Dovecot auth (passdb)     │
Client POP3/IMAP :110/143/993/995 ─────────────────────────▶ Dovecot login    │
                                                              │ mail_location ▼
                                     Postfix LMTP ───────────▶│  Maildir /var/spool/mail │
                    └──────────────────────────────────────────────────────────────────┘
```

- **Chủ quyền tài khoản:** vsftpd và sshd **đều không giữ mật khẩu riêng** — cả hai xác thực qua PAM/`/etc/shadow` (trên Ubuntu 24.04+ có thể là yescrypt). Dovecot mặc định (`passdb { driver = pam }` hoặc `system`) cũng đọc cùng nguồn. Vì vậy **một user Linux = login được cả ba**, và `userdel`/khoá account (`passwd -l`) cắt luôn FTP/SFTP/IMAP — đó là điểm kiểm soát tập trung, cũng là điểm khuếch đại rủi ro.
- **Postfix gửi câu hỏi xác thực cho Dovecot:** trong `main.cf`, `smtpd_sasl_type = dovecot` + `smtpd_sasl_path = private/auth` khiến Postfix không tự verify password mà **kết nối tới unix socket do Dovecot tạo trong `10-master.conf`** (`/var/spool/postfix/private/auth`, mode 0660 user/group `postfix`). Người dùng SMTP AUTH vì thế dùng đúng mật khẩu IMAP — không có "database thứ hai" để lệch. Socket nằm trong **chroot của Postfix** (`/var/spool/postfix`) — đặt sai đường dẫn là triệu chứng "AUTH không xuất hiện trong EHLO".
- **Chuỗi delivery:** Postfix nhận → (quyết định local hay relay) → chuyển cho Dovecot qua **LMTP** hoặc tự ghi; Dovecot serve POP3/IMAP đọc cùng thư mục theo `mail_location`.
- **Góc systemd:** mỗi service là một unit (`vsftpd`, `ssh`, `postfix`, `dovecot`) — độc lập restart/reload, và `journalctl -u <dịch vụ>` cho log chuẩn hoá. Kiểm tra trạng thái tổng: `systemctl status vsftpd ssh postfix dovecot --no-pager`.

#### Ví dụ xuyên suốt một hành vi

Alice upload web-shell qua FTPES bằng account của cô (vsftpd → PAM → `/etc/shadow`), trong lúc Carol gửi spam qua `:587` (Postfix → socket Dovecot → **cùng passdb**). Khi điều tra: `mail.log` chỉ ra Alice? Không — chỉ ra Carol; `auth.log` ghi SSH của cả hai; muốn đóng Carol khỏi *mọi* dịch vụ cùng lúc: khoá tài khoản Linux — và vì sao **phải audit cả `/etc/ftpusers` + whitelist vsftpd**, bởi "chủ quyền tập trung" nghĩa là một account bị lộ là ba mặt trận bị lộ.

#### Checklist quan sát nhanh trong lab

```bash
ss -tlnp | grep -E ':(21|22|25|110|143|465|587|993|995)\b'   # dịch vụ nào đang thật sự bật
postconf -n; doveconf -n; sshd -T | head; grep -vE '^(#|$)' /etc/vsftpd.conf
journalctl -u postfix -u dovecot -u vsftpd -u ssh --since "10 min ago"
```

Ghi nhớ điều xuyên suốt chương: **mỗi tham số đã học ở trên đều biến thành một dòng có thể grep, một cổng có thể `ss`, và một sự kiện có thể log** — đó là ba kênh (cấu hình — mạng — nhật ký) để "phát hiện sớm" ở các chương sau khai thác.

---

*Tài liệu chỉ dùng cho mục đích học tập & phòng thủ trong lab riêng của nhóm; mọi nội dung liên quan brute force, open relay hay escape chroot được trình bày ở mức "vì sao nó xảy ra", không phải hướng dẫn khai thác hệ thống thật.*
