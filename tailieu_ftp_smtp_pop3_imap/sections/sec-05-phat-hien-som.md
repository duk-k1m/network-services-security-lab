## 5. Kỹ thuật phát hiện sớm qua log và metric

Mục tiêu của chương này là trả lời câu hỏi: **làm sao biết hệ thống FTP/SFTP, SMTP, POP3, IMAP của mình đang bị dòm ngó sớm nhất có thể**, trước khi thiệt hại xảy ra (tài khoản bị chiếm, mail bị gửi lậu, dữ liệu bị lấy đi). Ý tưởng cốt lõi rất đơn giản: mọi hành vi — dù là người dùng hợp lệ hay kẻ tấn công — đều để lại dấu vết trong nhật ký hệ thống (log) và trong các đại số đo được (metric) như số kết nối mỗi phút, độ sâu hàng đợi mail. Phát hiện sớm = biến các dấu vết đó thành cảnh báo có ngưỡng, và xử lý cảnh báo nhầm cho gọn dần theo thời gian.

Toàn bộ kỹ thuật trong chương được minh họa trong **lab mạng riêng do nhóm sở hữu** (máy ảo Ubuntu dựng ở các chương trước). Trong lab, nhóm vừa là "quản trị" vừa đóng vai "người dùng hợp lệ" và "kẻ tấn công" (chạy các công cụ dò mật khẩu như hydra/medusa chỉ trên máy của mình, đã kiểm soát) để tạo log thật rồi quan sát hệ thống phát hiện. Không áp dụng các thao tác này lên hệ thống công cộng.

Với **mỗi hành vi bất thường**, chương trình bày đủ 4 vế theo một khuôn chung:

1. **Cách phát hiện**: lệnh `grep`/`journalctl`/bộ lọc Fail2ban/đồ thị metric đơn giản;
2. **Cặp log mẫu "bình thường vs đáng ngờ"** — đúng định dạng syslog thực tế mà dịch vụ sinh ra;
3. **Ngưỡng đề xuất ban đầu** kèm biện luận tại sao chọn con số đó;
4. **False positive (dương tính giả — cảnh báo nhầm)** có thể xảy ra và cách chỉnh ngưỡng.

### 5.1 Chuẩn bị: các dịch vụ ghi log vào đâu

Trên Ubuntu Server LTS (bản hành hiện nay là **26.04 LTS "Resolute Raccoon"**, phát hành 23/4/2026; bản 24.04 LTS vẫn được hỗ trợ song song), các daemon mạng ghi log theo chuẩn syslog — dòng log có dạng:

```
Tháng  Ngày  Giờ   hostname  tên_tiến_trình[PID]: nội dung
```

Ví dụ thật: `Aug 29 10:15:02 mailserver postfix/smtpd[1234]:` — ngày tháng kiểu `MMM DD HH:MM:SS` (định dạng syslog BSD cổ điển, RFC 3164; bản hiện đại là RFC 5424 nhưng file log cục bộ vẫn dùng kiểu cũ).

Mặc định, rsyslog nhận log từ journald rồi gom vào các file ở `/var/log`. Bảng nguồn log cần nhớ:

| Dịch vụ | Ghi vào đâu (mặc định Ubuntu) | Ghi chú bật thêm |
|---|---|---|
| vsftpd (FTP) | `/var/log/auth.log` (dòng PAM `pam_unix(vsftpd:auth)` — có sẵn khi xác thực fail) | Bật `syslog_enable=YES` → message riêng của vsftpd ghi qua **facility `ftp`**, rsyslog mặc định của Ubuntu đưa vào `/var/log/syslog` (chứ không phải auth.log); bật `dual_log_enable=YES` → có thêm `/var/log/vsftpd.log` dễ đọc hơn, và `xferlog_enable=YES` → `/var/log/xferlog` cho nhật ký chuyển file |
| OpenSSH/SFTP | `/var/log/auth.log` | SFTP đi qua `sshd` nên dùng chung một nguồn log |
| Postfix (SMTP) | `/var/log/mail.log` | Mặc định đã ghi rất chi tiết |
| Dovecot (POP3/IMAP) | `/var/log/mail.log` | Thêm `auth_verbose = yes` để log rõ lý do fail xác thực |

Hai điểm dễ vấp trong lab:

- Nếu cài Ubuntu bằng **bản ảnh "minimized"** (tối giản), rsyslog **không được cài sẵn** — không có `/var/log/auth.log` hay `/var/log/mail.log`, mọi thứ chỉ nằm trong journald. Cách xử lý: `apt install rsyslog && systemctl enable --now rsyslog`, hoặc dùng thẳng `journalctl`.
- Journald (systemd journal) là bản gốc của mọi log; đọc trực tiếp bằng:

```bash
journalctl -u ssh -u postfix -u dovecot --since "10 min ago"   # log 3 dịch vụ, 10 phút qua
journalctl -t sshd -p warning --since today                     # chỉ message mức warning trở lên
journalctl -f                                                 # theo dõi trực tiếp (giống tail -f)
```

Trong lab phần lớn ví dụ dùng `grep`/`awk` trên file text cho dễ quan sát; khi ra môi trường thật với nhiều máy, nên gom log về một chỗ (rsyslog gửi UDP/TCP đi, hoặc SIEM — xem 5.10).

Nguồn:
- https://documentation.ubuntu.com/release-notes/26.04/ (phiên bản LTS hiện hành)
- https://www.rfc-editor.org/rfc/rfc5424 (định dạng syslog)
- https://manpages.ubuntu.com/manpages/noble/man5/vsftpd.conf.5.html (các tham số log của vsftpd)

### 5.2 Nhiều lần đăng nhập thất bại từ một IP (brute-force)

**Bản chất.** Đây là tín hiệu cổ điển nhất: kẻ tấn công dùng danh sách mật khẩu (password spraying) hoặc dictionary để thử đăng nhập. Đặc trưng máy móc của nó: **tốc độ** — một script có thể thử hàng chục lần mỗi phút, trong khi người dùng thật gõ sai lắm cũng 2–3 lần trong vài chục giây rồi dừng lại nghĩ.

**Cách phát hiện.** Quan sát theo cặp IP nguồn ↔ số lần fail:

```bash
# Đếm số lần "Failed password" theo IP nguồn trong auth.log hiện hành (sshd)
grep "Failed password" /var/log/auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
  | sort | uniq -c | sort -rn | head -10        # top 10 IP fail nhiều nhất
```

Với Fail2ban, đây chính là việc của nó — không cần tự viết lệnh (cấu hình mẫu ở 5.10).

**Cặp log mẫu.** sshd (SFTP):

```log
# BÌNH THƯỜNG — một phiên đăng nhập hợp lệ:
Aug 29 10:16:10 server sshd[4010]: Accepted password for bob from 192.168.1.50 port 50000 ssh2
# ĐÁNG NGỜ — cùng IP này 2 giây sau lại fail, lặp hàng chục lần liên tiếp:
Aug 29 10:15:02 server sshd[4001]: Failed password for bob from 203.0.113.7 port 51234 ssh2
```

vsftpd (dòng PAM trong `/var/log/auth.log` — chính là mẫu regex `authentication failure; ... tty=ftp ruser=<...> rhost=<HOST>` của filter vsftpd trong Fail2ban):

```log
Aug 29 10:15:02 ftpserver vsftpd[2041]: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=bob rhost=203.0.113.7
```

và khi bật `dual_log_enable=YES`, `/var/log/vsftpd.log` có dòng gọn hơn — chú ý dòng này dùng định dạng ctime (thứ + ngày + giờ + **năm**, không có tên hostname/PID kiểu syslog) và IP đặt trong nháy kép **không** có dấu nhọn (dấu `<HOST>` trong filter fail2ban chỉ là placeholder, không phải nội dung log):

```log
Sat Aug 29 10:15:02 2026 [pid 2041] [bob] FAIL LOGIN: Client "203.0.113.7"
```

Dovecot (POP3/IMAP) trong `/var/log/mail.log` — từ khóa `Disconnected (auth failed, N attempts in N secs)`:

```log
Aug 29 10:15:02 mailserver dovecot: pop3-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<bob>, method=PLAIN, rip=203.0.113.7, lip=10.0.0.5, TLS, session=<Kx7f2p9q>
# so với dòng thành công:
Aug 29 10:16:10 mailserver dovecot: imap-login: Login: user=<bob>, method=PLAIN, rip=192.168.1.50, lip=10.0.0.5, mpid=2101, TLS, session=<Qw1t8z3x>
```

Chú ý: `Disconnected (auth failed, 1 attempts in 2 secs)` **có chủ ý ghi cả số lần thử và thời gian** — do đó khi điều tra, nhìn trường `rip=` (remote IP) và đếm là đủ, không cần tự gom dòng.

Postfix dùng cho đăng nhập SMTP có xác thực (SASL) — dòng fail nằm ở `mail.log`:

```log
Aug 29 10:15:02 mailserver postfix/smtpd[3010]: warning: unknown[203.0.113.7]: SASL LOGIN authentication failed: UGFzc3dvcmQ6
```

**Ngưỡng khởi điểm.** Theo yêu cầu đề bài, ngưỡng mẫu rất gắt: **`findtime = 60` (giây), `maxretry = 5`, `bantime = 3600`** — tức 5 lần sai trong 1 phút thì chặn 1 giờ. Biện luận: tốc độ này loại trừ hoàn toàn con người (5 lần gõ sai liên tiếp trong 60s là phi thực tế), nhưng script brute-force thông thường hàng trăm lần/phút vẫn bị bắt thừa sức. Giá trị gốc của Fail2ban trong `jail.conf` mặc định lỏng hơn — `bantime = 10m, findtime = 10m, maxretry = 5` (5 lần/10 phút) — phù hợp làm ngưỡng "an toàn" khi chưa quen log. Khuyến nghị của đồ án: bắt đầu bằng 5/10 phút, siết dần về 5/60s cho dịch vụ công cộng sau 2 tuần quan sát không có cảnh báo nhầm.

**False positive và cách chỉnh.** (1) Người dùng thật bật chế độ Caps Lock, hoặc gõ nhầm mật khẩu cũ đã đổi → 5 lần fail liên tục trong chưa đầy 1 phút. (2) Ứng dụng nội bộ dùng mật khẩu đã hết hạn (script cũ, máy scan "quét" SMTP bằng credential cũ) → fail đều đặn theo cron, vô hạn. Xử lý: `ignoreip` cho dải nội bộ và IP ứng dụng trong `jail.local`; cân nhắc bỏ chặn tự động, chỉ "gắn nhãn" (alert) để người quản trị xác nhận; với mail client người dùng sai persistent thì hướng dẫn lưu lại mật khẩu mới — giảm nguồn cảnh báo nhầm tốt nhất là giảm lý do fail thật.

Nguồn:
- https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/vsftpd.conf (regex `FAIL LOGIN`, `authentication failure`)
- https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/dovecot.conf
- https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/sshd.conf
- https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf (giá trị mặc định DEFAULT)

### 5.3 Một IP thử nhiều tài khoản khác nhau (username enumeration / credential stuffing)

**Bản chất.** Hai biến thể: *username enumeration* — kẻ tấn công thăm dò tên tài khoản nào tồn tại (để sau này đánh vào đó); *credential stuffing* — dùng danh sách cặp user:pass bị lộ từ vụ khác, thử lần lượt nhiều user trên hệ thống của mình (mỗi user đúng 1 lần thì không chạm ngưỡng 5-lần/1-phút của mục 5.2 — chính vì vậy cần một phép đếm khác). Chỉ báo: **số tài khoản distinct (không lặp) mà một IP nguồn chạm tới**, chứ không phải tổng số lần fail.

**Cách phát hiện.** Đếm distinct users theo từng IP nguồn trong cửa sổ 10 phút (đọc `ruser=`, `user=<...>`, `for ... from`, `rhost=`):

```bash
# Ví dụ với dovecot: tách cặp (rip, user) rồi đếm user khác nhau mỗi IP, 10 phút qua
journalctl -u dovecot --since "10 min ago" -o cat --no-pager \
 | grep "Disconnected" \
 | sed -nE 's/.*user=<([^>]+)>.*rip=([0-9.:]+).*/\2 \1/p' \
 | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head
# Cột đầu = số user khác nhau thử từ IP đó (mỗi dòng rip-user chỉ đếm 1 lần nhờ sort -u)
```

Ở môi trường thật, phép "distinct count theo nhóm" này là thứ mà SIEM hoặc truy vấn Graphite/Prometheus (count unique per label) làm tự nhiên hơn awk; trong lab thì awk đủ.

**Cặp log mẫu.** Bình thường: hai IP nội bộ, mỗi IP một user (`rip=192.168.1.50 user=<bob>` rồi lặp lại cùng cặp). Đáng ngờ:

```log
Aug 29 10:15:02 mailserver dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<admin>, method=PLAIN, rip=203.0.113.7, lip=10.0.0.5, TLS
Aug 29 10:15:03 mailserver dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<test>,  method=PLAIN, rip=203.0.113.7, lip=10.0.0.5, TLS
Aug 29 10:15:04 mailserver dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<oracle>, method=PLAIN, rip=203.0.113.7, lip=10.0.0.5, TLS
```

Cùng một `rip=` nhưng `user=<...>` đổi liên tục, mỗi user đúng 1 lần — "trải thảm" (spraying). Tương tự với vsftpd: `[pid ...] [admin] FAIL LOGIN`, rồi `[test] FAIL LOGIN`, cùng `Client "203.0.113.7"`.

**Ngưỡng khởi điểm.** Khuyến nghị: **≥10 user distinct từ 1 IP trong 10 phút → cảnh báo; ≥25 → cảnh báo khẩn**. Biện luận: một IP công cộng lạ không có lý do chính đáng nào chạm >2–3 tên tài khoản trong 10 phút (kèm hầu hết fail); ngưỡng 10 tạo biên độ an toàn, còn mức 25 gần như chắc chắn là tự động hóa. Có thể kết hợp điều kiện "tỉ lệ fail ≥80%" để loại trừ trường hợp hiếm hoi một kỹ thuật viên helpdesk reset mật khẩu hộ 5–6 user trong ca trực (các lần đó thường *thành công*).

**False positive và cách chỉnh.** Kẻ thù số một của phép đếm này là **NAT**: một IP công ty (vài trăm nhân viên ra internet chung một IP) dễ dàng chạm ngưỡng "nhiều user". Xử lý đúng quy trình: (1) tra xem IP có thuộc dải của khách hàng/đối tác/VPN công ty không; (2) có thì cho vào danh sách trắng (`ignoreip`, hoặc bộ lọc riêng) và **thay vào đó giám sát theo user** (mục 5.4) vì IP đã mất khả năng định danh; (3) hoặc nâng ngưỡng riêng cho các IP đã whitelist thành 100+ user/10 phút. Cũng nhớ IPv6: mỗi thiết bị di động trong cùng mạng 3G/4G có thể có cả một dải /64 — cân nhắc chặn theo prefix chứ không phải /128.

Nguồn:
- https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/dovecot.conf (trường user/rip trong log dovecot)
- https://www.rfc-editor.org/rfc/rfc1939, https://www.rfc-editor.org/rfc/rfc9051 (ngữ cảnh POP3/IMAP login)

### 5.4 Một tài khoản xuất hiện ở nhiều IP hoặc giờ bất thường

**Bản chất.** Ba mục trên nhìn theo trục IP; mục này lật trục lại: **phân tích theo user**. Khi kẻ tấn công đã có một cặp credential hợp lệ (từ phishing, từ stuffing thành công), mọi login của họ đều "đúng mật khẩu" — không có dòng fail nào cả. Chỉ còn bất thường về **ngữ cảnh**: một người không thể ở Hà Nội lúc 02:00 và ở một châu lục khác lúc 02:05 (impossible travel), và một kế toán không đăng nhập IMAP lúc 3 giờ sáng trong khi suốt 2 tuần chỉ hoạt động 8h–17h.

**Cách phát hiện.** Đếm distinct IP theo user, và so khớp khung giờ:

```bash
# Dovecot: user nào đến từ nhiều IP trong 5 phút?
journalctl -u dovecot --since "5 min ago" -o cat --no-pager | grep "Login:" \
 | sed -nE 's/.*user=<([^>]+)>.*rip=([0-9.:]+).*/\1 \2/p' \
 | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head
# Cột đầu = số IP khác nhau của user đó. Cảnh báo: >= 3
# (vsftpd/sshd: tách cặp theo ruser=...rhost=... / "for <user> from <ip>" — cùng nguyên tắc)
```

**Cặp log mẫu.** Bình thường (bob trên điện thoại + laptop, 2 IP nội bộ, cách nhau 40 phút):

```log
Aug 29 08:10:00 mailserver dovecot: imap-login: Login: user=<bob>, method=PLAIN, rip=192.168.1.50, lip=10.0.0.5, mpid=2101, TLS, session=<A1>
Aug 29 08:50:12 mailserver dovecot: imap-login: Login: user=<bob>, method=PLAIN, rip=192.168.1.51, lip=10.0.0.5, TLS, session=<A2>
```

Đáng ngờ — cùng user trong 5 phút, 4 IP ở 4 nước khác nhau, rồi nối tiếp toàn hoạt động 02:00–03:00 sáng:

```log
Aug 29 10:15:01 mailserver dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=198.51.100.23, lip=10.0.0.5, TLS, session=<B1>
Aug 29 10:17:44 mailserver dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=203.0.113.44, lip=10.0.0.5, TLS, session=<B2>
Aug 29 10:19:50 mailserver dovecot: imap-login: Login: user=<alice>, method=PLAIN, rip=192.0.2.77,   lip=10.0.0.5, TLS, session=<B3>
```

Ba `rip=` thuộc ba block địa chỉ khác nhau liên tiếp trong vòng chưa đầy 5 phút — thời gian bay giữa các nước không cho phép.

**Ngưỡng khởi điểm.** Hai luật độc lập, mỗi luật đủ để cảnh báo: (a) **≥3 IP distinct trong 5 phút cho cùng một user** (không tính các IP đã biết của user đó); (b) **thành công đăng nhập ngoài khung giờ baseline** — baseline = khoảng giờ hoạt động của chính user đó trong 2 tuần gần nhất, nới thêm ±2 giờ. Biện luận: 2 IP là chuyện bình thường (wifi + 4G); IP thứ 3 trong vài phút thì rất khó giải thích.

**False positive và cách chỉnh.** Roaming quốc tế thật (sai giờ địa phương — hãy quy log về UTC rồi so với múi giờ *khai báo* của người dùng, không phải giờ máy chủ); mail client trên điện thoại tự đồng bộ đẩy cả laptop + desktop + watch (có thể thành 3 IP nếu dùng cả 4G và wifi, hoặc IPv4 + IPv6 của cùng một thiết bị). Vì vậy luật này chỉ nên **cảnh báo (alert)**, không bao giờ tự động chặn — người quản trị hoặc chính chủ tài khoản xác nhận qua kênh khác (kênh phụ: hỏi thẳng, SMS, chat). Kèm theo đó, bật thêm tín hiệu "đăng nhập thành công ngay sau khi đổi mật khẩu từ IP lạ" — chuỗi hành vi kinh điển của chiếm tài khoản.

Nguồn:
- https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/dovecot.conf (mẫu log `Login:` / `Disconnected`)
- https://doc.dovecot.org/ (cấu hình log của Dovecot)

### 5.5 Volume tăng đột biến so với baseline

**Bản chất.** Brute-force, spam chiến dịch, data exfiltration qua FTP — tất cả đều làm **nhịp lượng** của hệ thống thay đổi: số kết nối mới/phút, số file transfer/phút, số mail chấp nhận/giờ tăng vọt so với chính nó ngày thường. Điểm mấu chốt: ngưỡng không phải một hằng số, mà là **đường cơ sở (baseline) học từ dữ liệu của lab**. Khuyến nghị của đồ án: dùng **trung bình động 2 tuần (moving average)** theo từng khung giờ (hour-of-day), vì lưu lượng mail/FTP có nhịp ngày—đêm rất rõ; cảnh báo khi giá trị hiện tại vượt `baseline + 3×độ lệch chuẩn` (hoặc đơn giản hơn: >5× baseline).

**Cách phát hiện.** Trong lab, đủ bằng awk gom theo phút rồi so; môi trường thật đẩy số liệu vào Graphite/Prometheus để có đồ thị và alert rule.

```bash
# Số lần login mỗi phút từ vsftpd.log (dual log — dòng "Sat Aug 29 10:15:02 2026 [pid ...]";
# $2=$3 = "T2 29", $4 = giờ:phút:giây nên cắt 5 ký tự đầu). auth.log không chứa OK/FAIL LOGIN.
awk '/(OK|FAIL) LOGIN/ {print $2" "$3" "substr($4,1,5)}' /var/log/vsftpd.log \
 | sort | uniq -c | tail -20      # cột 1 = số login/phút; mắt thường thấy đỉnh bất thường
```

```bash
# Mail được chấp nhận (queue ID mới) mỗi 10 phút từ mail.log
journalctl -u postfix --since "10 min ago" --no-pager -g "postfix/smtpd.*client=" -o short \
 | wc -l
```

**Ví dụ log + metric.** Bình thường: mail server của lab chấp nhận ~5 msg/10 phút (vài sinh viên gửi bài, nhận thông báo). Cảnh báo bật khi cửa số hiện tại là 200 msg/10 phút:

```log
# metric, không phải log: smtpd_accepts_per_10min = 200   (baseline = 5, ngưỡng = 3σ ≈ 40)
Aug 29 10:15:01 mailserver postfix/smtpd[3301]: connect from unknown[203.0.113.9]
Aug 29 10:15:02 mailserver postfix/smtpd[3301]: 4F2A1B3C89: client=unknown[203.0.113.9], sasl_method=LOGIN, sasl_username=sv1@lab.local
Aug 29 10:15:03 mailserver postfix/smtpd[3302]: 4F2A1B40A2: client=unknown[203.0.113.9], sasl_method=LOGIN, sasl_username=sv1@lab.local
... (197 dòng tương tự trong 9 phút tiếp theo, cùng 1 tài khoản)
```

Cùng dạng này cho FTP: baseline upload 1–2 file/tuần thì một đêm `xferlog` ghi 3.000 dòng `OK UPLOAD` là red flag khổng lồ của exfiltration.

**Ngưỡng khởi điểm.** Với hệ thống nhỏ như lab: `>5× baseline` và tối thiểu 50 sự kiện/cửa sổ (tránh cảnh báo 1→5). Biện luận: 5× nằm trên đỉnh dao động tự nhiên (đã nhân 3σ); sàn tuyệt đối 50 loại nhiễu thống kê khi baseline gần 0.

**False positive và cách chỉnh.** Lễ nộp bài tập lớn (sinh viên upload FTP đồng loạt đầu giờ), thứ Hai chiến dịch gửi thư thông báo, kỳ thi (truy vấn IMAP tăng). Đây chính là lúc tính "theo khung giờ" của baseline 2 tuần có giá trị — nếu mọi tuần đều nộp bài thứ Hai 8h, ngày đó không phải outlier; nếu là sự kiện một lần, quản trị tạm time-out cảnh báo và **ghi chú lý do vào ticket** để lần sau đưa vào baseline "có mùa vụ".

Nguồn:
- https://graphite.readthedocs.io/ (metric + alert theo đường cơ sở); https://prometheus.io/ (thay thế phổ biến)
- https://www.rsyslog.com/ubuntu-repository/ (đường ống log)

### 5.6 Hàng đợi mail (mail queue) tăng nhanh

**Bản chất.** Mail queue của Postfix phình nhanh khi: (a) mail bị chính sách bên ngoài từ chối và **deferred** — postfix thử lại, queue càng lúc càng dài; (b) máy phát hiện spam bị chặn giữa chừng; (c) có tài khoản nội bộ bị dùng để gửi spam nhưng bị rate-limit. Queue sâu là tín hiệu vừa về an toàn, vừa về vận hành, nên đáng giám sát riêng.

**Cách phát hiện.** Định kỳ bằng cron (mọi 5 phút):

```bash
postqueue -p | grep -cE '^[0-9A-F]{6,}'          # đếm số message đang chờ (mỗi message 1 dòng queue ID;
                                                 # hậu tố * = đang transfer, ! = đang giữ)
# đếm riêng các message defer — dòng lý do "(Deferred: ...)" đi kèm trong block queue ID:
mailq | grep -c '(Deferred:'
```

Cảnh báo khi **số message chờ > N (N = 100 cho lab)** hoặc **tốc độ tăng > 50 msg/phút trong 5 phút liên tiếp**, và luôn bắt keyword `deferred` trong log để biết lý do:

```log
# BÌNH THƯỜNG — gửi thành công sau 1 giây:
Aug 29 10:16:10 mailserver postfix/smtp[3100]: 4F2A1B3C89: to=<nguoinhan@other.example>, relay=smtp.other.example[192.0.2.99]:25, delay=0.83, delays=0.1/0.02/0.3/0.4, dsn=2.0.0, status=sent (250 Ok)
# ĐÁNG NGỜ — message kẹt lại vì từ ngoài từ chối (450 = tạm thời, sẽ defer):
Aug 29 10:15:02 mailserver postfix/smtp[3100]: 4F2A1B3C89: to=<x@other.example>, relay=smtp.other.example[192.0.2.99]:25, delay=1800, delays=0.5/0.1/1790/9.4, dsn=4.0.0, status=deferred (host smtp.other.example[192.0.2.99] said: 450 4.7.1 Service unavailable; Client host [203.0.113.9] blocked using Spamhaus)
```

Biện luận ngưỡng: 100 message deferred nghĩa là 100 người nhận đang chờ và hệ thống đã cố gửi suốt ~15–30 phút không xong (mặc định Postfix thử lại mỗi 1000s ở lần đầu); nếu queue một lúc rồi tự tiêu = sự cố mạng thoáng qua (FP); nếu queue tăng đều + nguyên nhân `blocked using ...` hoặc `550 User unknown` hàng loạt = **nội bộ đang bị lợi dụng để spam ra ngoài và bị các MTA khác chặn** — kiểm tra ngay `sasl_username` của các message deferred đó.

**False positive.** Máy chủ nhận vừa bị mất đường truyền internet (toàn bộ queue "treo", lý do `connect to ... timed out`) — phân biệt bằng cách xem message lý do: `timed out/connection refused` (vận hành) vs `blocked/rejected/unavailable` (an toàn). Cron chỉ đếm theo thời gian không phân biệt, nên cảnh báo cần in kèm top 10 lý do defer.

Nguồn:
- https://www.postfix.org/postqueue.1.html (lệnh postqueue)
- https://www.postfix.org/SMTPD_ACCESS_README.html (các reason từ chối)

### 5.7 Hành vi relay trái phép bị (hoặc không bị) chặn

**Bản chất.** Relay mở (open relay) là cấu hình sai lầm chết người của SMTP: máy cho phép người lạ gửi mail đến **địa chỉ thuộc domain khác** — kẻ spam biến server của bạn thành bàn đạp, và hệ quả trước mắt là tên miền/IP vào blacklist. Tin tốt: cấu hình mặc định của Postfix hiện đại **từ chối** relay kiểu đó (`Relay access denied`). Hai mức cảnh báo phải phân biệt:

- Có dòng `reject: RCPT ... Relay access denied` trong log = **ai đó ĐANG thử relay** → tín hiệu *tốt* (đã chặn), nhưng cần biết ai, bao nhiêu lần.
- Có message **thành công** (`status=sent`) với người nhận ngoài domain từ client **không qua SASL** = **cấu hình relay hỏng** → nghiêm trọng, phải gọi điện (double alert).

**Cách phát hiện.** Đếm theo src IP:

```bash
# Ai bị từ chối relay nhiều nhất trong ngày?
journalctl -u postfix --since today --no-pager -g "Relay access denied" \
 | grep -oP '\[\K[0-9.]+(?=\])' | sort | uniq -c | sort -rn | head
```

**Cặp log mẫu.**

```log
# BỊ CHẬN — postfix/smtpd từ chối relay (mẫu này match filter postfix mode "normal" của Fail2ban):
Aug 29 10:15:02 mailserver postfix/smtpd[3010]: NOQUEUE: reject: RCPT from unknown[203.0.113.7]: 554 5.7.1 <congnhan@other.example>: Relay access denied; from=<promo@spam.example> to=<congnhan@other.example> proto=ESMTP helo=<SPAMHOST>
# LỖ HỔNG — relay thành công cho người nhận ngoài mà không có sasl_username nào ở dòng client=:
Aug 29 10:16:10 mailserver postfix/smtpd[3050]: 5A9C2D1E77: client=unknown[203.0.113.7]
Aug 29 10:16:11 mailserver postfix/smtp[3100]: 5A9C2D1E77: to=<congnhan@other.example>, relay=smtp.other.example[192.0.2.99]:25, delay=1.2, delays=0.3/0.1/0.6/0.2, dsn=2.0.0, status=sent (250 Ok)
```

(mã trạng thái `554 5.7.1` là enhanced status code theo RFC 3463, lớp 5 = từ chối dứt khoát, thuộc SMTP — RFC 5321).

**Ngưỡng khởi điểm.** (a) `Relay access denied` xuất hiện **≥1 lần** → ghi nhận (mức info, để thống kê); **>30 lần/giờ từ 1 IP** → cảnh báo (đang bị "băm" vào cửa, nên để Fail2ban chặn luôn IP đó). (b) `status=sent` tới domain ngoài mà `client=` không kèm `sasl_username=` → **cảnh báo nghiêm trọng ngay lần đầu, không ngưỡng** — số lượng = 0 mới là bình thường. Biện luận: sự kiện (a) là hành vi kẻ quét internet nền (mỗi IP scan toàn cầu sẽ gặp server của bạn một lần — 1–2 lần/ngày là nhiễu), còn (b) là lỗi cấu hình nghiêm trọng nên không có "ngưỡng chấp nhận".

**False positive và cách chỉnh.** IP nội bộ (printer, scanner, hệ thống cũ khai báo sai `mynetworks`) bị từ chối relay vì quên thêm vào `mynetworks` → hàng loạt dòng "Relay access denied" nội bộ; xử lý bằng cách thêm đúng dải vào cấu hình, đồng thời `ignoreip` dải đó trong jail. Với luật (b): một vài application hợp lệ gửi mail qua server không cần auth vì được đặt trong `mynetworks` — khi đó luật phải viết là "client **không thuộc** `mynetworks` mà vẫn gửi ra ngoài thành công".

Nguồn:
- https://www.postfix.org/SMTPD_ACCESS_README.html
- https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/postfix.conf
- https://www.rfc-editor.org/rfc/rfc5321 ; https://www.rfc-editor.org/rfc/rfc3463

### 5.8 Dịch vụ dừng/khởi động lại bất thường

**Bản chất.** Một attacker chiếm quyền có thể tắt dịch vụ (dDoS ứng dụng, che giấu), hoặc một tiến trình bị crash vì exploit/oom. Hệ thống giám sát phải phân biệt được "tắt do quản trị" và "tắt không ai biết".

**Cách phát hiện.** Kết hợp (1) watchdog của systemd qua `journalctl`, (2) kiểm tra chủ động bằng script/cron hoặc metric `up` của Prometheus (blackbox exporter gửi kết nối thử tới port 21/22/25/110/143 mỗi 30s).

```log
# Crash — systemd ghi lại nguyên nhân:
Aug 29 10:15:02 server systemd[1]: dovecot.service: Main process exited, code=killed, status=11/SEGV
Aug 29 10:15:02 server systemd[1]: dovecot.service: Failed with result 'signal'.
# Restart loop — dòng "starting up" lặp lại liên tục sau vài giây (dấu hiệu vòng lặp khởi động lại):
Aug 29 10:15:05 server dovecot: Dovecot v2.3.21 starting up (rps-limit: ...)
Aug 29 10:15:09 server dovecot: Dovecot v2.3.21 starting up (...)     # ← restart lần 2 trong 4s
```

Kèm theo là nhóm "cert renewal fail" — Let's Encrypt/certbot gia hạn chứng chỉ TLS không thành công làm các kênh bảo mật (FTPS/IMAPS/SMTP-TLS) sụp dần mà dịch vụ vẫn "up":

```log
Aug 29 02:00:11 server certbot: 2026-08-29 02:00:11,002:ERROR:acme.challenges:Verification failure
# hoặc phía postfix báo lỗi khi load chứng chỉ:
Aug 29 10:15:02 mailserver postfix/smtpd[3010]: fatal: cannot access /etc/ssl/private/ssl-cert-snakeoil.key: No such file or directory
```

**Cách phát hiện nhanh bằng lệnh:**

```bash
journalctl --since "24 hours ago" -p err | grep -E "Failed with result|Main process exited"
systemctl show postfix -p NRestarts --value     # số lần systemd khởi động lại từ khi bật unit
```

**Ngưỡng khởi điểm.** `NRestarts` tăng >0 ngoài giờ thao tác của nhóm = cảnh báo; restart ≥2 lần/giờ = khẩn. Mọi lần "dừng có chủ đích" phải được log ngược lại bằng cách đối chiếu với lịch bảo trì.

**False positive.** Chính bạn đang `systemctl reload`/`restart` khi triển khai cấu hình, hoặc `apt upgrade` tự restart daemon (unattended-upgrades). Khắc phục bằng quy trình: trước khi bảo trì, đặt dấu im lặng (maintenance window — tắt alert cho unit đó theo thời gian hẹn giờ); đây là quy trình vận hành, không phải chỉnh ngưỡng số.

Nguồn:
- https://documentation.ubuntu.com/server/how-to/logging/ (journalctl; đường dẫn trang server docs của Ubuntu)
- https://manpages.ubuntu.com/manpages/noble/man1/systemctl.1.html (trạng thái unit)

### 5.9 File cấu hình bị thay đổi

**Bản chất.** Nhiều cuộc tấn công không cần crash — chỉ cần **sửa một dòng**: mở relay trong `main.cf`, tắt `chroot_local_user` trong `vsftpd.conf`, bật `PermitRootLogin yes` trong `sshd_config`. Phát hiện thay đổi file cấu hình là lớp cuối cùng bắt cả attacker *lẫn* quản trị viên sơ ý.

**Cách phát hiện.** Hai công cụ kinh điển, dùng độc lập hoặc song song:

```bash
# AIDE: snapshot "hồ sơ" checksum các file hệ thống, sau đó đối chiếu
apt install aide
sudo aideinit                                   # tạo DB ban đầu (chạy một lần sau khi hệ thống "sạch")
sudo aide --check                               # phát hiện file thêm/xóa/sửa — đưa vào cron mỗi ngày
```

```bash
# inotifywait: soi realtime các thư mục nhạy cảm
inotifywait -m -r --timefmt '%F %T' --format '%T %w%f %e' \
  /etc/vsftpd.conf /etc/postfix /etc/dovecot /etc/ssh/sshd_config \
  >> /var/log/config-watch.log                  # mỗi dòng = một event MODIFY/CLOSE_WRITE...
```

**Cặp log mẫu.** Bình thường (sự kiện có chủ đích, đi kèm commit) — dòng đầu là output của `inotifywait` đúng định dạng `--timefmt '%F %T' --format '%T %w%f %e'` đã ghi vào `config-watch.log`; các dòng sau là **báo cáo của `aide --check`** (AIDE không ghi qua syslog mà in báo cáo khi chạy, thường từ cron):

```log
2026-08-29 09:58:12 /etc/postfix/main.cf CLOSE_WRITE   # đúng lúc bạn đang deploy
Changed entries:
  FSF /etc/postfix/main.cf
    Size   : 24110 -> 24158                             # thêm 48 byte cho cấu hình antispam mới
```

Đáng ngờ:

```log
Changed entries:
  FSF /etc/ssh/sshd_config
    MD5    : 3f2a1c...d41 -> 8c1d77...9be    # không có ai đăng nhập bảo trì lúc 03:47
  FSF /etc/postfix/main.cf
    Line 112:
    - mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
    + mynetworks = 0.0.0.0/0                 # relay vừa bị mở cho cả thế giới
```

**Quy trình "mtime + diff vào git".** Biến `/etc` thành repo git (hoặc dùng **etckeeper** — gói đóng sẵn git + hook vào apt): mỗi lần đổi có một commit; commit message quy ước `[change] nội dung + lệnh của quản trị + JIRA ticket`, và một cron `git status` phát hiện dirty file không có commit → cảnh báo. Khi có alert AIDE, việc cần làm đầu tiên là `git diff` để đọc đúng dòng thay đổi.

**Ngưỡng khởi điểm.** Đây là loại cảnh báo **không có ngưỡng số** — *mọi* thay đổi ngoài cửa sổ bảo trì đều phải được giải thích. "Ngưỡng" nằm ở quy trình: thay đổi → phải có commit + message; không có → điều tra.

**False positive.** Bạn tự sửa khi deploy (đúng như đề bài lưu ý): giải quyết bằng quy trình commit message ở trên và bằng cách để script deploy tự động commit với message `[auto-deploy] ...`; ngoài ra apt tự cập nhật có thể sửa file trong `/etc` — etckeeper tự commit các thay đổi loại này với message rõ nguồn.

Nguồn:
- https://aide.github.io/ ; https://github.com/inotify-tools/inotify-tools
- https://etckeeper.branchable.com/

### 5.10 Tổng kết: bảng hành vi → log → ngưỡng → hành động, và tự động hóa bằng Fail2ban

Bảng tra nhanh toàn chương — cột "hành động" phân biệt **cảnh báo** (alert để người quản trị xem) và **ban** (chặn tự động, chỉ nên dùng khi độ chắc chắn cao):

| # | Hành vi | Nguồn log | Từ khóa / filter | Ngưỡng khởi điểm | Hành động |
|---|---|---|---|---|---|
| 1 | Nhiều lần login fail / 1 IP | auth.log, vsftpd.log, mail.log | `FAIL LOGIN`, `Failed password`, `Disconnected (auth failed`, `SASL ... authentication failed` — filter Fail2ban `vsftpd`,`sshd`,`dovecot`,`postfix` | 5 lần/1–10 phút (jail) | Cảnh báo + **ban IP** (bantime 10m–1h) |
| 2 | 1 IP thử nhiều tài khoản | như trên, group theo (rip,user) | distinct users / src IP | ≥10 user/10 phút; ≥25 khẩn | Cảnh báo; ban chỉ khi fail rate cao |
| 3 | 1 tài khoản nhiều IP / giờ lạ | mail.log (Login), auth.log | group theo user; so baseline giờ | ≥3 IP/5 phút; ngoài khung hoạt động | Cảnh báo (không tự ban) |
| 4 | Volume tăng đột biến | metric từ log (graphite/Prometheus) | kết nối/phút, upload/phút, msg/10 phút | >5× baseline 2 tuần & ≥50 | Cảnh báo |
| 5 | Queue mail tăng | `postqueue -p`, mail.log | `status=deferred`, đếm queue ID | >100 msg hoặc +50/phút | Cảnh báo + xem lý do defer |
| 6 | Relay trái phép | mail.log | `Relay access denied` / `status=sent` ngoài domain không SASL | ≥1 lần sent khả nghi = khẩn; >30 denied/giờ/IP | Cảnh báo; double alert khi sent; ban IP probing |
| 7 | Dịch vụ dừng/restart | journald | `Failed with result`, `NRestarts`, certbot error | mọi restart ngoài kế hoạch | Cảnh báo; khẩn khi loop |
| 8 | Config bị sửa | AIDE, inotifywait, git | diff `/etc/vsftpd.conf`, `/etc/postfix`, `/etc/dovecot`, `sshd_config` | mọi thay đổi không có commit | Cảnh báo + điều tra |

**Vai trò của Fail2ban.** Các mục 1–3 và một phần 6 là thứ Fail2ban tự động hóa tốt nhất: nó là một daemon đọc log theo `logpath`, khớp các bộ lọc failregex ở mục 5.2–5.3 (chính các file `filter.d/*.conf` mà chương này dùng làm mẫu log thật), đếm sự kiện theo `(IP, cửa sổ)`, và khi vượt `maxretry` thì áp `bantime` qua nftables/iptables. Khung jail mẫu trong `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime  = 1h          # thời gian chặn sau khi vi phạm
findtime = 60          # cửa sổ đếm sự kiện (siết hơn mặc định 10m của jail.conf)
maxretry = 5           # 5 lần vi phạm trong cửa sổ => ban
ignoreip = 127.0.0.1/8 192.168.1.0/24 203.0.113.10   # loopback, dải lab, IP NAT công ty (mục 5.3)

[sshd]                 # SFTP + SSH
enabled = true

[vsftpd]               # cần dual_log_enable=YES ở vsftpd và trỏ đúng logpath
enabled  = true
logpath  = /var/log/vsftpd.log

[dovecot]              # POP3 + IMAP
enabled = true

[postfix]              # SMTP — chọn mode tùy thứ muốn chặn
enabled = true
mode    = aggressive   # mode='normal' chỉ khớp các dòng 'reject:' (Relay access denied, ...);
                       # 'aggressive' khớp thêm 'SASL ... authentication failed' và pattern ddos
```

```bash
fail2ban-client status sshd          # IP nào đang bị chặn, bao nhiêu lần
fail2ban-client set sshd unbanip 203.0.113.7   # gỡ khi phát hiện chặn nhầm (FP)
```

Lưu ý thực tế: nếu lab cài bản minimized không có auth.log, đặt `backend = systemd` để Fail2ban đọc thẳng journald thay vì file.

**Điều quan trọng nhất của cả chương.** **Không có ngưỡng nào đúng cho mọi môi trường.** Các con số 5/60s, 10 user/10 phút, 5× baseline chỉ là *điểm xuất phát* để tinh chỉnh (tuning): chạy 1–2 tuần ở mức lỏng, thống kê tỉ lệ cảnh báo nhầm trên log thật của chính hệ thống, rồi siết dần. Giai đoạn đầu, số cảnh báo nhầm nhiều hơn cảnh báo đúng là **bình thường và có ích** — mỗi lần xem xét một FP là một lần hiểu hơn nhịp hoạt động bình thường của hệ thống mình. Song song, nhớ nguyên tắc NIST SP 800-92: log là bằng chứng, phải đồng bộ thời gian (NTP/chrony), giữ an toàn khỏi chính attacker (file chỉ root ghi được, tốt nhất là gửi log ra máy khác ngay — remote syslog), và có thời gian lưu đủ dài.

**Lab vs môi trường thật (giới thiệu ngắn).** Trong lab, `grep` + `awk` + `journalctl` là đủ và giúp hiểu bản chất. Khi có nhiều máy hoặc cần truy vấn tương tác, môi trường thật thường dùng SIEM: **Wazuh** (nguồn mở, có sẵn rule/decoder parse log vsftpd, postfix, dovecot, sshd và liên kết với agent) hoặc **Splunk** (thương mại, tìm kiếm log bằng cú pháp SPL, dashboard metric). Cả hai về bản chất chỉ là "grep + awk + baseline chạy ở quy mô lớn có giao diện"; kỹ thuật phát hiện ở chương này chuyển thẳng sang đó mà không thay đổi logic.

Nguồn:
- https://github.com/fail2ban/fail2ban (jail.conf, filter.d/*.conf — mẫu log và từ khóa thật)
- https://github.com/fail2ban/fail2ban/wiki (hướng dẫn backend systemd, jail.local)
- https://csrc.nist.gov/pubs/sp/800/92/final (NIST SP 800-92 — quản trị log)
- https://wazuh.com/ ; https://www.splunk.com/
