## 1. Kiến thức mạng nền tảng cần biết

Chương này trang bị phần "nền móng" bắt buộc trước khi đi vào từng dịch vụ FTP, SFTP, SMTP, POP3, IMAP ở các chương sau. Mỗi khái niệm được trình bày theo ba mức: **bản chất** (vì sao nó tồn tại) → **ví dụ gắn với 5 dịch vụ của đồ án** → **cách quan sát trong lab** (mạng riêng do nhóm sở hữu, ví dụ VirtualBox/VMware với các máy Ubuntu Server). Mọi lệnh kiểm thử dưới đây chỉ dùng trong phạm vi lab nội bộ của nhóm.

### 1.1. Mô hình TCP/IP bốn tầng và mô hình client–server

**Bản chất.** Để các máy tính khác hệ điều hành nói chuyện được với nhau, người ta chia truyền thông thành các tầng (layer), mỗi tầng giải quyết một vấn đề và chỉ giao tiếp với tầng kề nó qua giao diện rõ ràng. Mô hình OSI 7 tầng là khung lý thuyết; trong thực triển khai, **mô hình TCP/IP 4 tầng** mới là mô hình "chạy" trên Internet ngày nay:

| Tầng TCP/IP | Nhiệm vụ | Ví dụ giao thức/đối tượng | Dịch vụ đồ án nằm ở đâu |
|---|---|---|---|
| Application (Ứng dụng) | Ngôn ngữ trao đổi giữa hai tiến trình | FTP, SMTP, POP3, IMAP, SSH | **Cả 5 dịch vụ đều ở đây** |
| Transport (Giao vận) | Truyền tin giữa 2 *socket*, tin cậy hay không | TCP, UDP | FTP/SFTP/SMTP/POP3/IMAP đều chạy trên TCP |
| Internet (Mạng) | Định tuyến gói tin giữa 2 *máy* | IP, ICMP | Địa chỉ IP server/mail exchanger |
| Network Access (Truy cập mạng) | Truyền trong một links mạng cụ thể | Ethernet, Wi-Fi, ARP | Card ảo VirtualBox (NAT/Bridged) |

Khi một ứng dụng FTP gửi lệnh `RETR report.pdf`, dữ liệu được "bọc" (encapsulation) lần lượt qua các tầng: thêm header TCP (cổng, số thứ tự), thêm header IP (địa chỉ nguồn/đích), rồi thành khung Ethernet. Ở máy nhận, quá trình ngược lại diễn ra ("tách vỏ").

**Mô hình client–server.** Cả 5 dịch vụ đều theo cấu trúc: một *server*listen trên một cổng cố định, chờ kết nối; một *client* chủ động kết nối tới. Client là phía "có nhu cầu" (người tải file, người gửi mail, hộp thư đọc thư), server là phía "cung cấp" (vsftpd, OpenSSH, Postfix, Dovecot). Điểm cần khắc ngay: **SMTP hơi đặc thù** vì nó là quan hệ server–server (MTA này gửi cho MTA kia) *và* client–server (Outlook/Thunderbird POST thư lên 587) lẫn lộn; POP3/IMAP thì thuần client-mail đọc thư.

**Ví dụ.** vsftpd (FTP server) chạy trên máy Ubuntu `192.168.56.10`, listener của nó nằm ở tầng ứng dụng nhưng được OS quản lý qua socket TCP ở tầng giao vận. Client FileZilla trên máy Windows của bạn tạo kết nối tới cổng 21.

**Cách quan sát trong lab.** Trên server:

```bash
ss -tlnp          # liệt kê socket đang LISTEN (-t TCP, -l listen, -n số thay vì tên, -p process)
# Expected: :21 vsftpd, :22 sshd, :25 master(postfix), :143/:993 dovecot
```

Trong VirtualBox, chuyển card mạng sang **Bridged** để hai máy VM có IP thật trong cùng subnet — khi đó bạn đi hết 4 tầng của mô hình mà không bị ảo hóa "che" tầng Network Access.

Nguồn:
- Tổng quan mô hình tầng và TCP/IP: https://www.rfc-editor.org/info/rfc1122 và https://en.wikipedia.org/wiki/Internet_protocol_suite

### 1.2. TCP vs UDP, địa chỉ IP, cổng, DNS và socket

**TCP vs UDP — vì sao 5 giao thức này đều chọn TCP.**

- **TCP (Transmission Control Protocol)** là kênh truyền có kết nối (connection-oriented), tin cậy: mọi byte được đánh số thứ tự (sequence number), bên nhận xác nhận (acknowledgement), mất gói thì truyền lại, có kiểm soát tắc nghẽn. Byte stream đến nơi đúng thứ tự, không thiếu, không trùng.
- **UDP** thì nhanh, không kết nối, nhưng "gửi và cầu nguyện" — gói có thể mất, lặp, lộn xộn, và ứng dụng phải tự sửa lấy.

FTP truyền file, SMTP mang thư, POP3/IMAP mang hộp thư, SSH/SFTP mang toàn bộ phiên làm việc — **mất một byte là hỏng một file hoặc một thông điệp**, và cả 5 giao thức này đều là giao thức "text command + response" kiểu hỏi–đáp tuần tự, vốn đòi hỏi luồng byte đáng tin. Đó là lý do cả 5 đều chạy trên TCP (định nghĩa chuẩn hiện hành: RFC 9293, thay thế RFC 793 cũ). UDP phù hợp hơn với DNS query hay VoIP — thứ chấp nhận mất gói để đổi lấy độ trễ.

**Địa chỉ IP.** IP trả lời câu hỏi "gói này đi đến *máy nào* trên mạng". IPv4 gồm 4 octet (ví dụ `192.168.56.10`), không gian ~4,3 tỷ địa chỉ đã cạn nên tồn tại IPv6 (ví dụ `fe80::1`, RFC 8200). Trong lab bạn hầu hết dùng IPv4 riêng theo dải RFC 1918 (`10/8`, `172.16/12`, `192.168/16`).

**Subnet mask** quy định phần nào của IP là "địa chỉ mạng", phần nào là "máy trong mạng đó": `/24` (255.255.255.0) nghĩa là 3 octet đầu định danh mạng, octet cuối định danh máy → `192.168.56.0/24` chứa 254 host. Hai máy cùng subnet thì nói chuyện trực tiếp ở tầng 2; khác subnet thì phải đẩy gói cho **gateway mặc định** (default gateway) — thường là router ảo của VirtualBox NAT (`192.168.56.1` nếu dùng host-only, hoặc `10.0.2.1` trong chế độ NAT).

**Cổng (port).** IP định danh *máy*, còn port (số 16-bit, 0–65535) định danh *tiến trình* trên máy đó. IANA chia vùng port thành:

- **Well-known ports 0–1023**: gắn với dịch vụ hệ thống — đây là "bản đồ" của đồ án:

| Dịch vụ | Port chuẩn | Giao thức |
|---|---|---|
| FTP control | 21 | FTP (RFC 959) |
| FTP data (active mode) | 20 | FTP |
| FTPS (FTP + TLS) | 990 (implicit), 21 (explicit) | RFC 4217 |
| SSH / SFTP | 22 | SSH (RFC 4251/4253/4254), SFTP chạy "trên" SSH |
| SMTP | 25 | RFC 5321 |
| SMTP submission | 587 | RFC 6409 |
| SMTPS | 465 | (khôi phục làm cổng SMTP-over-TLS, xem RFC 8314) |
| POP3 | 110 | RFC 1939 |
| POP3S | 995 | RFC 2595 |
| IMAP | 143 | RFC 9051 (IMAP4rev2) |
| IMAPS | 993 | RFC 2595 |

- **Registered ports 1024–49151**: do ứng dụng đăng ký dùng (ví dụ các port data ngẫu nhiên của FTP passive mode thường rơi vào dải cao do admin cấu hình, như `pasv_min_port/pasv_max_port` trong vsftpd).

Trên Linux, tiến trình muốn bind vào port < 1024 cần quyền root (hoặc capability `CAP_NET_BIND_SERVICE`) — chi tiết này giải thích vì sao vsftpd/postfix/dovecot đều chạy daemon với quyền root rồi "hạ quyền" (drop privileges) xuống user riêng như `nobody`, `_postfix`, `dovenull`.

**DNS và quá trình phân giải tên.** Người nhớ `mail.example.com`, máy nhớ IP. **DNS (Domain Name System, RFC 1034/1035)** là cơ sở dữ liệu phân cấp dịch tên → IP. Quá trình khi Postfix cần gửi thư cho `nhungthanhdat.edu.vn`:

1. Client hỏi resolver (thư mục `/etc/resolv.conf` chỉ DNS của bạn, vd `1.1.1.1`).
2. Recursive resolver hỏi root → TLD (`.vn`) → nameserver của domain.
3. Nhận về bản ghi **A/AAAA** (IP) — hoặc **MX** (mail exchanger) nếu hỏi loại MX: MX trỏ tên máy chủ nhận mail cho domain kèm độ ưu tiên, ví dụ `mx1.example.com. preference 10`.
4. Kết quả được cache theo TTL để lần sau trả ngay.

**hostname vs domain vs FQDN.** `mail01` là **hostname** (tên máy); `example.com` là **domain** (vùng quản lý); `mail01.example.com` là **FQDN** (Full Qualified Domain Name — tên định danh đầy đủ, tra DNS là ra IP duy nhất). Trong lab, đặt hostname thật chuẩn (`hostnamectl set-hostname ftp01.lab.local`) rồi khai báo trong `/etc/hosts` — nhiều dịch vụ mail/tls từ chối chạy hoặc log lỗi lằng nhằng nếu FQDN không phân giải được hai chiều (forward + reverse).

**Socket = (IP, port, giao thức).** **Socket** là "đầu nối" mà OS cấp cho một ứng dụng, được nhận diện bằng bộ ba (địa chỉ IP, cổng, TCP/UDP). Một kết nối TCP là một **cặp socket**: `(client_ip:client_port, server_ip:server_port)` — chính vì thế một server FTP phục vụ 50 client cùng lúc vẫn phân biệt được từng client dù tất cả đều vào port 21: chúng khác nhau ở IP/port nguồn.

**Cách quan sát trong lab.**

```bash
dig mx example.com          # tra bản ghi MX (cài package dnsutils/bind9-dnsutils)
getent hosts mail01.lab.local  # resolver dùng NSS, đọc /etc/hosts + DNS
ss -tn state established     # xem các socket TCP đang ESTABLISHED (kết nối thật)
tcpdump -i any -nn port 21   # bắt gói tin ở tầng mạng để "thấy" socket vận hành
```

Nguồn:
- TCP (STD 7, RFC 9293): https://www.rfc-editor.org/info/rfc9293/
- FTP (RFC 959): https://www.rfc-editor.org/info/rfc959/ — FTPS: https://www.rfc-editor.org/info/rfc4217/
- SMTP: https://www.rfc-editor.org/info/rfc5321/ — Submission: https://www.rfc-editor.org/info/rfc6409/
- POP3: https://www.rfc-editor.org/info/rfc1939/ — IMAP4rev2 (RFC 9051): https://www.rfc-editor.org/info/rfc9051/
- DNS: https://www.rfc-editor.org/info/rfc1035/
- Bảng cổng IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

### 1.3. Bắt tay ba bước (three-way handshake) và kết thúc kết nối TCP

**Bản chất.** Vì TCP là "có kết nối", hai bên phải thống nhất tham số trước khi truyền dữ liệu: mỗi bên báo cho bên kia **ISN (Initial Sequence Number)** — số thứ tự khởi điểm — và khả năng nhận bao nhiêu byte chưa xác nhận (**window**). Việc trao đổi này gọi là **bắt tay ba bước (three-way handshake)**: SYN → SYN/ACK → ACK.

**Ví dụ với client kết nối vào port 21 (FTP):**

```
Client (192.168.56.1:52344)                 Server vsftpd (192.168.56.10:21)
        |  [SYN] seq=x, win=64240              |
        |------------------------------------->|   client chọn ISN=x, gửi SYN
        |                                      |   server cấp socket (client_ip,client_port,21)
        |  [SYN, ACK] seq=y, ack=x+1           |
        |<-------------------------------------|   server chọn ISN=y, xác nhận đã nhận x
        |  [ACK] seq=x+1, ack=y+1              |
        |------------------------------------->|   phiên TCP ESTABLISHED
        |<====== 220 (vsFTPd 3.0.5) ===========|   lúc này FTP mới bắt đầu "nói"
```

Ký hiệu: `seq` là số thứ tự byte tiếp theo bên gửi sẽ gửi; `ack = n` nghĩa "ta đã nhận đủ tới byte n−1, mong byte n". SYN và FIN mỗi loại **đốt 1 số thứ tự** dù không mang dữ liệu — nên `ack = x+1`. Điểm mấu chốt: server không thể gửi dòng chào `220` trước khi handshake xong → mọi nội dung ứng dụng đều nằm "bên trong" một kết nối đã xác lập.

**Trạng thái kết nối (state machine).** Hai phía đi qua các trạng thái: `CLOSED → LISTEN (server) → SYN_SENT/SYN_RCVD → ESTABLISHED → (truyền dữ liệu: các gói PSH, ACK qua lại)`. Server FTP sau khi fork tiến trình phục vụ sẽ trở lại LISTEN chờ client mới.

**Kết thúc phiên (teardown).** Khi client gõ `QUIT` hoặc trình mail đóng cửa sổ:

```
[FIN] → [ACK] → [FIN] → [ACK]
```

Bên gửi FIN nói "ta hết dữ liệu", bên kia ACK; rồi phía kia cũng FIN/ACK — tổng 4 gói. Trạng thái trung gian `FIN_WAIT_1/2`, `TIME_WAIT` (bên chủ động đóng chờ 2×MSL để gói muộn không lạc sang phiên sau), `CLOSE_WAIT` (nếu app quên close → socket "rò rỉ", một dạng lỗi quản lý tài nguyên hay gặp khi viết tool quét dịch vụ).

**Ý nghĩa bảo mật (sẽ dùng lại ở chương sau).** Vì server "tin" một gói vào port 21/25/143... chỉ khi nó thuộc kết nối ESTABLISHED, attacker phải hoàn tất handshake (hoặc spoof qua được state table của firewall) → đây là nền tảng của firewall stateful (mục 1.4) và của tấn công SYN flood (làm cạn bộ nhớ hàng đợi `SYN_RCVD` — có thể quan sát `ss -s` trong lab khi chạy công cụ stress *chỉ trên mạng riêng*).

**Cách quan sát trong lab.**

```bash
sudo tcpdump -i any -nn 'tcp port 21 and (tcp[tcpflags] & (tcp-syn|tcp-fin) != 0)'
# Chỉ in các gói SYN/FIN tới port 21 → đếm được số handshake/teardown
ss -tan state established '( dport = :21 )'   # các phiên FTP đang mở
nmap -sS 192.168.56.10                          # (lab) quét bán kết nối: gửi SYN, nhận SYN/ACK rồi gửi RUT (RST) để không hoàn tất handshake — cách hiểu vì sao SYN_RCVD tồn tại
```

Wireshark với filter `tcp.flags.syn==1` cho biểu đồ trực quan nhất cho người mới.

Nguồn:
- RFC 9293, mục Segment Lifecycle / Events (ba bước và 4 gói FIN): https://www.rfc-editor.org/rfc/rfc9293.html
- Wireshark (bắt gói, trực quan hóa handshake): https://www.wireshark.org/docs/

### 1.4. Firewall stateful, NAT (SNAT/DNAT) và port forwarding

**Firewall packet-filter stateful.** Firewall đời cũ chỉ đọc header từng gói độc lập (stateless: "cho vào port 21? OK/CHẶN"). Firewall **stateful** (Linux: netfilter/nftables, mặt tiền dễ dùng: `ufw`/`firewalld`) giữ **bảng kết nối (connection tracking, conntrack)**: nếu gói ra ngoài được phép, thì **các gói vào thuộc cùng kết nối đã ESTABLISHED được tự động cho về** mà không cần mở "cửa chiều vào" cho mọi port đã lắng nghe. Nguyên tắc cấu hình: chỉ **chủ động mở inbound** cho các dịch vụ cần publish (21, 22, 25, 143, ...); còn lại để stateful lo chiều "trả lời".

**NAT và hai chiều của nó.** IPv4 cạn → **NAT (Network Address Translation)** cho nhiều máy dùng IP riêng ra Internet bằng 1 IP công cộng:

- **SNAT (Source NAT) / MASQUERADE**: đổi *nguồn* khi máy trong lab đi ra (`192.168.56.10:33456 → 203.0.113.5:12000`). Máy trong VirtualBox NAT mode tự làm việc này.
- **DNAT (Destination NAT) = port forwarding**: đổi *đích* — người ngoài gõ `203.0.113.5:2222` được "dẫn" vào `192.168.56.10:22`. Đây chính là cách bạn publish SSH/SFTP server trong lab lên Internet (khai trong router/`VirtualBox NAT Port Forwarding`/`iptables -t nat`).

**Hệ quả thực tế #1 — FTP active mode "gãy" sau NAT/firewall.** FTP có 2 kênh: điều khiển (control, port 21) và dữ liệu (data) riêng. **Active mode**: client mở cổng `1024+n` rồi *báo cho server* trong lệnh PORT `("ta ở 192.168.56.1:4012, kết nối vào đó")`; server từ port 20 **chủ động connects ngược** vào client. Nếu client đứng sau NAT/firewall stateful: gói SYN từ server không khớp kết nối nào client đã *gửi ra* → bị chặn; tệ hơn, client báo IP riêng nội bộ nên server... không định tuyến được. Đó là lý do **passive mode (PASV)** ra đời: client gửi `PASV`, server trả một cổng cao do chính server mở, rồi *client chủ động kết nối đến* — hợp với stateful firewall chiều đi. Nhưng PASV lại cần *server* cho mở inbound dải cổng cao (vd `pasv_min_port=40000, pasv_max_port=40100` — mỗi tham số phải phản chiếu vào firewall và vào rule DNAT!), và nếu server sau NAT thì IP trong response PASV là IP nội bộ — vsftpd giải quyết bằng `pasv_address=<IP_công_cộng>`. Tóm lại: **hầu hết sự cố "FTP login được nhưng không list được folder" trong lab là bài toán firewall/NAT + mode, không phải hỏng FTP**.

**Hệ quả thực tế #2 — máy chủ trong lab ảo hóa.** Ở chế độ VirtualBox NAT mặc định, host là "router": SSH từ host vào VM phải cấu hình port forwarding (`ssh -p 2222 kimdv@127.0.0.1`); nếu chọn Bridged, VM nhận IP thật cùng dải mạng vật lý → mọi chuyện đơn giản hơn, phù hợp lab nhiều dịch vụ. Khi publish 25/143/995/993 qua DNAT, nhớ **stateful sẽ không tự cho inbound kết nối do server chủ động tạo** (trường hợp FTP active, hay Postfix gọi về máy phân giải blacklist qua cổng cao) — phải có module helper (nf_conntrack_ftp) hoặc mở rule rõ ràng.

**Cách quan sát trong lab.**

```bash
sudo iptables -L -n -v                 # rule filter hiện hành
sudo conntrack -L -p tcp --dport 21    # xem bảng stateful: kết nối FTP đang "được theo dõi"
sudo iptables -t nat -L -n -v          # nhìn SNAT/DNAT
# Test: đổi VM từ Bridged sang NAT → FTP active mode_fail_ ở LIST, PASV_ vẫn chạy
```

Nguồn:
- vsftpd + firewall/NAT (pasv_address, dải cổng): https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/monitoring_and_managing_system_status_and_performance/index — bài FTP qua firewall: xem thêm mục FTP trong tài liệu vsftpd trên https://access.redhat.com/ và https://wiki.archlinux.org/title/Vsftpd
- nftables/conntrack: https://netfilter.org/documentation/ và https://manksmesser.eu/~manoj/conntrack-tools/

### 1.5. Mật mã học nền tảng: đối xứng, bất đối xứng, hash, MAC, chữ ký số, TLS và SSH

**Mã hóa đối xứng (AES).** Một khóa bí mật chung dùng cho cả encrypt lẫn decrypt — nhanh, hợp lượng dữ liệu lớn (file FTP, nội dung mail, toàn bộ kênh SSH). Chuẩn hiện hành: **AES (FIPS 197)**, các mode an toàn như AES-GCM (vừa encrypt vừa xác thực). Vấn đề cố hữu: *làm sao hai bên có chung khóa mà không gặp nhau?*

**Mã hóa bất đối xứng (RSA/ECDSA).** Một cặp khóa: **public key** công khai, **private key** giữ kín; dữ liệu mã hóa bằng khóa này chỉ giải được bằng khóa kia. Chậm hơn nhiều nên chỉ dùng để **trao khóa / ký**, không mã hóa cả file. RSA (RFC 8017) và **ECDSA** (nhỏ hơn, nhanh hơn — dạng khóa `ecdsa-sha2-nistp256` bạn gặp trong SSH) là hai họ phổ biến.

**Hash vs MAC vs chữ ký số.** Ba công cụ "kiểm tra tính toàn vẹn" nhưng khác bản chất:

| Công cụ | Khóa? | Bảo vệ chống ai? | Dùng ở đâu trong đồ án |
|---|---|---|---|
| Hash (SHA-256, FIPS 180-4) | Không | Sửa đổi tình cờ/có chủ đích khi *khóa nằm cùng dữ liệu* | fingerprint cert, checksum file, lưu mật khẩu (salted hash) |
| MAC / HMAC (RFC 2104) | Khóa đối xứng chung | Người không có khóa giả mạo tag | tính toàn vẹn từng bản ghi TLS/SSH |
| Chữ ký số | Private key ký, public key verify | Chính cả *người giữ public key* (không thể giả chữ ký) — kèm **không thể phủ nhận** (non-repudiation) | chứng thư số TLS, `authorized_keys` + khóa SSH, DKIM mail |

Hash chỉ đảm bảo "không ai đổi file nếu họ không lấy được file+bản hash". Muốn *ai đó trên đường truyền* không giả được "báo cáo toàn vẹn", cần MAC (khóa chung) hoặc chữ ký (khóa công khai).

**Chứng thư số X.509, CA, chuỗi tin cậy.** Làm sao biết `pubkey` của `mail.example.com` là thật mà không phải của attacker đứng giữa? **Chứng thư số (X.509, RFC 5280)** = hồ sơ `⟨tên subject, public key, hạn dùng, ...⟩ được **CA (Certificate Authority)** ký chữ ký số. Client tin CA (danh sách gốc trong `ca-certificates` / Firefox store) → verify chữ ký trên cert → tin public key. Chuỗi cert server gửi thường gồm: leaf → intermediate → (root đã có sẵn) — **chain of trust**. Trong lab, cert **self-signed** (tự ký) hoặc cấp bởi **internal CA** của nhóm (openssl/mkcert): về toán học hợp lệ, nhưng trình mail/FTP sẽ cảnh báo "không rõ ai ký" — đúng hành vi mong đợi; trong lab thì import root CA tự tạo vào máy client để hết cảnh báo, tuyệt đối không tắt hẳn kiểm tra chứng thư rồi "quen tay" ngoài prod. Cert Let's Encrypt (ACME) cũng dùng được nếu máy trong lab có HTTPS out.

**TLS 1.2/1.3.** **TLS (Transport Layer Security)** là giao dịch "bọc" một kênh TCP thô thành kênh mã hóa+authenticating. Bắt tay TLS tóm tắt: ClientHello (liệt kê **cipher suite** — tổ hợp `[key exchange] + [chữ ký] + [AES-GCM/ChaCha20] + [HMAC]` mà client hỗ trợ) → ServerHello + cert chuỗi + key share → hai bên dựng **khóa đối xứng phiên (session keys)** qua trao đổi khóa (ECDHE), từ đó chỉ AES mã dữ liệu — kết hợp thế mạnh cả hai mục trên. TLS 1.3 (RFC 8446, 2018) rút gọn còn 1 RTT, bỏ các thuật toán cũ dễ sai; TLS 1.2 (RFC 5246) vẫn dùng được nhưng phải cấu hình cipher cẩn thận. **SSL 2.0/3.0 đã bị deprecated** (lần lượt theo RFC 6176 và RFC 7568) vì lỗi thiết kế (POODLE, BEAST...); **TLS 1.0/1.1 cũng bị RFC 8996 (2021) tuyên bố ngừng dùng** — nên trong cấu hình vsftpd/postfix/dovecot hiện đại bạn đặt tối thiểu TLS 1.2, tốt nhất 1.3.

**SSH khác TLS ở đâu.** SSH (Secure Shell, RFC 4251/4253/4254) cũng giải bài toán "kênh an toàn" nhưng theo mô hình riêng:

- **Đa kênh/kênh con (channels)**: một kết nối TCP:22 duy nhất *multiplex* nhiều "channel" — shell, forward, và các **subsystem** như `sftp` hay `scp`. FTP/FTPS cần 2–3 kênh TCP thì SFTP chỉ dùng đúng một → không đau khổ với firewall/NAT như FTP active (lý do thực tiễn lớn nhất chọn SFTP).
- **Key-based auth**: server lưu **public key** của user trong `~/.ssh/authorized_keys`, client chứng minh sở hữu private key bằng chữ ký số (thay vì gửi mật khẩu). Host cũng có key (`/etc/ssh/ssh_host_*_key`) để client biết "đúng server" — lần đầu bạn nhận fingerprint "The authenticity of host..." chính là mô hình **TOFU (Trust On First Use)**, khác TLS dựa CA.
- **Tunnel/port forwarding** (`ssh -L/-R`) — vì mọi thứ chạy trong một kênh mã hóa sẵn có, SSH dễ làm "đường hầm" cho dịch vụ khác (che port SMTP/IMAP chưa có TLS bằng SSH tunnel khi thử nghiệm).

**Cách quan sát trong lab.**

```bash
openssl s_client -connect 192.168.56.10:993 -servername imap01.lab.local
# xem negotiated protocol + cipher; thêm -tls1_1 sẽ FAIL nếu server đã chặn (đúng chính sách)
doveconf -a | grep -i 'ssl_protocols'   # tham số TLS thật của dovecot
ssh-keygen -t ed25519                   # tạo cặp khóa client cho SFTP key-based (lab)
```

Nguồn:
- TLS 1.3 RFC 8446: https://www.rfc-editor.org/info/rfc8446/ ; ngừng SSL/TLS 1.0/1.1: https://www.rfc-editor.org/info/rfc8996/ và https://www.rfc-editor.org/info/rfc7568/
- X.509/PKI: https://www.rfc-editor.org/info/rfc5280/
- SSH: https://www.rfc-editor.org/info/rfc4251/ và https://www.rfc-editor.org/info/rfc4254/ ; OpenSSH portable: https://www.openssh.com/portable.html
- AES FIPS 197 / SHA FIPS 180-4: https://csrc.nist.gov/pubs/fips/197/final , https://csrc.nist.gov/pubs/fips/180-4/final
- RFC 959 (FTP), RFC 4217 (FTP), TLS trong các dịch vụ: https://www.rfc-editor.org/info/rfc4217/

### 1.6. AAA — Authentication, Authorization, Accounting; đặc quyền tối thiểu và defense in depth

**Bản chất.** Trước mọi cổng dịch vụ luôn là câu hỏi 3A:

- **Authentication (xác thực) — "bạn là ai?"**: chứng minh danh tính. FTP: username+password qua kênh control (bất lợi nếu dùng FTP trần — mật khẩu bay plaintext, mục 1.5 chính là liều thuốc); SFTP: key hoặc password; SMTP submission: SASL (Postfix hỏi Dovecot); POP3/IMAP: user mail + mật khẩu/PAM.
- **Authorization (phân quyền) — "bạn được làm gì?"**: user `ftp` vsftpd chỉ vào được `ftp_root`, `chroot_local_user=YES` nhốt trong home; quyền read-only cho anon; mailbox của A thì B không được `SELECT` dù đã login IMAP thành công (Dovecot enforce qua `mail_location` + OS perms).
- **Accounting (ghi nhận) — "bạn đã làm gì?"**: nhật ký phiên/hành động — log FTP `200 ... OK: bytes`, Postfix ghi queue ID mỗi message (dùng để truy vết mail, mục 1.7), auth log ghi `Accepted publickey for kimdv`.

**Least privilege (đặc quyền tối thiểu).** Mỗi tiến trình/user chỉ giữ đúng quyền cần cho nhiệm vụ, không hơn. Trong 5 dịch vụ: daemon rootbind cổng thấp rồi **drop privileges** (vsftpd chạy `nobody`; Postfix fork các `nqmgr/smtp/cleanup` chạy user `_postfix`; Dovecot tách `auth` quyền cao khỏi `imap/lmtp` quyền thấp); user FTP không có shell (`/usr/sbin/nologin`); thư mục upload `chmod o+w` là *phải có*, đừng `777` "cho nhanh".

**Defense in depth (phòng thủ nhiều lớp).** Không lớp nào "tin" lớp nào: TLS mã hóa kênh (lớp 1) nhưng vẫn cần auth (2), chroot (3), firewall hạn chế inbound tới dải lab (4), fail2ban phản ứng khi thấy brute-force trong auth log (5), và audit log (6) — nếu attacker vượt 5 lớp, lớp 6 vẫn phát hiện. Chương 7-8 của tài liệu sẽ lần lượt đo từng lớp bằng chính các công cụ này.

**Cách quan sát trong lab.**

```bash
ps -o user,pid,cmd -C vsftpd -C postfix -C dovecot   # thấy ngay quá trình hạ quyền (vd nobody, _postfix)
id ftp ; getfacl /srv/ftp/upload                      # kiểm tra quyền user dịch vụ
grep -E 'Accept|Auth' /var/log/auth.log | tail        # lớp Accounting: ai login, lúc nào
```

Nguồn:
- least privilege + dịch vụ mail: https://documentation.ubuntu.com/postfix/ và https://www.postfix.org/README.html (mục privilege separation)
- privilege separation trong Dovecot: https://doc.dovecot.org/
- NIST SP 800-53 (kiểm soát AC — Access Control, AU — Audit), nền của AAA: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

### 1.7. Log hệ thống: syslog/rsyslog, journald và chỉ số phát hiện bất thường

**Bản chất.** Log là nguyên liệu thô của mọi hệ thống phát hiện sớm. Linux gom log theo hai dòng song song:

- **syslog/rsyslog** (giao thức syslog RFC 5424; rsyslog là daemon mặc định trên Ubuntu/Debian từ lâu): các daemon ghi vào socket `/dev/log`, rsyslog phân loại bằng **facility + severity** rồi chuyển tới file. Facility quan trọng cho đồ án: `mail` (Postfix), `auth/authpriv` (PAM/sshd/Dovecot auth), `daemon`/`ftp` (vsftpd nếu bật `xferlog_enable`). Ubuntu mặc định: `/var/log/mail.log` (mọi thứ mail), `/var/log/auth.log` (xác thực), `/var/log/syslog` (tổng hợp).
- **journald** (systemd): log có cấu trúc nhị phân, query bằng `journalctl`, hữu ích khi dịch vụ chạy qua systemd unit — `journalctl -u dovecot -f` theo dõi trực tiếp.

**Bốn loại log cần phân biệt** (ánh xạ vào 5 dịch vụ):

| Loại | Nội dung | Ví dụ dòng log thật (dạng chuẩn, rút gọn) |
|---|---|---|
| Kết nối | ai IP nào vào port nào | vsftpd: `CONNECT: Client "192.168.56.1"`; postfix: `connect from unknown[192.168.56.1]` |
| Xác thực | login đúng/sai | `sshd[123]: Failed password for invalid user admin from 192.168.56.1 port 52222 ssh2`; dovecot: `auth: Info: passwd-file(user,...): failed` ; vsftpd: `FAIL LOGIN: Client "192.168.56.1", "user", (tên/sai)` |
| Thao tác | việc làm sau khi vào | vsftpd `OK UPLOAD: "192.168.56.1" "a.pdf" 2034 bytes`; dovecot: `User logged in/out, Command SELECT INBOX` |
| Giao dịch mail | toàn bộ lifecycle message | postfix: `queue id A1B2C3... message-id=..., from=<>, to=<>, status=sent` (mỗi message một queue ID để lần theo qua mọi log khác) |

Lưu ý cấu hình: với vsftpd, log upload nằm ở `vsftpd.log`/`/var/log/xferlog` **chỉ khi** bật `xlog_enable`, `log_ftp_protocol=YES`; SMTPS/IMAPS khi bật full logging sẽ rất "nặng" → cân nhắc chọn lọc (đây là trade-off thật của admin).

**Chỉ số phát hiện bất thường (anomaly indicators).** Chỉ log thô chưa đủ; người quản trị tính các chỉ số trên nền log:

1. **Tần suất thất bại (failure rate)**: số `Failed password`/`FAIL LOGIN` từ cùng một IP trong 5/10 phút — tín hiệu kinh điển của brute-force (chính xác là logic mà fail2ban triển khai: đọc log, đếm regex trùng pattern, vượt `maxretry` thì chèn rule chặn).
2. **Entropy thời gian đăng nhập**: tài liệu legit thường đăng nhập giờ hành chính theo cluster; một account IMAP login rải rác đều khắp 24/7 (entropy cao bất thường) hoặc đăng nhập lúc 3 giờ sáng từ múi giờ lạ → cờ đỏ. Đo đơn giản bằng histogram theo giờ trong ngày trên `grep "Accepted"`/`grep logged in`.
3. **Volume (khối lượng)**: kilobytes/UPLOAD của một user FTP, số message một user submission gửi/giờ so với **baseline** của chính họ. SMTP volume đột biến từ một mailbox vừa đổi mật khẩu = dấu hiệu tài khoản bị chiếm để phát spam; POP3/IMAP volume đột biến từ IP lạ = mail box bị kéo toàn bộ (data exfiltration).
4. **Địa lý/thành phần**: số IP nguồn / số user trên mỗi nguồn ("1 IP thử 40 user" rất khác "40 IP cho 1 user" — credential stuffing).

Tất cả phép thử này trong tài liệu chỉ chạy **trên hạ tầng riêng của nhóm**: dựng lab, tự brute-force *lab của mình* bằng công cụ tồn tại cho mục đích đó (hydra, medusa... — chỉ để tạo mẫu log, không đưa cú pháp), rồi đo xem các chỉ số trên phát hiện ra mẫu thế nào — đó là chủ đề các chương sau.

**Cách quan sát trong lab.**

```bash
sudo tail -f /var/log/mail.log /var/log/auth.log /var/log/vsftpd.log
journalctl -u postfix -u dovecot -u vsftpd --since "1 hour ago" -o short-iso
grep -c "Failed password" /var/log/auth.log      # seed cho chỉ số tần suất
awk '/FAIL LOGIN/ {print $NF}' /var/log/vsftpd.log | sort | uniq -c | sort -rn | head
# ^ "top offenders" thủ công — phiên bản nhỏ của fail2ban (github.com/fail2ban/fail2ban)
```

Nguồn:
- RFC 5424 (syslog): https://www.rfc-editor.org/info/rfc5424/
- rsyslog: https://www.rsyslog.com/doc/ ; journald: https://docs.kernel.org/admin-guide/sysfs-bus-platform.html#systemd — thực tế dùng `man systemd.journal-fields` và https://documentation.ubuntu.com
- Pattern brute-force / jail mẫu (sshd, postfix, dovecot, vsftpd): https://github.com/fail2ban/fail2ban/tree/master/config/jail.d và https://manpages.ubuntu.com/manpages/noble/en/man5/jail.conf.5.html
- Postfix log format (truy vết queue ID): https://www.postfix.org/logfile.5.html
- Dovecot logging: https://doc.dovecot.org/configuration/core_settings/logging/

### 1.8. Kết chương

Bức nền của chương: (1) năm dịch vụ của đồ án đều là **tầng ứng dụng chạy trên TCP** với mô hình client–server; (2) mọi vấn đề "không vào được dịch vụ" hầu như quy về **socket + route + stateful firewall/NAT** — FTP active/passive là phép thử tổng hợp của cả ba; (3) mọi vấn đề "dịch vụ có an toàn không" quy về **TLS/SSH + AAA + nguyên tắc đặc quyền tối thiểu**; (4) sau cùng, muốn *biết* điều gì đang xảy ra thì cần **log đúng chỗ và chỉ số đúng cách**. Các chương 2–5 sẽ cài đặt và cấu hình cụ thể (vsftpd/FTPS, OpenSSH-SFTP, Postfix, Dovecot POP3/IMAP) — mỗi lần đụng cấu hình, hãy quay lại bảng port ở mục 1.2 và ví dụ handshake ở 1.3 để định vị mình đang ở tầng nào.

---

*Tài liệu tham khảo toàn chương — đã đối chiếu ngày 29/08/2026:*

- RFC 9293 — Transmission Control Protocol (STD 7): https://www.rfc-editor.org/info/rfc9293/
- RFC 959 — File Transfer Protocol (STD 9): https://www.rfc-editor.org/info/rfc959/
- RFC 4217 — Securing FTP with TLS: https://www.rfc-editor.org/info/rfc4217/
- RFC 5321 — SMTP: https://www.rfc-editor.org/info/rfc5321/ ; RFC 6409 — Message Submission: https://www.rfc-editor.org/info/rfc6409/
- RFC 1939 — POP3: https://www.rfc-editor.org/info/rfc1939/ ; RFC 9051 — IMAP4rev2: https://www.rfc-editor.org/info/rfc9051/
- RFC 4251/4253/4254 — SSH Architecture/Transport/Connection: https://www.rfc-editor.org/info/rfc4251/
- SFTP: chưa là RFC chính thức; chuẩn de facto là draft-ietf-secsh-filexfer (v3), dự thảo mới draft-spaghetti-sshm-filexfer qua nhóm SSHM: https://datatracker.ietf.org/doc/draft-ietf-secsh-filexfer/
- RFC 8446 — TLS 1.3: https://www.rfc-editor.org/info/rfc8446/ ; RFC 8996 — Deprecating TLS 1.0/1.1: https://www.rfc-editor.org/info/rfc8996/ ; RFC 7568 — Deprecating SSL 3.0: https://www.rfc-editor.org/info/rfc7568/
- RFC 5280 — X.509 PKI Certificate: https://www.rfc-editor.org/info/rfc5280/ ; RFC 2104 — HMAC: https://www.rfc-editor.org/info/rfc2104/
- RFC 1034/1035 — DNS: https://www.rfc-editor.org/info/rfc1035/ ; RFC 5424 — syslog: https://www.rfc-editor.org/info/rfc5424/
- NIST: FIPS 197 (AES) https://csrc.nist.gov/pubs/fips/197/final , FIPS 180-4 (SHA) https://csrc.nist.gov/pubs/fips/180-4/final , SP 800-53 Rev.5 (AC/AU controls) https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- IANA Port Registry: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
- Ubuntu 26.04 LTS "Resolute Raccoon" (LTS hiện hành, phát hành 23/04/2026; 24.04 LTS vẫn được hỗ trợ): https://documentation.ubuntu.com/release-notes/26.04/
- Documentation các dịch vụ: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/deploying_different_types_of_servers/configuring-ftp ; https://www.postfix.org/docs.html ; https://doc.dovecot.org/ ; https://www.openssh.com/manual.html ; https://github.com/fail2ban/fail2ban
- Wireshark user guide: https://www.wireshark.org/docs/wsug_html_chunked/
