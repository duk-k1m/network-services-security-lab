## 2a. Nguyên lý hoạt động: FTP, FTPS và SFTP

Chương này trình bày cách thức hoạt động "bên trong" của ba giao thức chuyển tệp phổ biến: **FTP** (File Transfer Protocol), **FTPS** (FTP over TLS) và **SFTP** (SSH File Transfer Protocol). Ba cái tên dễ gây nhầm lẫn — đặc biệt là "SFTP" *không phải* "FTP cộng thêm mã hoá" — nên phần đầu chương tập trung vào kiến trúc kênh, phiên lệnh và quá trình bắt tay (handshake) của từng giao thức; các phần cài đặt, quản trị chi tiết (vsftpd, OpenSSH...) thuộc chương sau.

Mọi quan sát paket, log và phiên mẫu trong chương này được thực hiện trong **lab mạng riêng do nhóm sở hữu** (máy client và máy server đặt trong cùng dải mạng ảo hoá), phục vụ mục đích học tập và phòng thủ.

### 2a.1 FTP: mục đích ra đời và mô hình client–server

FTP được định nghĩa trong **RFC 959 — File Transfer Protocol (October 1993)**, thuộc họ chuẩn STD 9 của IETF. Cần nhấn mạnh bối cảnh lịch sử: FTP không sinh ra năm 1993 mà có nguồn gốc từ các RFC đầu thập niên 1970; phiên bản RFC 959 chỉ là bản chuẩn hoá cuối cùng của một thiết kế **tiền-web (pre-web)** — thời mà mạng chỉ gồm các máy UNIX kết nối trực tiếp, tin cậy lẫn nhau, chưa có khái niệm "đường truyền không an toàn". Hệ quả trực tiếp của thiết kế này:

- **Chuẩn gốc hoàn toàn không có cơ chế mã hoá (encryption), xác thực mạnh hay toàn vẹn dữ liệu.** Mật khẩu đi trên mạng dưới dạng văn bản thuần (plaintext).
- Giao thức **kênh điều khiển (control channel) là văn bản ASCII**, mỗi lệnh là một dòng kết thúc bằng CRLF — đọc được ngay bằng mắt thường khi bắt gói.
- Thông điệp trả lời (reply) là **mã số 3 chữ số** kèm thông báo dạng người đọc.

Mô hình hoạt động là **client–server**: server FTP (daemon, ví dụ `vsftpd`, `ProFTPD`, `FileZilla Server`) lắng nghe ở cổng TCP 21; client kết nối tới, gửi lệnh, nhận hồi đáp, yêu cầu mở thêm kênh dữ liệu khi cần chuyển tệp. Một chi tiết kiến trúc quan trọng: FTP là giao thức "đảo ngược" — chính **server dùng cổng nguồn cố định 20 để chủ động kết nối lại phía client** trong chế độ active (xem 2a.4), điều gây ra hàng loạt vấn đề với NAT/firewall hiện đại.

Nguồn:
- RFC 959: https://www.rfc-editor.org/info/rfc959/
- STD 9 (FTP): https://www.rfc-editor.org/info/std9/

### 2a.2 Kiến trúc hai kênh, tập lệnh và mã hồi đáp

#### Hai kênh kết nối song song

FTP là giao thức **duy nhất trong nhóm khảo sát dùng hai kênh TCP riêng biệt** cho một phiên:

| Kênh | Cổng | Nội dung |
|---|---|---|
| Kênh điều khiển (control connection) | TCP **21** | Lệnh ASCII từ client, hồi đáp số từ server — kể cả tên đăng nhập/mật khẩu |
| Kênh dữ liệu (data connection) | TCP **20** (active) hoặc **cổng động** (passive) | Nội dung tệp, kết quả `LIST`, chuỗi chấp nhận tệp |

Mỗi khi cần truyền dữ liệu (danh sách thư mục, tải lên/xuống tệp), hai bên thương lượng một kênh dữ liệu *mới*, dùng xong thì đóng. Vì vậy trên Wireshark một phiên FTP hiện ra thành nhiều TCP stream — đây là dấu hiệu nhận biết đầu tiên khi phân tích log mạng trong lab.

#### Các lệnh FTP quan trọng

| Lệnh | Ý nghĩa | Reply thành công điển hình |
|---|---|---|
| `USER <tên>` | Bắt đầu định danh | `331` (cần mật khẩu) |
| `PASS <mật khẩu>` | Gửi mật khẩu — **plaintext** | `230` |
| `SYST` | Hỏi loại hệ điều hành server | `215 UNIX Type: L8` |
| `PWD` | In thư mục làm việc hiện hành | `257 "/"` |
| `CWD <dir>` | Đổi thư mục (change working dir) | `250` |
| `PASV` | Yêu cầu server mở kênh dữ liệu thụ động | `227 Entering Passive Mode (…)` |
| `PORT h1,h2,h3,h4,p1,p2` | Báo IP:cổng client để server gọi lại (active) | `200` |
| `LIST` | Liệt kê thư mục → qua **kênh dữ liệu** | `150` … `226` |
| `RETR <tệp>` | Tải xuống (retrieve) | `150` … `226 Transfer complete.` |
| `STOR <tệp>` | Tải lên (store) | `150` … `226` |
| `DELE <tệp>` | Xoá tệp | `250` |
| `QUIT` | Kết thúc phiên | `221 Goodbye.` |

#### Mã hồi đáp 3 chữ số

Chữ số đầu tiên quy định *loại* hồi đáp (theo RFC 959, trang "Reply Codes"):

- **1xx** — preliminary positive: chuẩn bị, ví dụ `150 File status okay; about to open data connection.`
- **2xx** — completion: thành công, ví dụ `200`, `226`, `230`, `250`, `257`.
- **3xx** — positive intermediate: chấp nhận một phần, chờ bước tiếp, ví dụ `331 User name okay, need password.`
- **4xx** — transient negative: thất bại tạm thời (dịch vụ chưa sẵn sàng lúc này, thử lại có thể được), ví dụ `421`, `425`.
- **5xx** — permanent negative: thất bại dứt khoát (sai cú pháp/không được phép), ví dụ `530 Not logged in`, `550 Failed to open file.`

#### Phiên FTP mẫu (ghi trong lab, client nối về vsftpd trên Ubuntu)

```text
S: 220 (vsFTPd 3.0.5)
C: USER labuser
S: 331 Please specify the password.
C: PASS LabPass2026          <-- mật khẩu đi rõ văn bản trên kênh 21
S: 230 Login successful.
C: SYST
S: 215 UNIX Type: L8
C: PWD
S: 257 "/"
C: CWD upload
S: 250 Directory successfully changed.
C: PASV
S: 227 Entering Passive Mode (192,168,10,20,195,132).
   # IP 192.168.10.20, cổng dữ liệu = 195*256 + 132 = 50052
C: LIST
S: 150 Here comes the directory listing.
S: 226 Directory send OK.
C: RETR report.txt
S: 150 Opening BINARY mode data connection for report.txt
S: 226 Transfer complete.
C: STOR note.txt
S: 150 Opening BINARY mode data connection for note.txt
S: 226 Transfer complete.
C: DELE old.txt
S: 250 File deleted successfully.
C: QUIT
S: 221 Goodbye.
```

**Quan sát trong lab:** bật Wireshark (filter `ftp`) trên máy chạy song song hoặc mirror cổng, toàn bộ transcript trên hiện nguyên văn — kể cả dòng `PASS`. Đây là bằng chứng trực quan nhất cho mục 2a.3 và 2a.8.

Nguồn:
- RFC 959 (danh sách lệnh, reply codes): https://www.rfc-editor.org/rfc/rfc959
- Wireshark FTP chapter: https://wiki.wireshark.org/FTP

### 2a.3 Xác thực FTP: plaintext và anonymous login

FTP chuẩn chỉ có đúng một cơ chế định danh: cặp `USER`/`PASS` gửi **dưới dạng văn bản thuần trên kênh điều khiển**. Không có salt, không có challenge–response, không có ràng buộc phiên — nghĩa là:

- Bất kỳ ai đứng giữa đường truyền (mirror port, ARP spoof trong cùng LAN lab) bắt được gói là có ngay credentials hợp lệ dùng mãi mãi.
- Server không biết "ai" đang gõ lệnh cho tới khi nhận dòng `PASS`; vì vậy **log FTP chỉ ghi được tên tài khoản, không phản ánh thiết bị** — điểm yếu bị lợi dụng trong brute-force (chương sau sẽ nói về fail2ban với filter `vsftpd`).

**Anonymous login** là cơ chế được RFC 1635 ("How to Use Anonymous FTP", 1994) và thực tiễn Internet quy ước: client đăng nhập bằng tài khoản `anonymous` (một số server nhận cả `ftp`), mật khẩu *theo lịch sự* là một địa chỉ email (ví dụ `ftp@example.com`) nhưng server thường **không kiểm tra giá trị này**. Chế độ này từng dùng để công bố tệp công khai (mirror phần mềm, tài liệu) mà không muốn cấp tài khoản riêng. Ngày nay nó gần như không còn lý do chính đáng (HTTPS/SFTP web mirror đã thay thế) và kéo theo rủi ro lớn:

- Người lạ đọc được toàn bộ cây thư mục công khai → **rò rỉ dữ liệu ngoài ý muốn** (cấu hình, backup đặt nhầm chỗ).
- Nếu server bật `write_enable` cho anonymous → trở thành **nơi phát tán malware, chứa nội dung vi phạm, hoặc bị làm đầy đĩa** (từ chối dịch vụ bằng hết dung lượng).
- Anonymous không có audit trail thực sự — mọi hành vi đều quy về một tài khoản.

vsftpd có khoá riêng `anonymous_enable=YES/NO` — lưu ý hai điểm hay gây nhầm lẫn: (1) gói quy định server là `vsftpd`, không phải `ftp` (package `ftp` chỉ là client dòng lệnh); (2) tệp cấu hình đóng gói sẵn `/etc/vsftpd.conf` trên Ubuntu từ trước đến nay bật `anonymous_enable=YES` kèm chú thích "allowed by default if you comment this out" — nghĩa là **chỉ comment dòng này ra KHÔNG tắt được anonymous** (mặc định compiled-in của vsftpd là YES; một số bản Debian/RHEL đóng gói `NO`). Quản trị viên phải đặt tường minh `anonymous_enable=NO` nếu không dùng; phần cấu hình chi tiết thuộc chương quản trị.

Nguồn:
- RFC 1635: https://www.rfc-editor.org/rfc/rfc1635
- vsftpd man page: https://manpages.ubuntu.com/manpages/noble/man5/vsftpd.conf.5.html
- Red Hat — FTP/FTPS with vsftpd guide: https://docs.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/deploying_network_services/index

### 2a.4 FTP Active vs Passive: hai chiều mở kênh dữ liệu

Vấn đề của FTP nằm ở kênh dữ liệu: *ai là bên khởi tạo (SYN) kết nối TCP thứ hai?*

#### Active mode (PORT) — server gọi lại client

Client ra lệnh `PORT` kèm IP + cổng tạm của chính nó, rồi **server chủ động kết nối từ cổng 20 của server tới cổng đó**:

```text
Client                                    Server
   |  ---- TCP SYN (control) :5xxxx -> :21 ---->  |
   |  <== 220/230 ... (điều khiển) ==============>  |
   |  ---- PORT 192,168,10,5,200,17 ------------>  |  "hãy gọi tôi ở 192.168.10.5:51217"
   |  ---- LIST -------------------------------->  |
   |  <==== TCP SYN :20 -> 192.168.10.5:51217 ===  |  <-- SERVER kết nối CHỦ ĐỘNG vào client
   |  ====== dữ liệu (danh sách/tệp) ============>  |   (chiều ngược chiều điều khiển)
   |  <== 226 Transfer complete ================>  |
```

**Vì sao active hỏng sau NAT/firewall của client:** NAT private chỉ cho phép inbound kết nối *được ánh xạ trước* bởi một outbound gần đó; gói SYN từ server (cổng 20) nhắm vào cổng tạm của client bị NAT/firewall chặn vì không có "cuộc hẹn" nào trong bảng mapping — và tệ hơn, IP client gửi trong lệnh `PORT` là **IP riêng** (192.168.x.x) mà server không định tuyến được. Triệu chứng kinh điển: login OK, `LIST` treo rồi timeout `425 Can't open data connection` (vsftpd in mã 425 với chuỗi "Failed to establish connection."). Đây là lý do mọi client FTP hiện đại **mặc định dùng passive**.

#### Passive mode (PASV) — client gọi cả hai kênh

Client gửi `PASV`; server *lắng nghe* một cổng động, trả về trong reply `227` dạng tuple `(h1,h2,h3,h4,p1,p2)` với `port = p1*256 + p2` (trong phiên mẫu ở 2a.2 là 50052). Sau đó client mở kết nối dữ liệu *đi vào* server:

```text
Client                                    Server
   |  ---- control =============================>  :21
   |  ---- PASV -------------------------------->  |
   |  <== 227 (192,168,10,20,195,132) =========  |  "tôi nghe ở :50052"
   |  ---- TCP SYN -> :50052 (client chủ động) ->  |
   |  <===== dữ liệu ==========================   |
   |  <== 226 =================================  |
```

**Cái giá của passive:** tường lửa *phía server* phải cho vào **một dải cổng động** chứ không riêng 20/21. vsftpd quản lý dải này bằng hai tham số trong `/etc/vsftpd.conf`:

```ini
pasv_enable=YES          # bật chế độ passive (client hiện đại cần)
pasv_min_port=50000      # cổng động thấp nhất — thu hẹp dải để siết firewall
pasv_max_port=50100      # cao nhất; mở đúng dải này trên firewall: INPUT tcp 50000:50100
pasv_address=203.0.113.10 # IP công khai ghi trong reply 227 khi server sau NAT
```

Nếu `pasv_address` không được đặt khi server đứng sau NAT, reply `227` trả về IP nội bộ → client không kết nối được kênh dữ liệu — lỗi cấu hình kinh điển khi dựng lab có port-forward.

**Quan sát trong lab:** chạy `tcpdump -i any -nn 'port 21 or portrange 50000-50100'` trên server; passive mode sẽ thấy SYN **từ client** tới dải cổng cao, còn active mode thấy SYN **từ server:.20** — hai fingerprint firewall-log hoàn toàn khác nhau.

Nguồn:
- RFC 959 (PORT/PASV): https://www.rfc-editor.org/rfc/rfc959
- RFC 1579 — "Firewall-Friendly FTP" (1994, giải thích vì sao client đứng sau firewall nên ưu tiên PASV): https://www.rfc-editor.org/rfc/rfc1579
- Red Hat vsftpd guide (pasv_min_port/pasv_max_port): https://docs.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/deploying_network_services/setting-up-an-ftp-server_deploying-network-services

### 2a.5 FTPS: "FTP over TLS" — explicit và implicit

FTPS giữ nguyên **toàn bộ giao thức FTP (hai kênh, lệnh, reply code)** và bọc kênh điều khiển (tuỳ chọn cả kênh dữ liệu) trong TLS. Có hai biến thể dễ nhầm:

- **Explicit FTPS (FTPES)** — chuẩn hoá trong **RFC 4217 "Securing FTP with TLS" (October 2005)**, obsoleted RFC 2228. Client kết nối **bình thường vào port 21** bằng plaintext, rồi ra lệnh nâng cấp:
  ```text
  C: AUTH TLS          # "từ giờ từ đây kênh điều khiển là TLS"
  S: 234 Authentication command accepted.
  === TLS handshake (ClientHello ... Finished) ===
  C: PBSZ 0            # protection buffer size = 0 (bắt buộc trước PROT)
  S: 200 PBSZ=0
  C: PROT P            # bảo vệ LUÔN dữ liệu trên kênh dữ liệu (P), mặc định là C=clear
  S: 200 Protection level set to Private
  ```
  Vì phiên *bắt đầu plaintext rồi mới mã hoá*, explicit cho phép nhiều virtual host dùng chung port 21 — nhưng cũng có nghĩa nếu không enforce, phiên có thể chạy trót lọt ở chế độ không mã hoá.
- **Implicit FTPS** — mã hoá **ngay từ byte đầu tiên** trên cổng dành riêng **TCP 990** (đăng ký IANA, service-name `ftps`). Cơ chế này ra đời *trước* RFC 4217 như một thoả thuận de facto, bị coi là **deprecated** so với explicit nhưng vẫn phổ biến. Vì handshake TLS diễn ra trước khi có bất kỳ lệnh FTP nào, implicit không thể dùng chung port với FTP thường.

Điểm yếu cố hữu còn lại của cả hai biến thể: **kênh dữ liệu vẫn là các TCP kết nối riêng**, phải tự lo bảo vệ bằng `PROT P`, và bài toán dải cổng passive vẫn nguyên — firewall phức tạp hơn SFTP một bậc.

Trong lab: `openssl s_client -connect <ip-server>:990` sẽ thấy bắt tay TLS mà không cần câu lệnh ứng dụng nào (implicit); với explicit trên port 21, Wireshark giải được toàn bộ lệnh cho tới `AUTH TLS` rồi chuyển sang dạng TLS encrypted.

Nguồn:
- RFC 4217: https://www.rfc-editor.org/info/rfc4217/ (obsolete RFC 2228: https://www.rfc-editor.org/rfc/rfc2228)
- Wikipedia FTPS (tổng quan implicit/explicit, cổng 990): https://en.wikipedia.org/wiki/FTPS

### 2a.6 SFTP: SSH File Transfer Protocol — không phải "FTP + TLS"

**SFTP về bản chất là một giao thức hoàn toàn khác**, chỉ tình cờ trùng họ tên: nó là **SSH File Transfer Protocol**, chạy như một **subsystem** (chương trình con) trên nền kênh đã mã hoá của SSH phiên bản 2, qua **TCP port 22** — cùng kết nối, cùng hàng rào mã hoá với lệnh đăng nhập SSH. Tên đăng nhập/mật khẩu để mở kênh con này do chính SSH xác thực (password, khoá công khai, keyboard-interactive...).

**Trạng thái chuẩn hoá (đã xác minh 8/2026):** SFTP **chưa bao giờ là một RFC**. Chuẩn bị viết trong các Internet-Draft của IETF qua hai thế hệ làm việc — nhóm `secsh` cũ với `draft-ietf-secsh-filexfer-*` (bản -02 khai sinh protocol **version 3**, được cài đặt rộng nhất; bản -13 cuối cùng năm 2005 đã "no longer active"), sau đó được nhóm **SSHM (Secure Shell Maintenance)** nối lại qua draft cá nhân `draft-spaghetti-sshm-filexfer-00` (07/2025, hết hạn 01/2026). Tính đến tháng 8/2026 **vẫn chưa có RFC cho SFTP**; SSHM WG tiếp tục thảo luận tại IETF 124 (11/2025) và IETF 126 (07/2026). Tài liệu tham chiếu *de facto* thực tế là man page OpenSSH (`sftp(1)`, `sftp-server(8)`) — vì OpenSSH chính là implementation chi phối thị trường.

**Giao thức là binary request/response, không phải văn bản ASCII.** Client và server trao đổi các gói theo kiểu SSH channel:

| Gói | Hướng | Vai trò |
|---|---|---|
| `INIT` / `VERSION` | C→S / S→C | Bắt tay chọn phiên bản giao thức (thường v3) |
| `OPEN` / `CLOSE` | C→S | Mở/đóng tệp hoặc thư mục (kèm cờ READ/WRITE/CREATE...) |
| `READ` / `WRITE` | C→S | Đọc/ghi theo offset — **không cần kênh thứ hai** |
| `STATUS` / `HANDLE` / `DATA` / `NAME` / `ATTRS` | S→C | Hồi đáp kiểu SSH_FXP_* (mã 101–105) |
| `STAT` / `LSTAT` / `FSTAT` | C→S | Lấy metadata tệp |
| `OPENDIR` / `READDIR` | C→S | Liệt kê thư mục |
| `REMOVE` / `RENAME` / `MKDIR` / `RMDIR` / `REALPATH` | C→S | Thao tác quản lý |

Vì mọi thứ — *cả "lệnh" lẫn dữ liệu* — chảy trong một kênh SSH đã mã hoá nên **không có khái niệm active/passive, không có cổng dữ liệu động, firewall chỉ thấy port 22**, và người sniff không đọc được gì ngoài dữ liệu mã hoá. SFTP cũng có các lợi ích kiến trúc FTP không có: resume theo offset chính xác, thao tác đồng thời nhiều tệp trên một kết nối, và khi cần chỉ một TCP connection cho cả phiên.

**Quan sát trong lab:**

```bash
sftp -vvv labuser@192.168.10.20
# debug client in ra vòng đời gói thật, ví dụ:
# debug2: channel 0: open confirm rwindow 0 rmax 32768
# request #3: open "report.txt" 1        (SSH_FXP_OPEN)
# incoming packet: type 102             (SSH_FXP_HANDLE)
# request #4: read 32768 bytes           (SSH_FXP_READ)
```

Ở phía server, daemon `sftp-server` (log qua `Subsystem sftp ... -l INFO` trong `sshd_config`) ghi từng thao tác open/read/write vào syslog — nguồn log giám sát chính của SFTP, khác hẳn log `xferlog` của vsftpd.

Nguồn:
- draft-ietf-secsh-filexfer-13 (lịch sử): https://datatracker.ietf.org/doc/draft-ietf-secsh-filexfer/
- draft-spaghetti-sshm-filexfer-00 / hoạt động SSHM WG: https://datatracker.ietf.org/doc/draft-spaghetti-sshm-filexfer/ và https://datatracker.ietf.org/group/sshm/
- OpenSSH portable man pages: https://www.openssh.com/portable.html ; `sftp-server(8)`: https://man.openbsd.org/sftp-server.8
- RFC 4253 (SSH transport layer): https://www.rfc-editor.org/info/rfc4253/

### 2a.7 Bảng so sánh tổng hợp FTP vs FTPS vs SFTP

| Tiêu chí | FTP | FTPS (explicit/implicit) | SFTP |
|---|---|---|---|
| Cổng | 21 (+20/động) | 21 (explicit) / 990 (implicit) (+ dải động) | 22 (chung với SSH) |
| Số kênh TCP | 2 (control + data), data mở lại mỗi lần truyền | 2 — như FTP, thêm thương lượng TLS cho từng kênh | **1** — tất cả qua SSH channel |
| Cái gì được mã hoá | **Không gì cả** | Control luôn (sau AUTH TLS); data *chỉ khi* `PROT P` | **Tất cả**: lệnh, dữ liệu, tên tệp, mật khẩu |
| Xác thực | USER/PASS plaintext (+PAM phía sau) | SSH/PAM + có thể kèm TLS client cert | SSH: password, **khoá công khai**, certificate |
| Firewall-friendliness | Active **rất kém** (server gọi vào client); passive cần dải cổng | Kém như FTP: vẫn cần dải passive ports | **Tốt** — mở đúng 1 cổng 22 |
| Giao diện giao thức | ASCII command + reply 3 số | Như FTP, bọc TLS | **Binary** INIT/OPEN/READ/WRITE/STATUS |
| Nền tảng chuẩn hoá | RFC 959 (1993) | RFC 4217 (2005) | Chưa có RFC; draft IETF + OpenSSH de facto |
| Hiệu năng | Cao nhất trên mạng hợp nhất (không TLS CPU) | Tốt; thêm chi phí TLS handshake mỗi kênh | Tốt; slightly slower do một pipe + CPU mã hoá; với AES-NI hiện nay khác biệt thường không đáng kể |
| Trường hợp dùng phù hợp | Chỉ lab cô lập / legacy device không TLS | App cũ buộc FTP semantics + cần TLS; công bố tệp lớn | **Khuyến nghị chung** cho MFT, automation, chuyển tệp qua WAN |

### 2a.8 Dữ liệu có được mã hóa mặc định không?

Câu trả lời thẳng cho từng giao thức:

- **FTP: KHÔNG.** Mọi thứ — credentials, tên tệp, nội dung tệp — đi plaintext. Không có biến thể "đã bật mã hoá"; nếu thấy "encrypted FTP" thì đó thực chất là FTPS hoặc SFTP. FTP chỉ chấp nhận được trong đoạn mạng cô lập có chủ đích và có giám sát.
- **FTPS: MẶC ĐỊNH CHƯA ĐỦ.** Explicit (RFC 4217) *cho phép* mã hoá nhưng không *buộc*: client có thể không gửi `AUTH TLS` và server nếu cấu hình lỏng vẫn phục vụ plaintext; kênh dữ liệu mặc định là clear cho tới khi có `PROT P`. Muốn "mã hoá mặc định thật sự" phải enforce ở server (vsftpd: `ssl_enable=YES` + `allow_anon_ssl=NO` + `force_local_data_ssl=YES` + `force_local_logins_ssl=YES`). Implicit trên 990 mã hoá từ byte đầu nên an toàn hơn theo bản chất, nhưng là cơ chế cũ/deprecated.
- **SFTP: CÓ, tuyệt đối.** Không tồn tại đường "chạy không mã hoá" — SFTP được sinh ra là subsystem của SSH đã hoàn tất key exchange; nếu SSH handshake chưa xong thì không có phiên SFTP. (Cấu hình có thể chọn *thuật toán yếu*, nhưng "plaintext" thì không.)

**Tóm tắt nguyên lý của chương:** FTP thiết kế 1971–1993 cho một Internet tin cậy nên dùng hai kênh plaintext; FTPS "vá" TLS vào đúng kiến trúc hai kênh đó; SFTP bỏ hẳn mô hình FTP và đặt thao tác tệp vào trong một kênh SSH đã mã hoá. Hiểu được *vị trí kênh và cái gì đi trên từng kênh* là chìa khoá cho cả phần nguy cơ tấn công (chương 3) lẫn phần phát hiện xâm nhập qua log/paket (chương 4) của tài liệu.

Nguồn:
- vsftpd.conf man page (ssl_enable, force_local_data_ssl): https://manpages.ubuntu.com/manpages/noble/man5/vsftpd.conf.5.html
- RFC 4217 §4 (AUTH TLS, PBSZ, PROT): https://www.rfc-editor.org/rfc/rfc4217
