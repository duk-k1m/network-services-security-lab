## 3b. Công cụ phía client và giám sát: FileZilla, Thunderbird, Wireshark, UFW, Fail2ban, nhật ký hệ thống

Chương 3a đã trình bày cách cài đặt và cấu hình các server FTP/FTPS/SFTP, SMTP (Postfix), POP3/IMAP (Dovecot). Chương 3b này hoàn thiện bức tranh "lab A" của đồ án bằng các công cụ mà người quản trị (administrator) thực sự dùng hằng ngày: client để kết nối (FileZilla, Thunderbird), công cụ quan sát gói tin (Wireshark), tường lửa (UFW), công cụ chống brute-force (Fail2ban) và hệ thống nhật ký (logging). Mỗi mục trình bày theo ba tầng: **bản chất** → **ví dụ cấu hình** → **cách quan sát trong lab**.

> **Phạm vi đạo đức — nhắc lại:** mọi phép thử trong chương này (capture gói tin, đăng nhập sai nhiều lần để kích hoạt Fail2ban, quét port...) chỉ thực hiện trên **mạng lab riêng do nhóm sở hữu** (VM nội bộ, không định tuyến ra Internet công cộng). Việc capture mạng của người khác hoặc của hệ thống không thuộc quyền sở hữu là vi phạm pháp luật (ở Việt Nam: Luật An toàn thông tin mạng 2015, Bộ luật Hình sự 2015).

---

### 3b.1. FileZilla — client FTP/FTPS/SFTP đa giao thức

#### 3b.1.1. Bản chất: một client, ba giao thức khác nhau

FileZilla là mã nguồn mở, chạy được trên Windows/Linux/macOS, hỗ trợ ba giao thức mà đồ án nghiên cứu:

| Giao thức | Bản chất | Port mặc định | Có mã hóa? |
|---|---|---|---|
| FTP (RFC 959) | Điều khiển + dữ liệu tách hai kênh TCP | 21 (command) | Không — mật khẩu đi dạng rõ (cleartext) |
| FTPS (RFC 4217) | FTP + TLS; "explicit" = bắt đầu trên port 21 rồi nâng cấp bằng lệnh `AUTH TLS` | 21 hoặc 990 ("implicit", đã lỗi thời) | Có (toàn bộ phiên sau handshake) |
| SFTP | Giao thức file chạy "trên" SSH (không liên quan FTP!), chuẩn của IETF từng là draft-ietf-secsh-filexfer, nay do OpenSSH duy trì | 22 | Có (từ gói tin đầu tiên) |

Điểm hay bị nhầm nhất: **SFTP không phải "FTP qua SSH" theo nghĩa FTP được bọc**; nó là một giao thức hoàn toàn khác, chỉ "đi ké" kênh SSH đã xác thực và mã hóa sẵn. Vì vậy khi dựng lab, mở port 22 là đủ cho SFTP — không cần mở port 21.

#### 3b.1.2. Site Manager: các mục cần hiểu khi cấu hình

Trong FileZilla, mở **File → Site Manager → New site**. Các trường quan trọng:

- **Protocol**: chọn *FTP - File Transfer Protocol*, *SFTP - SSH File Transfer Protocol*, hoặc *FTPS - FTP over TLS*.
- **Encryption** (chỉ hiện khi Protocol = FTP/FTPS) — đây là nơi thể hiện rõ nhất quan điểm bảo mật:
  - *Only use plain FTP (insecure)*: **không mã hóa gì cả** — chỉ dùng trong lab demo để sinh viên **chứng minh** mật khẩu bị nghe lén được (xem 3b.3.4). Ngoài lab: cấm dùng.
  - *Require explicit FTP over TLS*: kết nối mở trên port 21 ở dạng clear-text, sau đó client gửi `AUTH TLS` để nâng cấp lên TLS trước khi gửi bất kỳ thông tin đăng nhập nào. Đây là lựa chọn đúng cho FTPS kiểu explicit (RFC 4217).
  - *Require FTP over TLS if available*: tự động thử TLS nhưng **im lặng quay về plain FTP nếu server không hỗ trợ** — nguy hiểm hơn vì kẻ tấn công có thể cắt TLS (strip) và client vẫn đăng nhập, lộ mật khẩu.
  - *Require interactive FTP over TLS*: như trên nhưng dừng lại hỏi người dùng — an toàn hơn khi muốn chủ động.
- **Logon Type**: *Normal* (khai báo user/pass), *Interactive* (nhập tay từng lần), *Key file* (SFTP dùng khóa SSH — khi đó trường User có thể để trống nếu key đã chỉ định danh tính).
- **Servertype**: thường để *Default* để FileZilla tự thăm dò (gửi lệnh `SYST`). Chỉ chọn tường minh (UNIX, FTP over TLS capable server...) khi server cố tình ẩn danh `SYST` và autoscan không nhận ra.
- **Passive mode** (tab Transfer Settings): FTP cần một kênh TCP thứ hai cho dữ liệu. *Passive (PASV)*: client chủ động kết nối đến port dữ liệu do server chỉ định — **khuyến nghị** khi client đứng sau NAT/firewall. *Active (PORT)*: server gọi ngược về client — thường bị firewall phía client chặn. Trong lab, nếu kết nối được 21 nhưng `LIST` treo → tích cực chuyển sang PASV.

Mẫu một site lab đọc được từ giao thức (chỉ để demo):

```text
Host: 192.168.56.10   # IP "host-only" của VM server trong VirtualBox/VMware
Port: 21              # explicit FTPS
Protocol: FTP
Encryption: Require explicit FTP over TLS
Logon Type: Normal
User: ftpuser         # tài khoản ảo trong /etc/vsftpd passwd file của lab
```

#### 3b.1.3. Log window của FileZilla và cách đọc

Khung dưới cùng (Message window) ghi lại **từng dòng trao đổi giao thức**, là tài liệu học liệu tốt nhất cho người mới. Ví dụ đọc một kết nối plain FTP:

```text
Command: USER ftpuser
Response: 331 Please specify the password.   # server đồng ý cho nhập mật khẩu
Command: PASS ********                        # FileZilla che mask khi hiển thị...
Status: Connection established...              # ...nhưng trên wire thì KHÔNG che
```

Quy tắc đọc response code FTP (RFC 959): nhóm `1xx/2xx` = thành công/tạm chấp nhận, `3xx` = cần thêm thông tin (331 chờ PASS), `4xx` = lỗi tạm thời, `5xx` = lỗi vĩnh viễn (530 = đăng nhập sai). Với SFTP, log window hiện các dòng `Status: Remote directory: ...` và tiến trình từng file — không có lệnh FTP nào xuất hiện, vì SFTP dùng giao thức riêng.

**Quan sát trong lab:** bật *Debug → Output debug information* rồi so sánh log của cùng một thao tác upload qua (a) plain FTP, (b) explicit FTPS, (c) SFTP — thấy ngay khác biệt handshake và cảnh báo chứng chỉ.

Nguồn:
- FileZilla wiki (hướng dẫn Site Manager / Encryption): https://wiki.filezilla-project.org/
- RFC 959 (FTP): https://www.rfc-editor.org/rfc/rfc959 — cập nhật thành STD 9 bởi RFC 959 (2024, thay RFC 1123 phần FTP)
- RFC 4217 (FTP over TLS): https://datatracker.ietf.org/doc/html/rfc4217

---

### 3b.2. Thunderbird — client thư đồng thời là "máy tạo bằng chứng" TLS

#### 3b.2.1. Wizard tự động: ISP DB và autoconfig

Thunderbird liên kết một tài khoản thư gần như "tự động". Quy trình phát hiện (autoconfiguration) theo tài liệu Mozilla:

1. Tra **ISPDB** (Internet Service Provider Database) của Mozilla tại `https://autoconfig.thunderbird.net/v1.1/<domain>`.
2. Không thấy → thăm dò các URL "well-known" trên chính hạ tầng của nhà cung cấp: `https://<domain>/.well-known/autoconfig/mail/config-v1.1.htm` và `http://autoconfig.<domain>/mail/config-v1.1.xml` (tên host theo chuẩn `autoconfig.<domain>` hoặc cấu hình qua bản ghi DNS `_automx`).
3. Không thấy tiếp → đoán cổng theo tập hợp heuristic chuẩn (imap/993 SSL, smtp/465 hoặc 587...).

Kết quả là một file XML mô tả hostname, port, socketType (`SSL` = implicit TLS, `STARTTLS` = nâng cấp, `plain` = không mã hóa) và method xác thực. **Với lab của đồ án**, server mail nội bộ không có tên DNS công khai nên wizard sẽ thất bại — chuyển sang cấu hình tay, hoặc (nâng cao) nhóm tự phục vụ file `config-v1.1.xml` để mô phỏng một ISP thật.

#### 3b.2.2. Manual config: chọn giao thức và mã hóa

Account Settings → Account Actions → Add Mail Account → *Configure manually*:

- Nhận/Incoming: **IMAP** (khuyến nghị — mail đồng bộ 2 chiều trên server, các thao tác đọc/xóa/label phản ánh trạng thái server) hoặc **POP3** (tải về một chiều, lịch sử nằm ở client).
- Outgoing: **SMTP**.
- Mục *Connection security* có ba lựa chọn, tương ứng ba mức rủi ro:
  - **SSL/TLS**: bắt đầu TLS ngay từ gói đầu tiên → cổng 993 (IMAPS), 995 (POP3S), 465 (SMTPS/submission-tunnel).
  - **STARTTLS**: kết nối clear-text rồi nâng cấp → cổng 143 (IMAP), 110 (POP3), 25/587 (SMTP; 587 là cổng "submission" theo RFC 6409, bắt buộc xác thực, khuyến nghị cho client).
  - **None**: chỉ dùng để lab **chứng minh mật khẩu lộ trên wire** (xem Wireshark bên dưới). Thunderbird hiện chữ "Not recommended" bằng đỏ và xác nhận hai lần trước khi cho phép — thiết kế "đánh thức" người dùng.
- **Cổng tự đổi khi chọn loại mã hóa**: chọn SSL/TLS thì trường Port tự nhảy sang 993/995/465; chọn None về 143/110/25. Đây là manh mối để sinh viên đoán "server này đang phục vụ kiểu gì" chỉ bằng cách nhìn cấu hình client.

Bảng cổng tham chiếu nhanh cho lab:

| Dịch vụ | Clear-text | Implicit TLS (SSL) | STARTTLS |
|---|---|---|---|
| IMAP | 143 | 993 | 143 |
| POP3 | 110 | 995 | 110 |
| SMTP (submit) | 25/587 | 465 | 587 |

#### 3b.2.3. Profile và nơi lưu mật khẩu

Hồ sơ (profile) Thunderbird chứa toàn bộ mail đã cache, danh bạ và file `logins.json` (mật khẩu). Nơi lưu (Linux): `~/.thunderbird/<random>.default-release/`; Windows: `%APPDATA%\Thunderbird\Profiles\`. Mặc định mật khẩu được mã hóa bằng khóa nằm trong `key4.db`; nếu **không đặt Master Password** thì `key4.db` nằm ngay trên đĩa và bất kỳ ai đọc được profile đều giải được mật khẩu (Firefox/Thunderbird đã ngừng dùng tên file cũ `cert8.db`/`key3.db` từ các bản nhiều năm trước).

- **Master Password** (Preferences → Privacy → Passwords → Use a Primary Password): thêm một lớp khóa đối xứng — `key4.db` trở nên vô dụng nếu không có mật khẩu chính. Khuyến nghị bật cho mọi máy thật.
- Trên Linux bản tích hợp, Thunderbird có thể dùng **OS password manager** (GNOME Keyring/kwallet) thay cho `logins.json`.

**Thí nghiệm lab:** copy thư mục profile sang máy khác, mở Thunderbird bằng bản portable → email tự đăng nhập mà không hỏi mật khẩu → chính là lý do phải bật Master Password.

#### 3b.2.4. SSLKEYLOGFILE: xuất khóa TLS để giải mã trong Wireshark (kỹ thuật chủ lực của lab A)

Thunderbird (như Firefox) dùng thư viện **NSS**, vốn hỗ trợ chuẩn *NSS Key Log Format*: nếu biến môi trường `SSLKEYLOGFILE` trỏ tới một đường dẫn, mọi phiên TLS mới do ứng dụng khởi tạo sẽ được ghi **khóa bí mật phiên (session keys)** vào file đó dưới dạng văn bản:

```text
CLIENT_RANDOM 7a3f...e91b 4d2c...f0a7   # mỗi dòng: nhãn + client-random + khóa
```

Cách làm trên Linux (GUI launcher thường KHÔNG kế thừa biến môi trường → phải chạy từ shell):

```bash
export SSLKEYLOGFILE="$HOME/sslkey.log"   # đặt TRƯỚC khi khởi động Thunderbird
thunderbird &                              # phiên cũ đang chạy phải tắt hẳn trước
```

Windows: đặt biến trong *System → Environment Variables* cho user, khởi động lại Thunderbird. Lưu ý Mozilla **cố ý hiển thị cảnh báo bảo mật** khi phát hiện `SSLKEYLOGFILE` đang bật — vì file key log + pcap = đọc được toàn bộ mail đã "mã hóa"; đây đúng là điểm dạy học của kỹ thuật. Sau đó nạp file vào Wireshark (xem 3b.3.5).

Không cần mở Security Device Manager theo cách thủ công: với Thunderbird/NSS, `SSLKEYLOGFILE` là con đường chuẩn và được tài liệu chính thức xác nhận. Nếu cần chọn/xóa thiết bị lưu chứng chỉ, *Preferences → Settings → Encryption → Devices → Security Device Manager* (nơi quản lý token PKCS#11 và key4.db).

Nguồn:
- Thunderbird Autoconfiguration spec: https://wiki.mozilla.org/Thunderbird:Autoconfiguration và https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
- ISPDB GitHub: https://github.com/thunderbird/autoconfig
- NSS Key Log Format: https://nss-crypto.org/reference/security/nss/legacy/key_log_format/index.html
- Mozilla về SSLKEYLOGFILE: https://support.mozilla.org/en-US/kb/automatic-account-configuration , https://support.mozilla.org/en-US/kb/sslkeylogfile-warning
- RFC 6409 (Message Submission): https://www.rfc-editor.org/rfc/rfc6409

---

### 3b.3. Wireshark — "tai mắt" của quản trị và của kẻ tấn công

#### 3b.3.1. Nguyên lý capture: vì sao không phải lúc nào cũng "bắt được"

Wireshark dựa trên thư viện **libpcap** (Linux/macOS) hoặc **Npcap** (Windows) để nhận bản sao mọi khung tin đi qua card mạng. Hai điều kiện vật lý quyết định capture có thu được lưu lượng của máy khác không:

- **Promiscuous mode** (chế độ lẫn lộn): card mạng nhận cả khung không dành cho mình. Mặc định card chỉ nhận khung có đúng MAC đích. Khi bật bằng `ip link set <iface> promisc on` (hoặc chọn trong Wireshark), mới mong thấy traffic "quá cảnh".
- **Hub vs Switch**: mạng hub (thiết bị lớp 1) phát broadcast mọi cổng → promiscuous mode bắt được hết. Switch hiện đại chỉ gửi khung đến đúng cổng đích → muốn "nghe lén" phải dùng **port mirroring/SPAN** trên switch, hoặc ARP spoofing (chỉ đề cập mức tồn tại, nằm ngoài phạm vi lab phòng thủ của đồ án). **Vì vậy trong lab dùng mạng host-only/internal của VirtualBox/VMware, capture trên adapter của máy "trung tâm" hoặc ngay trên máy client/server là hợp lệ và an toàn** — không ảnh hưởng mạng thật bên ngoài.

#### 3b.3.2. Capture filter (BPF) vs Display filter — đừng nhầm

| | Capture filter (BPF) | Display filter |
|---|---|---|
| Chạy khi nào | Lúc ghi gói — quyết định gói nào được GIỮ lại | Lúc xem — chỉ ẩn/hiện trên giao diện |
| Vị trí đặt | Ô "Filter" của capture box | Thanh "Display filter" đầu cửa sổ |
| Cú pháp | `tcp port 21 or tcp port 25 or tcp port 110 or tcp port 143` | `ftp \|\| smtp \|\| pop \|\| imap` |
| Hệ quả dùng sai | Lọc luôn → không "hồi cứu" được gói đã bỏ | Đã capture đủ → đổi filter thoải mái |

Mẹo lab: capture với bộ BPF rộng `tcp port 20 || tcp port 21 || tcp port 25 || tcp port 110 || tcp port 143 || tcp port 465 || tcp port 587 || tcp port 990 || tcp port 993 || tcp port 995`, rồi dùng display filter để điều hướng.

#### 3b.3.3. Follow TCP Stream và bằng chứng cleartext

Chuột phải một gói FTP → **Follow → Follow TCP Stream** mở nguyên đoạn hội thoại dạng văn bản:

```text
USER ftpuser
PASS MatKhauLab2026!        # ← đọc nguyên văn: bằng chứng plain FTP không an toàn
...
+OK Logged in.               # (tương tự với POP3; SMTP: 235 Authentication successful)
```

Cùng thao tác trên stream IMAP/POP3/SMTP ở chế độ None/STARTTLS-trước-nâng-cấp cũng cho kết quả tương tự với `LOGIN`/`AUTH LOGIN` (AUTH LOGIN chỉ là base64, **không phải mã hóa** — ai cũng giải được). Đây là slide "khoảnh khắc giác ngộ" trong báo cáo đồ án.

#### 3b.3.4. Decode As

Wireshark tự nhận diện giao thức theo cổng quen thuộc. Khi server lab chạy ở cổng lạ (SMTP trên 2525, FTPS-control trên 2121...), chọn gói → Analyze → **Decode As** → ép cột *Current* sang `FTP`/`SMTP`/`IMAP`/`POP`. Đặc biệt với **implicit TLS trên cổng không chuẩn** (SMTPS 2465...), phân tích vẫn đúng nếu decode là TLS rồi bật giải mã (mục sau).

#### 3b.3.5. Giải mã FTPS/SMTP-TLS để CHỨNG MINH "không đọc được nội dung nữa"

Đây là thí nghiệm đối chứng của 3b.3.3, dùng chính key log của Thunderbird/FileZilla:

1. Mở `SSLKEYLOGFILE` (Thunderbird — xem 3b.2.4; FileZilla từ bản mới cũng ghi key log khi bật debug, hoặc dùng trình khác cùng NSS/OpenSSL).
2. Capture phiên IMAPS/STARTTLS SMTP.
3. Wireshark: **Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename** → trỏ tới file key log.
4. Kết quả: các record TLS biến thành giao thức gốc (IMAP, SMTP) **đã giải mã** — nhóm thấy lệnh và cả... không có gì lộ nếu lab dùng đúng. Đối chứng: **SFTP thì hoàn toàn vô vọng** — SFTP nằm trong kênh SSH đã mã hóa, không phải TLS; bắt được cũng chỉ là các gói `SSH-2.0` binary, không có cơ chế key-log tương ứng trong các bước trên → bằng chứng trực quan rằng SFTP "đóng kín" hơn FTPS/STARTTLS ở mặt bị nghe lén chủ động.

Lưu ý kỹ thuật: key log chỉ ghi được nếu file tồn tại **trước khi** handshake diễn ra, và bắt buộc phải capture thấy đủ ClientHello; riêng FTPS dữ liệu (kênh data trên port ngẫu nhiên theo PASV) phải decode as TLS từng kênh.

**Ràng buộc pháp lý/đạo đức:** capture phải có sự đồng ý của chủ mạng và chỉ trên mạng lab; key log chứa khóa phiên plaintext = "chìa khóa phòng", phải lưu/dọn như mật khẩu, không commit vào repo báo cáo.

Nguồn:
- Wireshark capture/filter: https://www.wireshark.org/docs/ , https://wiki.wireshark.org/TLS , https://wiki.wireshark.org/SMTP
- Display filter syntax: https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html

---

### 3b.4. UFW — tường lửa đơn giản hóa iptables/nftables

#### 3b.4.1. Bản chất

**UFW (Uncomplicated Firewall)** là front-end cho iptables (hoặc nftables — Ubuntu 24.04 về sau mặc định dùng `nf_tables` backend khi kernel hỗ trợ, tra trong `/etc/default/ufw` dòng `IPTABLES=...`). Mục tiêu: đổi câu lệnh iptables dài dòng thành ngữ pháp người-lành-thao-tác. Mọi rule UFW cuối cùng vẫn là chain `ufw-user-input`/`ufw-after-*` trong bảng filter — nên có thể đọc chéo giữa `ufw status` và `iptables -S`.

#### 3b.4.2. Lệnh nền tảng

```bash
sudo ufw status verbose   # xem trạng thái + rule kèm policy mặc định (VERBOSE hiện cả log level)
sudo ufw default deny incoming   # mặc định CHẶN mọi chiều vào — nền tảng của "zero-trust lab"
sudo ufw default allow outgoing  # cho phép chiều ra (client cần ra ngoài)
sudo ufw allow 21/tcp     # mở FTP control cho lab
sudo ufw allow 20/tcp     # active-mode data (bỏ nếu lab luôn PASV)
sudo ufw allow 30000:31000/tcp  # dải passive ports phải KHỚP với pasv_min/max_port trong vsftpd.conf
sudo ufw allow from 192.168.56.0/24 to any port 22 proto tcp comment 'SSH - chi mang lab'
sudo ufw limit 22/tcp     # "limit": cho phép nhưng chặn nếu >5 kết nối/30s (tự thêm rule rate-limit)
sudo ufw delete allow 21/tcp   # xóa rule bằng chính cú pháp đã thêm
sudo ufw enable / disable
```

Nguyên tắc quản trị SSH: **không bao giờ `allow 22/tcp` rộng cho 0.0.0.0/0 trên máy có IP công khai**; giới hạn theo source IP của ban quản trị (như mẫu trên) hoặc đặt SSH ở cổng đổi + key-only auth (thuộc chương SSH).

#### 3b.4.3. File cấu hình và chiến lược rule cho lab

- `/etc/default/ufw` — cấu hình toàn cục: `DEFAULT_INPUT_POLICY="DROP"`, `IPTABLES=...` (chọn backend), `ENABLED=yes/no`.
- `/etc/ufw/before.rules` / `after.rules` — chèn iptables thủ công UFW không diễn đạt được (VD: cấu hình MASQUERADE cho VM gateway).
- `/etc/ufw/sysctl.conf` — kernel params khi bật (`nf_conntrack_ftp` helper để "thấu hiểu" FTP data channel — FTP dạng này rất hay bị quên; không có helper thì PASV bị DROP giữa chừng dù đã allow 21).
- `/etc/ufw/ufw.conf` — cờ bật/tắt khi boot.

**Chiến lược lab đề xuất** (áp cho máy server 192.168.56.10): `default deny incoming` → chỉ allow đúng: 22 từ subnet lab (hoặc limit), 21 + dải PASV (nếu test FTP/FTPS), 25 (nếu mail server nhận thư nội bộ), 587, 143/993, 110/995, 22 (SFTP dùng lại nó). Mọi thứ khác đóng — kể cả khi service có bug thì attacker từ ngoài cũng không thấy cổng nào để đánh. Đây là lớp "reduce attack surface" bổ khuyết cho lớp Fail2ban (phát hiện hành vi) bên dưới.

Nguồn: Ubuntu Server guide — PTF (firewalls): https://documentation.ubuntu.com/server/how-to/security/firewall-management/ ; man ufw: https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html (theo dõi bản LTS hiện hành — tính đến 8/2026 Ubuntu LTS mới nhất là 26.04 "Resolute Raccoon" (04/2026); lab nhóm có thể chạy 24.04 LTS, hỗ trợ tới 6/2029).

---

### 3b.5. Fail2ban — hàng rào chống brute-force dựa trên nhật ký

#### 3b.5.1. Kiến trúc: jail / filter / action

Fail2ban là **daemon đọc log**, đếm các dòng khớp regex "đăng nhập thất bại" theo từng nguồn IP, và khi vượt ngưỡng trong cửa sổ thời gian thì gọi một **action** (mặc định: chèn rule vào iptables/nftables để DROP/NẶNG hơn REJECT). Ba thành phần:

- **Filter**: regex khớp các dòng thất bại (VD: `failregex = ...`).
- **Jail**: đơn vị cấu hình ghép *một filter* + *một logpath* + *một action* + *các ngưỡng*, khai báo trong `jail.conf`/`jail.local`.
- **Action**: lệnh firewall/SMTP thông báo... được thực thi khi ban.

**Luật bất di bất dịch:** không bao giờ sửa `/etc/fail2ban/jail.conf` — file này bị **ghi đè mỗi lần cập nhật gói**. Mọi tùy biến vào `/etc/fail2ban/jail.local` (ghi đè từng section theo tên), và filter độ chế vào `filter.d/<ten>.local`.

#### 3b.5.2. Các jail liên quan tới dịch vụ của đồ án (tên thật trên bản hiện hành)

Trong `/etc/fail2ban/jail.conf`, tên section mặc định = tên filter: `[sshd]`, `[vsftpd]`, `[dovecot]`, `[postfix]`, `[recidive]`...

- **vsftpd**: jail `[vsftpd]`, filter `filter.d/vsftpd.conf` (khớp `530 Login incorrect`).
- **sshd**: `[sshd]`, filter `filter.d/sshd.conf` — dùng được cho cả SFTP vì xác thực SFTP = xác thực SSH.
- **postfix**: bản fail2ban 0.10+ đã **gộp các filter cũ** (`postfix-sasl`, `postfix-smtpd`, `postfix-auth`) vào `filter.d/postfix.conf`; chỉ cần bật `[postfix]` với `mode = all` (bắt cả reject spam/RCPT) — lệnh `fail2ban-client status postfix-sasl` sẽ báo "does not exist" trên cài đặt mới.
- **dovecot**: `[dovecot]`, filter `filter.d/dovecot.conf`; tài liệu Dovecot cũ từng nhắc tên `dovecot-pop3imap`, bản nay thay bằng `[dovecot]` (khuyến nghị `mode = aggressive` để bắt cả "user không tồn tại").
- **recidive**: jail "ban lại những IP đã bị ban ≥ N lần" — hữu ích cho lab mô phỏng brute-force dai dẳng.

Mẫu `/etc/fail2ban/jail.local` tối giản cho lab:

```ini
[DEFAULT]
bantime  = 1h        # thời gian ban một IP vi phạm
findtime = 10m       # cửa sổ thời gian đếm vi phạm
maxretry = 5         # vượt ngưỡng này trong findtime => ban
backend  = auto      # 'systemd' nếu distro chỉ ghi journald (VD vsftpd log qua journal);
                     # polling khi log ghi ra file thường

[sshd]
enabled = true

[vsftpd]
enabled = true
# logpath = /var/log/vsftpd.log  # BỎ khi backend=systemd: fail2ban tự đọc journal của unit vsftpd

[postfix]
enabled = true
mode    = all

[dovecot]
enabled = true
mode    = aggressive
logpath = %(syslog_mail)s   # trỏ tới mail.log (chuẩn macro Debian/Ubuntu)

[recidive]
enabled = true
```

#### 3b.5.3. Tham số cốt lõi

| Tham số | Ý nghĩa | Giá trị lab gợi ý |
|---|---|---|
| `findtime` | Cửa sổ thời gian gom vi phạm | `10m` |
| `maxretry` | Số lần thất bại tối đa trong cửa sổ | `3` (lab dễ kích hoạt) / `5` (thực tế) |
| `bantime` | Thời gian ban | `1h`; `-1` = vĩnh viễn |
| `banaction` | Tên action (`/etc/fail2ban/action.d/`), mặc định `iptables-multiport` | đổi `nftables-multiport` nếu UFW dùng nftables backend |
| `ignoreip` | IP miễn ban (luôn thêm IP máy test của nhóm!) | `127.0.0.1/8 192.168.56.1` |

(Tham số `ipset`: ở hệ thống cài `ipset`, có thể dùng action `iptables-ipset-proto6` để ban qua **ipset** — một tập hợp IP tra cứu O(1) thay vì chèn hàng nghìn rule iptables; trên Ubuntu server mặc định dùng `iptables-multiport`.)

#### 3b.5.4. Kiểm tra trong lab (quan trọng hơn cả cấu hình)

```bash
fail2ban-client status              # danh sách jail đang chạy
fail2ban-client status sshd         # số ban hiện tại, IP nào đang bị ban, total banned
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf --print-all-matched
                                    # THỬ regex offline: đếm matched/failed mà không cần tấn công lại
sudo journalctl -u fail2ban -f      # log hành vi của chính fail2ban
```

Quy trình test chuẩn của lab: mở 2 VM → từ VM attacker đăng nhập sai SSH/FTP ≥ `maxretry` lần (dùng `hydra`/`medusa` **chỉ ở mức nhắc đến: tồn tại, dùng được trong lab được phê duyệt**, không nêu cú pháp) → `fail2ban-client status sshd` hiện IP trong `Banned IP list` → `sudo ufw status`/`iptables -L -n` thấy rule DROP → lần kết nối tiếp theo treo/từ chối. Sau đó `fail2ban-client set sshd unbanip <IP>` để dọn.

Nguồn:
- Fail2ban GitHub (docs, README, wiki): https://github.com/fail2ban/fail2ban , https://github.com/fail2ban/fail2ban/wiki
- Fail2ban filter/jail cấu hình chuẩn: https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf
- Dovecot — HowTo Fail2ban: https://doc.dovecot.org/2.3/configuration_manual/howto/fail2ban/
- Gộp filter postfix 0.10+: https://github.com/fail2ban/fail2ban/issues/3103

---

### 3b.6. Nhật ký hệ thống — "hộp đen" để phát hiện sớm

#### 3b.6.1. journalctl — cánh cửa vào nhật ký systemd

Trên Ubuntu hiện đại mọi daemon ghi qua **journald** (binary, tra cứu nhanh) và/hoặc syslog text. Lệnh nền:

```bash
journalctl -u vsftpd -f            # theo dõi (follow) log của unit vsftpd, kiểu tail -f
journalctl -u postfix --since "10 min ago"   # chỉ 10 phút gần nhất
journalctl -u dovecot -u postfix --since today  # ghép nhiều unit
journalctl -u ssh --grep="Failed password"   # lọc theo chuỗi (bản journald đủ mới)
journalctl --disk-usage / --vacuum-time=7d   # kiểm soát dung lượng
```

#### 3b.6.2. Bảng log truyền thống và mẫu dòng thật

Ubuntu vẫn giữ các file văn bản qua **rsyslog** — quen thuộc với công cụ như Fail2ban (dù backend systemd cũng dùng được):

| File | Ai ghi | Dùng cho |
|---|---|---|
| `/var/log/auth.log` | sshd, PAM, sudo | brute-force SSH/SFTP, đăng nhập FTP (vsftpd qua PAM) |
| `/var/log/mail.log` (RHEL: `/var/log/maillog`) | postfix, dovecot, amavis | hành trình thư + auth failure IMAP/POP |
| `/var/log/vsftpd.log` (nếu `xferlog_enable`+`log_ftp_protocol=YES`) | vsftpd | lệnh USER/PASS, upload/download |
| `/var/log/syslog` | mọi thứ tổng hợp | khi không chắc nguồn |

Mẫu dòng thật (rất hữu ích khi viết regex cho 3b.5.4):

```text
# auth.log — sshd/PAM brute-force:
Aug 29 10:14:02 lab-server sshd[21431]: Failed password for invalid user admin from 192.168.56.20 port 52114 ssh2

# mail.log — postfix với queue-id (mỗi thư một mã 6-12 ký tự, nối các dòng về CÙNG thư):
Aug 29 10:20:11 lab-server postfix/smtpd[21600]: connect from unknown[192.168.56.20]
Aug 29 10:20:12 lab-server postfix/smtpd[21600]: warning: hostname ... does not resolve
Aug 29 10:21:03 lab-server postfix/smtpd[21600]: 4A2F1E0137: client=unknown[192.168.56.20], sasl_method=LOGIN, sasl_username=user1
Aug 29 10:21:09 lab-server postfix/qmgr[21555]: 4A2F1E0137: from=<user1@lab.local>, size=612, nrcpt=1
Aug 29 10:21:10 lab-server postfix/smtp[21640]: 4A2F1E0137: to=<user2@lab.local>, relay=dovecot..., status=sent (250 2.0.0 Ok)
   # ↑ grep -F '4A2F1E0137' mail.log = truy vết TOÀN BỘ vòng đời một bức thư — định dạng syslog chuẩn (RFC 5424 là bản hiện đại của định dạng BSD-syslog mà postfix/dovecot dùng qua rsyslog)

# mail.log — dovecot auth failure:
Aug 29 10:25:44 lab-server dovecot: imap-login: Disconnected (auth failed, 4 attempts in 22 secs): user=<user1>, method=PLAIN, rip=192.168.56.20, ...

# vsftpd.log:
Sat Aug 29 10:30:01 2026 [pid 21770] [ftpuser] FAILED LOGIN ON 192.168.56.20 <- 192.168.56.10 [ftpuser]
```

Kỹ năng đọc nhanh: (1) luôn bắt đầu bằng `auth.log`/`mail.log` của khoảng thời gian nghi ngờ; (2) dùng `queue-id` để lần theo một thư; (3) đếm thất bại theo IP nguồn — `grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head` cho ra "top thủ phạm" — chính là dữ liệu đầu vào để kiểm chứng jail Fail2ban hoạt động.

Nguồn:
- journald/systemd.journal-fields man: https://manpages.ubuntu.com/manpages/noble/man1/journalctl.1.html
- Postfix LOG_FILES (định dạng queue-id): https://www.postfix.org/LOG_FILES.html
- Dovecot LogConfig: https://doc.dovecot.org/2.3/configuration_manual/logging/

#### 3b.6.3. rsyslog và logrotate — vì sao lab phải xoay log

- **rsyslog** (`/etc/rsyslog.conf`, drop-in `/etc/rsyslog.d/*.conf`) là daemon nhận bản ghi từ journald/kernel và **ghi thành file text** `/var/log/mail.log`... Nếu tắt rsyslog (bản tối giản), các file text biến mất và Fail2ban chế độ polling không còn gì để đọc — lab cần biết mối liên hệ này.
- **logrotate** (`/etc/logrotate.d/` — có sẵn cấu hình cho `vsftpd`, `rsyslog`, apt; postfix/dovecot tự xoay hoặc qua gói) cắt file khi tới ngưỡng:

```text
/var/log/vsftpd.log {
    weekly          # xoay mỗi tuần
    rotate 4        # giữ 4 bản nén (.1.gz ... .4.gz) rồi xóa bản cũ nhất
    compress        # gzip bản cũ — tiết kiệm 90% dung lượng
    missingok       # không báo lỗi nếu file chưa sinh
    copytruncate    # vsftpd giữ mở file → copy rồi cắt, không bắt restart
}
```

Vì sao bắt buộc: một lab brute-force vài nghìn dòng/phút có thể độn `/var/log` đầy → dịch vụ chết dây chuyền (journald halt, postfix không ghi được log, fail2ban mất nguồn). Test nhanh: `logrotate -d /etc/logrotate.d/vsftpd` (dry-run) rồi `sudo logrotate -f`.

Nguồn: rsyslog docs: https://www.rsyslog.com/doc/ ; logrotate (GitHub): https://github.com/logrotate/logrotate

---

### 3b.7. Tổng kết chương 3b

| Công cụ | Vai trò trong hệ thống phòng thủ của đồ án |
|---|---|
| FileZilla / Thunderbird | Chủ thể phát sinh traffic (client); Thunderbird còn là *nguồn tạo key log* để kiểm chứng TLS |
| Wireshark | Quan sát bằng chứng: plaintext (FTP/POP/IMAP/SMTP không TLS) vs. ciphertext (FTPS/IMAPS/SFTP) |
| UFW | Giảm bề mặt tấn công (attack-surface reduction) — chặn trước |
| Fail2ban | Phát hiện sớm + tự phản ứng qua log — chặn sau, theo hành vi |
| journalctl / rsyslog / logrotate | Chuỗi dữ liệu: sinh log → tập hợp → xoay vòng; là *nguyên liệu* cho mọi kỹ thuật phát hiện sớm ở chương 5 |

Bốn lớp này hợp thành đúng mô hình phòng thủ nhiều lớp (defense in depth): cấu hình an toàn (ch.3a) → kiểm soát truy cập mạng (UFW) → giám sát hành vi (Fail2ban) → truy vết (nhật ký).
