# FTP Forensics and Investigation

## Evidence Sources

Combine FTP access/transfer logs, authentication logs, firewall or flow data, endpoint filesystem metadata, and packet captures collected under policy.

## Server Logs

Look for account, client IP, session start and end, requested command, file path, transfer result, bytes, and TLS error fields. Preserve original timestamps and log rotation context.

## Network Evidence

Control-channel traffic can establish session order. In cleartext FTP it may also show commands and credentials; in FTPS it usually provides metadata rather than content.

## PCAP

- [Wireshark Documentation](https://www.wireshark.org/docs/) - inspect streams, protocol fields, and transfer context.
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html) - repeatable field extraction.

## File Artifacts

Collect file path, size, hash, owner, creation/modification metadata, quarantine outcome, and any server-side audit records. Do not alter potential evidence while collecting it.

## Investigation Guides

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) - log handling and analysis foundations.
- [NIST SP 800-123](https://csrc.nist.gov/pubs/sp/800/123/final) - server security and operational context.

## Tools

- [Wireshark](https://www.wireshark.org/docs/)
- [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Zeek](https://docs.zeek.org/en/current/)

## Labs / Datasets

- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)

## Our Notes

| Evidence | Location | What It Can Reveal |
|---|---|---|
| FTP transfer log | Service host | Account, path, result, timing, and volume |
| Packet capture | Sensor or lab endpoint | Command sequence; cleartext exposure when applicable |
| Filesystem metadata | FTP storage host | Existence, ownership, hash, and timeline context |
| Firewall or flow record | Network control | Client/server relationship and data-channel endpoints |

## Related

- [FTP Detection](./detection.md)
- [FTP Defense](./defense.md)
- [PCAP and Datasets](../references/datasets-pcap.md)

