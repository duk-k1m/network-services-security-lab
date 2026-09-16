# POP3 Forensics and Investigation

## Evidence Sources

Collect POP3 session and authentication logs, identity records, mailbox audit data, client and server timestamps, network-flow records, and packet captures while preserving original context.

## Server Logs

Look for account, source IP, authentication result, TLS state, login/logout time, command or retrieval records when available, and service errors.

## Network Evidence

Use network records to place the client, server, session timing, and volume in context. Treat cleartext protocol payloads as sensitive evidence and handle them accordingly.

## PCAP

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html)

## File / Mail Artifacts

Preserve relevant message identifiers, headers, retrieval context, account records, and exported mailbox artifacts under the applicable legal and privacy process.

## Investigation Guides

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)
- [Dovecot Documentation](https://doc.dovecot.org/main/)

## Tools

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Wazuh Documentation](https://documentation.wazuh.com/current/)
- [Zeek Documentation](https://docs.zeek.org/en/current/)

## Labs / Datasets

- [Network Forensic Puzzle Contest](https://www.netresec.com/?page=NetworkForensicPuzzle)

## Our Notes

| Evidence | Location | What It Can Reveal |
|---|---|---|
| POP3 access log | Mail server | Account, source, session and result |
| Identity log | Authentication platform | Account state and correlated authentication pressure |
| Mailbox record | Mail store | Scope of retrieved messages where auditing exists |
| PCAP or flow record | Network sensor | Cleartext exposure or protected-session timing and volume |

## Related

- [POP3 Detection](./detection.md)
- [POP3 Defense](./defense.md)
- [PCAP and Datasets](../references/datasets-pcap.md)

