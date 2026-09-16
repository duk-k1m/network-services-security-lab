# IMAP Forensics and Investigation

## Evidence Sources

Collect IMAP service logs, identity events, mailbox audit records, message headers, endpoint evidence, network-flow data, and packet captures according to the applicable privacy and incident-response process.

## Server Logs

Retain account, source IP, authentication outcome, transport state, client/session details, mailbox access data when logged, and administrative configuration changes.

## Network Evidence

Network telemetry provides session timing, source/destination, TLS context, and volume. Pair it with server and identity evidence to understand protected IMAP activity.

## PCAP

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Zeek Documentation](https://docs.zeek.org/en/current/)

## File / Mail Artifacts

Preserve raw messages, full headers, Message-ID values, MIME structure, attachment hashes, mailbox folder context, and audit records. Avoid modifying mailbox evidence during collection.

## Investigation Guides

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)
- [NIST SP 800-177 Revision 1](https://csrc.nist.gov/pubs/sp/800/177/r1/final)

## Tools

- [Google Messageheader Analyzer](https://toolbox.googleapps.com/apps/messageheader/)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Wazuh Documentation](https://documentation.wazuh.com/current/)

## Labs / Datasets

- [Digital Corpora](https://digitalcorpora.org/)
- [Network Forensic Puzzle Contest](https://www.netresec.com/?page=NetworkForensicPuzzle)

## Our Notes

| Evidence | Location | What It Can Reveal |
|---|---|---|
| IMAP access/session log | Mail server | Account, source, time, authentication and transport context |
| Mailbox audit history | Mail platform | Folder and operation patterns where supported |
| Message headers and MIME | Preserved message | Mail-routing and content artifacts |
| Flow and endpoint data | Sensor and managed client | Session scale and whether another device accessed the account |

## Related

- [IMAP Detection](./detection.md)
- [IMAP Defense](./defense.md)
- [PCAP and Datasets](../references/datasets-pcap.md)

