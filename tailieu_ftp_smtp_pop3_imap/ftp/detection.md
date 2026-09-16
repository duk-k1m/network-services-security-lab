# FTP Detection

## What to Monitor

Monitor failed and successful logins, anonymous sessions, command failures, unexpected upload or download volume, data-channel destinations, TLS negotiation failures, and server process errors.

## Relevant Logs

- FTP server access and transfer logs
- Operating-system authentication and audit logs
- Firewall or flow logs showing control and data connections
- Centralized log records with synchronized timestamps

## Network Evidence

Classic FTP exposes control commands and may expose payloads. For FTPS, retain connection metadata and TLS handshake information alongside server logs.

## Detection Engineering Resources

- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) - evidence collection and retention principles.
- [Zeek Documentation](https://docs.zeek.org/en/current/) - network telemetry and protocol analysis framework.
- [Suricata User Guide](https://docs.suricata.io/en/latest/) - IDS/IPS event and rule documentation.

## SIEM Resources

- [Elastic Security detection and alerting](https://www.elastic.co/docs/solutions/security/detect-and-alert) - rule and alert-triage concepts.
- [Wazuh Documentation](https://documentation.wazuh.com/current/) - host telemetry and alerting reference.

## IDS / IPS

- [Suricata User Guide](https://docs.suricata.io/en/latest/)
- [Snort Documentation](https://docs.snort.org/)

## PCAP Analysis

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html)

## Our Notes

| Signal | Evidence | Possible Meaning |
|---|---|---|
| Many failed logins | Repeated account and source-IP pairs | Password guessing or a client configuration problem |
| Login then high-volume transfer | Session, bytes, file names, duration | Possible bulk collection; validate against job context |
| Cleartext USER/PASS | FTP control-channel packet fields | Transport exposure requiring containment and migration |
| Repeated TLS failures | Handshake errors by source and version | Incompatible client, scanning, or downgrade probing |

## Related

- [FTP Attack Surface](./attack.md)
- [FTP Defense](./defense.md)
- [FTP Forensics](./forensics.md)

