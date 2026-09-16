# IMAP Detection

## What to Monitor

Monitor login success/failure, source IP and client changes, encryption state, session duration, mailbox operation volume, administrative configuration changes, and correlation with identity or endpoint activity.

## Relevant Logs

- IMAP authentication and session logs
- Identity-provider, operating-system, and administrative audit logs
- Mailbox audit records and storage telemetry where supported
- Network-flow, IDS, and SIEM events

## Network Evidence

For cleartext sessions, protocol commands may be visible. For TLS-protected sessions, use connection metadata, TLS context, byte volume, and endpoint/server logs rather than assuming payload access.

## Detection Engineering Resources

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)
- [Zeek Documentation](https://docs.zeek.org/en/current/)
- [Sigma Documentation](https://sigmahq.io/docs/)

## SIEM Resources

- [Elastic Security detection and alerting](https://www.elastic.co/docs/solutions/security/detect-and-alert)
- [Wazuh Documentation](https://documentation.wazuh.com/current/)

## IDS / IPS

- [Suricata User Guide](https://docs.suricata.io/en/latest/)
- [Security Onion Documentation](https://docs.securityonion.net/en/2.4/)

## PCAP Analysis

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html)

## Our Notes

| Signal | Evidence | Possible Meaning |
|---|---|---|
| Password failures across accounts | Source IP and several targeted users | Password spraying or a faulty shared client |
| New client plus mailbox activity | Novel device/IP with successful login | Legitimate enrollment or account compromise |
| Unusual fetch/search pattern | Mailbox operation count and session volume | Potential collection; validate baselines |
| Access without TLS | Port, protocol state, service policy | Cleartext exposure or migration exception |

## Related

- [IMAP Attack Surface](./attack.md)
- [IMAP Defense](./defense.md)
- [IMAP Forensics](./forensics.md)

