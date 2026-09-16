# POP3 Detection

## What to Monitor

Monitor authentication successes and failures, client IPs, encryption state, session duration, mailbox retrieval volume, errors, and changes to mail-access configuration.

## Relevant Logs

- POP3 service authentication and session logs
- Identity-provider or operating-system authentication logs
- Mailbox audit records where supported
- Firewall, flow, IDS, and central log-platform telemetry

## Network Evidence

Cleartext POP3 can expose protocol commands and credentials. For TLS-protected sessions, capture peer, timing, TLS metadata, and volume, then correlate with service logs.

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
- [tcpdump manual page](https://www.tcpdump.org/manpages/tcpdump.1.html)

## Our Notes

| Signal | Evidence | Possible Meaning |
|---|---|---|
| Failed login burst | Account, source, timestamp | Guessing, credential error, or stale client |
| First-seen client for an account | New source and successful login | Normal travel or possible compromise |
| Large retrieval immediately after login | Session duration and volume | Possible mailbox collection; validate normal sync behavior |
| Cleartext listener used | Port and protocol details | Encryption policy gap |

## Related

- [POP3 Attack Surface](./attack.md)
- [POP3 Defense](./defense.md)
- [POP3 Forensics](./forensics.md)

