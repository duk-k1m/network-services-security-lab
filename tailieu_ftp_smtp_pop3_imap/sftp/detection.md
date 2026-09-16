# SFTP / SSH Detection

## What to Monitor

Monitor authentication success and failure, source addresses, new account or key changes, daemon configuration changes, session timing, connection volume, and SFTP-related filesystem access.

## Relevant Logs

- SSH authentication and daemon logs
- Operating-system audit and account-management logs
- File-access and filesystem integrity telemetry
- Firewall, flow, and network sensor records

## Network Evidence

SSH encrypts SFTP operations. Network evidence therefore emphasizes server fingerprinting, client/server tuples, timing, volume, protocol metadata, and correlated host events.

## Detection Engineering Resources

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) - centralized logging and retention guidance.
- [Zeek Documentation](https://docs.zeek.org/en/current/) - network metadata and logs.
- [Sigma Documentation](https://sigmahq.io/docs/) - portable detection-rule format and workflow.

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
| Many failures then a success | Tight sequence for account and source | Password guessing that may have succeeded |
| New source for a privileged account | Novel IP, device, or time window | Valid use or possible account/key compromise |
| New authorized key or config change | File-integrity or audit event | Administrative change requiring validation |
| Long session with unusual volume | Flow and storage telemetry | Possible bulk transfer; compare with business context |

## Related

- [SFTP Attack Surface](./attack.md)
- [SFTP Defense](./defense.md)
- [SFTP Forensics](./forensics.md)

