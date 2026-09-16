# SFTP / SSH Forensics and Investigation

## Evidence Sources

Use SSH daemon and authentication logs, account and key-management audit records, filesystem metadata, endpoint telemetry, network-flow data, and packet captures. Content usually remains encrypted in network captures.

## Server Logs

Preserve records for successful and failed login, account, source IP, authentication method when logged, session lifecycle, subsystem use, and daemon configuration errors.

## Network Evidence

Correlate source/destination, time, byte volume, SSH metadata, and session duration with endpoint events. Do not claim file contents or SFTP commands from encrypted PCAPs unless they were obtained independently from the endpoint.

## PCAP

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Zeek Documentation](https://docs.zeek.org/en/current/)

## File Artifacts

Collect access times carefully, file hashes, owner/group, authorization-key changes, configuration change records, and relevant filesystem audit events.

## Investigation Guides

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final)
- [NIST SP 800-123](https://csrc.nist.gov/pubs/sp/800/123/final)

## Tools

- [Wazuh Documentation](https://documentation.wazuh.com/current/)
- [Sigma Documentation](https://sigmahq.io/docs/)
- [Wireshark Documentation](https://www.wireshark.org/docs/)

## Labs / Datasets

- [Network Forensic Puzzle Contest](https://www.netresec.com/?page=NetworkForensicPuzzle)

## Our Notes

| Evidence | Location | What It Can Reveal |
|---|---|---|
| SSH auth log | Server or central log platform | Attempts, account, source, success/failure sequence |
| Authorized-key and config audit | Server filesystem/audit trail | Changes that could enable persistent access |
| File metadata and audit records | SFTP storage | Scope and timing of accessed or altered data |
| Flow telemetry | Network sensor | Session scale and peer relationship |

## Related

- [SFTP Detection](./detection.md)
- [SFTP Defense](./defense.md)
- [Logging and Monitoring](../fundamentals/logging-monitoring.md)

