# FTP Attack Surface

## Attack Surface Overview

FTP risk concentrates around cleartext transport, weak or anonymous authentication, unsafe write permissions, split data channels, and outdated server implementations. Discuss and reproduce only controlled scenarios in an isolated lab.

## Recommended Resources

### FTP Security Considerations

- **Link:** [RFC 2577: FTP Security Considerations](https://www.rfc-editor.org/rfc/rfc2577)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Enumerates protocol and deployment risks, including authentication, bounce behavior, and data-channel concerns.

- [MITRE ATT&CK T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/) - maps cleartext exposure to a documented adversary technique.
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) - provides technique context for repeated authentication attempts.
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) - safe public capture material for practicing analysis workflows.

## Authentication

- Weak passwords, reused credentials, and anonymous access can turn an exposed FTP service into an unauthorized-data-access path.
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) - behavior and mitigations for authentication guessing.

## Misconfiguration

- Anonymous access, broad read/write permissions, exposed upload directories, and permissive firewall rules should be reviewed against an approved business need.
- [NIST SP 800-123: Guide to General Server Security](https://csrc.nist.gov/pubs/sp/800/123/final) - server-security lifecycle guidance.

## Protocol-specific Attacks

- Cleartext USER, PASS, commands, and data may be observable in a non-encrypted FTP session.
- FTP's active/passive data-channel behavior can be abused or mismanaged if endpoint and firewall policy are not restrictive.
- [RFC 2577](https://www.rfc-editor.org/rfc/rfc2577) - primary security discussion.

## Historical Vulnerabilities

Check the vendor's security advisories for the exact FTP server version in scope. Do not infer a vulnerability from a protocol name alone.

## Labs

- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) - analyze provided traces instead of live third-party traffic.

## Our Notes

| Security Event | Observable Evidence | Detection Source | Defensive Control | Forensic Artifact |
|---|---|---|---|---|
| Cleartext login | USER and PASS in control traffic | PCAP | Migrate to FTPS or SFTP | Session timeline and exposed account |
| Repeated login failure | Dense failure sequence from one source | Service and auth logs | Rate limiting and account policy | Source-IP and target-account summary |
| Unauthorized upload | New file and transfer command | FTP and filesystem logs | Least-privilege write permissions | File hash, owner, timestamp |

## Related

- [FTP Detection](./detection.md)
- [FTP Defense](./defense.md)
- [FTP Forensics](./forensics.md)

