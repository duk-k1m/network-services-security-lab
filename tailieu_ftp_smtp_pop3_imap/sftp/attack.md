# SFTP / SSH Attack Surface

## Attack Surface Overview

SFTP inherits SSH authentication, authorization, key-management, and implementation risk. Primary concerns include weak passwords, exposed private keys, permissive account access, unsafe directory restrictions, and unpatched SSH servers.

## Recommended Resources

### OpenSSH Server Configuration

- **Link:** [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- **Type:** Official documentation
- **Level:** Intermediate
- **Why read:** Documents authentication, forwarding, subsystem, and account-restriction controls that shape the attack surface.

- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) - authentication-guessing technique context.
- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) - risk after credential or key compromise.
- [NIST SP 800-123](https://csrc.nist.gov/pubs/sp/800/123/final) - server administration lifecycle guidance.

## Authentication

- Weak passwords and permissive password authentication expose SSH to repeated guessing attempts.
- Leaked private keys can provide durable access until they are revoked or removed from authorization.
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/) - explains why successful valid-account activity must be assessed in context.

## Misconfiguration

- Overbroad file permissions, unrestricted forwarding, excessive group membership, and ineffective SFTP-only restrictions can broaden impact.
- [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config) - exact configuration semantics.

## Protocol-specific Attacks

- SSH brute-force pressure is visible at the authentication boundary; avoid reproducing it outside an owned isolated lab.
- Host-key warnings can reveal a trust or infrastructure problem and should not be bypassed casually.

## Historical Vulnerabilities

Review the release and security advisories for the exact SSH implementation and version. Do not assign a CVE without matching its affected version and configuration.

## Labs

- [Network Forensic Puzzle Contest](https://www.netresec.com/?page=NetworkForensicPuzzle) - public network-forensics practice material.

## Our Notes

| Security Event | Observable Evidence | Detection Source | Defensive Control | Forensic Artifact |
|---|---|---|---|---|
| Password guessing | Repeated failed attempts | SSH authentication log | Key-based auth, rate limiting, source restrictions | Source-IP and account timeline |
| Key compromise suspicion | Login from new host or unusual time | SSH and endpoint logs | Key rotation and access review | Authorized-key change history |
| Excessive file access | SFTP session plus storage activity | SFTP, filesystem, and audit logs | Least privilege and scoped chroot | File path, hash, and account context |

## Related

- [SFTP Detection](./detection.md)
- [SFTP Defense](./defense.md)
- [SFTP Forensics](./forensics.md)

