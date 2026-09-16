# SFTP / SSH Defense

## Defense Priorities

Use a current SSH implementation, limit exposed accounts and networks, favor managed public-key authentication, restrict SFTP users to the minimum required access, and collect protected authentication and audit logs.

## Recommended Resources

### sshd_config Reference

- **Link:** [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- **Type:** Official documentation
- **Level:** Intermediate to Advanced
- **Why read:** The authoritative reference for SSH daemon authentication, cryptographic, forwarding, and Match-block options.

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html) - official implementation documentation.
- [NIST SP 800-123](https://csrc.nist.gov/pubs/sp/800/123/final) - secure server operations.
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) - defense context for authentication pressure.

## Configuration Focus

- Use modern SSH versions and algorithms supported by the approved client population.
- Prefer protected public-key authentication; disable or tightly scope password authentication where feasible.
- Protect private keys, remove stale authorization entries, and review account ownership regularly.
- Use SFTP-only and chroot-style restrictions only after validating permissions and update requirements.
- Limit source networks, administrative access, and forwarding features to the documented use case.

## Our Notes

- A key-only policy is only as strong as private-key handling and revocation.
- Chroot boundaries reduce exposure but are not a substitute for filesystem permissions and patching.
- Retest both the authorized file-transfer path and failed authentication behavior after every SSH policy change.

## Related

- [SFTP Overview](./overview.md)
- [SFTP Detection](./detection.md)
- [SFTP Forensics](./forensics.md)

