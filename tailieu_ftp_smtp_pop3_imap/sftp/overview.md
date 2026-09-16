# SFTP / SSH Overview

## Quick Facts

| Item | Value |
|---|---|
| Transport | SSH |
| Common port | TCP 22 |
| File transfer | SFTP subsystem/channel, not FTP over TLS |
| Server configuration | Commonly controlled with sshd_config |

## Key Concepts

- SFTP is a file-transfer protocol carried inside an SSH connection.
- SSH authenticates the server through host keys and supports password or public-key client authentication.
- SFTP does not use FTP control/data channels and does not use TLS.
- An SSH server can restrict an account to SFTP-oriented access and a constrained directory tree.

## How It Works

An SSH client first negotiates transport protection and server identity, then authenticates. An SFTP client requests the file-transfer subsystem and performs file operations through the authenticated SSH channel.

## Recommended Resources

### SSH Protocol Architecture

- **Link:** [RFC 4251: The Secure Shell Protocol Architecture](https://www.rfc-editor.org/rfc/rfc4251)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Defines the SSH components and security model that SFTP inherits.

- [RFC 4253: SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253) - encrypted transport and server authentication.
- [SFTP draft, version 3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) - protocol operations commonly seen in implementations.
- [OpenSSH Manual Pages](https://www.openssh.com/manual.html) - official operational documentation.

## Official Documentation

- [OpenSSH Manual Pages](https://www.openssh.com/manual.html)
- [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)

## RFC / Standards

- [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251)
- [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253)
- [SFTP draft](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)

## Packet / Protocol Analysis

- [Wireshark Documentation](https://www.wireshark.org/docs/) - inspect SSH metadata and handshake context without assuming encrypted payload recovery.
- [Zeek Documentation](https://docs.zeek.org/en/current/) - structured network telemetry.

## Our Notes

- SFTP traffic normally keeps file names and contents encrypted in transit, so application and host logs are essential for file-operation attribution.
- Host-key validation protects against connecting to an impostor server; it is not replaced by a password prompt.
- Public-key authentication reduces password-guessing exposure but requires private-key protection and lifecycle management.
- A chroot or SFTP-only restriction narrows interactive access but must be tested with the service account's legitimate workflow.
- SSH configuration should be reviewed as an effective whole because later directives and Match blocks can change behavior.

## Related

- [SFTP Attack Surface](./attack.md)
- [SFTP Detection](./detection.md)
- [SFTP Defense](./defense.md)
- [SFTP Forensics](./forensics.md)

