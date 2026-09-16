# FTP Overview

## Quick Facts

| Item | Value |
|---|---|
| Control connection | TCP 21 by convention |
| Data transfer | Separate connection negotiated as active or passive |
| Authentication | USER and PASS commands in classic FTP |
| Transport security | Requires FTPS when TLS protection is needed |

## Key Concepts

- FTP uses a persistent control channel and a distinct data channel.
- Active and passive modes differ in which side opens the data connection.
- The protocol itself does not encrypt usernames, passwords, commands, or transferred content.
- FTPS is FTP protected with TLS; it is distinct from SFTP, which uses SSH.

## How It Works

A client establishes the control session, authenticates, negotiates transfer parameters, and opens one or more data connections for directory listings or files. Firewalls and NAT must account for this split-channel design.

## Recommended Resources

### FTP Protocol Specification

- **Link:** [RFC 959: File Transfer Protocol](https://www.rfc-editor.org/rfc/rfc959)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Defines commands, replies, and control/data-channel behavior needed to understand captures and logs.

- [RFC 4217: Securing FTP with TLS](https://www.rfc-editor.org/rfc/rfc4217) - standard FTPS extension.
- [RFC 2577: FTP Security Considerations](https://www.rfc-editor.org/rfc/rfc2577) - security implications of FTP deployment.
- [Wireshark Documentation](https://www.wireshark.org/docs/) - practical packet-analysis reference.

## Official Documentation

- [Wireshark Documentation](https://www.wireshark.org/docs/)

## RFC / Standards

- [RFC 959](https://www.rfc-editor.org/rfc/rfc959)
- [RFC 4217](https://www.rfc-editor.org/rfc/rfc4217)
- [RFC 2577](https://www.rfc-editor.org/rfc/rfc2577)

## Packet / Protocol Analysis

- [tcpdump manual page](https://www.tcpdump.org/manpages/tcpdump.1.html) - capture filtering before detailed analysis.
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html) - scriptable extraction and inspection.

## Our Notes

- A successful login on the control channel does not guarantee that a later data connection belongs to the expected user without correlation.
- Passive-mode ports can complicate firewall policy and transfer investigation.
- Classic FTP exposes credentials and file content to an on-path observer.
- FTPS encryption moves much of the evidentiary burden from PCAP content to service and TLS logs.
- Treat FTP and SFTP as different protocol families with different configuration and telemetry.

## Related

- [FTP Attack Surface](./attack.md)
- [FTP Detection](./detection.md)
- [FTP Defense](./defense.md)
- [FTP Forensics](./forensics.md)

