# IMAP Overview

## Quick Facts

| Item | Value |
|---|---|
| Purpose | Remote mailbox access and synchronization |
| Typical cleartext port | TCP 143 |
| Typical implicit TLS port | TCP 993 |
| Mailbox model | Folders, flags, search, and concurrent client access |

## Key Concepts

- IMAP lets a client work with mailbox folders and messages that remain on the server.
- TLS can be negotiated with STARTTLS or provided with implicit TLS according to service policy.
- IMAP activity can include search, fetch, copy, delete, and flag changes, subject to implementation logging.
- Mailbox compromise can have confidentiality, integrity, and persistence implications.

## How It Works

An IMAP client connects, negotiates protection where configured, authenticates, selects a mailbox, and issues tagged commands to synchronize and manage messages. The server maintains mailbox state across sessions.

## Recommended Resources

### IMAP4rev2

- **Link:** [RFC 9051: Internet Message Access Protocol (IMAP) - Version 4rev2](https://www.rfc-editor.org/rfc/rfc9051)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Defines current IMAP commands, states, and response structure for protocol and log analysis.

- [RFC 2595](https://www.rfc-editor.org/rfc/rfc2595) - TLS extension reference.
- [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314) - secure mail-access policy direction.
- [Dovecot Documentation](https://doc.dovecot.org/main/) - implementation context.

## Official Documentation

- [Dovecot Documentation](https://doc.dovecot.org/main/)
- [Dovecot SSL Configuration](https://doc.dovecot.org/main/core/config/ssl.html)

## RFC / Standards

- [RFC 9051](https://www.rfc-editor.org/rfc/rfc9051)
- [RFC 2595](https://www.rfc-editor.org/rfc/rfc2595)
- [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314)

## Packet / Protocol Analysis

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Zeek Documentation](https://docs.zeek.org/en/current/)

## Our Notes

- IMAP keeps mailbox state on the server, so a single compromised account can affect multiple clients and folders.
- Authentication events alone do not describe mailbox impact; pair them with mailbox and endpoint activity where available.
- Encrypted IMAP shifts command visibility from PCAPs to service-side logs and authorized audit telemetry.
- A surge in fetch or search activity is a triage lead, not proof of malicious collection without user and client context.
- IMAPS is the conventional implicit-TLS service; encryption policy should be made explicit for both new and legacy clients.

## Related

- [IMAP Attack Surface](./attack.md)
- [IMAP Detection](./detection.md)
- [IMAP Defense](./defense.md)
- [IMAP Forensics](./forensics.md)

