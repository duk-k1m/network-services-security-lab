# POP3 Overview

## Quick Facts

| Item | Value |
|---|---|
| Purpose | Mailbox retrieval |
| Typical cleartext port | TCP 110 |
| Typical implicit TLS port | TCP 995 |
| Authentication risk | Cleartext authentication is unsafe without transport protection |

## Key Concepts

- POP3 is a mailbox-access protocol, commonly optimized for retrieving messages to a client.
- TLS can be negotiated through STARTTLS or provided through an implicit TLS service according to deployment policy.
- Mail access control is separate from SMTP transport security, though the same account ecosystem may be involved.
- POP3 session and message retrieval activity can be useful during mailbox-compromise investigation.

## How It Works

A client connects, negotiates protection where offered, authenticates, lists or retrieves messages, and ends the session. Server behavior and message retention depend on client settings and service configuration.

## Recommended Resources

### POP3 Specification

- **Link:** [RFC 1939: Post Office Protocol - Version 3](https://www.rfc-editor.org/rfc/rfc1939)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Defines POP3 commands and state transitions needed to interpret protocol traces.

- [RFC 2595: TLS for POP3 and IMAP](https://www.rfc-editor.org/rfc/rfc2595) - secure extension details.
- [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314) - guidance away from cleartext access.
- [Dovecot Documentation](https://doc.dovecot.org/main/) - implementation context.

## Official Documentation

- [Dovecot Documentation](https://doc.dovecot.org/main/)
- [Dovecot SSL Configuration](https://doc.dovecot.org/main/core/config/ssl.html)

## RFC / Standards

- [RFC 1939](https://www.rfc-editor.org/rfc/rfc1939)
- [RFC 2595](https://www.rfc-editor.org/rfc/rfc2595)
- [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314)

## Packet / Protocol Analysis

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html)

## Our Notes

- POP3 on cleartext transport can expose account credentials and mailbox commands to network observers.
- Mail deletion and retention behavior must be understood before drawing conclusions from server-side message presence.
- TLS reduces packet-content visibility, making service logs and endpoint evidence more important.
- POP3 event volume should be interpreted together with normal client synchronization behavior.
- POP3S is a deployment convention for POP3 with implicit TLS; do not conflate it with SMTP submission.

## Related

- [POP3 Attack Surface](./attack.md)
- [POP3 Detection](./detection.md)
- [POP3 Defense](./defense.md)
- [POP3 Forensics](./forensics.md)

