# SMTP Overview

## Quick Facts

| Item | Value |
|---|---|
| Primary use | Message submission and mail relay |
| Common relay port | TCP 25 |
| Common submission port | TCP 587 |
| Transport protection | STARTTLS extension when offered and required |
| Authentication | SMTP AUTH is an extension, not a property of every relay |

## Key Concepts

- SMTP moves messages between clients and mail transfer agents; mailbox retrieval is handled by POP3 or IMAP.
- A relay must distinguish authorized destination delivery from unauthorized third-party relay.
- SMTP reply codes, envelope addresses, queue identifiers, and message headers support investigation.
- TLS protects a hop; mail authentication standards address domain-level signaling and validation.

## How It Works

A sending client or server connects, identifies itself, may negotiate STARTTLS and authentication, supplies envelope sender and recipients, then transfers message content. The receiving MTA queues, delivers, or relays according to policy.

## Recommended Resources

### SMTP Specification

- **Link:** [RFC 5321: Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Defines SMTP commands, replies, envelope handling, and relay behavior.

- [RFC 3207: SMTP over TLS](https://www.rfc-editor.org/rfc/rfc3207) - STARTTLS extension.
- [RFC 4954: SMTP Authentication](https://www.rfc-editor.org/rfc/rfc4954) - AUTH extension details.
- [Postfix Basic Configuration](https://www.postfix.org/BASIC_CONFIGURATION_README.html) - production-oriented implementation reference.

## Official Documentation

- [Postfix Basic Configuration](https://www.postfix.org/BASIC_CONFIGURATION_README.html)
- [Postfix Mail Logging](https://www.postfix.org/MAILLOG_README.html)

## RFC / Standards

- [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)
- [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207)
- [RFC 4954](https://www.rfc-editor.org/rfc/rfc4954)
- [RFC 8461: MTA-STS](https://www.rfc-editor.org/rfc/rfc8461)

## Packet / Protocol Analysis

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html)

## Our Notes

- SMTP envelope fields and visible message headers serve different purposes and should be documented separately in an investigation.
- A server accepting mail for its own domains is normal; accepting arbitrary sender-to-recipient relay without authorization is a security problem.
- Queue identifiers are high-value correlation keys across MTA log lines.
- STARTTLS should be evaluated for policy enforcement and certificate validation, not only for the presence of a capability banner.
- SPF, DKIM, DMARC, and MTA-STS address different layers of mail security and are complementary.

## Related

- [SMTP Attack Surface](./attack.md)
- [SMTP Detection](./detection.md)
- [SMTP Defense](./defense.md)
- [SMTP Forensics](./forensics.md)

