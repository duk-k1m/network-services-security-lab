# POP3 Security

## Research Areas

- [Overview](./overview.md)
- [Attack Surface](./attack.md)
- [Detection](./detection.md)
- [Defense](./defense.md)
- [Forensics](./forensics.md)

## Quick Facts

| Item | Value |
|---|---|
| Protocol | Post Office Protocol version 3 |
| Default cleartext port | TCP 110 |
| Implicit TLS port | TCP 995 by convention |
| Primary model | Client retrieves messages from a mailbox |

## Recommended Starting Resources

- [RFC 1939: POP3](https://www.rfc-editor.org/rfc/rfc1939) - core protocol.
- [RFC 2595: TLS for POP3 and IMAP](https://www.rfc-editor.org/rfc/rfc2595) - STARTTLS extension context.
- [RFC 8314: Cleartext Considered Obsolete](https://www.rfc-editor.org/rfc/rfc8314) - modern secure email-access direction.
- [Dovecot Documentation](https://doc.dovecot.org/main/) - official implementation documentation.

## Related

- [RFC and Standards](../references/rfc.md)
- [Hands-on Labs](../references/labs.md)
- [Forensic Tools](../tools/forensic-tools.md)

