# SMTP Security

## Research Areas

- [Overview](./overview.md)
- [Attack Surface](./attack.md)
- [Detection](./detection.md)
- [Defense](./defense.md)
- [Forensics](./forensics.md)

## Quick Facts

| Item | Value |
|---|---|
| Protocol | Simple Mail Transfer Protocol |
| Common ports | TCP 25 for relay; TCP 587 for message submission |
| Encryption | STARTTLS or implicit TLS according to service policy |
| Core role | Transports and relays email between systems |

## Recommended Starting Resources

- [RFC 5321: Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321) - core protocol.
- [RFC 3207: SMTP Service Extension for Secure SMTP over TLS](https://www.rfc-editor.org/rfc/rfc3207) - STARTTLS.
- [RFC 4954: SMTP Authentication](https://www.rfc-editor.org/rfc/rfc4954) - AUTH extension.
- [Postfix Basic Configuration](https://www.postfix.org/BASIC_CONFIGURATION_README.html) - official implementation guidance.

## Related

- [RFC and Standards](../references/rfc.md)
- [Hands-on Labs](../references/labs.md)
- [Forensic Tools](../tools/forensic-tools.md)

