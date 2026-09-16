# SMTP Defense

## Defense Priorities

Restrict relay to intended networks and authenticated submission users, require suitable transport protection, protect credentials, implement sender-domain controls, patch mail components, and preserve actionable logs.

## Recommended Resources

### Postfix Basic Configuration

- **Link:** [Postfix Basic Configuration](https://www.postfix.org/BASIC_CONFIGURATION_README.html)
- **Type:** Official documentation
- **Level:** Intermediate
- **Why read:** Covers core Postfix policy concepts used to build a narrowly scoped mail relay.

- [NIST SP 800-177 Revision 1](https://csrc.nist.gov/pubs/sp/800/177/r1/final) - email-security architecture and operations.
- [RFC 3207: SMTP over TLS](https://www.rfc-editor.org/rfc/rfc3207) - STARTTLS standard.
- [RFC 8461: MTA-STS](https://www.rfc-editor.org/rfc/rfc8461) - policy signaling for secure MTA-to-MTA transport.

## Configuration Focus

- Reject unauthorized destination relay and keep trusted network definitions minimal.
- Separate authenticated client submission from server-to-server relay policy.
- Enforce and validate TLS according to the service's risk and interoperability requirements.
- Deploy SPF, DKIM, and DMARC with monitoring and staged policy changes.
- Rate limit and monitor submission behavior; keep queue and authentication logs protected.

## Our Notes

- An open-relay test should be a safe acceptance/rejection check within the lab, never a message campaign against external recipients.
- SPF, DKIM, and DMARC are domain authentication controls; they do not replace account authentication or transport encryption.
- Queue growth is both an availability and a security signal, so it should have an owner and threshold.

## Related

- [SMTP Overview](./overview.md)
- [SMTP Detection](./detection.md)
- [SMTP Forensics](./forensics.md)
- [TLS and Encryption](../fundamentals/tls.md)

