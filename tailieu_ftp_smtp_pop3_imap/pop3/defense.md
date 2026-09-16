# POP3 Defense

## Defense Priorities

Require protected mail access, use current TLS policy and certificate management, protect accounts, constrain network exposure, update the mail-access server, and retain sufficient access telemetry.

## Recommended Resources

### Dovecot TLS Configuration

- **Link:** [Dovecot SSL Configuration](https://doc.dovecot.org/main/core/config/ssl.html)
- **Type:** Official documentation
- **Level:** Intermediate
- **Why read:** Gives implementation-specific guidance for configuring encrypted mail-access transport.

- [RFC 8314](https://www.rfc-editor.org/rfc/rfc8314) - standards-based direction for secure mail access.
- [NIST SP 800-52 Revision 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) - TLS baseline.
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) - maintained configuration profiles.

## Configuration Focus

- Require TLS for mail access and prevent plaintext authentication when not protected by TLS.
- Use valid, managed certificates and test client certificate validation behavior.
- Apply strong account controls and monitor unusual authentication activity.
- Restrict exposed networks and maintain timely security updates for the POP3 implementation.
- Protect logs and synchronize time across mail and identity systems.

## Our Notes

- The secure-state test is not only that TLS works; it is that unprotected login is rejected according to policy.
- Client compatibility must be evaluated during migration because outdated clients may fail safely after cleartext access is removed.
- Mailbox-access hardening should be coordinated with IMAP if both are served by the same platform.

## Related

- [POP3 Overview](./overview.md)
- [POP3 Detection](./detection.md)
- [POP3 Forensics](./forensics.md)
- [TLS and Encryption](../fundamentals/tls.md)

