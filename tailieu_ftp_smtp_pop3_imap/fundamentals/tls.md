# TLS and Encryption

## Focus

TLS protects FTP when using FTPS and protects SMTP, POP3, and IMAP through STARTTLS or implicit TLS. SFTP instead uses SSH transport and should not be described as TLS.

## Recommended Resources

### TLS 1.3

- **Link:** [RFC 8446: The Transport Layer Security Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** The primary standard for modern TLS terminology, handshake behavior, and cipher-suite expectations.

### NIST TLS Configuration

- **Link:** [NIST SP 800-52 Revision 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
- **Type:** Government guidance
- **Level:** Intermediate
- **Why read:** Gives an authoritative baseline for selecting and configuring TLS in federal information systems.

### Mozilla SSL Configuration Generator

- **Link:** [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- **Type:** Configuration guidance
- **Level:** Intermediate
- **Why read:** Offers maintained practical configuration profiles that complement standards and product documentation.

### Implicit TLS for Email Access

- **Link:** [RFC 8314: Cleartext Considered Obsolete](https://www.rfc-editor.org/rfc/rfc8314)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Explains the current direction for secure mail-access and mail-submission services.

## Our Notes

- STARTTLS is an in-band upgrade, so policy must prevent unintended cleartext fallback.
- Certificate validation is part of transport security; encryption without peer authentication does not establish a trusted endpoint.
- Encrypted payloads reduce PCAP visibility, increasing the value of endpoint, application, DNS, and TLS-handshake logs.
- SFTP rides over SSH; inspect SSH algorithms and host-key trust separately from TLS controls.

## Related

- [Network Basics](./network-basics.md)
- [FTP Defense](../ftp/defense.md)
- [SMTP Defense](../smtp/defense.md)
- [POP3 Defense](../pop3/defense.md)
- [IMAP Defense](../imap/defense.md)

