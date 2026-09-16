# FTP Defense

## Defense Priorities

Prefer retiring classic FTP where feasible. If FTP must remain, use explicit FTPS with validated certificates, strong TLS policy, narrow network access, least-privilege accounts, and durable logging.

## Recommended Resources

### Securing FTP with TLS

- **Link:** [RFC 4217: Securing FTP with TLS](https://www.rfc-editor.org/rfc/rfc4217)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Defines TLS protection for FTP control and data channels.

- [NIST SP 800-52 Revision 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) - TLS configuration baseline.
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) - practical maintained TLS profiles.
- [NIST SP 800-123](https://csrc.nist.gov/pubs/sp/800/123/final) - secure server operation guidance.

## Configuration Focus

- Require encrypted control and data channels when FTPS is used.
- Validate certificates on clients; do not treat warning bypasses as normal operation.
- Disable anonymous access and unnecessary write capability unless there is a documented requirement.
- Restrict source networks and passive data-port ranges at the firewall.
- Patch the selected server implementation and preserve access, transfer, and error logs.

## Our Notes

- Encryption prevents routine packet-content inspection, so service-side logs become a required control rather than an optional one.
- A successful hardening change needs a retest for both blocked unsafe behavior and a functioning legitimate transfer.
- If a team can use SFTP instead, evaluate it as a migration decision rather than assuming FTPS and SFTP are interchangeable.

## Related

- [FTP Overview](./overview.md)
- [FTP Detection](./detection.md)
- [TLS and Encryption](../fundamentals/tls.md)

