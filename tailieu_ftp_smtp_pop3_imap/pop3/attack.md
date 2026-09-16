# POP3 Attack Surface

## Attack Surface Overview

POP3 exposure is driven by cleartext authentication, weak account credentials, outdated TLS configuration, broad network access, and the impact of a compromised mailbox account.

## Recommended Resources

### Secure Email Access Direction

- **Link:** [RFC 8314: Cleartext Considered Obsolete](https://www.rfc-editor.org/rfc/rfc8314)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Explains why modern deployments should move away from cleartext mail-access services.

- [RFC 2595](https://www.rfc-editor.org/rfc/rfc2595) - TLS extension behavior.
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) - repeated authentication-risk context.
- [MITRE ATT&CK T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/) - cleartext credential exposure context.

## Authentication

- Weak, reused, or guessed passwords can allow mailbox access.
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/) - detect and mitigate repeated authentication attempts.

## Misconfiguration

- Cleartext listeners, optional encryption without enforced policy, weak certificate management, and overly broad source access increase risk.
- [Dovecot SSL Configuration](https://doc.dovecot.org/main/core/config/ssl.html) - official configuration reference.

## Protocol-specific Attacks

- Cleartext login or retrieval traffic may disclose credentials and mailbox activity to an on-path observer.
- A compromised account can be used to retrieve historical messages, depending on retention and client behavior.

## Historical Vulnerabilities

Use the vendor's security advisory and the installed version before attributing a CVE. Protocol-level guidance is not a substitute for version-specific patch review.

## Labs

- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) - public traces for learning analysis techniques.

## Our Notes

| Security Event | Observable Evidence | Detection Source | Defensive Control | Forensic Artifact |
|---|---|---|---|---|
| Cleartext POP3 auth | User/password commands in PCAP | Network capture | Require TLS | Exposure timeframe and account |
| Repeated failed login | Repeated source/account attempts | Mail-access logs | Rate limits and account policy | Source-IP timeline |
| Sudden retrieval spike | Message retrieval and session volume | POP3 and mailbox logs | Access controls and alerting | Account, client IP, message count |

## Related

- [POP3 Detection](./detection.md)
- [POP3 Defense](./defense.md)
- [POP3 Forensics](./forensics.md)

