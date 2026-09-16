# IMAP Attack Surface

## Attack Surface Overview

IMAP exposure combines account authentication risk, protected-transport policy, mailbox permission design, client synchronization behavior, and the impact of an authenticated mailbox session.

## Recommended Resources

### Secure Mail Access

- **Link:** [RFC 8314: Cleartext Considered Obsolete](https://www.rfc-editor.org/rfc/rfc8314)
- **Type:** RFC
- **Level:** Intermediate
- **Why read:** Provides a standards-based rationale for eliminating cleartext mail access.

- [RFC 9051: IMAP4rev2](https://www.rfc-editor.org/rfc/rfc9051) - protocol-state and command reference.
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) - authentication-attack context.
- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) - impact of successful account compromise.

## Authentication

- Brute force and credential stuffing risk increase when passwords are weak, reused, or not adequately monitored.
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/) - valid-account use can blend with normal mail access, requiring contextual detection.

## Misconfiguration

- Optional TLS, weak certificate management, broad administrative access, inherited mailbox permissions, and exposed legacy clients increase risk.
- [Dovecot SSL Configuration](https://doc.dovecot.org/main/core/config/ssl.html) - official transport-security reference.

## Protocol-specific Attacks

- A cleartext IMAP session can expose authentication and mailbox command activity to an on-path observer.
- An authenticated mailbox session may enable search and bulk retrieval; legitimate synchronization must be distinguished from misuse.

## Historical Vulnerabilities

Review advisories for the exact IMAP server, authentication backend, and library versions. Do not cite a vulnerability without confirmed applicability.

## Labs

- [Google Messageheader Analyzer](https://toolbox.googleapps.com/apps/messageheader/) - safe inspection of sanitized email-header artifacts.
- [Network Forensic Puzzle Contest](https://www.netresec.com/?page=NetworkForensicPuzzle) - public investigation practice.

## Our Notes

| Security Event | Observable Evidence | Detection Source | Defensive Control | Forensic Artifact |
|---|---|---|---|---|
| Credential guessing | Repeated login failures | IMAP and identity logs | Rate controls, monitoring, account protections | Source/account time series |
| New successful login | First-seen source or client | Mail-access and endpoint logs | Risk-based access review | Session and client details |
| Mailbox collection pattern | High fetch/search volume | IMAP, flow, and mailbox audit logs | Least privilege, alert thresholds | Folders, counts, timing |

## Related

- [IMAP Detection](./detection.md)
- [IMAP Defense](./defense.md)
- [IMAP Forensics](./forensics.md)

