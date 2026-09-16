# SMTP Attack Surface

## Attack Surface Overview

SMTP security depends on relay policy, authentication and submission design, encryption policy, recipient handling, message validation, and the health of the mail server implementation. All testing must use controlled accounts, domains, and recipients.

## Recommended Resources

### NIST Trustworthy Email

- **Link:** [NIST SP 800-177 Revision 1: Trustworthy Email](https://csrc.nist.gov/pubs/sp/800/177/r1/final)
- **Type:** Government guidance
- **Level:** Intermediate
- **Why read:** Connects email transport, authentication, and operational controls into a defensible email-security program.

- [RFC 5321: SMTP](https://www.rfc-editor.org/rfc/rfc5321) - relay semantics and reply behavior.
- [Postfix Basic Configuration](https://www.postfix.org/BASIC_CONFIGURATION_README.html) - policy-relevant configuration guidance.
- [MITRE ATT&CK T1566: Phishing](https://attack.mitre.org/techniques/T1566/) - documented phishing technique context.

## Authentication

- Weak or unprotected submission credentials can be targeted with repeated authentication attempts.
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) - technique context and defensive considerations.

## Misconfiguration

- Open relay, overbroad trusted networks, permissive recipient restrictions, weak TLS policy, and missing sender-domain controls enlarge exposure.
- [Postfix Basic Configuration](https://www.postfix.org/BASIC_CONFIGURATION_README.html) - authoritative implementation reference.

## Protocol-specific Attacks

- Spoofed display names, misleading envelope/header relationships, and malicious message content require different detection layers.
- STARTTLS downgrade or certificate-validation failure undermines transport expectations if cleartext fallback remains accepted.
- [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207) - TLS extension behavior.

## Historical Vulnerabilities

Track security notices for the exact MTA, content filter, and library versions in scope. Avoid mapping generic spam or phishing behavior to a CVE.

## Labs

- [Google Messageheader Analyzer](https://toolbox.googleapps.com/apps/messageheader/) - inspect headers using sanitized sample messages.
- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/) - public traffic-analysis exercises; select only lawful samples.

## Our Notes

| Security Event | Observable Evidence | Detection Source | Defensive Control | Forensic Artifact |
|---|---|---|---|---|
| Unauthorized relay attempt | Recipient policy rejection or acceptance | MTA log and queue records | Restrictive relay policy | Queue ID, source IP, envelope recipients |
| Repeated AUTH failure | Account and source failure series | Submission and auth logs | MFA where supported, rate limits, monitoring | Attempt timeline |
| Suspicious sender identity | SPF/DKIM/DMARC results and headers | Mail gateway and headers | Domain authentication controls | Raw message headers |
| TLS downgrade symptom | STARTTLS or handshake error | SMTP and TLS logs | Require approved TLS policy | Negotiation metadata |

## Related

- [SMTP Detection](./detection.md)
- [SMTP Defense](./defense.md)
- [SMTP Forensics](./forensics.md)

