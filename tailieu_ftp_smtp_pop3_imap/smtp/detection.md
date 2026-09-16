# SMTP Detection

## What to Monitor

Monitor relay rejections and acceptances, SMTP AUTH failures, queue growth, connection volume, destination patterns, message-delivery failures, TLS errors, sender-domain authentication results, and unusual outbound rates.

## Relevant Logs

- MTA connection, SMTP, submission, and queue logs
- Authentication and operating-system security logs
- Mail-gateway, DNS, SPF/DKIM/DMARC, and content-filter events
- Firewall, flow, and IDS telemetry

## Network Evidence

SMTP captures can reveal commands and message headers on an unencrypted session. With TLS, retain connection and handshake metadata plus service logs for attribution.

## Detection Engineering Resources

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) - log-management baseline.
- [Postfix Mail Logging](https://www.postfix.org/MAILLOG_README.html) - explains how Postfix records mail flow.
- [Zeek Documentation](https://docs.zeek.org/en/current/) - network telemetry reference.

## SIEM Resources

- [Elastic Security detection and alerting](https://www.elastic.co/docs/solutions/security/detect-and-alert)
- [Sigma Documentation](https://sigmahq.io/docs/)

## IDS / IPS

- [Suricata User Guide](https://docs.suricata.io/en/latest/)
- [Snort Documentation](https://docs.snort.org/)

## PCAP Analysis

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)

## Our Notes

| Signal | Evidence | Possible Meaning |
|---|---|---|
| Delivery volume spike | Queue depth, recipient count, outbound rate | Spam abuse, campaign, or legitimate batch activity |
| Many invalid recipients | Repeated rejection patterns | Enumeration, broken client, or misaddressed campaign |
| Same queue ID across events | MTA log correlation | End-to-end path of one message |
| New sender domain with validation failures | Header and mail-gateway results | Spoofing, configuration issue, or attack attempt |

## Related

- [SMTP Attack Surface](./attack.md)
- [SMTP Defense](./defense.md)
- [SMTP Forensics](./forensics.md)

