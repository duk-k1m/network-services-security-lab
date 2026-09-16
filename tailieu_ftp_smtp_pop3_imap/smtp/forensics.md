# SMTP Forensics and Investigation

## Evidence Sources

Collect MTA logs, queue records, raw messages with headers, authentication logs, mail-gateway verdicts, DNS authentication results, endpoint telemetry, and network evidence while preserving chain-of-custody requirements.

## Server Logs

Prioritize queue ID, timestamp, client IP, envelope sender and recipients, relay/delivery outcome, TLS state, authentication result, and rejection reason. Preserve related log lines before rotation.

## Network Evidence

Network records can establish connection and message-flow timing. Do not rely on network content alone when TLS is present; correlate with MTA logs and preserved original messages.

## PCAP

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html)

## File / Mail Artifacts

Preserve the message source, full headers, Message-ID, MIME structure, attachment hashes, delivery status, and domain-authentication results. Header order and received lines can assist a timeline but require contextual validation.

## Investigation Guides

- [NIST SP 800-177 Revision 1](https://csrc.nist.gov/pubs/sp/800/177/r1/final)
- [Postfix Mail Logging](https://www.postfix.org/MAILLOG_README.html)

## Tools

- [Google Messageheader Analyzer](https://toolbox.googleapps.com/apps/messageheader/)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Zeek Documentation](https://docs.zeek.org/en/current/)

## Labs / Datasets

- [Digital Corpora](https://digitalcorpora.org/) - public forensic corpora; confirm licensing and relevance before use.
- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/) - safe study material when used under its terms.

## Our Notes

| Evidence | Location | What It Can Reveal |
|---|---|---|
| Queue ID and MTA log lines | Mail server | Message path, client, recipients, delivery outcome |
| Full message headers | Preserved raw message | Received chain, Message-ID, authentication results |
| MIME body and attachments | Message artifact | Payload type, attachment hash, and claimed sender content |
| DNS and gateway results | Mail security platform | SPF/DKIM/DMARC evaluation at processing time |

## Related

- [SMTP Detection](./detection.md)
- [SMTP Defense](./defense.md)
- [RFC and Standards](../references/rfc.md)

