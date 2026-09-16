# Forensic Tools

## Packet and Network Evidence

- [Wireshark Documentation](https://www.wireshark.org/docs/) - packet inspection and evidence review.
- [tshark manual page](https://www.wireshark.org/docs/man-pages/tshark.html) - reproducible packet-field extraction.
- [Zeek Documentation](https://docs.zeek.org/en/current/) - structured network logs and metadata.

## Email Evidence

- [Google Messageheader Analyzer](https://toolbox.googleapps.com/apps/messageheader/) - visualize and inspect sanitized email headers.
- [RFC 2045: MIME](https://www.rfc-editor.org/rfc/rfc2045) - standard reference for message body structure.

## Host and Log Evidence

- [Wazuh Documentation](https://documentation.wazuh.com/current/) - host security telemetry.
- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) - log-management and preservation principles.

## Our Notes

- Preserve raw input, analyst notes, tool version, timezone, and reproducible query or filter where the process requires it.
- Header-analysis results are supporting evidence; retain the original message source and correlate it with MTA records.
- Work from a copy of evidence and follow the relevant privacy, retention, and incident-response policy.

## Related

- [Network Analysis Tools](./network-analysis.md)
- [PCAP and Datasets](../references/datasets-pcap.md)
- [SMTP Forensics](../smtp/forensics.md)

