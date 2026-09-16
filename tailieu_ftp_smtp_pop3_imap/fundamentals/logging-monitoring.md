# Logging and Monitoring

## Focus

Service investigations require evidence from application logs, authentication logs, packet capture, network-monitoring logs, IDS alerts, and SIEM correlation. Time synchronization and retention determine whether those sources can be joined later.

## Recommended Resources

### NIST Log Management

- **Link:** [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)
- **Type:** Government guidance
- **Level:** Intermediate
- **Why read:** Establishes durable principles for log generation, collection, analysis, retention, and protection.

### Suricata Documentation

- **Link:** [Suricata User Guide](https://docs.suricata.io/en/latest/)
- **Type:** Official documentation
- **Level:** Intermediate
- **Why read:** Documents IDS/IPS alerting, protocol awareness, and event output that can complement host logs.

### Elastic Security Detection and Alerting

- **Link:** [Elastic Security detection and alerting](https://www.elastic.co/docs/solutions/security/detect-and-alert)
- **Type:** Official documentation
- **Level:** Intermediate
- **Why read:** Provides a practical view of rule-based detection, alert triage, and security-data workflows.

### Wazuh Documentation

- **Link:** [Wazuh Documentation](https://documentation.wazuh.com/current/)
- **Type:** Official documentation
- **Level:** Intermediate
- **Why read:** Useful for host log collection, file integrity monitoring, and agent-based security telemetry.

## Our Notes

| Event | Evidence | Detection Source | Investigation Value |
|---|---|---|---|
| Repeated login failures | Account, source IP, timestamp | Authentication and SIEM logs | Supports brute-force or spraying triage |
| Cleartext session | Commands or credentials in a capture | PCAP and protocol analyzer | Proves exposure and bounds affected data |
| TLS negotiation failure | Version, certificate, error, client IP | Service and TLS logs | Distinguishes misconfiguration from probing |
| Unusual transfer volume | Bytes, file names, duration | Service, flow, and endpoint logs | Supports possible exfiltration analysis |

## Related

- [Network Basics](./network-basics.md)
- [Tools](../tools/README.md)
- [PCAP and Datasets](../references/datasets-pcap.md)

