# Network Basics

## Focus

Client-server communication, TCP ports, DNS context, packet capture, authentication, and authorization are the shared vocabulary behind every service in this repository.

## Recommended Resources

### Wireshark Documentation

- **Link:** [Wireshark User and Developer Documentation](https://www.wireshark.org/docs/)
- **Type:** Official documentation
- **Level:** Beginner to Intermediate
- **Why read:** Provides the packet-analysis workflow used to inspect service control channels, TLS handshakes, and evidence in PCAPs.

### tcpdump Manual

- **Link:** [tcpdump manual page](https://www.tcpdump.org/manpages/tcpdump.1.html)
- **Type:** Official documentation
- **Level:** Beginner to Intermediate
- **Why read:** Explains a common command-line capture tool and its capture-filter model before traffic reaches a GUI analyzer.

### Zeek Documentation

- **Link:** [Zeek Documentation](https://docs.zeek.org/en/current/)
- **Type:** Official documentation
- **Level:** Intermediate
- **Why read:** Shows how network telemetry can become structured logs for service and session analysis.

## Our Notes

- A port identifies a transport endpoint; it does not prove that the traffic is benign or even that it uses the expected protocol.
- Authentication establishes an asserted identity, while authorization decides what that identity may access.
- A PCAP records network-visible behavior, but server logs are usually needed to attribute the event to an account or application outcome.
- Encryption protects content in transit but leaves useful metadata such as peer IPs, timing, certificate information, and connection volume.

## Related

- [TLS and Encryption](./tls.md)
- [Logging and Monitoring](./logging-monitoring.md)
- [Research Hub](../resource-hub.md)

