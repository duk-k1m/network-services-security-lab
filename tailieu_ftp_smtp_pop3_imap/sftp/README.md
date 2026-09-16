# SFTP / SSH Security

## Research Areas

- [Overview](./overview.md)
- [Attack Surface](./attack.md)
- [Detection](./detection.md)
- [Defense](./defense.md)
- [Forensics](./forensics.md)

## Quick Facts

| Item | Value |
|---|---|
| Protocol | SSH File Transfer Protocol over SSH |
| Default port | TCP 22 by convention |
| Encryption | Provided by SSH transport |
| Authentication | Password, public key, and other SSH-supported methods |

## Recommended Starting Resources

- [RFC 4251: SSH Protocol Architecture](https://www.rfc-editor.org/rfc/rfc4251) - SSH model and terminology.
- [RFC 4253: SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253) - transport protection details.
- [SFTP draft, version 3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) - commonly implemented SFTP protocol draft.
- [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config) - authoritative configuration reference.

## Related

- [RFC and Standards](../references/rfc.md)
- [Hands-on Labs](../references/labs.md)
- [Detection Tools](../tools/detection-tools.md)

