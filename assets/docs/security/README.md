# Portway Security

Portway is designed to expose private services through an authenticated public
gateway. Operators remain responsible for host security, network policy,
credential handling, and the applications exposed through a tunnel.

## Supported security model

- Every client-server transport requires Portway Token authentication.
- TCP transport establishes an authenticated encrypted application channel.
- QUIC transport requires TLS 1.3 certificate verification and still performs
  Portway Token authentication.
- Public HTTPS terminates at portwayd with TLS 1.2 or later and uses an
  independently configured SNI certificate set.
- Portway does not support plaintext transport or automatic fallback to a less
  secure mode.
- Invalid authentication, malformed configuration, and invalid trusted-source
  headers fail closed.

The server can combine one Shared Token with independently owned Governed and
Managed client records. Every configured Token must be globally unique within
that server and contain at least 32 bytes of cryptographically random data.
Treat each Token as a long-term credential.

Authentication failures are rate-limited per normalized source IP with bounded
server memory. This is an application safety boundary, not a replacement for
upstream or kernel-level denial-of-service controls.

## Credential handling

- Never commit real Tokens, private keys, or production certificates.
- Do not pass credentials directly on command lines.
- Restrict private-key and configuration-file permissions.
- Use a secret manager or protected configuration deployment mechanism.
- Rotate credentials after suspected disclosure.
- Keep an internal CA private key offline when practical.
- Distribute the CA certificate, never the CA private key, to clients.

`portwayd` may generate a missing Token and log it once at startup so an
operator can configure clients. Protect startup logs accordingly. Explicitly
configured Tokens are not logged.

## QUIC certificates

Clients verify the server certificate against either the operating-system trust
store or a configured CA bundle. The configured server name must match a
certificate SAN.

`portwayd gen cert` is intended for private deployments that need a small
internal CA. Generated material must still be protected, backed up, rotated, and
distributed using normal production credential controls.

## Public HTTPS certificates

Public HTTPS selects an explicitly configured certificate by SNI. Every mapped
name must be covered by that certificate's SAN. Certificate contents, paths,
and mappings reload as one atomic set. A missing, expired, invalid, or mismatched
candidate leaves the previous set active. Public HTTPS certificates and QUIC
transport certificates remain independent even when they reference the same files.

## Source IP filtering

The server can load an IPv4/IPv6 deny list containing individual addresses and
CIDR prefixes. Updates are validated as a complete snapshot before becoming
active. Invalid updates retain the last valid snapshot.

The policy covers client-server transport connections and public proxy
listeners. Newly denied active sources are closed where the runtime owns a
corresponding connection.

HTTP and HTTPS can optionally obtain source addresses from one configured
trusted header. When the setting is empty, HTTPS socket filtering occurs before
the TLS handshake. When configured, both listeners use the trusted header
instead of the socket peer, and HTTPS checks it after TLS decryption. Enable
this only when a trusted upstream removes client values, writes the verified
chain, and clients cannot bypass it. Invalid chains are rejected.

Application-layer source filtering is not a DDoS control and does not replace a
firewall, cloud security group, load-balancer ACL, or kernel packet filter.

## Deployment recommendations

- Expose only required transport and proxy ports.
- Run Portway as a dedicated, unprivileged operating-system account.
- Keep Portway and the Go runtime updated through controlled releases.
- Place high-volume filtering at the earliest network boundary.
- Monitor authentication failures, reconnects, registration failures, and
  source-policy rejections.
- Test recovery and rollback procedures before production deployment.
- Apply independent authentication and authorization to exposed applications.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue.

Use GitHub's private security advisory workflow for this repository when
available. Include the affected version, deployment mode, reproduction steps,
impact, and any proposed mitigation. Do not include real Tokens, private keys,
certificates containing private material, or unrelated user data.

## Public documentation boundary

Public documentation describes supported security properties and operator
responsibilities. It is not a complete protocol specification. Portway does not
treat unpublished implementation details as a security control; authentication,
cryptographic verification, strict validation, and fail-closed behavior remain
the security boundary.
