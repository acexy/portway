<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
  Lightweight reverse tunneling for reliable, long-running service exposure.
</p>

Portway exposes services from private networks through a public server. It keeps
the control plane separate from tunneled traffic, supports TCP and QUIC as its
underlying client-server transport, and is designed around explicit ownership,
bounded resources, and secure defaults.

[中文版](README_ZH.md)

## Highlights

- TCP, UDP, and domain-based HTTP/HTTPS reverse proxying
- Selectable TCP or QUIC client-server transport
- Authenticated and encrypted client-server connections
- Atomic proxy registration and bounded session recovery
- HTTP/HTTPS streaming and Upgrade support with connection reuse
- Server-side HTTPS TLS termination with atomic certificate reload
- Source IP access control with an independently watched IPv4/IPv6 deny-list file
- Strict YAML configuration and fail-closed validation
- Small client and server binaries with a consistent command-line interface
- **Flexible client governance:**
  - shared configuration for trusted fleets
  - policy-governed client configuration
  - fully server-managed configuration
- **Fail-closed server main-configuration reload:**
  - atomic validation and publication of complete configuration generations
  - deployment-wide disconnect on Token changes, selective policy revocation,
    and online Managed configuration rollout
  - retention of the previous effective snapshot on validation failure

## Quick start

The following example exposes the client's local SSH service on TCP port
`22022` of the Portway server.

Create `server.yaml`:

```yaml
transport:
  type: tcp
  listen_address: 127.0.0.1:7000

authentication:
  shared_token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
```

Create `client.yaml`:

```yaml
transport:
  type: tcp
  server_address: 127.0.0.1:7000

authentication:
  token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES

proxies:
  - name: ssh
    type: tcp
    local_ip: 127.0.0.1
    local_port: 22
    remote_port: 22022
```

Use the same cryptographically random Token on both sides, then start the
server and client:

```bash
portwayd run --config server.yaml
portway run --config client.yaml
```

The local SSH service is now available at:

```text
127.0.0.1:22022
```

## HTTP and HTTPS proxy

Enable either or both public HTTP and HTTPS listeners on the server. HTTPS is
disabled when `https_listen_address` is empty:

```yaml
tunnel:
  http_listen_address: 127.0.0.1:8080
  https_listen_address: 127.0.0.1:8443

https:
  certificates:
    - domains: [app.example.com]
      cert_file: /path/to/https-server.crt
      key_file: /path/to/https-server.key
```

Register a domain on the client:

```yaml
proxies:
  - name: web
    type: http
    public_schemes:
      - https
      - http
    domain: app.example.com
    local_ip: 127.0.0.1
    local_port: 8080
```

`type` selects the proxy semantics carried between `portwayd` and `portway`;
`public_schemes` explicitly selects the public HTTP/HTTPS listeners. Every
selected listener must be enabled or the complete registration is rejected.
When omitted or empty, `public_schemes` defaults to HTTP only.
The public `Host` is matched to an authenticated client registration. Portwayd
terminates public HTTPS and forwards HTTP through the authenticated tunnel, so
the local application receives a normal HTTP request. Visitor-supplied
`Forwarded` and `X-Forwarded-*` values are removed; Portwayd writes trusted
`X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` values. HTTP and
HTTPS share the same proxy limits. HTTPS selects certificates by SNI from an atomically
reloadable certificate set; invalid updates leave the previous set active. HTTPS supports
HTTP/1.1 and HTTP/2 with a minimum TLS version of 1.2. HTTPS backend forwarding,
SNI passthrough, ACME, and HTTP/3 are not currently supported.

## UDP proxy

Register a public UDP port and a local UDP service on the client:

```yaml
proxies:
  - name: dns
    type: udp
    local_ip: 127.0.0.1
    local_port: 53
    remote_port: 5353
```

Portway preserves datagram boundaries and gives each public visitor association
an isolated authenticated data link. UDP works with both TCP and QUIC as the
selected client-server transport. Server-side association, queue, rate, memory,
and idle limits have safe defaults and configurable hard boundaries.

## QUIC transport

Portway can use QUIC instead of TCP between `portway` and `portwayd`. QUIC
requires a server certificate and TLS verification in addition to Portway Token
authentication.

For private deployments, generate an internal CA and server certificate:

```bash
portwayd gen cert \
  --server-name gateway.example.com \
  --ip 10.0.0.10
```

Run `portwayd help gen cert` for all certificate options. Keep the generated root CA
private key offline and distribute only the root CA certificate to clients.

## Commands

```text
portway run [--config FILE]
portway gen config [full]
portway version

portwayd run [--config FILE]
portwayd gen config [full]
portwayd gen cert [options]
portwayd version
```

`gen config` creates a minimal `client.yaml` or `server.yaml` in the current
directory. Add `full` to use the complete annotated template. Existing files
are never overwritten. Run either binary without arguments to display every
available command, including nested generation commands.

## Install with Homebrew

The official [Acexy Homebrew tap](https://github.com/acexy/homebrew-tap)
provides separate formulae for the client and server on macOS and Linux.

Install the client:

```bash
brew install acexy/tap/portway
```

Install the server:

```bash
brew install acexy/tap/portwayd
```

Both components can be installed on the same host when needed:

```bash
brew install acexy/tap/portway acexy/tap/portwayd
```

The formulae do not create or overwrite configuration files. Prepare the
appropriate `client.yaml` or `server.yaml` before running the installed command.

## Public documentation

- [Technical overview](assets/docs/technical/README.md)
- [Operations endpoints](assets/docs/operations/README.md)
- [Authentication and configuration control](assets/docs/authentication/README.md)
- [Server configuration reload](assets/docs/reload/README.md)
- [Security](assets/docs/security/README.md)
- [Future plans](assets/docs/future/README.md)
- Fully annotated configuration examples:
  [client](config/client.yaml) and [server](config/server.yaml)

The public documentation intentionally describes stable behavior and security
properties without serving as a complete wire-protocol specification.

## Current scope

Portway focuses on lightweight, operator-managed reverse tunneling. It does not
currently provide a web dashboard, P2P NAT traversal, TUN/TAP networking,
dynamic plugins, or a distributed multi-tenant control plane.

## License

Copyright 2026 Acexy.

Portway is licensed under the [Apache License 2.0](LICENSE). See
[NOTICE](NOTICE) for attribution information.
