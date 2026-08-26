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
  shared_token: REPLACE_TOKEN
```

Create `client.yaml`:

```yaml
transport:
  type: tcp
  server_address: 127.0.0.1:7000

authentication:
  token: REPLACE_TOKEN

proxies:
  - name: ssh
    type: tcp
    local_ip: 127.0.0.1
    local_port: 22
    remote_port: 22022
```

Use the same Token on both sides. It must contain more than 32 UTF-8 characters;
cryptographically generated values are strongly recommended. Then start the
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
`Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`
values are removed; Portwayd writes trusted
`X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` values. HTTP and
HTTPS share the same proxy limits. For HTTPS, the normalized SNI and HTTP `Host`
must match. Protocol timeouts and request-body limits default to disabled and can
be enabled under the server `http` configuration. HTTPS selects certificates by SNI from an atomically
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

For private deployments, generate an internal CA and server certificate. Choose
SANs that match the value clients will configure as `transport.quic.server_name`:

```bash
# Clients verify the server by IP.
portwayd gen cert --ip 10.0.0.10

# Clients verify the server by DNS name. server_address may still contain an IP.
portwayd gen cert --server-name gateway.example.com

# Allow either identity.
portwayd gen cert \
  --server-name gateway.example.com \
  --ip 10.0.0.10
```

When neither `--server-name` nor `--ip` is supplied, the certificate defaults
to `localhost` and `127.0.0.1` and is suitable only for local use. If
`server_name` is an IP address, that exact address must be present through
`--ip`; a DNS SAN does not validate an IP identity.

Configure the generated server certificate and key on `portwayd`:

```yaml
transport:
  type: quic
  listen_address: 0.0.0.0:7000
  quic:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
```

Configure the matching identity and generated root CA certificate on `portway`:

```yaml
transport:
  type: quic
  server_address: 10.0.0.10:7000
  quic:
    server_name: 10.0.0.10
    ca_file: ./certs/root-ca.crt
```

For a DNS certificate, `server_address` may still be `10.0.0.10:7000`, but
`server_name` must be `gateway.example.com`. Portway uses `server_address` to
connect and `server_name` to verify the certificate.

Run `portwayd help gen cert` for all certificate options. Keep `root-ca.key` and
`server.key` private. Distribute only `root-ca.crt` to clients; clients do not
need either private key.

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
directory. Client generation writes a fresh canonical 256-bit Token into the
owner-only file. Add `full` to use the complete annotated template. Existing
files are never overwritten. Run either binary without arguments to display
every available command, including nested generation commands.

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

## License

Copyright 2026 Acexy.

Portway is licensed under the [Apache License 2.0](LICENSE). See
[NOTICE](NOTICE) for attribution information.
