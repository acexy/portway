<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
  Lightweight bidirectional tunneling for reliable, long-running network access.
</p>

Portway establishes an authenticated tunnel between `portway` and `portwayd`,
then carries traffic in either direction:

- **Proxy mode (server to client):** expose a service reachable by `portway`
  through a TCP/UDP port or HTTP/HTTPS domain on `portwayd`.
- **Forward mode (client to server):** open a local TCP/UDP listener on
  `portway` and reach an explicitly allowed IP and port from the `portwayd`
  network.

The two modes are independent features and can run separately or share one
authenticated client-server connection.

[中文版](README_ZH.md)

## Functional architecture

```text
Portway
├── Proxy: publish client-side services through portwayd
│   ├── Standard Proxy: one public entry maps to one client service
│   │   ├── TCP / UDP public port
│   │   └── HTTP / HTTPS domain
│   └── Mirror Proxy: public TCP/UDP ports copy input to multiple clients
│       └── one configured Primary replies; other replies are discarded
└── Forward: expose an approved server-side service on a portway local port
    └── TCP / UDP local listener
```

**Proxy** is for publishing services from a client network. `portwayd` owns the
public listener and carries visitor traffic through the tunnel to `portway`.
Standard Proxy is suited to SSH, web applications, DNS, game servers, and other
services that need a stable public entry.

**Mirror Proxy** is a controlled TCP/UDP variant for traffic observation,
parallel processing, protocol migration, auditing, and validation against a
shadow service. Every online member receives the same visitor input, but only
the configured Primary can reply, so mirror clients cannot interfere with the
visitor response. Members that join an active flow receive only subsequent
traffic: TCP starts at an arbitrary byte offset, while UDP starts with the next
datagram. See [TCP and UDP Proxy mirroring](assets/docs/proxy-mirroring/README.md).

**Forward** is for consuming services from the server network. `portway` owns
the local TCP/UDP listener and sends connections or datagrams to an explicitly
allowed target reachable by `portwayd`. Typical uses include private databases,
administration endpoints, internal DNS, and other services that should remain
off the public network.

| Requirement | Feature | Entry location | Target location | Protocols |
| --- | --- | --- | --- | --- |
| Publish one client service | Standard Proxy | `portwayd` | Client network | TCP, UDP, HTTP, HTTPS |
| Copy public input to multiple clients | Mirror Proxy | `portwayd` | Multiple client networks | TCP, UDP |
| Access a server-side service locally | Forward | `portway` | Server network | TCP, UDP |

For traffic diagrams and complete mode boundaries, see
[Proxy and Forward modes](assets/docs/modes/README.md).

## Highlights

**Bidirectional traffic**

- Proxy client-side TCP and UDP services through public listeners on the server.
- Mirror a governed or managed public TCP/UDP Proxy entry to multiple clients
  without allowing shadow clients to affect visitor responses.
- Route domains over HTTP or HTTPS, with server-side TLS termination, streaming,
  Upgrade support, connection reuse, and atomic certificate reload.
- Forward TCP and UDP from client-side listeners to server-side networks. A
  server-wide allowlist restricts every target by CIDR, protocol, and port.
- Run Proxy and Forward entries together over one authenticated client session.

**Transport and security**

- Select TCP or QUIC for the underlying client-server transport.
- Authenticate and encrypt control and data connections without a plaintext
  fallback.
- Enforce strict YAML and protocol validation, bounded queues and sessions, and
  fail-closed configuration publication.
- Reject source IPs through an independently watched IPv4/IPv6 deny-list.

**Operations and governance**

- Atomically register complete Proxy and Forward sets and recover interrupted
  sessions within bounded limits.
- Run small client and server binaries with a consistent command-line interface.
- Choose shared configuration for trusted fleets, policy-governed client
  configuration, or fully server-managed configuration.
- Reload the server configuration atomically, including Token revocation,
  selective policy revocation, Managed configuration rollout, Forward policy,
  and HTTPS certificates. Invalid updates retain the previous effective state.

## Quick start

The examples below use the Shared authentication mode. Replace
`REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS` with the same cryptographically
generated Token in both files. The Token must contain more than 32 UTF-8
characters. Start `portwayd` before `portway` in either scenario.

### Scenario 1: expose a client-side service through the server

Use Proxy mode when a service is reachable from `portway`, but users need to
connect through the public or centrally reachable `portwayd` host. This example
publishes the client's SSH service as `SERVER_IP:22022`.

Create `server.yaml`:

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

Create `client.yaml`:

```yaml
transport:
  type: tcp
  server_address: SERVER_IP:7000

authentication:
  token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS

proxies:
  - name: ssh
    type: tcp
    local:
      ip: 127.0.0.1
      port: 22
    public:
      port: 22022
```

Start both processes with their configuration paths:

```bash
portwayd run server.yaml
portway run client.yaml
```

Users can now reach the client-side SSH service through the server:

```text
SERVER_IP:22022
```

Traffic flows as follows:

```text
Visitor -> portwayd:22022 -> authenticated tunnel -> portway -> 127.0.0.1:22
```

### Scenario 2: access a server-side network from the client

Use Forward mode when a service is reachable from `portwayd`, but a user or
application beside `portway` needs a local entry point. This example exposes the
server-side database `10.20.1.15:5432` only on the client's loopback address at
`127.0.0.1:15432`.

Create `server.yaml`. Forward is disabled by default, so enable it and allow the
exact target network, protocol, and port:

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS

forwards:
  enabled: true
  rules:
    - ip_range: 10.20.1.0/24
      tcp:
        port_ranges:
          - start: 5432
            end: 5432
```

Create `client.yaml`:

```yaml
transport:
  type: tcp
  server_address: SERVER_IP:7000

authentication:
  token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS

forwards:
  - name: database
    type: tcp
    listen:
      ip: 127.0.0.1
      port: 15432
    target:
      ip: 10.20.1.15
      port: 5432
```

Start both processes:

```bash
portwayd run server.yaml
portway run client.yaml
```

Applications on the client host can now connect to the server-side database at:

```text
127.0.0.1:15432
```

Traffic flows in the opposite direction from Proxy mode:

```text
Local application -> portway:15432 -> authenticated tunnel
                  -> portwayd -> 10.20.1.15:5432
```

Forward targets accept IP addresses only. Every target must match one complete
server rule; ranges from different rules are never combined. Bind the client
listener to loopback unless other hosts intentionally need access. TCP and UDP
Forward entries are supported, while domain-based HTTP/HTTPS routing belongs to
Proxy mode.

## HTTP and HTTPS proxy

Enable either or both public HTTP and HTTPS listeners on the server. HTTPS is
disabled when `proxies.https.listen_address` is empty:

```yaml
proxies:
  http:
    listen_address: 127.0.0.1:8080
  https:
    listen_address: 127.0.0.1:8443
    certificates:
      - domains:
          - app.example.com
        cert_file: /path/to/https-server.crt
        key_file: /path/to/https-server.key
```

Register a domain on the client:

```yaml
proxies:
  - name: web
    type: http
    local:
      ip: 127.0.0.1
      port: 8080
    public:
      schemes:
        - https
        - http
      domain: app.example.com
```

`type` selects the proxy semantics carried between `portwayd` and `portway`;
`public.schemes` explicitly selects the public HTTP/HTTPS listeners. Every
selected listener must be enabled or the complete registration is rejected.
When omitted or empty, `public.schemes` defaults to HTTP only.
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
    local:
      ip: 127.0.0.1
      port: 53
    public:
      port: 5353
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
portway run [FILE]
portway gen config [full]
portway version

portwayd run [FILE]
portwayd gen config [full]
portwayd gen cert [options]
portwayd version
```

`gen config` creates a minimal `client.yaml` or `server.yaml` in the current
directory. Client generation writes a fresh canonical 256-bit Token into the
owner-only file. Add `full` to use the complete annotated template. Existing
files are never overwritten. Run either binary without arguments to display
every available command, including nested generation commands.

The optional positional `FILE` selects a configuration path. When omitted,
`portway run` loads `client.yaml` and `portwayd run` loads `server.yaml` from
the current working directory. There is no `--config` option.

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

## Technical documentation

- [Proxy and Forward modes](assets/docs/modes/README.md)
- [TCP and UDP Proxy mirroring](assets/docs/proxy-mirroring/README.md)
- [Technical overview](assets/docs/technical/README.md)
- [Operations endpoints](assets/docs/operations/README.md)
- [Authentication and configuration control](assets/docs/authentication/README.md)
- [Server configuration reload](assets/docs/reload/README.md)
- [Security](assets/docs/security/README.md)
- [Future plans](assets/docs/future/README.md)
- Fully annotated configuration examples:
  [client](config/client.yaml) and [server](config/server.yaml)

The technical documentation describes stable behavior and security
properties without serving as a complete wire-protocol specification.

## License

Copyright 2026 Acexy.

Portway is licensed under the [Apache License 2.0](LICENSE). See
[NOTICE](NOTICE) for attribution information.
