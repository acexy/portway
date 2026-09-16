<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
  Lightweight, secure, and stable network connectivity through Proxy, Forward, and VNet modes.
</p>

Portway establishes an authenticated, encrypted connection between `portway` and
`portwayd` and provides three independent capabilities that can be combined as needed:

- **Proxy mode:** reach client-side services through a public `portwayd` entry.
- **Forward mode:** reach restricted server-side services through a local `portway` entry.
- **VNet mode:** form a mutually reachable private network cluster with automatic QUIC P2P between Managed clients.

Proxy and Forward address explicit services and ports. VNet provides a
centralized VPN-like private-network experience: Managed nodes in different
networks reach each other through stable addresses. Client-to-client traffic starts
through the server and automatically upgrades new flows to a direct QUIC Datagram path
when peer probing succeeds; client-to-server traffic always remains relayed. VNet carries authorized IPv4 TCP/UDP traffic,
and each destination node's port policy remains the access boundary. Proxy and
Forward can share an authenticated session; VNet uses server-owned Managed
identities and address assignments.

[中文版](README_ZH.md)

## Three connectivity modes

```text
Portway
├── Proxy: publish client-side services through portwayd
│   ├── Standard Proxy: one public entry maps to one client service
│   │   ├── TCP / UDP public port
│   │   └── HTTP / HTTPS domain
│   └── Mirror Proxy: public TCP/UDP ports copy input to multiple clients
│       └── one configured Primary replies; other replies are discarded
├── Forward: expose an approved server-side service on a portway local port
│   └── TCP / UDP local listener
└── VNet: connect managed nodes through stable private IPv4 addresses
    ├── automatic QUIC Datagram P2P for reachable client pairs
    └── server Relay fallback over 1-8 isolated packet channels (default: 4)
```

### Proxy: publish a client service through a server entry

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
Local service outages do not log clients out; forwarding resumes automatically
after recovery, without replaying traffic lost during the outage.

### Forward: bring a server-network service to the client

**Forward** is for consuming services from the server network. `portway` owns
the local TCP/UDP listener and sends connections or datagrams to an explicitly
allowed target reachable by `portwayd`. Typical uses include private databases,
administration endpoints, internal DNS, and other services that should remain
off the public network.

### VNet: form a cross-network private cluster of managed nodes

**VNet** is a managed-only Linux, macOS, and Windows amd64 mode for forming a VPN-like private
network cluster from nodes in different private networks, clouds, or edge
networks. The server owns address
`172.20.0.1` by default and assigns stable addresses to configured clients;
client-to-client traffic uses automatic QUIC P2P when reachable and otherwise remains centrally relayed. Portway creates only its owned
logical `portway0` network and enforces each destination's TCP/UDP port allowlist.
P2P requires no feature switch: traffic continues over Relay during probing,
LAN candidates are tried before Internet candidates, and only new flows use a
verified direct path. The direct data plane always uses QUIC Datagram regardless
of whether the authenticated client-server transport uses TCP or QUIC.
The server-owned `network_mode` defaults to native TUN delivery; `loopback` uses
a userspace TCP/IP stack to reach same-port TCP/UDP services bound to `127.0.0.1`.
On Linux use `portwayd vnetwork status|install|repair|uninstall`; Linux clients
expose only the safe `portway vnetwork uninstall` command because their assignment
is server-owned. On macOS the `run` process automatically uses a short-lived
privileged mode of the same binary and manual VNet management commands are unavailable.
On Windows amd64, the official signed `wintun.dll` is bundled only in the Windows
amd64 archive. Start a VNet-enabled `portway` or `portwayd` as administrator;
the temporary adapter is created lazily and removed when its owning process closes it.
Proxy, Forward, and VNet-disabled runs neither load Wintun nor require elevation.
See [VNet configuration and operations](assets/docs/vnetwork/README.md).

| Requirement | Feature | Entry location | Target location | Protocols |
| --- | --- | --- | --- | --- |
| Publish one client service | Standard Proxy | `portwayd` | Client network | TCP, UDP, HTTP, HTTPS |
| Copy public input to multiple clients | Mirror Proxy | `portwayd` | Multiple client networks | TCP, UDP |
| Access a server-side service locally | Forward | `portway` | Server network | TCP, UDP |
| Connect managed virtual nodes | VNet | Any configured node | Server or client node | TCP, UDP |

The table helps choose a mode. For traffic diagrams and complete boundaries, see
[Three connectivity modes](assets/docs/modes/README.md).

## Highlights

**Three controlled connectivity capabilities**

- Proxy client-side TCP and UDP services through public listeners on the server.
- Mirror a governed or managed public TCP/UDP Proxy entry to multiple clients
  without allowing shadow clients to affect visitor responses.
- Route domains over HTTP or HTTPS, with server-side TLS termination, streaming,
  Upgrade support, connection reuse, and atomic certificate reload.
- Forward TCP and UDP from client-side listeners to server-side networks. A
  server-wide allowlist restricts every target by CIDR, protocol, and port.
- Run Proxy and Forward entries together over one authenticated client session.
- Connect Managed VNet clients through automatic QUIC Datagram P2P, with
  uninterrupted server Relay during probing and automatic fallback when direct
  connectivity is unavailable; node-level TCP/UDP policies remain enforced.

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

The first two examples use Shared authentication. Replace
`REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS` with the same cryptographically
generated Token in both files. The Token must contain more than 32 UTF-8
characters. Start `portwayd` before `portway`. The third example uses Managed
authentication, whose identity and configuration are server-owned.

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

### Scenario 3: connect managed nodes through private addresses

Use VNet when nodes in different networks, managed by one server, should reach
each other through stable private addresses, rather than creating a Proxy or
Forward entry for every service. It makes access feel like a VPN: applications
connect directly to a node's private address and port. This example assigns
`172.20.0.1` to the server and `172.20.0.2` to an edge node, exposing only TCP
port `8080` on that node.

First create a Managed client record in the directory named by
`managed_clients_path`, for example `managed/edge-a.yaml`:

```yaml
authentication:
  client_id: edge-a
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_OVER_32_CHARS
configuration:
  revision: 1
  proxies: []
  forwards: []
```

Enable its address and port policy in `server.yaml`:

```yaml
authentication:
  managed_clients_path: ./managed

virtual_network:
  enabled: true
  cidr: 172.20.0.0/16
  server_ip: 172.20.0.1
  server_ports:
    tcp:
      port_ranges:
        - start: 22
          end: 22
  nodes:
    - client_id: edge-a
      ip: 172.20.0.2
      ports:
        tcp:
          port_ranges:
            - start: 8080
              end: 8080
```

Configure the smallest `client.yaml` on the node; its Token must match the
Managed record:

```yaml
transport:
  type: tcp
  server_address: SERVER_IP:7000
authentication:
  client_id: edge-a
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_OVER_32_CHARS
```

After startup, the server can reach `172.20.0.2:8080`, and the node can reach
authorized `172.20.0.1:22`. Client-to-client traffic automatically uses direct
QUIC when probing succeeds and otherwise remains relayed through `portwayd`;
traffic involving the server is never upgraded to P2P. Permit `P+1/UDP` for P2P,
where `P` is the configured transport port. VNet needs TUN privileges on Linux
or macOS and may request operating system authorization on first activation. On
Windows amd64, run the VNet-enabled process as administrator; the release archive
already includes Wintun. For complete configuration, `tun` and
`loopback` delivery, port policies, and management commands, see
[VNet configuration and operations](assets/docs/vnetwork/README.md).

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
must match. HTTP/HTTPS share a hard limit of 4096 public connections. TLS handshakes
are limited to 10 seconds; request headers default to 10 seconds and public keep-alive
idle time to 60 seconds. Request-body and upstream business limits remain disabled
by default and can be configured under `proxies.http`. HTTPS selects certificates by SNI from an atomically
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

**Getting started**

- [Three connectivity modes: Proxy, Forward, and VNet](assets/docs/modes/README.md)
- Fully annotated configuration examples:
  [client](config/client.yaml) and [server](config/server.yaml)
- [Authentication and configuration control](assets/docs/authentication/README.md)
- [Security](assets/docs/security/README.md)

**Optional capabilities**

- [VNet configuration and operations](assets/docs/vnetwork/README.md)
- [TCP and UDP Proxy mirroring](assets/docs/proxy-mirroring/README.md)

**Architecture and operations**

- [Technical overview](assets/docs/technical/README.md)
- [Operations endpoints](assets/docs/operations/README.md)
- [Server configuration reload](assets/docs/reload/README.md)
- [Future plans](assets/docs/future/README.md)

The technical documentation describes stable behavior and security
properties without serving as a complete wire-protocol specification.

## License

Copyright 2026 Acexy.

Portway is licensed under the [Apache License 2.0](LICENSE). See
[NOTICE](NOTICE) for attribution information.
