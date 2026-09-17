<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
A lightweight, secure way to publish private services, reach remote networks, and connect managed nodes.
</p>

Portway creates authenticated, encrypted connections between the `portway` client and the
`portwayd` server. It is designed for services behind NAT, without a stable public address, or
that should not expose ports directly.

```text
Private network / edge node  <-- authenticated tunnel -->  Public or central node
           portway                                           portwayd
```

## What you can do

### Publish a private service

Make SSH, web applications, DNS, game servers, or other services on a home network,
development machine, or edge node available through a reachable `portwayd` host.

```text
Visitor -> portwayd public port or domain -> portway -> private service
```

This is **Proxy** mode. It supports TCP, UDP, HTTP, and HTTPS. TCP and UDP proxies can also
mirror the same input to multiple clients for observation, auditing, and shadow validation.

### Reach a remote private network

Open a local port for a database, management endpoint, internal DNS server, or another service
that only the `portwayd` network can reach, without exposing that service publicly.

```text
Local application -> portway local port -> portwayd -> approved private target
```

This is **Forward** mode. It supports TCP and UDP. Server-side IP, protocol, and port rules
limit which targets a client may access.

### Get a VPN-like private-network experience

Assign stable private IPv4 addresses to servers, workstations, and edge nodes across different
networks so applications can reach managed nodes directly by private address, much like a VPN.

```text
Managed node A -> private address -> portwayd relay / automatic QUIC P2P -> managed node B
```

This is **VNet** mode. It provides a VPN-like private-network experience: clients automatically
try a QUIC Datagram direct path and continue through the server relay when direct connectivity
is unavailable. Unlike an unrestricted layer 2 or layer 3 VPN, each destination node still
controls inbound access with TCP and UDP port policies.

| Your goal | Choose | Entry point | Target |
| --- | --- | --- | --- |
| Publish a client-side service | Proxy | `portwayd` | Client network |
| Use a server-side private service locally | Forward | `portway` | Server network |
| Get controlled, VPN-like private networking | VNet | Node private address | Server or managed client |

## Why Portway

- **Clear responsibilities:** use Proxy, Forward, and VNet independently or combine them.
- **Secure by default:** every connection requires token authentication and encryption, with no plaintext downgrade.
- **Protocol fidelity:** preserves TCP streams and half-close, UDP datagram boundaries, and HTTP semantics.
- **Flexible transport:** use TCP or QUIC between the client and server.
- **Controlled access:** supports Shared, Governed, and Managed configuration models, source-IP
  deny lists, and server hot reload.
- **Bounded operation:** resources, queues, and recovery windows are bounded, and configurations
  are published atomically as complete sets.

## Try it in five minutes

The following example publishes SSH from the client host at `SERVER_IP:22022`.

Create `server.yaml` on the server:

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

Create `client.yaml` on the client:

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

Replace the example token with the same cryptographically secure random value on both sides.
Start the server, then the client:

```bash
portwayd run server.yaml
portway run client.yaml
```

The client's SSH service is now available at `SERVER_IP:22022`.

See [Installation and quick start](assets/docs/getting-started/README.md) for Forward, VNet,
HTTP/HTTPS, UDP, and QUIC setup. The fully annotated templates are the
[client configuration](config/client.yaml) and [server configuration](config/server.yaml).

## Install

On macOS and Linux, install the client and server separately from the
[Acexy Homebrew Tap](https://github.com/acexy/homebrew-tap):

```bash
brew install acexy/tap/portway
brew install acexy/tap/portwayd
```

Release archives for supported platforms are also available from GitHub Releases. Windows amd64
archives include the officially signed Wintun component required by VNet.

## Documentation

**Get started**

- [Installation, commands, and quick start](assets/docs/getting-started/README.md)
- [The three connectivity modes: Proxy, Forward, and VNet](assets/docs/modes/README.md)
- [Complete client configuration](config/client.yaml) and [complete server configuration](config/server.yaml)

**Features and security**

- [Authentication and configuration control](assets/docs/authentication/README.md)
- [VNet configuration and operations](assets/docs/vnetwork/README.md)
- [TCP and UDP proxy mirroring](assets/docs/proxy-mirroring/README.md)
- [Security](assets/docs/security/README.md)

**Architecture and operations**

- [Technical overview](assets/docs/technical/README.md)
- [Operational endpoints](assets/docs/operations/README.md)
- [Server configuration reload](assets/docs/reload/README.md)
- [Future](assets/docs/future/README.md)

## License

Copyright 2026 Acexy.

Portway is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
