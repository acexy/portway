# Installation and quick start

This guide covers installation, commands, configuration-file conventions, and basic setup for
Proxy, Forward, VNet, and QUIC transport. See the annotated
[client configuration](../../../config/client.yaml) and
[server configuration](../../../config/server.yaml) for every field and default.

## Install

On macOS and Linux, install from the [Acexy Homebrew Tap](https://github.com/acexy/homebrew-tap):

```bash
brew install acexy/tap/portway
brew install acexy/tap/portwayd
```

The client and server may be installed on the same host. Formulae do not create or overwrite
configuration files. Release archives are also available from GitHub Releases. Windows amd64
archives include the officially signed `wintun.dll` required by VNet.

## Commands and configuration files

Common commands are:

```text
portway run [config]
portway gen config [full]
portway version

portwayd run [config]
portwayd gen config [full]
portwayd gen cert [options]
portwayd version
```

`gen config` creates a minimal `client.yaml` or `server.yaml` in the current directory. Add
`full` for a fully annotated template. Existing files are never overwritten. Without an explicit
path, `portway run` reads `client.yaml` and `portwayd run` reads `server.yaml` from the current directory.

The following examples use a shared token. Use the same cryptographically secure random token of
more than 32 UTF-8 characters on both sides, and never commit real credentials.

## Proxy: publish a client-side service

Server configuration:

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

The client publishes local SSH on TCP port `22022` at the server:

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

Run `portwayd run server.yaml`, then `portway run client.yaml`. Visitors can now connect to
`SERVER_IP:22022`. UDP uses the same structure with `type: udp`; Portway preserves datagram boundaries.

HTTP and HTTPS proxies use `public.domain` and `public.schemes` to select server entry points.
HTTPS terminates TLS at `portwayd` and uses HTTP over the authenticated tunnel to the origin.
See the complete server template for listeners, certificates, timeouts, and capacity settings,
and the [technical overview](../technical/README.md) for behavior.

For controlled one-to-many delivery, Mirror Proxy copies the same public TCP or UDP input to
several Governed or Managed clients while allowing only one configured Primary to reply. It is
useful for observation, auditing, parallel processing, and shadow validation, but it is not a
load balancer. See [TCP and UDP Proxy mirroring](../proxy-mirroring/README.md).

## Forward: reach the server-side network

Forward is disabled by default. The server must enable it and constrain the allowed destination
networks, protocols, and ports:

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

The client creates a local loopback entry point:

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

After starting both sides, local applications reach the database at `127.0.0.1:15432`. Bind the
entry point to loopback unless other hosts genuinely need access. Targets use explicit IP addresses,
and every connection is authorized against current server policy. See
[Forward: reach server-side networks](../forward/README.md) for the complete boundary.

## VNet: VPN-like private networking

VNet assigns stable private IPv4 addresses to the server and Managed clients, providing a
VPN-like node-to-node experience. It is not an unrestricted network: each destination node's
TCP and UDP inbound port policy remains the access boundary.

Create a Managed client record under `managed_clients_path`, then configure addresses and policies
on the server:

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

Managed clients only provide identity, token, and transport settings that match their server-side
record; the server supplies VNet parameters. Client-to-client traffic starts on the relay. New flows
automatically use a QUIC Datagram direct path after successful probing and remain relayed when a
direct path is unavailable. Traffic involving the server always stays relayed.

VNet supports Linux, macOS, and Windows amd64 and needs the corresponding TUN or Wintun permissions.
P2P also requires `P+1/UDP`, where `P` is the transport port. See
[VNet configuration and operations](../vnetwork/README.md) for complete Managed records,
`tun` and `loopback` modes, and platform commands.

## Use QUIC transport

TCP and QUIC transport do not change Proxy, Forward, or VNet semantics. In addition to Portway
token authentication, QUIC requires the client to validate the server TLS certificate.

For a private deployment, generate an internal CA and server certificate:

```bash
portwayd gen cert --server-name gateway.example.com --ip 10.0.0.10
```

Configure the certificate and key on the server:

```yaml
transport:
  type: quic
  listen_address: 0.0.0.0:7000
  quic:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
```

Configure the matching identity and root CA on the client:

```yaml
transport:
  type: quic
  server_address: 10.0.0.10:7000
  quic:
    server_name: gateway.example.com
    ca_file: ./certs/root-ca.crt
```

`server_name` must match a certificate SAN. Protect `root-ca.key` and `server.key`, and distribute
only `root-ca.crt` to clients. See [Security](../security/README.md) for additional requirements.

## Next steps

- Choose a configuration-control model: [Authentication and configuration control](../authentication/README.md)
- Publish client-side services: [Proxy](../proxy/README.md)
- Reach server-side networks: [Forward](../forward/README.md)
- Connect managed nodes: [VNet](../vnetwork/README.md)
- Copy public TCP/UDP input safely: [TCP and UDP Proxy mirroring](../proxy-mirroring/README.md)
- Configure monitoring and probes: [Operational endpoints](../operations/README.md)
- Understand reload scope: [Server configuration reload](../reload/README.md)
