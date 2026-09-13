# Three connectivity modes: Proxy, Forward, and VNet

Portway provides three modes for different network boundaries. Proxy publishes
services reachable by `portway`; Forward provides local access to approved
services reachable by `portwayd`; VNet places the server and explicitly
configured Managed nodes across networks in a mutually reachable private IPv4
cluster governed by port policy.

## Modes and traffic directions

### Proxy: publish a client-side service

```text
Public visitor
      |
      v
portwayd public listener
      |
      | authenticated tunnel
      v
portway client
      |
      v
Client-side local service
```

The listener belongs to `portwayd`. TCP and UDP proxies use a public server
port; HTTP/HTTPS proxies use a domain. A Standard Proxy maps the entry to one
client service. A governed or managed TCP/UDP
[Mirror Proxy](../proxy-mirroring/README.md) copies the same visitor input to
multiple configured clients while allowing only one Primary to reply. The
client declares its local destination through the nested `local` endpoint.

```yaml
proxies:
  - name: ssh
    type: tcp
    local:
      ip: 127.0.0.1
      port: 22
    public:
      port: 22022
```

Use Proxy when an application on the client network must be reachable through
the Portway server.

### Forward: access a server-side service locally

```text
Local visitor
      |
      v
portway client listener
      |
      | authenticated tunnel
      v
portwayd
      |
      v
Approved server-side target
```

The listener belongs to `portway`. Forward supports TCP and UDP and preserves
their byte-stream or datagram semantics. The client listener is configured with
`listen`; `target` identifies the service
reachable from the server.

```yaml
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

Use Forward for administration, databases, DNS, or other services that should
remain private on the server network while being available through a local
client port.

## Forward security boundary

Forward is disabled when `server.yaml` omits `forwards` or sets `enabled: false`.
When the section is present, it must contain explicit IP/CIDR and TCP/UDP port
rules. Client declarations remain dormant while disabled, so clients stay
online without Forward listeners and automatically restore authorized listeners
when the feature is enabled again. Enabling it makes those rules the global allowlist:

```yaml
forwards:
  enabled: true
  rules:
    - ip_range: 10.20.0.0/16
      tcp:
        port_ranges:
          - start: 5432
            end: 5432
```

Shared, Governed, and Managed clients cannot bypass this boundary. Governed and
Managed records may narrow it further. Targets are explicit IP addresses rather
than hostnames, and every new link is authorized against the current policy.

All server-side Forward settings and permissions support fail-closed hot reload.
Invalid candidates retain the previous snapshot; affected connections close
automatically after a successful policy change. The client does not reload its
local YAML, so Shared or Governed listener changes require a client restart.

Proxy and Forward can coexist in one Shared or Governed client configuration and use TCP
or QUIC as the underlying transport, and retain their application protocol
semantics across the tunnel.

Forward listeners are created after server approval and closed when the client
control session ends; recovery creates new listeners. If local startup fails,
Shared/Governed clients close their prepared listeners, notify the server on a
best-effort basis, and exit. Ordinary TCP Proxy and Forward preserve normal
half-close without a fixed response-drain timeout; I/O errors and session
cancellation close both directions. Mirror TCP retains its separate drain policy.

### VNet: connect managed nodes through stable private addresses

```text
Server or VNet client
          |
          | Private IPv4 TCP / UDP
          v
  Central routing at portwayd
          |
          v
Another authorized VNet node
```

VNet has neither a public entry nor a client-local forwarding listener. The
server assigns stable private IPv4 addresses to itself and each Managed client,
then decides delivery using the destination node's TCP/UDP inbound allowlist.
Client-to-client traffic is always relayed through `portwayd`. It gives fixed
nodes in different networks a VPN-like private-access experience and suits
management, service discovery, and internal service access. It currently does
not carry arbitrary IP protocols, broadcast, or general Internet egress.

Only the server configures `virtual_network`, and only Managed clients can join.
VNet uses TUN network resources on Linux or macOS. `network_mode: tun` delivers
traffic to services on the virtual IP, while `loopback` delivers authorized
traffic to the same port on `127.0.0.1`. See [VNet configuration and
operations](../vnetwork/README.md) for configuration, operations, and security
boundaries.

## Choosing a mode

| Need | Mode | Entry or address owner | Target location |
| --- | --- | --- | --- |
| Publish a private client service to visitors | Proxy | Public `portwayd` listener | Client network |
| Use a server-side service locally on the client | Forward | Local `portway` listener | Server network |
| Privately connect centrally managed nodes | VNet | Server-assigned private IPv4 addresses | Server or Managed client |
