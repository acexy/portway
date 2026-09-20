# VNet

VNet connects a `portwayd` server and explicitly configured Managed clients in
different networks by stable private IPv4 addresses. It supports IPv4 TCP and
UDP on Linux, macOS, and Windows amd64. It gives fixed nodes a VPN-like private cluster and
access experience: applications use the destination's private address and port.
Client-to-client traffic starts on the server relay and automatically uses a
QUIC Datagram direct path for new flows after successful probing. Traffic involving
the server always remains relayed. VNet is
independent of Proxy and Forward state.

This mutual access is bounded by destination port policy rather than being
unrestricted network access: each node receives only the TCP/UDP ports explicitly
allowed by its `ports` value. VNet currently provides neither arbitrary IP
protocols, broadcast, nor Internet egress.

## When to use VNet

VNet is suited to a fixed, operator-managed set of servers, workstations, and
edge nodes that should communicate by stable private address. Typical uses are
cross-network administration, service discovery, internal service-to-service
access, and direct client-to-client traffic when network conditions permit.

VNet is not a general remote-access VPN for arbitrary users or Internet egress.
Only explicitly configured Managed clients join, and every destination continues
to enforce its TCP/UDP inbound port policy. Use [Proxy](../proxy/README.md) for a
stable public service entry, or [Forward](../forward/README.md) for narrowly
scoped local access to a server-side target.

## Network architecture and packet flow

```text
Application on node A
        |
        v
portway0 / utunN / Wintun, or loopback userspace stack
        |
        v
source-address validation + destination port policy
        |
        +---- Relay packet channels ----> portwayd ----+
        |                                              |
        +---- authenticated QUIC Datagram P2P ---------+
                                                       v
                                           VNet endpoint on node B
                                                       |
                                                       v
                                                local application
```

The server assigns each Managed client its address, MTU, packet-channel count,
and policy. In `tun` mode, complete IPv4 TCP/UDP packets enter through the
platform device; in `loopback` mode, Portway terminates authorized traffic in a
userspace TCP/IP stack. The server validates source ownership and destination
policy before Relay routing. Client pairs probe in parallel, and only new flows
select P2P after both sides authenticate the direct path. Uncertain packets are
never replayed during fallback.

## Automatic QUIC P2P

P2P is automatic whenever VNet is enabled and has no separate configuration
switch. The first flow between two clients remains on Relay while `portwayd`
coordinates bounded connectivity checks. LAN host candidates are tried first,
then Internet server-reflexive candidates. After both peers authenticate a QUIC
path, only new flows use QUIC Datagram directly; established Relay flows are not
migrated. A failed probe or direct path keeps or returns traffic to Relay without
disabling VNet, Proxy, or Forward. Traffic involving the server never attempts P2P.

P2P always uses an independent QUIC Datagram connection, regardless of whether
the configured client-server transport is TCP or QUIC. Peer traffic remains
subject to the destination node's TCP/UDP allowlist and authenticated virtual
address. The server coordinates identity, policy, activation, and revocation but
does not relay packets once a direct flow is active.

Both `portwayd` and each participating `portway` exclusively bind UDP port `P+1`,
where `P` is the configured transport port. Permit both the transport port and
`P+1/UDP` through the firewall. A local bind conflict is fatal; NAT, CGNAT, or
firewall traversal failure only keeps Relay active.

```text
Relay
  └─ Probing
       ├─ LAN QUIC Direct
       ├─ Internet QUIC Direct
       └─ Relay fallback
```

## Configuration

### Transport recommendation

VNet works with either TCP or QUIC as the authenticated client-server transport.
QUIC is recommended when UDP is available because its independent streams fit
VNet's parallel packet channels and avoid TCP connection-level head-of-line
blocking during loss. QUIC also provides TLS 1.3 server identity verification.
Use TCP when UDP transport is unavailable or consistently blocked.

The transport choice does not control client-to-client P2P: direct VNet traffic
always uses a separate QUIC Datagram connection. A deployment therefore still
needs `P+1/UDP` for P2P even when its main transport is TCP.

```yaml
# server.yaml
transport:
  type: quic
  listen_address: 0.0.0.0:7000
  quic:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
```

```yaml
# client.yaml
transport:
  type: quic
  server_address: SERVER_IP:7000
  quic:
    server_name: gateway.example.com
    ca_file: ./certs/root-ca.crt
```

`server_name` must match a DNS or IP SAN in the server certificate. Run
`portwayd gen cert` for a private CA deployment and protect both private keys.

### VNet policy

Configure VNet only on the server. Each endpoint's `ports` value is the inbound
TCP/UDP allowlist for that endpoint:

```yaml
virtual_network:
  enabled: true
  network_mode: tun
  cidr: 172.20.0.0/16
  server_ip: 172.20.0.1
  packet_channels: 4
  server_ports:
    tcp:
      port_ranges:
        - start: 22
          end: 22
    udp:
      port_ranges: []
  nodes:
    - client_id: managed-a
      ip: 172.20.0.2
      ports:
        tcp:
          port_ranges:
            - start: 8080
              end: 8080
        udp:
          port_ranges: []
```

The referenced ClientID must exist in `managed_clients_path`. `packet_channels`
defaults to 4 and accepts 1 through 8 for both TCP and QUIC transport.

`network_mode` defaults to `tun`. In this mode an application must listen on the
machine's virtual IP or a wildcard address that covers it. With `loopback`,
Portway terminates authorized inbound TCP/UDP in its userspace stack and connects
to the same port on `127.0.0.1`. The server owns
this setting, clients follow the assignment, and changing it requires restart.

## Platform privileges and lifecycle

On first activation Portway invokes the operating system's `sudo` mechanism when
privileges are needed; Portway never reads or stores the password. Linux uses a
persistent `portway0` TUN and supports the management commands below. On macOS,
`run` automatically launches a short-lived privileged mode of the same binary,
receives its process-owned `utunN` descriptor, and remains unprivileged. macOS
does not support manual `vnetwork` commands; the interface and route are removed
by the operating system when the owning process closes the descriptor.

The Windows amd64 release archive bundles the official signed `wintun.dll`; it
is not a separate installer. Commands that may need Windows VNet privileges
request administrator authorization through UAC and continue in a relaunched
elevated process after approval. Because a client learns whether VNet is enabled
only after authentication, `portway run` requests authorization before startup;
`portwayd run` does so only when `virtual_network.enabled` is true. Portway loads
Wintun and creates its temporary `portway0` adapter only when VNet is actually
activated, then removes the adapter when the owning process closes it. Windows
provides read-only `vnetwork status` and `vnetwork uninstall` for safely
inspecting or removing an owned adapter left
outside the normal process lifecycle. Windows arm64 and other Windows
architectures are not supported.

Linux server management commands are:

```text
portwayd vnetwork status
portwayd vnetwork install [server.yaml]
portwayd vnetwork repair [server.yaml]
portwayd vnetwork uninstall
```

Each command reports its result to the invoking terminal: `status` prints the
network fields, successful `install` and `repair` print `Installed` and
`Repaired`, and `uninstall` prints its stable removal result. Windows UAC
operations relay their result back to the original terminal, including when
output is redirected.

The Linux client receives its network parameters only after authentication, so it has
no install or repair command. It exposes only `portway vnetwork uninstall`.
Uninstall removes the single `portway0` network by name but refuses a network
currently locked by Portway. On Windows
amd64, both executables expose `vnetwork status` and `vnetwork uninstall`.
Status is read-only and does not request UAC; uninstall requests authorization
when necessary and refuses removal while a Portway process owns the network.
Live Windows address changes migrate the existing Adapter in place; a stale
same-named Adapter is replaced before startup. On macOS, `vnetwork` is omitted from
command help because VNet is managed automatically during `run`.

## Security and operational considerations

- Allow the configured transport port and `P+1/UDP` in host, cloud, and upstream
  firewalls. Failed traversal retains Relay; failure to bind the local P2P port
  prevents VNet startup.
- Linux and macOS `tun` mode needs privileged network setup. macOS uses a
  short-lived `sudo` helper and may require an interactive password when no sudo
  authorization is cached. A detached process cannot prompt after startup.
- Windows amd64 requests UAC for a VNet-enabled process. Other Windows
  architectures are not supported.
- Choose a CIDR that does not overlap LANs, cloud routes, container networks, or
  another VPN. Portway rejects detected conflicts instead of replacing foreign routes.
- In `tun` mode, bind applications to the virtual address or an appropriate
  wildcard. Use `loopback` only for intentional same-port delivery to `127.0.0.1`.
- Keep inbound port ranges narrow. VNet complements rather than replaces host
  firewalls and application credentials.
- Prefer QUIC transport where UDP is reliable, while remembering that P2P and
  the main transport use different sockets and certificate boundaries.

See the annotated [server configuration](../../../config/server.yaml),
[Managed client record](../../../config/managed/managed-client.yaml), and
[Security](../security/README.md) for complete deployment guidance.

## Reliability and capacity

VNet recovers channels and direct paths within a single-server deployment; it
has no replicated server state or seamless server failover. Applications must
allow reconnection after a server restart. TCP flow authorization expires after
five minutes without packet activity; use application or TCP keepalives below
that interval for idle long-lived connections. Unknown TCP ACKs cannot recreate
expired authorization. Loopback TCP expiry closes both proxy connections and
releases their capacity. UDP flow authorization expires after one idle minute.

Each node pair shares a limit of 1024 flows and a new-flow budget of 128 per
second with a burst of 256. Existing flows and replies do not consume new-flow
rate tokens. These limits supplement the existing node and global budgets;
capacity or rate rejection drops new traffic without rebuilding packet channels.
They are resource safeguards, not throughput guarantees.

Peer coordination uses separate bounded queues per control session. If a
security notice cannot be delivered within five seconds of enqueueing, or its
queue fills, the affected control connection closes to revoke stale direct-path
authority. Other sessions continue; applications on that node may reconnect.
Failed peer pairs release their quota after the retry delay. Periodic
`vnet_statistics` logs report flow occupancy, capacity/rate rejections, peer
state, loopback connection usage, direct-path failure fallbacks, client pool
failures, write timeouts, and the latest pool recovery duration without packet
contents or credentials.

Ordinary control-session reconnection keeps the P2P UDP socket and its QUIC
transport bound to the same local port. It closes old direct connections and
replaces session credentials, peer state, and registration before probing again.
Virtual-IP or MTU changes also reuse the socket. Disabling VNet, removing the
node, revoking P2P capability, or stopping the client releases the binding;
a changed bind port or a failed socket requires a new binding. Retaining the
socket does not retain authorization from the old control session.
