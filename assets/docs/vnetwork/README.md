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
