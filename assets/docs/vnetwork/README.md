# VNet

VNet connects a `portwayd` server and explicitly configured Governed clients by
stable private IPv4 addresses. It supports IPv4 TCP and UDP on Linux and macOS.
Client-to-client packets always pass through the server; VNet is independent of
Proxy and Forward state.

Configure VNet only on the server. Each endpoint's `ports` value is the inbound
TCP/UDP allowlist for that endpoint:

```yaml
virtual_network:
  enabled: true
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
    - client_id: governed-a
      ip: 172.20.0.2
      ports:
        tcp:
          port_ranges:
            - start: 8080
              end: 8080
        udp:
          port_ranges: []
```

The referenced ClientID must exist in `governed_clients_path`. `packet_channels`
defaults to 4 and accepts 1 through 8 for both TCP and QUIC transport.

On first activation Portway invokes the operating system's `sudo` mechanism when
privileges are needed; Portway never reads or stores the password. Linux uses a
persistent `portway0` TUN. macOS uses a process-owned `utunN`, represented as the
logical network `portway0`. Normal process exit preserves the ownership record
and does not uninstall system state.

Server management commands are:

```text
portwayd vnetwork status
portwayd vnetwork install [server.yaml]
portwayd vnetwork repair [server.yaml]
portwayd vnetwork uninstall
```

The client receives its network parameters only after authentication, so it has
no install or repair command. It exposes only `portway vnetwork uninstall`.
Uninstall refuses foreign, drifted, or currently locked resources.
