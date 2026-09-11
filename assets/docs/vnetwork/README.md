# VNet

VNet connects a `portwayd` server and explicitly configured Managed clients by
stable private IPv4 addresses. It supports IPv4 TCP and UDP on Linux and macOS.
Client-to-client packets always pass through the server; VNet is independent of
Proxy and Forward state.

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

Linux server management commands are:

```text
portwayd vnetwork status
portwayd vnetwork install [server.yaml]
portwayd vnetwork repair [server.yaml]
portwayd vnetwork uninstall
```

The Linux client receives its network parameters only after authentication, so it has
no install or repair command. It exposes only `portway vnetwork uninstall`.
Uninstall refuses foreign, drifted, or currently locked resources. On macOS all
of these commands report that VNet is managed automatically during `run`.
