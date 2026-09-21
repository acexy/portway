# Choose a connectivity mode

Portway provides three independent connectivity modes. Choose them by where the
entry point and destination live; a deployment may use more than one mode.

| Need | Mode | Entry point | Destination |
| --- | --- | --- | --- |
| Publish one private service | [Proxy](../proxy/README.md) | Public `portwayd` port or domain | Service reachable from `portway` |
| Copy public TCP/UDP input to controlled consumers | [Mirror Proxy](../proxy/README.md#mirror-proxy) | Public `portwayd` port | Several client services; one Primary replies |
| Use a remote private service through a local port | [Forward](../forward/README.md) | Local `portway` listener | Approved service reachable from `portwayd` |
| Connect managed nodes by stable private IPv4 address | [VNet](../vnetwork/README.md) | Virtual address on each node | Server or Managed client |

The detailed documents describe use cases, packet flow, configuration, security
boundaries, and operational considerations for each mode:

- [Proxy: publish client-side services](../proxy/README.md)
- [Forward: reach server-side networks](../forward/README.md)
- [VNet: connect managed nodes](../vnetwork/README.md)
