# Forward: reach server-side networks

Forward creates a local TCP or UDP listener on `portway` and carries its traffic
through the authenticated tunnel to an explicitly authorized IP and port
reachable from `portwayd`. The destination stays private: it does not need a
public listener and does not accept connections directly from the client network.

## When to use Forward

Forward is suited to:

- accessing a private database through a local loopback port;
- reaching a server-network administration or monitoring endpoint;
- using an internal DNS, directory, or infrastructure service;
- granting narrowly scoped access to one protocol and port without joining a
  broad private network.

Use [Proxy](../proxy/README.md) when visitors enter through a server public port
or domain and the service is beside the client. Use [VNet](../vnetwork/README.md)
when Managed nodes should communicate by stable private addresses.

## Network flow

```text
Local application
       |
       v
portway local TCP/UDP listener
       |
       | authenticated Data Link over TCP or QUIC transport
       v
portwayd policy check
       |
       v
approved server-side IP:port
```

1. The client declares its complete Forward set, or receives it through a
   Managed record.
2. The server checks every target against the global Forward allowlist and any
   narrower client permission.
3. Only after approval does `portway` create the local listener.
4. Each connection or UDP association receives an authenticated Data Link.
5. `portwayd` connects or sends to the configured target after checking the
   current policy again.

TCP preserves full-duplex byte streams and half-close. UDP preserves datagram
boundaries and isolates source associations. Forward works over either TCP or
QUIC client-server transport without changing these application semantics.

## Configuration

Forward is disabled by default. The server must enable it and define a global
allowlist. This example permits only PostgreSQL on `10.20.1.0/24`:

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

The client exposes that database only on its loopback address:

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

The application connects to `127.0.0.1:15432`; `portwayd` connects to
`10.20.1.15:5432`. UDP uses the same shape with `type: udp` and a matching UDP
server rule.

Targets must be canonical IP addresses rather than hostnames. This keeps policy
evaluation independent from mutable DNS resolution. A target must match one
complete rule; Portway does not combine a CIDR from one rule with a port range
from another.

## Authorization models

- **Shared:** the client chooses its Forward declarations, but every target must
  remain inside the global server allowlist.
- **Governed:** the global allowlist applies first, and the client's own server
  record may narrow destination CIDRs, protocols, ports, and limits further.
- **Managed:** the server owns the complete Forward set; the client cannot
  replace it with local declarations.

Disabling Forward keeps clients online but removes their local Forward listeners.
Re-enabling it restores declarations that remain authorized. A successful
server policy reload closes affected active links and listeners; an invalid
candidate keeps the previous policy active.

## Security and operational considerations

- Bind `listen.ip` to `127.0.0.1` unless other machines intentionally need the
  local entry. Binding `0.0.0.0` can turn the client into a network gateway.
- Keep the global allowlist narrow. Avoid granting an entire private CIDR when
  only one service port is required.
- The target is reached from the `portwayd` host, so its routing, DNS-independent
  IP reachability, host firewall, and return path must permit the connection.
- Forward is not a general-purpose SOCKS or HTTP proxy and does not accept a
  destination supplied dynamically by the local application.
- Client YAML is read at process startup. Shared or Governed Forward declaration
  changes require a client restart; server policy supports fail-closed reload.
- If local listener creation fails, Shared and Governed clients close the batch,
  report failure on a best-effort basis, and exit instead of running partially.
- No TUN device or administrator privilege is required for Forward itself.

See [Authentication and configuration control](../authentication/README.md) for
permission records, and the annotated [client](../../../config/client.yaml) and
[server](../../../config/server.yaml) templates for all fields and limits.
