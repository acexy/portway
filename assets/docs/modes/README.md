# Proxy and Forward modes

Portway provides two complementary traffic modes over the same authenticated
client-server tunnel. Proxy publishes a service reachable by `portway`; Forward
provides local access to an approved service reachable by `portwayd`.

## Traffic directions

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
port; HTTP/HTTPS proxies use a domain. The client declares the local destination
through the nested `local` endpoint.

```yaml
proxies:
  - name: ssh
    type: tcp
    local: {ip: 127.0.0.1, port: 22}
    public: {port: 22022}
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
    listen: {ip: 127.0.0.1, port: 15432}
    target: {ip: 10.20.1.15, port: 5432}
```

Use Forward for administration, databases, DNS, or other services that should
remain private on the server network while being available through a local
client port.

## Forward security boundary

Forward is disabled when `server.yaml` omits `forwards` or sets `enabled: false`.
When the section is present, it must contain explicit IP/CIDR and TCP/UDP port
rules. Enabling it makes those rules the global allowlist:

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

## Choosing a mode

| Requirement | Mode | Listener owner | Destination |
| --- | --- | --- | --- |
| Publish a private client service | Proxy | `portwayd` | Client network |
| Reach a protected server-side service locally | Forward | `portway` | Server network |

Both modes can coexist in one Shared or Governed client configuration, use TCP
or QUIC as the underlying transport, and retain their application protocol
semantics across the tunnel.
