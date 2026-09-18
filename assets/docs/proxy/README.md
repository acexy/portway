# Proxy: publish client-side services

Proxy makes a service reachable from a `portway` client available through a
stable public or centrally reachable entry on `portwayd`. The service itself
may remain on a home LAN, development machine, private cloud, or edge site
without accepting an inbound connection from the public network.

Proxy supports TCP and UDP public ports, plus domain-routed HTTP and HTTPS.
TCP/UDP Proxy also has a controlled Mirror variant for one-to-many delivery.

## When to use Proxy

Use Proxy when:

- SSH, a web application, DNS, telemetry, or another service is behind NAT;
- a service has no stable public address but needs a stable server entry;
- public TLS should terminate centrally at `portwayd`;
- several authorized consumers must observe identical TCP/UDP input.

Use [Forward](../forward/README.md) instead when the desired entry is local to
the client and the destination is reachable from the server. Use
[VNet](../vnetwork/README.md) when managed nodes should communicate by stable
private addresses rather than one explicitly published service at a time.

## Network flow

```text
                       authenticated TCP or QUIC transport
Public visitor      +-----------------------------------------+
      |              |                                         |
      v              v                                         v
portwayd public listener -> authorized Proxy -> Data Link -> portway
                                                                  |
                                                                  v
                                                     client-side service
```

1. The client authenticates and registers its complete Proxy set, or receives
   the set from a Managed server record.
2. `portwayd` validates ownership and conflicts before publishing the listener
   or domain route atomically.
3. A visitor connects to the server port or sends an HTTP request to the domain.
4. The server requests an authenticated Data Link from the owning client.
5. The client connects to the configured local IP and port and relays traffic.

TCP keeps byte-stream and half-close semantics. UDP keeps datagram boundaries
and isolates visitors with bounded associations. HTTP preserves request,
streaming response, and Upgrade behavior; public HTTPS terminates TLS on
`portwayd`, while the client-side origin receives HTTP.

## Standard Proxy configuration

The smallest Shared-authentication server only needs a transport listener and
the same high-entropy Token used by the client:

```yaml
transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  shared_token: REPLACE_WITH_SAME_RANDOM_TOKEN_OVER_32_CHARS
```

The client publishes local SSH and UDP DNS:

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

  - name: dns
    type: udp
    local:
      ip: 127.0.0.1
      port: 53
    public:
      port: 5353
```

Visitors reach these services at `SERVER_IP:22022/TCP` and
`SERVER_IP:5353/UDP`. The local target may be another canonical IP reachable
from the client; hostnames are not accepted.

## HTTP and HTTPS

Enable the public listener on the server. HTTPS additionally requires an SNI
certificate mapping; its certificate is independent from a QUIC transport
certificate.

```yaml
proxies:
  http:
    listen_address: 0.0.0.0:80
  https:
    listen_address: 0.0.0.0:443
    certificates:
      - domains:
          - app.example.com
        cert_file: /path/to/app.example.com.crt
        key_file: /path/to/app.example.com.key
```

Register the domain on the client:

```yaml
proxies:
  - name: web
    type: http
    local:
      ip: 127.0.0.1
      port: 8080
    public:
      schemes:
        - http
        - https
      domain: app.example.com
```

DNS must point the domain to `portwayd`. For HTTPS, SNI and HTTP `Host` must
match. The local service speaks HTTP; Portway currently does not provide HTTPS
origin forwarding, TLS passthrough, ACME, or HTTP/3.

## Mirror Proxy

Mirror Proxy copies the same TCP bytes or UDP datagrams to multiple Governed or
Managed clients. Only `primary_client_id` may reply; other responses are drained
and discarded.

```text
                              +-> Primary client -> primary service --+
Visitor -> portwayd TCP/UDP --+                                      +-> Visitor
                              +-> Mirror client  -> shadow service --X
                              +-> Mirror client  -> observer -------X
```

This is useful for traffic observation, auditing, protocol analysis, parallel
processing, and validating a replacement service with live input. It is not a
load balancer: visitors are not distributed, responses are not aggregated, and
no replacement Primary is elected.

Mirror groups are server-owned and require Governed or Managed identities:

```yaml
proxies:
  mirror:
    governed:
      - name: telemetry
        type: tcp
        public:
          port_ranges:
            - start: 2233
              end: 2233
        primary_client_id: governed-primary
        client_ids:
          - governed-primary
          - governed-observer
```

Each member still needs matching permission and a Proxy with the same public
port. A member joining an active TCP flow may start at an arbitrary byte offset;
prior input is never replayed. See [TCP and UDP Proxy mirroring](../proxy-mirroring/README.md)
for complete membership, recovery, and reload behavior.

## Security and operational considerations

- Public Proxy ports and domains are Internet-facing unless restricted by an
  upstream firewall or reverse proxy. Secure the application itself as needed.
- Bind `proxies.bind_ip` to the intended interface and use the source-IP deny
  list as an application control, not as a replacement for a firewall.
- Shared clients choose declarations directly. Governed clients are constrained
  by server permissions; Managed declarations are fully server-owned.
- TCP and QUIC transport preserve the same Proxy semantics. QUIC requires a
  valid server TLS identity in addition to Portway Token authentication.
- Public ports and domains must be unique. A conflicting complete registration
  is rejected atomically rather than partially applied.
- Mirror traffic and Data Link consumption grow with the number of online
  members. Size bandwidth, connection limits, and queues accordingly.

See the annotated [client](../../../config/client.yaml) and
[server](../../../config/server.yaml) templates for all limits and defaults.
