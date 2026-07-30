# Portway Technical Overview

This document gives operators and contributors a concise public overview of
Portway. It describes stable component boundaries and runtime properties, not
the complete wire protocol or internal state machines.

## Architecture

```text
Public TCP/UDP/HTTP traffic
          |
          v
  +-----------------+        TCP or QUIC        +-----------------+
  |    portwayd     | <-----------------------> |     portway     |
  | public server   |    control + data links   | private client  |
  +-----------------+                           +-----------------+
          |                                              |
          | Host/port routing                            | local TCP/UDP/HTTP
          v                                              v
     public users                                  private services
```

Portway separates five responsibilities:

- **Transport** establishes authenticated client-server connections over TCP or
  QUIC.
- **Control plane** owns client identity, proxy registration, heartbeats,
  recovery, and data-link requests.
- **Data plane** carries independent logical streams for proxied traffic.
- **Proxy runtime** maps public TCP/UDP ports or HTTP domains to authenticated
  client registrations.
- **Security controls** validate configuration, authenticate connections, and
  enforce source-address policy.

The proxy layer does not depend on one concrete client-server transport. A
public TCP connection can therefore be carried to the client over either TCP or
QUIC without changing the public protocol or the private service.

## Registration and identity

The server may accept Shared, Governed, and Managed authentication records at
the same time. A client supplies only its Token; the selected server record
determines its mode and authoritative identity. Shared clients use a runtime
ClientID for resource ownership, while Governed and Managed clients receive a
server-owned ClientID bound to their independent Token.

Shared and Governed clients send their complete desired proxy set as one
registration operation. Governed declarations are additionally constrained by
server-owned proxy-type, port, domain, and quota rules. Managed clients receive
their complete proxy configuration from the server and cannot register a
replacement set.

The server validates a complete set before publishing it. If any proxy conflicts
with an existing port, domain, or rule, the complete operation fails and no
partial state becomes visible. See
[Authentication and configuration control](../authentication/README.md) for
mode selection and configuration examples.

Temporary transport loss may recover the authenticated session within a bounded
window. Connection generations prevent stale connections from taking ownership
after a newer connection has been accepted.

## TCP proxy

For every accepted public TCP connection, the server requests a data link from
the owning client. The client connects to the configured local IP and port, then
relays the byte stream in both directions.

Portway preserves TCP stream semantics, including half-close behavior. Public
listeners and active links have explicit owners and cancellation paths.

## HTTP proxy

The server owns one optional public HTTP listener and routes requests by a
validated, canonical domain registration.

HTTP forwarding uses Go's standard HTTP server and reverse-proxy implementation.
Backend connections are reused where possible instead of creating a new tunnel
for every request. Streaming responses and HTTP/1.1 Upgrade connections remain
streamed through the authenticated client link.

The local application receives an ordinary HTTP request. It does not implement
Portway framing, authentication, or session behavior.

## UDP proxy

Public UDP datagrams are grouped by proxy binding and visitor address into
bounded associations. Each association owns one authenticated data link and one
connected local UDP socket, so responses return to the correct visitor.

Datagram boundaries are preserved with bounded binary frames. TCP transport
uses an independent RoleData connection per association, while QUIC transport
uses an independent bidirectional stream. This confines stream head-of-line
blocking to one visitor. Queue saturation drops the newest datagram, and a
bounded write timeout closes only the congested association.

Global, client, proxy, source-IP, pending, creation-rate, datagram-size, queue,
and memory limits are validated against compiled hard boundaries.

## Transport choices

### TCP

TCP transport uses Portway application authentication and an authenticated
encrypted channel. Control and data roles share one listener and are explicitly
validated before entering their respective runtime paths.

### QUIC

QUIC transport uses TLS 1.3 for transport security and Portway Token
authentication for application identity. Multiple Portway streams can share one
QUIC connection while retaining independent logical ownership.

Changing the selected transport does not change registered proxy semantics.

## Reliability model

Portway is designed around:

- parent-child context cancellation;
- deadlines for blocking network operations;
- idempotent resource closure;
- bounded queues, maps, pending links, and concurrency;
- atomic proxy publication;
- explicit permanent and retryable connection errors;
- bounded graceful shutdown and session recovery.

Authentication failures, invalid credentials, certificate validation errors,
and known transport mismatches are treated as permanent client errors instead
of being retried indefinitely.

## Operational boundaries

Portway is currently optimized for a single operator-managed server rather than
a distributed multi-tenant control plane. High availability, shared cluster
state, a web dashboard, and dynamic plugins are outside the current scope.

Application-layer controls complement but do not replace operating-system,
cloud, or upstream network policy.
