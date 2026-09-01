# TCP and UDP Proxy mirroring

Proxy mirroring is a controlled variant of Proxy mode. One logical group of
public TCP or UDP ports on `portwayd` accepts visitor traffic and copies the
same input to multiple configured `portway` clients.

It is not a load balancer and does not distribute visitors among members. It is
also unrelated to Forward mode: the public listener remains on `portwayd`, and
the destinations remain services reachable from the clients.

## Why use it

Typical uses include:

- feeding the same telemetry or event stream to multiple processors;
- observing production traffic without allowing an observer to affect replies;
- validating a replacement service against live input before migration;
- running protocol analysis, auditing, or intrusion detection in parallel;
- comparing implementations while keeping one authoritative responder.

Mirror Proxy should not be used when every backend must independently serve a
visitor, when responses need aggregation, or when visitors should be balanced
among backends. Those requirements need application-level fan-out, a message
system, or a load balancer.

## Traffic and reply model

```text
                              +-> Primary client -> primary service --+
Visitor -> portwayd TCP/UDP --+                                      +-> Visitor
                              +-> Mirror client  -> shadow service --X
                              +-> Mirror client  -> observer -------X
```

For every new TCP connection or UDP visitor association:

1. `portwayd` takes a snapshot of the online configured members.
2. Visitor input is copied independently to every member in that snapshot.
3. Only `primary_client_id` has reply authority.
4. Non-Primary replies are continuously read and discarded so their send
   buffers do not stall normal processing.
5. If the Primary is offline, other online members still receive input, but no
   response is sent to the visitor and no replacement Primary is elected.

TCP preserves byte-stream and half-close behavior on each member link. A slow
or failed member is isolated from the other members. UDP preserves datagram
boundaries and creates an independent member link for each visitor association.

Reply authority is fixed when a TCP connection or UDP association is created.
A Primary change therefore affects new traffic units without mixing response
sources inside an active connection or association.

## Configuration boundary

Mirror Proxy is available only in Governed and Managed authentication modes.
It supports TCP and UDP public ports. Shared clients, HTTP/HTTPS domain proxies,
and Forward entries cannot join a mirror group.

Each group must have:

- a unique `name`;
- one or more sorted, non-overlapping public `port_ranges` whose concrete ports
  do not overlap another group of the same protocol;
- `type` set to `tcp` or `udp`;
- one `primary_client_id` that also appears in `client_ids`;
- an explicit, bounded list of authorized member client IDs.

Governed members must already be permitted to register the group port. Managed
members must each have exactly one matching server-managed Proxy entry. Portway
rejects incomplete groups, unlisted clients, conflicting ports, and mode
mismatches before publishing the configuration.

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
            - start: 2240
              end: 2249
        primary_client_id: governed-primary
        client_ids:
          - governed-primary
          - governed-observer
    managed:
      - name: discovery
        type: udp
        public:
          port_ranges:
            - start: 5353
              end: 5353
        primary_client_id: managed-primary
        client_ids:
          - managed-primary
          - managed-observer
```

The corresponding client permissions and Managed Proxy definitions remain in
their normal authentication records. See the annotated
[`config/server.yaml`](../../../config/server.yaml) for the surrounding server
configuration.

## Hot reload and operations

Mirror groups, membership, and Primary selection support fail-closed server
configuration reload. An invalid candidate leaves the previous effective state
unchanged. A same-port update reuses the public endpoint; removed members stop
receiving new traffic, and new TCP connections or UDP associations use the new
membership and Primary snapshot.

The operations endpoint reports group and active-member counts separately for
TCP and UDP. Existing Proxy capacity, link, queue, session, and UDP association
limits continue to apply, so adding mirror members increases data-link and
bandwidth usage in proportion to the number of online recipients.
