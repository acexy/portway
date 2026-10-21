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

When a member becomes active, it joins both current and future visitor traffic:

1. Visitor input is copied independently to every active member.
2. A newly active member receives only traffic that arrives after its own Data
   Link is ready; prior traffic is never replayed.
3. Only `primary_client_id` has reply authority.
4. Non-Primary replies are continuously read and discarded so their send
   buffers do not stall normal processing.
5. If the Primary is offline, other online members still receive input, but no
   response is sent to the visitor and no replacement Primary is elected.

TCP isolates slow or failed replicas; a slow Primary applies backpressure to visitor input. A member added to a live
TCP connection can begin at any byte offset: Portway does not detect protocol
or message boundaries and does not replay a handshake or request prefix. Its
local service must tolerate incomplete stream context. UDP preserves datagram
boundaries; a newly active member begins with the next datagram.

For a new TCP visitor, forwarding starts as soon as any member's link is ready;
it does not wait for every member or specifically for the Primary. Members that
finish connecting later can therefore miss the beginning of the stream even if
their clients were already registered. If every initial link attempt fails,
visitor input is consumed and discarded while members retry independently.

A local service being unavailable does not log out its client. TCP members,
including the Primary, automatically retry failed links with backoff and resume
forwarding subsequent bytes when the local service starts or restarts. Traffic
lost during the outage and queued on a failed link is not replayed. The visitor's
response direction remains open while the Primary recovers. Visitor input EOF
ends retries and cancels pending link attempts. The Primary request queue drains
before its write half-close, and its complete response is forwarded without a
fixed total drain deadline. A clean Primary response EOF reaches the visitor
while the request direction remains usable. Clean EOF does not rebuild the link,
even when caused by a graceful service restart. UDP removes failed associations
and retries on subsequent datagrams; sockets that report no error continue sending normally.
Neither protocol requires a Portway client restart to recover the local service.

While the Primary link is healthy, a full bounded queue pauses further visitor
reads instead of dropping requests. Primary request and response writes have no
fixed short timeout. Replicas have queues of at most 32 blocks of 32 KiB and a
15-second write timeout. Queue overflow or timeout may discard and retry a copy
without affecting the Primary. After visitor input EOF, replicas have at most
15 seconds to drain and finish. This does not guarantee buffering 15 seconds of
traffic: capacity can be exhausted sooner. UDP can still lose datagrams through
network or capacity limits and does not provide reliable delivery.

Visitors should set application request timeouts. Actual failures, revoked
authorization, and shutdown can still interrupt in-flight data. If a failed
member retains a blocked visitor response write, the visitor session is closed
to release its resources.

Only the configured Primary has reply authority; every non-Primary response is
discarded even while that member joins or leaves an active flow.

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
unchanged. Existing TCP visitors and unaffected groups remain connected during
a same-port membership or Primary update. Reply authority switches atomically;
an already authorized old Primary response write has at most 15 seconds from
the switch to finish before the new Primary writes. Failure closes that visitor
session. A session whose response direction has already half-closed is closed
on a Primary switch. Existing UDP associations also use current reply authority
instead of the Primary identity at creation; previously admitted writes may finish. A same-port update reuses the public endpoint; removed members stop
receiving traffic. Newly active members begin receiving subsequent traffic on
both current and new TCP connections or UDP associations, subject to the
no-replay and TCP-boundary limitations above.

The operations endpoint reports group and active-member counts separately for
TCP and UDP. Existing Proxy capacity, link, queue, session, and UDP association
limits continue to apply, so adding mirror members increases data-link and
bandwidth usage in proportion to the number of online recipients.
