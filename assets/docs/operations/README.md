# Portway Operations Endpoints

Portwayd can expose a small, independent HTTP listener for process probes and
low-cardinality runtime metrics. The listener is disabled by default and does
not carry proxy traffic or client-server tunnel traffic.

## Enabling the listener

Configure a dedicated address in `server.yaml`:

```yaml
operations:
  listen_address: 127.0.0.1:9090
```

Changing this address requires restarting `portwayd`. It must differ from the
Transport, public HTTP, and public HTTPS listener addresses.

The operations endpoints do not implement application authentication. Bind the
listener to loopback or a protected management network. Do not expose it
directly to the public Internet.

## Health check

`GET /healthz` verifies that the process and its operations HTTP server can
respond. A healthy process returns:

```text
HTTP/1.1 200 OK

ok
```

This endpoint is suitable for a process liveness probe. It does not guarantee
that the tunnel listener or proxy listeners have completed initialization.

## Readiness check

`GET /readyz` reports whether the Transport, Proxy Registry, and all configured
listeners have completed initialization.

- Ready: `200 OK` with `ready`.
- Not initialized or shutting down: `503 Service Unavailable` with `not ready`.

This endpoint is suitable for a readiness probe or load-balancer health check.

## Metrics

`GET /metrics` returns a Prometheus-compatible text snapshot. Metrics ending in
`_total` are counters; all other metrics are gauges:

| Metric | Meaning |
|---|---|
| `portway_ready` | Whether all configured listeners are initialized |
| `portway_configuration_generation` | Current published server configuration generation |
| `portway_sessions_initializing` | Initializing control Sessions |
| `portway_sessions_active` | Active control Sessions |
| `portway_sessions_suspended` | Recoverable suspended Sessions |
| `portway_links_pending` | Data Links waiting for binding |
| `portway_links_active` | Bound active Data Links |
| `portway_tcp_proxies` | Registered TCP proxies |
| `portway_udp_proxies` | Registered UDP proxies |
| `portway_http_proxies` | Registered HTTP domain proxies |
| `portway_http_active_requests` | Active HTTP/HTTPS requests |
| `portway_http_active_upgrades` | Active upgraded HTTP connections |
| `portway_udp_associations` | UDP Associations, including pending Associations |
| `portway_udp_pending_associations` | UDP Associations waiting for a Data Link |
| `portway_udp_queued_bytes` | UDP payload bytes currently queued in memory |
| `portway_forward_links_pending` | Forward Data Links waiting for binding |
| `portway_forward_links_active` | Bound Forward Data Links |
| `portway_forward_bindings` | Registered Forward bindings |
| `portway_forward_bindings_active` | Active Forward bindings |
| `portway_forward_bindings_inactive` | Non-active Forward bindings; not a failure count |
| `portway_tcp_forwards` | Registered TCP Forwards |
| `portway_udp_forwards` | Registered UDP Forwards |
| `portway_forward_udp_associations` | Server-side Forward UDP associations, including pending |
| `portway_forward_udp_pending_associations` | Pending server-side Forward UDP associations |
| `portway_forward_udp_queued_bytes` | Queued server-side Forward UDP payload bytes |
| `portway_tcp_mirror_groups` | TCP mirror groups |
| `portway_udp_mirror_groups` | UDP mirror groups |
| `portway_tcp_mirror_members` | Registered TCP mirror members |
| `portway_udp_mirror_members` | Registered UDP mirror members |
| `portway_vnet_enabled` | Whether VNet is configured as enabled |
| `portway_vnet_device_open` | Whether the server runtime holds a VNet device |
| `portway_vnet_device_preparing` | Whether server VNet device preparation is in progress |
| `portway_vnet_nodes` | Configured VNet nodes |
| `portway_vnet_sessions` | Attached VNet control sessions |
| `portway_vnet_configuration_generation` | VNet configuration generation |
| `portway_vnet_pools_pending` | Pending channel pools |
| `portway_vnet_pools_active` | Published active channel pools |
| `portway_vnet_channels_active` | Channels in published active pools |
| `portway_vnet_flows` | Server router flow records |
| `portway_vnet_peer_pairs` | Server-coordinated peer pairs |
| `portway_vnet_direct_pairs` | Direct pairs activated by the server |
| `portway_vnet_queued_packets` | Packets queued for server transmission |
| `portway_vnet_userspace_flows` | Server userspace flow records |
| `portway_vnet_tcp_connections` | Server userspace TCP connections |
| `portway_vnet_udp_associations` | Server userspace UDP associations |
| `portway_vnet_capacity_rejected_total` | Cumulative router capacity rejections |
| `portway_vnet_rate_rejected_total` | Cumulative router rate rejections |
| `portway_vnet_policy_rejected_total` | Cumulative router policy rejections |
| `portway_vnet_queue_rejected_total` | Cumulative packet queue admission rejections |
| `portway_vnet_queue_expired_total` | Cumulative queued packet expirations |
| `portway_vnet_queue_revoked_total` | Cumulative queued packet authorization revocations |
| `portway_vnet_queue_write_failed_total` | Cumulative queued packet write failures |

Metrics intentionally do not use ClientID, SessionID, ProxyName, LinkID,
domain, or source IP labels. This keeps metric cardinality bounded and avoids
exposing deployment identities through the monitoring interface.

Counters accumulate within one server VNet runtime. Configuration updates, Session
reconnections, pool replacement, and disabling VNet do not explicitly reset them;
a new runtime or process restart may reset them. Components not created report zero.

These metrics describe only server-observed resources and events. Active Forward
bindings do not guarantee client listener or target availability. Holding a VNet
device does not guarantee correct system routes or end-to-end connectivity. Attached
Sessions are not active nodes. Direct pairs represent coordination state, not current
path health. P2P traffic bypasses the server, so these endpoints do not report total
VNet traffic. Normal relay fallback is not an overall failure.

Components are sampled separately, without a globally transactional snapshot. Forward
and Proxy UDP accounting remain separate. Local feature unavailability does not fail
global `/readyz`. Collection does not probe targets, repair system networking, or
return identity, address, or policy details. Existing listener protection requirements
continue to apply.

## Example probes

```bash
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/metrics
```

Example Kubernetes probes:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9090
readinessProbe:
  httpGet:
    path: /readyz
    port: 9090
```

Network policy or an equivalent host firewall must still restrict access to
the operations listener.

## Client reconnection

The client retries transient connection and server failures until it is stopped.
Permanent authentication, protocol, and configuration errors terminate the client.
Each control session setup has a 20-second total budget, including a maximum
5-second transport dial. Cancellation can shorten either budget.

Heartbeats are sent every 5 seconds; 20 seconds without a valid response triggers
reconnection. The server retains a suspended session for 60 seconds. The client
tries to recover its identity for up to 90 seconds, then registers again. Failed
recovery initialization does not extend the server's retention window.

Recovery retries use 0.5, 1, 2, and at most 3 seconds; ordinary registration retries
use 1, 2, 4, 8, 15, and at most 30 seconds. Both include ±25% jitter. The first
established connection enables fast recovery. Later short connections preserve
backoff; a connection must remain healthy for at least 60 seconds and receive
valid heartbeat responses before backoff resets. These timing values are fixed.
