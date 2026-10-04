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

`GET /metrics` returns a Prometheus-compatible text snapshot. The current
metrics are gauges:

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

Metrics intentionally do not use ClientID, SessionID, ProxyName, LinkID,
domain, or source IP labels. This keeps metric cardinality bounded and avoids
exposing deployment identities through the monitoring interface.

The first version reports current resource levels rather than cumulative
request, failure, or traffic counters.

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
