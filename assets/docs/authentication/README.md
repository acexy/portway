# Authentication and Configuration Control

Portway can serve trusted personal devices, independently operated clients, and
centrally managed nodes from the same server. Shared clients configure a Token
and may use an automatically generated ClientID. Governed and Managed clients
configure both the ClientID and Token from their server-owned record. The Token
selects exactly one authentication record and configuration-control mode; the
ClientID must then match before Session registration.

## Choosing a mode

| Mode | Best suited for | Client controls proxies | Server controls |
|---|---|---:|---|
| Shared Token | One operator controls the server and all clients | Yes | Global runtime limits |
| Governed | The server operator and client operators are different people | Yes, within an allowlist | Client identity, proxy types, public ports/domains, and quotas |
| Managed | The server operator must define the complete client behavior | No | Client identity and complete proxy configuration |

All three modes may be enabled on one server. The client does not configure or
declare a mode. Within one server's effective authentication configuration, a
Token must be unique across Shared, Governed, and Managed records, so it selects
exactly one record. This constraint is not enforced across separate Portway
server instances.

After the server confirms the selected mode, the client validates its local
proxy configuration again. Shared and Governed clients require at least one
local proxy; Managed clients must not define local proxies. The server
independently rejects an empty Shared or Governed proxy declaration.

## Shared Token

Use Shared Token when one trusted operator controls the complete deployment,
or when a small group of equivalent clients can safely share one credential.

Server:

```yaml
authentication:
  shared_token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
```

Client:

```yaml
authentication:
  token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES

proxies:
  - name: ssh
    type: tcp
    local_ip: 127.0.0.1
    local_port: 22
    remote_port: 22022
```

Shared clients declare their own complete proxy sets. Their generated or
configured ClientID identifies runtime resources, but is not an independently
authenticated identity. Every holder of the shared Token has equivalent
authentication authority.

Choose another mode when clients belong to different people, require separate
revocation, or must receive different permissions.

## Governed clients

Use Governed mode when clients should remain free to select their local
services, while the server operator retains control over public exposure and
resource consumption.

Server:

```yaml
authentication:
  governed_clients_path: ./governed
```

Create `governed/customer-a.yaml`:

```yaml
client_id: customer-a
token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES

permissions:
  proxy_types: [tcp, http]

  tcp:
    remote_port_ranges:
      - start: 20000
        end: 20999

  http:
    public_schemes: [https]
    domains:
      - app.customer-a.example.com
      - "*.customer-a.example.com"

  limits:
    max_proxies: 20
    max_tcp_proxies: 10
    max_udp_proxies: 5
    max_http_proxies: 10
    max_active_links: 100
```

The file name is an operator-facing label and does not need to match
`client_id`. The client configures the matching ClientID, record Token, and its
desired proxies:

```yaml
client_id: customer-a

authentication:
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES

proxies:
  - name: app
    type: http
    public_schemes: [https]
    domain: app.customer-a.example.com
    local_ip: 127.0.0.1
    local_port: 8080
```

After Token proof, the server requires the declared ClientID to match the
identity bound to that Token before registering a Session. Empty or mismatched
identities are non-retryable authentication failures. The server then validates
the complete proxy set against the configured type, TCP/UDP port, HTTP domain,
proxy-count, and active-link limits. One denied declaration rejects the
complete update and closes the rejected control session; the server never
silently publishes a partial set.

Every type listed in `proxy_types` must have a non-empty corresponding rule:
TCP and UDP require at least one `remote_port_ranges` entry. HTTP requires at
least one domain; omitted or empty `public_schemes` authorizes HTTP only. Rules for a type not
listed in `proxy_types` must be empty
or omitted. Multiple ranges allow disjoint public port allocations without
granting the unused ports between them.

Omitted Governed limit fields use production-safe defaults: 20 total proxies,
10 TCP proxies, 5 UDP proxies, 10 HTTP proxies, and 100 pending or active
links. Explicit values must be greater than zero. Proxy limits have a compiled
hard maximum of 128 per client, and active links have a compiled hard maximum
of 512 per client. A per-type proxy limit cannot exceed `max_proxies`.

Governed mode controls public exposure. It does not currently restrict the
client's private `local_ip` or `local_port`, because those fields are not sent in
client proxy declarations.

## Managed clients

Use Managed mode for centrally administered nodes where the server must provide
the complete proxy configuration.

Server:

```yaml
authentication:
  managed_clients_path: ./managed
```

Create `managed/internal-node.yaml`:

```yaml
client_id: internal-node
token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES

configuration:
  revision: 1
  proxies:
    - name: ssh
      type: tcp
      local_ip: 127.0.0.1
      local_port: 22
      remote_port: 22022
```

The Managed client configures the matching ClientID and Token but must not
define local `proxies`:

```yaml
client_id: internal-node

authentication:
  token: REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN_AT_LEAST_32_BYTES
```

After authentication, the server delivers the complete configuration through a
prepare/activate exchange. The client validates and stages it before the server
publishes the corresponding public bindings. A Managed client cannot use the
normal proxy-registration message to override the server configuration.

Increment `configuration.revision` whenever the Managed proxy configuration
changes. Reusing a revision with different content is rejected.

The complete Managed proxy set may contain at most 128 TCP, UDP, and HTTP
entries combined. An oversized set prevents server startup. During hot reload,
it rejects the complete candidate, retains the previous snapshot, and logs the
validation failure without exposing credentials.

Across all Managed records, TCP remote ports, UDP remote ports, and HTTP domains
must each be globally unique. TCP and UDP may use the same numeric port because
they use different network protocols. Managed resources remain reserved for
their configured ClientID while the client is offline, so Shared or Governed
clients cannot claim them. A conflict prevents startup or rejects the complete
hot-reload candidate before it is published.

Managed mode enforces behavior in the Portway protocol and official client. It
is not remote attestation and cannot make a client machine trustworthy if its
owner modifies the binary or operating environment.

## Running multiple modes together

The entries can be combined:

```yaml
authentication:
  shared_token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
  governed_clients_path: ./governed
  managed_clients_path: ./managed
```

At startup and every configuration reload, Portway validates that:

- every independent ClientID is unique;
- every Token is unique across this server's Shared, Governed, and Managed
  records;
- a ClientID does not appear in both Governed and Managed directories;
- permissions, quotas, ports, domains, and Managed proxy sets are valid.

The client does not configure a mode. Its Token selects one record, while
Governed and Managed authentication also requires the configured ClientID to
match that record. After identity validation, the server returns the associated
mode and confirmed ClientID over the protected channel.

## Reloading, revocation, and failure behavior

The server reloads its main configuration and authentication directories as one
validated candidate. A malformed, conflicting, oversized, or incomplete
candidate is rejected in full, and the previous effective configuration remains
active.

Credential and policy changes are fail-closed:

- adding, removing, replacing, or reassigning any Shared, Governed, or Managed
  Token publishes the new authentication snapshot and disconnects every client,
  including recoverable sessions;
- clients with unchanged credentials may reconnect using the same Token, while
  a changed credential requires the newly published Token;
- changing Governed permissions closes that client's sessions, bindings,
  pending tickets, and active links;
- changing Managed proxy configuration performs an online prepare/activate
  rollout; an incomplete switch leaves the session inactive and reconnects to
  the latest desired configuration.

For policy-only and Managed configuration-only changes, unrelated clients remain
active. Fields that cannot be safely reloaded, such as the selected transport or
listener addresses, are rejected with a restart-required error instead of being
partially applied.

## Operational guidance

- Generate Tokens from a cryptographically secure random source with at least
  32 bytes of entropy.
- Never reuse a Token across clients, modes, servers, or unrelated systems.
- Do not commit Tokens to version control or include them in command lines and
  logs.
- Give Governed clients the narrowest practical port, domain, and quota rules.
- Use atomic file replacement when updating authentication records.
- Treat authentication directories as sensitive server configuration.
- Keep ordinary network firewall and upstream access controls in place.

Complete annotated examples are available in
[`config/server.yaml`](../../../config/server.yaml),
[`config/governed/governed-client.yaml`](../../../config/governed/governed-client.yaml),
and
[`config/managed/managed-client.yaml`](../../../config/managed/managed-client.yaml).
