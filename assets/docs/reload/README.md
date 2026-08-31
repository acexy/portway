# Server Configuration Reload

Portway reloads authentication, authorization, and server-managed client
configuration without restarting `portwayd`. Reloading is fail-closed and
generation-based: a complete candidate is validated before any runtime state
changes.

## What is watched

When `portwayd` starts from an explicit configuration file, it scans every
three seconds:

- the active server YAML file;
- `authentication.governed_clients_path`;
- `authentication.managed_clients_path`;
- ordinary `*.yaml` files directly inside those directories.

Authentication directories are not scanned recursively. Symbolic links are
rejected. Relative directory paths are resolved from the server configuration
file, not from an arbitrary process working directory.

## Atomic candidate behavior

Every scan builds one candidate from the main file and every Governed and
Managed record:

```text
read all sources
→ strictly decode YAML
→ apply defaults and hard limits
→ validate cross-file identity and resource rules
→ compare with the effective generation
→ atomically publish
```

The candidate is all-or-nothing. If one newly added client file is valid and a
second file is invalid, neither file is published. The previous generation,
sessions, listeners, bindings, and proxy behavior remain active.

If startup generated the Shared Token because `shared_token` was empty or was
omitted without independent authentication directories, later scans reuse that
same effective Token. They do not silently generate a new credential.

This prevents partially published credentials, ambiguous Token or ClientID
ownership, and inconsistent Managed port/domain reservations.

## Reloadable settings

The current implementation reloads:

- `log_level`;
- an explicitly configured Shared Token;
- Governed and Managed directory paths and contents;
- Governed permissions and quotas;
- complete Managed client configurations.
- `forwards.enabled`, global Forward rules, and client Forward permissions.

Changing authentication state has immediate runtime effects:

- adding, removing, replacing, or reassigning any Shared, Governed, or Managed
  Token disconnects every client, including sessions waiting in the recovery
  window;
- clients whose credentials did not change may reconnect with the same Token;
  clients whose credentials changed must use the newly published Token;
- changing Governed permissions closes that client's session and resources so
  it reconnects under the new policy;
- a Managed configuration-only change still uses online rollout and does not
  disconnect unrelated clients.

Disabling `forwards.enabled` keeps all client declarations and permissions as
dormant state. Online and newly started clients remain connected, close only
Forward listeners and links, and log `forward_disabled`. Re-enabling restores
still-authorized listeners in the same Session from the latest rules.

## Settings that require restart

The following are validated but not applied online:

- `transport.type` and `transport.listen_address`;
- QUIC certificate and private-key settings;
- `proxies.bind_ip`, `proxies.http.listen_address`, and
  `proxies.https.listen_address`;
- HTTP, UDP, security, and other runtime-component limits.

If any of these fields changes, Portway rejects the complete candidate with
`restart_required`. Reloadable fields included in the same candidate are not
partially applied.

Public HTTPS certificate contents, paths, and `proxies.https.certificates` entries are
exceptions: a complete valid SNI certificate set is published atomically without
replacing the HTTPS listener. Invalid candidates keep the previous set active.

## Managed online rollout

A changed Managed record becomes the new desired state. For an online client,
the server performs:

```text
managed_config_prepare
→ managed_config_prepared
→ managed_config_activate
→ managed_config_applied
```

The client validates and stages the complete configuration before activation.
The server synchronizes public bindings between Prepare and Activate. A failed
or incomplete switch is never marked effective; the affected session is closed
or kept inactive and reconnects toward the latest desired revision. Other
clients are not blocked by that rollout.

Every Managed configuration content change must increase
`configuration.revision`. Reusing a revision with different content is
rejected.

## Validation and logs

Common reasons for rejecting a candidate include:

- malformed YAML, unknown fields, or missing required fields;
- short or duplicate Tokens;
- duplicate or invalid ClientIDs;
- invalid Governed rules or quotas;
- invalid Managed local targets, domains, ports, or proxy counts;
- duplicate Managed TCP ports, UDP ports, or HTTP domains;
- a new Managed reservation conflicting with an active binding;
- changes to restart-required fields.

Failure logs include an actionable error, stable `error_code`, and the current
generation. Tokens and raw authentication payloads are never logged. The same
unchanged failure is logged once instead of every scan; a later successful
candidate emits recovery and applied events.

## Safe update workflow

Update configuration files atomically:

1. create a temporary file on the same filesystem;
2. write and close the complete YAML;
3. set its ownership and permissions;
4. rename it over the destination.

Do not edit several live files slowly in place. Intermediate combinations are
valid candidates from the watcher's perspective and may produce temporary
validation failures. Atomic candidate semantics protect the running generation,
but atomic file replacement keeps operational logs and rollout intent clear.

For field examples, see [`config/server.yaml`](../../../config/server.yaml),
[`config/governed/governed-client.yaml`](../../../config/governed/governed-client.yaml),
and
[`config/managed/managed-client.yaml`](../../../config/managed/managed-client.yaml).
