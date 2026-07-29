<p align="center">
  <img src="assets/portway-logo.png" width="180" alt="Portway logo">
</p>

<h1 align="center">Portway</h1>

<p align="center">
  A lightweight, production-oriented reverse tunneling system for TCP and HTTP services.
</p>

Portway exposes services from private networks through a public server. It keeps
the control plane separate from tunneled traffic, supports TCP and QUIC as its
underlying client-server transport, and is designed around explicit ownership,
bounded resources, and secure defaults.

## Highlights

- TCP and domain-based HTTP reverse proxying
- Selectable TCP or QUIC client-server transport
- Authenticated and encrypted client-server connections
- Atomic proxy registration and bounded session recovery
- HTTP streaming and Upgrade support with connection reuse
- Dynamically reloaded IPv4/IPv6 deny lists
- Strict YAML configuration and fail-closed validation
- Small client and server binaries with a consistent command-line interface

## Quick start

The following example exposes the client's local SSH service on TCP port
`22022` of the Portway server.

Create `server.yaml`:

```yaml
transport:
  type: tcp
  listen_address: 127.0.0.1:7000

authentication:
  token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
```

Create `client.yaml`:

```yaml
transport:
  type: tcp
  server_address: 127.0.0.1:7000

authentication:
  token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES

proxies:
  - name: ssh
    type: tcp
    local_ip: 127.0.0.1
    local_port: 22
    remote_port: 22022
```

Use the same cryptographically random Token on both sides, then start the
server and client:

```bash
portwayd run --config server.yaml
portway run --config client.yaml
```

The local SSH service is now available at:

```text
127.0.0.1:22022
```

Do not commit real Tokens, private keys, or production certificates.

## HTTP proxy

Enable one public HTTP listener on the server:

```yaml
tunnel:
  http_listen_address: 127.0.0.1:8080
```

Register a domain on the client:

```yaml
proxies:
  - name: web
    type: http
    domain: app.example.com
    local_ip: 127.0.0.1
    local_port: 8080
```

The public `Host` is matched to an authenticated client registration. The local
application receives a normal HTTP request and does not need to understand the
Portway protocol.

## QUIC transport

Portway can use QUIC instead of TCP between `portway` and `portwayd`. QUIC
requires a server certificate and TLS verification in addition to Portway Token
authentication.

For private deployments, generate an internal CA and server certificate:

```bash
portwayd cert generate \
  --server-name gateway.example.com \
  --ip 10.0.0.10
```

Run `portwayd help cert` for all certificate options. Keep the generated root CA
private key offline and distribute only the root CA certificate to clients.

## Commands

```text
portway run [--config FILE]
portway version

portwayd run [--config FILE]
portwayd cert generate [options]
portwayd version
```

Run either binary without arguments to display its command overview.

## Build from source

Portway currently targets Go 1.25.8.

```bash
make build
```

The current-platform binaries are written to `target/bin/`.

To cross-compile and package all supported release targets:

```bash
./release.sh
```

The release matrix includes Linux and macOS on `amd64` and `arm64`, plus
Windows on `amd64`. Each archive contains only the matching `portway` and
`portwayd` executables at its root:

```text
target/portway-linux-amd64.tar
target/portway-linux-arm64.tar
target/portway-darwin-amd64.tar
target/portway-darwin-arm64.tar
target/portway-win-amd64.tar
```

Windows archives contain `portway.exe` and `portwayd.exe`. Override release
metadata when needed:

```bash
VERSION=v1.0.0 COMMIT="$(git rev-parse HEAD)" ./release.sh
```

## Publishing a release

Pushing a semantic version Tag triggers the GitHub Actions release workflow:

```bash
git tag -a v1.0.0 -m "Portway v1.0.0"
git push origin v1.0.0
```

The workflow runs all Go tests, builds the complete release matrix, creates
SHA-256 checksums, generates release notes from merged changes, and publishes
the archives as GitHub Release assets. Tags with a suffix such as
`v1.0.0-rc.1` are published as pre-releases.

Push the target commit to the repository's default branch before creating its
release Tag. Release downloads are available from:

```text
https://github.com/acexy/portway/releases
```

## Public documentation

- [Technical overview](assets/docs/technical/README.md)
- [Security](assets/docs/security/README.md)
- Fully annotated configuration examples:
  [client](config/client.yaml) and [server](config/server.yaml)

The public documentation intentionally describes stable behavior and security
properties without serving as a complete wire-protocol specification.

## Current scope

Portway focuses on lightweight, operator-managed reverse tunneling. It does not
currently provide a web dashboard, P2P NAT traversal, TUN/TAP networking,
dynamic plugins, or a distributed multi-tenant control plane.
