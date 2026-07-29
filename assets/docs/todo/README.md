# Portway Roadmap and TODO

This document summarizes the next public development priorities for Portway.
Items are directional and do not represent release-date commitments.

## Next core protocol: UDP

- [ ] Add UDP proxy registration and configuration.
- [ ] Preserve UDP datagram boundaries end to end.
- [ ] Define bounded UDP session ownership and idle expiration.
- [ ] Support UDP forwarding over both TCP and QUIC transports.
- [ ] Apply authentication, atomic registration, source IP filtering, and
      lifecycle rules consistently with existing proxy types.
- [ ] Define queue limits, overflow behavior, maximum datagram sizes, and
      operator-visible errors.
- [ ] Add deterministic tests for session expiry, cancellation, packet loss,
      queue overflow, and resource release.

## Performance

- [ ] Establish repeatable TCP, HTTP, UDP, and transport benchmarks.
- [ ] Profile CPU, memory allocations, goroutines, and file descriptors under
      sustained load.
- [ ] Reduce avoidable allocations and copies in verified hot paths.
- [ ] Tune HTTP connection reuse and link scheduling from measured results.
- [ ] Evaluate buffer reuse, pooling, and multiplexing only when benchmarks
      demonstrate a meaningful benefit.
- [ ] Document capacity expectations for representative deployment sizes.

## Stability and bug fixes

- [ ] Continuously fix correctness, compatibility, and resource-lifecycle bugs.
- [ ] Expand race-detector, fuzz, fault-injection, and long-running tests.
- [ ] Verify reconnect and recovery behavior under packet loss and network
      interruption.
- [ ] Improve malformed-input and protocol-state coverage.
- [ ] Maintain Linux, macOS, and Windows release compatibility.
- [ ] Keep dependencies, operational documentation, and security guidance
      current.

## Operational maturity

- [ ] Add health, readiness, and metrics endpoints.
- [ ] Define stable operational metrics and log fields.
- [ ] Add repeatable load and soak test scenarios.
- [ ] Improve release verification, upgrade guidance, and rollback procedures.

## Contributing

Bug reports should include the Portway version, operating system, selected
transport, relevant proxy type, a minimal reproduction, and sanitized logs.
Never include Tokens, private keys, certificates containing private material,
or business traffic.

Security issues must follow the private reporting process described in the
[security documentation](../security/README.md).
