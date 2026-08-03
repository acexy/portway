# Portway Future Plans

This document summarizes possible future directions for Portway. These items
are exploratory, are not accepted scope or implementation commitments, and do
not represent release-date commitments.

## Distribution

- Publish Portway through Homebrew.

## UDP hardening

- Add repeatable packet-loss, congestion, queue-overflow, and high-source-
  cardinality load scenarios.
- Add long-running Association expiry and resource-trend verification.
- Measure whether native QUIC Datagram support provides enough benefit to
  justify an additional transport capability.

## Performance

- Establish repeatable TCP, HTTP, HTTPS, UDP, and transport benchmarks.
- Profile CPU, memory allocations, goroutines, and file descriptors under
  sustained load.
- Reduce avoidable allocations and copies in verified hot paths.
- Tune HTTP connection reuse and link scheduling from measured results.
- Evaluate buffer reuse, pooling, and multiplexing only when benchmarks
  demonstrate a meaningful benefit.
- Document capacity expectations for representative deployment sizes.

## Stability and bug fixes

- Continuously fix correctness, compatibility, and resource-lifecycle bugs.
- Expand race-detector, fuzz, fault-injection, and long-running tests.
- Verify reconnect and recovery behavior under packet loss and network
  interruption.
- Improve malformed-input and protocol-state coverage.
- Maintain Linux, macOS, and Windows release compatibility.
- Keep dependencies, operational documentation, and security guidance current.

## Operational maturity

- Add health, readiness, and metrics endpoints.
- Define stable operational metrics and log fields.
- Add repeatable load and soak test scenarios.
- Improve release verification, upgrade guidance, and rollback procedures.

## Contributing

Bug reports should include the Portway version, operating system, selected
transport, relevant proxy type, a minimal reproduction, and sanitized logs.
Never include Tokens, private keys, certificates containing private material,
or business traffic.

Security issues must follow the private reporting process described in the
[security documentation](../security/README.md).
