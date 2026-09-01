---
name: "fix: make idle timeout test deterministic (sync writes)"
about: "Replace async writes in idle timeout test with synchronous writes to avoid CI race"
---

Problem
-------
On CI the test TestIdleTimeoutConnectionRefreshesOnActivity fails intermittently with:

    idle_connection_test.go:32: read activity 2: io: read/write on closed pipe

Root cause
----------
The test wrote to the client side using a goroutine and then immediately called Read on the wrapped connection. On CI the goroutine may not run before the idle timeout closes the underlying connection, producing a read/write-on-closed-pipe error.

Change
------
This commit replaces the asynchronous write goroutine with a synchronous client.Write call in the test to make the behavior deterministic.

Impact
------
Test-only change. Makes the test more reliable on CI.
