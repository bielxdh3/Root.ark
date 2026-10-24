# Issue #65: same-generation GET replay must match the live gate head

Starting commit: `978ed7b684bf9a54ae2868403d0a2af12fad83a8`.

## Observed failure

`Zk1SharedPgGateAuthority.beginIoAdmission` accepts an existing `ACTIVE`
admission as a fresh `proceed: true` GET grant when PostgreSQL still says
`OPEN` and the generation matches. The replay branch had not compared the
**current** head revision and digest against the admission's signed tuple.
An interrupted operator rotation or head replacement retaining the same
generation therefore let the old worker regain an egress grant, although the
new-admission branch and the physical chunk-write path rejected that tuple.

The replayed input is the exact old worker tuple. The authority
change is a trusted-head fault/partial recovery, not a claim that the normal
quiesce/commit path fails to advance its generation.

## Change and proof

For an existing worker on an `OPEN` head with the same generation, replay now
requires an exact match of both `head.revision` and `head.digest`. A mismatch
fails closed with `ZK_GATE_DENIED`. An unchanged lost-ACK retry remains
idempotent; `QUIESCING` and a newer generation still return `proceed: false`
so the old admission can be reconciled without re-enabling egress.

Deterministic restricted-PG transaction-double test:

- **RED** on the starting commit: a revised head incorrectly returns a grant
  (`Missing expected rejection`).
- **GREEN** after the change: `node --test
  test/issue-65-gate-get-head-replay.test.js` → 2 PASS, 0 FAIL on
  Windows Node 24.14.1 and Ubuntu/WSL Node 22.22.1.
- Adjacent existing tests: `issue-65-shared-gate-postgres.test.js` and
  `issue-65-supervised-get-egress-lab.test.js` → 1 PASS, 0 FAIL, 17 SKIP
  without disposable PostgreSQL credentials.

## Boundary

The new test exercises the real gate implementation against deterministic
transaction responses, not a live PostgreSQL instance or an HTTP socket.
The supervised GET endpoint remains a synthetic loopback lab. This check
does not grant device authorization, make cloud ciphertext GET atomic with
SQL, or prove production-safe cross-host revocation/egress. A disposable
PostgreSQL run with the independent STOP role remains needed for integration.
