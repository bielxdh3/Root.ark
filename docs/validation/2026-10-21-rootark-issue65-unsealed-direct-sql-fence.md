# Root.ark issue #65 — direct SQL INSERT of unsealed ciphertext

Status: **local disposable PostgreSQL hardening only**. No deployment,
production role/DDL migration, multi-host release or ZK-1 acceptance.

## Threat and confirmed RED

The restricted `zk1_gate_runtime` login has physical INSERT privilege on
`zk1_gate.ciphertext_chunk`. The earlier `reject_chunk_after_seal` trigger
locked the scope's head but rejected only rows whose object already had a
`SEALED` marker. For an *unsealed* object, a direct SQL INSERT bypassed the
trusted JavaScript gate and could succeed without any ACTIVE admission, or
after the head became QUIESCING/PENDING.

The adversarial test `test/issue-65-unsealed-sql-fence.test.js` reproduced the
first exploit on real disposable PostgreSQL 18.6 with independent restricted
gate credential: **RED 29 PASS / 1 FAIL**. Failure was an actual unexpected
successful direct INSERT with no admission, not a fabricated authorization
claim. The first run's second test fixture had a pool-cleanup hang; only the
exact stuck disposable test child was terminated, and the labeled Docker
container cleanup was independently confirmed. The fixture teardown has
since been repaired; this is not a production workload.

**GREEN (after SQL trigger correction):** the full focused disposable
PostgreSQL/TLS runner passed **33/33 tests, 0 FAIL, 0 SKIP**, exit code 0,
including the two new direct-SQL tests and the separately committed local
supervised-child I/O tests at `7770be4`. The second test now observes
actual PostgreSQL contention via `pg_blocking_pids` before queuing the raw
late INSERT, instead of treating a timer as evidence of lock ordering.
`SHARED_GATE_PG_CLEANUP verified=true` confirmed exact disposable cleanup.
Node 24 on Windows hosted the PG integration; this is **not** Node 22 or
multi-host/production validation.

## SQL invariant being enforced

Before *any* physical chunk INSERT (including raw restricted-role SQL):

1. Require transaction isolation READ COMMITTED; stale MVCC snapshots from
   REPEATABLE READ/SERIALIZABLE must never weaken physical fencing.
2. Hold the authoritative scope head `FOR UPDATE` and require `phase=OPEN`.
3. Reject already SEALED objects and chunk indices outside the versioned
   0–4095 range.
4. Require a currently ACTIVE PUT admission for the exact scope/object,
   authenticated head revision, digest and generation. The head lock orders
   admission state transitions and quiescence against the physical INSERT.

The test additionally checks a positive OPEN+ACTIVE write, rejection after
QUIESCING and PENDING without a seal, physical remaining indices and a real
head-lock/quiescence interleaving.

## Limits

An attacker holding the independently provisioned gate SQL credential may
still inject *staging* ciphertext while another legitimate PUT admission for
that exact object is ACTIVE and the gate remains OPEN. The independently
authenticated client/device ciphertext root, live manifest/revocation state
and fully complete `SEALED` check are separate gates. This SQL trigger is
neither an owner signature verifier nor per-process OS attestation.

PostgreSQL row-lock fencing here does **not** prove that an HTTPS socket,
S3/Drive/WebDAV operation, download, remote worker, descendant or buffered
egress stopped after a network partition. No full production acceptance.

The integration runner `lab/issue-65-packet-b/run-shared-gate-postgres.js`
uses exclusively labeled disposable loopback PostgreSQL, verifies container
identity at cleanup and never applies this schema to user data.
