# Root.ark #65 — PostgreSQL monotonic head fencing (NOT physical STOP proof)

**Date:** 2026-10-21
**Scope:** isolated, non-production, operator-provisioned shared PostgreSQL gate

The `zk1_gate.head` trigger now enforces only `OPEN → QUIESCING` with strictly
incremented fencing `generation`, and `QUIESCING → PENDING` with preserved
generation and operation/reservation IDs, matching immutable keyring/revision/
digest. It rejects all attempts to rewrite the old head to `OPEN`, decrease
generation, skip directly to `PENDING`, or alter the pinned scope. While a
worker is not `FINISHED`, `PENDING` is rejected. Calls using non-READ-COMMITTED
PostgreSQL isolation are rejected. No terminal-state reopening or CAS proof
reconciliation is offered, so this remains **fail closed** after `PENDING`.

RED→GREEN real PostgreSQL 18.6: a dedicated NO-SUPERUSER runtime login
successfully reverted QUIESCING to OPEN and skipped active workers before the
trigger. After the fix, the same raw SQL is rejected, and the trusted Gate
Authority still finishes workers and advances monotonically. Disposable
PostgreSQL runner: **24/24 PASS, 0 failures, 0 skips**, with verified cleanup.

**Important confirmed gap:** independent read-only security review reproduced
that the same restricted runtime role can directly `UPDATE
zk1_gate.admission SET state='FINISHED'` with no actual worker STOP and then
`UPDATE zk1_gate.head SET phase='PENDING'`. The head trigger correctly checks
the database state but has **no independent physical-stop attestation**; a
compromised gate SQL runtime can forge the state being checked. This is a
conditional P2 under a threat model that includes misuse of the restricted
runtime credential. It does **not** allow physical PostgreSQL ciphertext
chunk effects after `QUIESCING`, because those are already fenced by the head
generation/phase, but it **does** prohibit claiming a verified physical drain
or authorized witness commitment. A separate independently governed STOP
receipt/role and OS-process termination proof are prerequisites to claiming
that property; they are not implemented by this one-way phase trigger.

This is not a normative distributed gate, remote egress barrier, migration,
recovery completion or production release. No push, merge or user data mutation.
