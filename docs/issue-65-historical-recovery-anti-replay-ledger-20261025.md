# Issue #65 — witness historical recovery nonce ledger (2026-10-25)

## Scope and invariant

The original historical admission and its ISSUE nonce remain durably paired
in the existing immutable Ed25519 witness admission transaction.
Every *successful* lost-ACK recovery writes its own never-reusable 32-byte
challenge into `witness_cas_sync_historical_recovery_nonce` using SQLite WAL,
`synchronous=FULL`, and `BEGIN IMMEDIATE` before returning the signed
physical evidence to the authenticated mTLS client. The receipt itself is
neither updated nor reissued.

The recovery nonce journal is **append-only**. SQLite triggers reject direct
`UPDATE` and `DELETE`, including an otherwise expired nonce. Each record
contains the ordinal, the exact operation and immutable admission hash,
the prior record hash, and the new record hash. An independent witness Ed25519
signature covers the cumulative sequence/hash in
`witness_cas_sync_historical_recovery_head`. Startup and subsequent reads
verify all rows, their original admission bindings, schema/triggers, and the
signed head. A deleted entry, a missing trigger, an invalid signature or a
non-contiguous chain prevents serving any recovery. The limit is 4,096
successful recovery challenges **over the lifetime of this ledger**, not a
rolling five-minute window; exhaustion intentionally fails closed.

## External rollback protection and compatibility

**Strict historical issuer now REQUIRES live external custody.** The operator's
separately governed executable launcher injects
`trustedRecoveryNonceAuthority` with synchronous `loadHead()` and
`compareAndAdvance(expectedHead,nextHead)`. Both must access an independently
durable, linearizable monotonic store outside witness SQLite, CAS/writer JSON,
and the witness host's replaceable storage. The stock CLI/JSON cannot add this
authority. The standalone launcher checks this capability and reads the live
external floor before constructing the witness; direct strict issuers deny
bootstrap or restart if the provider is absent/unavailable.

Before **every** ISSUE and RECOVER (including their last SQLite transaction),
the witness reloads the operator's current committed floor and requires EXACT
equality with its locally verified signed recovery head. During RECOVER, after
the immutable SQLite FULL transaction commits, it advances the externally
held floor via a monotonic CAS and independently re-reads the result BEFORE
returning the new signed evidence. If the external CAS is unavailable,
ambiguous, ahead, behind, or does not acknowledge a durable write, there is no
HTTP success response or authority to start another historical admission.
There is deliberately no fallback to `trustedRecoveryNonceHead`, old
owner/PG floors, a local signed SQLite head, writer/client metadata or JSON.

**Crash boundary:** SQLite FULL and the operator's external CAS are two
independent durability domains and CANNOT be made atomic by this protocol.
If SQLite is ahead (crash before external CAS), startup and all historical
operations fail closed. If external custody is ahead (CAS committed but SQLite
rolled back), startup also fails closed. If external CAS succeeds but its ACK
is lost, recovery is denied; after restart the original spent nonce remains
unusable. Reconciliation is **manual and separately authorized**: the operator
must independently inspect the witness's original signed recovery chain and
the external monotonic record, then advance only a proven predecessor to its
successor. The launcher NEVER self-promotes SQLite or silently rewinds the
external floor. In particular, a historical SQLite snapshot signed by the
same witness key is NOT sufficient authority if external head moved forward.
The older optional `trustedRecoveryNonceHead` is only an additional static
minimum; it cannot replace the live externally loaded head.

The test-only SQLite authority fixture lives in a separate disposable file;
it tests the protocol and crash window but is NOT evidence of independent
operator custody or cross-host durability. Deployment requires a real
separately controlled authority endpoint and external trust/access controls.

**There is no unattended upgrade or nonce reconstruction** from the earlier
recovery tables (pre-append-only, time-pruned schema). Such a file fails
closed. A new issuer requires operator-approved, independently anchored
schema/nonce migration; do not drop the old table or invent a receipt's
original challenge.

No compaction, TTL pruning, counter reset or forced reuse is authorized.
Recoveries stop at capacity until a separately reviewed and externally
anchored compaction/rotation protocol exists. Independent PG physical
readback, current owner-controlled device revocation, fresh floor challenge
and exact original receipt/scope validation remain mandatory for every
recovery. This mechanism alone is **not** external ciphertext durability or
production GO for issue #65.
