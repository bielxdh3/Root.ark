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
equality with its locally verified signed recovery head. During RECOVER, the
first SQLite FULL transaction **atomically** consumes the recovery nonce,
advances the signed chain and persists `PENDING` ACK state inside the witness-
Ed25519-signed recovery head. The witness then advances external custody via
monotonic CAS and independently re-reads its committed result. **Only explicit
CAS `true` plus matching external read** permit a *second* `BEGIN IMMEDIATE` /
WAL `synchronous=FULL` transaction to sign `READY` on that same recovery head.
Immediately before signing in the second FULL transaction, the witness reads
the **last trusted-device revocation policy** again and checks the originally
verified PG Ed25519 proof age against the then-current clock (30-second bound).
Because synchronous SQLite statement preparation, Ed25519 signing and UPDATE
execution can stall, the same checks run **again after the READY UPDATE and
before the FULL COMMIT**. The entire READY change rolls back if policy was
revoked or the proof expired during any of those steps. A slow FULL/fsync can
also cross the freshness boundary: the witness checks again **after COMMIT
and before returning any ACK**, rejects the recovery if stale and attempts a
separately FULL-committed, witness-signed transition back to `PENDING`.
If that compensating durable commit itself becomes unavailable, the current
process denies further historical operations; the operator must not assume
crash-safe reconciliation without independent evidence of the final persisted
phase. External device-policy changes and a local SQLite COMMIT cannot be made
globally atomic without a separately governed external policy-fencing protocol.
Revocation or physical-proof expiry while an external CAS blocks leaves the
already-consumed nonce and signed `PENDING` marker in durable quarantine, even
if the external CAS itself succeeded. Old device proof expiry alone is not a
replacement for live revocation: this historical flow explicitly permits an
expired original envelope only when the trusted-device policy remains valid.
A success response is impossible before that second durable commit. Missing,
old or mismatched ACK state fails closed: the recovery signature domain and
persistent issuer identity are versioned; old databases cannot become READY.

External CAS failure, ambiguous/lost ACK, mismatched external state, or a
crash before the second FULL transaction leaves the witness-signed `PENDING`
marker. It quarantines ALL historical ISSUE/RECOVER in this process and after
restart, **even if external custody eventually matches SQLite**. Equal heads
are not proof of the original ACK. No caller/launcher-controlled clear API exists.
There is deliberately no fallback to `trustedRecoveryNonceHead`, old
owner/PG floors, a local signed SQLite head, writer/client metadata or JSON.

**Crash boundary:** SQLite FULL and the operator's external CAS are two
independent durability domains and CANNOT be made atomic by this protocol.
If SQLite is ahead (crash before external CAS), startup and all historical
operations fail closed. If external custody is ahead (CAS committed but SQLite
rolled back), startup also fails closed. If external CAS succeeds but its ACK
is lost, the nonce remains spent and the signed marker remains PENDING.
Reconciliation is **manual, separately authorized and requires a separately
reviewed recovery/migration procedure**: merely matching the heads is NOT
enough, and there is no automatic clear or in-process override. The launcher
NEVER self-promotes SQLite or rewinds external custody. A historical SQLite
snapshot signed by the witness key cannot override the off-host anchor.
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
