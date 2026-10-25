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

The operator can read `historicalRecoveryNonceHead()` and retain
`{sequence,lastHash}` outside witness SQLite. On restart, pass the latest
trusted checkpoint as the constructor option `trustedRecoveryNonceHead`.
The witness rejects a rollback below that signed and independently pinned
minimum, and checks chain ancestry as the journal advances. A standalone
SQLite database **cannot** detect a full rollback to a previously valid,
already signed snapshot if both its recovery history and its internally
signed head are restored together and the external recovery minimum is absent.
The existing independently pinned CAS/PG and historical-admission heads do
not automatically cover recovery nonces. This external monotonic checkpoint
is mandatory to claim rollback resistance against whole-file restoration.

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
