# Root.ark #65 — PostgreSQL sealed ciphertext object foundation

**Date:** 2026-10-21
**Scope:** isolated operator-provisioned PostgreSQL zk-1 write-only reference provider. Not a released normative ZK implementation.

## Durable object-finalization boundary

Existing `zk1_gate.ciphertext_chunk` writes may succeed physically before a worker
crashes, a socket loses its PUT acknowledgement, the complete stream arrives,
or recovery starts. Therefore their presence **must not** imply an authenticated
complete object. New `zk1_gate.sealed_object` is an immutable, restricted-runtime
INSERT-only marker. `Zk1SharedPgSealedObjectStore.seal()` requires an *exact*
trusted worker admission, matching current committed head digest/revision,
keyring, epoch generation, action `put`, and phase `OPEN`; all checks and the
marker INSERT occur in the transaction holding the **same PostgreSQL head row
FOR UPDATE lock** as physical ciphertext writes and `beginQuiesce`.

The client-supplied `expectedChunkCount` (1–4096) and
`expectedRootHash` (SHA-256, 32 bytes) **must come from independently
authenticated signed user/device metadata**, never be invented by the storage
server. The `Root.ark/zk-1/ciphertext-chunk-root/v1\0` commitment comprises:
`uint32_be(chunkCount)` followed, in exact zero-based order, by
`uint32_be(chunkIndex) || uint32_be(chunkByteLength) || SHA256(chunkCiphertext)`.
The outer digest is SHA-256 over the domain-separated concatenation. Chunks
are read and hashed one at a time (max 4 MiB in JS memory per row; no aggregate
buffer over an entire large object). The seal fails for missing/extra chunks,
altered sequence, wrong digest, wrong worker/admission, mismatched head, or
quiescence. Lost seal ACK can retry only the identical still-authorized seal.
Each seal transaction has a 15-second PostgreSQL 18+ `transaction_timeout`;
a stalled/oversized object aborts rather than holding the authoritative
quiescence lock indefinitely. Such a timeout is a failed seal, never proof of
a completed object.

An operator-owned `BEFORE INSERT` trigger takes the authoritative head lock
and refuses **all additional physical ciphertext chunks** once an object has
been sealed. This prevents authorized lingering workers and restricted SQL
inserts from appending invisible trailing chunks. It is deliberately stricter
than retrying an existing chunk after seal; the retry fails closed. The role
`zk1_gate_runtime` has `SELECT` and column-limited `INSERT` on the seal table,
but neither UPDATE nor DELETE, and no table/TRIGGER DDL privilege. A privileged
PostgreSQL DBA remains part of the trust boundary.

## Tests and proof boundaries

The disposable PostgreSQL 18.6 lab runner executes two opt-in sealed-object
integration tests as part of its 14-test real-PG suite. They cover incomplete
streams, wrong root, wrong worker/scope, exact retry, successful immutable
seal, post-seal physical extra-chunk rejection and no seal after QUIESCING.
Tests execute the new store under the independently provisioned restricted
`zk1_gate_runtime` login. The post-seal trailing-chunk test was **RED** before
the database trigger, then **GREEN** with 14/14 overall real-PG tests PASS and
verified cleanup of the labeled disposable container. No user database or
uploads were touched.

## Known incompleteness

This does **not** publish a signed normative ZK manifest, verify device
authorization itself, enable GET/egress, authorize recovery, close the CAS
transaction, or migrate any legacy objects. The current mTLS gateway/sink
must be integrated with explicit sealing before any normal route can treat
the ciphertext as complete. Failed/partial chunks remain physically stored
but **not sealed**; deleting or expiring them requires a separately reviewed,
owner-safe reconciliation and retention protocol. There is no object-size
quota other than per-chunk and chunk-count bounds here, and large-object
sealing may hold the head lock for substantial time; benchmark and bound such
work before multi-host production. A single PostgreSQL primary and trusted
runtime/operator are assumed; cross-provider and network-egress fencing,
independently proven worker STOP, and full issue #65 acceptance remain open.
