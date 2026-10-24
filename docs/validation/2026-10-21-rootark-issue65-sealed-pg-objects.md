# Root.ark #65 — bounded physical PostgreSQL ciphertext sealing

**Date:** 2026-10-21
**Status:** ISOLATED LAB / PARTIAL / NON-PRODUCTION — no normal-file or provider migration.

## Implementation

The separate `zk1_gate` PostgreSQL schema has a `sealed_object` marker and a
trigger preventing additional `ciphertext_chunk` inserts once a particular
scope/object has been sealed. A local, explicitly trusted
`Zk1SharedPgSealedObjectStore` checks one active, exact worker admission and
the shared head/generation inside an authoritative PostgreSQL transaction,
streams through a bounded ordered sequence of 1–4096 ciphertext chunks,
verifies the versioned SHA-256 domain-separated root that binds count, index,
length, and chunk hash, and commits a single immutable seal. Absent/extra
chunks, mismatched digest, mismatched worker, revoked generation and incorrect
scope are rejected without publishing a marker. Retries are idempotent only
for the exact already-sealed tuple while its authenticated worker remains
active. This does **not** publish a ZK manifest or certify that its expected
root was actually signed by the owner/device.

The isolated mTLS `/v1/chunk/seal` endpoint now requires its **own `seal`
role** and exact scoped certificate identity; it is disabled if no sealed
store was provisioned. The pinned `zk1SharedPgGateHttpsClient` passes only an
independently owner-authenticated expected root and exact admission identity,
and validates the response's status/count. The normal protected and legacy
Root.ark HTTP routes are unchanged; GET/egress remains blocked.

## Independent P1 discovery and verified correction

An independent reviewer confirmed a **P1** against the first `sealed_object`
SQL trigger under **real PostgreSQL 18.6** and the **restricted runtime
login**, not a superuser. A transaction started in `REPEATABLE READ`, pinned
an earlier snapshot of an unsealed object, waited while another connection
committed its complete seal, and then inserted an extra ciphertext chunk
after that seal. Its old snapshot made the trigger's `sealed_object` lookup
incorrectly see no seal; the head row's `FOR UPDATE` alone was insufficient,
since the seal transaction did not update that row. This invalidated the
claimed physical immutability, even with the SQL privilege boundary intact.

The trigger now **rejects every isolation mode except `READ COMMITTED`** for
ciphertext INSERT. A new disposable-PG adversarial test establishes pre-seal
views under `READ COMMITTED`, `REPEATABLE READ`, and `SERIALIZABLE` using the
restricted gate login, commits a seal concurrently, then verifies that a
late direct SQL INSERT is rejected and only the originally sealed index
remains. The test initially exposed an accepted post-seal INSERT (**RED**);
the isolation guard and stale-snapshot regression subsequently ran **GREEN**.
An isolated PG lab also tests restricted-role SQL permissions, complete
ordered roots, cross-compartment rejection, wrong root, post-seal writes,
revocation, mTLS certificate authorization, genuine witness drain and crash.

## Second independently confirmed SQL completion bypass (P2)

An independent reviewer proved that the previously restricted
`zk1_gate_runtime` role could directly INSERT a `sealed_object` marker for an
object with **zero real chunks and no active admission**, bypassing the Node
`seal()` validation. This was reproduced on PostgreSQL 18.6 with a separate
non-superuser login, despite an earlier passing happy-path test. A new
restricted-role regression showed the issue **RED**; the repaired schema
introduces a `BEFORE INSERT` SQL trigger that requires `READ COMMITTED`, an
exact `OPEN` head and `ACTIVE` admission, the contiguous complete ciphertext
sequence and the exact SHA-256 versioned root recomputed **inside PostgreSQL**
before any durable seal. Forged missing-admission, truncated, mismatched-root
and stale-transaction attempts now fail; a legitimate authenticated worker's
seal still succeeds. This is not independent owner-device signature proof.

**Validation:** `node lab/issue-65-packet-b/run-shared-gate-postgres.js`
reported **18/18 passed, 0 failed, 0 skipped**, using disposable PostgreSQL
18.6 and verifying cleanup of only its labeled test container. The bounded
post-repair independent P1/P2 assessment is recorded separately when returned.

## Strict boundary

This is a **PG-only** physical WRITE guarantee under one dedicated
PostgreSQL primary and a trusted operator. It does not prove independent
multi-site consensus, online revocation of already exported ciphertext,
physical **network egress** fencing after a connection loss, real external
provider stop acknowledgements or that privileged database administrators
cannot mutate the schema. It does not turn completed chunks into a committed,
signed device manifest. The owner/device signature on the expected root,
normal upload/restore/version/cloud/sync operations and reversible migration
are still outstanding. No push, merge, deploy or release is implied.
