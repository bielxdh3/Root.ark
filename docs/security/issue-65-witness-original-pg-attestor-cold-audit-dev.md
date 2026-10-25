# Issue #65 — witness-retained ORIGINAL PG18 attestor proof (DEV / NO-GO)

The strict `Zk1WitnessCasAnchorFloor` now retains the **original, canonical,
independently Ed25519-signed PostgreSQL physical readback** and the separate
signed inventory commitment. Each committed CAS event stores an immutable
`original_pg_evidence` blob containing the exact original signed bytes,
witness-generated 32-byte nonce, scope and operation (including `operation_id`,
object, revision, epoch and ciphertext digest), attestor Ed25519 SPKI and the
validated final inventory sequence/root. No secret key, PG credential,
plaintext or CEK is persisted in this record.

The witness signs the SHA-256 of this blob in the physical-fence v3 signature
domain. The blob remains bound to its exact signed CAS event, operation ID,
scope, inventory head and independent attestor identity. The strict SQLite
identity pins `operation-id-v3-original-pg-attestor`; restarting an old v2
physical fence as v3 **fails closed** rather than silently adding an unverified
column. A separately approved, physically durable v2→v3 migration of existing
anchors is still required. Never reset an existing witness high-water to zero.

Each original proof is capped at 8 KiB, and total retained PG evidence at
64 MiB; the previous snapshot cap of 64 MiB remains separately enforced.
Malformed/missing evidence or a changed attestor SPKI, nonce, signed operation,
receipt, checkpoint sequence/root, or raw Ed25519 signature causes denial.

`auditRetainedPhysicalEvidence()` verifies the complete retained chain against
the already pinned inventory and attestor public keys without contacting
PostgreSQL. A restarted strict witness cannot use synchronous `freshHead()`
to sign before successful cold audit. `freshHeadAsync()` and the historical
`proveCommittedPhysicalFence()` path perform this check automatically; new
strict advances also require it. A cached audit is valid only while the
originally signed physical-fence chain digest remains identical; file/SQLite
mutation checks still apply. This proves the original PG readback signature
was valid at its **signed historic issuance time**, not that PG is presently
reachable or that a fresh WAL flush happened after restart.

The signed per-operation evidence preserves the **target operation's** original
PG attestation. The full multi-page authenticated ancestry of transient PG
challenge responses remains runtime-verified but is not independently archived
for every older operation in this increment. The witnessed inventory snapshot,
local WAL/FULL barrier and original target signature therefore do **not** prove
whole-provider archival completeness, hardware independence, S3/Drive/WebDAV
durability, cross-service atomicity or power-loss survival. Full physical
ancestry archival, external monotonic retention/pins and hostile multi-host
restore must be independently implemented and tested before production.

Adversarial regression tests exercise retained original bytes, signer
substitution, forged signature, replay against a different `operation_id`,
second witness instance with its PG transport deliberately offline, refusal
of signed heads before cold audit, and tampering a disposable SQLite copy.
The separate real PostgreSQL 18 lab needs the disposable admin/runtime/attestor
connection URLs and is not replaced by synthetic protocol proofs.
