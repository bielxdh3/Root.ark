# Issue #65 — V2 remote checkpoint endorsement, opt-in

**Status: experimental / NOT production-ready.** This milestone implements
durable, independently pinned *local* CAS and floor v2 checkpoint authorities
in src/services/zk1OpaqueCheckpointV2Remote.js. Each runs on its own
SQLite WAL/FULL, mTLS listener and Ed25519 private key. This is not cloud
or multi-host physical independence.

## Preconditions

* Before every v2 operation, the coordinator verifies fresh independently
  signed v1 CAS and floor mTLS heads at **absolute sequence 128**, with
  identical digest, distinct key pins and floor-to-CAS fingerprint linkage.
* Each v2 authority pins the scope, owner-history genesis, checkpoint signer,
  owner signer, CAS/floor keys, predecessor v1 head and previous v2 checkpoint
  digest in immutable local configuration.
* The one-header canonical Merkle archive at **absolute 129**, checkpoint
  signature and owner approval are verified in both independent authorities.
  Owner approval has a distinct domain and binds the operation ID, both
  authority fingerprints and exact final checkpoint/head digests.
* Both separately verify owner-rooted public recovery history, current
  independently signed witness head, epoch, signer enrolment and revocation.
  The owner-approval signer itself MUST be a currently authorized device
  from this authenticated history.

## Recoverable two-authority protocol

FLOOR persists a full immutable intent as PREPARED and signs it. CAS verifies
that receipt and persists CAS_COMMITTED. FLOOR verifies CAS's signed receipt
before FINALIZED, then CAS verifies FLOOR's final signature before itself
finalizing. On each step, SQLite WAL/FULL and immutable state-transition SQL
triggers protect against deletion/downgrade. The coordinator only returns
V2_CHECKPOINT_BOTH_FINALIZED_LOCAL_ONLY after fresh signed readbacks of both.
Disconnected acknowledgments are uncertain and can be reconciled by exact
operation ID/intent after restart. A pending partial commit is fenced, not
treated as published. Only the strict 128-to-129 boundary is supported.

## Adversarial tests

test/issue-65-opaque-checkpoint-v2-remote-mtls.test.js on Node24 writes
**128 real v1 CAS+floor commits** over mTLS to distinct SQLite stores before
v2 rollover. It tests owner history revocation of signer A; newly enrolled B
can approve, while signed-but-revoked A and forged owner keys fail. It drops
CAS ACK after durable local commit, restarts SQLite and mTLS servers, then
reconciles FLOOR PREPARED -> both FINALIZED. It verifies replay/fork refusal
and leaves v1 at 128. A second scenario runs CAS and FLOOR in **two separate
Node24 OS processes**, with distinct SQLite, TLS and Ed25519 signing keys,
under concurrent clients. This is loopback, NOT independent cloud hosting.
The witness private key shared by the fixture processes is test-only.

## Remaining NO-GO boundaries

* This is a **fenced distributed protocol**, not one physical atomic disk
  transaction across CAS and floor. Cloud, multi-host and correlated power
  failure/rollback resistance are NOT proven by loopback.
* The v2 predecessor checkpoint digest at sequence 128 is pinned and signed
  but not reverified against a complete remote historical checkpoint archive
  by bootstrap. External monotonic checkpoint floor and full recovery
  continuity remain required before production.
* Owner/witness endpoints and trust are caller provisioned; an independently
  administered witness, owner key rotation/revocation authority recovery,
  long-offline pending reauthorization and disaster restore still need work.
* There is **no** browser/sync/restore integration or global seq129 admission.
  Returned outcomes explicitly declare publishedToBrowser=false,
  remoteCloudDurabilityProven=false and
  atomicCrossDatabaseTransactionProven=false. **V1 hard max128 is unchanged,
  and production global sequence 129 remains NO-GO.**
