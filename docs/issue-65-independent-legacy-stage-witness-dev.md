# Issue #65 — Independent legacy V1→V2 stage witness (opt-in DEV)

`Zk1LegacyArchiveStageWitness` is an **operator-only, separate-process**
monotonic evidence ledger for already signed V1 1..128 / legacy V2 #129+
dual-archive staging. It never alters source data, migration checkpoints,
CAS/FLOOR authority databases, signed predecessors, backups or trash.
**No write, restore or destructive cutover is authorized.**

The operator provisions a separate stage-ledger Ed25519 keypair, a private
SQLite directory, six keys from independent custody (owner, archive
checkpoint, V1 CAS/FLOOR, V2 CAS/FLOOR), **and a separately provisioned
current-owner witness Ed25519 public key, key ID and externally retained
minimum witness head**. All eight signer keys must differ. The owner witness
pin and minimum head are mandatory `trustedOwnerWitness` constructor inputs,
never derived from the request's mutable `readbackInput.ownerTrust`.
The persisted trust configuration binds the expected scope, all signer pins,
the owner witness key ID and the minimum revision/sequence/digest floor,
and is immutable. SQLite uses WAL and `synchronous=FULL`, no-clobber file
bootstrap, private SQLite-path/sidecar checks, immutable triggers and
an `IMMEDIATE` transaction for generational compare-and-swap.

Security repair (ledger v2): **offline stage promotion is disabled**.
The former `stageSignedEvidence` method is now fail-closed, even when its
CAS/FLOOR signatures are genuine. Those signatures authenticate authority
archival fields but do **not** authenticate subject assertions
`owner_revision`, `owner_epoch`, or `owner_digest`. An attacker could
forge those fields and recompute the subject digest. Only
`stageFromLiveReadback`, including its nonce-fresh pinned owner/V1/V2
readbacks, may commit STAGED. A caller-supplied owner witness signing key or
lower minimum head is rejected before any asynchronous readback; cryptographic
verification uses an immutable copy of the constructor trust. This prevents
an attacker from forging an apparently current owner witness after revocation
while reusing genuine earlier signed CAS/FLOOR staging evidence.

Every signed v2 receipt cryptographically covers `provenance`:
`LIVE_OWNER_V1_V2_READBACK` for STAGED and
`OPERATOR_WITHDRAWAL_OF_LIVE_STAGE` for WITHDRAWN. Receipt validation,
restart, `audit(minimumHead)` and CAS/withdrawal enforce provenance.
The receipt signature domain, type and persisted trust hash have been
versioned from v1 to v2; **old v1 ledger databases are rejected on
restart**, never silently promoted. Retain historical v1 evidence
separately and provision a new v2 witness with genuine live readback.

`stageFromLiveReadback({readbackInput, expectedHead})` repeats
`verifyLegacyArchiveDualReadback`: independent TLS-pinned V1 and V2
authorities, complete authenticated V1 archive, owner consent, both V2
signed stage readbacks, and final independent owner witness. It also rechecks
the candidate's canonical subject, role pins and terminal signatures before
persisting a new `STAGED` witness-signed receipt. A null `expectedHead` is
allowed only for an empty ledger. Each subsequent operation must supply the
exact last signed receipt, including generation and hash. Concurrent writers
compete on the same SQLite CAS; only one can advance.

Offline signed CAS/FLOOR evidence can be archived or inspected outside
this witness ledger for forensic purposes, but cannot create a STAGED head,
be used after a WITHDRAWN tombstone to re-stage, or attest owner liveness.
Callers cannot substitute the independent witness signer, key ID, rollback
floor, or synthetic TLS transport clients in the live method. Provisioning a
new minimum head requires a new stage ledger bootstrap; it cannot silently
reinterpret an existing signed ledger under another trust policy.

`withdraw({expectedHead})` appends a witness-signed `WITHDRAWN` tombstone
at the next generation. This reverses **the operator's evidence stage**,
while leaving both remote write-quarantine markers and all ciphertext
untouched. A new stage can be recorded with a newer generation; old heads
and duplicate withdrawals are rejected. On restart, compare the newest
witness receipt to a separately preserved trusted head via
`audit(minimumHead)`. A valid older SQLite copy is refused when the retained
head points to a newer generation. If both DB and independently stored head
are rolled back, this protection is lost. A constructor-pinned witness floor
alone does not prove external liveness: the custodian must independently
retain and advance it with revocations, outside request-controlled state.

Every result returns `v2WriteAuthorized:false`, `restoreAuthorized:false`,
`destructiveCutoverAuthorized:false`,
`independentMonotonicStageWitnessProven:false` and
`externalProviderDurabilityProven:false`. A private local SQLite witness
ledger and software signature do not prove true physically independent
operator custody or power-loss durability. This implementation provides
no production witness endpoint, externally operated monotonic adapter,
distributed transaction, physical provider readback/restore, or dual-anchor
successor write envelope. The operator must separately enforce custody,
transport and immutable external receipt retention. PR #228 stays **DRAFT
/ NO-GO** until the missing guarantees and hostile tests are demonstrated.
