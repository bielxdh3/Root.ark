# Issue #65 — Independent legacy V1→V2 stage witness (opt-in DEV)

`Zk1LegacyArchiveStageWitness` is an **operator-only, separate-process**
monotonic evidence ledger for already signed V1 1..128 / legacy V2 #129+
dual-archive staging. It never alters source data, migration checkpoints,
CAS/FLOOR authority databases, signed predecessors, backups or trash.
**No write, restore or destructive cutover is authorized.**

The operator provisions a separate witness Ed25519 keypair, a private SQLite
directory and six pinned keys from independent custody: owner, archive
checkpoint, V1 CAS/FLOOR, V2 CAS/FLOOR. All seven keys must differ. The
persisted trust configuration binds the expected scope and every key pin,
and is immutable. SQLite uses WAL and `synchronous=FULL`, no-clobber file
bootstrap, private SQLite-path/sidecar checks, immutable triggers and
an `IMMEDIATE` transaction for generational compare-and-swap.

`stageFromLiveReadback({readbackInput, expectedHead})` repeats
`verifyLegacyArchiveDualReadback`: independent TLS-pinned V1 and V2
authorities, complete authenticated V1 archive, owner consent, both V2
signed stage readbacks, and final independent owner witness. It also rechecks
the candidate's canonical subject, role pins and terminal signatures before
persisting a new `STAGED` witness-signed receipt. A null `expectedHead` is
allowed only for an empty ledger. Each subsequent operation must supply the
exact last signed receipt, including generation and hash. Concurrent writers
compete on the same SQLite CAS; only one can advance.

`stageSignedEvidence` verifies the cryptographic candidate without repeating
the remote owner and historical archive queries. It returns the narrower
`SIGNED_STAGE_EVIDENCE_ONLY` result, suitable for forensic archiving. It is
**not** evidence of a current owner, complete historical archive or physical
independence. Callers cannot supply synthetic transport clients to the live
method, which uses the existing strict pinned-client verifier.

`withdraw({expectedHead})` appends a witness-signed `WITHDRAWN` tombstone
at the next generation. This reverses **the operator's evidence stage**,
while leaving both remote write-quarantine markers and all ciphertext
untouched. A new stage can be recorded with a newer generation; old heads
and duplicate withdrawals are rejected. On restart, compare the newest
witness receipt to a separately preserved trusted head via
`audit(minimumHead)`. A valid older SQLite copy is refused when the retained
head points to a newer generation. If both DB and independently stored head
are rolled back, this protection is lost.

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
