# Issue #65 — Legacy V2 remote authority full-128 archive migration, phase 1 (DEV)

Status: **PARTIAL DEVELOPMENT / NO-GO**. This is an explicit, irreversible
**write-quarantine stage**, not a complete legacy 129+ migration and not a
production cutover. It does not silently rewrite a signed checkpoint.

## The two different roots must coexist

Legacy V2 CAS/FLOOR authority `config.base_checkpoint` stores the signed
last-head-only checkpoint at V1 absolute sequence 128. Legacy signed V2 #129+
intent records, immutable predecessor receipts, and existing device journals
are rooted in that exact digest. A fresh full 1..128 V1 archive has a different
Merkle checkpoint and archival root. The two checkpoints are **not equal** and
must never be substituted for one another, even by an authorized operator.

`OpaqueCheckpointV2Authority.stageLegacyArchiveMigration()` is an
operator-local method, not a public mTLS endpoint. It requires:

- Fresh complete V1 1..128 archive; independently pinned V1 CAS/FLOOR,
  owner, checkpoint, V2 CAS/FLOOR keys; valid owner Ed25519 handoff with a
  real current witnessed epoch; complete 128-item signed/canonical history.
- A separate fresh Ed25519 **owner migration consent** using the domain
  `Root.ark/zk-1/opaque-checkpoint-v2-legacy-archive-migration/v1\0`, binding
  scope, **old** legacy baseline, exact current legacy sequence/digest/
  checkpoint/operation, **new** full archival root/checkpoint, both V2 signer
  pins, current owner head and epoch, random nonce and ≤300-second lifetime.
- A fresh nonce-bound HTTPS/mTLS `head()` read from the independently pinned
  **other** authority, agreeing exactly with the local fully verified legacy
  terminal state. Every existing V2 transition must already be FINALIZED;
  PREPARED/CAS_COMMITTED disagreements cannot stage.

Only on success is an immutable stage row installed in a `FULL`-synchronous
SQLite immediate transaction after rechecking local head and sequence. This
row **does not change** `config`, `transitions`, any existing signed intent,
owner approval or predecessor receipt. Native SQLite INSERT/UPDATE triggers
stop even a concurrently running older writer using the same file. The
authority refuses `prepare`, `commit`, `finalize`, `attestFinalized` once staged;
`head()` and historical signed readback remain intact. A restart without
specifying any migration option cannot resume writes; its staged row is
rechecked, including the original owner signature and permanent legacy pin.

The two authorities are staged separately. A crash between the first and
second stage **never constitutes agreement**. The first authority stays
fenced, the other must be quarantined by its operator before this can become
a safe two-party cutover. Stage responses report
`independentlyReconciledAcrossAuthorities: false` and
`v2WriteAuthorized: false`. No automatic unquarantine or downgrade is offered.

## Remaining protocol prerequisites for phase 2 — do not fake these

1. **Durable two-authority stage attestation:** Both independent operators
   must sign receipts binding the exact owner migration consent hash, both
   current legacy terminal receipt identities, old and new archival roots,
   epoch, operation and monotonically anchored fencing generation. Each side
   must verify the other's signature and an independent witness, not trust a
   client-provided state flag or an in-memory boolean.
2. **Crash-safe reconciliation:** Persist PREPARED/COUNTERPART_PREPARED/
   COMMITTED states with monotonic fencing, explicit refusal of rollback,
   replacement or competing migrations. A crash after only CAS or FLOOR
   stages must remain read-only until the matching counterparty is proven.
   Two SQLite databases alone are not an atomic cross-host transaction.
3. **Versioned signed bridge for future writes:** The existing strict V2
   intent schema binds its `previous_checkpoint_digest` to the old 129+ chain.
   It cannot encode a second archival anchor. A new reviewed owner-signed
   versioned successor envelope must bind **both** the immutable legacy
   terminal receipt chain and newly authenticated full-128 archive, without
   relabeling the old digest or invalidating any #129+ proof. Its client and
   both authorities require coordinated version negotiation; old clients
   must fail closed for new protected commits, while old reads still verify.
4. **Write authorization after dual activation:** Every protected commit must
   verify a fresh independently signed peer activation/fencing state plus
   current owner epoch, not merely a local SQLite marker. A partially active
   authority must not publish alone. Operator-approved migration rollout
   requires exhaustive adversarial mTLS, restart, revocation and rollback
   testing on genuine independently pinned authorities.
5. **External rollback limits:** Removing a local SQLite table or restoring a
   complete pre-stage database can defeat its local triggers. Independent
   monotonic witness/custody must anchor stage/activation to detect this.
   No external provider durability, cross-host atomicity or power-loss proof
   is claimed here.

The existing `Zk1OpaqueCheckpointV2Client.migrateLegacy129()` migrates a
**local device journal only**; it must not be mistaken for migration of remote
CAS/FLOOR root identities. Legacy mTLS authorities not explicitly staged
retain their original DEV write behavior; this phase does **not** solve the
universal direct-authority bypass. Operators must not deploy a mixed state
or advertise `#65` complete. Preserve both old and new proof corpora.
