# Opaque catalog v1: 128-head exhaustion and v2 rollover gate

Status: **DESIGN / NO-GO for rollover.** This document records the mandatory
protocol transition; no v2 checkpoint is accepted by the running v1 services.
The executable boundary proof is
`test/issue-65-opaque-cas-sequence-ceiling-evidence.test.js`.

## Isolated implemented primitive (not a rollover)

`src/crypto/rootark-zk1-opaque-catalog-checkpoint-v2.js` now exports four
opt-in operations: `createAuthenticatedOpaqueCatalogArchiveV2`,
`verifyAuthenticatedOpaqueCatalogArchiveV2`,
`createOpaqueCatalogInclusionProofV2` and
`verifyAuthenticatedOpaqueCatalogInclusionV2`. The primitive keeps original
canonical CBOR v1 headers, Ed25519 signatures, and opaque page bytes. It
verifies each historic device signature through a **caller-provided trusted**
`resolveCatalogSigner(header)`; the resolver must independently validate the
owner's then-valid device authorization and never trust the archived signer
identity without an authenticated owner history. The v2 archive signature is
made using a distinct, **independently pinned** Ed25519 checkpoint key.

Leaf, interior Merkle node, checkpoint signing and checkpoint digest use four
different v2 domain prefixes. A full archive verifier checks an absolute,
consecutive sequence, predecessor digest for every historical head, final
digest, canonical CBOR, signed page hashes, item order, archive Merkle root,
and the predecessor checkpoint digest. Inclusion proofs authenticate exact
historical bytes by index against the signed archive root. They do **not**
prove the intermediate chain without a verified complete archive or separate
consistency proof; callers requiring end-to-end continuity must invoke the
full archive verifier. The root is over a bounded range, not an arbitrary
server-provided digest. The primitive caps each archive at 128 heads and 8
MiB of serialized head/signature/page payload, with separate per-head/page
caps. All values remain zero knowledge: no content, plaintext names or keys.

Archived headers continue to carry the original v1 type because historical
signed bytes cannot be rewritten. **Only** the checkpoint format is v2.
The primitive can mathematically authenticate a data-only 128→129 chain but
never grants CAS admission, floor authority, browser permission or restore
authorization for 129. No service imports it and no v1 limits changed.
`test/issue-65-opaque-checkpoint-v2-merkle.test.js` exercises the isolated
archive and hostile mutation on Node 22 and 24.

## Confirmed v1 constraint

- `src/services/zk1OpaqueCatalog.js` validates both owner-signed headers and
  authority-signed CAS heads against `MAX_HEADS=128`; `verifyStoredChain`
  replays archived snapshots from **absolute sequence 1**, compares consecutive
  digests, audits re-endorsements, and revalidates physical ciphertext versions.
  Its local repair path admits only the immediately missing final snapshot.
- `src/services/zk1OpaqueCatalogCasLedger.js` stores every owner-signed header,
  signature and page body as an immutable SQLite WAL/FULL row. Startup checks
  `row.sequence === index + 1`, verifies all signatures and page hashes, and
  reconciles the complete history against an independently signed floor.
- `src/services/zk1OpaqueCatalogIndependentFloor.js` stores every transition
  in a second independently administered immutable SQLite history. Its startup
  derives the head from the number of rows, from 1; it rejects more than 128.
- `src/services/zk1OpaqueCatalogCasHttpsClient.js`,
  `src/services/zk1OpaqueCatalogCasService.js`,
  `src/crypto/rootark-zk1-opaque-catalog-client-v1.js` and
  `public/client/rootark-zk1-browser-opaque-catalog-commit.js` separately
  reject sequence 129. The browser denies new intents at sequence 128, while
  retaining the read path for signed sequence 128.

Increasing an individual maximum cannot enable rollover: an otherwise valid
Ed25519-signed head 129 is refused by another layer. Dropping rows or
restarting from 1 breaks authenticated continuity and rollback protection.
Removing all maxima without replacing complete-history scans admits
unbounded replay/verification cost. Full inventory snapshots may be near the
3 MiB request cap, and owner evidence may be near 2 MiB **per sequence**.
Bounded active verification does not imply bounded historical archive storage.

## Required domain-separated v2 records

Introduce a new owner-signed `opaque-catalog-checkpoint/v2` canonical CBOR
record with the exact scope, absolute `start_sequence` and `end_sequence`,
digest immediately before the range, digest of the final committed head,
previous checkpoint digest (zero only for the first), immutable prefix hash,
archived range Merkle root, item count, archive format/version, owner manifest
revision/digest, epoch, authorized signer identity and issuance time. The
archive must include original signed headers, header signatures, ciphertext
page bodies, CAS proofs/nonces and owner/signer-history evidence. Hash leaves
with separate v2 domain tags, canonical lengths, absolute sequence numbers,
and an unambiguous Merkle tree shape so missing, reordered, duplicated or
replaced snapshots fail verification. Do not substitute a mere archive URL,
digest list, local SQLite head or unverified file pointer for these bytes.

Independently pinned CAS and floor Ed25519 keys must endorse the *same*
checkpoint bytes and current absolute head digest, with distinct v2 signature
domains, exact nonce challenge and rollback floors. A current owner-witness
head must authenticate the live owner authority and non-revoked checkpoint
signer; preserve historical owner proofs so an archived signer can be checked
against its **then-valid** manifest without granting a revoked signer new
authority. Pins must come from the client/operator, never server JSON.

Add `opaque-catalog-head/v2`, `opaque-catalog-cas/v2` and
`opaque-catalog-independent-floor/v2` formats or an equally explicit,
reviewed version-negotiated envelope. The forward first head is **129**, its
`previous_digest` is exactly committed head 128's digest. The checkpoint has
its own monotonic checkpoint counter; it cannot reset the catalog sequence or
turn an already signed historical head into a new genesis.

## Atomicity and crash/recovery barriers

1. At fully committed head 128, verify complete immutable v1 histories,
   metadata re-endorsement, owner authorization, content inventory and signed
   independent floor. Never checkpoint a locally ahead or uncertain head.
2. Durably write/read back all exact archived history bytes to independently
   administered storage. Verify every leaf/root and an unambiguous archive
   inventory. Any missing history or provider uncertainty aborts retirement.
3. Authenticate owner checkpoint signature and independently commit an
   immutable floor checkpoint record referencing the same archived root,
   absolute sequence 128 and head digest. Bind its nonce, counter and
   predecessor checkpoint digest; a lost ACK requires a *fresh signed floor
   read* and exact-match reconciliation, never a negative-ACK assumption.
4. Commit the CAS-side checkpoint pointer and durable archive evidence with
   WAL/FULL, then reconcile its exact checksum against the independent floor.
   Keep old immutable rows until the archive is proven retrievable. Create a
   versioned schema/table; existing immutable DELETE/UPDATE triggers cannot
   simply be disabled to make compaction work.
5. Admit owner-signed CAS **128 -> 129** only after every authority has
   re-read and validated the same checkpoint and current owner head. A crash
   at any barrier must have a single fail-closed recovery answer, including
   when one service committed and another lost its ACK. Competing writers,
   stale epochs and stale checkpoint attestations must be rejected.
6. Reopen/recover from independently pinned floor and archived prefix, then
   verify only a bounded live suffix while maintaining the absolute cursor.
   To verify re-endorsement across a checkpoint, retain/read back the final
   complete predecessor inventory and independently verify physical versions.
   Historical `fetchSnapshot(sequence)` must still return authenticated bytes
   (with inclusion proof) for old sequences, not a synthetic empty snapshot.

## Compatibility, migration and release tests

V1 signed objects and receipts are immutable. Existing clients hard-reject
head 129. An upgraded server must negotiate v2 explicitly and return a
non-success **upgrade-required** response to v1 writers/readers once its head
requires v2; it cannot transparently send a v2 proof under a v1 signature
domain or silently reset to 1. Preserve existing v1 read behavior at <=128
while the scope is still genuinely at <=128. Backups, restores, migrations,
multi-host replicas and all client caches must carry and pin both the archive
root and the absolute independent floor, with complete historic retrieval.

Required executable gates before enabling any v2 write: 127->128->129
in real separate-process CAS/floor hosts; restart after every persistence
barrier and uncertain ACK; parallel writers, replayed nonce, replayed/forged
checkpoint, altered archive leaf/proof, missing archive/provider, rollback of
local/CAS/floor databases, stale/rotated/revoked owner keys, restore of an old
backup, historical fetch at 1/127/128/129, and genuine browser v1 refusal and
v2 authenticated read/commit. Include Windows/Node 22 and 24 fixtures and
report physical local durability separately from remote cloud independence.

The current boundary test proves that the v1 system stays fail-closed, **not**
that these v2 rollout requirements are implemented. Any v2 rollout must be
independently reviewed before it replaces the bounded v1 contract.
