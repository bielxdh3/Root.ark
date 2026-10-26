# Issue #65 — V1 #128 -> V2 owner rollover preflight (DEV / read-only)

## Current architecture, inspected

- `zk1OpaqueCatalogCasLedger.js` and the browser's
  `rootark-zk1-browser-opaque-catalog-commit.js` intentionally cap V1 at
  **128**, including the durable SQLite history. Do **not** relax that bound,
  reset sequence to 0, or rotate the database behind existing pins.
- `zk1OpaqueCheckpointV2Client.js` and `zk1OpaqueCheckpointV2Remote.js`
  already implement opt-in **absolute sequence 129 and later**, through
  independent V2 CAS and FLOOR HTTPS/mTLS authorities, owner-approved intent,
  immutable SQLite journal, and dual `FINALIZED` signed receipts.
- `rootark-zk1-browser-authority-head-relay.js` currently permits
  **read-only** verification of a supplied signed V2 129...N intent chain,
  pinned owner grant, signed historical device endorsements, dual remote heads
  and protected ciphertext GET. It does not publish V2 content.
- The existing V2 mTLS fixture bootstraps a V2 predecessor checkpoint signed
  over **only its last V1 head #128**. That is not proof by itself that the
  *complete* 1..128 archive is retained. A new 128-record Merkle checkpoint
  has a different digest from that legacy single-record predecessor; it
  cannot be swapped in without explicit owner-authorized baseline migration.

## New independent preflight slice

Two **new** modules, with no edits to worker-7 catalog, backend or server files:

1. `src/services/zk1OpaqueCatalogV1RolloverPreflight.js` verifies **all 128**
   canonical CBOR headers and pages, signed by historical device signers
   supplied by an independently owner-authenticated signer-history resolver.
   It checks one checkpoint-signature/Merkle archive, unbroken
   sequence/digest continuity since genesis, archive root, full archive
   checkpoint digest, two fresh nonce-bound V1 CAS receipts and independently
   signed V1 FLOOR receipts, pinned and distinct signing authorities, and a
   short-lived Ed25519 owner-signed V1->V2 handoff.
2. `public/client/rootark-zk1-opaque-v1-v2-handoff-preflight.js` checks the
   handoff locally with WebCrypto, the OFFLINE owner SPKI pin, archive checkpoint
   and root pins, owner's independent witnessed head pin, independent V2
   authority key pins, scope, absolute sequence #128, epoch non-downgrade and
   a maximum 300-second handoff validity. It explicitly returns
   `archivedHistoryVerifiedHere: false`; the browser cannot infer that all
   128 records exist merely from an owner-signed summary.

The handoff owner signature uses the domain (NUL-terminated):

`Root.ark/zk-1/opaque-v1-v2-owner-rollover-handoff/v1\0`

over UTF-8 `JSON.stringify(handoff)`, in the exact fixed property order
defined by `FIELDS` in the Node module. The owner checks the current
independently witnessed V2 manifest/epoch and signs this external handoff.
The full certificate includes scope, `v1_sequence=128`, `v1_digest`,
`v1_archive_root`, `v1_archive_checkpoint`, V2 CAS/FLOOR/checkpoint
SPKI SHA-256 pins, `owner_revision`, `owner_digest`, `owner_epoch`,
`next_epoch`, 32-byte random nonce and expiry. `next_epoch` must equal
the already independently witnessed `owner_epoch`; a future unsigned epoch
is not preauthorized by a numerically larger value.

The new preflight additionally requires an **independently pinned V2
predecessor checkpoint digest**, byte-for-byte matching the complete 128-head
archive checkpoint. The two existing authorities must remain online and
prove the immutable current #128; both receipts are verified cryptographically
against independently pinned SPKIs. A second read rejects a concurrent or
rolled-back head. A local output never authorizes a catalog PUT.

## Strict V2 client/coordinator admission (DEV, opt-in)

The existing `createOpaqueCheckpointV2Coordinator` and
`Zk1OpaqueCheckpointV2Client` now accept
`requireFullV1ArchiveRollover: true` together with
`fullV1ArchiveRollover` (the complete input to `verifyRolloverPreflight`,
including the actual pinned V1 CAS/FLOOR mTLS clients). Missing evidence,
client/key/scope mismatch, any corrupt 1..128 record, an unapproved handoff,
or a checkpoint digest different from the externally pinned full archive
fails closed. The coordinator verifies signed V2 CAS and FLOOR `V1_BASELINE`
heads independently against exactly that full-history digest before initial
publication. Retries still verify the full V1 archive and use the existing
signed immutable V2 intent/predecessor chain for interrupted #129 writes.

In strict mode, the device client checks the authenticated baseline *before*
local SQLite append, and pins the strict requirement in its immutable SQLite
identity so restart cannot silently revert to the legacy behavior. The
read-only `verifyFullArchiveBaseline()` method returns
`v2WriteAuthorized: false`: a baseline read alone grants nothing. Live V2
publication still requires the separate owner/epoch validation, witness and
both V2 authority FINALIZED receipts implemented by the existing workflow.

Node 22/24 tests exercise real localhost HTTPS/mTLS V1 CAS/FLOOR advancement
through all 128 heads, independently signed V2 CAS/FLOOR baseline reads,
tampered single-head baseline refusal, missing approval refusal, and a strict
SQLite journal restart downgrade attempt. The existing 128 limit is unchanged.

This is a **new, explicit DEV mode**. Existing V2 journals and authority
databases initialized with a single-head #128 predecessor have not been
migrated or made write-safe. The V2 server authority does not yet enforce the
new full-archive proof independently of its client: a direct legacy V2
authority caller remains outside this strict gate. Proof of separate
independent operators, trusted offline provenance of supplied pins, and an
atomic owner-approved migration of previously written V2 history are not
established by localhost mTLS. Production/cutover remain **NO-GO**.

## Blockers, handoff contract and NO-GO

- Existing V2 startup currently allows the **single-head** #128 checkpoint.
  To switch to the **full 128-head** checkpoint, an owner-approved baseline
  migration must preserve all published 129+ proofs and update the independent
  V2 CAS and FLOOR pins atomically with rollback/fork protection. Without a
  pinned full-history predecessor matching both V2 authorities, this
  preflight **fails closed** and never claims rollout complete.
- The caller must independently verify the *historical signer resolver*
  against owner V2 history and the *current* `ownerHead` against a fresh,
  independently signed witness, before passing them in. Passing arbitrary
  signer callbacks, public keys, or witness state does **not** establish
  trust. This module does not replace
  `verifyRecoveryHistoryPublicV2`, the independent floor, or V2 admission.
- The caller must obtain key pins and the checkpoint digest **outside**
  the server response under inspection. The source/issuer of these pins is
  outside this standalone verifier's trust boundary.
- Edge WebCrypto check authenticates the owner handoff and independent pins
  only; Node validates the entire archive and signed terminal receipts.
  Integration requires both, plus existing V2 mTLS admission and hosted
  cross-device tests. The signed handoff alone never permits write.
- No server plaintext, no physical deletion, no reset/rollback of V1, no
  server DB or worker-7 changes, no V2 write activation or production claims.
