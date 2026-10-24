# Issue #65 — V2 direct-authority full-128 admission (DEV)

The V1 signed opaque-catalog CAS stops at absolute sequence **128**. Its V2
successor continues at 129+ through two different HTTPS/mTLS authorities,
CAS and FLOOR. Previous strict validation checked the local coordinator but
did not stop a caller from directly invoking V2 authorities with a weaker
single-head-only predecessor checkpoint.

## New write boundary

`OpaqueCheckpointV2Authority` now has an **authority-enforced strict mode**
when provisioned with a complete owner-approved, independently pinned
`requireFullV1ArchiveRollover=true` proof. For that instance,
`prepare`, `commit`, `finalize` and `attestFinalized` all revalidate the
full history before mutations; `head()` remains readable without such proof.
Legacy authorities remain compatible with their earlier protocol. **This
step does not make full-archive enrollment mandatory for every constructor.**

When strict full128 is configured for a new V2 authority, its bootstrap
stores an immutable `strict_rollover` row containing the complete-archive
Merkle root and the exact V2 predecessor checkpoint digest. Restart with
`bootstrapNew=false` rejects omission, mode downgrade or mismatch of this
pinned root/checkpoint **before opening SQLite writable**. An unexpected
legacy DB cannot pretend to be a strict one. Existing legacy V2 snapshots
can still be inspected through their already signed head proofs. A legacy
authority with no strict marker can still use its earlier write contract:
this is the **remaining last-head-only bypass** awaiting migration.

Before each mutation the authority rechecks the independently signed live
owner witness (same head revision/digest), current operator-held Ed25519
handoff with <=300-second lifetime and no epoch downgrade, ALL 128
cryptographically signed/canonical catalog snapshots + immutable archive
checkpoint, fresh nonce-bound V1 CAS and independently signed V1 FLOOR
terminal receipts. It checks owner and authority SPKI pins, the exact
V2 predecessor checkpoint and archive root against its persisted row.
The exact same V1 #128 genesis / Merkle anchor must be accepted by CAS and
FLOOR; the server never accesses CEKs, plaintext or client secret keys.

The local method `renewFullV1ArchiveOwnerHandoff({handoff,
ownerSignature,ownerHead})` accepts a **new** owner-authorized <=300-second
approval only after rechecking the entire independent proof, V1 terminal
and current signed witness. Invalid renewal leaves the old verified proof
unchanged. This is in-memory: after a restart the operator must re-present
the full independently sourced archive and a fresh signed owner handoff.
No server-generated substitute, unsigned timeout extension or magic reset.

## DEV limitations and integration blockers

- This is scoped to `OpaqueCheckpointV2Authority`'s V1-128-based rollovers.
  Other V2-from-genesis protocols are **not** modified or redirected.
- The currently installed preflight requires the caller to verify the
  owner-authenticated historical signer resolver and current V2 owner
  history externally. The authority cryptographically checks the current
  witness head against the supplied owner head, but full V2 history
  admission still belongs to its existing `inspectIntent` path.
- An owner-approved full-128 Merkle checkpoint must **match the independently
  pinned V2 baseline on BOTH remotes**. Already finalized legacy 129+
  histories rooted in a *last-head-only* #128 checkpoint cannot be reset
  or repinned in place. They need a separate two-authority migration, and
  cannot enter this new strict mode until an owner-approved migration. Old
  legacy mode stays unmodified and may still write.
- Earlier DEV mTLS canaries using a last-head-only #128 checkpoint still
  exercise that older contract and must be migrated to a full-archive anchor
  **before making strict enforcement mandatory-by-default**. Disabling
  legacy writes immediately makes the existing V2 lifecycle regression red.
  No production or cloud fsync guarantee, no deploy, no merge, no cutover.
