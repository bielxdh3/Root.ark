# Issue #65 — authoritative versioned backup inventory (offline DEV)

public/client/rootark-zk1-authoritative-backup-inventory.js exports
createVerifiedSnapshot(input) and verifyBackupSnapshot(input). This is an
offline Node 22/24 client-side ciphertext-only reference verifier. It
does not expose an HTTP route, request server plaintext or CEKs, write any
server file, perform cloud I/O, or grant restore/cutover/production access.

The verifier requires all of these independently supplied authorities:

- Exact owner Ed25519 SPKI SHA-256, current recovery head, and owner-signed,
  genesis-to-current history checkpoints; the current non-revoked device grant
  must match the same head and scope.
- A portable owner-signed inventory checkpoint chain, its separately
  pinned final checkpoint SHA-256, inventory signer Ed25519 SPKI SHA-256 and
  key ID. Its final snapshot's SHA-256, sequence and root must match.
- The signed content-inventory genesis snapshot and every signed committed
  append receipt through the final snapshot. No gaps, forks, reordering,
  deleted versions or altered ciphertext digests are accepted.
- A complete, canonically ordered set of all object/revision ciphertext
  records from that owner-signed snapshot. Each record must match exactly
  (object_id, revision, epoch, ciphertext_sha256) and include a separately
  verifiable owner ciphertext-root checkpoint for its exact one-chunk bytes.

The resulting signed snapshot contains ciphertext and proof metadata only.
Its SHA-256 must be preserved by the owner independently. The verifier
preserves repeated object IDs with distinct consecutive revision numbers,
bounded to 64 version records / 8 MiB total ciphertext, and rejects partial,
unverified, or unordered versions.

completeRelativeToOwnerCheckpoint=true means ONLY that the supplied
snapshot matches every revision recorded by the particular owner-authenticated,
fully chained signed inventory checkpoint. That signature does not prove the
ledger saw every existing account/keyring object, that off-server custody or
replication is durable, that a later commit has not occurred, or that the
account's other keyrings are covered. Such claims remain false. The
independent owner checkpoint pin and current head must come from outside
the application server.

This module is a ciphertext inventory and snapshot verifier, not a
portable recoverable CEK archive. The existing
rootark-zk1-keyring-portable-archive.js explicitly rejects repeated
object IDs, even when version IDs differ. Its current format cannot
consume this multi-revision snapshot; do not label its output a complete
historical backup or silently omit revisions to fit it. The signed content
inventory tuple also lacks the application's opaque version ID, so binding
that field requires a separately signed protocol extension. Version-aware
CEK wrapping, historical restore integration, and a provider-independent
completeness proof are still separate blockers.

public/client/rootark-zk1-owner-account-backup-roster.js additionally
offers createOwnerRoster() and verifyOwnerRosterCoverage() for a separately
pinned owner-signed list of keyring scopes and their individually verified
backup digests. The verifier accepts only genuine in-memory verified proof
objects from verifyBackupSnapshot(), tied to the SAME pinned owner SPKI and
account. It rejects an omitted third keyring, duplicate scope, foreign owner
and forged boolean success indicators. This establishes completeness relative
to the owner-declared, independently pinned ROSTER, not an independently
discovered actual account keyring population. Its result intentionally does
not expose an ambiguous allKeyringsVerified field or claim full-account
completeness.
