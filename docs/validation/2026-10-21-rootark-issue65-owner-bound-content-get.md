# Root.ark #65 — strict owner-rooted GET requires a signed content version and digest

## Confirmed provenance gap

The `signedHistoryRequired` protected store authenticates the entire public
device/keyring history, anchored to an independently provisioned genesis and
fresh witness head. That history does **not** commit to the local SQLite
content-version catalog. Before this patch, even that strict mode permitted
an Ed25519 GET with `expected_object_revision: null` and
`ciphertext_digest: null`, delegating selection of the latest opaque bytes to
the mutable database projection. A privileged SQLite writer can append a
forged contiguous revision, compute its own SHA-256 archive digest and move
the current projection to the forged bytes without removing UPDATE/DELETE
immutability triggers. Internal parity checks alone accept this local state.

## Change and test evidence

Before accessing the witness or CAS, `Zk1ProtectedObjectStore.authorize()`
now denies **unbound latest GET** when `signedHistoryRequired` is true.
The trusted signing device must bind an exact `expected_object_revision` and
the SHA-256 `ciphertext_digest` in its canonical Ed25519 GET authorization.
The SQLite transaction checks the archived revision's bytes against that
digest. An exact signed historical GET remains supported, including after
another local revision is appended.

TDD: `test/issue-65-protected-signed-history-authorization.test.js` first
reproduced **RED: Missing expected rejection** for a signed but unbound
GET. After enforcing the strict check, **GREEN: 2/2 PASS**. The test also
performs a hostile direct SQLite INSERT of revision 2 with attacker-generated
ciphertext/digest plus an UPDATE of the current projection. The unbound GET
stays denied and a valid, independently selected signed revision-1 digest
still retrieves the original revision-1 ciphertext.

The separate real pinned CAS/witness mTLS test now signs exact revision/digest
for its legitimate GET and continues to check active/revoked devices. Legacy
experimental stores without `signedHistoryRequired` retain their previously
tested latest-read behavior; no preexisting content is rewritten or deleted.

## Strict limits

The device can sign a forged digest if it mistakenly trusts an attacker-
controlled catalog to choose its expected revision/hash. This improvement
**does not** prove the provenance of that expected digest, detect total
object erasure, or establish externally durable object membership/monotonicity.
Such guarantees require independent per-object content commitments,
including authenticated absence/tombstones, bound to CAS/witness and physical
fencing of real provider writes/egress. The browser still verifies the
separately supplied expected ciphertext root before local decryption.

Production and release remain **NO-GO**. No GET socket, provider or
PostgreSQL physical STOP boundary was changed or promoted by this patch.
