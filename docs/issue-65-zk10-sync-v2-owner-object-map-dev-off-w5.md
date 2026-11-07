# Issue #65 — SyncV2 ↔ ZK10 exact owner-signed object map (W5, DEV-OFF)

This change supplies a **non-authorizing client-side cryptographic verifier**.
It adds no HTTP route, plaintext handling, migration, persistent state, key
enrollment or operator permission. It does not imply an approved ZK10 cutover.

## Input and verification boundary

`src/crypto/rootark-zk10-sync-v2-owner-object-map-v1.js` requires trust
provided by the embedding client/operator **outside** SyncV2 JSON, JWT and
the storage server. The verifier is created with three independent bundles:

1. `sourceAuthority`: immutable SyncV2 owner account/store/username/compartment
   certificate signed by its independently pinned owner provisioner, bound to
   independently pinned physical witness and CAS keys and its retained digest;
   independently pinned device registry, plus a fresh registry readback.
2. `zkAuthority`: the independently pinned ZK owner root and immutable account,
   signed owner rotation + ZK10 cutover history, and the separately retained
   current owner-cutover digest. The existing owner-signed inventory root must
   prove inclusion of the exact target `(object_id, revision, ciphertext_sha256)`.
3. `mappingAuthority`: a separate Ed25519 public key with an independently
   retained minimum mapping floor `(sequence, digest)`, and a genuinely external
   `readCurrentHead(challenge)` implementation. The verifier creates a new
   random 32-byte challenge and accepts only that challenge in the external
   authority's Ed25519 signature over current mapping digest, account IDs and
   monotonic sequence. The authority key must differ from **all owner signing
   keys, including valid owner rotations**, provisioner, witness and CAS keys.

Before owner-rotation and cutover verification, both signed histories are
recursively snapshotted through own data descriptors. The snapshot rejects
Proxies and accessor properties; both signature verification and cutover digest
therefore use the **same immutable copy of the signed cutover chain**. Two
separately valid owner-signed cutovers cannot be spliced to pair the inventory
root of one with the independently retained cutover digest of another.

The owner-signed canonical map binds exact SyncV2 account/store/compartment,
operation/object/file/version IDs, revision counter + device, `epoch-N` key
epoch, and SHA-256 of **decoded ciphertext bytes** to the ZK immutable account,
ZK account/object ID, object revision/epoch and target ciphertext-byte SHA-256.
It also binds the current owner generation and signed cutover digest, mapping
sequence, previous mapping digest and owner nonce. The SyncV2 device signature,
envelope AAD/nonce/tag digests, trusted device pin and current revocations are
checked before any result is returned. An old map requires a current external
challenge response; a head behind the independent floor is refused. A map at
`floor + 1` must link to the floor digest, and a gap greater than one refuses
until an independently verified/re-pinned intermediate floor exists. A single
verifier rejects repeated or concurrent reuse of an accepted sequence.

The injected `readCurrentHead(challenge, { signal })` is bounded to a 1500 ms
deadline by default (configurable only within 5–5000 ms). Each verifier admits
at most 16 outstanding native read promises by default, with an additional
process-wide ceiling of 64; explicit bounded options may adjust the per-verifier
limit within 1–64. An expired or caller-aborted read is denied without waiting
for its native promise to settle, and a late signed
head cannot re-enter verification or consume the mapping sequence. If the
native callback ignores its AbortSignal, its slot stays occupied until its
promise actually settles. A monotonic deadline check also rejects a late
valid return from a synchronous callback that blocked the JS event loop;
JavaScript cannot preempt that native blockage. Callers may supply an
`AbortSignal` as the optional `verify(input, { signal })` argument. These
budgets do not attest an independently operated mapping authority.

**Remaining external blockers:** This module does not implement a trusted
SyncV2↔ZK account enrollment ceremony, independently operated mapping signer,
authenticated fresh readback, independently durable monotonic floor/CAS, or
re-pinning after restart. It cannot establish that the SyncV2 bytes were ever
physically stored, that a ZK migration/re-encryption has occurred, that the
owner-controlled inventory is historically complete, or that any backing
provider retained ciphertext. In-memory rejection of repeated verifications
is not a durable replay ledger. Tests use ephemeral synthetic keys and a
synthetic authority callback, not real custody or external migration approval.

The result deliberately returns `authorizesIo: false`,
`independentCustodyProven: false` and
`historicalLegacyCompletenessProven: false`. Runtime cutover remains blocked
on independently administered owner/issuer mapping, durable fresh current
head/nonce/CAS floor, corpus proof and end-to-end I/O fences.

Focused regression: `node --test
test/issue-65-zk10-sync-v2-owner-object-map.test.js`.
