# Root.ark #65 — portable owner-signed checkpoint and peer-held rollback floor

**CLIENT-SIDE CRYPTOGRAPHIC BUILDING BLOCK. NOT AN INDEPENDENT AUTHORITY.
DOES NOT AUTHORIZE PROTECTED I/O OR RECOVERY. PRODUCTION NO-GO.**

Module: `public/client/rootark-zk1-owner-signed-checkpoint.js` (UMD
WebCrypto, also importable in Node tests). No server-side private key, admin
master key, new production route, persistent database or destructive migration
is introduced. **The checkpoint bytes and the pinned owner public key must
be retained on a trusted client/off-server medium**; this module does not
provision, persist or protect that medium.

## Signed wire and trust boundaries

`signOwnerCheckpoint` demands a nonextractable WebCrypto Ed25519 private key
plus the corresponding caller-pinned verification key. It snapshots all
caller-controlled scope IDs, device name, public-key ID, monotonic sequence,
revision, 32-byte manifest digest and previous checkpoint digest before the
first `await`. It signs the canonical RFC 8949 text-key map:

`schema, account_id, compartment_id, keyring_id, device_id,
signer_key_id, revision, manifest_digest, sequence,
previous_checkpoint_digest, issued_at`

using `Root.ark/zk-1/owner-history-checkpoint/v1\0` domain separation.
The complete signed record hash uses the distinct
`Root.ark/zk-1/owner-history-checkpoint-hash/v1\0` domain. The result is
a compact JSON/base64url wire checkpoint; names/metadata are **public
commitments**, not protected plaintext.

`verifyOwnerCheckpoint` checks exact keys, canonical base64url, trusted
account/compartment/keyring scope, matching provisioned owner Ed25519 public
key and key ID, deterministic CBOR signature, and a contiguous chain. The
first checkpoint requires sequence 1 and no predecessor. Every successor
must link the independently verified previous full signed-record digest,
advance sequence exactly once, not decrease timestamp or revision, and never
change digest at an unchanged revision. Branded predecessor metadata is
kept only in a private `WeakMap`; caller-created objects cannot stand in
for verified predecessors. The predecessor's **original Ed25519 signature
must also validate under the current verification CryptoKey** in BOTH
signing and verification. Repeating the old `signer_key_id` while swapping
to a fresh Ed25519 key cannot silently rebind the chain. A signed key
rotation would require a separately specified, owner-approved protocol.

`checkCandidateHeadAgainstCheckpoint` rejects a candidate head behind the
owner-held floor or with a different manifest digest at the same revision.
It returns only `monotonicOnly:true`,
`freshWitnessVerified:false`, `authorizesProtectedIo:false`, and
`authorizesRecovery:false`. **It does not verify a candidate head's
CAS/witness TLS source or signature.** A higher arbitrary value can be
monotonic relative to the checkpoint without being a valid new manifest.
Callers must independently authenticate its CAS/witness provenance and
freshness before giving it any significance.

## RED→GREEN and targeted evidence

`test/issue-65-browser-owner-signed-checkpoint.test.js` proves the
WebCrypto signature against independently constructed Node deterministic
CBOR and Ed25519 verify; executes UMD in two **distinct browser VM realms**
with independent branded-proof stores and imports signed JSON wire data
between them; exercises replay/truncation, scope/key mismatch, missing
predecessor, corrupt signature, equal-revision fork, stale head, mutable
caller bytes and fabricated proof. An independent read-only reviewer found
a conditional P2 chain-key substitution flaw: a valid successor could be
signed with a different private key carrying the same key ID. The test
reproduced this in RED; private predecessor signed-message/signature
verification under the **current public key** fixed it in GREEN.

A separate test combines this module with the existing
`inspectZk1ExperimentalRemoteSignedHistory` signed public v2 chain
checker. It first accepts manifest revision 2, then changes both **local
in-process CAS and witness adapters** to offer genuine revision 1
signatures. The witness produces a **fresh nonce-bound, valid Ed25519
signature over the old head**, not replayed bytes. The existing verifier
without an independently retained floor can accept that jointly restored
state; the separately retained owner checkpoint at revision 2 detects it.
Restoring revision 2 passes again. This is **not a real two-host restore**:
test adapters and private witness signing key share one trusted local
process; it establishes only a cryptographic conditional invariant.

## Remaining normative requirements

Provision owner keys from signed/PoP-verified active devices, bind them to
trusted history, and retain checkpoints on truly independent, rollback-safe
client custody across sessions/hosts. Define authenticated key rotation and
owner-approved transfer, durable client high-water persistence, and how a
server-controlled JavaScript origin cannot erase/substitute local roots.
Implement independent operator CAS/witness, distributed GateAuthority,
physical remote-socket STOP, cloud providers, normal browser UI, Android
protocol alignment, sync/WebDAV, backup/restore and the complete dual
recovery cutover. No operational host independence, provider linearization,
destructive migration or production authorization is claimed or performed.
