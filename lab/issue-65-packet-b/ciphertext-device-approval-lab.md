# Root.ark issue #65 — experimental ciphertext device approval v1

**Status: cryptographic experiment only; non-authorizing.**

The isolated `src/crypto/rootark-zk-ciphertext-device-approval-v1.js`
defines a proposed deterministic-CBOR Ed25519 signing profile. The existing
approved v2 recovery manifest carries `account_id`, `compartment_id`,
`keyring_id`, `revision`, `current_epoch`, `devices`, each device's
`authorization_key_id`/`authorization_public_key` and its revocation epoch.
The normative wire-type registry covers recovery witness/CAS proof objects;
**it does not assign a released ciphertext commitment approval encoding**.
This candidate introduces no deployed or backward-compatible protocol claim.

Proposed proof `type` is `rootark-zk1-ciphertext-device-approval/v1`.
Signature preimage is:

`ASCII("Root.ark/zk-1/ciphertext-device-approval/v1") || 0x00 || RFC8949_deterministic_CBOR(unsigned_fields)`.

The exact unsigned map contains `type`, `suite="rootark-zk-1"`,
`account_id` (16 bytes), `compartment_id` (1–128 bytes), `keyring_id`
(16 bytes), `object_id` (canonical 22-char base64url/128-bit opaque ID),
`object_revision` (positive safe integer), `manifest_revision` (positive safe
integer), `manifest_digest` (32 bytes), `keyring_epoch` (1–64),
`expected_chunk_count` (1–4096), `expected_root_hash` (32 bytes, corresponding
to the existing `Root.ark/zk-1/ciphertext-chunk-root/v1` algorithm),
`device_id` (1–64 printable characters), `signer_key_id` (16 bytes), `nonce`
(32 bytes), `issued_at` (positive UTC seconds, inclusive) and `expires_at`
(exclusive UTC seconds, at most 300 seconds after issuance). The wire adds exactly one
`signature` (64 bytes). Unknown, missing, extra, duplicate or noncanonical
fields are rejected, as are signed values that mismatch the verifier's
independently supplied expected scope/head/epoch/chunk commitment and pinned
device Ed25519 key. Caller-owned buffers and KeyObject references are captured
before any asynchronous CBOR operation.

The signing helper is for offline client/synthetic vectors; the verifier
requires a separately provisioned pinned public `KeyObject` and its key ID.
**A ciphertext sender's own key, key ID, device status, witness head or
manifest digest is never a trust root.** This module only checks the signature,
expected exact tuple and local wall-clock window. A matching signature is
replayable as cryptographic evidence; no nonce is consumed here.

The inspector always returns `authorizesRelease: false`,
`deviceAuthorizationVerified: false`, `liveManifestHeadVerified: false` and
`nonceConsumed: false`. A separate future operator-controlled verifier must
first authenticate the exact signed v2 manifest/history and independently
fresh committed CAS/witness head, check the signing device's public key and
active/non-revoked status **at that exact revision and epoch**, and atomically
consume an operation-bound nonce/permit. Those proofs cannot be invented by a
sender-controlled snapshot or a signature on its own. The candidate's domain,
field schema, replay policy and interoperability require owner/protocol review
before enabling any release, sink, ordinary app or strict HTTPS endpoint.

Run synthetic adversarial tests in Node 22 with
`node --test test/issue-65-ciphertext-device-approval-v1.test.js`.
No user data, real keys, production storage, release logic or deploy changed.
