# Issue #65 — DEV browser recoverable PUT journal

**Status:** development-only recoverable encrypted-file path; no deployment,
remote durability, independent write authority or production authorization.

## Invariants

1. The browser derives a one-use random file CEK and seals it inside a portable
   recovery bundle, itself encrypted with a *separately user-held* 256-bit
   recovery secret. Neither key nor file plaintext is sent through protected
   content HTTP.
2. Before the **first** PUT, the signed operation nonce/signature, owner SPKI
   fingerprint, signed grant's pinned manifest revision/digest, epoch, owner
   history sequence if available, object/version IDs, ciphertext digest/root
   and bundle are committed as an immutable `add()` record in IndexedDB.
   The bundle is encrypted again using AES-256-GCM/HKDF-SHA256 with the holder
   secret and domain-separated associated data bound to the public record.
   Non-secret locator/head fields and the signed operation receipt remain
   visible to this same-origin browser profile; filenames and wrapped CEK do not.
3. A `readwrite` IndexedDB transaction with `{durability:"strict"}` and a
   successful transaction-complete event is required. A separate readback must
   authenticate/decrypt the newly persisted journal, its portable CEK wrap,
   ciphertext digest and root **before PUT**. Failure means zero PUTs.
4. The signed PUT occurs at most once. A missing/invalid ACK may mean the
   server committed: it cannot authorize a PUT replay. An exact-revision GET
   with a new Ed25519 signature, bound ciphertext digest and independent root
   must succeed before an export is labeled `clientReadbackVerified`.
5. Crash/disconnect at any point after journal commit leaves its encrypted
   record intact. UI **Listar IDs locais pendentes** enumerates only opaque
   object IDs; with the original holder secret, current valid signed grant,
   independently pinned owner head and local monotonic floor, **Retomar GET sem
   PUT** restores *only* by signing another exact-version GET. If no ciphertext
   was committed, GET fails closed: no automatic upload, rollback, deletion,
   false success, or plaintext/key fallback.
6. Wrong holder secret, changed ID/epoch/digest/owner fingerprint, reverted
   locally authenticated journal, stale owner floor, or invalid/revoked device
   authorization must fail. Server online revocation is enforced by the
   protected GET admission; local checks never claim independent fresh
   revocation proof.
7. Journal entries are deliberately retained even after successful GET or
   attempted export. This avoids losing the only sealed CEK if a browser crash
   follows GET but precedes the user's file download. There is no automatic
   cleanup, erasure, cutover or object deletion; the user must preserve a
   separately downloaded bundle and owner-signed historical-root proof for
   eventual **second-device** restoration.

## Failure and recovery protocol

- **Before journal commit:** abort; no PUT; user keeps original local file.
- **After commit, before PUT:** pending ID remains; signed GET may be absent;
  do not issue PUT on automatic resume.
- **PUT ACK lost, GET unavailable:** leave sealed journal pending; no bundle
  export or false commit receipt. Wait for availability and retry GET-only with
  fresh local trust anchors and active device grant.
- **GET readback verified, download interrupted:** journal remains intact;
  open it with the holder secret and re-run the signed GET.
- **Secret lost or profile evicted:** the journal cannot be decrypted or may be
  gone entirely. Keep an independently saved recovery bundle/secret. Without
  either the sealed CEK or original file, the random CEK is not reconstructible.
- **Device revoked or owner head rolled forward:** import fresh independently
  authenticated head/grant and owner history; never bypass revocation or local
  floor. A new device requires owner-approved historical ciphertext root and
  its own enrolled grant before external cross-device restore.

**Durability boundary:** IndexedDB `durability:"strict"` + `oncomplete` +
readback is the strongest browser-local software acknowledgment here; it is
not a verifiable OS fsync/power-loss guarantee and cannot stop browser profile
deletion, quota eviction, storage corruption, external rollback of the entire
profile, loss of the holder secret, or denial of future signed GET. The journal
is not an owner root endorsement, witness/CAS floor, independent physical
receipt, multiprovider/cloud durability or production security claim.

**Evidence:** the focused Node22/24 WebCrypto test simulates reload, dropped
PUT ACK, offline GET, wrong secret, absent strict transaction and an attempted
replay. The Node24 real HTTP/SQLite fixture covers exact signed GET, local
restart, altered anchors, revocation, owner-approved new-device restore and
logical trash regression. Actual Edge on Windows verifies the AES-GCM journal,
strict IndexedDB transaction, persistence across page reload and rejection of
an incorrect secret. The Edge test does not simulate an OS power failure.
