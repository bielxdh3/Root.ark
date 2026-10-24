# Root.ark #65 — dual client-only content recovery integration

**Status: disposable crypto/Node browser-WebCrypto integration ONLY. Non-authorizing.**

`test/issue-65-dual-client-content-recovery.test.js` and its local test-support
fixture exercise **one identical protected file**, not two fabricated plaintext
copies: the same synthetic account, compartment, immutable keyring ID,
AES-256-GCM per-version non-extractable `CryptoKey`, file metadata/AAD, one-shot
CEK wrap, encrypted file wire, and file root are used in both recovery paths.

* **User-held emergency package**: an actual Argon2id13 worker + AES-GCM
  `createRecoveryPackageV1` export is constructed from a real signed v2 base
  manifest and an independently signed witness *BASE* receipt; the full
  signed `register-package` transition contains the exact envelope digest and
  recovery public keys. `verifyRecoveryPackageHistoryV2` validates the signed
  transition, package's HPKE private key and package epoch coverage before
  local `openRecoveryPackageV1` and file decryption. The encrypted package is
  user-held test memory, never a recovery password sent to the service.
* **Previously trusted device**: the registered source device already holds
  the epoch key in client memory. A synthetic replacement proves its HPKE
  decryption and Ed25519 signing over the existing target proof-of-possession
  challenge. The source transfers the epoch key under the existing HPKE
  keyring-wrap v2 `info`/`aad` profile, the target opens it with its own
  X25519 key, unwraps the same file CEK, and decrypts the same AES-GCM bytes.
  The test makes no claim that the server has enrolled the target device.

Adversarial coverage includes wrong password, package AEAD tampering, wrong
scope/keyring, lost local device, validated v2 signed revocation and epoch
rotation (the old device no longer qualifies, while the package can still
decrypt historical ciphertext), wrong file version and AEAD AAD, wrong key
epoch and chunk-root commitment, a stale/foreign head, and negative
no-go states for unresolved CAS/witness reservations and replay.

**Critical non-go claims:**

1. The negative `pendingReservation`, `staleHead`, `replayedRequest`,
   `lostDevice` and missing-witness switches are **synthetic, in-memory test
   gates**. They are not a live CAS, witness, consumed-ID ledger, validated
   secure device store, or evidence of durable anti-replay. A repeated
   valid password can reopen an immutable package as expected; that operation
   alone is not an authorization to enroll or release content on the server.
2. The base witness receipt authenticates a historical manifest; it does not
   independently attest the **latest** committed head, a pending gate, a live
   high-water floor, clock health, or a fresh nonce from a remote witness.
   Both verified histories deliberately report `freshnessProven:false`.
3. Offline copies of previously held keys and ciphertext survive revocation;
   revocation gates **future server-authorized uses**, not retroactive
   destruction. No account/login reset, server administrator, package holder
   alone, or old signer may create content authority without a fresh,
   independently pinned CAS/witness admission.
4. Browser CryptoKey capability was exercised using Node's native WebCrypto
   implementation, not a deployed browser/OS-backed keychain. The rev3 dual
   recovery protocol remains a draft; owner acceptance, actual device pairing,
   export/retention UX, and persistent cross-runtime secure custody remain
   separately blocked.

This milestone adds only synthetic tests and test-support fixtures. It makes
no change to production routes, database schema, wire registry, sink, keys,
user data, package policy or deployment. It never sets release authorization
true. The next integration dependency is an independently operated, fresh
nonce-bound CAS/witness head and linearizable protected-content admission gate,
with persistent one-use authorization and OS-protected device high-water.

Run on Node 22: `node --test test/issue-65-dual-client-content-recovery.test.js`.
