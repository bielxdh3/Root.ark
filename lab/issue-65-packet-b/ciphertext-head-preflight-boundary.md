# Issue #65 — ciphertext approval vs. signed recovery-head preflight

**Standalone opt-in READ-ONLY experiment. Never authorizes release.**

`src/crypto/rootark-zk-ciphertext-approval-head-preflight-v1.js` reuses:

- The existing WeakMap-backed `verifyRecoveryHistoryPublicV2` result, which
  attests the exact signed v2 manifest history and its digest. A caller-created
  manifest or cloned `verifiedPublicHistory` object is not a trusted history.
- Existing `verifyWitnessHeadMatchesSignedHistoryV1`, which cryptographically
  verifies canonical deterministic-CBOR, independent pinned witness Ed25519
  public key and ID, exact account/compartment/keyring, a separately supplied
  32-byte challenge, committed status, revision/digest and high-water floor.
- Existing experimental `inspectZk1CiphertextDeviceApprovalCryptoV1`, which
  verifies the device's Ed25519 approval of the exact object revision, manifest
  revision/digest, epoch, expected ciphertext chunk count/root and nonce.

The inspector matches the owner's separately pinned device key ID, device ID
and Ed25519 public key to the **actual device entry in the verified signed
manifest**. It rejects revoked devices (`revoked_at_epoch !== null`), devices
not yet enrolled at that epoch, key substitution, stale/foreign signed heads,
tampered object/root/chunk count, epoch, scope, digest or challenge. It checks
that the signed witness `observed_at` is no more than 60 seconds old and not
from the future relative to the verifier's supplied clock. Every caller-owned
buffer and Ed25519 `KeyObject` pin is captured before asynchronous CBOR work.
An independent adversarial review additionally proved a TOCTOU P2 in the
first preflight version: transiently changing a revoked device entry to
`revoked_at_epoch=null` before the first async history verification, then
restoring it before the await resumed, could make the inspector report
`signerListedActiveInSignedHead:true` for a *verified revoked* signed head.
The corrected inspector synchronously snapshots the entire bounded head
manifest and verifies **the snapshot's** SHA-256 manifest digest against the
verified signed public history before examining device enrollment/revocation.
New RED regression `manifest device revocation...` was 4/5 PASS (false
acceptance reproduced) and GREEN Node 22 focused inspector suites were
**9/9 PASS**, 0 FAIL. This remains non-authorizing history consistency
evidence, not online revocation or release authority.

**Security limits that are NOT closed:**

1. The revision-3 spec `docs/superpowers/specs/2026-10-19-rootark-dual-recovery-design.md`
   remains `REVISED_DRAFT_FOR_INDEPENDENT_REVIEW`, not protocol-approved.
   The existing Phase-8 accepted architecture and frozen primitive suite do
   **not** register the candidate ciphertext-device-approval/v1 wire format.
   No new normative v1 proof format is introduced by this milestone.
2. The signed witness head and the verifier's `nowSeconds` are *supplied*.
   This inspector makes **no online witness request**, proves no witness
   independence or current CAS storage state, and cannot establish that the
   witness operator, key bootstrap or timestamp is independently trustworthy.
   A malicious caller replacing both its claimed public key pin and signed
   receipt can present a self-consistent transcript. Production trust roots
   must be provisioned independently by the owner/operator, not the sender.
3. An authenticated witness HEAD is not an independently verified live CAS
   terminal-status/fence proof. Existing CAS-status wire verifier checks a
   particular operation's signed terminal response but explicitly does not
   establish live CAS authority or transaction durability. No online CAS
   status/linearizable gate/physical I/O admission is called here.
4. A signature bound to a nonce does not consume that nonce; repeated exact
   bytes remain cryptographically valid until expiry, and an attacker can
   replay a saved (otherwise valid) witness response. There is no durable
   consumed-approval ledger, challenged session, clock-health monitor,
   device keychain/high-water provider, browser pairing or anti-rollback
   guarantee. Device status is proven **inside that signed head only**, not
   necessarily at the live current authority revision.

The only positive result is `cryptographicLinkVerified: true`, accompanied by
`authorizesRelease: false`, `liveAuthorityVerified: false`, and
`nonceConsumed: false`. This result must NOT be consumed as an authorization
to invoke the existing ciphertext sink, normal app, strict mTLS gate, or any
content-release endpoint.

**Next necessary integration:** owner/operator-provisioned non-exportable
device trust keys and durable high-water, separately operated fresh witness
challenge with pinned root, live CAS/head verification and linearizable
content-I/O gate permit with atomic one-use consumption, plus owner approval
of the device-approval wire profile. Only then can a separately reviewed
release/admission decision be designed.

Tests use synthetic keys and bytes only:
`node --test test/issue-65-ciphertext-approval-head-preflight-v1.test.js`.
No backend secrets, production data, migration, HTTP/sink wiring or deployment.
