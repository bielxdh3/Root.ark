# Root.ark #65 — wire verifier input-context snapshot hardening

**Date:** 2026-10-20
**Worktree branch:** `cdx/rootark-dual-recovery-20261019`
**Baseline HEAD:** `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`
**Security gate:** `WIRE_CONTEXT_SNAPSHOT_LOCAL_PASS; PRODUCT_RECOVERY_NO_GO`.

## Root cause and correction

The three pure wire proof verifiers previously copied or decoded signed CBOR across an `await` while continuing to compare later against mutable, caller-owned `Buffer`/typed-array objects (fresh nonce, externally pinned key ID, query/scope, high-water digest and operation details). A caller could initially supply a mismatched value then repair its bytes in a microtask after invocation but before verification. A valid signed proof could be accepted against those **later** bytes, which breaks invocation-time verification-context binding.

Three new targeted adversarial tests were written first; all three **failed RED** under the prior code with `Missing expected rejection`:

- `test/issue-65-cas-status-wire-v1.test.js`: nonce, exact query and status-authority pinned key ID.
- `test/issue-65-witness-fresh-head-v1.test.js`: fresh nonce, scope, witness key ID and caller-supplied minimum high-water digest.
- `test/issue-65-witness-operation-wire-v1.test.js`: operation tuple, witness key ID where this field exists in the signed receipt, and cancellation terminal-proof digest.

Production-adjacent standalone pure modules now synchronously create owned byte snapshots **before their first asynchronous decode**, and use those same copies throughout the signature/tuple checks:

- `src/crypto/rootark-zk-cas-status-wire-v1.js`
- `src/crypto/rootark-zk-witness-head-wire-v1.js`
- `src/crypto/rootark-zk-witness-operation-wire-v1.js`

The v1 witness **commit** receipt does not contain a signed `witness_key_id`, so an initial test that required matching that absent field was incorrect. It was corrected to rely on the separately pinned Ed25519 public key as the normative commit identity. This is not an assertion that commit receipts gain a new key-ID field.

The earlier cancellation-link implementation already snapshots its status bytes, cancellation bytes, nonce, query and pinned key IDs. The changes here close the analogous boundary for callers that invoke the underlying proof verifiers directly.

### Follow-up independent review: mutable public-key reference

The independent read-only reviewer found a separate confirmed **P2**: although the three modules validated the caller's `pinned.publicKey` before decoding, they **re-read that mutable object property after an `await`** when calling `crypto.verify`. Using one Ed25519 key at invocation and replacing it with the signature's true key in a microtask incorrectly produced successful signature verification. The reviewer demonstrated this across CAS, fresh witness head, reservation, commit and cancellation.

Three added tests produced **RED 3/3** with missing expected rejections. All three modules now synchronously retain the validated `KeyObject` reference and use precisely that reference for `crypto.verify`; this does not change or derive any signing key or introduce trust bootstrap. **GREEN 20/20** focused. The commit receipt still lacks an embedded witness key ID under the normative v1 schema and must be bound through the pinned public key.

## Verification evidence

- RED: **3 failures**, one in each new input-mutation test before implementation.
- GREEN focused proof-verification tests after both corrections: **20/20** passed (Windows).
- Final #65 tests plus existing mock lab: **150/150 Windows**, **150/150 WSL Node 22**, no failures, exit 0 in each environment.
- `npm run validate:syntax`: **246 checked, 0 failed**, exit 0.
- `npm run validate:artifacts`: exit 0.
- `git diff --check`: exit 0. No production, remote or deployed resources changed.

## Security boundary — still NO-GO

This is cryptographic **input-context integrity**, not a live authorization decision. All affected helpers continue to report `authorizesRecovery:false` and remain unintegrated into a production recovery service. They cannot supply or establish an independently trusted CAS/status key, a durable no-commit tombstone after expiry + skew, a witness whose monotonic ledger survives restarts and operator compromise, a physically serialized admission/quiesce/data-plane gate, correct browser/OS device custody, full history/revocation liveness at capacity, or a green full-project release gate. Full provider/HA and browser recovery tests are not represented by these local results.

**No release, deployment, merge, issue closure or statement of complete security is justified by this evidence.**
