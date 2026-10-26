# Root.ark #65 — signed witness wire validation and cancellation linkage

**Date:** 2026-10-20. **Starting HEAD:** `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`, branch `cdx/rootark-dual-recovery-20261019`.
**Outcome:** `WIRE_CRYPTO_LOCAL_PASS — PRODUCTION_NO_GO`.

## Completed bounded work

1. `src/crypto/rootark-zk-witness-head-wire-v1.js` and `test/issue-65-witness-fresh-head-v1.test.js`: authenticate a **committed** witness fresh-head receipt under its exact v1 domain, pinned Ed25519 witness key and key ID, exact caller scope and a 32-byte nonce. Reject pending/unavailable heads, unresolved reservation IDs, noncanonical CBOR, noncontiguous committed witness sequence, wrong revision/digest, and a rollback below an externally supplied minimum high-water. The minimum high-water is **caller supplied and not independently protected in this module**. A receipt at a later revision still requires a full authenticated CAS history check; this verifier does not establish that. The return value always includes `authorizesRecovery:false`.
2. `src/crypto/rootark-zk-witness-operation-wire-v1.js` and `test/issue-65-witness-operation-wire-v1.test.js`: signature/CBOR/schema verification for a reservation ticket, commit receipt and cancellation receipt; pin the witness public key, require matching account/compartment/keyring/reservation/operation, validate integer ranges, initialize null pair and proposed next revision, expected package/request digests, committed revision/witness sequence, and a caller-provided CAS terminal-proof digest. This module **does not** validate that the digest came from a genuine status authority or that a reservation expired and was fenced.
3. `src/crypto/rootark-zk-cancellation-crypto-link-v1.js` and `test/issue-65-cancellation-crypto-link-v1.test.js`: cryptographically verify a canonical signed CAS `not-committed-final` proof with its pinned distinct status-authority key, fresh nonce and exact operation tuple; hash the **entire canonical signed proof including signature** with SHA-256, then verify that the independently signed witness cancellation receipt binds that digest and operation. A signed `committed` proof cannot cancel a reservation. This is a proof *link check* only: no provider durable tombstone or actual witness reconciliation is established.

**All new modules are pure and unintegrated**: no server routes, browser APIs, database migration, real keys, remote services, deployment, or selected provider were changed. No helper returns content/recovery authorization, unlocks an envelope, admits I/O, or asserts that a witness gate is open. These are protocol primitives, not proof that the service is Zero-Knowledge.

## Validation

- TDD RED: dedicated tests first failed with missing verifier modules. GREEN: fresh-head **4/4**, operation receipts **4/4**, cancellation link **3/3**.
- Independent read-only review of the fresh-head and operation validators reported no confirmed P1/P2 in their isolated verification scope (8/8 focused tests), with explicit limits for caller-supplied high-water and proof digest.
- Independent read-only review of the cancellation link **confirmed P2**: mutable `rawStatus` could change between verified canonical CBOR decoding and later SHA-256 hashing across an `await`. Two additional RED→GREEN regression cases established that this issue extended to caller-owned nonce and query bytes. The link now snapshots signed status bytes, cancellation bytes, scoped query, pinned key IDs, and nonce **synchronously before any await**, and hashes the exact status-byte snapshot that was cryptographically verified. Test evidence: raw status 3/4 before → 4/4 after; nonce/query 4/5 before → 5/5 after. No runtime recovery authorization was enabled.
- Independent **follow-up** read-only source-order review confirmed the P2 fix with no remaining P1/P2 in the bounded cancellation-link code and **5/5** focused tests.
- All `test/issue-65-*.test.js` plus existing isolated mock lab test: **142/142 Windows Node 24** and **142/142 WSL Node 22**, zero failures **before the two extra mutation regressions**; final updated aggregate is recorded separately below.
- Final aggregate **after the TOCTOU fixes**: **144/144 Windows Node 24**, **144/144 WSL Node 22**, zero failures and exit 0. `npm run validate:syntax` checked **246 files, 0 failed**; `npm run validate:artifacts` and `git diff --check` returned 0.
- `npm run validate:syntax`: **246** checked, **0** failed.
- `npm run validate:artifacts`, `git diff --check`: exit 0.
- These are focused unit tests. The **entire application full CI** has not been proven green in this stage; the prior 127-file broad run had server-startup timeouts and a prolonged upload-security test. Tests alone do not confirm service independence or real fault behavior.

## High-risk integration gates still open

- Trusted root bootstrap, key rotation and key custody independent of the Root.ark application process; direct nonce requests to live witness/CAS status authorities and independently persistent monotonic high-water.
- A **real** durable linearizable CAS operation ledger, irreversible no-commit tombstone after expiry plus the prescribed skew bound, retained witness reservation log and crash/restart/HA tests; app-server reports cannot satisfy this.
- Correct cancellation sequence: final CAS proof, linked signed witness cancellation, and a **separate later** fresh nonce-bound committed witness head with no pending reservation. The last step and physical pending gate are not exercised here.
- Actual shared GateAuthority admission/quiesce, multi-gateway effect ordering, storage-side revision/epoch fences and physical streaming-output stop acknowledgements; not just policy/mock checks.
- Browser OS-key custody, recovery-package compromise and future-epoch isolation, real migration/backups/recovery lifecycle and capacity exhaustion/compromise-revocation liveness.
- Cross-runtime independent CBOR encoding and full interop, adversarial provider split view/restore, security and operational review, full CI and an explicit residual-risk decision.

**Decision:** no merge of recovery as complete, no deploy, no issue closure. Absolute security cannot be guaranteed; this source-backed local progress closes only the bounded verification primitives described here.
