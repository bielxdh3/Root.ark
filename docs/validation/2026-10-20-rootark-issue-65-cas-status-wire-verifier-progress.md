# Root.ark #65 — bounded CAS terminal-status wire verifier progress

**Date:** 2026-10-20
**Baseline branch/HEAD:** `cdx/rootark-dual-recovery-20261019` / `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`
**Status:** `PURE_WIRE_VERIFIER_LOCAL_PASS; RECOVERY_RUNTIME_NO_GO`.

## Local implementation

- New **pure and unintegrated** CommonJS module: `src/crypto/rootark-zk-cas-status-wire-v1.js`.
- New focused test: `test/issue-65-cas-status-wire-v1.test.js`.
- `inspectVerifiedCasStatusProofV1({raw,pinned,query,nonce})` accepts a canonical deterministic-CBOR signed CAS terminal-status proof, verified under a separately supplied pinned Ed25519 public key and 16-byte key ID, the v1 ASCII domain with NUL separator, 32-byte fresh challenge supplied by caller and exact query tuple (scope, operation and reservation IDs, request/package digests, expected/proposed revision and manifest digests).
- Enforces only the frozen v1 status wire object's 19 named fields; unsigned additions, duplicate/non-canonical CBOR, unknown type, altered validly re-signed query and incorrect observed terminal head fail closed. Enforces unsigned 64-bit revision/time primitives, initialize null pairing, next revision and signed status enum.
- A syntactically and cryptographically verified terminal-status object returns `{verifiedSignatureOnly:true,authorizesRecovery:false,...}`; **it never authorizes recovery or claims an irreversible fence, live independent authority, clock health, I/O generation safety, or a fresh witness head**. No status proof is signed by the Root.ark application.
- Input raw bytes capped at 8 MiB as a fail-closed decoder guard; no new wire field or domain is introduced.
- A read-only independent GPT-6 reviewer examined the bounded new source and 4 original tests and reported **no confirmed P1/P2** within raw-CBOR/signature/tuple checking. It correctly identified uncovered initialize/null-head and unsigned-number/length boundaries. Two follow-up tests now cover those cases and pass; the reviewer did not certify the whole recovery design.

### TDD and verification

- RED: new focused test failed with MODULE_NOT_FOUND (no prior v1 CAS status proof parser). GREEN: **4/4 pass** with real project CBOR codec and Node Ed25519 verification. Additional synthetic initialize/null-head, u64 overflow, invalid revision, wrong-length and invalid timestamp cases passed **6/6** after correcting a test fixture that attempted to encode an unsupported negative CBOR integer.
- Previous full-suite failures revisited: `test/approval-method-security.test.js`, `test/approval-sqlite-consistency.test.js`, `test/audit-console-redaction.test.js` passed **6/6 serial** and **6/6 concurrent** in isolated focused runs. This does **not** prove the prior broad 127-file full suite is green, nor establish the cause of its timeouts.
- Final issue #65 + existing local mock tests, after the additional initialize/numeric/length negatives: **131/131 Windows, 131/131 WSL**, exits 0.
- `npm run validate:syntax`: **240 files checked, 0 failed**, exit 0.
- `npm run validate:artifacts`: exit 0; `git diff --check`: exit 0.

## Explicit release gate

**NO-GO for merge of recovery as complete, NO-GO for production.** A standalone verification helper is not an integrated authority. The CAS provider still must prove committed operation durability and irreversible no-commit tombstones (with expiration/skew bound); clients must validate cancellation links, fresh directly fetched committed witness heads and monotonic history. Real independent trust roots/operators, browser custody proof, storage/egress generation fencing, history-capacity revocation lifecycle, migration and full CI remain unresolved. Host/browser and multi-operator infrastructure evidence cannot be manufactured from a one-machine Node test.

The authorization to continue local development does not imply a deployment choice, production data access, provider purchasing, merge or closure of #65. Existing untracked laboratory files are preserved.
