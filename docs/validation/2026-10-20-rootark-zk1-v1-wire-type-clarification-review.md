# Root.ark #65 — v1 authority wire-type clarification and bounded cryptographic review

**Date:** 2026-10-20
**Branch:** `cdx/rootark-dual-recovery-20261019`
**Starting source SHA:** `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2`
**Scope:** protocol documentation and test-only contract evidence, not implementation, migration, deployment, or provider selection.

## Protocol decision

The three previously unassigned Section 12.4 `type` literals now have explicitly assigned values in `docs/superpowers/specs/2026-10-20-rootark-zk1-v1-wire-type-registry.json`: `rootark-recovery-cas-status/v1`, `rootark-recovery-witness-reservation/v1`, and `rootark-recovery-witness-cancel/v1`. Bounded inspection of Section 12.4 identified a **fourth unassigned field**, the witness commit receipt; `rootark-recovery-witness-commit/v1` is assigned concurrently to avoid a second implementation blocker. The pre-existing fresh witness-head `type` is unchanged.

The signing domains remain exactly `Root.ark/zk-1/recovery-cas-status/v1`, `Root.ark/zk-1/recovery-witness-reservation/v1`, `Root.ark/zk-1/recovery-witness-cancel/v1`, and `Root.ark/zk-1/recovery-witness-commit/v1`, respectively. The previously withdrawn `rootark-cas-terminal-status/v1` / `Root.ark/zk-1/cas-terminal-status/v1` draft is forbidden. The new types were not present as released v1 encodings in the bounded in-repository `src/crypto` and `test` search. If an external client or downstream dependency already used other bytes, compatibility must be independently investigated before any wire deployment.

No existing normative field set was enlarged, shrunk or renamed by this clarification. For each signed proof, the Ed25519 signature input is ASCII(domain) + zero byte + RFC 8949 deterministic-CBOR of all and only its normative unsigned fields, **including `type`**. A validator must pin the expected domain independently from parsed untrusted input and require the exact expected `type`, key, challenge, request/head tuple and signed field set. No dynamic domain based on `type`, alternate type aliases, unknown signed keys, or permissive v1 fallback is accepted.

The cancellation linkage now defines `status_authority_proof_digest` as SHA-256 of canonical deterministic-CBOR of the **entire signed** terminal proof, including its signature. The witness/client must validate the signed terminal proof's exact scope, nonce, outcome, pinned status-authority root and durable terminal/fence evidence before using the digest; the digest alone cannot establish freshness or durable fencing. The cancellation receipt has its own witness signature, and the old expected head remains unacceptable until a separate **fresh** nonce-bound committed witness head has been checked.

## Test-only cryptographic evidence

`test/issue-65-wire-type-registry.test.js` uses Node crypto Ed25519 with actual project deterministic CBOR encoding. It verifies exact registry type/domain pairs, type and domain separation, signing-input changes, wrong key, changed operation ID, unexpected signed fields, invalid signature, nonce mismatch and cancellation proof-digest mismatch. All keys, messages and nonce values in these vectors are synthetic, and these checks are **not** a deployed encoder/verifier, network freshness test, independent cryptographic security evaluation or hardware/key custody validation.

**Validation evidence (independently executed by primary assistant):**

- Windows Node: `node --test` over `test/issue-65-*.test.js` plus existing mock lab — **121/121 passed, exit 0**.
- WSL Ubuntu Node 22: equivalent scoped run — **121/121 passed, exit 0**.
- `npm run validate:syntax` — **238 checked, 0 failed**, exit 0.
- `npm run validate:artifacts` — exit 0.
- `git diff --check` — exit 0; all protocol source/registry/test/documentation additions passed a bounded trailing-whitespace scan.
- HEAD remains unchanged; neither production runtime nor PostgreSQL/Docker artifacts were changed by this protocol-only stage.

## Acceptance boundary

**Type-literal ambiguity:** clarified for Section 12.4 objects within the repository. **Production:** NO-GO. Before live signing/verifying: perform independently verified interoperability vectors with the actual receiver and sender, deploy-independent root bootstrap and rotation, nonce challenge freshness, CAS terminal-result/fence durability, operator separation, witness-equivocation controls, browser client trust, and physical I/O gate admission/fencing. Full history exhaustion and emergency revocation lifecycle remain unresolved. No production-ready Zero-Knowledge claim follows from this amendment.

## Separate bounded read-only review

The Chat On Steroids independent GPT-6 reviewer read the normative Section 12.4, Packet B contract, registry, existing CBOR codec and test-only vectors **without editing or deploying**. It independently reran the dedicated type-registry test (3/3) and reported **PASS for the limited v1 literal/domain clarification, with no confirmed P1/P2 type collisions, signed-preimage confusion, or proof-digest defect**. This is an independent *agent review* with a separate execution context, **not** external third-party cryptographic certification or actual product-level verification.

The reviewer correctly observed that original tests used a tampered type without a fresh valid signature and that the synthetic noninitialize status example used a revision-zero head. Follow-up regression changes now include a *correctly signed wrong type under the pinned domain*, expected revision 1, and proposed revision 2. These test-only improvements do not change the registry, signed field set or protocol semantics.

**Later same-day test-only follow-up:** `test/issue-65-wire-type-registry.test.js` now exercises hostile raw CBOR (including duplicate and noncanonical keys) through the real decoder, malformed **validly signed** field widths and status/head semantics, mandatory challenge and full query-tuple binding, and mandatory caller-supplied cancellation proof-digest binding. This supersedes the earlier raw-CBOR and width-coverage gaps **for the local reference tests only**; it does not implement a live signer, verifier, status authority, or trusted-device flow. Production acceptance still requires a verified complete CAS status proof, actual expiry+30s irreversible fence, linked signed cancellation and subsequent fresh witness head, real trust roots and provider-specific persistence. No full crypto-protocol or production-security signoff is implied.
