# Root.ark #65 — Externally Verifiable Content Inventory Authority Implementation Plan

> **For agentic workers:** Execute the substantive Phase A task with RED→GREEN TDD. Read repository rules and applicable PONYTAIL/Superpowers instructions. Do not create a substitute Executor.

**Goal:** Add a durable, independently signed and verifiable experimental catalog of encrypted object versions and absence proofs.

**Architecture:** A separate content inventory signer owns a SQLite WAL FULL ledger, publishes canonical Ed25519 signed snapshots with complete version membership, and exposes a verifier requiring a separately trusted signer and monotonic floor. Keep existing Root.ark PUT/GET disabled for this authority until cross-service crash atomicity is designed and tested.

**Tech Stack:** Node.js CommonJS, built-in Ed25519/SHA-256, deterministic CBOR from existing zk-1 crypto, better-sqlite3, node:test.

**Spec:** `docs/superpowers/specs/2026-10-19-rootark-dual-recovery-design.md` section 12, together with GitHub issue #65 and its owner decisions.

## Global Constraints

- This is development-only. No merge, deploy, release, issue closure, production I/O or schema migration of user data.
- One bounded scope at a time; deterministic exact fields; 4,096 maximum version entries; 4 MiB maximum single ciphertext outside this ledger; no legacy plaintext.
- Do not equate a separate database on the same host with independently operated providers or a truly rollback-resistant anchor.
- Preserve existing untracked work and original Git history. Only prime creates coauthored commits and performs normal push.
- **AI Memory preflight:** In this workspace, the first-party AI Memory CLI is installed as `E:\ai-memory\app\ai-memory.exe` and stores data in `E:\ai-memory\data`. The Architect successfully ran `ai-memory.exe --data-dir E:\ai-memory\data search Root.ark --global -n 5`. Before coding, the Executor can use this exact CLI to search `Root.ark` / `issue-65` as a real memory query; no unavailable MCP `memory_query` name should be invented. Report any actual retrieval failures.
- Superpowers `using-superpowers`, `writing-plans`, and `test-driven-development` instructions were explicitly loaded by the Architect from installed `skills://plugins/superpowers/*/skill.md`; follow their RED→GREEN process and existing PONYTAIL instructions. If a required skill cannot be accessed by the Executor, report that accurately but do not claim it was invoked by a missing tool.

## Review Focus

- Input is a signed but stale complete catalog: must fail against an independent minimum head.
- Input includes duplicated or reordered object/version rows: must be rejected before lookup.
- Entire object absent after prior inclusion: must be distinguishable from authenticated nonmembership and fail when floor proves presence.
- Crash after intent but before committed durable seal: unknown state must remain pending and nonauthorizing.
- Same operation ID with distinct proposed bytes: exact retry idempotence must reject conflicted replay.

## Task 1 — Signed Full Inventory Snapshot and Cryptographic Verifier

**Files:** Create `src/crypto/rootark-zk-content-inventory-v1.js`; test in `test/issue-65-content-inventory-authority.test.js`.

**Interfaces:** signer consumes canonical complete bounded tuples and independently configured Ed25519 signing key ID; verifier consumes serialized snapshot, pinned public key, exact scope, requested object/revision/digest, independent minimum `(sequence,root)` and fresh nonce. Return bounded verified data and explicit nonauthorizing status; never produce production GO flags.

- [ ] Write red tests for signed present/absent, sorted chronology, forged signature, wrong scope, stale sequence, repeated object/revision and tampered digest.
- [ ] Run focused test and record expected RED.
- [ ] Implement exact canonical deterministic CBOR and domain-separated Ed25519 signing/verification. Reject oversized tuples before copying.
- [ ] Run focused tests and record GREEN.

## Task 2 — Durable Separate Signer Ledger

**Files:** Create `src/services/zk1DurableContentInventoryLedger.js`; extend the same focused test and add validation evidence `docs/validation/2026-10-21-rootark-issue65-content-inventory-authority.md`.

**Interfaces:** explicit new-file bootstrap; identity-bound signer and scope; append exact operation `(operationId,expectedSequence,expectedRoot,objectId,version,epoch,ciphertextDigest)` to immutable chronology; get complete signed snapshot and query presence with caller nonce; fail closed on uncertainty.

- [ ] RED: restart, malformed existing file, two concurrent expected-root CAS operations, exact retry vs conflicting operation bytes, partial intent, wrong key/scope, disjoint roots.
- [ ] Implement WAL FULL durable checks and immutable monotonic catalog; retain unresolved pending entries without granting approval.
- [ ] GREEN: focused tests, browser-independent Node22 cryptographic verification, `npm run validate:syntax`, `npm run validate:artifacts`, `git diff --check`.
- [ ] Report remaining external independent-operation and cross-store atomicity limits; prime arranges independent review and coauthored commit.

---

## Intent
Close a substantive zero-knowledge data provenance gap. Existing CAS/witness signed history authenticates the **keyring** only. Local SQLite archive version, digest and provenance can all be rewritten by a privileged SQL writer; a deleted whole object can disappear undetected. Phase A creates a separately keyed, durable, versioned content-inventory authority with a verifiable signed **complete** per-scope snapshot, allowing both inclusion and absence checks. This is experimental and fail-closed, not production activation.

## Boundary and files
Inspect before editing: `src/services/zk1ProtectedObjectStore.js`, `src/services/zk1DurableCasStatusLedger.js`, `src/services/zk1CasTerminalAnchor.js`, `src/crypto/rootark-zk-1.js`, `src/services/zk1CasManifestHttpsClient.js`, and their focused tests.

Implement coherent standalone API modules, preferably `src/crypto/rootark-zk-content-inventory-v1.js` and `src/services/zk1DurableContentInventoryLedger.js`; choose names fitting current naming conventions. Add targeted `test/issue-65-content-inventory-authority.test.js` and validation evidence `docs/validation/2026-10-21-rootark-issue65-content-inventory-authority.md`. Do not alter main routing or enable strict GET/PUT through this authority until cross-service crash/atomicity can be proven in Phase B.

## Required protocol
1. Domain-separated Ed25519 signed deterministic CBOR; strict canonical decoding/re-encoding. A separately provisioned signer key ID and identity; never infer key from the application server or same-content SQLite. Verifier pins public key and scope and checks nonce, signature, bound root, sequence and externally trusted minimum head.
2. A signed complete bounded inventory snapshot with sorted unique (object_id,revision,epoch,ciphertext_sha256) tuples for ALL versions of ALL objects in one keyring scope; authenticated EMPTY/ABSENT and PRESENT results must derive from that same complete root. Monotonic sequence and previous-root continuity; no duplicate, out-of-order, omission, cross-scope or size exhaustion.
3. Durable ledger in its own explicit-bootstrap SQLite WAL FULL file, identity-bound to public signing key and scope; immutable committed entry sequence; unique operation ID and exact retry semantics, CAS expected sequence/root, restrictive limits, transactions. Do not accept a provider-supplied claim of independent operation as proof. Treat unknown/pending results as nonauthorizing. Disallow unauthorized filesystem cleanup.
4. Cryptographically verify signed root against the deterministic entire inventory for any returned snapshot; verify requested inclusion or absence from the same validated inventory; reject stale signed snapshot against caller's independent minimum sequence/root. A valid signature alone never authorizes production I/O, cutover, removal or recovery.
5. If atomicity of separate local ciphertext SQL commit and inventory ledger cannot be established, document the crash gap and make no claim of atomic integration; keep current application routes unchanged.

## Adversarial RED→GREEN acceptance
- Empty genesis inventory and authenticated absence, then first object/version, a second version and a different object; verify historical inclusion and unrelated-object absence.
- Tampered bytes/root/signature/scope, forged entry, reordered/truncated/duplicated list, replay, stale but genuinely signed prior inventory, future/incorrect floor; fail closed.
- Concurrent CAS writes, same-operation identical retry vs conflicting payload, restart and durable sequence/root continuity, malformed DB and unknown preexisting DB path.
- Limit checks before large copies/allocations; callbacks and caller buffers copied before any await. Never interpret local hash alone as external proof.
- Node focused tests PASS, syntax/artifacts/diff check PASS. Independent P1/P2 review before any prime-owned commit/push.

## Execution and reporting
Use PONYTAIL, test-driven-development, verification-before-completion and relevant installed Superpowers skills. Preserve foreign untracked files (especially `.codex-rootark-issue65-completion-20261021.md` and `test/issue-65-browser-backup-client-roundtrip.test.js`). Only change files directly required by this phase. Work exclusively on branch `cdx/rootark-dual-recovery-20261019` within its existing worktree. Do not reset, amend, cherry-pick, commit, push, merge, deploy, modify production data, or close issue; ChatGPT prime performs review, coauthored commits and authorized normal push. Report exact changed files, test results, external-independent proof limitations and remaining Phase B blockers.
